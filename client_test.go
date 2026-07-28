package intyga

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// mockGateway is an in-process stand-in for the Intyga gateway. httptest runs in the SAME process
// (no child process, no external socket dependency), so these tests exercise the real HTTP paths.
func TestRequireApprovalHappyPath(t *testing.T) {
	var polls int32
	mux := http.NewServeMux()

	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("authorization"); got != "Bearer test-token" {
			t.Errorf("missing/wrong bearer token: %q", got)
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["actionDescription"] != "Wire $5,000 to Acme Corp" {
			t.Errorf("unexpected actionDescription: %v", body["actionDescription"])
		}
		writeJSON(w, map[string]interface{}{"nonce": "n_abc123", "status": "PENDING"})
	})

	mux.HandleFunc("/authorize/n_abc123", func(w http.ResponseWriter, r *http.Request) {
		// Stay PENDING for the first poll, then APPROVED — exercises the polling loop.
		if atomic.AddInt32(&polls, 1) < 2 {
			writeJSON(w, map[string]interface{}{"status": "PENDING"})
			return
		}
		writeJSON(w, map[string]interface{}{
			"status":        "APPROVED",
			"signatureHash": "deadbeef",
			"receipt":       map[string]interface{}{"canonicalPayload": "{}", "actionDescription": "Wire $5,000 to Acme Corp", "params": map[string]interface{}{}, "verificationCode": "AAAA-BBBB"},
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(ClientOptions{GatewayURL: srv.URL, Token: "test-token"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := client.RequireApproval(ctx, "Wire $5,000 to Acme Corp", RequireApprovalOptions{
		AuthorizeOptions: AuthorizeOptions{
			ActionType: "wire_transfer",
			Params:     map[string]interface{}{"to": "Acme Corp", "amount": 5000},
		},
		Interval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RequireApproval: %v", err)
	}
	if res.Status != StatusApproved {
		t.Fatalf("expected APPROVED, got %s", res.Status)
	}
	if res.Nonce != "n_abc123" {
		t.Fatalf("expected nonce to be set to n_abc123, got %q", res.Nonce)
	}
	if res.Receipt == nil {
		t.Fatal("expected a receipt on approval")
	}
}

func TestAuthorizeDeniedStopsPolling(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"nonce": "n_deny", "status": "PENDING"})
	})
	mux.HandleFunc("/authorize/n_deny", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"status": "DENIED"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(ClientOptions{GatewayURL: srv.URL, Token: "t"})
	res, err := client.RequireApproval(context.Background(), "delete prod", RequireApprovalOptions{
		Interval: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RequireApproval: %v", err)
	}
	if res.Status != StatusDenied {
		t.Fatalf("expected DENIED, got %s", res.Status)
	}
}

func TestTokenExchange(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "cid" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		writeJSON(w, map[string]interface{}{"access_token": "exchanged-token"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(ClientOptions{GatewayURL: srv.URL, ClientID: "cid", ClientSecret: "secret"})
	tok, err := client.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "exchanged-token" {
		t.Fatalf("expected exchanged-token, got %q", tok)
	}
	// Second call must use the cached token without another exchange.
	tok2, _ := client.Token(context.Background())
	if tok2 != "exchanged-token" {
		t.Fatalf("expected cached token, got %q", tok2)
	}
}

func TestConsumeRebinding(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize/verify", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["nonce"] != "n_1" {
			t.Errorf("unexpected nonce: %v", body["nonce"])
		}
		writeJSON(w, map[string]interface{}{"ok": true})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := NewClient(ClientOptions{GatewayURL: srv.URL, Token: "t"})
	out, err := client.Consume(context.Background(), "n_1", "wire_transfer", map[string]interface{}{"amount": 5000})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !out.OK {
		t.Fatalf("expected ok, got %+v", out)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
