package intyga

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "test-token"})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, err := client.RequireApproval(ctx, "Wire $5,000 to Acme Corp", RequireApprovalOptions{
		AuthorizeOptions: AuthorizeOptions{
			Target:     "prod-payments",
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

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	res, err := client.RequireApproval(context.Background(), "delete prod", RequireApprovalOptions{
		AuthorizeOptions: AuthorizeOptions{Target: "prod-db"},
		Interval:         10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("RequireApproval: %v", err)
	}
	if res.Status != StatusDenied {
		t.Fatalf("expected DENIED, got %s", res.Status)
	}
}

func TestTokenExchange(t *testing.T) {
	var exchanges int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "cid" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		atomic.AddInt32(&exchanges, 1)
		writeJSON(w, map[string]interface{}{"access_token": "exchanged-token", "token_type": "Bearer", "expires_in": 3600})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, ClientID: "cid", ClientSecret: "secret"})
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
	if n := atomic.LoadInt32(&exchanges); n != 1 {
		t.Fatalf("expected exactly one exchange, got %d", n)
	}
}

// tokenServer is a gateway stub whose /oauth/token mints "tok-N" on the Nth exchange and reports the
// given expires_in (omitted when nil), so a test can tell a cached token from a re-exchanged one.
func tokenServer(t *testing.T, expiresIn interface{}, exchanges *int32, mux *http.ServeMux) {
	t.Helper()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(exchanges, 1)
		body := map[string]interface{}{"access_token": fmt.Sprintf("tok-%d", n), "token_type": "Bearer"}
		if expiresIn != nil {
			body["expires_in"] = expiresIn
		}
		writeJSON(w, body)
	})
}

// fakeClock is an injectable clock for Client.now: tests advance it instead of sleeping.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) Advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

// The cached token is served until min(60s, expires_in/10) before expiry and re-exchanged after
// that — for expires_in=100 the margin is 10s, so the boundary sits at 90s.
func TestTokenRefreshesBeforeExpiry(t *testing.T) {
	var exchanges int32
	mux := http.NewServeMux()
	tokenServer(t, 100, &exchanges, mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	clock := &fakeClock{now: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)}
	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, ClientID: "cid", ClientSecret: "secret"})
	client.now = clock.Now

	tok, err := client.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("expected tok-1, got %q", tok)
	}

	// One second inside the margin: still cached.
	clock.Advance(89 * time.Second)
	if tok, _ := client.Token(context.Background()); tok != "tok-1" {
		t.Fatalf("expected the cached token at 89s, got %q", tok)
	}
	if n := atomic.LoadInt32(&exchanges); n != 1 {
		t.Fatalf("expected one exchange at 89s, got %d", n)
	}

	// Past the margin, before the actual expiry: re-exchanged proactively.
	clock.Advance(2 * time.Second)
	tok, err = client.Token(context.Background())
	if err != nil {
		t.Fatalf("Token after margin: %v", err)
	}
	if tok != "tok-2" {
		t.Fatalf("expected a fresh token at 91s, got %q", tok)
	}
	if n := atomic.LoadInt32(&exchanges); n != 2 {
		t.Fatalf("expected two exchanges at 91s, got %d", n)
	}

	// The fresh token carries its own expiry, measured from the exchange that minted it.
	clock.Advance(60 * time.Second)
	if tok, _ := client.Token(context.Background()); tok != "tok-2" {
		t.Fatalf("expected tok-2 to still be cached 60s after its exchange, got %q", tok)
	}
}

// A gateway that reports no expires_in gets the pre-refresh behaviour: cached for the life of the
// Client, no matter how much time passes. Only a 401 invalidates it.
func TestTokenWithoutExpiresInIsCachedIndefinitely(t *testing.T) {
	var exchanges int32
	mux := http.NewServeMux()
	tokenServer(t, nil, &exchanges, mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	clock := &fakeClock{now: time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)}
	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, ClientID: "cid", ClientSecret: "secret"})
	client.now = clock.Now

	if _, err := client.Token(context.Background()); err != nil {
		t.Fatalf("Token: %v", err)
	}
	clock.Advance(365 * 24 * time.Hour)
	tok, err := client.Token(context.Background())
	if err != nil {
		t.Fatalf("Token a year later: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("expected the cached token, got %q", tok)
	}
	if n := atomic.LoadInt32(&exchanges); n != 1 {
		t.Fatalf("expected exactly one exchange, got %d", n)
	}
}

// A non-numeric expires_in must not fail the exchange; it means "no expiry known".
func TestTokenNonNumericExpiresInIsIgnored(t *testing.T) {
	var exchanges int32
	mux := http.NewServeMux()
	tokenServer(t, "soon", &exchanges, mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, ClientID: "cid", ClientSecret: "secret"})
	tok, err := client.Token(context.Background())
	if err != nil {
		t.Fatalf("Token: %v", err)
	}
	if tok != "tok-1" {
		t.Fatalf("expected tok-1, got %q", tok)
	}
	if !client.cachedExpiry.IsZero() {
		t.Fatalf("expected no expiry recorded for a non-numeric expires_in, got %v", client.cachedExpiry)
	}
}

// A 401 on an exchanged token invalidates the cache and retries exactly once with a fresh exchange.
func TestUnauthorizedRetriesExchangeOnce(t *testing.T) {
	var exchanges int32
	var bearers []string
	var bearersMu sync.Mutex
	mux := http.NewServeMux()
	tokenServer(t, 3600, &exchanges, mux)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		bearersMu.Lock()
		bearers = append(bearers, r.Header.Get("authorization"))
		n := len(bearers)
		bearersMu.Unlock()
		if n == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"Invalid token: ERR_JWT_EXPIRED"}`))
			return
		}
		writeJSON(w, map[string]interface{}{"nonce": "n_retry", "status": "PENDING"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, ClientID: "cid", ClientSecret: "secret"})
	res, err := client.Authorize(context.Background(), "wire", AuthorizeOptions{Target: "prod-payments", ActionType: "wire_transfer"})
	if err != nil {
		t.Fatalf("Authorize should have succeeded on the retry: %v", err)
	}
	if res.Nonce != "n_retry" {
		t.Fatalf("expected nonce n_retry, got %q", res.Nonce)
	}
	if n := atomic.LoadInt32(&exchanges); n != 2 {
		t.Fatalf("expected two exchanges (initial + retry), got %d", n)
	}
	bearersMu.Lock()
	defer bearersMu.Unlock()
	if len(bearers) != 2 || bearers[0] != "Bearer tok-1" || bearers[1] != "Bearer tok-2" {
		t.Fatalf("expected /authorize to see tok-1 then tok-2, got %v", bearers)
	}
}

// The retry is bounded: a gateway that keeps answering 401 gets exactly two attempts, then the
// error surfaces — never a refresh loop.
func TestUnauthorizedRetriesOnlyOnce(t *testing.T) {
	var exchanges, authorizes int32
	mux := http.NewServeMux()
	tokenServer(t, 3600, &exchanges, mux)
	mux.HandleFunc("/authorize/n_dead", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&authorizes, 1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, ClientID: "cid", ClientSecret: "secret"})
	_, err := client.Status(context.Background(), "n_dead")
	if err == nil {
		t.Fatal("expected the second 401 to surface as an error")
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected a 401 error, got %v", err)
	}
	if n := atomic.LoadInt32(&authorizes); n != 2 {
		t.Fatalf("expected exactly two attempts, got %d", n)
	}
	if n := atomic.LoadInt32(&exchanges); n != 2 {
		t.Fatalf("expected exactly two exchanges, got %d", n)
	}
}

// An explicit Token has no credential behind it: a 401 is returned as-is, with no exchange attempted.
func TestExplicitTokenIsNotReExchangedOn401(t *testing.T) {
	var exchanges, authorizes int32
	mux := http.NewServeMux()
	tokenServer(t, 3600, &exchanges, mux)
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&authorizes, 1)
		w.WriteHeader(http.StatusUnauthorized)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "explicit", ClientID: "cid", ClientSecret: "secret"})
	_, err := client.Authorize(context.Background(), "wire", AuthorizeOptions{Target: "prod-payments"})
	if err == nil {
		t.Fatal("expected the 401 to surface as an error")
	}
	if n := atomic.LoadInt32(&authorizes); n != 1 {
		t.Fatalf("expected a single attempt with an explicit token, got %d", n)
	}
	if n := atomic.LoadInt32(&exchanges); n != 0 {
		t.Fatalf("expected no exchange with an explicit token, got %d", n)
	}
}

// Concurrent first callers share one exchange: the cache is guarded by a mutex held across the
// exchange, so N goroutines racing on a cold cache produce one token, not N. Run with -race.
func TestConcurrentTokenCallsExchangeOnce(t *testing.T) {
	var exchanges int32
	mux := http.NewServeMux()
	tokenServer(t, 3600, &exchanges, mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, ClientID: "cid", ClientSecret: "secret"})
	const callers = 16
	var wg sync.WaitGroup
	tokens := make([]string, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			tok, err := client.Token(context.Background())
			if err != nil {
				t.Errorf("Token: %v", err)
			}
			tokens[i] = tok
		}(i)
	}
	wg.Wait()
	if n := atomic.LoadInt32(&exchanges); n != 1 {
		t.Fatalf("expected one exchange across %d concurrent callers, got %d", callers, n)
	}
	for i, tok := range tokens {
		if tok != "tok-1" {
			t.Fatalf("caller %d got %q, expected tok-1", i, tok)
		}
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
		// The gateway's authorizationConsume schema requires target, so a mock that accepts any body
		// is not testing the contract. This omission used to 400 every Consume call in production
		// while this test stayed green — the reason it went unnoticed for so long.
		if body["target"] != "prod-payments" {
			t.Errorf("consume body must carry the bound target, got %v", body["target"])
		}
		if body["actionType"] != "wire_transfer" {
			t.Errorf("unexpected actionType: %v", body["actionType"])
		}
		writeJSON(w, map[string]interface{}{"ok": true})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	out, err := client.Consume(context.Background(), "n_1", "prod-payments", "wire_transfer", map[string]interface{}{"amount": 5000})
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if !out.OK {
		t.Fatalf("expected ok, got %+v", out)
	}
}

// DIV §3 Invariant 5: an approval that names no target binds no execution environment, and the
// gateway silently defaults a missing one to "global" — so refusing client-side is the only place
// the caller finds out.
func TestTargetIsRequired(t *testing.T) {
	client := mustClient(t, ClientOptions{GatewayURL: "http://127.0.0.1:1", Token: "t"})

	if _, err := client.Authorize(context.Background(), "wire", AuthorizeOptions{ActionType: "wire"}); err == nil {
		t.Fatal("Authorize accepted an empty Target; the gateway would have signed target=global")
	}
	if _, err := client.Consume(context.Background(), "n_1", "  ", "wire", nil); err == nil {
		t.Fatal("Consume accepted a blank target; the gateway would have rejected it with a 400")
	}
}

// The authorize request must actually carry the target through to the wire, not merely accept it.
func TestAuthorizeSendsTarget(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["target"] != "prod-payments" {
			t.Errorf("authorize body must carry the target, got %v", body["target"])
		}
		if body["actionType"] != "wire_transfer" {
			t.Errorf("authorize body must preserve explicit actionType, got %v", body["actionType"])
		}
		writeJSON(w, map[string]interface{}{"nonce": "n_1", "status": "PENDING"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	if _, err := client.Authorize(context.Background(), "Wire $5,000", AuthorizeOptions{
		Target:     "prod-payments",
		ActionType: "wire_transfer",
	}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
}

func TestAuthorizeOmitsUnsetActionType(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if _, present := body["actionType"]; present {
			t.Errorf("unset actionType must be omitted, got %v", body["actionType"])
		}
		writeJSON(w, map[string]interface{}{"nonce": "n_1", "status": "PENDING"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	if _, err := client.Authorize(context.Background(), "Wire", AuthorizeOptions{Target: "prod-payments"}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("content-type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func TestIssuedAgentContextAndPublicLookup(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"nonce": "ctx", "status": "PENDING", "agentContext": map[string]interface{}{"nbf": "issued"}})
	})
	mux.HandleFunc("/authorize/ctx", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"status": "APPROVED", "agentContext": map[string]interface{}{"nbf": "poll-must-not-replace"}})
	})
	mux.HandleFunc("/verify/hash", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Error("public lookup sent credentials")
		}
		writeJSON(w, map[string]interface{}{"verified": true, "status": "SIGNED", "documentHash": "hash"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	result, err := client.RequireApproval(context.Background(), "wire", RequireApprovalOptions{AuthorizeOptions: AuthorizeOptions{Target: "prod"}})
	if err != nil || result.AgentContext["nbf"] != "issued" {
		t.Fatalf("lost issuance context: %+v %v", result, err)
	}
	public := mustClient(t, ClientOptions{GatewayURL: srv.URL})
	found, err := public.Verify(context.Background(), "hash")
	if err != nil || !found.Verified {
		t.Fatalf("public lookup requires credentials: %+v %v", found, err)
	}
}

func TestDefaultTransportRefusesAuthenticatedRedirect(t *testing.T) {
	var forwarded atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/sink", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/sink", func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		writeJSON(w, map[string]interface{}{"access_token": "wrong"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := mustClient(t, ClientOptions{GatewayURL: srv.URL + "/", ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Token(context.Background()); err == nil || !strings.Contains(err.Error(), "307") {
		t.Fatalf("redirect accepted: %v", err)
	}
	if forwarded.Load() != 0 {
		t.Fatal("credentialed request followed a redirect")
	}
}

func TestTruncatedBodyIsNotAcceptedEvenWhenJSONIsComplete(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "500")
		writeJSON(w, map[string]interface{}{"access_token": "t", "status": "APPROVED"})
	}))
	defer srv.Close()
	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, ClientID: "id", ClientSecret: "secret"})
	if _, err := client.Token(context.Background()); err == nil {
		t.Fatal("accepted truncated token response")
	}
	client = mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	if _, err := client.Status(context.Background(), "nonce"); err == nil {
		t.Fatal("accepted truncated approval response")
	}
}

func TestLateApprovalIsExpired(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"nonce": "late", "status": "PENDING"})
	})
	mux.HandleFunc("/authorize/late", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(30 * time.Millisecond)
		writeJSON(w, map[string]interface{}{"status": "APPROVED"})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	client := mustClient(t, ClientOptions{GatewayURL: srv.URL, Token: "t"})
	result, err := client.RequireApproval(context.Background(), "wire", RequireApprovalOptions{AuthorizeOptions: AuthorizeOptions{Target: "prod"}, Timeout: 10 * time.Millisecond, Interval: time.Millisecond})
	if err != nil || result.Status != StatusExpired || result.Nonce != "late" {
		t.Fatalf("late approval accepted: %+v %v", result, err)
	}
}

// mustClient is NewClient for tests whose gateway URL is valid by construction.
func mustClient(t *testing.T, opts ClientOptions) *Client {
	t.Helper()
	c, err := NewClient(opts)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// I11: a plain-http gateway would carry the bearer token or client secret in the clear, so NewClient
// refuses it before any request exists. Loopback stays usable for a local gateway.
func TestNewClientRefusesNonHTTPSGateway(t *testing.T) {
	for _, bad := range []string{
		"http://gw.example",
		"http://10.0.0.5:8787",
		"http://128.0.0.1",
		"http://localhost.evil.example",
		"http://[::2]",
		"ftp://gw.example",
		"gw.example",
		"",
	} {
		if c, err := NewClient(ClientOptions{GatewayURL: bad, Token: "t"}); err == nil || c != nil {
			t.Errorf("NewClient accepted %q", bad)
		}
	}
	if _, err := NewClient(ClientOptions{GatewayURL: "http://gw.example"}); err == nil ||
		!strings.Contains(err.Error(), "must use https://") {
		t.Errorf("error does not name the rule: %v", err)
	}
	for _, ok := range []string{
		"https://gw.example",
		"https://gw.example/",
		"HTTPS://gw.example",
		"http://localhost:8787",
		"http://LOCALHOST",
		"http://127.0.0.1:8787",
		"http://127.200.3.4",
		"http://[::1]:8787",
	} {
		if _, err := NewClient(ClientOptions{GatewayURL: ok, Token: "t"}); err != nil {
			t.Errorf("NewClient refused %q: %v", ok, err)
		}
	}
	c := mustClient(t, ClientOptions{GatewayURL: "https://gw.example//", Token: "t"})
	if c.opts.GatewayURL != "https://gw.example" {
		t.Errorf("trailing slashes kept: %q", c.opts.GatewayURL)
	}
}
