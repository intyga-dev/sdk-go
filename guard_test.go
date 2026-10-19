package intyga

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	verify "github.com/intyga-dev/sdk-go/v2/verify"
)

type guardTransport func(*http.Request) (*http.Response, error)

func (f guardTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type guardFixture struct {
	vector                                   map[string]interface{}
	receipt                                  interface{}
	params                                   map[string]interface{}
	opts                                     ApprovalGuardOptions
	client                                   *Client
	nonce, status                            string
	consumeOK, dispatchFail, dispatchRefused bool
	failPath                                 string
	events                                   []string
	bodies                                   []map[string]interface{}
	onAuthorize, onConsume                   func()
}

func newGuardFixture(t *testing.T) *guardFixture {
	t.Helper()
	raw, err := os.ReadFile("vectors/webauthn-vector.json")
	if err != nil {
		t.Fatal(err)
	}
	f := &guardFixture{consumeOK: true, status: "APPROVED"}
	if err := json.Unmarshal(raw, &f.vector); err != nil {
		t.Fatal(err)
	}
	exp := f.vector["expected"].(map[string]interface{})
	f.receipt = f.vector["receipt"]
	f.params = exp["params"].(map[string]interface{})
	f.nonce = exp["nonce"].(string)
	f.opts = ApprovalGuardOptions{
		Target: exp["target"].(string), ActionType: exp["actionType"].(string),
		Approvers:      verify.ApproverTrustAnchor{PublicKeys: []string{f.receipt.(map[string]interface{})["signerPublicKey"].(string)}},
		ExpectedOrigin: f.vector["origin"].(string), ExpectedRpID: f.vector["rpId"].(string),
		Timeout: time.Second, Interval: time.Millisecond, ReportDispatch: 60,
	}
	f.client = mustClient(t, ClientOptions{GatewayURL: "https://gateway.example", Token: "test-token",
		HTTPClient: &http.Client{Transport: guardTransport(func(req *http.Request) (*http.Response, error) {
			path := req.URL.Path
			var body map[string]interface{}
			if req.Body != nil {
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatal(err)
				}
			}
			var response interface{}
			code := 200
			switch {
			case path == "/authorize":
				f.events = append(f.events, "authorize")
				f.bodies = append(f.bodies, body)
				if f.onAuthorize != nil {
					f.onAuthorize()
				}
				response = map[string]interface{}{"nonce": f.nonce, "status": "PENDING"}
			case path == "/authorize/verify":
				f.events = append(f.events, "consume")
				f.bodies = append(f.bodies, body)
				if f.onConsume != nil {
					f.onConsume()
				}
				response = map[string]interface{}{"ok": f.consumeOK, "reason": "already consumed"}
			case strings.HasSuffix(path, "/dispatched"):
				f.events = append(f.events, "dispatch")
				if body["evidenceWithinSeconds"] != float64(60) {
					t.Errorf("wrong window: %v", body)
				}
				if f.dispatchFail {
					code = 503
				}
				response = map[string]interface{}{"ok": !f.dispatchRefused}
			default:
				f.events = append(f.events, "status")
				response = map[string]interface{}{"status": f.status, "receipt": f.receipt}
			}
			if path == f.failPath {
				code = 403
			}
			encoded, _ := json.Marshal(response)
			return &http.Response{StatusCode: code, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(encoded)))}, nil
		})},
	})
	return f
}

func TestGuardBindsDetachedArgumentsAndOrdersExecution(t *testing.T) {
	f := newGuardFixture(t)
	want, _ := verify.StableStringify(f.params)
	f.onAuthorize = func() {
		f.params["amount"] = 999999
		f.params["meta"].(map[string]interface{})["ok"] = false
	}
	guard, err := NewApprovalGuard(f.client, f.opts, func(_ context.Context, args map[string]interface{}) (string, error) {
		f.events = append(f.events, "tool")
		got, _ := verify.StableStringify(args)
		if got != want {
			t.Fatalf("tool did not receive approved snapshot: %s", got)
		}
		return "sent", nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Construction snapshots trust too: later reconfiguration cannot change an existing guard.
	f.opts.Approvers.PublicKeys[0] = "untrusted"
	got, err := guard(context.Background(), f.params)
	if err != nil || got != "sent" {
		t.Fatalf("got %q, %v", got, err)
	}
	if !reflect.DeepEqual(f.events, []string{"authorize", "status", "consume", "tool", "dispatch"}) {
		t.Fatal(f.events)
	}
	for _, body := range f.bodies {
		got, _ := verify.StableStringify(body["params"])
		if got != want || body["target"] != f.opts.Target || body["actionType"] != f.opts.ActionType {
			t.Fatalf("binding drift: %v", body)
		}
	}
}

func TestGuardRefusesBeforeToolAndDispatch(t *testing.T) {
	cases := map[string]func(*guardFixture){
		"denied":       func(f *guardFixture) { f.status = "DENIED" },
		"expired":      func(f *guardFixture) { f.status = "EXPIRED" },
		"consumed":     func(f *guardFixture) { f.status = "CONSUMED" },
		"offline":      func(f *guardFixture) { f.status = "OFFLINE_APPROVED" },
		"no receipt":   func(f *guardFixture) { f.receipt = nil },
		"nonce":        func(f *guardFixture) { f.nonce = "another-challenge" },
		"target":       func(f *guardFixture) { f.opts.Target = "another-service" },
		"action":       func(f *guardFixture) { f.opts.ActionType = "another-action" },
		"params":       func(f *guardFixture) { f.params["amount"] = 1 },
		"signer":       func(f *guardFixture) { f.opts.Approvers.PublicKeys[0] = "untrusted" },
		"signature":    func(f *guardFixture) { f.receipt.(map[string]interface{})["signature"] = "invalid" },
		"origin":       func(f *guardFixture) { f.opts.ExpectedOrigin = "https://wrong.example" },
		"rpId":         func(f *guardFixture) { f.opts.ExpectedRpID = "wrong.example" },
		"missing pins": func(f *guardFixture) { f.opts.ExpectedOrigin = ""; f.opts.ExpectedRpID = "" },
		// The vector's receipt is v1: an expected tenant is forwarded to the verifier, which refuses it.
		"tenant":               func(f *guardFixture) { f.opts.TenantID = "another-workspace" },
		"quorum floor":         func(f *guardFixture) { f.opts.Requirement = &verify.RequirementFloor{RequiredApprovals: 2} },
		"consume false":        func(f *guardFixture) { f.consumeOK = false },
		"consume HTTP error":   func(f *guardFixture) { f.failPath = "/authorize/verify" },
		"authorize HTTP error": func(f *guardFixture) { f.failPath = "/authorize" },
		"non JSON":             func(f *guardFixture) { f.params["bad"] = func() {} },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			f := newGuardFixture(t)
			edit(f)
			guard, err := NewApprovalGuard(f.client, f.opts, func(context.Context, map[string]interface{}) (string, error) {
				t.Fatal("executed refused tool")
				return "", nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := guard(context.Background(), f.params); err == nil {
				t.Fatal("expected refusal")
			}
			for _, e := range f.events {
				if e == "dispatch" {
					t.Fatal("reported an unexecuted tool")
				}
				if e == "consume" && name != "consume false" && name != "consume HTTP error" {
					t.Fatal("consumed before verification")
				}
			}
		})
	}
}

func TestGuardDispatchCannotMaskToolOutcome(t *testing.T) {
	for _, outcome := range []string{"success", "error", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			f := newGuardFixture(t)
			f.dispatchFail = true
			diagnosed := false
			f.opts.OnDispatchError = func(nonce string, err error) {
				diagnosed = true
				if nonce != f.nonce || err == nil {
					t.Error("missing retry context")
				}
				panic("diagnostic failed")
			}
			original := errors.New("tool failed")
			guard, err := NewApprovalGuard(f.client, f.opts, func(context.Context, map[string]interface{}) (string, error) {
				if outcome == "panic" {
					panic(original)
				}
				if outcome == "error" {
					return "partial", original
				}
				return "sent", nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if outcome == "panic" {
				func() {
					defer func() {
						if recover() != original {
							t.Error("tool panic replaced")
						}
					}()
					_, _ = guard(context.Background(), f.params)
				}()
			} else {
				got, err := guard(context.Background(), f.params)
				if outcome == "success" && (got != "sent" || err != nil) {
					t.Fatalf("%q %v", got, err)
				}
				if outcome == "error" && (got != "partial" || err != original) {
					t.Fatalf("%q %v", got, err)
				}
			}
			if !diagnosed {
				t.Fatal("missing dispatch diagnostic")
			}
		})
	}
}

func TestGuardDisabledDispatchAndCancellation(t *testing.T) {
	for _, cancelBeforeTool := range []bool{false, true} {
		f := newGuardFixture(t)
		f.opts.ReportDispatch = 0
		ctx, cancel := context.WithCancel(context.Background())
		if cancelBeforeTool {
			f.onConsume = cancel
		}
		ran := false
		guard, err := NewApprovalGuard(f.client, f.opts, func(context.Context, map[string]interface{}) (bool, error) { ran = true; return true, nil })
		if err != nil {
			t.Fatal(err)
		}
		_, err = guard(ctx, f.params)
		cancel()
		if cancelBeforeTool && (ran || !errors.Is(err, context.Canceled)) {
			t.Fatalf("canceled tool ran: %v", err)
		}
		if !cancelBeforeTool && (!ran || err != nil) {
			t.Fatal(err)
		}
		for _, e := range f.events {
			if e == "dispatch" {
				t.Fatal("unexpected dispatch")
			}
		}
	}
}

func TestGuardRequiresConfiguration(t *testing.T) {
	for _, edit := range []func(*guardFixture){
		func(f *guardFixture) { f.client = nil },
		func(f *guardFixture) { f.opts.Target = " " },
		func(f *guardFixture) { f.opts.ActionType = "" },
		func(f *guardFixture) { f.opts.Approvers = verify.ApproverTrustAnchor{} },
		func(f *guardFixture) { f.opts.ReportDispatch = 9 },
		func(f *guardFixture) { f.opts.ReportDispatch = 86401 },
	} {
		f := newGuardFixture(t)
		edit(f)
		if _, err := NewApprovalGuard(f.client, f.opts, func(context.Context, map[string]interface{}) (bool, error) { return true, nil }); err == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
}

func TestGuardReportsAnUnacknowledgedDispatchWithoutRetryingTool(t *testing.T) {
	f := newGuardFixture(t)
	f.dispatchRefused = true
	diagnosed, executed := 0, 0
	f.opts.OnDispatchError = func(nonce string, err error) {
		diagnosed++
		if nonce != f.nonce || err == nil {
			t.Error("missing report retry context")
		}
	}
	guard, err := NewApprovalGuard(f.client, f.opts, func(context.Context, map[string]interface{}) (bool, error) {
		executed++
		return true, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := guard(context.Background(), f.params)
	if !result || err != nil || diagnosed != 1 || executed != 1 {
		t.Fatalf("%v %v diagnostics=%d calls=%d", result, err, diagnosed, executed)
	}
}
