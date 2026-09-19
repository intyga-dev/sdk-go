// Package intyga is the Go client for Intyga. The primitive is uniform: request a challenge → a human
// approves with a passkey or security key → poll until resolved. It works for AI agents, humans, and
// any backend service; the only difference is which API key/token you hold.
//
// Offline receipt verification lives in the standalone github.com/intyga-dev/sdk-go/verify package;
// this client returns its ApprovalReceipt type so a relying party can re-verify what was signed.
package intyga

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	verify "github.com/intyga-dev/sdk-go/verify"
)

// ApprovalReceipt is re-exported from verify-go so callers can verify offline without a second import.
type ApprovalReceipt = verify.ApprovalReceipt

// ApprovalStatus is the lifecycle state of a challenge.
//
// CONSUMED means the approval was real but has ALREADY BEEN REDEEMED — single-use is enforced by the
// gateway. Treat it as not authorized: only APPROVED permits execution.
type ApprovalStatus string

const (
	StatusApproved ApprovalStatus = "APPROVED"
	StatusConsumed ApprovalStatus = "CONSUMED"
	StatusDenied   ApprovalStatus = "DENIED"
	StatusExpired  ApprovalStatus = "EXPIRED"
	StatusPending  ApprovalStatus = "PENDING"
)

// ClientOptions configures a Client.
type ClientOptions struct {
	GatewayURL string
	// Token is a pre-minted bearer token (agent or human). If empty, ClientID/ClientSecret are exchanged.
	// An explicit Token is used as-is: it is never re-exchanged, and a 401 on it is returned to the
	// caller rather than retried, because there is no credential behind it to exchange again.
	Token string
	// ClientID / ClientSecret are exchanged for a bearer token via client-credentials when Token is empty.
	// The exchanged token is cached and re-exchanged automatically shortly before the `expires_in` the
	// gateway reported (see Token), so a long-lived Client keeps working across token lifetimes.
	ClientID     string
	ClientSecret string
	// HTTPClient is optional; a sensible default with a 30s timeout is used when nil.
	HTTPClient *http.Client
}

// Client talks to a Intyga gateway. It is safe for concurrent use.
type Client struct {
	opts ClientOptions
	http *http.Client

	// mu guards the token cache. It is held across the exchange itself so that concurrent first
	// callers (or concurrent callers at refresh time) perform one exchange, not one each.
	mu           sync.Mutex
	cachedToken  string
	cachedExpiry time.Time     // when the cached token expires; zero when the exchange reported no expires_in
	cachedMargin time.Duration // how long before cachedExpiry the cache stops being served

	// now is the clock the expiry check reads. It exists so tests can advance time without sleeping;
	// it defaults to time.Now.
	now func() time.Time
}

// NewClient constructs a Client. It does not perform any network I/O.
func NewClient(opts ClientOptions) *Client {
	httpClient := opts.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{opts: opts, http: httpClient, now: time.Now}
}

// maxRefreshMargin caps how early a token is re-exchanged ahead of its expiry. The margin is
// min(maxRefreshMargin, expires_in/10): 60s for anything a gateway mints today, and proportionally
// less for a very short-lived token so it is not refreshed on every call.
const maxRefreshMargin = 60 * time.Second

// refreshMargin returns how far ahead of expiry a token with the given lifetime is refreshed.
func refreshMargin(ttl time.Duration) time.Duration {
	margin := ttl / 10
	if margin > maxRefreshMargin {
		margin = maxRefreshMargin
	}
	return margin
}

// AuthorizeOptions carries the structured, WYSIWYS-bound details of an approval request.
type AuthorizeOptions struct {
	// Target identifies the relying party / execution environment this approval is bound to
	// (DIV §3 Invariant 5, Target Isolation). REQUIRED, and asserted from YOUR own identity.
	//
	// Leaving it empty is not neutral: the gateway defaults a missing target to the literal
	// "global", so the signed intent binds no environment and an approval minted for this service
	// verifies at every other relying party that also asserts "global". That is exactly the
	// cross-service replay Target Isolation exists to prevent, which is why this is rejected
	// client-side rather than quietly defaulted.
	Target string
	// ActionType is the action identifier, e.g. "wire_transfer". Bound into the signed payload.
	ActionType string
	// Params are the exact structured variables that will execute — displayed to the approver AND signed.
	Params map[string]interface{}
	// TimeoutSeconds optionally overrides the server's default challenge TTL.
	TimeoutSeconds int
}

// AuthorizeResponse is returned by Authorize.
type AuthorizeResponse struct {
	Nonce  string         `json:"nonce"`
	Status ApprovalStatus `json:"status"`
}

// ConsumeResult is returned by Consume.
type ConsumeResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// ApprovalResult is the current state of a challenge.
type ApprovalResult struct {
	Status        ApprovalStatus   `json:"status"`
	SignatureHash string           `json:"signatureHash,omitempty"`
	Receipt       *ApprovalReceipt `json:"receipt,omitempty"`
	// Nonce is the challenge this result belongs to. Set by RequireApproval so callers can pass it as
	// expected.Nonce to verify.VerifyApprovalReceipt and record it as redeemed for their own single-use check.
	Nonce string `json:"nonce,omitempty"`
}

// VerifyResult is the public witness lookup response.
type VerifyResult struct {
	Verified      bool   `json:"verified"`
	Status        string `json:"status"`
	DocumentHash  string `json:"documentHash"`
	SignerDid     string `json:"signerDid,omitempty"`
	SignedAt      string `json:"signedAt,omitempty"`
	SignatureHash string `json:"signatureHash,omitempty"`
}

// Token resolves a bearer token: the provided one, a cached exchange, or a fresh client-credentials exchange.
//
// An exchanged token is served from the cache until min(60s, expires_in/10) before the expiry the
// gateway reported in `expires_in`, then exchanged again. A response without a numeric `expires_in`
// is cached for the life of the Client (the pre-refresh behaviour); a 401 from the gateway on such a
// token is what invalidates it (see doJSON).
func (c *Client) Token(ctx context.Context) (string, error) {
	if c.opts.Token != "" {
		return c.opts.Token, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedToken != "" && (c.cachedExpiry.IsZero() || c.now().Before(c.cachedExpiry.Add(-c.cachedMargin))) {
		return c.cachedToken, nil
	}
	if c.opts.ClientID == "" || c.opts.ClientSecret == "" {
		return "", fmt.Errorf("provide Token, or ClientID + ClientSecret")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.opts.GatewayURL+"/oauth/token", nil)
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(c.opts.ClientID, c.opts.ClientSecret)
	res, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return "", fmt.Errorf("token exchange failed: %d %s", res.StatusCode, string(body))
	}
	var data struct {
		AccessToken string `json:"access_token"`
		// Decoded separately below so a missing or non-numeric value means "no expiry known" rather
		// than failing the whole exchange.
		ExpiresIn json.RawMessage `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &data); err != nil {
		return "", err
	}
	c.cachedToken = data.AccessToken
	c.cachedExpiry = time.Time{}
	c.cachedMargin = 0
	var expiresIn float64
	if len(data.ExpiresIn) > 0 && json.Unmarshal(data.ExpiresIn, &expiresIn) == nil && expiresIn > 0 {
		ttl := time.Duration(expiresIn * float64(time.Second))
		c.cachedExpiry = c.now().Add(ttl)
		c.cachedMargin = refreshMargin(ttl)
	}
	return data.AccessToken, nil
}

// invalidateToken drops the cached token if it is still the one the caller saw fail. A token that
// another goroutine has already replaced is left alone, so a stale 401 cannot discard a fresh exchange.
func (c *Client) invalidateToken(failed string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cachedToken == failed {
		c.cachedToken = ""
		c.cachedExpiry = time.Time{}
		c.cachedMargin = 0
	}
}

// Authorize creates an approval challenge and returns its nonce and initial status.
func (c *Client) Authorize(ctx context.Context, actionDescription string, opts AuthorizeOptions) (AuthorizeResponse, error) {
	var out AuthorizeResponse
	params := opts.Params
	if params == nil {
		params = map[string]interface{}{}
	}
	if strings.TrimSpace(opts.Target) == "" {
		return out, errors.New("intyga: AuthorizeOptions.Target is required (DIV Target Isolation): " +
			"name the relying party / execution environment this approval is bound to")
	}
	body := map[string]interface{}{
		"target":            opts.Target,
		"actionDescription": actionDescription,
		"params":            params,
	}
	if opts.ActionType != "" {
		body["actionType"] = opts.ActionType
	}
	if opts.TimeoutSeconds > 0 {
		body["timeout"] = opts.TimeoutSeconds
	}
	if err := c.doJSON(ctx, http.MethodPost, "/authorize", body, &out); err != nil {
		return out, err
	}
	return out, nil
}

// Consume performs execution-time re-binding: after APPROVED, call this immediately before running the
// action so the gateway confirms the approved signature matches the exact instruction and marks it single-use.
//
// target is REQUIRED by the gateway's authorizationConsume schema. Omitting it was a 400 on every
// call, which made single-use redemption unreachable from this SDK entirely: the challenge stayed
// APPROVED rather than CONSUMED, and stayed replayable by any holder of the same token until it
// expired naturally.
func (c *Client) Consume(ctx context.Context, nonce, target, actionType string, params map[string]interface{}) (ConsumeResult, error) {
	var out ConsumeResult
	if params == nil {
		params = map[string]interface{}{}
	}
	if strings.TrimSpace(target) == "" {
		return out, errors.New("intyga: Consume requires the same target the approval was bound to")
	}
	body := map[string]interface{}{
		"nonce":      nonce,
		"target":     target,
		"actionType": actionType,
		"params":     params,
	}
	if err := c.doJSON(ctx, http.MethodPost, "/authorize/verify", body, &out); err != nil {
		return out, err
	}
	return out, nil
}

// Status polls a challenge's current state (non-blocking).
func (c *Client) Status(ctx context.Context, nonce string) (ApprovalResult, error) {
	var out ApprovalResult
	if err := c.doJSON(ctx, http.MethodGet, "/authorize/"+url.PathEscape(nonce), nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

// RequireApprovalOptions extends AuthorizeOptions with polling controls.
type RequireApprovalOptions struct {
	AuthorizeOptions
	// Timeout is the total wait window. Defaults to 120s. It is also sent to the gateway as the challenge
	// TTL so the challenge cannot outlive the wait.
	Timeout time.Duration
	// Interval is the poll interval. Defaults to 2s.
	Interval time.Duration
}

// maxPollErrors is how many back-to-back polling failures before RequireApproval declares the gateway unreachable.
const maxPollErrors = 5

// RequireApproval is the core zero-trust gate: call it immediately before a high-risk action. It creates
// the challenge and blocks until the human approves/denies with their passkey (or it times out or ctx is done).
func (c *Client) RequireApproval(ctx context.Context, actionDescription string, opts RequireApprovalOptions) (ApprovalResult, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	interval := opts.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}

	// Forward the caller's options wholesale and override only the timeout. Rebuilding this struct
	// field-by-field silently drops anything added to AuthorizeOptions later — which is how Target
	// would have gone missing here even after being made required.
	authOpts := opts.AuthorizeOptions
	authOpts.TimeoutSeconds = int((timeout + time.Second - 1) / time.Second) // ceil to seconds

	authRes, err := c.Authorize(ctx, actionDescription, authOpts)
	if err != nil {
		return ApprovalResult{}, err
	}
	nonce := authRes.Nonce

	deadline := time.Now().Add(timeout)
	consecutiveErrors := 0
	for {
		// A human approval can outlast a transient 502 or socket hangup — don't discard the whole wait
		// over one bad poll. Only give up once the gateway looks genuinely unreachable.
		r, err := c.Status(ctx, nonce)
		if err != nil {
			consecutiveErrors++
			if consecutiveErrors >= maxPollErrors {
				return ApprovalResult{}, fmt.Errorf("polling failed after %d consecutive errors: %w", maxPollErrors, err)
			}
		} else {
			consecutiveErrors = 0
			if r.Status != StatusPending {
				r.Nonce = nonce
				return r, nil
			}
		}

		if time.Now().After(deadline) {
			return ApprovalResult{Status: StatusExpired, Nonce: nonce}, nil
		}
		select {
		case <-ctx.Done():
			return ApprovalResult{}, ctx.Err()
		case <-time.After(interval):
		}
	}
}

// Verify is the public witness lookup: has this document hash been signed, by whom, and when?
func (c *Client) Verify(ctx context.Context, documentHash string) (VerifyResult, error) {
	var out VerifyResult
	if err := c.doJSON(ctx, http.MethodGet, "/verify/"+url.PathEscape(documentHash), nil, &out); err != nil {
		return out, err
	}
	return out, nil
}

// doJSON performs an authenticated JSON request and decodes the response into out.
//
// A 401 on an exchanged token (never on an explicit ClientOptions.Token) invalidates the cache and
// retries exactly once with a fresh exchange — this covers clock skew against the proactive refresh
// and a gateway that shortened its token lifetime under a running client. A second 401 is returned.
func (c *Client) doJSON(ctx context.Context, method, path string, body interface{}, out interface{}) error {
	var buf []byte
	if body != nil {
		var err error
		buf, err = json.Marshal(body)
		if err != nil {
			return err
		}
	}
	retried := false
	for {
		token, err := c.Token(ctx)
		if err != nil {
			return err
		}
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(buf)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.opts.GatewayURL+path, reader)
		if err != nil {
			return err
		}
		req.Header.Set("authorization", "Bearer "+token)
		if body != nil {
			req.Header.Set("content-type", "application/json")
		}
		res, err := c.http.Do(req)
		if err != nil {
			return err
		}
		respBody, _ := io.ReadAll(res.Body)
		res.Body.Close()
		if res.StatusCode == http.StatusUnauthorized && c.opts.Token == "" && !retried {
			retried = true
			c.invalidateToken(token)
			continue
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return fmt.Errorf("%s %s failed: %d %s", method, path, res.StatusCode, string(respBody))
		}
		if out == nil {
			return nil
		}
		return json.Unmarshal(respBody, out)
	}
}
