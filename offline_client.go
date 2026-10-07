package intyga

// The client half of offline approval (DIV §5a): telling "the gateway could not be asked" apart from
// "the gateway answered", the RequireApproval fallback, and reconciliation once connectivity returns.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// GatewayRefusedError is a non-2xx answer from a reachable gateway — a verdict, not an outage.
//
// Distinct from a transport failure on purpose: RequireApproval routes only the latter (and 5xx,
// infrastructure failing) into the DIV §5a offline fallback. A 403, 401 or 429 is the gateway
// refusing, and a refusal must not be answered by collecting signatures out of band.
type GatewayRefusedError struct {
	// StatusCode is the HTTP status the gateway answered with.
	StatusCode int
	// Body is the response body, as text.
	Body    string
	message string
}

func (e *GatewayRefusedError) Error() string { return e.message }

// GatewayUnreachableError means the gateway could not be asked at all: the request got no answer
// (connection refused, DNS, TLS, a timeout before the response arrived). It and a 5xx
// GatewayRefusedError are the only failures that may route RequireApproval to the DIV §5a offline
// path, and the ones a caller without the offline opt-in can tell an outage by. Err is the transport
// error, which is also its message.
type GatewayUnreachableError struct {
	Err error
}

func (e *GatewayUnreachableError) Error() string { return e.Err.Error() }
func (e *GatewayUnreachableError) Unwrap() error { return e.Err }

// couldNotAsk reports whether err means the gateway could not be asked (DIV §5a): no answer at all, or
// a 5xx from infrastructure in front of or inside it. A refusal below 500, a local error (blank
// Target, missing credentials) and an unreadable body are not.
func couldNotAsk(err error) bool {
	var refused *GatewayRefusedError
	if errors.As(err, &refused) {
		return refused.StatusCode >= 500
	}
	var unreachable *GatewayUnreachableError
	return errors.As(err, &unreachable)
}

// offlineFallback runs UseOfflineApproval for a RequireApproval call whose gateway could not be asked.
// cause describes that failure and err is it.
func (c *Client) offlineFallback(ctx context.Context, cause string, err error, actionDescription string, opts RequireApprovalOptions) (ApprovalResult, error) {
	// An agent-continuity approval is chained into the agent's signed session; an offline proof is
	// not, so it can never stand in for one.
	if opts.AgentContext != nil {
		return ApprovalResult{}, fmt.Errorf("agent continuity requests cannot fall back to an unchained offline proof: %w", err)
	}
	params := opts.Params
	if params == nil {
		params = map[string]interface{}{}
	}
	res, offlineErr := UseOfflineApproval(ctx, OfflineAction{
		Target:     opts.Target,
		ActionType: opts.ActionType,
		Display:    actionDescription,
		Params:     params,
	}, *opts.Offline)
	if offlineErr != nil {
		return ApprovalResult{}, fmt.Errorf("%s — and the offline approval did not complete: %w", cause, offlineErr)
	}
	receipt := res.Receipt
	return ApprovalResult{Status: StatusOfflineApproved, Receipt: &receipt, Nonce: res.Nonce}, nil
}

// ReconcileResult reports one ReconcileOfflineApprovals run.
type ReconcileResult struct {
	// Reported is how many buffered approvals the gateway acknowledged (and were cleared).
	Reported int
	// Failed is how many could not be reported, or could not be read; they stay buffered.
	Failed int
	// Reasons explains each failure, as "<nonce or file>: <reason>".
	Reasons []string
}

// ReconcileOfflineApprovals reports the offline approvals that happened while the gateway was
// unreachable (DIV §5a.7), POSTing each buffered record — receipt included, so the gateway re-verifies
// rather than taking the reporter's word for it — to /offline-approval/reconcile.
//
// Call it on reconnect: a scheduled retry, a health check, or service start. Until an approval is
// reported it exists only on the relying party's disk, and an unreported approval is
// indistinguishable from an unauthorized action. A record is cleared ONLY on a 2xx acknowledgement; a
// refusal or a network failure leaves it queued for the next attempt. A misconfigured client returns
// an error up front instead of failing every record.
func (c *Client) ReconcileOfflineApprovals(ctx context.Context, opts PendingOptions) (ReconcileResult, error) {
	var out ReconcileResult
	if _, err := c.Token(ctx); err != nil {
		return out, err
	}
	records, problems := readPending(opts.dir())
	for _, problem := range problems {
		out.Failed++
		out.Reasons = append(out.Reasons, problem)
	}
	for _, record := range records {
		body := map[string]interface{}{
			"nonce":      record.Nonce,
			"usedAt":     record.UsedAt,
			"target":     record.Target,
			"actionType": record.ActionType,
			"display":    record.Display,
			"receipt":    record.Receipt,
		}
		if record.DelegationNonce != "" {
			body["delegationNonce"] = record.DelegationNonce
		}
		err := c.doJSON(ctx, http.MethodPost, "/offline-approval/reconcile", body, nil)
		if err == nil {
			ClearPendingApproval(record.Nonce, opts)
			out.Reported++
			continue
		}
		out.Failed++
		var refused *GatewayRefusedError
		if errors.As(err, &refused) {
			out.Reasons = append(out.Reasons, strings.TrimSpace(fmt.Sprintf("%s: %d %s", record.Nonce, refused.StatusCode, refused.Body)))
		} else {
			out.Reasons = append(out.Reasons, fmt.Sprintf("%s: %v", record.Nonce, err))
		}
	}
	return out, nil
}
