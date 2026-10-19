package intyga

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	verify "github.com/intyga-dev/sdk-go/v2/verify"
)

// Tool is a framework-neutral tool callback. Only the detached, approved arguments are passed in.
type Tool[R any] func(context.Context, map[string]interface{}) (R, error)

// ApprovalGuardOptions binds one tool to the relying party's own target, action and approver trust.
// There is no unverified, auto-approved or offline execution path through this guard.
type ApprovalGuardOptions struct {
	Target, ActionType, Description string
	Approvers                       verify.ApproverTrustAnchor
	Requirement                     *verify.RequirementFloor
	ExpectedOrigin, ExpectedRpID    string
	// TenantID is the independently trusted tenant expected on DIV v2 receipts: supply it from your
	// trust anchor or other independently trusted configuration; it is never inferred from the gateway
	// response or the receipt. Empty keeps v1-only verification, which refuses every v2 receipt the
	// hosted gateway issues.
	TenantID          string
	Timeout, Interval time.Duration
	// ReportDispatch is the evidence window in seconds (10..86400); zero disables reporting.
	ReportDispatch int
	// OnDispatchError receives a failed post-execution report so the caller can retry with its nonce.
	// It must not log credentials. A panic in this diagnostic callback cannot replace the tool outcome.
	OnDispatchError func(nonce string, err error)
}

// ApprovalGuardError is a refusal before the tool ran, never a successful tool result.
type ApprovalGuardError struct{ Status, Reason string }

func (e *ApprovalGuardError) Error() string {
	return fmt.Sprintf("intyga: tool approval %s: %s", e.Status, e.Reason)
}

// NewApprovalGuard wraps a tool: snapshot -> approve -> verify locally -> consume -> execute.
// Params must be a canonical JSON object; decoded numbers are float64 (JSON/JavaScript semantics).
// A successful consume response MUST have OK=true. A dispatch report runs after a return or panic, and is best
// effort: its failure cannot turn a completed action into an error that a framework might retry.
func NewApprovalGuard[R any](client *Client, opts ApprovalGuardOptions, tool Tool[R]) (Tool[R], error) {
	if client == nil || tool == nil {
		return nil, errors.New("intyga: approval guard requires a client and a tool")
	}
	if strings.TrimSpace(opts.Target) == "" || strings.TrimSpace(opts.ActionType) == "" {
		return nil, errors.New("intyga: approval guard requires Target and ActionType")
	}
	if len(opts.Approvers.PublicKeys) == 0 && (len(opts.Approvers.DIDs) == 0 || (opts.Approvers.ResolveKey == nil && opts.Approvers.ResolveKeys == nil)) {
		return nil, errors.New("intyga: approval guard requires caller-provisioned approvers")
	}
	if opts.ReportDispatch != 0 && (opts.ReportDispatch < 10 || opts.ReportDispatch > 86400) {
		return nil, errors.New("intyga: ReportDispatch must be zero or 10..86400 seconds")
	}
	opts.Approvers.PublicKeys = append([]string(nil), opts.Approvers.PublicKeys...)
	opts.Approvers.DIDs = append([]string(nil), opts.Approvers.DIDs...)
	if opts.Requirement != nil {
		floor := *opts.Requirement
		opts.Requirement = &floor
	}
	if opts.Description == "" {
		opts.Description = "Execute " + opts.ActionType
	}
	return func(ctx context.Context, params map[string]interface{}) (R, error) {
		var zero R
		if params == nil {
			return zero, errors.New("intyga: tool arguments must be a JSON object")
		}
		canonical, err := verify.StableStringify(params)
		if err != nil {
			return zero, fmt.Errorf("intyga: invalid tool arguments: %w", err)
		}
		var bound map[string]interface{}
		if err := json.Unmarshal([]byte(canonical), &bound); err != nil {
			return zero, err
		}
		approval, err := client.RequireApproval(ctx, opts.Description, RequireApprovalOptions{
			AuthorizeOptions: AuthorizeOptions{Target: opts.Target, ActionType: opts.ActionType, Params: bound},
			Timeout:          opts.Timeout, Interval: opts.Interval,
		})
		if err != nil {
			return zero, err
		}
		if approval.Status != StatusApproved {
			return zero, &ApprovalGuardError{string(approval.Status), "the action was not approved"}
		}
		if approval.Receipt == nil || approval.Nonce == "" {
			return zero, &ApprovalGuardError{"UNVERIFIED", "approval has no receipt or nonce"}
		}
		var tenantID *string
		if opts.TenantID != "" {
			tenant := opts.TenantID
			tenantID = &tenant
		}
		checked := verify.VerifyApprovalReceipt(*approval.Receipt, verify.Expected{
			TenantID: tenantID,
			Target:   opts.Target, ActionType: opts.ActionType, Params: bound, Nonce: approval.Nonce,
			Approvers: opts.Approvers, Requirement: opts.Requirement,
		}, verify.VerifyOptions{ExpectedOrigin: opts.ExpectedOrigin, ExpectedRpID: opts.ExpectedRpID})
		if !checked.OK {
			return zero, &ApprovalGuardError{"UNVERIFIED", checked.Reason}
		}
		consumed, err := client.Consume(ctx, approval.Nonce, opts.Target, opts.ActionType, bound)
		if err != nil {
			return zero, err
		}
		if !consumed.OK {
			return zero, &ApprovalGuardError{"NOT_CONSUMED", consumed.Reason}
		}
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if opts.ReportDispatch != 0 {
			defer reportToolDispatch(client, ctx, approval.Nonce, opts)
		}
		return tool(ctx, bound)
	}, nil
}

func reportToolDispatch(client *Client, ctx context.Context, nonce string, opts ApprovalGuardOptions) {
	// Includes transport/diagnostic panics: the tool's result or original panic must survive.
	defer func() { _ = recover() }()
	// A tool can cancel its context after sending a command. Reporting gets a separate bounded wait.
	reportCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	reported, err := client.ReportDispatched(reportCtx, nonce, opts.ReportDispatch)
	if err == nil && !reported.OK {
		err = errors.New("intyga: dispatch report was not acknowledged")
	}
	if err != nil {
		if opts.OnDispatchError != nil {
			opts.OnDispatchError(nonce, err)
		} else {
			log.Print("INTYGA: dispatch reporting failed; retry ReportDispatched for the consumed approval")
		}
	}
}
