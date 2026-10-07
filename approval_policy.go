package intyga

// Exact-ID approval-rule selection (approval policy version 3), ported from the TypeScript reference
// packages/verify/src/approval-policy.ts. Pure: no crypto, database or network.
//
// Only version 3 is ported. It is the only version a v1 trust bundle carries (the gateway refuses to
// export a bundle for anything else), and the legacy substring/ranking modes exist in the reference
// solely for gateway back-compatibility. Display text never selects a rule here.

import (
	"regexp"
	"strings"
	"unicode"
)

// PolicyRule is one approval rule, as far as rule selection and the baseline-conflict check read it.
// It mirrors PolicyRule in packages/verify/src/approval-policy.ts; the optional fields of the
// reference are nil slices or nil pointers here.
type PolicyRule struct {
	// ActionPattern is an exact action ID, or "*" for the tenant baseline.
	ActionPattern string `json:"actionPattern"`
	// RequiredApprovals is int64, not int, so a large value means the same on 32- and 64-bit builds:
	// anything up to 2^53-1 (JavaScript's safe-integer bound) is a valid quorum that no rule can meet.
	RequiredApprovals        int64    `json:"requiredApprovals"`
	ApproverDids             []string `json:"approverDids"`
	RequireHardwareKey       bool     `json:"requireHardwareKey"`
	AllowedAaguids           []string `json:"allowedAaguids"`
	RequesterCannotApprove   bool     `json:"requesterCannotApprove"`
	RequireAttestedRequester bool     `json:"requireAttestedRequester"`
	AllowedIssuers           []string `json:"allowedIssuers"`
	ApproverGroupIds         []string `json:"approverGroupIds,omitempty"`
	EscalationApproverDids   []string `json:"escalationApproverDids"`
	EscalationGroupIds       []string `json:"escalationGroupIds,omitempty"`
	EscalateAfterSeconds     *int64   `json:"escalateAfterSeconds"`
	AutoApproveRequesterDid  *string  `json:"autoApproveRequesterDid"`
	AutoApproveDayOfWeek     *int     `json:"autoApproveDayOfWeek"`
	AutoApproveWindowStart   *string  `json:"autoApproveWindowStart"`
	AutoApproveWindowEnd     *string  `json:"autoApproveWindowEnd"`
}

// ApprovalPolicyConflict reports a policy that cannot be resolved without guessing. Fields names the
// constraints in conflict, e.g. "requiredApprovals" or "invalidOrDuplicateActionId".
type ApprovalPolicyConflict struct {
	Fields []string
}

func (e *ApprovalPolicyConflict) Error() string {
	return "Conflicting approval requirements: " + strings.Join(e.Fields, ", ")
}

// maxSafeInteger is JavaScript's Number.MAX_SAFE_INTEGER. The reference validates integers with
// Number.isSafeInteger, so the same bound applies here.
const maxSafeInteger = 1<<53 - 1

var approvalActionID = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*(?:[._:/-][A-Za-z0-9]+)*$`)

// ValidApprovalActionID reports whether value is a stable action ID of the version-3 grammar.
func ValidApprovalActionID(value string) bool {
	return len(value) <= 200 && approvalActionID.MatchString(value)
}

// ValidateExactApprovalPolicy validates a whole version-3 policy, so that a corrupt or duplicate rule
// cannot hide behind another action: every pattern is "*" or a valid action ID, unique ignoring
// case; every quorum is an integer of at least 1; a non-empty policy has a "*" baseline; and no rule
// drops a constraint the baseline imposes (LostApprovalConstraints). It returns an
// *ApprovalPolicyConflict, or nil.
func ValidateExactApprovalPolicy(rules []PolicyRule) error {
	seen := map[string]bool{}
	for _, rule := range rules {
		lower := strings.ToLower(rule.ActionPattern)
		if (rule.ActionPattern != "*" && !ValidApprovalActionID(rule.ActionPattern)) ||
			rule.RequiredApprovals < 1 || rule.RequiredApprovals > maxSafeInteger || seen[lower] {
			return &ApprovalPolicyConflict{Fields: []string{"invalidOrDuplicateActionId"}}
		}
		seen[lower] = true
	}
	if len(rules) > 0 && !seen["*"] {
		return &ApprovalPolicyConflict{Fields: []string{"missingBaseline"}}
	}
	baseline := -1
	for i, rule := range rules {
		if rule.ActionPattern == "*" {
			baseline = i
			break
		}
	}
	if baseline < 0 {
		return nil
	}
	for _, rule := range rules {
		if fields := LostApprovalConstraints(rule, rules[baseline]); len(fields) > 0 {
			return &ApprovalPolicyConflict{Fields: fields}
		}
	}
	return nil
}

// LostApprovalConstraints lists the constraints of other that selected does not preserve. Empty
// eligible lists denote the same owner fallback, NOT unrestricted eligibility.
func LostApprovalConstraints(selected, other PolicyRule) []string {
	var lost []string
	if selected.RequiredApprovals < other.RequiredApprovals {
		lost = append(lost, "requiredApprovals")
	}
	if other.RequireHardwareKey && !selected.RequireHardwareKey {
		lost = append(lost, "requireHardwareKey")
	}
	if other.RequesterCannotApprove && !selected.RequesterCannotApprove {
		lost = append(lost, "requesterCannotApprove")
	}
	if other.RequireAttestedRequester && !selected.RequireAttestedRequester {
		lost = append(lost, "requireAttestedRequester")
	}
	if len(other.AllowedAaguids) > 0 && (len(selected.AllowedAaguids) == 0 || !subset(selected.AllowedAaguids, other.AllowedAaguids)) {
		lost = append(lost, "allowedAaguids")
	}
	if len(other.AllowedIssuers) > 0 && (len(selected.AllowedIssuers) == 0 || !subset(selected.AllowedIssuers, other.AllowedIssuers)) {
		lost = append(lost, "allowedIssuers")
	}
	// Different unresolved groups cannot be compared safely. DB callers expand them first.
	if !sameSet(selected.ApproverGroupIds, other.ApproverGroupIds) {
		lost = append(lost, "approverGroups")
	}
	a, b := selected.ApproverDids, other.ApproverDids
	if (len(a) == 0) != (len(b) == 0) || !subset(a, b) {
		lost = append(lost, "approverDids")
	}
	// Escalation widens eligibility with time. Conservatively require the same schedule and added set.
	if !sameInt64(selected.EscalateAfterSeconds, other.EscalateAfterSeconds) ||
		!sameSet(selected.EscalationApproverDids, other.EscalationApproverDids) ||
		!sameSet(selected.EscalationGroupIds, other.EscalationGroupIds) {
		lost = append(lost, "escalation")
	}
	if truthy(selected.AutoApproveRequesterDid) || truthy(other.AutoApproveRequesterDid) {
		if !sameWindow(selected, other) ||
			selected.RequiredApprovals != other.RequiredApprovals ||
			selected.RequireHardwareKey != other.RequireHardwareKey ||
			selected.RequesterCannotApprove != other.RequesterCannotApprove ||
			selected.RequireAttestedRequester != other.RequireAttestedRequester ||
			!sameSet(a, b) ||
			!sameSet(selected.AllowedAaguids, other.AllowedAaguids) ||
			!sameSet(selected.AllowedIssuers, other.AllowedIssuers) {
			lost = append(lost, "autoApproval")
		}
	}
	return lost
}

// SelectExactApprovalRule selects the rule for actionType under approval policy version 3 and returns
// its index in rules, or -1 when no rule applies. It validates the whole policy first
// (ValidateExactApprovalPolicy), refuses the OWNER_APPROVAL fallback, refuses a differently cased
// spelling of a configured ID rather than letting it fall to a weaker baseline, and falls back to
// the "*" rule only when unmatched is "BASELINE". Display text is not an input: it never selects.
func SelectExactApprovalRule(rules []PolicyRule, actionType, unmatched string) (int, error) {
	if err := ValidateExactApprovalPolicy(rules); err != nil {
		return -1, err
	}
	if unmatched == "OWNER_APPROVAL" {
		return -1, &ApprovalPolicyConflict{Fields: []string{"invalidFallback"}}
	}
	if actionType == "" || !ValidApprovalActionID(actionType) {
		return -1, nil
	}
	// IDs remain case-sensitive on the wire, but a differently cased spelling of a protected ID must
	// not drop to a weaker baseline. Require the caller to use the configured spelling.
	for _, r := range rules {
		if r.ActionPattern != "*" && r.ActionPattern != actionType &&
			strings.ToLower(r.ActionPattern) == strings.ToLower(actionType) {
			return -1, &ApprovalPolicyConflict{Fields: []string{"actionIdCaseMismatch"}}
		}
	}
	for i, r := range rules {
		if r.ActionPattern == actionType {
			return i, nil
		}
	}
	if unmatched == "BASELINE" {
		for i, r := range rules {
			if r.ActionPattern == "*" {
				return i, nil
			}
		}
	}
	return -1, nil
}

func subset(a, b []string) bool {
	for _, v := range a {
		found := false
		for _, w := range b {
			if v == w {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func sameSet(a, b []string) bool { return subset(a, b) && subset(b, a) }

func sameInt64(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameString(a, b *string) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// sameWindow compares the auto-approval window the reference keys as
// JSON.stringify([requesterDid, dayOfWeek, windowStart, windowEnd]).
func sameWindow(a, b PolicyRule) bool {
	return sameString(a.AutoApproveRequesterDid, b.AutoApproveRequesterDid) &&
		sameInt(a.AutoApproveDayOfWeek, b.AutoApproveDayOfWeek) &&
		sameString(a.AutoApproveWindowStart, b.AutoApproveWindowStart) &&
		sameString(a.AutoApproveWindowEnd, b.AutoApproveWindowEnd)
}

// truthy is JavaScript truthiness for an optional string: present and non-empty.
func truthy(s *string) bool { return s != nil && *s != "" }

// jsTrim is String.prototype.trim: JavaScript's whitespace and line terminators, which differ from
// unicode.IsSpace at U+0085 (not JS whitespace) and U+FEFF (JS whitespace).
func jsTrim(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		switch r {
		case '\t', '\n', '\v', '\f', '\r', '\u2028', '\u2029', '\ufeff':
			return true
		}
		return unicode.Is(unicode.Zs, r)
	})
}
