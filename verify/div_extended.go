package verify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CanonicalAgentAuthorityPayload reproduces the DIV §5b signed bytes.
func CanonicalAgentAuthorityPayload(target string, actionPatterns []string, display, agentDID string, requester RequesterIdentity, requirement ApprovalRequirement, nonce, sealedAt, expiresAt string, parentReceiptHash ...string) (string, error) {
	req, rq := canonicalCommon(requester, requirement)
	patterns := append([]string(nil), actionPatterns...)
	sort.Slice(patterns, func(i, j int) bool { return utf16Less(patterns[i], patterns[j]) })
	if patterns == nil {
		patterns = []string{}
	}
	var parent interface{}
	if len(parentReceiptHash) > 0 && parentReceiptHash[0] != "" {
		parent = parentReceiptHash[0]
	}
	return StableStringify(map[string]interface{}{"v": DivVersion, "type": DivAgentAuthorityType, "target": target, "actionPatterns": patterns, "display": display, "agent": map[string]interface{}{"did": agentDID}, "parentReceiptHash": parent, "requester": req, "requirement": rq, "nonce": nonce, "sealedAt": sealedAt, "expiresAt": expiresAt})
}

// CanonicalPlatformIntentPayload reproduces the DIV §5c hash-only signed bytes.
func CanonicalPlatformIntentPayload(payloadHash, rpID, subjectExternalID, signedAt, expiresAt, nonce string) (string, error) {
	return StableStringify(map[string]interface{}{"v": DivVersion, "type": DivPlatformIntentType, "hashAlg": "SHA-256", "payloadHash": payloadHash, "rpId": rpID, "subject": map[string]interface{}{"externalId": subjectExternalID}, "signedAt": signedAt, "expiresAt": expiresAt, "nonce": nonce})
}

type PlatformReceipt = ApprovalReceipt
type PlatformReceiptExpectation struct {
	Approvers                                   ApproverTrustAnchor
	PayloadHash, RpID, Nonce, SubjectExternalID string
}

func VerifyPlatformReceipt(receipt PlatformReceipt, expected PlatformReceiptExpectation, opts VerifyOptions) VerifyResult {
	var f canonicalFields
	if json.Unmarshal([]byte(receipt.CanonicalPayload), &f) != nil || f.V == nil || *f.V != DivVersion {
		return VerifyResult{Reason: "unsupported DIV payload version"}
	}
	if f.Type != DivPlatformIntentType {
		return VerifyResult{Reason: "payload is not a div-platform-intent"}
	}
	if expected.Nonce == "" {
		return VerifyResult{Reason: "expected.Nonce is required"}
	}
	if f.Nonce != expected.Nonce {
		return VerifyResult{Reason: "receipt is for a different challenge"}
	}
	if len(expected.PayloadHash) != 64 || strings.ToLower(expected.PayloadHash) != expected.PayloadHash || !isHash64(expected.PayloadHash) {
		return VerifyResult{Reason: "expected.PayloadHash must be the 64-character lowercase hex SHA-256 you recomputed yourself"}
	}
	if expected.RpID == "" {
		return VerifyResult{Reason: "expected.RpID is required — it must be YOUR registered RP ID"}
	}
	if opts.ExpectedRpID != "" && opts.ExpectedRpID != expected.RpID {
		return VerifyResult{Reason: "opts.ExpectedRpID conflicts with expected.RpID — pass the RP ID once"}
	}
	if f.Subject == nil || f.Subject.ExternalID == "" {
		return VerifyResult{Reason: "receipt missing subject.externalId"}
	}
	if expected.SubjectExternalID != "" && expected.SubjectExternalID != f.Subject.ExternalID {
		return VerifyResult{Reason: "receipt was signed by a different subject"}
	}
	recomputed, err := CanonicalPlatformIntentPayload(expected.PayloadHash, expected.RpID, f.Subject.ExternalID, f.SignedAt, f.ExpiresAt, expected.Nonce)
	if err != nil || recomputed != receipt.CanonicalPayload {
		return VerifyResult{Reason: "payloadHash/rpId do not match what was signed"}
	}
	signed, e1 := time.Parse(time.RFC3339, f.SignedAt)
	expiry, e2 := time.Parse(time.RFC3339, f.ExpiresAt)
	if e1 != nil {
		return VerifyResult{Reason: "signedAt is not a valid RFC3339 timestamp"}
	}
	if e2 != nil {
		return VerifyResult{Reason: "expiresAt is not a valid RFC3339 timestamp"}
	}
	if expiry.Before(signed) {
		return VerifyResult{Reason: "receipt expires before it was signed"}
	}
	now, skew := evaluationTime(opts)
	if signed.After(now.Add(skew)) {
		return VerifyResult{Reason: "receipt is signed in the future (DIV §5c.3)"}
	}
	if !opts.AllowExpired && now.After(expiry.Add(skew)) {
		return VerifyResult{Reason: "proof has expired (set AllowExpired for audit re-verification)"}
	}
	if receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
		return VerifyResult{Reason: "a platform receipt cannot be auto-approved — there is no signature to verify"}
	}
	w := witnessesOf(receipt)
	if len(w) == 0 {
		return VerifyResult{Reason: "receipt missing signature material"}
	}
	if len(w) > MaxWitnesses {
		return VerifyResult{Reason: fmt.Sprintf("receipt carries %d witnesses, above the %d this verifier will process", len(w), MaxWitnesses)}
	}
	opts.ExpectedRpID = expected.RpID
	verified := map[string]bool{}
	failures := []string{}
	for _, x := range w {
		if x.SigAlg == nil || *x.SigAlg != "WEBAUTHN" {
			failures = append(failures, fmt.Sprintf("signer %s used a bare key; platform receipts are WebAuthn-only", x.SignerDID))
			continue
		}
		cs, r := candidateKeys(expected.Approvers, x, nil)
		if r != "" {
			failures = append(failures, r)
			continue
		}
		for _, c := range cs {
			if verifyWitness(x, c[0], receipt, opts) == "" {
				verified[c[1]] = true
				break
			}
		}
	}
	if len(verified) < 1 {
		return VerifyResult{Reason: "no valid subject signature" + foldFailures(failures)}
	}
	out := make([]string, 0, len(verified))
	for k := range verified {
		out = append(out, k)
	}
	sort.Strings(out)
	return VerifyResult{OK: true, Signers: out}
}

type AgentAuthorityExpectation struct {
	Approvers        ApproverTrustAnchor
	Target, AgentDID string
}
type VerifiedAgentAuthority struct {
	AgentDID, Target    string
	ActionPatterns      []string
	Nonce               string
	Signers             []string
	SealedAt, ExpiresAt string
	ParentReceiptHash   string
}

func VerifyAgentAuthority(receipt ApprovalReceipt, expected AgentAuthorityExpectation, opts VerifyOptions) (VerifyResult, *VerifiedAgentAuthority) {
	var f canonicalFields
	if json.Unmarshal([]byte(receipt.CanonicalPayload), &f) != nil || f.V == nil || *f.V != DivVersion {
		return VerifyResult{Reason: "unsupported DIV payload version"}, nil
	}
	if f.Type != DivAgentAuthorityType {
		return VerifyResult{Reason: "payload is not a div-agent-authority"}, nil
	}
	if len(f.ActionPatterns) == 0 {
		return VerifyResult{Reason: "authority is missing a valid actionPatterns set"}, nil
	}
	if f.ParentReceiptHash == nil {
		return VerifyResult{Reason: "authority is missing parentReceiptHash"}, nil
	}
	parent := ""
	if string(f.ParentReceiptHash) != "null" {
		if json.Unmarshal(f.ParentReceiptHash, &parent) != nil || !strings.HasPrefix(parent, "sha256:") || !isHash64(strings.TrimPrefix(parent, "sha256:")) {
			return VerifyResult{Reason: "authority has invalid parentReceiptHash"}, nil
		}
	}
	for _, p := range f.ActionPatterns {
		if p == "" {
			return VerifyResult{Reason: "authority is missing a valid actionPatterns set"}, nil
		}
	}
	sealed, e1 := time.Parse(time.RFC3339, f.SealedAt)
	expiry, e2 := time.Parse(time.RFC3339, f.ExpiresAt)
	if e1 != nil {
		return VerifyResult{Reason: "sealedAt is not a valid RFC3339 timestamp"}, nil
	}
	if e2 != nil {
		return VerifyResult{Reason: "expiresAt is not a valid RFC3339 timestamp"}, nil
	}
	if expiry.Before(sealed) {
		return VerifyResult{Reason: "authority expires before it was sealed"}, nil
	}
	now, skew := evaluationTime(opts)
	if sealed.After(now.Add(skew)) {
		return VerifyResult{Reason: "authority is sealed in the future (DIV §5b.2)"}, nil
	}
	if receipt.Requester == nil || f.Requirement == nil {
		return VerifyResult{Reason: "authority payload is missing the signed approval requirement"}, nil
	}
	if ok, r := checkQuorumMinimum(*f.Requirement); !ok {
		return VerifyResult{Reason: r}, nil
	}
	if ok, r := checkSignerClass(*f.Requirement); !ok {
		return VerifyResult{Reason: r}, nil
	}
	if expected.Target == "" || expected.AgentDID == "" {
		return VerifyResult{Reason: "expected target and agent DID are required"}, nil
	}
	recomputed, err := CanonicalAgentAuthorityPayload(expected.Target, f.ActionPatterns, receipt.ActionDescription, expected.AgentDID, *receipt.Requester, *f.Requirement, f.Nonce, f.SealedAt, f.ExpiresAt, parent)
	if err != nil || recomputed != receipt.CanonicalPayload {
		return VerifyResult{Reason: "target/agent/actionPatterns do not match what was sealed"}, nil
	}
	if !opts.AllowExpired && now.After(expiry.Add(skew)) {
		return VerifyResult{Reason: "authority has expired (set AllowExpired for audit re-verification)"}, nil
	}
	if receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
		return VerifyResult{Reason: "an agent authority cannot be auto-approved — granting agent scope requires human signatures"}, nil
	}
	ws := witnessesOf(receipt)
	if len(ws) == 0 {
		return VerifyResult{Reason: "authority missing signature material"}, nil
	}
	if len(ws) > MaxWitnesses {
		return VerifyResult{Reason: "authority carries too many witnesses"}, nil
	}
	// See the identical hoist in VerifyApprovalReceipt: a key-set anchor cannot authenticate
	// signerDid, so the sealed four-eyes rule is unenforceable and the receipt is refused outright
	// rather than per witness.
	if f.Requirement.RequesterCannotApprove && len(expected.Approvers.PublicKeys) > 0 {
		return VerifyResult{Reason: "requesterCannotApprove requires a DID-mode trust anchor"}, nil
	}
	verified := map[string]bool{}
	fails := []string{}
	for _, w := range ws {
		cs, r := candidateKeys(expected.Approvers, w, nil)
		if r != "" {
			fails = append(fails, r)
			continue
		}
		matched := ""
		for _, c := range cs {
			if verifyWitness(w, c[0], receipt, opts) == "" {
				matched = c[1]
				break
			}
		}
		if matched == "" {
			continue
		}
		if f.Requirement.RequireHardwareKey && (w.SigAlg == nil || *w.SigAlg != "WEBAUTHN") {
			continue
		}
		if f.Requirement.RequesterCannotApprove && w.SignerDID == receipt.Requester.DID {
			continue
		}
		verified[matched] = true
	}
	if len(verified) < f.Requirement.RequiredApprovals {
		return VerifyResult{Reason: fmt.Sprintf("authority sealing quorum not met: %d of %d required approver signatures verified%s", len(verified), f.Requirement.RequiredApprovals, foldFailures(fails))}, nil
	}
	signers := make([]string, 0, len(verified))
	for k := range verified {
		signers = append(signers, k)
	}
	sort.Strings(signers)
	uniq := map[string]bool{}
	patterns := []string{}
	for _, p := range f.ActionPatterns {
		if !uniq[p] {
			uniq[p] = true
			patterns = append(patterns, p)
		}
	}
	sort.Strings(patterns)
	a := &VerifiedAgentAuthority{expected.AgentDID, expected.Target, patterns, f.Nonce, signers, f.SealedAt, f.ExpiresAt, parent}
	return VerifyResult{OK: true, Signers: signers}, a
}
