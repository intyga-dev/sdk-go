package verify

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CanonicalAgentAuthorityPayload reproduces the DIV §5b signed bytes.
func CanonicalAgentAuthorityPayload(target string, actionPatterns []string, display, agentDID string, requester RequesterIdentity, requirement ApprovalRequirement, nonce, sealedAt, expiresAt string, parentReceiptHash ...string) (string, error) {
	parent := ""
	if len(parentReceiptHash) > 0 {
		parent = parentReceiptHash[0]
	}
	return canonicalAgentAuthorityPayload(target, actionPatterns, display, agentDID, requester, requirement, nonce, sealedAt, expiresAt, parent, "")
}

// CanonicalAgentAuthorityPayloadWithTenant builds a tenant-bound DIV v2 authority. The tenant ID
// and parent hash are explicit, separate arguments so a caller cannot accidentally swap the existing
// optional parent argument for a tenant. Pass an empty parentReceiptHash for a root authority.
func CanonicalAgentAuthorityPayloadWithTenant(target string, actionPatterns []string, display, agentDID string, requester RequesterIdentity, requirement ApprovalRequirement, nonce, sealedAt, expiresAt, parentReceiptHash, tenantID string) (string, error) {
	if tenantID == "" {
		return "", fmt.Errorf("tenantID must be a non-empty opaque string")
	}
	return canonicalAgentAuthorityPayload(target, actionPatterns, display, agentDID, requester, requirement, nonce, sealedAt, expiresAt, parentReceiptHash, tenantID)
}

func canonicalAgentAuthorityPayload(target string, actionPatterns []string, display, agentDID string, requester RequesterIdentity, requirement ApprovalRequirement, nonce, sealedAt, expiresAt, parentReceiptHash, tenantID string) (string, error) {
	req, rq, err := canonicalCommon(requester, requirement, false)
	if err != nil {
		return "", err
	}
	patterns := append([]string(nil), actionPatterns...)
	sort.Slice(patterns, func(i, j int) bool { return utf16Less(patterns[i], patterns[j]) })
	if patterns == nil {
		patterns = []string{}
	}
	var parent interface{}
	if parentReceiptHash != "" {
		parent = parentReceiptHash
	}
	obj := map[string]interface{}{"type": DivAgentAuthorityType, "target": target, "actionPatterns": patterns, "display": display, "agent": map[string]interface{}{"did": agentDID}, "parentReceiptHash": parent, "requester": req, "requirement": rq, "nonce": nonce, "sealedAt": sealedAt, "expiresAt": expiresAt}
	if tenantID == "" {
		obj["v"] = DivVersion
	} else if err := applyTenantBinding(obj, []string{tenantID}); err != nil {
		return "", err
	}
	return StableStringify(obj)
}

// CanonicalPlatformIntentPayload reproduces the DIV §5c hash-only signed bytes.
func CanonicalPlatformIntentPayload(payloadHash, rpID, subjectExternalID, signedAt, expiresAt, nonce string, tenantID ...string) (string, error) {
	obj := map[string]interface{}{"type": DivPlatformIntentType, "hashAlg": "SHA-256", "payloadHash": payloadHash, "rpId": rpID, "subject": map[string]interface{}{"externalId": subjectExternalID}, "signedAt": signedAt, "expiresAt": expiresAt, "nonce": nonce}
	if err := applyTenantBinding(obj, tenantID); err != nil {
		return "", err
	}
	return StableStringify(obj)
}

type PlatformReceipt = ApprovalReceipt
type PlatformReceiptExpectation struct {
	Approvers                                   ApproverTrustAnchor
	PayloadHash, RpID, Nonce, SubjectExternalID string
	TenantID                                    *string
}

func VerifyPlatformReceipt(receipt PlatformReceipt, expected PlatformReceiptExpectation, opts VerifyOptions) VerifyResult {
	tenantID, tenantReason := verifyTenantBinding(receipt.CanonicalPayload, expected.TenantID)
	if tenantReason != "" {
		return VerifyResult{Reason: tenantReason}
	}
	if why := canonicalTextProblem(receipt.CanonicalPayload); why != "" {
		return VerifyResult{Reason: why}
	}
	var f canonicalFields
	if json.Unmarshal([]byte(receipt.CanonicalPayload), &f) != nil {
		return VerifyResult{Reason: "unsupported DIV payload version"}
	}
	if f.Type != DivPlatformIntentType {
		if f.Type == DivIntentType || f.Type == DivOfflineIntentType {
			return VerifyResult{Reason: "this is an ordinary approval receipt — verify it with VerifyApprovalReceipt"}
		}
		return VerifyResult{Reason: "payload is not a div-platform-intent"}
	}
	if expected.Nonce == "" {
		return VerifyResult{Reason: nonceRequiredReason}
	}
	if f.Nonce != expected.Nonce {
		return VerifyResult{Reason: "receipt is for a different challenge"}
	}
	if expected.Approvers.isUnset() {
		return VerifyResult{Reason: "expected.Approvers is required — the subject's key MUST come from your own trust policy, never from the receipt (DIV Invariant 3)"}
	}
	if len(expected.PayloadHash) != 64 || strings.ToLower(expected.PayloadHash) != expected.PayloadHash || !isHash64(expected.PayloadHash) {
		return VerifyResult{Reason: "expected.PayloadHash must be the 64-character lowercase hex SHA-256 you recomputed yourself"}
	}
	if expected.RpID == "" {
		return VerifyResult{Reason: "expected.RpID is required — it must be YOUR registered RP ID, asserted independently of the receipt"}
	}
	if opts.ExpectedRpID != "" && opts.ExpectedRpID != expected.RpID {
		return VerifyResult{Reason: "opts.ExpectedRpID conflicts with expected.RpID — pass the RP ID once"}
	}
	if f.SignedAt == "" {
		return VerifyResult{Reason: "receipt missing signedAt"}
	}
	if f.ExpiresAt == "" {
		return VerifyResult{Reason: "receipt missing expiresAt"}
	}
	if f.Subject == nil || f.Subject.ExternalID == "" {
		return VerifyResult{Reason: "receipt missing subject.externalId"}
	}
	if expected.SubjectExternalID != "" && expected.SubjectExternalID != f.Subject.ExternalID {
		return VerifyResult{Reason: "receipt was signed by a different subject"}
	}
	recomputed, err := CanonicalPlatformIntentPayload(expected.PayloadHash, expected.RpID, f.Subject.ExternalID, f.SignedAt, f.ExpiresAt, expected.Nonce, tenantArgs(tenantID)...)
	if err != nil {
		return VerifyResult{Reason: "platform payload is not canonicalizable: " + err.Error()}
	}
	if recomputed != receipt.CanonicalPayload {
		return VerifyResult{Reason: "payloadHash/rpId do not match what was signed"}
	}
	signed, e1 := parseSignedTime(f.SignedAt)
	expiry, e2 := parseSignedTime(f.ExpiresAt)
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
		return VerifyResult{Reason: "proof has expired (pass VerifyOptions{AllowExpired: true} for audit re-verification)"}
	}
	if receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
		return VerifyResult{Reason: "a platform receipt cannot be auto-approved — there is no signature to verify"}
	}
	if malformed := witnessProblem(receipt); malformed != "" {
		return VerifyResult{Reason: malformed}
	}
	w := witnessesOf(receipt)
	if len(w) == 0 {
		return VerifyResult{Reason: "receipt missing signature material"}
	}
	if len(w) > MaxWitnesses {
		return VerifyResult{Reason: fmt.Sprintf("receipt carries %d witnesses, above the %d this verifier will process", len(w), MaxWitnesses)}
	}
	opts.ExpectedRpID = expected.RpID
	// User verification is UNCONDITIONAL on this plane (DIV §5c.3): the ordinary-receipt waiver
	// RequireUserVerification=false is overridden here, never honoured.
	uv := true
	opts.RequireUserVerification = &uv
	verified := map[string]bool{}
	countedKeys := map[string]string{}
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
		matched, matchedKey := "", ""
		last := "signature does not verify against any trusted subject key"
		for _, c := range cs {
			if why := verifyWitness(x, c[0], receipt, opts); why == "" {
				matched, matchedKey = c[1], c[0]
				break
			} else {
				last = why
			}
		}
		if matched == "" {
			failures = append(failures, last)
			continue
		}
		if why := sharedKeyProblem(countedKeys, matchedKey, matched); why != "" {
			failures = append(failures, why)
			continue
		}
		verified[matched] = true
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
	TenantID         *string
	// Requirement is STRONGLY RECOMMENDED: YOUR sealing policy for agent authority (DIV §5b.3, §5
	// step 3d). Nil enforces only the sealers' own stated quorum.
	Requirement *RequirementFloor
}
type VerifiedAgentAuthority struct {
	AgentDID, Target    string
	TenantID            string
	ActionPatterns      []string
	Nonce               string
	Signers             []string
	SealedAt, ExpiresAt string
	ParentReceiptHash   string
}

// AgentAuthorityChainLink is one independently pinned authority receipt and its caller-owned scope.
type AgentAuthorityChainLink struct {
	Receipt  ApprovalReceipt
	Expected AgentAuthorityExpectation
}

// AgentDelegatedAction is the independently asserted action a verified authority chain must cover.
type AgentDelegatedAction struct {
	TenantID, Target, ActionType, AgentDID, DelegatedBy string
}

func VerifyAgentAuthority(receipt ApprovalReceipt, expected AgentAuthorityExpectation, opts VerifyOptions) (VerifyResult, *VerifiedAgentAuthority) {
	tenantID, tenantReason := verifyTenantBinding(receipt.CanonicalPayload, expected.TenantID)
	if tenantReason != "" {
		return VerifyResult{Reason: tenantReason}, nil
	}
	if why := canonicalTextProblem(receipt.CanonicalPayload); why != "" {
		return VerifyResult{Reason: why}, nil
	}
	var f canonicalFields
	if json.Unmarshal([]byte(receipt.CanonicalPayload), &f) != nil {
		return VerifyResult{Reason: "unsupported DIV payload version"}, nil
	}
	if f.Type != DivAgentAuthorityType {
		return VerifyResult{Reason: "payload is not a div-agent-authority"}, nil
	}
	// The reference's order: the parent commitment, then the pattern set.
	parent := ""
	if f.ParentReceiptHash == nil || string(f.ParentReceiptHash) != "null" {
		if f.ParentReceiptHash == nil || json.Unmarshal(f.ParentReceiptHash, &parent) != nil ||
			!strings.HasPrefix(parent, "sha256:") || !isHash64(strings.TrimPrefix(parent, "sha256:")) {
			return VerifyResult{Reason: "authority is missing a valid parent receipt commitment"}, nil
		}
	}
	if len(f.ActionPatterns) == 0 || containsDID(f.ActionPatterns, "") {
		return VerifyResult{Reason: "authority is missing a valid actionPatterns set"}, nil
	}
	if f.SealedAt == "" {
		return VerifyResult{Reason: "authority is missing sealedAt"}, nil
	}
	if f.ExpiresAt == "" {
		return VerifyResult{Reason: "authority is missing expiresAt"}, nil
	}
	sealed, e1 := parseSignedTime(f.SealedAt)
	expiry, e2 := parseSignedTime(f.ExpiresAt)
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
	if receipt.Requester == nil {
		return VerifyResult{Reason: "authority missing requester"}, nil
	}
	if f.Requirement == nil {
		return VerifyResult{Reason: "authority payload is missing the signed approval requirement"}, nil
	}
	if ok, r := checkQuorumMinimum(*f.Requirement); !ok {
		return VerifyResult{Reason: r}, nil
	}
	// Identity extensions before the signer class, in every port (DIV §4.3.2).
	if ok, r := checkExcludedSigners(*f.Requirement, *receipt.Requester); !ok {
		return VerifyResult{Reason: r}, nil
	}
	if ok, r := checkSignerClass(*f.Requirement); !ok {
		return VerifyResult{Reason: r}, nil
	}
	// DIV §5 step 3e: this payload kind can never carry requireEnrolledDevice.
	if why := enrolledDeviceStructureProblem(*f.Requirement, false); why != "" {
		return VerifyResult{Reason: why}, nil
	}
	if ok, r := checkRequirementFloor(*f.Requirement, expected.Requirement); !ok {
		return VerifyResult{Reason: r}, nil
	}
	if expected.Target == "" {
		return VerifyResult{Reason: "expected.Target is required — it must be YOUR target identifier, asserted independently of the authority (DIV Target Isolation)"}, nil
	}
	if expected.AgentDID == "" {
		return VerifyResult{Reason: "expected.AgentDID is required — name the agent whose authority you are checking"}, nil
	}
	if expected.Approvers.isUnset() {
		return VerifyResult{Reason: "expected.Approvers is required — the sealing approvers MUST come from your own trust policy, never from the artifact (DIV Invariant 3)"}, nil
	}
	var recomputed string
	var err error
	if tenantID == "" {
		recomputed, err = CanonicalAgentAuthorityPayload(expected.Target, f.ActionPatterns, receipt.ActionDescription, expected.AgentDID, *receipt.Requester, *f.Requirement, f.Nonce, f.SealedAt, f.ExpiresAt, parent)
	} else {
		recomputed, err = CanonicalAgentAuthorityPayloadWithTenant(expected.Target, f.ActionPatterns, receipt.ActionDescription, expected.AgentDID, *receipt.Requester, *f.Requirement, f.Nonce, f.SealedAt, f.ExpiresAt, parent, tenantID)
	}
	if err != nil {
		return VerifyResult{Reason: "authority payload is not canonicalizable: " + err.Error()}, nil
	}
	if recomputed != receipt.CanonicalPayload {
		return VerifyResult{Reason: "target/agent/actionPatterns do not match what was sealed"}, nil
	}
	if !opts.AllowExpired && now.After(expiry.Add(skew)) {
		return VerifyResult{Reason: "authority has expired (pass VerifyOptions{AllowExpired: true} for audit re-verification)"}, nil
	}
	if receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
		return VerifyResult{Reason: "an agent authority cannot be auto-approved — granting agent scope requires human signatures"}, nil
	}
	if malformed := witnessProblem(receipt); malformed != "" {
		return VerifyResult{Reason: strings.Replace(malformed, "receipt", "authority", 1)}, nil
	}
	ws := witnessesOf(receipt)
	if len(ws) == 0 {
		return VerifyResult{Reason: "authority missing signature material"}, nil
	}
	if len(ws) > MaxWitnesses {
		return VerifyResult{Reason: fmt.Sprintf("authority carries %d witnesses, above the %d this verifier will process", len(ws), MaxWitnesses)}, nil
	}
	// See the identical hoist in VerifyApprovalReceipt: a key-set anchor cannot authenticate
	// signerDid, so the sealed four-eyes rule is unenforceable and the receipt is refused outright
	// rather than per witness.
	if f.Requirement.RequiredApprovals > 1 && expected.Approvers.PublicKeys != nil {
		return VerifyResult{Reason: "multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)"}, nil
	}
	if (f.Requirement.RequesterCannotApprove || (f.Requirement.ExcludedSignerDIDs != nil && len(*f.Requirement.ExcludedSignerDIDs) > 0)) &&
		expected.Approvers.PublicKeys != nil {
		return VerifyResult{Reason: keyOnlyFourEyesReason}, nil
	}
	verified := map[string]bool{}
	countedKeys := map[string]string{}
	if why := seedExcludedSigningKeys(countedKeys, expected.Approvers, *f.Requirement, *receipt.Requester); why != "" {
		return VerifyResult{Reason: why}, nil
	}
	fails := []string{}
	for _, w := range ws {
		cs, r := candidateKeys(expected.Approvers, w, nil)
		if r != "" {
			fails = append(fails, r)
			continue
		}
		matched, matchedKey := "", ""
		last := "signature does not verify against any trusted approver key"
		for _, c := range cs {
			if why := verifyWitness(w, c[0], receipt, opts); why == "" {
				matched, matchedKey = c[1], c[0]
				break
			} else {
				last = why
			}
		}
		if matched == "" {
			fails = append(fails, last)
			continue
		}
		if f.Requirement.RequiresHardwareCredential() && (w.SigAlg == nil || *w.SigAlg != "WEBAUTHN") {
			fails = append(fails, fmt.Sprintf(
				"signer %s used a bare key, but the signed policy requires a hardware-backed WebAuthn credential", w.SignerDID))
			continue
		}
		if f.Requirement.RequireHardwareKey {
			if why := backupFlagsProblem(w); why != "" {
				fails = append(fails, why)
				continue
			}
		}
		excluded := map[string]bool{}
		if f.Requirement.ExcludedSignerDIDs != nil {
			for _, did := range *f.Requirement.ExcludedSignerDIDs {
				excluded[did] = true
			}
		}
		if f.Requirement.RequesterCannotApprove {
			excluded[receipt.Requester.DID] = true
			if receipt.Requester.CredentialIssuerDID != nil {
				excluded[*receipt.Requester.CredentialIssuerDID] = true
			}
		}
		if excluded[w.SignerDID] {
			fails = append(fails, fmt.Sprintf("four-eyes: requester %s cannot seal their own request", w.SignerDID))
			continue
		}
		if why := sharedKeyProblem(countedKeys, matchedKey, matched); why != "" {
			fails = append(fails, why)
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
	a := &VerifiedAgentAuthority{
		AgentDID: expected.AgentDID, Target: expected.Target, TenantID: tenantID,
		ActionPatterns: patterns, Nonce: f.Nonce, Signers: signers,
		SealedAt: f.SealedAt, ExpiresAt: f.ExpiresAt, ParentReceiptHash: parent,
	}
	return VerifyResult{OK: true, Signers: signers}, a
}

// AgentReceiptDigest commits to the complete authority proof, including every witness in canonical
// order. A pending intent without its human signatures therefore cannot be substituted as a parent.
func AgentReceiptDigest(receipt ApprovalReceipt) (string, error) {
	witnesses := witnessesOf(receipt)
	projected := make([]interface{}, 0, len(witnesses))
	for _, w := range witnesses {
		fieldOrNil := func(name, value string) interface{} {
			if w.decoded && (!w.present[name] || w.nulls[name]) {
				return nil
			}
			return value
		}
		pointerOrNil := func(value *string) interface{} {
			if value == nil {
				return nil
			}
			return *value
		}
		projected = append(projected, map[string]interface{}{
			"signerDid": fieldOrNil("signerDid", w.SignerDID), "signerPublicKey": fieldOrNil("signerPublicKey", w.SignerPublicKey),
			"signature": fieldOrNil("signature", w.Signature), "sigAlg": pointerOrNil(w.SigAlg),
			"authenticatorData": pointerOrNil(w.AuthenticatorData),
			"clientDataJSON":    pointerOrNil(w.ClientDataJSON),
		})
	}
	sort.Slice(projected, func(i, j int) bool {
		left, _ := StableStringify(projected[i])
		right, _ := StableStringify(projected[j])
		return utf16Less(left, right)
	})
	content, err := StableStringify(map[string]interface{}{
		"canonicalPayload": receipt.CanonicalPayload,
		"witnesses":        projected,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("intyga-agent-receipt-v1\x00"), []byte(content)...))
	return fmt.Sprintf("sha256:%x", sum), nil
}

// VerifyAgentDelegationChain verifies a complete root-to-leaf human-sealed authority chain, including
// tenant, target, parent hash, lifetime and scope continuity. A chain is governance evidence only.
func VerifyAgentDelegationChain(chain []AgentAuthorityChainLink, action AgentDelegatedAction, opts VerifyOptions) VerifyResult {
	if len(chain) < 2 || !agentDigestPattern.MatchString(action.DelegatedBy) {
		return VerifyResult{Reason: "delegation requires a complete root-to-leaf authority chain"}
	}
	var parent *VerifiedAgentAuthority
	parentHash := ""
	for index, link := range chain {
		proof, authority := VerifyAgentAuthority(link.Receipt, link.Expected, opts)
		if !proof.OK || authority == nil {
			return VerifyResult{Reason: fmt.Sprintf("authority link %d: %s", index+1, proof.Reason)}
		}
		if authority.TenantID != action.TenantID {
			return VerifyResult{Reason: "authority chain and action belong to different tenants"}
		}
		if authority.Target != action.Target {
			return VerifyResult{Reason: "delegated authority changes target"}
		}
		if authority.ParentReceiptHash != parentHash {
			return VerifyResult{Reason: "delegated authority has a missing or different parent receipt"}
		}
		if parent != nil {
			if authority.TenantID != parent.TenantID {
				return VerifyResult{Reason: "authority chain crosses tenant boundaries"}
			}
			childSealed, e1 := parseSignedTime(authority.SealedAt)
			parentSealed, e2 := parseSignedTime(parent.SealedAt)
			childExpires, e3 := parseSignedTime(authority.ExpiresAt)
			parentExpires, e4 := parseSignedTime(parent.ExpiresAt)
			if e1 != nil || e2 != nil || e3 != nil || e4 != nil || childSealed.Before(parentSealed) || childExpires.After(parentExpires) {
				return VerifyResult{Reason: "child authority outlives or predates its parent"}
			}
			for _, child := range authority.ActionPatterns {
				covered := false
				for _, scope := range parent.ActionPatterns {
					if scope == "*" || strings.Contains(strings.ToLower(child), strings.ToLower(scope)) {
						covered = true
						break
					}
				}
				if !covered {
					return VerifyResult{Reason: "child authority escalates the parent's action scope"}
				}
			}
		}
		parent = authority
		var err error
		parentHash, err = AgentReceiptDigest(link.Receipt)
		if err != nil {
			return VerifyResult{Reason: fmt.Sprintf("authority link %d cannot be digested: %s", index+1, err)}
		}
	}
	if parentHash != action.DelegatedBy || parent == nil || parent.AgentDID != action.AgentDID {
		return VerifyResult{Reason: "action does not name its delegated agent and leaf authority receipt"}
	}
	covered := false
	for _, pattern := range parent.ActionPatterns {
		if pattern == "*" || strings.Contains(strings.ToLower(action.ActionType), strings.ToLower(pattern)) {
			covered = true
			break
		}
	}
	if !covered {
		return VerifyResult{Reason: "action falls outside the delegated authority"}
	}
	return VerifyResult{OK: true}
}
