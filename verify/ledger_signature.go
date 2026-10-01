package verify

import "encoding/json"

// AuditSignaturePolicy comes from the relying party, never from the evidence.
// COSE keys for WebAuthn; SPKI keys for ES256. This checks a signature, not an approval quorum.
type AuditSignaturePolicy struct {
	TrustedSigners map[string][]string `json:"trustedSigners"`
	ExpectedOrigin string              `json:"expectedOrigin"`
	ExpectedRpID   string              `json:"expectedRpId"`
}
type AuditSignatureCheck struct {
	Status  string `json:"status"`
	Reason  string `json:"reason"`
	Trusted bool   `json:"trusted"`
}
type AuditEntrySignature struct {
	Seq string `json:"seq"`
	AuditSignatureCheck
}

func uncheckedSignature() AuditSignatureCheck {
	return AuditSignatureCheck{"not_checked", "Content not verified or unavailable.", false}
}
func VerifyAuditSignature(c AuditLeaf, p *AuditSignaturePolicy) AuditSignatureCheck {
	result := func(status, reason string) AuditSignatureCheck { return AuditSignatureCheck{status, reason, false} }
	if (c.SigAlg == nil || *c.SigAlg == "") && ((c.Signature != nil && *c.Signature != "") || (c.SignedPayload != nil && *c.SignedPayload != "") || (c.SignerPublicKey != nil && *c.SignerPublicKey != "")) {
		return result("not_checked", "Signature algorithm is missing.")
	}
	if c.SigAlg == nil || *c.SigAlg == "" || *c.SigAlg == "AUTO_APPROVED" {
		return result("not_applicable", "No human signature is declared.")
	}
	alg := *c.SigAlg
	if alg != "ES256" && alg != "WEBAUTHN" {
		return result("not_checked", "Unsupported signature algorithm.")
	}
	if c.Signature == nil || *c.Signature == "" || c.SignedPayload == nil || *c.SignedPayload == "" {
		return result("not_checked", "Signature or signed payload is missing.")
	}
	if p == nil && alg == "ES256" {
		if c.SignerPublicKey == nil || *c.SignerPublicKey == "" {
			return result("not_checked", "Signer public key is missing.")
		}
		if VerifyEmbeddedSignature(c) {
			return result("verified", "Signature valid under embedded key; signer identity is not established.")
		}
		return result("invalid", "Signature does not verify.")
	}
	var keys []string
	if p != nil && c.SignerDid != nil {
		keys = p.TrustedSigners[*c.SignerDid]
	}
	if len(keys) == 0 {
		return result("not_checked", "No caller-trusted key for this signer.")
	}
	for _, k := range keys {
		if k == "" {
			return result("not_checked", "No caller-trusted key for this signer.")
		}
	}
	if alg == "WEBAUTHN" && (p.ExpectedOrigin == "" || p.ExpectedRpID == "") {
		return result("not_checked", "Caller-selected WebAuthn origin and RP ID are required.")
	}
	var meta struct {
		WebAuthn struct {
			AuthenticatorData string `json:"authenticatorData"`
			ClientDataJSON    string `json:"clientDataJSON"`
		} `json:"webauthn"`
	}
	raw, _ := json.Marshal(c.Metadata)
	_ = json.Unmarshal(raw, &meta)
	if alg == "WEBAUTHN" && (meta.WebAuthn.AuthenticatorData == "" || meta.WebAuthn.ClientDataJSON == "") {
		return result("not_checked", "WebAuthn authenticatorData or clientDataJSON is missing.")
	}
	for _, key := range keys {
		valid := false
		if alg == "ES256" {
			clone := c
			clone.SignerPublicKey = &key
			valid = VerifyEmbeddedSignature(clone)
		} else {
			w := ApprovalWitness{Signature: *c.Signature, AuthenticatorData: &meta.WebAuthn.AuthenticatorData, ClientDataJSON: &meta.WebAuthn.ClientDataJSON}
			valid = verifyWebAuthnWitness(w, key, ApprovalReceipt{CanonicalPayload: *c.SignedPayload}, VerifyOptions{ExpectedOrigin: p.ExpectedOrigin, ExpectedRpID: p.ExpectedRpID}) == ""
		}
		if valid {
			return AuditSignatureCheck{"verified", "Signature valid under caller-trusted signer key.", true}
		}
	}
	return result("invalid", "Signature or WebAuthn assertion does not verify under caller trust.")
}
