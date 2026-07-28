package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// DIV protocol constants (docs/DIV.md v1).
const (
	DivVersion    = 1
	DivIntentType = "div-intent-verification"
	// DefaultClockSkewSeconds is the RECOMMENDED expiry tolerance (DIV §6.2).
	DefaultClockSkewSeconds = 30
)

// RequesterAttestation represents the workload identity attestation.
type RequesterAttestation struct {
	Method  string `json:"method"`
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

// ApprovalRequirement is the approval policy in force, frozen at challenge creation and SIGNED into
// the intent payload. Without it in the signed bytes a 3-of-3 hardware-pinned receipt is
// indistinguishable from a 1-of-1 one, so a relying party has to trust the gateway for the policy.
//
// Offline checkability differs per field: RequiredApprovals and RequesterCannotApprove are fully
// verifiable; RequireHardwareKey only partially (an assertion proves WebAuthn, not the authenticator
// model); AllowedAaguids not at all (the AAGUID lives in registration data, never in an assertion).
type ApprovalRequirement struct {
	RequiredApprovals      int      `json:"requiredApprovals"`
	RequireHardwareKey     bool     `json:"requireHardwareKey"`
	AllowedAaguids         []string `json:"allowedAaguids"`
	RequesterCannotApprove bool     `json:"requesterCannotApprove"`
}

// RequesterIdentity defines who requested the action.
type RequesterIdentity struct {
	DID         string                `json:"did"`
	Attestation *RequesterAttestation `json:"attestation"`
}

// ApprovalReceipt is a DIV Proof Envelope: the signed canonical payload plus the signature
// metadata needed to verify it (extended with the WebAuthn assertion components).
type ApprovalReceipt struct {
	CanonicalPayload  string                 `json:"canonicalPayload"`
	Target            *string                `json:"target,omitempty"` // display/telemetry only; RP asserts its own
	ActionType        *string                `json:"actionType,omitempty"`
	ActionDescription string                 `json:"actionDescription"` // the DIV `display` field
	Params            map[string]interface{} `json:"params"`
	// Signatures carries EVERY witness — one entry per approver. Emitting only the first approval
	// made an M-of-N receipt indistinguishable from a 1-of-1 one, so the quorum could not be checked
	// offline at all. Empty for AUTO_APPROVED, which has no human signature.
	Signatures        []ApprovalWitness      `json:"signatures,omitempty"`
	SignerDID         *string                `json:"signerDid,omitempty"`
	SignerPublicKey   *string                `json:"signerPublicKey,omitempty"`   // base64 SPKI/raw P-256 (ES256) or COSE key (WEBAUTHN)
	Signature         *string                `json:"signature,omitempty"`         // base64 P-256 signature
	SigAlg            *string                `json:"sigAlg,omitempty"`            // "ES256" | "WEBAUTHN" | "AUTO_APPROVED"
	AuthenticatorData *string                `json:"authenticatorData,omitempty"` // base64 (WEBAUTHN only)
	ClientDataJSON    *string                `json:"clientDataJSON,omitempty"`    // base64 (WEBAUTHN only)
	Requester         *RequesterIdentity     `json:"requester,omitempty"`
	VerificationCode  string                 `json:"verificationCode"`
}

// VerifyOptions carries relying-party context required to verify certain receipts.
// The WebAuthn expectations are mandatory for a WEBAUTHN receipt: without a pinned
// origin and RP ID, an assertion harvested at any relying party would verify.
type VerifyOptions struct {
	// AllowAutoApproved opts in to attesting policy AUTO_APPROVED receipts, which carry no
	// human signature. Off by default: such receipts fail closed.
	AllowAutoApproved bool
	// ExpectedOrigin is the exact origin the assertion must carry, e.g. "https://app.example.com".
	ExpectedOrigin string
	// ExpectedRpID is the RP ID the authenticatorData must hash to, e.g. "app.example.com".
	ExpectedRpID string
	// RequireUserVerification demands the User-Verified flag (biometric/PIN). Defaults to true;
	// set to a non-nil false to accept mere user presence.
	RequireUserVerification *bool
	// AllowExpired opts out of the fail-closed expiry check (DIV §5.8) for post-hoc audit
	// re-verification. Off by default.
	AllowExpired bool
	// AsOf overrides "now" for expiry evaluation. Zero value means time.Now().
	AsOf time.Time
	// ClockSkewSeconds is the expiry tolerance. Zero means DefaultClockSkewSeconds.
	ClockSkewSeconds *int
	// AllowCrossOrigin accepts an assertion produced inside a cross-origin frame. Defaults to false
	// (refuse): origin and rpIdHash both match for an embedded RP frame, so crossOrigin is the only
	// signal that the ceremony ran inside a third-party embedder.
	AllowCrossOrigin bool `json:"allowCrossOrigin,omitempty"`
}

// WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
const (
	authDataFlagUP = 0x01 // User Present
	authDataFlagUV = 0x04 // User Verified
)

// Expected contains expected context when verifying a receipt. Target and Nonce are asserted from
// the relying party's own state — never read from the receipt (DIV Target Isolation + replay binding).
type Expected struct {
	Target     string                 `json:"target"`
	Nonce      string                 `json:"nonce"`
	ActionType string                 `json:"actionType"`
	Params     map[string]interface{} `json:"params"`
	// Approvers is REQUIRED. Verification uses a key YOU resolve, never receipt.SignerPublicKey:
	// a receipt checked against its own embedded key proves only internal consistency, and per the
	// DIV threat model anyone able to hand you a receipt could have minted that keypair.
	// DIV §3 Invariant 3 / §5 step 3.
	Approvers ApproverTrustAnchor `json:"-"`
}

// ApproverTrustAnchor is the set of approver keys the relying party trusts, resolved from its OWN
// key-management policy. Supply either PublicKeys (a direct base64 SPKI/COSE allowlist) or DIDs plus
// ResolveKey (your own directory lookup; return "" for an unknown DID).
type ApproverTrustAnchor struct {
	PublicKeys []string
	DIDs       []string
	ResolveKey func(did string) string
}

// candidates returns the keys this witness may be accepted under, each tagged with the identity it
// represents so a quorum counts distinct APPROVERS. In PublicKeys mode the identity is the key
// itself: the receipt's signerDid is unverified there, and counting it would let one approver claim
// to be three. The presented key is deliberately NOT compared against the trusted one — a mismatched
// key simply fails to verify, and byte-equality is wrong for COSE, which has many valid encodings of
// the same P-256 key.
func (a ApproverTrustAnchor) candidates(signerDID string) ([][2]string, string) {
	if len(a.PublicKeys) > 0 {
		out := make([][2]string, 0, len(a.PublicKeys))
		for _, k := range a.PublicKeys {
			out = append(out, [2]string{k, k})
		}
		return out, ""
	}
	if len(a.DIDs) == 0 || a.ResolveKey == nil {
		return nil, "expected.Approvers is required — the Approver key MUST come from your own trust policy, never from the receipt (DIV Invariant 3)"
	}
	found := false
	for _, d := range a.DIDs {
		if d == signerDID && signerDID != "" {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Sprintf("signer %s is not an authorized approver", signerDID)
	}
	key := a.ResolveKey(signerDID)
	if key == "" {
		return nil, fmt.Sprintf("no trusted key could be resolved for %s", signerDID)
	}
	return [][2]string{{key, signerDID}}, ""
}

// ApprovalWitness is one approver's signature over the canonical payload.
type ApprovalWitness struct {
	SignerDID       string  `json:"signerDid"`
	SignerPublicKey string  `json:"signerPublicKey"`
	Signature       string  `json:"signature"`
	SigAlg          *string `json:"sigAlg,omitempty"`
	AuthenticatorData *string `json:"authenticatorData,omitempty"`
	ClientDataJSON    *string `json:"clientDataJSON,omitempty"`
}

// VerifyResult represents the verification outcome.
type VerifyResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// utf16Less compares two strings by UTF-16 code units (matching JS localeCompare/sort).
func utf16Less(a, b string) bool {
	u1 := utf16.Encode([]rune(a))
	u2 := utf16.Encode([]rune(b))
	min := len(u1)
	if len(u2) < min {
		min = len(u2)
	}
	for i := 0; i < min; i++ {
		if u1[i] != u2[i] {
			return u1[i] < u2[i]
		}
	}
	return len(u1) < len(u2)
}

// StableStringify recursively serializes a Go data structure into deterministic JSON with UTF-16 sorted keys.
func StableStringify(v interface{}) string {
	if v == nil {
		return "null"
	}
	switch val := v.(type) {
	case bool:
		if val {
			return "true"
		}
		return "false"
	case string:
		b, _ := json.Marshal(val)
		return string(b)
	case float64:
		if val == float64(int64(val)) {
			return strconv.FormatInt(int64(val), 10)
		}
		b, _ := json.Marshal(val)
		return string(b)
	case int:
		return strconv.Itoa(val)
	case int64:
		return strconv.FormatInt(val, 10)
	case []interface{}:
		items := make([]string, len(val))
		for i, x := range val {
			items[i] = StableStringify(x)
		}
		return "[" + strings.Join(items, ",") + "]"
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			return utf16Less(keys[i], keys[j])
		})
		parts := make([]string, len(keys))
		for i, k := range keys {
			kB, _ := json.Marshal(k)
			parts[i] = fmt.Sprintf("%s:%s", string(kB), StableStringify(val[k]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	default:
		b, _ := json.Marshal(val)
		return string(b)
	}
}

// CanonicalIntentPayload builds a byte-identical DIV Intent Payload (docs/DIV.md v1). It builds the
// full object and serializes it with StableStringify (strict RFC 8785 JCS — every key sorted). Do NOT
// hand-template key order; the sort is the contract.
func CanonicalIntentPayload(
	target string,
	actionType string,
	display string,
	params map[string]interface{},
	requester RequesterIdentity,
	requirement ApprovalRequirement,
	nonce string,
	expiresAt string,
) string {
	var attestation interface{}
	if requester.Attestation != nil {
		attestation = map[string]interface{}{
			"method":  requester.Attestation.Method,
			"issuer":  requester.Attestation.Issuer,
			"subject": requester.Attestation.Subject,
		}
	}
	// The SET is the policy: sort so two identical allowlists written in different orders produce
	// identical signed bytes. Copy first — mutating the caller's slice would be a nasty surprise.
	aaguids := append([]string(nil), requirement.AllowedAaguids...)
	sort.Strings(aaguids)
	if aaguids == nil {
		aaguids = []string{}
	}
	obj := map[string]interface{}{
		"v":          DivVersion,
		"type":       DivIntentType,
		"target":     target,
		"actionType": actionType,
		"display":    display,
		"params":     params,
		"requester": map[string]interface{}{
			"did":         requester.DID,
			"attestation": attestation,
		},
		"requirement": map[string]interface{}{
			"requiredApprovals":      requirement.RequiredApprovals,
			"requireHardwareKey":     requirement.RequireHardwareKey,
			"allowedAaguids":         aaguids,
			"requesterCannotApprove": requirement.RequesterCannotApprove,
		},
		"nonce":     nonce,
		"expiresAt": expiresAt,
	}
	return StableStringify(obj)
}

// canonicalFields is just enough of the DIV Intent Payload to gate version/type and read the fields
// the relying party takes from the receipt (nonce, expiresAt) rather than asserting itself.
type canonicalFields struct {
	V           *int                 `json:"v"`
	Type        string               `json:"type"`
	Nonce       string               `json:"nonce"`
	ExpiresAt   string               `json:"expiresAt"`
	Requirement *ApprovalRequirement `json:"requirement"`
}

// VerifyApprovalReceipt verifies an ApprovalReceipt offline without external dependencies.
//
// It recomputes the canonical payload from the caller's own params, confirms it byte-matches
// what was signed, and verifies the human's ES256 or WebAuthn signature. A WEBAUTHN receipt
// additionally requires opts.ExpectedOrigin and opts.ExpectedRpID.
func VerifyApprovalReceipt(receipt ApprovalReceipt, expected Expected, opts VerifyOptions) VerifyResult {
	if receipt.CanonicalPayload == "" {
		return VerifyResult{OK: false, Reason: "missing canonicalPayload"}
	}

	var fields canonicalFields
	if err := json.Unmarshal([]byte(receipt.CanonicalPayload), &fields); err != nil {
		return VerifyResult{OK: false, Reason: "canonicalPayload is not valid JSON"}
	}
	if fields.V == nil || *fields.V != DivVersion {
		return VerifyResult{OK: false, Reason: "unsupported DIV payload version"}
	}
	if fields.Type != DivIntentType {
		return VerifyResult{OK: false, Reason: "payload is not a div-intent-verification"}
	}
	if fields.Nonce != expected.Nonce {
		return VerifyResult{OK: false, Reason: "receipt is for a different challenge"}
	}

	if receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
		if !opts.AllowAutoApproved {
			return VerifyResult{OK: false, Reason: "AUTO_APPROVED receipts are refused by default"}
		}
		return VerifyResult{OK: true}
	}

	if receipt.Requester == nil {
		return VerifyResult{OK: false, Reason: "receipt missing requester"}
	}
	if fields.ExpiresAt == "" {
		return VerifyResult{OK: false, Reason: "receipt missing expiresAt"}
	}

	// The requirement is part of the SIGNED bytes, so reading it back from the payload is not
	// circular: a forged value changes the string and fails the byte comparison below.
	if fields.Requirement == nil {
		return VerifyResult{OK: false, Reason: "receipt payload is missing the signed approval requirement"}
	}

	recomputed := CanonicalIntentPayload(
		expected.Target,
		expected.ActionType,
		receipt.ActionDescription,
		expected.Params,
		*receipt.Requester,
		*fields.Requirement,
		fields.Nonce,
		fields.ExpiresAt,
	)

	if recomputed != receipt.CanonicalPayload {
		return VerifyResult{OK: false, Reason: "target/params/actionType do not match what was approved"}
	}

	// Expiration (DIV §5.8/§6.2). Fail-closed by default; opt out only for audit re-verification.
	if !opts.AllowExpired {
		expiry, err := time.Parse(time.RFC3339, fields.ExpiresAt)
		if err != nil {
			return VerifyResult{OK: false, Reason: "expiresAt is not a valid RFC3339 timestamp"}
		}
		now := opts.AsOf
		if now.IsZero() {
			now = time.Now()
		}
		skew := DefaultClockSkewSeconds
		if opts.ClockSkewSeconds != nil {
			skew = *opts.ClockSkewSeconds
		}
		if now.After(expiry.Add(time.Duration(skew) * time.Second)) {
			return VerifyResult{OK: false, Reason: "proof has expired (set AllowExpired for audit re-verification)"}
		}
	}

	witnesses := witnessesOf(receipt)
	if len(witnesses) == 0 {
		return VerifyResult{OK: false, Reason: "missing signature or public key"}
	}

	// Count DISTINCT approvers whose signature verifies under a key we independently trust. Distinct
	// is load-bearing: without it, N copies of one approver's signature satisfy an N-of-M quorum.
	verified := map[string]bool{}
	var failures []string
	for _, w := range witnesses {
		cands, reason := expected.Approvers.candidates(w.SignerDID)
		if reason != "" {
			failures = append(failures, reason)
			continue
		}
		matched := ""
		last := "signature does not verify against any trusted approver key"
		for _, c := range cands {
			if why := verifyWitness(w, c[0], receipt, opts); why == "" {
				matched = c[1]
				break
			} else {
				last = why
			}
		}
		if matched == "" {
			failures = append(failures, last)
			continue
		}
		// A hardware-key policy is only partially checkable offline: a bare P-256 key carries no
		// attestation at all, so it can never satisfy the requirement, while a WebAuthn assertion is
		// accepted without proving the authenticator's model.
		if fields.Requirement.RequireHardwareKey && (w.SigAlg == nil || *w.SigAlg != "WEBAUTHN") {
			failures = append(failures, fmt.Sprintf(
				"signer %s used a bare key, but the signed policy requires a hardware-backed WebAuthn credential", w.SignerDID))
			continue
		}
		// Four-eyes, verified offline against the requester in the same signed payload.
		if fields.Requirement.RequesterCannotApprove && w.SignerDID == receipt.Requester.DID {
			failures = append(failures, fmt.Sprintf(
				"four-eyes: requester %s cannot approve their own action", w.SignerDID))
			continue
		}
		verified[matched] = true
	}

	required := fields.Requirement.RequiredApprovals
	if required < 1 {
		required = 1
	}
	if len(verified) < required {
		detail := ""
		if len(failures) > 0 {
			detail = " (" + strings.Join(failures, "; ") + ")"
		}
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"quorum not met: %d of %d required approver signatures verified%s", len(verified), required, detail)}
	}
	return VerifyResult{OK: true}
}

// witnessesOf normalizes a receipt to a witness list: Signatures if present, else the
// single-signature fields.
func witnessesOf(receipt ApprovalReceipt) []ApprovalWitness {
	if len(receipt.Signatures) > 0 {
		return receipt.Signatures
	}
	if receipt.SignerPublicKey == nil || receipt.Signature == nil {
		return nil
	}
	did := ""
	if receipt.SignerDID != nil {
		did = *receipt.SignerDID
	}
	return []ApprovalWitness{{
		SignerDID:         did,
		SignerPublicKey:   *receipt.SignerPublicKey,
		Signature:         *receipt.Signature,
		SigAlg:            receipt.SigAlg,
		AuthenticatorData: receipt.AuthenticatorData,
		ClientDataJSON:    receipt.ClientDataJSON,
	}}
}

// verifyWitness verifies one witness using an already-TRUSTED key. Returns "" on success.
func verifyWitness(w ApprovalWitness, trustedKey string, receipt ApprovalReceipt, opts VerifyOptions) string {
	if w.SigAlg != nil && *w.SigAlg == "WEBAUTHN" {
		return verifyWebAuthnWitness(w, trustedKey, receipt, opts)
	}
	// ES256: the human's key signed the canonical payload bytes directly.
	pubKeyBytes, err := base64.StdEncoding.DecodeString(trustedKey)
	if err != nil {
		return "invalid trusted key base64"
	}
	ecdsaPub, err := parseSpkiP256(pubKeyBytes)
	if err != nil {
		return err.Error()
	}
	sigBytes, err := base64.StdEncoding.DecodeString(w.Signature)
	if err != nil {
		return "invalid signature base64"
	}
	if !verifyEcdsaSignature(ecdsaPub, []byte(receipt.CanonicalPayload), sigBytes) {
		return "signature does not verify against the trusted signer key"
	}
	return ""
}

// parseSpkiP256 parses a base64-decoded SPKI/PKIX public key and asserts it is P-256.
func parseSpkiP256(der []byte) (*ecdsa.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("failed to parse SPKI public key")
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("signerPublicKey is not an ECDSA key")
	}
	// Pin the curve: an ES256 label must not be honoured by a key on some other curve.
	if ecdsaPub.Curve != elliptic.P256() {
		return nil, errors.New("signerPublicKey is not a P-256 key")
	}
	return ecdsaPub, nil
}

// verifyEcdsaSignature verifies an ES256 (P-256 + SHA-256) signature over message, accepting
// either ASN.1/DER or raw IEEE-P1363 (r‖s) encodings.
func verifyEcdsaSignature(pub *ecdsa.PublicKey, message, sigBytes []byte) bool {
	hashed := sha256.Sum256(message)
	if ecdsa.VerifyASN1(pub, hashed[:], sigBytes) {
		return true
	}
	if len(sigBytes) == 64 {
		r := new(big.Int).SetBytes(sigBytes[:32])
		s := new(big.Int).SetBytes(sigBytes[32:])
		return ecdsa.Verify(pub, hashed[:], r, s)
	}
	return false
}
