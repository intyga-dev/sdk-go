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
		"nonce":     nonce,
		"expiresAt": expiresAt,
	}
	return StableStringify(obj)
}

// canonicalFields is just enough of the DIV Intent Payload to gate version/type and read the fields
// the relying party takes from the receipt (nonce, expiresAt) rather than asserting itself.
type canonicalFields struct {
	V         *int   `json:"v"`
	Type      string `json:"type"`
	Nonce     string `json:"nonce"`
	ExpiresAt string `json:"expiresAt"`
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

	recomputed := CanonicalIntentPayload(
		expected.Target,
		expected.ActionType,
		receipt.ActionDescription,
		expected.Params,
		*receipt.Requester,
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

	if receipt.Signature == nil || receipt.SignerPublicKey == nil {
		return VerifyResult{OK: false, Reason: "missing signature or public key"}
	}

	if receipt.SigAlg != nil && *receipt.SigAlg == "WEBAUTHN" {
		return verifyWebAuthn(receipt, opts)
	}

	// ES256: the human's key signed the canonical payload bytes directly.
	pubKeyBytes, err := base64.StdEncoding.DecodeString(*receipt.SignerPublicKey)
	if err != nil {
		return VerifyResult{OK: false, Reason: "invalid signerPublicKey base64"}
	}
	ecdsaPub, err := parseSpkiP256(pubKeyBytes)
	if err != nil {
		return VerifyResult{OK: false, Reason: err.Error()}
	}
	sigBytes, err := base64.StdEncoding.DecodeString(*receipt.Signature)
	if err != nil {
		return VerifyResult{OK: false, Reason: "invalid signature base64"}
	}
	if !verifyEcdsaSignature(ecdsaPub, []byte(receipt.CanonicalPayload), sigBytes) {
		return VerifyResult{OK: false, Reason: "signature verification failed"}
	}
	return VerifyResult{OK: true}
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
