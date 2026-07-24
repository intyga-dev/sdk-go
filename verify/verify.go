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
	"unicode/utf16"
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

// ApprovalReceipt contains the signed witness payload and signature.
type ApprovalReceipt struct {
	CanonicalPayload  string                 `json:"canonicalPayload"`
	ActionType        *string                `json:"actionType,omitempty"`
	ActionDescription string                 `json:"actionDescription"`
	Params            map[string]interface{} `json:"params"`
	SignerDID         *string                `json:"signerDid,omitempty"`
	SignerPublicKey   *string                `json:"signerPublicKey,omitempty"`   // base64 SPKI/raw P-256 (ES256) or COSE key (WEBAUTHN)
	Signature         *string                `json:"signature,omitempty"`         // base64 P-256 signature
	SigAlg            *string                `json:"sigAlg,omitempty"`            // "ES256" | "WEBAUTHN" | "AUTO_APPROVED"
	AuthenticatorData *string                `json:"authenticatorData,omitempty"` // base64 (WEBAUTHN only)
	ClientDataJSON    *string                `json:"clientDataJSON,omitempty"`    // base64 (WEBAUTHN only)
	Requester         *RequesterIdentity     `json:"requester,omitempty"`
	ExpiresAt         *string                `json:"expiresAt,omitempty"`
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
}

// WebAuthn authenticatorData flag bits (WebAuthn L3 §6.1).
const (
	authDataFlagUP = 0x01 // User Present
	authDataFlagUV = 0x04 // User Verified
)

// Expected contains expected context when verifying a receipt.
type Expected struct {
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

// CanonicalAuthorizationPayloadV3 builds a byte-identical v3 canonical authorization payload.
func CanonicalAuthorizationPayloadV3(
	nonce string,
	actionType string,
	actionDescription string,
	params map[string]interface{},
	requester RequesterIdentity,
	expiresAt *string,
) string {
	nonceB, _ := json.Marshal(nonce)
	actionTypeB, _ := json.Marshal(actionType)
	actionB, _ := json.Marshal(actionDescription)
	paramsJSON := StableStringify(params)
	didB, _ := json.Marshal(requester.DID)

	var attestationStr string
	if requester.Attestation == nil {
		attestationStr = "null"
	} else {
		mB, _ := json.Marshal(requester.Attestation.Method)
		iB, _ := json.Marshal(requester.Attestation.Issuer)
		sB, _ := json.Marshal(requester.Attestation.Subject)
		attestationStr = fmt.Sprintf(`{"method":%s,"issuer":%s,"subject":%s}`, string(mB), string(iB), string(sB))
	}

	expiresSuffix := ""
	if expiresAt != nil && *expiresAt != "" {
		expB, _ := json.Marshal(*expiresAt)
		expiresSuffix = fmt.Sprintf(`,"expiresAt":%s`, string(expB))
	}

	return fmt.Sprintf(
		`{"v":3,"type":"agent-authorization","nonce":%s,"actionType":%s,"action":%s,"params":%s,"requester":{"did":%s,"attestation":%s}%s}`,
		string(nonceB), string(actionTypeB), string(actionB), paramsJSON, string(didB), attestationStr, expiresSuffix,
	)
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

	if receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
		if !opts.AllowAutoApproved {
			return VerifyResult{OK: false, Reason: "AUTO_APPROVED receipts are refused by default"}
		}
		return VerifyResult{OK: true}
	}

	if receipt.Requester == nil {
		return VerifyResult{OK: false, Reason: "v3 receipt missing requester"}
	}

	recomputed := CanonicalAuthorizationPayloadV3(
		expected.Nonce,
		expected.ActionType,
		receipt.ActionDescription,
		expected.Params,
		*receipt.Requester,
		receipt.ExpiresAt,
	)

	if recomputed != receipt.CanonicalPayload {
		return VerifyResult{OK: false, Reason: "params/actionType do not match what was approved"}
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
