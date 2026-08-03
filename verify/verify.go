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
	"math"
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
	// DivOfflineIntentType marks an OFFLINE APPROVAL (DIV §5a.2): a normal quorum approval collected
	// OUT OF BAND at incident time because the gateway is unreachable. The relying party builds the
	// challenge itself, humans sign it on a disconnected device, and this verifier checks the result.
	//
	// The distinct type lives INSIDE the signed bytes, so an offline proof can never verify as a normal
	// approval, or the reverse — even for a byte-identical action, because the reconstructed payload
	// differs and the signature comparison fails.
	DivOfflineIntentType = "div-offline-intent"
	// DivDelegationType marks a DELEGATION (DIV §5a.5): a pre-signed statement transferring the
	// AUTHORITY TO APPROVE one pre-declared action to named local operators. It authorizes NOTHING on
	// its own — VerifyApprovalReceipt refuses this type outright, with no opt-in. Use VerifyDelegation.
	DivDelegationType = "div-delegation"
	// DefaultClockSkewSeconds is the RECOMMENDED expiry tolerance (DIV §6.2).
	DefaultClockSkewSeconds = 30
	// MaxOfflineWindowMinutes caps an offline proof's validity window, enforced at verification and not
	// only at mint. An offline relying party has no revocation channel, so the short window is the only
	// bound there is (DIV §5a.3).
	MaxOfflineWindowMinutes = 60
	// MaxDelegationWindowHours caps a delegation's window (DIV §5a.6). Hours, not weeks: a delegation
	// cannot be recalled from a relying party that is offline.
	MaxDelegationWindowHours = 72
	// MaxWitnesses caps the witness list either verifier will process. A DIV quorum is single
	// digits — this is a denial-of-service bound, not a policy limit, because verification runs in
	// the relying party's own process on an attacker-supplied receipt immediately before an
	// irreversible action. Mirrors MAX_WITNESSES in the TS reference, where a 20,000-witness
	// receipt measured 3.6 seconds of blocked event loop and a 1.16 MB failure string.
	MaxWitnesses = 64
	// maxReportedFailures caps how many per-witness failure reasons are folded into a returned
	// Reason string; the rest are elided as "+N more".
	maxReportedFailures = 8
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
	Signatures        []ApprovalWitness  `json:"signatures,omitempty"`
	SignerDID         *string            `json:"signerDid,omitempty"`
	SignerPublicKey   *string            `json:"signerPublicKey,omitempty"`   // base64 SPKI/raw P-256 (ES256) or COSE key (WEBAUTHN)
	Signature         *string            `json:"signature,omitempty"`         // base64 P-256 signature
	SigAlg            *string            `json:"sigAlg,omitempty"`            // "ES256" | "WEBAUTHN" | "AUTO_APPROVED"
	AuthenticatorData *string            `json:"authenticatorData,omitempty"` // base64 (WEBAUTHN only)
	ClientDataJSON    *string            `json:"clientDataJSON,omitempty"`    // base64 (WEBAUTHN only)
	Requester         *RequesterIdentity `json:"requester,omitempty"`
	VerificationCode  string             `json:"verificationCode"`
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
	// AllowOffline opts in to accepting an OFFLINE APPROVAL (DIV §5a.3). Off by default, exactly like
	// AllowAutoApproved: set it at the SPECIFIC call permitted to run under one, never globally. A
	// process-wide default would make every gated action in the service accept an out-of-band approval.
	//
	// It weakens nothing else: the quorum, four-eyes and target binding signed into the payload are
	// still enforced, the window is capped at MaxOfflineWindowMinutes, and a proof whose signed policy
	// demands a hardware key is REFUSED because that cannot be satisfied offline.
	AllowOffline bool
	// Delegation is a delegation ALREADY verified by VerifyDelegation, substituting the eligible
	// approver set and the quorum for this one verification (DIV §5a.6). Only meaningful with
	// AllowOffline. It narrows rather than widens.
	Delegation *VerifiedDelegation
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
	// ResolveKeys returns EVERY key bound to one DID, and takes precedence over ResolveKey.
	//
	// An approver commonly holds a software key plus one or more registered authenticators, and any of
	// them is legitimately theirs. Returning them all keeps the identity intact instead of forcing
	// callers to flatten everything into PublicKeys mode and lose the DID binding — which would make
	// quorum count credentials instead of people, so one approver with three keys could satisfy a
	// 3-of-N. Every key returned here counts as that ONE approver.
	ResolveKeys func(did string) []string
}

// candidates returns the keys this witness may be accepted under, each tagged with the identity it
// represents so a quorum counts distinct APPROVERS. In PublicKeys mode the identity is the key
// itself: the receipt's signerDid is unverified there, and counting it would let one approver claim
// to be three. The presented key is deliberately NOT compared against the trusted one — a mismatched
// key simply fails to verify, and byte-equality is wrong for COSE, which has many valid encodings of
// the same P-256 key.
func (a ApproverTrustAnchor) candidates(signerDID string) ([][2]string, string) {
	return a.candidatesRestricted(signerDID, nil)
}

// candidatesRestricted is candidates plus an optional narrowing to the identities a delegation names
// (DIV §5a.6 step 3). Applied ON TOP of the trust anchor, never instead of it: a delegation says WHO
// may approve, and the anchor still says which key is actually theirs.
func (a ApproverTrustAnchor) candidatesRestricted(signerDID string, restrictTo []string) ([][2]string, string) {
	if len(a.PublicKeys) > 0 {
		// A delegation names identities, and in PublicKeys mode signerDID is an unverified string —
		// enforcing DelegatedTo against it would be security theatre. Refuse rather than pretend.
		if restrictTo != nil {
			return nil, "a delegation names approver identities, so it requires a DID-mode trust anchor (DIDs + ResolveKeys); in PublicKeys mode signerDid is unverified and delegatedTo cannot be enforced"
		}
		out := make([][2]string, 0, len(a.PublicKeys))
		for _, k := range a.PublicKeys {
			out = append(out, [2]string{k, k})
		}
		return out, ""
	}
	if len(a.DIDs) == 0 || (a.ResolveKey == nil && a.ResolveKeys == nil) {
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
	if restrictTo != nil {
		named := false
		for _, d := range restrictTo {
			if d == signerDID {
				named = true
				break
			}
		}
		if !named {
			return nil, fmt.Sprintf("signer %s is not named in the delegation", signerDID)
		}
	}
	var keys []string
	if a.ResolveKeys != nil {
		keys = a.ResolveKeys(signerDID)
	} else if key := a.ResolveKey(signerDID); key != "" {
		keys = []string{key}
	}
	out := make([][2]string, 0, len(keys))
	for _, k := range keys {
		if k != "" {
			// All keys for one DID share that DID as their identity, so quorum still counts one approver.
			out = append(out, [2]string{k, signerDID})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Sprintf("no trusted key could be resolved for %s", signerDID)
	}
	return out, ""
}

// ApprovalWitness is one approver's signature over the canonical payload.
type ApprovalWitness struct {
	SignerDID         string  `json:"signerDid"`
	SignerPublicKey   string  `json:"signerPublicKey"`
	Signature         string  `json:"signature"`
	SigAlg            *string `json:"sigAlg,omitempty"`
	AuthenticatorData *string `json:"authenticatorData,omitempty"`
	ClientDataJSON    *string `json:"clientDataJSON,omitempty"`
}

// VerifyResult represents the verification outcome.
type VerifyResult struct {
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
	// AutoApproved reports that the receipt was pre-approved by policy and carries no human
	// signature, on both the accepted and the refused path. Mirrors the TypeScript reference so a
	// caller can distinguish "no human approved this" from an ordinary verification failure.
	AutoApproved bool `json:"autoApproved,omitempty"`
	// Signers lists the distinct approver IDENTITIES whose signatures verified, sorted, on the
	// accepted signature path only. Sorted in every port (the TS reference returned insertion order
	// until this was reconciled). Empty for AUTO_APPROVED —
	// no human signed — and on every refusal.
	Signers []string `json:"signers,omitempty"`
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
//
// It REFUSES any number whose canonical form could diverge across the TS/Go/Rust/Python ports —
// NaN/±Inf, negative zero, nonzero |x| >= 1e16, and nonzero non-integer |x| < 1e-4 — mirroring
// isPortableNumber in @intyga/mcp-schemas and the strict canonicalizer in @intyga/verify. Such a
// value serializes one way in one port and another way elsewhere (JS switches to exponent notation
// at different thresholds than Go and Python; serde_json prints -0.0 with a decimal point), so
// bytes signed over it would fail verification in another port and read as tampering there.
// Refusing up front, with a reason that names the number, is the only fail-closed option.
func StableStringify(v interface{}) (string, error) {
	if v == nil {
		return "null", nil
	}
	switch val := v.(type) {
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case string:
		// MUST NOT use encoding/json for strings: it escapes <, > and & (SetEscapeHTML) plus
		// U+2028/U+2029 (not configurable at all), none of which JSON.stringify or RFC 8785 escape.
		// Any target, display, DID or param containing one of those five characters recomputed to
		// different bytes here than in the TS/Rust/Python ports, and this verifier reported a
		// perfectly valid approval as tampering.
		return jsMarshalString(val), nil
	case float64:
		if err := checkPortableFloat(val); err != nil {
			return "", err
		}
		if val == float64(int64(val)) {
			// Safe: checkPortableFloat guarantees |val| < 1e16, far inside int64 range. Before that
			// guard existed this cast silently overflowed above 2^63.
			return strconv.FormatInt(int64(val), 10), nil
		}
		return jsonMarshalNoEscape(val), nil
	case int:
		return portableInt(int64(val))
	case int64:
		return portableInt(val)
	case []interface{}:
		items := make([]string, len(val))
		for i, x := range val {
			s, err := StableStringify(x)
			if err != nil {
				return "", err
			}
			items[i] = s
		}
		return "[" + strings.Join(items, ",") + "]", nil
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
			s, err := StableStringify(val[k])
			if err != nil {
				return "", err
			}
			// Object KEYS need the same treatment as values — a key containing "&" is just as
			// divergent as a value containing one.
			parts[i] = fmt.Sprintf("%s:%s", jsMarshalString(k), s)
		}
		return "{" + strings.Join(parts, ",") + "}", nil
	default:
		return jsonMarshalNoEscape(val), nil
	}
}

// checkPortableFloat refuses a float64 whose canonical serialization differs between the language
// ports. The rules mirror the TS reference (NonCanonicalValue in @intyga/verify): reject NaN/±Inf,
// negative zero, nonzero |x| >= 1e16, and nonzero non-integer |x| < 1e-4.
func checkPortableFloat(val float64) error {
	if math.IsNaN(val) || math.IsInf(val, 0) {
		return errors.New("NaN/Infinity is not JSON")
	}
	if val == 0 && math.Signbit(val) {
		return errors.New("-0 does not serialize portably across verifiers")
	}
	abs := math.Abs(val)
	if val != 0 && abs >= 1e16 {
		return fmt.Errorf("%v is outside the portable range (|x| < 1e16)", val)
	}
	if val != 0 && val != math.Trunc(val) && abs < 1e-4 {
		return fmt.Errorf("%v is outside the portable float range (1e-4 ≤ |x| < 1e16)", val)
	}
	return nil
}

// portableInt serializes an integer under the same |x| < 1e16 bound as floats. This branch exists
// for caller-constructed maps only (JSON decoding always yields float64), and it MUST enforce the
// bound too: every TS number is a float64, so an int64(1e17) that Go serialized exactly would sign
// bytes the TS reference can never produce — the exact drift the bound exists to prevent.
func portableInt(val int64) (string, error) {
	if val >= 1e16 || val <= -1e16 {
		return "", fmt.Errorf("%d is outside the portable range (|x| < 1e16)", val)
	}
	return strconv.FormatInt(val, 10), nil
}

// CanonicalIntentPayload builds a byte-identical DIV Intent Payload (docs/DIV.md v1). It builds the
// full object and serializes it with StableStringify (strict RFC 8785 JCS — every key sorted). Do NOT
// hand-template key order; the sort is the contract. Errors only when params carry a value
// StableStringify refuses (a non-portable number).
func CanonicalIntentPayload(
	target string,
	actionType string,
	display string,
	params map[string]interface{},
	requester RequesterIdentity,
	requirement ApprovalRequirement,
	nonce string,
	expiresAt string,
) (string, error) {
	req, rq := canonicalCommon(requester, requirement)
	obj := map[string]interface{}{
		"v":           DivVersion,
		"type":        DivIntentType,
		"target":      target,
		"actionType":  actionType,
		"display":     display,
		"params":      params,
		"requester":   req,
		"requirement": rq,
		"nonce":       nonce,
		"expiresAt":   expiresAt,
	}
	return StableStringify(obj)
}

// canonicalCommon builds the requester + requirement projection shared by all three builders. One
// definition rather than three copies: these bytes are the contract, and a field added to one builder
// but not the others is exactly the drift the golden vectors exist to catch.
func canonicalCommon(requester RequesterIdentity, requirement ApprovalRequirement) (interface{}, interface{}) {
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
	// UTF-16 code units, not Go's native UTF-8 byte order — the same comparator the object keys
	// use (utf16Less). The two orders differ only for non-BMP characters, which no AAGUID (hex
	// UUID) or DID carries today, but a set sorted one way here and another way in the TS
	// reference would produce different SIGNED BYTES, and nothing would catch it until a
	// receipt failed at a customer's site. See DIV §4.3.3.
	sort.Slice(aaguids, func(i, j int) bool { return utf16Less(aaguids[i], aaguids[j]) })
	if aaguids == nil {
		aaguids = []string{}
	}
	return map[string]interface{}{
			"did":         requester.DID,
			"attestation": attestation,
		}, map[string]interface{}{
			"requiredApprovals":      requirement.RequiredApprovals,
			"requireHardwareKey":     requirement.RequireHardwareKey,
			"allowedAaguids":         aaguids,
			"requesterCannotApprove": requirement.RequesterCannotApprove,
		}
}

// CanonicalOfflineIntentPayload builds a byte-identical OFFLINE APPROVAL payload (DIV §5a.2), pinned
// by the offlineIntentPayloads golden vectors.
//
// Deliberately a separate function rather than a type argument on CanonicalIntentPayload, so the
// ordinary approval path cannot accidentally emit an offline payload.
//
// challengedAt exists so a verifier can bound the validity WINDOW, not merely the expiry: a payload
// minted with an over-long expiresAt is otherwise indistinguishable from a correct one.
func CanonicalOfflineIntentPayload(
	target string,
	actionType string,
	display string,
	params map[string]interface{},
	requester RequesterIdentity,
	requirement ApprovalRequirement,
	nonce string,
	challengedAt string,
	expiresAt string,
) (string, error) {
	req, rq := canonicalCommon(requester, requirement)
	return StableStringify(map[string]interface{}{
		"v":            DivVersion,
		"type":         DivOfflineIntentType,
		"target":       target,
		"actionType":   actionType,
		"display":      display,
		"params":       params,
		"requester":    req,
		"requirement":  rq,
		"nonce":        nonce,
		"challengedAt": challengedAt,
		"expiresAt":    expiresAt,
	})
}

// CanonicalDelegationPayload builds a byte-identical DELEGATION payload (DIV §5a.5) — a signed
// statement about WHO MAY APPROVE, not about what may run.
//
// delegatedTo is sorted because it is a SET, exactly as allowedAaguids is. requirement describes the
// quorum that signed this delegation; delegatedQuorum is how many of delegatedTo must sign at incident
// time. Two different quorums, so both are in the signed bytes.
func CanonicalDelegationPayload(
	target string,
	actionType string,
	display string,
	params map[string]interface{},
	requester RequesterIdentity,
	requirement ApprovalRequirement,
	delegatedTo []string,
	delegatedQuorum int,
	nonce string,
	sealedAt string,
	expiresAt string,
) (string, error) {
	req, rq := canonicalCommon(requester, requirement)
	delegates := append([]string(nil), delegatedTo...)
	// UTF-16 code units, not Go's native UTF-8 byte order — the same comparator the object keys
	// use (utf16Less). The two orders differ only for non-BMP characters, which no AAGUID (hex
	// UUID) or DID carries today, but a set sorted one way here and another way in the TS
	// reference would produce different SIGNED BYTES, and nothing would catch it until a
	// receipt failed at a customer's site. See DIV §4.3.3.
	sort.Slice(delegates, func(i, j int) bool { return utf16Less(delegates[i], delegates[j]) })
	if delegates == nil {
		delegates = []string{}
	}
	return StableStringify(map[string]interface{}{
		"v":               DivVersion,
		"type":            DivDelegationType,
		"target":          target,
		"actionType":      actionType,
		"display":         display,
		"params":          params,
		"requester":       req,
		"requirement":     rq,
		"delegatedTo":     delegates,
		"delegatedQuorum": delegatedQuorum,
		"nonce":           nonce,
		"sealedAt":        sealedAt,
		"expiresAt":       expiresAt,
	})
}

// canonicalFields is just enough of the DIV Intent Payload to gate version/type and read the fields
// the relying party takes from the receipt (nonce, expiresAt) rather than asserting itself.
type canonicalFields struct {
	V               *int                 `json:"v"`
	Type            string               `json:"type"`
	Nonce           string               `json:"nonce"`
	ExpiresAt       string               `json:"expiresAt"`
	ChallengedAt    string               `json:"challengedAt"`
	SealedAt        string               `json:"sealedAt"`
	DelegatedTo     []string             `json:"delegatedTo"`
	DelegatedQuorum *int                 `json:"delegatedQuorum"`
	Requirement     *ApprovalRequirement `json:"requirement"`
}

// VerifiedDelegation is a delegation whose own signature, quorum and window have been checked by
// VerifyDelegation. It is an INPUT to a later approval check, never a substitute for one.
type VerifiedDelegation struct {
	// DelegatedTo are the identities permitted to approve at incident time, deduplicated.
	DelegatedTo []string
	// DelegatedQuorum is how many distinct members of DelegatedTo must sign.
	DelegatedQuorum int
	// The single action this delegation covers. All three must equal what is being executed.
	Target     string
	ActionType string
	Params     map[string]interface{}
	// Nonce is the delegation's OWN nonce — for the audit trail, never for authorization.
	Nonce     string
	Signers   []string
	ExpiresAt string
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
	// A DELEGATION authorizes nothing (DIV §5a.5). Refused here unconditionally — there is deliberately
	// NO option that would let one through, because a delegation that could authorize its own action
	// would be exactly the pre-signed bearer capability the design exists to avoid.
	if fields.Type == DivDelegationType {
		return VerifyResult{OK: false, Reason: "this is a delegation, which authorizes no action on its own — verify it with VerifyDelegation and pass the result as opts.Delegation, together with an offline approval signed by the delegated operators"}
	}
	offline := fields.Type == DivOfflineIntentType
	if !offline && fields.Type != DivIntentType {
		return VerifyResult{OK: false, Reason: "payload is not a div-intent-verification"}
	}
	if offline && !opts.AllowOffline {
		return VerifyResult{OK: false, Reason: "this is an offline approval; set AllowOffline at the specific call site permitted to run under one"}
	}
	// A delegation only ever substitutes the approver set for an OFFLINE proof. Accepting it against an
	// ordinary gateway-mediated receipt would silently replace the quorum the gateway enforced.
	if opts.Delegation != nil && !offline {
		return VerifyResult{OK: false, Reason: "a delegation can only substitute the approver set for an offline approval"}
	}
	if fields.Nonce != expected.Nonce {
		return VerifyResult{OK: false, Reason: "receipt is for a different challenge"}
	}

	// NOTE: the AUTO_APPROVED decision deliberately does NOT live here. Accepting it before the
	// canonical payload has been recomputed would attest a receipt on the strength of a matching
	// nonce alone — see the block after the expiry check below.

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

	// Offline proofs carry challengedAt so the validity WINDOW can be bounded here, not merely at mint.
	if offline {
		if fields.ChallengedAt == "" {
			return VerifyResult{OK: false, Reason: "offline proof is missing challengedAt"}
		}
		challenged, err := time.Parse(time.RFC3339, fields.ChallengedAt)
		if err != nil {
			return VerifyResult{OK: false, Reason: "challengedAt is not a valid RFC3339 timestamp"}
		}
		// An unparseable `expiresAt` must be refused HERE rather than skipping the window cap and
		// relying on the expiry check further down — that check is disabled by AllowExpired, so the
		// `AllowOffline + AllowExpired` combination (the documented forensic re-verification mode, and
		// the only mode under which an offline proof is examined at all) left the cap unenforced on a
		// proof whose window could not be computed at all.
		//
		// `expiresAt` is inside the signed bytes, but an offline proof is minted by whoever constructs
		// it and the verifier reconstructs the payload from the receipt's OWN expiresAt, so any string
		// round-trips. Measured before this fix: a 10-year window passed with OK=true against a
		// 60-minute cap. DIV §5a.3 makes the window the entire revocation story for an offline proof —
		// an offline relying party has no channel to recall one — so an unbounded window turns a
		// 60-minute incident credential into a permanent bearer capability for that action.
		//
		// This mirrors packages/verify/src/index.ts (the TS reference), where the same fix landed
		// first. DIV.md declares expiresAt RFC3339 UTC, so refusing a non-conformant one is correct
		// behaviour rather than a compatibility risk.
		expiry, err := time.Parse(time.RFC3339, fields.ExpiresAt)
		if err != nil {
			return VerifyResult{OK: false, Reason: "expiresAt is not a valid RFC3339 timestamp"}
		}
		window := expiry.Sub(challenged)
		if window < 0 {
			return VerifyResult{OK: false, Reason: "offline proof expires before it was challenged"}
		}
		if window > time.Duration(MaxOfflineWindowMinutes)*time.Minute {
			return VerifyResult{OK: false, Reason: fmt.Sprintf(
				"offline window is %.1f minutes, over the %d-minute maximum", window.Minutes(), MaxOfflineWindowMinutes)}
		}
		// A hardware-key policy CANNOT be satisfied offline (DIV §5a.3 step 4). WebAuthn needs a secure
		// context and an RP ID an offline signing surface will not match, so an offline witness is always
		// a bare key. Accepting the proof anyway would silently downgrade the policy the approver
		// attested to, so it is refused instead — fail closed, and say why.
		if fields.Requirement.RequireHardwareKey {
			return VerifyResult{OK: false, Reason: "the signed policy requires a hardware-backed WebAuthn credential, which cannot be produced offline — this action cannot be approved out of band (DIV §5a.3)"}
		}
	}

	// A delegation substitutes WHO may approve and HOW MANY, and nothing else (DIV §5a.6). Every
	// agreement check is on the SIGNED bytes of both proofs, so neither can widen the other.
	var delegatedTo []string
	delegatedQuorum := 0
	if opts.Delegation != nil {
		d := opts.Delegation
		if d.Target != expected.Target {
			return VerifyResult{OK: false, Reason: "the delegation was issued for a different target"}
		}
		if d.ActionType != expected.ActionType {
			return VerifyResult{OK: false, Reason: "the delegation was issued for a different actionType"}
		}
		delegationParams, dErr := StableStringify(d.Params)
		executingParams, eErr := StableStringify(expected.Params)
		if dErr != nil || eErr != nil {
			cause := dErr
			if cause == nil {
				cause = eErr
			}
			// A non-portable number, not a mismatch — say so, rather than sending the caller
			// hunting for a tampering that isn't there.
			return VerifyResult{OK: false, Reason: "params are not canonicalizable: " + cause.Error()}
		}
		if delegationParams != executingParams {
			return VerifyResult{OK: false, Reason: "the delegation was issued for different params"}
		}
		// The offline payload's signed quorum must equal the delegated one, so the operators signed the
		// policy their signatures are being counted toward rather than a different one.
		if fields.Requirement.RequiredApprovals != d.DelegatedQuorum {
			return VerifyResult{OK: false, Reason: fmt.Sprintf(
				"offline proof declares %d required approval(s) but the delegation delegates a quorum of %d",
				fields.Requirement.RequiredApprovals, d.DelegatedQuorum)}
		}
		delegatedTo = d.DelegatedTo
		delegatedQuorum = d.DelegatedQuorum
	}

	var recomputed string
	var recomputeErr error
	if offline {
		recomputed, recomputeErr = CanonicalOfflineIntentPayload(
			expected.Target,
			expected.ActionType,
			receipt.ActionDescription,
			expected.Params,
			*receipt.Requester,
			*fields.Requirement,
			fields.Nonce,
			fields.ChallengedAt,
			fields.ExpiresAt,
		)
	} else {
		recomputed, recomputeErr = CanonicalIntentPayload(
			expected.Target,
			expected.ActionType,
			receipt.ActionDescription,
			expected.Params,
			*receipt.Requester,
			*fields.Requirement,
			fields.Nonce,
			fields.ExpiresAt,
		)
	}
	if recomputeErr != nil {
		// Almost always expected.Params carrying a non-portable number (see StableStringify). This
		// reason is deliberately DISTINCT from the mismatch below: reporting it as "do not match"
		// would send an operator chasing a tampering that isn't there.
		return VerifyResult{OK: false, Reason: "expected.Params is not canonicalizable: " + recomputeErr.Error()}
	}

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

	// A policy AUTO_APPROVED receipt carries NO human signature, so there is nothing to verify
	// cryptographically and a relying party must opt in. Opting in waives the SIGNATURE requirement —
	// it does not waive DIV §5 steps 8 and 9. This check therefore sits AFTER the canonical payload
	// comparison and the expiry check, matching the TypeScript reference.
	//
	// It used to sit immediately after the nonce comparison. An agent holding a nonce could then get
	// any trivial action auto-approved under it and present that receipt for a destructive call: the
	// target, actionType and params were never examined, and a years-expired approval passed too.
	if receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
		// An offline approval with no human signature is a contradiction: the entire premise is that
		// humans signed out of band, so AllowAutoApproved must not rescue it.
		if offline {
			return VerifyResult{OK: false, AutoApproved: true, Reason: "an offline approval cannot be auto-approved — there is no human signature to verify"}
		}
		if !opts.AllowAutoApproved {
			return VerifyResult{OK: false, AutoApproved: true, Reason: "AUTO_APPROVED receipts are refused by default"}
		}
		return VerifyResult{OK: true, AutoApproved: true}
	}

	witnesses := witnessesOf(receipt)
	if len(witnesses) == 0 {
		return VerifyResult{OK: false, Reason: "missing signature or public key"}
	}
	// The witness list is attacker-supplied and every entry costs ECDSA verifications, in the
	// relying party's own process, immediately before the action it gates. A real quorum is single
	// digits; the TS reference measured a 20,000-witness receipt at 3.6s of blocked event loop and
	// a 1.16 MB failure string. Bound it.
	if len(witnesses) > MaxWitnesses {
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"receipt carries %d witnesses, above the %d this verifier will process", len(witnesses), MaxWitnesses)}
	}

	// Count DISTINCT approvers whose signature verifies under a key we independently trust. Distinct
	// is load-bearing: without it, N copies of one approver's signature satisfy an N-of-M quorum.
	verified := map[string]bool{}
	var failures []string
	for _, w := range witnesses {
		cands, reason := expected.Approvers.candidatesRestricted(w.SignerDID, delegatedTo)
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

	// Under a delegation the quorum is the DELEGATED one. Already checked to equal the offline payload's
	// signed RequiredApprovals, so this is the same number by a different route — stated explicitly so
	// the substitution is visible where it takes effect.
	required := fields.Requirement.RequiredApprovals
	if delegatedQuorum > 0 {
		required = delegatedQuorum
	}
	if required < 1 {
		required = 1
	}
	if len(verified) < required {
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"quorum not met: %d of %d required approver signatures verified%s",
			len(verified), required, foldFailures(failures))}
	}
	signers := make([]string, 0, len(verified))
	for k := range verified {
		signers = append(signers, k)
	}
	sort.Strings(signers)
	return VerifyResult{OK: true, Signers: signers}
}

// VerifyDelegation verifies a DELEGATION (DIV §5a.6 step 1) — a statement, signed in advance by the
// ordinary quorum, naming local operators who may approve one pre-declared action while the gateway is
// unreachable.
//
// Deliberately a SEPARATE function from VerifyApprovalReceipt, which refuses this payload type
// outright. A delegation authorizes nothing, and the only way to keep that true structurally is to make
// it impossible to hand one to the approval verifier and get an OK back. What you get here is a
// VerifiedDelegation — an input to a later approval check, never a substitute for one.
//
// expected.Approvers MUST be the ORDINARY approver set, not the delegated operators: the point of the
// check is that the people entitled to approve this action are the ones who signed away that
// entitlement.
func VerifyDelegation(receipt ApprovalReceipt, expected Expected, opts VerifyOptions) (VerifyResult, *VerifiedDelegation) {
	if receipt.CanonicalPayload == "" {
		return VerifyResult{OK: false, Reason: "missing canonicalPayload"}, nil
	}
	var fields canonicalFields
	if err := json.Unmarshal([]byte(receipt.CanonicalPayload), &fields); err != nil {
		return VerifyResult{OK: false, Reason: "canonicalPayload is not valid JSON"}, nil
	}
	if fields.V == nil || *fields.V != DivVersion {
		return VerifyResult{OK: false, Reason: "unsupported DIV payload version"}, nil
	}
	if fields.Type != DivDelegationType {
		return VerifyResult{OK: false, Reason: "payload is not a div-delegation"}, nil
	}
	if len(fields.DelegatedTo) == 0 {
		return VerifyResult{OK: false, Reason: "delegation is missing a valid delegatedTo set"}, nil
	}
	if fields.DelegatedQuorum == nil || *fields.DelegatedQuorum < 1 {
		return VerifyResult{OK: false, Reason: "delegation is missing a valid delegatedQuorum"}, nil
	}
	// Deduplicate before the size check: a delegatedTo listing one operator three times would otherwise
	// appear to support a 3-of-3 quorum that one person could satisfy alone.
	seen := map[string]bool{}
	var distinct []string
	for _, d := range fields.DelegatedTo {
		if d != "" && !seen[d] {
			seen[d] = true
			distinct = append(distinct, d)
		}
	}
	if len(distinct) < *fields.DelegatedQuorum {
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"delegation names %d distinct operator(s) but delegates a quorum of %d — it can never be satisfied",
			len(distinct), *fields.DelegatedQuorum)}, nil
	}
	if fields.SealedAt == "" {
		return VerifyResult{OK: false, Reason: "delegation is missing sealedAt"}, nil
	}
	if fields.ExpiresAt == "" {
		return VerifyResult{OK: false, Reason: "delegation is missing expiresAt"}, nil
	}
	sealed, err := time.Parse(time.RFC3339, fields.SealedAt)
	if err != nil {
		return VerifyResult{OK: false, Reason: "sealedAt is not a valid RFC3339 timestamp"}, nil
	}
	expiry, err := time.Parse(time.RFC3339, fields.ExpiresAt)
	if err != nil {
		return VerifyResult{OK: false, Reason: "expiresAt is not a valid RFC3339 timestamp"}, nil
	}
	window := expiry.Sub(sealed)
	if window < 0 {
		return VerifyResult{OK: false, Reason: "delegation expires before it was sealed"}, nil
	}
	if window > time.Duration(MaxDelegationWindowHours)*time.Hour {
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"delegation window is %.1f hours, over the %d-hour maximum", window.Hours(), MaxDelegationWindowHours)}, nil
	}
	if receipt.Requester == nil {
		return VerifyResult{OK: false, Reason: "delegation missing requester"}, nil
	}
	if fields.Requirement == nil {
		return VerifyResult{OK: false, Reason: "delegation payload is missing the signed approval requirement"}, nil
	}
	if expected.Target == "" {
		return VerifyResult{OK: false, Reason: "expected.Target is required — it must be YOUR target identifier, asserted independently of the delegation (DIV Target Isolation)"}, nil
	}

	recomputed, recomputeErr := CanonicalDelegationPayload(
		expected.Target,
		expected.ActionType,
		receipt.ActionDescription,
		expected.Params,
		*receipt.Requester,
		*fields.Requirement,
		fields.DelegatedTo,
		*fields.DelegatedQuorum,
		fields.Nonce,
		fields.SealedAt,
		fields.ExpiresAt,
	)
	if recomputeErr != nil {
		// A non-portable number in expected.Params, not tampering — the mismatch reason below would
		// send an operator chasing a forgery that isn't there.
		return VerifyResult{OK: false, Reason: "expected.Params is not canonicalizable: " + recomputeErr.Error()}, nil
	}
	if recomputed != receipt.CanonicalPayload {
		return VerifyResult{OK: false, Reason: "target/params/actionType do not match what was delegated"}, nil
	}

	if !opts.AllowExpired {
		now := opts.AsOf
		if now.IsZero() {
			now = time.Now()
		}
		skew := DefaultClockSkewSeconds
		if opts.ClockSkewSeconds != nil {
			skew = *opts.ClockSkewSeconds
		}
		if now.After(expiry.Add(time.Duration(skew) * time.Second)) {
			return VerifyResult{OK: false, Reason: "delegation has expired (set AllowExpired for audit re-verification)"}, nil
		}
	}
	if receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
		return VerifyResult{OK: false, Reason: "a delegation cannot be auto-approved — delegating approval authority requires human signatures"}, nil
	}

	witnesses := witnessesOf(receipt)
	if len(witnesses) == 0 {
		return VerifyResult{OK: false, Reason: "delegation missing signature material"}, nil
	}
	// Same denial-of-service bound as the approval path: the witness list is attacker-supplied and
	// each entry costs ECDSA verifications in the relying party's own process.
	if len(witnesses) > MaxWitnesses {
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"delegation carries %d witnesses, above the %d this verifier will process", len(witnesses), MaxWitnesses)}, nil
	}
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
		if fields.Requirement.RequireHardwareKey && (w.SigAlg == nil || *w.SigAlg != "WEBAUTHN") {
			failures = append(failures, fmt.Sprintf(
				"signer %s used a bare key, but the signed policy requires a hardware-backed WebAuthn credential", w.SignerDID))
			continue
		}
		if fields.Requirement.RequesterCannotApprove && w.SignerDID == receipt.Requester.DID {
			failures = append(failures, fmt.Sprintf(
				"four-eyes: requester %s cannot delegate to themselves", w.SignerDID))
			continue
		}
		verified[matched] = true
	}
	required := fields.Requirement.RequiredApprovals
	if required < 1 {
		required = 1
	}
	if len(verified) < required {
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"delegation quorum not met: %d of %d required approver signatures verified%s",
			len(verified), required, foldFailures(failures))}, nil
	}

	signers := make([]string, 0, len(verified))
	for k := range verified {
		signers = append(signers, k)
	}
	sort.Strings(signers)
	return VerifyResult{OK: true}, &VerifiedDelegation{
		// The DEDUPLICATED set: this is what gets enforced against witness DIDs later, and a duplicate
		// entry must not create the illusion of a larger eligible pool.
		DelegatedTo:     distinct,
		DelegatedQuorum: *fields.DelegatedQuorum,
		Target:          expected.Target,
		ActionType:      expected.ActionType,
		Params:          expected.Params,
		Nonce:           fields.Nonce,
		Signers:         signers,
		ExpiresAt:       fields.ExpiresAt,
	}
}

// foldFailures renders at most maxReportedFailures per-witness reasons as a parenthesized detail
// suffix, eliding the rest as "+N more". Folding every failure is what turned a long witness list
// into a megabyte of error text in the TS reference; the leading reasons are the diagnostic ones
// anyway.
func foldFailures(failures []string) string {
	if len(failures) == 0 {
		return ""
	}
	shown := failures
	elided := 0
	if len(failures) > maxReportedFailures {
		shown = failures[:maxReportedFailures]
		elided = len(failures) - maxReportedFailures
	}
	detail := " (" + strings.Join(shown, "; ")
	if elided > 0 {
		detail += fmt.Sprintf("; +%d more", elided)
	}
	return detail + ")"
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
