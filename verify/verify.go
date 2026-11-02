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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

var agentDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var agentSequencePattern = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
var agentDecimalPattern = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,29})(?:\.[0-9]{1,9})?$`)
var agentCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
var agentTimePattern = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$`)

// The caller supplies this independently of the receipt. Keep these checks aligned with the
// TypeScript reference before local payload reconstruction accepts the asserted context.
func validateAgentContext(context map[string]interface{}, exp string, sigAlg *string) string {
	obj := func(value interface{}) map[string]interface{} { out, _ := value.(map[string]interface{}); return out }
	str := func(value interface{}) string { out, _ := value.(string); return out }
	action, agent, session := obj(context["action"]), obj(context["agent"]), obj(context["session"])
	reversibility := str(action["reversibility"])
	if reversibility != "reversible" && reversibility != "irreversible" {
		return "invalid agent action reversibility"
	}
	label, configDigest := str(agent["label"]), str(agent["configDigest"])
	if label == "" || len(utf16.Encode([]rune(label))) > 200 || !agentDigestPattern.MatchString(configDigest) {
		return "invalid agent identity or configuration digest"
	}
	if !norm.NFC.IsNormalString(label) || !norm.NFC.IsNormalString(str(session["id"])) {
		return "agent labels and session identifiers must be NFC"
	}
	delegatedBy, hasDelegatedBy := agent["delegatedBy"]
	if !hasDelegatedBy || (delegatedBy != nil && !agentDigestPattern.MatchString(str(delegatedBy))) {
		return "invalid parent authority digest"
	}
	id, seq := str(session["id"]), str(session["seq"])
	if !agentDigestPattern.MatchString(id) || !agentSequencePattern.MatchString(seq) {
		return "invalid agent session identity or sequence"
	}
	prev, hasPrev := session["prev"]
	if !hasPrev || (seq == "1") != (prev == nil) || (prev != nil && !agentDigestPattern.MatchString(str(prev))) {
		return "invalid agent session predecessor"
	}
	validMoney := func(value interface{}) bool {
		m := obj(value)
		return m != nil && agentDecimalPattern.MatchString(str(m["amount"])) && agentCurrencyPattern.MatchString(str(m["currency"]))
	}
	amount, hasAmount := action["amount"]
	aggregate, hasAggregate := session["aggregate"]
	if !hasAmount || !hasAggregate {
		return "invalid agent monetary amount"
	}
	if (amount != nil && !validMoney(amount)) || (aggregate != nil && !validMoney(aggregate)) {
		return "invalid agent monetary amount"
	}
	if (amount == nil) != (aggregate == nil) || (amount != nil && str(obj(amount)["currency"]) != str(obj(aggregate)["currency"])) {
		return "agent monetary amount and aggregate disagree"
	}
	nbf := str(context["nbf"])
	from, fromErr := time.Parse("2006-01-02T15:04:05.000Z", nbf)
	to, toErr := time.Parse("2006-01-02T15:04:05.000Z", exp)
	if !agentTimePattern.MatchString(nbf) || !agentTimePattern.MatchString(exp) || fromErr != nil || toErr != nil || !to.After(from) || to.Sub(from) > 5*time.Minute {
		return "agent intent must use canonical UTC times within five minutes"
	}
	if reversibility == "irreversible" && sigAlg != nil && *sigAlg == "AUTO_APPROVED" {
		return "irreversible agent action requires a human signature"
	}
	return ""
}

// DIV protocol constants. v1 remains the historical unbound format; v2 adds tenantId.
const (
	DivVersion            = 1
	DivTenantBoundVersion = 2
	DivIntentType         = "div-intent-verification"
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
	// Agent authorities and platform intents have dedicated verification entry points. They must
	// never be accepted by VerifyApprovalReceipt because neither is an ordinary action approval.
	DivAgentAuthorityType = "div-agent-authority"
	DivPlatformIntentType = "div-platform-intent"
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
	MaxWitnesses            = 64
	SelfCertifyingDIDPrefix = "did:intyga:key:"
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
// model); AllowedAaguids not at all (the AAGUID lives in registration data, never in an assertion) —
// but a non-empty allowlist is refused exactly like RequireHardwareKey for bare-key and offline witnesses.
// SignerClass is partially checkable: a WEBAUTHN witness's UV flag corroborates a human ceremony,
// an ES256 witness carries no class evidence — but the verifier's own rule is absolute: refuse any
// value it does not recognize ("human" is the only class defined today, DIV §4.3.2).
type ApprovalRequirement struct {
	RequiredApprovals      int      `json:"requiredApprovals"`
	RequireHardwareKey     bool     `json:"requireHardwareKey"`
	AllowedAaguids         []string `json:"allowedAaguids"`
	RequesterCannotApprove bool     `json:"requesterCannotApprove"`
	SignerClass            string   `json:"signerClass"`
	// ExcludedSignerDIDs is nil when the field was absent from historical signed bytes. A non-nil
	// empty slice is an explicitly signed empty set and must remain present during reconstruction.
	ExcludedSignerDIDs *[]string `json:"excludedSignerDids,omitempty"`
	// RequireEnrolledDevice is DIV §4.3.2 "Enrolled approver devices": serialized only when true, and
	// then as the literal `true` (absence is "not required", so historical bytes are unchanged). Defined
	// only for div-intent-verification payloads and never together with a hardware requirement. Under
	// it only an ES256 witness under one of the caller's Expected.EnrolledDeviceKeys counts.
	RequireEnrolledDevice bool `json:"requireEnrolledDevice,omitempty"`
	// excludedSignerDIDsNull records a present-but-null excludedSignerDids, which encoding/json
	// would otherwise collapse into the nil pointer of an absent field (DIV §4.3.2: refused, not dropped).
	excludedSignerDIDsNull bool
	// requireEnrolledDeviceMalformed records a present requireEnrolledDevice whose value is anything
	// but the literal `true` (false, null, a string, ...). A bool cannot tell present-false from
	// absent, and DIV §4.3.2 refuses the former rather than dropping it.
	requireEnrolledDeviceMalformed bool
}

// UnmarshalJSON keeps a present-but-null excludedSignerDids distinguishable from an absent one, and a
// present requireEnrolledDevice other than `true` distinguishable from an absent one.
func (r *ApprovalRequirement) UnmarshalJSON(data []byte) error {
	type requirementFields ApprovalRequirement
	// The outer field shadows the embedded bool (shallower depth wins in encoding/json), so a
	// non-boolean value is captured for refusal instead of failing the whole payload parse.
	var decoded struct {
		requirementFields
		RequireEnrolledDevice json.RawMessage `json:"requireEnrolledDevice"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = ApprovalRequirement(decoded.requirementFields)
	r.excludedSignerDIDsNull = jsonFieldIsNull(data, "excludedSignerDids")
	r.RequireEnrolledDevice = false
	r.requireEnrolledDeviceMalformed = false
	if decoded.RequireEnrolledDevice != nil {
		if strings.TrimSpace(string(decoded.RequireEnrolledDevice)) == "true" {
			r.RequireEnrolledDevice = true
		} else {
			r.requireEnrolledDeviceMalformed = true
		}
	}
	return nil
}

// DIV §5 step 3e refusal texts. Identical in every port (pinned by verifier-parity-vectors.json),
// with the TypeScript API name expected.enrolledDeviceKeys rewritten to Go's.
const (
	EnrolledDeviceMalformedReason     = "requirement.requireEnrolledDevice must be omitted or true (DIV §4.3.2)"
	EnrolledDeviceOrdinaryOnlyReason  = "requireEnrolledDevice is defined only for ordinary approval intents (DIV §4.3.2)"
	EnrolledDeviceWithHardwareReason  = "requireEnrolledDevice cannot be combined with requireHardwareKey or allowedAaguids (DIV §4.3.2)"
	EnrolledDeviceKeysRequiredReason  = "the signed policy requires an enrolled approver device; supply expected.EnrolledDeviceKeys from your own enrollment records (DIV §4.3.2)"
	EnrolledDeviceKeysMalformedReason = "expected.EnrolledDeviceKeys must be an array of base64 public keys"
)

// enrolledDeviceStructureProblem is DIV §5 step 3e, structural half: the signed field is absent, or
// exactly `true` on an ordinary intent with no hardware requirement. `ordinary` is whether the
// payload type is div-intent-verification. Read from the parsed signed requirement, so `false` and
// `null` are refused rather than dropped.
func enrolledDeviceStructureProblem(requirement ApprovalRequirement, ordinary bool) string {
	if requirement.requireEnrolledDeviceMalformed {
		return EnrolledDeviceMalformedReason
	}
	if !requirement.RequireEnrolledDevice {
		return ""
	}
	if !ordinary {
		return EnrolledDeviceOrdinaryOnlyReason
	}
	if requirement.RequiresHardwareCredential() {
		return EnrolledDeviceWithHardwareReason
	}
	return ""
}

// enrolledDeviceFingerprints is DIV §5 step 3e, list half: the caller's enrolled device keys as key
// fingerprints (so SPKI and COSE spellings of one key match, like the one-key-one-person rule), or a
// refusal reason. Only consulted under a signed requireEnrolledDevice; a malformed list is refused
// even then, never read as "no list". A nil and an empty list are both "no list".
func enrolledDeviceFingerprints(keys []string) (map[string]bool, string) {
	if keys == nil {
		return nil, EnrolledDeviceKeysRequiredReason
	}
	for _, key := range keys {
		if key == "" {
			return nil, EnrolledDeviceKeysMalformedReason
		}
	}
	if len(keys) == 0 {
		return nil, EnrolledDeviceKeysRequiredReason
	}
	out := make(map[string]bool, len(keys))
	for _, key := range keys {
		out[signingKeyIdentity(key)] = true
	}
	return out, ""
}

// jsonFieldIsNull reports whether object `data` carries `key` with an explicit null value.
func jsonFieldIsNull(data []byte, key string) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil {
		return false
	}
	raw, ok := fields[key]
	return ok && strings.TrimSpace(string(raw)) == "null"
}

// RequiresHardwareCredential: RequireHardwareKey, or a non-empty AllowedAaguids model allowlist. A bare
// key satisfies neither and neither can be met offline (DIV §4.3.2), so every check treats them alike.
func (r ApprovalRequirement) RequiresHardwareCredential() bool {
	return r.RequireHardwareKey || len(r.AllowedAaguids) > 0
}

// knownSignerClasses are the signer classes this verifier can reason about (DIV §4.3.2). "human" is
// the only class defined today.
var knownSignerClasses = map[string]bool{"human": true}

// checkSignerClass validates requirement.signerClass out of the signed bytes. FAIL CLOSED both ways:
// an absent class predates (or dropped) the field, and an unrecognized class must never verify as if
// it were human-approved — that is the entire point of putting the class in the signed bytes.
func checkSignerClass(requirement ApprovalRequirement) (bool, string) {
	if requirement.SignerClass == "" {
		return false, "the signed requirement is missing signerClass (DIV §4.3.2)"
	}
	if !knownSignerClasses[requirement.SignerClass] {
		return false, "the signed requirement declares signerClass \"" + requirement.SignerClass + "\", which this verifier does not recognize — refusing rather than treating it as human-approved (DIV §4.3.2)"
	}
	return true, ""
}

// checkEvidence validates the reserved `evidence` field out of the signed bytes (DIV §4.3.4).
// REQUIRED to be present and REQUIRED to be null in v1; a non-null value is an evidence-conditioned
// authorization whose semantics this verifier has not been taught, and must never verify as if it
// were unconditioned.
//
// Takes json.RawMessage, not a *T: encoding/json maps BOTH an absent key and an explicit null to a
// nil pointer, so a pointer field cannot express the distinction this check is made of. A raw
// message is nil only when the key is absent, and holds the four bytes "null" when it is present.
func checkEvidence(raw json.RawMessage) (bool, string) {
	if raw == nil {
		return false, "the signed payload is missing evidence (DIV §4.3.4)"
	}
	if strings.TrimSpace(string(raw)) != "null" {
		return false, "the signed payload declares an evidence condition, which this verifier does not support — refusing rather than treating it as unconditioned (DIV §4.3.4)"
	}
	return true, ""
}

// invalidQuorumReason is the shared refusal text for a signed quorum below DIV §4.3.2's minimum.
const invalidQuorumReason = "signed requirement.requiredApprovals must be an integer of at least 1 (DIV §4.3.2)"

// checkQuorumMinimum enforces DIV §4.3.2: requiredApprovals is an integer ≥ 1. Stated as its own
// refusal rather than clamped, because §5 step 7 rejects unless the counted identities are AT LEAST
// this number — 0 is satisfied by counting nothing, so an unenforced minimum would attest an
// envelope carrying no valid witness signature. (Non-integral values never reach here: the field
// unmarshals into an int, so a fractional one fails the payload parse instead.)
func checkQuorumMinimum(requirement ApprovalRequirement) (bool, string) {
	if requirement.RequiredApprovals < 1 {
		return false, invalidQuorumReason
	}
	return true, ""
}

func checkExcludedSigners(requirement ApprovalRequirement, requester RequesterIdentity) (bool, string) {
	// Present-but-null is malformed, not absent (DIV §4.3.2), exactly as the reference refuses it.
	if requester.credentialIssuerDIDNull ||
		(requester.CredentialIssuerDID != nil && !validOptionalDID(*requester.CredentialIssuerDID)) {
		return false, "signed requester.credentialIssuerDid must be a non-empty DID"
	}
	if requirement.excludedSignerDIDsNull {
		return false, "signed requirement.excludedSignerDids must be an array of valid DIDs"
	}
	if requirement.ExcludedSignerDIDs == nil {
		return true, ""
	}
	// Every entry's validity first, then repeats — the reference's order and texts.
	for _, did := range *requirement.ExcludedSignerDIDs {
		if !validOptionalDID(did) {
			return false, "signed requirement.excludedSignerDids must be an array of valid DIDs"
		}
	}
	seen := map[string]bool{}
	for _, did := range *requirement.ExcludedSignerDIDs {
		if seen[did] {
			return false, "signed requirement.excludedSignerDids must not contain duplicates"
		}
		seen[did] = true
	}
	return true, ""
}

func validOptionalDID(value string) bool {
	if len(value) > 4096 || !utf8.ValidString(value) || !strings.HasPrefix(value, "did:") || len(value) == 4 {
		return false
	}
	for _, r := range value {
		if r <= 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// RequirementFloor is the MINIMUM approval requirement the relying party's own policy demands for
// this action (DIV §5 step 3d). The signed requirement is authored by whoever composed the bytes the
// approvers signed — the issuer, or any one approver composing their own payload — so its signature
// protects it against third parties but NOT against the signers the quorum constrains. Without a
// floor, a verifier proves only the signers' OWN stated quorum: an approver who is also the requester
// can sign {requiredApprovals: 1, requesterCannotApprove: false} alone and it verifies.
//
// Only strictly weaker signed values are refused; an equal or stricter one passes and the SIGNED
// value is then enforced. AllowedAaguids is not floored — express that as RequireHardwareKey.
type RequirementFloor struct {
	// Integer ≥ 1. The signed requiredApprovals must be at least this.
	RequiredApprovals int `json:"requiredApprovals"`
	// When true, the signed requirement must also forbid the requester approving.
	RequesterCannotApprove bool `json:"requesterCannotApprove"`
	// When true, the signed requirement must also demand a hardware key.
	RequireHardwareKey bool `json:"requireHardwareKey"`
	// When true, the signed requirement must also demand an enrolled approver device (DIV §4.3.2).
	RequireEnrolledDevice bool `json:"requireEnrolledDevice"`
	// When present, the signed exclusion set must be present and include every DID in this floor.
	ExcludedSignerDIDs *[]string `json:"excludedSignerDids,omitempty"`
	// malformedFlag records a floor decoded from JSON whose boolean flag was present but not a JSON
	// boolean (null, "yes", ...). Such a floor fails CLOSED as malformed, as in the reference, rather
	// than reading the flag as false.
	malformedFlag bool
}

// UnmarshalJSON decodes a floor from your own policy configuration. A flag that is present but not a
// JSON boolean marks the floor malformed (refused at verification) instead of silently meaning false.
func (f *RequirementFloor) UnmarshalJSON(data []byte) error {
	type floorFields RequirementFloor
	var decoded struct {
		floorFields
		RequesterCannotApprove json.RawMessage `json:"requesterCannotApprove"`
		RequireHardwareKey     json.RawMessage `json:"requireHardwareKey"`
		RequireEnrolledDevice  json.RawMessage `json:"requireEnrolledDevice"`
	}
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*f = RequirementFloor(decoded.floorFields)
	f.malformedFlag = false
	flag := func(raw json.RawMessage) bool {
		if raw == nil {
			return false
		}
		switch strings.TrimSpace(string(raw)) {
		case "true":
			return true
		case "false":
			return false
		}
		f.malformedFlag = true
		return false
	}
	f.RequesterCannotApprove = flag(decoded.RequesterCannotApprove)
	f.RequireHardwareKey = flag(decoded.RequireHardwareKey)
	f.RequireEnrolledDevice = flag(decoded.RequireEnrolledDevice)
	return nil
}

// nonceRequiredReason refuses an omitted expected nonce, immediately before the nonce comparison.
const nonceRequiredReason = "expected.Nonce is required — it must be the challenge YOU issued (DIV §5 step 10)"

// keyOnlyFourEyesReason refuses a signed four-eyes rule or exclusion set against a key-set anchor.
const keyOnlyFourEyesReason = "requesterCannotApprove requires a DID-mode trust anchor; key-only mode cannot authenticate requester identity"

// isUnset reports the zero anchor — no keys, no DIDs, no resolver — which is the reference's absent
// expected.approvers.
func (a ApproverTrustAnchor) isUnset() bool {
	return a.PublicKeys == nil && a.DIDs == nil && a.ResolveKey == nil && a.ResolveKeys == nil
}

// WeakerRequirementReason is the reason stem every port uses for a signed requirement below the
// caller's floor.
const WeakerRequirementReason = "signed requirement is weaker than the relying party's policy"

// checkRequirementFloor is DIV §5 step 3d. A nil floor is "none supplied" (legacy behaviour). A
// malformed floor fails CLOSED rather than silently meaning "no floor".
func checkRequirementFloor(signed ApprovalRequirement, floor *RequirementFloor) (bool, string) {
	if floor == nil {
		return true, ""
	}
	// The reference's single malformed-floor text, then its order: exclusion coverage, quorum, the
	// requester flag, the hardware flag, the enrolled-device flag. A repeated DID in the floor is accepted: it is a set the
	// signed exclusions must cover.
	malformed := floor.RequiredApprovals < 1 || floor.malformedFlag
	if floor.ExcludedSignerDIDs != nil {
		for _, did := range *floor.ExcludedSignerDIDs {
			if !validOptionalDID(did) {
				malformed = true
			}
		}
	}
	if malformed {
		return false, "expected.Requirement is malformed: requiredApprovals must be an integer of at least 1 and the flags booleans"
	}
	if floor.ExcludedSignerDIDs != nil {
		if signed.ExcludedSignerDIDs == nil || !stringSetContains(*signed.ExcludedSignerDIDs, *floor.ExcludedSignerDIDs) {
			return false, WeakerRequirementReason + ": it omits a required signer exclusion"
		}
	}
	if signed.RequiredApprovals < floor.RequiredApprovals {
		return false, fmt.Sprintf("%s: it requires %d approval(s), the policy %d (DIV §5 step 3d)", WeakerRequirementReason, signed.RequiredApprovals, floor.RequiredApprovals)
	}
	if floor.RequesterCannotApprove && !signed.RequesterCannotApprove {
		return false, WeakerRequirementReason + ": it does not forbid the requester approving (DIV §5 step 3d)"
	}
	if floor.RequireHardwareKey && !signed.RequireHardwareKey {
		return false, WeakerRequirementReason + ": it does not require a hardware key (DIV §5 step 3d)"
	}
	if floor.RequireEnrolledDevice && !signed.RequireEnrolledDevice {
		return false, WeakerRequirementReason + ": it does not require an enrolled approver device (DIV §5 step 3d)"
	}
	return true, ""
}

func stringSetContains(have, required []string) bool {
	set := map[string]bool{}
	for _, value := range have {
		set[value] = true
	}
	for _, value := range required {
		if !set[value] {
			return false
		}
	}
	return true
}

// evaluationTime resolves the instant and skew tolerance every time-based check in this package
// shares: expiry (DIV §6.2) and the forward-dating rule of §5a.3 rule 3.
func evaluationTime(opts VerifyOptions) (time.Time, time.Duration) {
	now := opts.AsOf
	if now.IsZero() {
		now = time.Now()
	}
	skew := DefaultClockSkewSeconds
	if opts.ClockSkewSeconds != nil {
		skew = *opts.ClockSkewSeconds
	}
	return now, time.Duration(skew) * time.Second
}

// RequesterIdentity defines who requested the action.
type RequesterIdentity struct {
	DID                 string                `json:"did"`
	Attestation         *RequesterAttestation `json:"attestation"`
	CredentialIssuerDID *string               `json:"credentialIssuerDid,omitempty"`
	// credentialIssuerDIDNull records a present-but-null credentialIssuerDid, which a *string
	// cannot tell apart from an absent one. The verifier refuses it (DIV §4.3.2).
	credentialIssuerDIDNull bool
}

// UnmarshalJSON keeps a present-but-null credentialIssuerDid distinguishable from an absent one.
func (r *RequesterIdentity) UnmarshalJSON(data []byte) error {
	type requesterFields RequesterIdentity
	var decoded requesterFields
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	*r = RequesterIdentity(decoded)
	r.credentialIssuerDIDNull = jsonFieldIsNull(data, "credentialIssuerDid")
	return nil
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
	// AgentAuthorityChain is the complete independently trusted root-to-leaf chain required when an
	// agent intent names delegatedBy. Each link is verified before scope and tenant continuity checks.
	AgentAuthorityChain []AgentAuthorityChainLink
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
	authDataFlagBE = 0x08 // Backup Eligible — the credential may be synced to other devices
	authDataFlagBS = 0x10 // Backup State — the credential is currently backed up
)

// backupFlagsProblem: under a signed RequireHardwareKey, a WEBAUTHN witness whose authenticatorData
// carries the Backup Eligible or Backup State flag cannot count (DIV §4.4.5 rule 6). The flags are
// covered by the assertion signature, so a relying party can catch an issuer that let a synced passkey
// sign a hardware-pinned action. BE=0 is the authenticator's own claim, not attestation. Called only
// for a witness that already verified, so authenticatorData decodes to at least 37 bytes.
func backupFlagsProblem(w ApprovalWitness) string {
	if w.SigAlg == nil || *w.SigAlg != "WEBAUTHN" || w.AuthenticatorData == nil {
		return ""
	}
	authData, err := decodeBase64Flexible(*w.AuthenticatorData)
	if err != nil || len(authData) < 37 {
		return "authenticatorData is unreadable"
	}
	if authData[32]&(authDataFlagBE|authDataFlagBS) == 0 {
		return ""
	}
	return fmt.Sprintf("signer %s used a backup-eligible (synced) passkey — authenticatorData BE/BS flag set — but the signed policy requires a hardware-backed WebAuthn credential", w.SignerDID)
}

// Expected contains expected context when verifying a receipt. Target and Nonce are asserted from
// the relying party's own state — never read from the receipt (DIV Target Isolation + replay binding).
type Expected struct {
	// TenantID is independently trusted context. Nil preserves archival v1 verification; a non-nil
	// empty value is invalid, and a non-empty value requires a matching v2 payload.
	TenantID   *string                `json:"tenantId,omitempty"`
	Target     string                 `json:"target"`
	Nonce      string                 `json:"nonce"`
	ActionType string                 `json:"actionType"`
	Params     map[string]interface{} `json:"params"`
	// RP-asserted live agent context; never populated from the receipt itself.
	AgentContext map[string]interface{} `json:"agentContext,omitempty"`
	// RequesterDID is the independently asserted executing agent identity for delegated agent intents.
	RequesterDID string `json:"requesterDid,omitempty"`
	// Approvers is REQUIRED. Verification uses a key YOU resolve, never receipt.SignerPublicKey:
	// a receipt checked against its own embedded key proves only internal consistency, and per the
	// DIV threat model anyone able to hand you a receipt could have minted that keypair.
	// DIV §3 Invariant 3 / §5 step 3.
	Approvers ApproverTrustAnchor `json:"-"`
	// Requirement is STRONGLY RECOMMENDED: the minimum requirement YOUR approval rule demands (see
	// RequirementFloor). Nil keeps the legacy behaviour, which enforces only the quorum the signers
	// themselves stated. Under a delegation pass the ORDINARY rule — the delegated quorum must already
	// be at least as strict (DIV §5a.5). VerifyDelegation applies it to the sealing requirement.
	Requirement *RequirementFloor `json:"requirement,omitempty"`
	// EnrolledDeviceKeys are the enrolled approver device keys YOU trust (base64 SPKI or COSE), from
	// your own enrollment records — e.g. a console trust-anchor export's enrolledDeviceKeys.
	// Consulted only when the signed requirement sets requireEnrolledDevice: then a witness counts only
	// if it is ES256 and verified under one of these keys, and verification is refused without the
	// list (DIV §4.3.2). Each key must ALSO be a trusted approver key for its signer in Approvers;
	// this list narrows, it never adds trust. Nil and empty both mean "no list".
	EnrolledDeviceKeys []string `json:"enrolledDeviceKeys,omitempty"`
}

// TenantID returns caller-owned tenant context for verifier expectations. A pointer is required so
// the API can distinguish omitted (legacy-v1 compatibility) from explicitly empty (invalid).
func tenantIDPtr(value string) *string { return &value }

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

// SelfCertifyingDID derives did:intyga:key:<base64url(sha256(decoded key bytes))>.
func SelfCertifyingDID(publicKeyB64 string) string {
	b, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(publicKeyB64)
	}
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return SelfCertifyingDIDPrefix + base64.RawURLEncoding.EncodeToString(h[:])
}

func candidateKeys(a ApproverTrustAnchor, w ApprovalWitness, restrict []string) ([][2]string, string) {
	// Step for step the reference's candidateKeys, refusal texts included.
	if len(a.PublicKeys) > 0 {
		// A delegation names identities, and in PublicKeys mode signerDID is an unverified string —
		// enforcing DelegatedTo against it would be security theatre. Refuse rather than pretend.
		if restrict != nil {
			return nil, "a delegation names approver identities, so it requires a DID-mode trust anchor (DIDs + ResolveKeys); in PublicKeys mode signerDid is unverified and delegatedTo cannot be enforced"
		}
		out := make([][2]string, 0, len(a.PublicKeys))
		for _, k := range a.PublicKeys {
			out = append(out, [2]string{k, k})
		}
		return out, ""
	}
	if a.PublicKeys != nil && a.DIDs == nil {
		// An explicit, empty key allowlist: the reference's { publicKeys: [] }.
		if restrict != nil {
			return nil, "a delegation names approver identities, so it requires a DID-mode trust anchor (DIDs + ResolveKeys); in PublicKeys mode signerDid is unverified and delegatedTo cannot be enforced"
		}
		return nil, "trusted approver allowlist is empty"
	}
	signerDID := w.SignerDID
	if signerDID == "" || !containsDID(a.DIDs, signerDID) {
		shown := signerDID
		if shown == "" {
			shown = "(unknown)"
		}
		return nil, fmt.Sprintf("signer %s is not an authorized approver", shown)
	}
	if restrict != nil && !containsDID(restrict, signerDID) {
		return nil, fmt.Sprintf("signer %s is not named in the delegation", signerDID)
	}
	// PRECEDENCE: the anchor's own key mapping always wins, self-certifying DID or not.
	var resolved []string
	if a.ResolveKeys != nil {
		resolved = a.ResolveKeys(signerDID)
	} else if a.ResolveKey != nil {
		if key := a.ResolveKey(signerDID); key != "" {
			resolved = []string{key}
		}
	}
	out := make([][2]string, 0, len(resolved))
	for _, k := range resolved {
		if k != "" {
			// All keys for one DID share that DID as their identity, so quorum still counts one approver.
			out = append(out, [2]string{k, signerDID})
		}
	}
	if len(out) > 0 {
		return out, ""
	}
	// Self-certifying fallback: with no mapped keys the pinned identifier itself is the commitment.
	if strings.HasPrefix(signerDID, SelfCertifyingDIDPrefix) {
		if w.SignerPublicKey == "" {
			return nil, "witness carries no public key to validate against self-certifying " + signerDID
		}
		if SelfCertifyingDID(w.SignerPublicKey) != signerDID {
			return nil, "witness public key does not hash to the pinned self-certifying DID (did:intyga:key), and the trust anchor names no keys for it"
		}
		return [][2]string{{w.SignerPublicKey, signerDID}}, ""
	}
	if a.ResolveKeys == nil && a.ResolveKey == nil {
		return nil, signerDID + " is not self-certifying (" + SelfCertifyingDIDPrefix + "…) and the trust anchor provides no ResolveKeys"
	}
	return nil, fmt.Sprintf("no trusted key could be resolved for %s", signerDID)
}

func containsDID(list []string, did string) bool {
	for _, d := range list {
		if d == did {
			return true
		}
	}
	return false
}

// ApprovalWitness is one approver's signature over the canonical payload.
type ApprovalWitness struct {
	SignerDID         string  `json:"signerDid"`
	SignerPublicKey   string  `json:"signerPublicKey"`
	Signature         string  `json:"signature"`
	SigAlg            *string `json:"sigAlg,omitempty"`
	AuthenticatorData *string `json:"authenticatorData,omitempty"`
	ClientDataJSON    *string `json:"clientDataJSON,omitempty"`
	decoded           bool
	present           map[string]bool
	nulls             map[string]bool
}

// UnmarshalJSON remembers absent witness fields separately from explicit empty strings. Agent
// receipt digests project absent values as null but preserve empty strings, matching the TS/Python
// implementations; the distinction is otherwise lost by Go's zero-value string fields.
func (w *ApprovalWitness) UnmarshalJSON(data []byte) error {
	type witnessFields ApprovalWitness
	var decoded witnessFields
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*w = ApprovalWitness(decoded)
	w.decoded = true
	w.present = make(map[string]bool, len(fields))
	w.nulls = make(map[string]bool)
	for key := range fields {
		w.present[key] = true
		if strings.TrimSpace(string(fields[key])) == "null" {
			w.nulls[key] = true
		}
	}
	return nil
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
//
// It also refuses any Go type outside the JSON shapes listed in the switch below. Go, unlike the
// other ports, has no closed JSON value type, so a caller can hand this a float32, a uint64, a
// struct or a map[string]string — none of which the port can canonicalize without guessing.
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
		if !utf8.ValidString(val) {
			return "", errInvalidUTF8
		}
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
	case []string:
		// The canonical builders hand this in directly (allowedAaguids, delegatedTo), so it must go
		// through jsMarshalString like every other string rather than down the default branch.
		items := make([]string, len(val))
		for i, x := range val {
			if !utf8.ValidString(x) {
				return "", errInvalidUTF8
			}
			items[i] = jsMarshalString(x)
		}
		return "[" + strings.Join(items, ",") + "]", nil
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
			if !utf8.ValidString(k) {
				return "", errInvalidUTF8
			}
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
		// REFUSE, never fall through to encoding/json. That package sorts object keys by UTF-8
		// bytes rather than UTF-16 code units, escapes <, >, & and U+2028/U+2029, and serializes
		// any integer width or float with no portable-range check — so a typed value canonicalized
		// there produces bytes no other port can reproduce, and the receipt reads as tampering at
		// the relying party. TS, Rust, Python and Java all fail closed on a value they cannot
		// canonicalize; this is that choice.
		return "", fmt.Errorf(
			"%T cannot be canonicalized; convert it to a JSON value first (map[string]interface{}, []interface{}, []string, string, float64, int, int64, bool, nil)",
			val,
		)
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

// CanonicalIntentPayload builds a byte-identical DIV Intent Payload. Omitting tenantID preserves v1;
// one explicit tenantID emits tenant-bound v2. It builds the
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
	tenantID ...string,
) (string, error) {
	req, rq, err := canonicalCommon(requester, requirement, true)
	if err != nil {
		return "", err
	}
	obj := map[string]interface{}{
		"type":       DivIntentType,
		"target":     target,
		"actionType": actionType,
		"display":    display,
		"params":     params,
		// DIV §4.3.4. Reserved and REQUIRED in the bytes; `null` states that no external-evidence
		// condition applied. Untyped nil on purpose — StableStringify's default branch refuses any
		// Go type outside the closed JSON set, so a typed nil pointer would error out here.
		"evidence":    nil,
		"requester":   req,
		"requirement": rq,
		"nonce":       nonce,
		"expiresAt":   expiresAt,
	}
	if err := applyTenantBinding(obj, tenantID); err != nil {
		return "", err
	}
	return StableStringify(obj)
}

// CanonicalAgentIntentPayload is the DIV agent variant. All agent fields enter the same JCS
// object as the ordinary intent and are therefore covered by the WebAuthn challenge.
func CanonicalAgentIntentPayload(target, actionType, display string, params map[string]interface{},
	requester RequesterIdentity, requirement ApprovalRequirement, nonce, exp string,
	context map[string]interface{}, tenantID ...string) (string, error) {
	req, rq, err := canonicalCommon(requester, requirement, true)
	if err != nil {
		return "", err
	}
	obj := map[string]interface{}{
		"type": DivIntentType, "target": target, "actionType": actionType,
		"display": display, "params": params, "evidence": nil, "requester": req,
		"requirement": rq, "nonce": nonce, "action": context["action"],
		"agent": context["agent"], "session": context["session"], "nbf": context["nbf"], "exp": exp,
	}
	if err := applyTenantBinding(obj, tenantID); err != nil {
		return "", err
	}
	return StableStringify(obj)
}

// applyTenantBinding preserves the historical v1 bytes when no tenant is supplied and emits v2
// only for one explicit, non-empty tenant. Tenant IDs are opaque and are never trimmed or normalized.
func applyTenantBinding(obj map[string]interface{}, tenantID []string) error {
	if len(tenantID) == 0 {
		obj["v"] = DivVersion
		return nil
	}
	if len(tenantID) != 1 || tenantID[0] == "" {
		return errors.New("tenantID must be one non-empty opaque string")
	}
	obj["v"] = DivTenantBoundVersion
	obj["tenantId"] = tenantID[0]
	return nil
}

// canonicalCommon builds the requester + requirement projection shared by all three builders. One
// definition rather than three copies: these bytes are the contract, and a field added to one builder
// but not the others is exactly the drift the golden vectors exist to catch.
//
// ordinary is true only for div-intent-verification (ordinary and agent intents): the one payload
// kind that may carry requireEnrolledDevice (DIV §4.3.2). Every other builder passes false so a
// caller cannot sign a kind whose verifiers would refuse the field.
func canonicalCommon(requester RequesterIdentity, requirement ApprovalRequirement, ordinary bool) (interface{}, interface{}, error) {
	// The identity extensions are refused at canonicalization, as in the reference (NonCanonicalValue):
	// a builder that emitted them would produce bytes no other port reproduces.
	if requester.credentialIssuerDIDNull ||
		(requester.CredentialIssuerDID != nil && !validOptionalDID(*requester.CredentialIssuerDID)) {
		return nil, nil, errors.New("credentialIssuerDid must be a valid DID")
	}
	if requirement.excludedSignerDIDsNull {
		return nil, nil, errors.New("excludedSignerDids must be a DID array")
	}
	if requirement.ExcludedSignerDIDs != nil {
		for _, did := range *requirement.ExcludedSignerDIDs {
			if !validOptionalDID(did) {
				return nil, nil, errors.New("excludedSignerDids must be a DID array")
			}
		}
	}
	if requirement.RequireEnrolledDevice {
		if !ordinary {
			return nil, nil, errors.New(EnrolledDeviceOrdinaryOnlyReason)
		}
		if requirement.RequiresHardwareCredential() {
			return nil, nil, errors.New(EnrolledDeviceWithHardwareReason)
		}
	}
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
	requesterObject := map[string]interface{}{
		"did":         requester.DID,
		"attestation": attestation,
	}
	if requester.CredentialIssuerDID != nil {
		requesterObject["credentialIssuerDid"] = *requester.CredentialIssuerDID
	}
	requirementObject := map[string]interface{}{
		"requiredApprovals":      requirement.RequiredApprovals,
		"requireHardwareKey":     requirement.RequireHardwareKey,
		"allowedAaguids":         aaguids,
		"requesterCannotApprove": requirement.RequesterCannotApprove,
		"signerClass":            requirement.SignerClass,
	}
	if requirement.ExcludedSignerDIDs != nil {
		excluded := append([]string{}, (*requirement.ExcludedSignerDIDs)...)
		sort.Slice(excluded, func(i, j int) bool { return utf16Less(excluded[i], excluded[j]) })
		unique := excluded[:0]
		for _, did := range excluded {
			if len(unique) == 0 || unique[len(unique)-1] != did {
				unique = append(unique, did)
			}
		}
		excluded = unique
		requirementObject["excludedSignerDids"] = excluded
	}
	// Only as the literal true: one policy has one encoding, and `false` is never emitted.
	if requirement.RequireEnrolledDevice {
		requirementObject["requireEnrolledDevice"] = true
	}
	return requesterObject, requirementObject, nil
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
	tenantID ...string,
) (string, error) {
	req, rq, err := canonicalCommon(requester, requirement, false)
	if err != nil {
		return "", err
	}
	obj := map[string]interface{}{
		"type":       DivOfflineIntentType,
		"target":     target,
		"actionType": actionType,
		"display":    display,
		"params":     params,
		// DIV §4.3.4. Reserved and REQUIRED in the bytes; `null` states that no external-evidence
		// condition applied. Untyped nil on purpose — StableStringify's default branch refuses any
		// Go type outside the closed JSON set, so a typed nil pointer would error out here.
		"evidence":     nil,
		"requester":    req,
		"requirement":  rq,
		"nonce":        nonce,
		"challengedAt": challengedAt,
		"expiresAt":    expiresAt,
	}
	if err := applyTenantBinding(obj, tenantID); err != nil {
		return "", err
	}
	return StableStringify(obj)
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
	tenantID ...string,
) (string, error) {
	req, rq, err := canonicalCommon(requester, requirement, false)
	if err != nil {
		return "", err
	}
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
	obj := map[string]interface{}{
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
	}
	if err := applyTenantBinding(obj, tenantID); err != nil {
		return "", err
	}
	return StableStringify(obj)
}

// canonicalFields is just enough of the DIV Intent Payload to gate version/type and read the fields
// the relying party takes from the receipt (nonce, expiresAt) rather than asserting itself.
type canonicalFields struct {
	V                 *int            `json:"v"`
	TenantID          json.RawMessage `json:"tenantId"`
	Type              string          `json:"type"`
	Nonce             string          `json:"nonce"`
	ExpiresAt         string          `json:"expiresAt"`
	Exp               string          `json:"exp"`
	ChallengedAt      string          `json:"challengedAt"`
	SealedAt          string          `json:"sealedAt"`
	DelegatedTo       []string        `json:"delegatedTo"`
	DelegatedQuorum   *int            `json:"delegatedQuorum"`
	ActionPatterns    []string        `json:"actionPatterns"`
	ParentReceiptHash json.RawMessage `json:"parentReceiptHash"`
	SignedAt          string          `json:"signedAt"`
	PayloadHash       string          `json:"payloadHash"`
	RpID              string          `json:"rpId"`
	Subject           *struct {
		ExternalID string `json:"externalId"`
	} `json:"subject"`
	Agent *struct {
		DID string `json:"did"`
	} `json:"agent"`
	Requirement *ApprovalRequirement `json:"requirement"`
	// Raw, not *T: encoding/json collapses an absent key and an explicit null into the same nil
	// pointer, and DIV §4.3.4 turns on telling those apart. See checkEvidence.
	Evidence json.RawMessage `json:"evidence"`
}

// VerifiedDelegation is a delegation whose own signature, quorum and window have been checked by
// VerifyDelegation. It is an INPUT to a later approval check, never a substitute for one.
type VerifiedDelegation struct {
	// TenantID is the independently verified v2 tenant. It is empty only for a legacy v1 delegation.
	TenantID string
	// RequesterDID is frozen by the signed seal and must match any offline approval using it.
	RequesterDID string
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

// verifyTenantBinding validates the version/tenant contract against caller-owned context, first, as
// the reference's checkTenantBinding does: it reads `v` and `tenantId` from the payload text itself,
// so an unparseable payload reports an unparseable version. It returns the tenant to use when
// reconstructing v2 bytes; it never trusts receipt data as the caller's expectation. A legacy v1
// payload that carries a tenantId is not refused here: rebuilt without one, it fails the byte
// comparison, exactly as in the reference.
func verifyTenantBinding(canonical string, expectedTenantID *string) (string, string) {
	version := 0.0
	var probe map[string]json.RawMessage
	if json.Unmarshal([]byte(canonical), &probe) == nil {
		if raw, ok := probe["v"]; ok {
			var f float64
			if json.Unmarshal(raw, &f) == nil {
				version = f
			}
		}
	}
	if version == DivVersion {
		if expectedTenantID != nil {
			return "", "legacy DIV v1 payload cannot be verified with an expected tenantId"
		}
		return "", ""
	}
	if version != DivTenantBoundVersion {
		shown := "unparseable"
		if version != 0 {
			shown = jsNumberString(version)
		}
		return "", "unsupported DIV payload version (" + shown + ")"
	}
	if expectedTenantID == nil || *expectedTenantID == "" {
		return "", "expected.TenantID is required for tenant-bound DIV v2 payloads"
	}
	var signed string
	if raw, ok := probe["tenantId"]; !ok || json.Unmarshal(raw, &signed) != nil || signed == "" {
		return "", "tenant-bound DIV v2 payload is missing a non-empty tenantId"
	}
	if signed != *expectedTenantID {
		return "", "receipt was signed for a different tenant"
	}
	return *expectedTenantID, ""
}

// jsNumberString is JavaScript's Number#toString for a finite double, for refusal text.
func jsNumberString(f float64) string {
	if abs := math.Abs(f); abs != 0 && (abs >= 1e21 || abs < 1e-6) {
		mantissa, exp, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
		digits := strings.TrimLeft(exp[1:], "0")
		if digits == "" {
			digits = "0"
		}
		return mantissa + "e" + exp[:1] + digits
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// VerifyApprovalReceipt verifies an ApprovalReceipt offline without external dependencies.
//
// It recomputes the canonical payload from the caller's own params, confirms it byte-matches
// what was signed, and verifies the human's ES256 or WebAuthn signature. A WEBAUTHN receipt
// additionally requires opts.ExpectedOrigin and opts.ExpectedRpID.
func VerifyApprovalReceipt(receipt ApprovalReceipt, expected Expected, opts VerifyOptions) VerifyResult {
	tenantID, tenantReason := verifyTenantBinding(receipt.CanonicalPayload, expected.TenantID)
	if tenantReason != "" {
		return VerifyResult{OK: false, Reason: tenantReason}
	}

	if why := canonicalTextProblem(receipt.CanonicalPayload); why != "" {
		return VerifyResult{OK: false, Reason: why}
	}
	var fields canonicalFields
	if err := json.Unmarshal([]byte(receipt.CanonicalPayload), &fields); err != nil {
		return VerifyResult{OK: false, Reason: "canonicalPayload is not valid JSON"}
	}
	// A DELEGATION authorizes nothing (DIV §5a.5). Refused here unconditionally — there is deliberately
	// NO option that would let one through, because a delegation that could authorize its own action
	// would be exactly the pre-signed bearer capability the design exists to avoid.
	if fields.Type == DivDelegationType {
		return VerifyResult{OK: false, Reason: "this is a delegation, which authorizes no action on its own — verify it with VerifyDelegation and pass the result as VerifyOptions.Delegation, together with an offline approval signed by the delegated operators"}
	}
	if fields.Type == DivAgentAuthorityType {
		return VerifyResult{OK: false, Reason: "this is an agent authority, which authorizes no action on its own — verify it with VerifyAgentAuthority; execution still requires an approval receipt"}
	}
	if fields.Type == DivPlatformIntentType {
		return VerifyResult{OK: false, Reason: "this is a platform hash-only intent (DIV §5c) — verify it with VerifyPlatformReceipt"}
	}
	// A DEWP execution-evidence statement (DEWP §4.7) is a source's observation AFTER execution, not
	// an approval. Refused with its own reason, like the other non-approval kinds.
	if fields.Type == DewpExecutionEvidenceType {
		return VerifyResult{OK: false, Reason: "this is a DEWP execution-evidence statement, which approves nothing — evaluate it with EvaluateExecutionEvidence over an evidence bundle"}
	}
	offline := fields.Type == DivOfflineIntentType
	if !offline && fields.Type != DivIntentType {
		return VerifyResult{OK: false, Reason: "payload is not a div-intent-verification"}
	}
	if offline && !opts.AllowOffline {
		return VerifyResult{OK: false, Reason: "this is an offline approval; pass VerifyOptions{AllowOffline: true} at the specific call site permitted to run under one"}
	}
	// A delegation only ever substitutes the approver set for an OFFLINE proof. Accepting it against an
	// ordinary gateway-mediated receipt would silently replace the quorum the gateway enforced.
	if opts.Delegation != nil && !offline {
		return VerifyResult{OK: false, Reason: "a delegation can only substitute the approver set for an offline approval"}
	}
	// An empty expected nonce binds no challenge: refused, never compared (DIV §5 step 10).
	if expected.Nonce == "" {
		return VerifyResult{OK: false, Reason: nonceRequiredReason}
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
	if opts.Delegation != nil && receipt.Requester.DID != opts.Delegation.RequesterDID {
		return VerifyResult{OK: false, Reason: "offline approval was requested by a different principal than the delegation"}
	}
	agentIntent := fields.Agent != nil
	if agentIntent && expected.AgentContext == nil {
		return VerifyResult{Reason: "agent receipt requires independently asserted PEP context"}
	}
	if !agentIntent && expected.AgentContext != nil {
		return VerifyResult{Reason: "agent context was expected but is absent from the signed payload"}
	}
	if agentIntent {
		fields.ExpiresAt = fields.Exp
		if fields.ExpiresAt == "" {
			return VerifyResult{Reason: "receipt missing expiration"}
		}
		if problem := validateAgentContext(expected.AgentContext, fields.Exp, nil); problem != "" {
			return VerifyResult{Reason: "invalid independently asserted agent context: " + problem}
		}
		// The reference's order: validity window, then the irreversible/AUTO_APPROVED rule, then the
		// delegated-agent chain.
		nbf, _ := time.Parse("2006-01-02T15:04:05.000Z", expected.AgentContext["nbf"].(string))
		if now, skew := evaluationTime(opts); nbf.After(now.Add(skew)) {
			return VerifyResult{Reason: "agent approval is not valid yet"}
		}
		if action, _ := expected.AgentContext["action"].(map[string]interface{}); action["reversibility"] == "irreversible" &&
			receipt.SigAlg != nil && *receipt.SigAlg == "AUTO_APPROVED" {
			return VerifyResult{Reason: "irreversible agent action requires a human signature"}
		}
		if agent, ok := expected.AgentContext["agent"].(map[string]interface{}); ok && agent["delegatedBy"] != nil {
			delegatedBy, _ := agent["delegatedBy"].(string)
			if expected.RequesterDID == "" || len(opts.AgentAuthorityChain) == 0 {
				return VerifyResult{Reason: "delegated agent receipt requires a trusted root-to-leaf authority chain"}
			}
			authority := VerifyAgentDelegationChain(opts.AgentAuthorityChain, AgentDelegatedAction{
				TenantID: tenantID, Target: expected.Target, ActionType: expected.ActionType,
				AgentDID: expected.RequesterDID, DelegatedBy: delegatedBy,
			}, opts)
			if !authority.OK {
				return VerifyResult{Reason: authority.Reason}
			}
		}
	}
	if fields.ExpiresAt == "" {
		return VerifyResult{OK: false, Reason: "receipt missing expiration"}
	}
	// FAIL CLOSED on a missing target (DIV Invariant 5, Target Isolation): defaulting to the receipt's
	// own target would have the receipt vouch for its own scope.
	if expected.Target == "" {
		return VerifyResult{OK: false, Reason: "expected.Target is required — it must be YOUR target identifier, asserted independently of the receipt (DIV Target Isolation)"}
	}
	if expected.Approvers.isUnset() {
		return VerifyResult{OK: false, Reason: "expected.Approvers is required — the Approver key MUST come from your own trust policy, never from the receipt (DIV Invariant 3)"}
	}

	// The requirement is part of the SIGNED bytes, so a third party cannot alter it: a forged value
	// changes the string and fails the byte comparison below. It does NOT bind the signers themselves
	// — they authored it — which is why step 3d compares it against expected.Requirement.
	if fields.Requirement == nil {
		return VerifyResult{OK: false, Reason: "receipt payload is missing the signed approval requirement"}
	}
	if ok, reason := checkQuorumMinimum(*fields.Requirement); !ok {
		return VerifyResult{OK: false, Reason: reason}
	}
	// Identity extensions before the signer class, in every port (DIV §4.3.2).
	if ok, reason := checkExcludedSigners(*fields.Requirement, *receipt.Requester); !ok {
		return VerifyResult{OK: false, Reason: reason}
	}
	if ok, reason := checkSignerClass(*fields.Requirement); !ok {
		return VerifyResult{OK: false, Reason: reason}
	}
	// DIV §5 step 3e, structural half: an offline intent cannot carry requireEnrolledDevice, and an
	// ordinary one carries it only as `true` without a hardware requirement.
	if why := enrolledDeviceStructureProblem(*fields.Requirement, !offline); why != "" {
		return VerifyResult{OK: false, Reason: why}
	}
	if ok, reason := checkRequirementFloor(*fields.Requirement, expected.Requirement); !ok {
		return VerifyResult{OK: false, Reason: reason}
	}
	// DIV §5-step-3c. Before Local Payload Reconstruction: a non-null value would also fail the byte
	// comparison below, but it would report as a params mismatch — a tampering message for what is
	// really an unsupported payload shape.
	if ok, reason := checkEvidence(fields.Evidence); !ok {
		return VerifyResult{OK: false, Reason: reason}
	}

	// Offline proofs carry challengedAt so the validity WINDOW can be bounded here, not merely at mint.
	if offline {
		if fields.ChallengedAt == "" {
			return VerifyResult{OK: false, Reason: "offline proof is missing challengedAt"}
		}
		challenged, err := parseSignedTime(fields.ChallengedAt)
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
		expiry, err := parseSignedTime(fields.ExpiresAt)
		if err != nil {
			return VerifyResult{OK: false, Reason: "expiresAt is not a valid RFC3339 timestamp"}
		}
		// Milliseconds, the reference's resolution, and its order: the cap, then a negative window.
		windowMinutes := float64(expiry.UnixMilli()-challenged.UnixMilli()) / 60_000
		if windowMinutes > MaxOfflineWindowMinutes {
			return VerifyResult{OK: false, Reason: fmt.Sprintf(
				"offline window is %s minutes, over the %d-minute maximum", jsToFixed1(windowMinutes), MaxOfflineWindowMinutes)}
		}
		if windowMinutes < 0 {
			return VerifyResult{OK: false, Reason: "offline proof expires before it was challenged"}
		}
		// The cap above bounds the window's WIDTH; this bounds its POSITION (DIV §5a.3 rule 3).
		// Without it a proof challenged for a date years out, with a compliant 60-minute window,
		// verifies today and keeps verifying until that date — the pre-signed bearer capability
		// §5a.1 rejects. NOT gated on AllowExpired: that override re-examines a proof that WAS
		// valid and has lapsed, and says nothing about one dated in the future.
		if now, skew := evaluationTime(opts); challenged.After(now.Add(skew)) {
			return VerifyResult{OK: false, Reason: "offline proof is challenged in the future (DIV §5a.3)"}
		}
		// A hardware-key policy CANNOT be satisfied offline (DIV §5a.3 step 4). WebAuthn needs a secure
		// context and an RP ID an offline signing surface will not match, so an offline witness is always
		// a bare key. Accepting the proof anyway would silently downgrade the policy the approver
		// attested to, so it is refused instead — fail closed, and say why. A non-empty model allowlist
		// is the same policy class: a bare key has no authenticator model at all.
		if fields.Requirement.RequiresHardwareCredential() {
			return VerifyResult{OK: false, Reason: "the signed policy requires a hardware-backed WebAuthn credential, which cannot be produced offline — this action cannot be approved out of band (DIV §5a.3)"}
		}
	}

	// A delegation substitutes WHO may approve and HOW MANY, and nothing else (DIV §5a.6). Every
	// agreement check is on the SIGNED bytes of both proofs, so neither can widen the other.
	var delegatedTo []string
	delegatedQuorum := 0
	if opts.Delegation != nil {
		d := opts.Delegation
		if d.TenantID != tenantID {
			return VerifyResult{OK: false, Reason: "delegation and approval belong to different tenants"}
		}
		expiry, err := parseSignedTime(d.ExpiresAt)
		if err != nil {
			return VerifyResult{OK: false, Reason: "delegation expiresAt is not a valid RFC3339 timestamp"}
		}
		if !opts.AllowExpired {
			now, skew := evaluationTime(opts)
			if now.After(expiry.Add(skew)) {
				return VerifyResult{OK: false, Reason: "delegation has expired (pass VerifyOptions{AllowExpired: true} for audit re-verification)"}
			}
		}
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
			tenantArgs(tenantID)...,
		)
	} else if agentIntent {
		recomputed, recomputeErr = CanonicalAgentIntentPayload(expected.Target, expected.ActionType,
			receipt.ActionDescription, expected.Params, *receipt.Requester, *fields.Requirement,
			fields.Nonce, fields.ExpiresAt, expected.AgentContext, tenantArgs(tenantID)...)
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
			tenantArgs(tenantID)...,
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
		expiry, err := parseSignedTime(fields.ExpiresAt)
		if err != nil {
			return VerifyResult{OK: false, Reason: "expiresAt is not a valid RFC3339 timestamp"}
		}
		now, skew := evaluationTime(opts)
		if now.After(expiry.Add(skew)) {
			return VerifyResult{OK: false, Reason: "proof has expired (pass VerifyOptions{AllowExpired: true} for audit re-verification)"}
		}
	}
	// Optional: assert WHICH workload the approval was granted to.
	if expected.RequesterDID != "" && receipt.Requester.DID != expected.RequesterDID {
		return VerifyResult{Reason: "approval was requested by a different principal"}
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
			return VerifyResult{OK: false, AutoApproved: true, Reason: "auto-approved by policy — no human signature to verify (pass VerifyOptions{AllowAutoApproved: true} to accept)"}
		}
		return VerifyResult{OK: true, AutoApproved: true}
	}

	witnesses := witnessesOf(receipt)
	if len(witnesses) == 0 {
		return VerifyResult{OK: false, Reason: "receipt missing signature material"}
	}
	// The witness list is attacker-supplied and every entry costs ECDSA verifications, in the
	// relying party's own process, immediately before the action it gates. A real quorum is single
	// digits; the TS reference measured a 20,000-witness receipt at 3.6s of blocked event loop and
	// a 1.16 MB failure string. Bound it.
	if len(witnesses) > MaxWitnesses {
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"receipt carries %d witnesses, above the %d this verifier will process", len(witnesses), MaxWitnesses)}
	}
	// A signed four-eyes rule cannot be enforced against a key-set anchor: PublicKeys mode never
	// authenticates signerDid, so "this signer is not the requester" is unverifiable. Refuse the
	// receipt outright rather than letting every witness fail individually — the caller's anchor is
	// the wrong shape for the policy, which is not a quorum shortfall. All five ports decide it
	// here, before the loop; TypeScript decided it mid-loop until this was reconciled.
	if fields.Requirement.RequiredApprovals > 1 && len(expected.Approvers.PublicKeys) > 0 {
		return VerifyResult{OK: false, Reason: "multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)"}
	}
	if (fields.Requirement.RequesterCannotApprove || (fields.Requirement.ExcludedSignerDIDs != nil && len(*fields.Requirement.ExcludedSignerDIDs) > 0)) &&
		len(expected.Approvers.PublicKeys) > 0 {
		return VerifyResult{OK: false, Reason: keyOnlyFourEyesReason}
	}
	// DIV §5 step 3e, list half: decided before counting, like the anchor-shape checks above, so a
	// caller missing its enrollment records is told so instead of reading a quorum shortfall.
	var enrolledDevices map[string]bool
	if fields.Requirement.RequireEnrolledDevice {
		fingerprints, why := enrolledDeviceFingerprints(expected.EnrolledDeviceKeys)
		if why != "" {
			return VerifyResult{OK: false, Reason: why}
		}
		enrolledDevices = fingerprints
	}

	// Count DISTINCT approvers whose signature verifies under a key we independently trust. Distinct
	// is load-bearing: without it, N copies of one approver's signature satisfy an N-of-M quorum.
	verified := map[string]bool{}
	countedKeys := map[string]string{}
	if why := seedExcludedSigningKeys(countedKeys, expected.Approvers, *fields.Requirement, *receipt.Requester); why != "" {
		return VerifyResult{OK: false, Reason: why}
	}
	var failures []string
	for _, w := range witnesses {
		cands, reason := candidateKeys(expected.Approvers, w, delegatedTo)
		if reason != "" {
			failures = append(failures, reason)
			continue
		}
		matched, matchedKey := "", ""
		last := "signature does not verify against any trusted approver key"
		for _, c := range cands {
			if why := verifyWitness(w, c[0], receipt, opts); why == "" {
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
		// A hardware-key policy is only partially checkable offline: a bare P-256 key carries no
		// attestation at all, so it can never satisfy the requirement, while a WebAuthn assertion is
		// accepted without proving the authenticator's model.
		if fields.Requirement.RequiresHardwareCredential() && (w.SigAlg == nil || *w.SigAlg != "WEBAUTHN") {
			failures = append(failures, fmt.Sprintf(
				"signer %s used a bare key, but the signed policy requires a hardware-backed WebAuthn credential", w.SignerDID))
			continue
		}
		if fields.Requirement.RequireHardwareKey {
			if why := backupFlagsProblem(w); why != "" {
				failures = append(failures, why)
				continue
			}
		}
		// DIV §5 step 7: under requireEnrolledDevice only an ES256 witness under one of the caller's
		// enrolled device keys counts. The key compared is the TRUSTED one it verified under.
		if enrolledDevices != nil &&
			((w.SigAlg != nil && *w.SigAlg == "WEBAUTHN") || !enrolledDevices[signingKeyIdentity(matchedKey)]) {
			failures = append(failures, fmt.Sprintf(
				"signer %s did not sign with an enrolled approver device key, but the signed policy requires one", w.SignerDID))
			continue
		}
		// Four-eyes, verified offline against the requester in the same signed payload.
		excluded := map[string]bool{}
		if fields.Requirement.ExcludedSignerDIDs != nil {
			for _, did := range *fields.Requirement.ExcludedSignerDIDs {
				excluded[did] = true
			}
		}
		if fields.Requirement.RequesterCannotApprove {
			excluded[receipt.Requester.DID] = true
			if receipt.Requester.CredentialIssuerDID != nil {
				excluded[*receipt.Requester.CredentialIssuerDID] = true
			}
		}
		if excluded[w.SignerDID] {
			failures = append(failures, fmt.Sprintf(
				"four-eyes: requester %s cannot approve their own action", w.SignerDID))
			continue
		}
		if why := sharedKeyProblem(countedKeys, matchedKey, matched); why != "" {
			failures = append(failures, why)
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
	tenantID, tenantReason := verifyTenantBinding(receipt.CanonicalPayload, expected.TenantID)
	if tenantReason != "" {
		return VerifyResult{OK: false, Reason: tenantReason}, nil
	}
	if why := canonicalTextProblem(receipt.CanonicalPayload); why != "" {
		return VerifyResult{OK: false, Reason: why}, nil
	}
	var fields canonicalFields
	if err := json.Unmarshal([]byte(receipt.CanonicalPayload), &fields); err != nil {
		return VerifyResult{OK: false, Reason: "canonicalPayload is not valid JSON"}, nil
	}
	if fields.Type != DivDelegationType {
		return VerifyResult{OK: false, Reason: "payload is not a div-delegation"}, nil
	}
	// DIV §4.4.6: a Delegation REQUIRES an identity-associating anchor and MUST be refused under a
	// key-set anchor — at seal verification too, not only when delegatedTo is enforced at use time.
	// The sealing quorum names PEOPLE; in PublicKeys mode it would count credentials instead.
	if expected.Approvers.PublicKeys != nil {
		return VerifyResult{OK: false, Reason: "a delegation requires a DID-mode trust anchor (DIDs + ResolveKeys); a key-set anchor cannot associate identities (DIV §4.4.6)"}, nil
	}
	// An empty list is a valid set here, as in the reference: it fails the distinct-operator count
	// below. Absent, null or an empty entry is not a set at all.
	if fields.DelegatedTo == nil || containsDID(fields.DelegatedTo, "") {
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
	sealed, err := parseSignedTime(fields.SealedAt)
	if err != nil {
		return VerifyResult{OK: false, Reason: "sealedAt is not a valid RFC3339 timestamp"}, nil
	}
	expiry, err := parseSignedTime(fields.ExpiresAt)
	if err != nil {
		return VerifyResult{OK: false, Reason: "expiresAt is not a valid RFC3339 timestamp"}, nil
	}
	windowHours := float64(expiry.UnixMilli()-sealed.UnixMilli()) / 3_600_000
	if windowHours < 0 {
		return VerifyResult{OK: false, Reason: "delegation expires before it was sealed"}, nil
	}
	if windowHours > MaxDelegationWindowHours {
		return VerifyResult{OK: false, Reason: fmt.Sprintf(
			"delegation window is %s hours, over the %d-hour maximum", jsToFixed1(windowHours), MaxDelegationWindowHours)}, nil
	}
	// Position, not just width (DIV §5a.6 step 1, mirroring §5a.3 rule 3). A forward-dated sealedAt
	// slides the 72-hour window arbitrarily far out, and §5a.8 names that cap as Delegation's ONLY
	// mitigation. Unconditional, like the offline mirror: AllowExpired does not reach it.
	if now, skew := evaluationTime(opts); sealed.After(now.Add(skew)) {
		return VerifyResult{OK: false, Reason: "delegation is sealed in the future (DIV §5a.6)"}, nil
	}
	if receipt.Requester == nil {
		return VerifyResult{OK: false, Reason: "delegation missing requester"}, nil
	}
	if expected.RequesterDID != "" && receipt.Requester.DID != expected.RequesterDID {
		return VerifyResult{OK: false, Reason: "approval was requested by a different principal"}, nil
	}
	if fields.Requirement == nil {
		return VerifyResult{OK: false, Reason: "delegation payload is missing the signed approval requirement"}, nil
	}
	if ok, reason := checkQuorumMinimum(*fields.Requirement); !ok {
		return VerifyResult{OK: false, Reason: reason}, nil
	}
	// Identity extensions before the signer class, in every port (DIV §4.3.2).
	if ok, reason := checkExcludedSigners(*fields.Requirement, *receipt.Requester); !ok {
		return VerifyResult{OK: false, Reason: reason}, nil
	}
	if ok, reason := checkSignerClass(*fields.Requirement); !ok {
		return VerifyResult{OK: false, Reason: reason}, nil
	}
	// DIV §5 step 3e: this payload kind can never carry requireEnrolledDevice.
	if why := enrolledDeviceStructureProblem(*fields.Requirement, false); why != "" {
		return VerifyResult{OK: false, Reason: why}, nil
	}
	if ok, reason := checkRequirementFloor(*fields.Requirement, expected.Requirement); !ok {
		return VerifyResult{OK: false, Reason: reason}, nil
	}
	if expected.Target == "" {
		return VerifyResult{OK: false, Reason: "expected.Target is required — it must be YOUR target identifier, asserted independently of the delegation (DIV Target Isolation)"}, nil
	}
	if expected.Approvers.isUnset() {
		return VerifyResult{OK: false, Reason: "expected.Approvers is required — the delegating approvers MUST come from your own trust policy, never from the delegation (DIV Invariant 3)"}, nil
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
		tenantArgs(tenantID)...,
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
		now, skew := evaluationTime(opts)
		if now.After(expiry.Add(skew)) {
			return VerifyResult{OK: false, Reason: "delegation has expired (pass VerifyOptions{AllowExpired: true} for audit re-verification)"}, nil
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
	if fields.Requirement.RequiredApprovals > 1 && expected.Approvers.PublicKeys != nil {
		return VerifyResult{OK: false, Reason: "multi-approver quorum requires a DID-mode trust anchor (DIV §5 step 3b)"}, nil
	}
	if (fields.Requirement.RequesterCannotApprove || (fields.Requirement.ExcludedSignerDIDs != nil && len(*fields.Requirement.ExcludedSignerDIDs) > 0)) &&
		expected.Approvers.PublicKeys != nil {
		return VerifyResult{OK: false, Reason: keyOnlyFourEyesReason}, nil
	}
	verified := map[string]bool{}
	countedKeys := map[string]string{}
	if why := seedExcludedSigningKeys(countedKeys, expected.Approvers, *fields.Requirement, *receipt.Requester); why != "" {
		return VerifyResult{OK: false, Reason: why}, nil
	}
	var failures []string
	for _, w := range witnesses {
		cands, reason := candidateKeys(expected.Approvers, w, nil)
		if reason != "" {
			failures = append(failures, reason)
			continue
		}
		matched, matchedKey := "", ""
		last := "signature does not verify against any trusted approver key"
		for _, c := range cands {
			if why := verifyWitness(w, c[0], receipt, opts); why == "" {
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
		if fields.Requirement.RequiresHardwareCredential() && (w.SigAlg == nil || *w.SigAlg != "WEBAUTHN") {
			failures = append(failures, fmt.Sprintf(
				"signer %s used a bare key, but the signed policy requires a hardware-backed WebAuthn credential", w.SignerDID))
			continue
		}
		if fields.Requirement.RequireHardwareKey {
			if why := backupFlagsProblem(w); why != "" {
				failures = append(failures, why)
				continue
			}
		}
		excluded := map[string]bool{}
		if fields.Requirement.ExcludedSignerDIDs != nil {
			for _, did := range *fields.Requirement.ExcludedSignerDIDs {
				excluded[did] = true
			}
		}
		if fields.Requirement.RequesterCannotApprove {
			excluded[receipt.Requester.DID] = true
			if receipt.Requester.CredentialIssuerDID != nil {
				excluded[*receipt.Requester.CredentialIssuerDID] = true
			}
		}
		if excluded[w.SignerDID] {
			failures = append(failures, fmt.Sprintf(
				"four-eyes: requester %s cannot delegate to themselves", w.SignerDID))
			continue
		}
		if why := sharedKeyProblem(countedKeys, matchedKey, matched); why != "" {
			failures = append(failures, why)
			continue
		}
		verified[matched] = true
	}
	required := fields.Requirement.RequiredApprovals
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
		TenantID:     tenantID,
		RequesterDID: receipt.Requester.DID,
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

func tenantArgs(tenantID string) []string {
	if tenantID == "" {
		return nil
	}
	return []string{tenantID}
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
	// DIV §4.4.2: absent/unknown labels fall back to ES256, except AUTO_APPROVED.
	if w.SigAlg != nil && *w.SigAlg == "AUTO_APPROVED" {
		return "unsupported witness signature algorithm"
	}
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

// jsToFixed1 is Number.prototype.toFixed(1) for refusal text: the exact binary value rounded to one
// decimal, a tie going to the larger digit — fmt's %.1f rounds half to even, so 30.25 would print
// "30.2" where the reference prints "30.3".
func jsToFixed1(x float64) string {
	neg := x < 0
	r := new(big.Rat).SetFloat64(math.Abs(x))
	if r == nil {
		return jsNumberString(x)
	}
	r.Mul(r, big.NewRat(10, 1))
	r.Add(r, big.NewRat(1, 2))
	n := new(big.Int).Quo(r.Num(), r.Denom())
	tenths := new(big.Int)
	whole, _ := new(big.Int).QuoRem(n, big.NewInt(10), tenths)
	out := whole.String() + "." + tenths.String()
	if neg && n.Sign() != 0 {
		out = "-" + out
	}
	return out
}
