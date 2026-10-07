package intyga

// Offline trust bundle (docs/DIV.md §5a.4) — the relying party's local answer to "whose signature
// counts, and what does policy require?" Ported from packages/sdk/src/trust-bundle.ts.
//
// Offline verification needs two things the network normally supplies: the approver public keys (DIV
// Invariant 3 forbids taking them from the proof under verification) and the approval REQUIREMENT.
// The relying party builds its own offline challenge, so if it also invented the quorum it would be
// setting its own policy and the resulting proof would attest to nothing but that host's
// configuration. The bundle is the offline projection of the tenant's real policy, exported while
// the gateway was reachable, as a compact JWS signed with the gateway's OIDC key. The verifying key
// is PINNED at export: fetching it at incident time is both impossible (offline) and pointless.

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	verify "github.com/intyga-dev/sdk-go/verify"
)

// DivTrustBundleType is the bundle's `type` discriminator, inside the signed JWS payload.
const DivTrustBundleType = "div-trust-bundle-v1"

// MaxTrustBundleAgeDays is the hard ceiling on bundle age, enforced regardless of the `expiresAt` the
// gateway wrote. A stale bundle is a stale approver set: a revoked approver stays trusted, and a
// tightened quorum stays loose. Exactly 30 days is accepted.
const MaxTrustBundleAgeDays = 30

const (
	trustBundleFile = "trust-bundle.jws"
	gatewayKeyFile  = "gateway-key.jwk.json"
)

// BundleApprover is one approver and every public key bound to them at export time.
type BundleApprover struct {
	DID string `json:"did"`
	// PublicKeys are base64 SPKI (raw P-256) and/or base64 COSE (WebAuthn credential) keys. All of them
	// are this ONE approver.
	PublicKeys []string `json:"publicKeys"`
	// OfflinePublicKeys are base64 SPKI offline signing keys (DIV §5a.4). They count ONLY toward a
	// div-offline-intent — never a delegation or an ordinary intent — so they are kept apart from
	// PublicKeys rather than merged into it. See ApproverAnchor.
	OfflinePublicKeys []string `json:"offlinePublicKeys,omitempty"`
}

// BundleAnchorPurpose says what an anchor built from a bundle will verify.
type BundleAnchorPurpose string

const (
	// BundleAnchorOrdinary admits PublicKeys only. It is what a delegation or an ordinary intent is
	// verified against, and the default.
	BundleAnchorOrdinary BundleAnchorPurpose = "ordinary"
	// BundleAnchorOfflineIntent also admits OfflinePublicKeys. Use it ONLY to verify a
	// div-offline-intent proof.
	BundleAnchorOfflineIntent BundleAnchorPurpose = "offline-intent"
)

// BundlePolicy is the approval requirement in force for one action pattern, as the gateway resolved
// it. Mirrors the gateway's TrustBundlePolicyEntry (apps/gateway/src/approvalMatch.ts).
type BundlePolicy struct {
	PolicyRule
	// SignerClass is "human", the only class defined (DIV §4.3.2).
	SignerClass string `json:"signerClass"`
	// SelectionRank and SelectionKey are signed, informational rule-selection metadata. Selection
	// never reads them; they are kept verbatim.
	SelectionRank json.RawMessage `json:"selectionRank,omitempty"`
	SelectionKey  json.RawMessage `json:"selectionKey,omitempty"`
}

// TrustBundle is the verified payload of a div-trust-bundle-v1 JWS.
type TrustBundle struct {
	V         int              `json:"v"`
	Type      string           `json:"type"`
	TenantID  string           `json:"tenantId"`
	Approvers []BundleApprover `json:"approvers"`
	Policy    []BundlePolicy   `json:"policy"`
	// UnmatchedActionPolicy is "DENY" or "BASELINE".
	UnmatchedActionPolicy string `json:"unmatchedActionPolicy"`
	IssuedAt              string `json:"issuedAt"`
	ExpiresAt             string `json:"expiresAt"`
}

// TrustBundleFiles is what SaveTrustBundle writes: the bundle JWS and the key it must be verified
// against.
type TrustBundleFiles struct {
	// JWS is the compact JWS produced by the gateway.
	JWS string
	// GatewayJWK is the gateway public key as JWK JSON, PINNED when the bundle was exported.
	GatewayJWK json.RawMessage
}

// ResolvedRequirement is the approval requirement RequirementFor resolved for one action.
type ResolvedRequirement struct {
	Requirement verify.ApprovalRequirement `json:"requirement"`
	// ApproverDids are the approvers eligible for this action, per the selected rule.
	ApproverDids []string `json:"approverDids"`
}

// VerifyTrustBundle verifies a compact JWS bundle against a PINNED gateway key (JWK JSON) and returns
// its payload. asOf overrides "now" for the freshness check; the zero time means time.Now().
//
// Only RS256 is accepted, and the header's `alg` is checked against that fixed expectation rather
// than used to select an algorithm: trusting the token's own `alg` is the classic JWS confusion bug
// (`none` would skip verification; an HMAC alg would verify a MAC keyed with the public key).
func VerifyTrustBundle(jws string, gatewayJWK json.RawMessage, asOf time.Time) (*TrustBundle, error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 {
		return nil, errors.New("trust bundle is not a compact JWS")
	}
	headerBytes, err := decodeBase64URL(parts[0])
	if err != nil || !json.Valid(headerBytes) {
		return nil, errors.New("trust bundle header is not JSON")
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(headerBytes, &fields); err != nil || fields == nil {
		return nil, errors.New("invalid trust bundle header")
	}
	if alg, present := fields["alg"]; alg != "RS256" {
		shown := "(none)"
		if present && alg != nil {
			shown = fmt.Sprint(alg)
		}
		return nil, fmt.Errorf("trust bundle alg must be RS256, got %s", shown)
	}

	key, err := rsaKeyFromJWK(gatewayJWK)
	if err != nil {
		return nil, err
	}
	sig, err := decodeBase64URL(parts[2])
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err != nil || rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], sig) != nil {
		return nil, errors.New("trust bundle signature does not verify against the pinned gateway key")
	}

	payload, err := decodeBase64URL(parts[1])
	if err != nil || !json.Valid(payload) {
		return nil, errors.New("trust bundle payload is not JSON")
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(payload, &obj); err != nil || obj == nil {
		return nil, errors.New("invalid trust bundle payload")
	}
	bundle, err := trustBundleFromJSON(obj)
	if err != nil {
		return nil, err
	}

	if err := ValidateExactApprovalPolicy(policyRules(bundle.Policy)); err != nil {
		var conflict *ApprovalPolicyConflict
		if errors.As(err, &conflict) {
			return nil, fmt.Errorf("trust bundle has invalid exact-action policy: %s", strings.Join(conflict.Fields, ", "))
		}
		return nil, err
	}
	if bundle.UnmatchedActionPolicy == "BASELINE" && !hasBaseline(bundle.Policy) {
		return nil, errors.New("trust bundle has no baseline for unknown actions")
	}
	if err := CheckTrustBundleFreshness(bundle, asOf); err != nil {
		return nil, err
	}
	return bundle, nil
}

// CheckTrustBundleFreshness rechecks a verified bundle — after an out-of-band signing ceremony, say —
// without changing its trust keys. It refuses when now is after `expiresAt`, or when now − `issuedAt`
// exceeds MaxTrustBundleAgeDays. The zero asOf means time.Now().
//
// Two independent checks: the gateway's own `expiresAt` can be set generously, so the local age cap
// is what actually bounds drift.
func CheckTrustBundleFreshness(bundle *TrustBundle, asOf time.Time) error {
	if bundle == nil {
		return errors.New("no trust bundle")
	}
	now := nowOr(asOf).UnixMilli()
	expiry, ok := parseTimestampMillis(bundle.ExpiresAt)
	if !ok {
		return errors.New("trust bundle expiresAt is not a valid RFC3339 timestamp")
	}
	if now > expiry {
		return fmt.Errorf("trust bundle expired at %s — export a fresh one", bundle.ExpiresAt)
	}
	issued, ok := parseTimestampMillis(bundle.IssuedAt)
	if !ok {
		return errors.New("trust bundle issuedAt is not a valid RFC3339 timestamp")
	}
	const dayMillis = 86_400_000
	if age := now - issued; age > MaxTrustBundleAgeDays*dayMillis {
		return fmt.Errorf("trust bundle is %.1f days old, over the %d-day maximum — export a fresh one",
			float64(age)/dayMillis, MaxTrustBundleAgeDays)
	}
	return nil
}

// SaveTrustBundle writes a bundle and its pinned verification key into dir (`trust-bundle.jws` and
// `gateway-key.jwk.json`, private files in a private directory), for use during a later outage.
func SaveTrustBundle(dir string, files TrustBundleFiles) error {
	var jwk bytes.Buffer
	if err := json.Indent(&jwk, files.GatewayJWK, "", "  "); err != nil {
		return fmt.Errorf("gateway key is not JSON: %w", err)
	}
	jwk.WriteString("\n")
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	if err := writePrivateFile(filepath.Join(dir, trustBundleFile), []byte(files.JWS)); err != nil {
		return err
	}
	return writePrivateFile(filepath.Join(dir, gatewayKeyFile), jwk.Bytes())
}

// LoadTrustBundle loads and verifies the bundle saved in dir. The zero asOf means time.Now().
//
// It fails closed and LOUDLY: there is deliberately no "continue without a bundle" path, because the
// fallback would be an unverified approver set — the one thing DIV Invariant 3 forbids.
func LoadTrustBundle(dir string, asOf time.Time) (*TrustBundle, error) {
	bundlePath := filepath.Join(dir, trustBundleFile)
	jws, err := os.ReadFile(bundlePath)
	if err != nil {
		return nil, fmt.Errorf("no trust bundle at %s — export one with `intyga trust-bundle export` while the gateway is reachable", bundlePath)
	}
	keyPath := filepath.Join(dir, gatewayKeyFile)
	jwk, err := os.ReadFile(keyPath)
	if err != nil || !json.Valid(jwk) {
		return nil, fmt.Errorf("no pinned gateway key at %s", keyPath)
	}
	return VerifyTrustBundle(jsTrim(string(jws)), jwk, asOf)
}

// ApproverAnchor builds a DID-mode trust anchor from the bundle.
//
// DID mode, not PublicKeys mode, and that is load-bearing: quorum must count distinct APPROVERS, and
// a delegation (DIV §5a.6) names identities that cannot be enforced against an unverified signerDid.
// Flattening every key into one allowlist would let one approver holding a software key and two
// passkeys satisfy a 3-of-N quorum alone.
//
// limitToDids narrows the eligible set; nil means every approver in the bundle (an empty, non-nil
// slice narrows to nobody). purpose BundleAnchorOrdinary never admits an offline signing key; pass
// BundleAnchorOfflineIntent only when the receipt being verified is a div-offline-intent — a bare
// offline key that could seal a delegation would hand its holder the authority the delegation
// transfers.
func ApproverAnchor(bundle *TrustBundle, limitToDids []string, purpose BundleAnchorPurpose) verify.ApproverTrustAnchor {
	var order []string
	byDID := map[string][]string{}
	if bundle != nil {
		for _, a := range bundle.Approvers {
			if limitToDids != nil && !containsString(limitToDids, a.DID) {
				continue
			}
			keys := append([]string(nil), a.PublicKeys...)
			if purpose == BundleAnchorOfflineIntent {
				keys = append(keys, a.OfflinePublicKeys...)
			}
			if _, seen := byDID[a.DID]; !seen {
				order = append(order, a.DID)
			}
			byDID[a.DID] = keys
		}
	}
	return verify.ApproverTrustAnchor{
		DIDs: order,
		ResolveKeys: func(did string) []string {
			keys, ok := byDID[did]
			if !ok {
				return nil
			}
			return append([]string(nil), keys...)
		},
	}
}

// RequirementFor resolves the approval requirement for an action from the bundle's offline policy
// projection, with the exact-ID selection of approval policy version 3 (SelectExactApprovalRule).
//
// display is accepted for parity with the other SDKs and is never read: display text does not select
// a rule. It reports false — a refusal, with no default to fall back on — when the bundle is not a
// valid v1 bundle, the action is unmatched, the policy conflicts, the rule names fewer distinct
// approvers than its quorum, or the rule uses a control an offline ceremony cannot reproduce
// (requireAttestedRequester, allowedIssuers, escalation, an auto-approve requester).
func RequirementFor(bundle *TrustBundle, actionType, display string) (ResolvedRequirement, bool) {
	_ = display // never an authorization input
	if bundle == nil || bundle.V != 1 || bundle.Type != DivTrustBundleType ||
		(bundle.UnmatchedActionPolicy != "DENY" && bundle.UnmatchedActionPolicy != "BASELINE") {
		return ResolvedRequirement{}, false
	}
	for _, p := range bundle.Policy {
		if !validBundlePolicy(p) {
			return ResolvedRequirement{}, false
		}
	}
	i, err := SelectExactApprovalRule(policyRules(bundle.Policy), actionType, bundle.UnmatchedActionPolicy)
	if err != nil || i < 0 {
		return ResolvedRequirement{}, false
	}
	winner := bundle.Policy[i]
	if int64(len(distinctStrings(winner.ApproverDids))) < winner.RequiredApprovals ||
		winner.RequireAttestedRequester ||
		len(winner.AllowedIssuers) > 0 ||
		(winner.EscalateAfterSeconds != nil && *winner.EscalateAfterSeconds != 0) ||
		truthy(winner.AutoApproveRequesterDid) {
		return ResolvedRequirement{}, false
	}
	aaguids := append([]string{}, winner.AllowedAaguids...)
	approvers := append([]string{}, winner.ApproverDids...)
	return ResolvedRequirement{
		Requirement: verify.ApprovalRequirement{
			// Fits an int: it is at most the number of distinct approvers, checked above.
			RequiredApprovals:      int(max(1, winner.RequiredApprovals)),
			RequireHardwareKey:     winner.RequireHardwareKey,
			AllowedAaguids:         aaguids,
			RequesterCannotApprove: winner.RequesterCannotApprove,
			SignerClass:            "human",
		},
		ApproverDids: approvers,
	}, true
}

// validBundlePolicy is the typed form of the reference's validBundlePolicy: a typed entry always has
// every field, so what remains is the value constraints.
func validBundlePolicy(p BundlePolicy) bool {
	if p.SignerClass != "human" || jsTrim(p.ActionPattern) == "" ||
		p.RequiredApprovals < 1 || p.RequiredApprovals > maxSafeInteger {
		return false
	}
	for _, list := range [][]string{p.ApproverDids, p.AllowedAaguids, p.AllowedIssuers, p.EscalationApproverDids} {
		for _, v := range list {
			if v == "" {
				return false
			}
		}
	}
	if p.EscalateAfterSeconds != nil && (*p.EscalateAfterSeconds < 1 || *p.EscalateAfterSeconds > maxSafeInteger) {
		return false
	}
	return p.AutoApproveDayOfWeek == nil || (*p.AutoApproveDayOfWeek >= 0 && *p.AutoApproveDayOfWeek <= 6)
}

// trustBundleFromJSON validates a decoded payload exactly as the reference does — field by field, on
// the JSON value itself, so a field that is absent is told apart from one that is false or empty —
// and only then builds the typed bundle from the validated values. Building it from the generic value
// rather than decoding the bytes a second time matters: encoding/json matches keys
// case-insensitively, so a second decode could read a "Policy" that the checks never saw.
func trustBundleFromJSON(obj map[string]interface{}) (*TrustBundle, error) {
	if v, ok := obj["v"].(float64); obj["type"] != DivTrustBundleType || !ok || v != 1 {
		return nil, errors.New("unsupported trust bundle type or version")
	}
	unmatched, _ := obj["unmatchedActionPolicy"].(string)
	if unmatched != "DENY" && unmatched != "BASELINE" {
		return nil, errors.New("trust bundle has no valid unmatched-action decision")
	}
	rawApprovers, ok := obj["approvers"].([]interface{})
	if !ok || len(rawApprovers) == 0 {
		return nil, errors.New("trust bundle names no approvers")
	}
	approvers := make([]BundleApprover, 0, len(rawApprovers))
	for _, ra := range rawApprovers {
		a, ok := approverFromJSON(ra)
		if !ok {
			return nil, errors.New("invalid bundle approver keys")
		}
		approvers = append(approvers, a)
	}
	// A key listed as both ordinary and offline-only would undo the split the second list exists for.
	ordinary := map[string]bool{}
	for _, a := range approvers {
		for _, k := range a.PublicKeys {
			ordinary[k] = true
		}
	}
	for _, a := range approvers {
		for _, k := range a.OfflinePublicKeys {
			if ordinary[k] {
				return nil, errors.New("trust bundle lists an offline signing key as an ordinary key")
			}
		}
	}
	rawPolicy, ok := obj["policy"].([]interface{})
	if !ok {
		return nil, errors.New("trust bundle carries invalid or incomplete policy")
	}
	policy := make([]BundlePolicy, 0, len(rawPolicy))
	for _, rp := range rawPolicy {
		p, ok := bundlePolicyFromJSON(rp)
		if !ok {
			return nil, errors.New("trust bundle carries invalid or incomplete policy")
		}
		policy = append(policy, p)
	}
	tenantID, ok := obj["tenantId"].(string)
	if _, present := obj["tenantId"]; present && !ok {
		return nil, errors.New("trust bundle tenantId is not a string")
	}
	issuedAt, _ := obj["issuedAt"].(string)
	expiresAt, _ := obj["expiresAt"].(string)
	return &TrustBundle{
		V:                     1,
		Type:                  DivTrustBundleType,
		TenantID:              tenantID,
		Approvers:             approvers,
		Policy:                policy,
		UnmatchedActionPolicy: unmatched,
		IssuedAt:              issuedAt,
		ExpiresAt:             expiresAt,
	}, nil
}

func approverFromJSON(raw interface{}) (BundleApprover, bool) {
	a, ok := raw.(map[string]interface{})
	if !ok {
		return BundleApprover{}, false
	}
	did, ok := a["did"].(string)
	if !ok || did == "" {
		return BundleApprover{}, false
	}
	keys, ok := nonEmptyStrings(a["publicKeys"])
	if !ok || len(keys) == 0 {
		return BundleApprover{}, false
	}
	out := BundleApprover{DID: did, PublicKeys: keys}
	if rawOffline, present := a["offlinePublicKeys"]; present {
		offline, ok := nonEmptyStrings(rawOffline)
		if !ok {
			return BundleApprover{}, false
		}
		out.OfflinePublicKeys = offline
	}
	return out, true
}

// bundlePolicyFromJSON is the reference's validBundlePolicy on the JSON value, plus the conversion.
// Every field of a v1 entry is required; the nullable ones must be present as null.
func bundlePolicyFromJSON(raw interface{}) (BundlePolicy, bool) {
	p, ok := raw.(map[string]interface{})
	if !ok || p["signerClass"] != "human" {
		return BundlePolicy{}, false
	}
	var out BundlePolicy
	out.SignerClass = "human"
	pattern, ok := p["actionPattern"].(string)
	if !ok || jsTrim(pattern) == "" {
		return BundlePolicy{}, false
	}
	out.ActionPattern = pattern
	required, ok := safeInteger(p["requiredApprovals"])
	if !ok || required < 1 {
		return BundlePolicy{}, false
	}
	out.RequiredApprovals = required
	for field, dst := range map[string]*bool{
		"requireHardwareKey":       &out.RequireHardwareKey,
		"requesterCannotApprove":   &out.RequesterCannotApprove,
		"requireAttestedRequester": &out.RequireAttestedRequester,
	} {
		v, ok := p[field].(bool)
		if !ok {
			return BundlePolicy{}, false
		}
		*dst = v
	}
	for field, dst := range map[string]*[]string{
		"approverDids":           &out.ApproverDids,
		"allowedAaguids":         &out.AllowedAaguids,
		"allowedIssuers":         &out.AllowedIssuers,
		"escalationApproverDids": &out.EscalationApproverDids,
	} {
		v, ok := nonEmptyStrings(p[field])
		if !ok {
			return BundlePolicy{}, false
		}
		*dst = v
	}
	escalate, present := p["escalateAfterSeconds"]
	if !present {
		return BundlePolicy{}, false
	}
	if escalate != nil {
		seconds, ok := safeInteger(escalate)
		if !ok || seconds < 1 {
			return BundlePolicy{}, false
		}
		out.EscalateAfterSeconds = &seconds
	}
	for field, dst := range map[string]**string{
		"autoApproveRequesterDid": &out.AutoApproveRequesterDid,
		"autoApproveWindowStart":  &out.AutoApproveWindowStart,
		"autoApproveWindowEnd":    &out.AutoApproveWindowEnd,
	} {
		v, present := p[field]
		if !present {
			return BundlePolicy{}, false
		}
		if v != nil {
			s, ok := v.(string)
			if !ok {
				return BundlePolicy{}, false
			}
			*dst = &s
		}
	}
	day, present := p["autoApproveDayOfWeek"]
	if !present {
		return BundlePolicy{}, false
	}
	if day != nil {
		d, ok := day.(float64)
		if !ok || d != math.Trunc(d) || d < 0 || d > 6 {
			return BundlePolicy{}, false
		}
		dow := int(d)
		out.AutoApproveDayOfWeek = &dow
	}
	// Not validated by the reference either, but read when present: LostApprovalConstraints compares
	// them, and the gateway's own rule shape carries them.
	for field, dst := range map[string]*[]string{
		"approverGroupIds":   &out.ApproverGroupIds,
		"escalationGroupIds": &out.EscalationGroupIds,
	} {
		if v, present := p[field]; present && v != nil {
			list, ok := nonEmptyStrings(v)
			if !ok {
				return BundlePolicy{}, false
			}
			*dst = list
		}
	}
	for field, dst := range map[string]*json.RawMessage{
		"selectionRank": &out.SelectionRank,
		"selectionKey":  &out.SelectionKey,
	} {
		if v, present := p[field]; present {
			b, err := json.Marshal(v)
			if err != nil {
				return BundlePolicy{}, false
			}
			*dst = b
		}
	}
	return out, true
}

// nonEmptyStrings accepts a JSON array whose every element is a non-empty string.
func nonEmptyStrings(raw interface{}) ([]string, bool) {
	list, ok := raw.([]interface{})
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		s, ok := v.(string)
		if !ok || s == "" {
			return nil, false
		}
		out = append(out, s)
	}
	return out, true
}

// safeInteger is Number.isSafeInteger on a decoded JSON value.
func safeInteger(raw interface{}) (int64, bool) {
	f, ok := raw.(float64)
	if !ok || f != math.Trunc(f) || math.Abs(f) > maxSafeInteger {
		return 0, false
	}
	return int64(f), true
}

func rsaKeyFromJWK(raw json.RawMessage) (*rsa.PublicKey, error) {
	var jwk struct {
		Kty string `json:"kty"`
		N   string `json:"n"`
		E   string `json:"e"`
	}
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return nil, errors.New("pinned gateway key is unusable: not a JSON Web Key")
	}
	// RS256 means an RSA key. A pinned EC key would otherwise have the KEY choose the algorithm —
	// the confusion the alg check exists to prevent.
	if jwk.Kty != "RSA" {
		return nil, errors.New("pinned gateway key must be an RSA JWK")
	}
	n, err := decodeBase64URL(jwk.N)
	if err != nil || len(n) == 0 {
		return nil, errors.New("pinned gateway key is unusable: modulus n is not base64url")
	}
	e, err := decodeBase64URL(jwk.E)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.New("pinned gateway key is unusable: exponent e is not a valid base64url integer")
	}
	exponent := new(big.Int).SetBytes(e).Int64()
	if exponent < 3 || exponent > math.MaxInt32 {
		return nil, errors.New("pinned gateway key is unusable: exponent e is out of range")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent)}, nil
}

// decodeBase64URL decodes a JWS segment or JWK member: base64url or base64, padded or not — the
// leniency of the reference's Buffer.from(s.replace(-→+, _→/), "base64") for these signed or pinned
// inputs, short of its silently skipping invalid characters. Envelopes use decodeStrictBase64URL.
func decodeBase64URL(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64.RawStdEncoding.DecodeString(s)
}

// strictBase64URL is the envelope alphabet: base64url, optionally padded. A character outside it is
// refused rather than skipped — Go's decoder would otherwise drop CR and LF, and the reference's
// decoder drops anything — so a paste with stray text never decodes to something other than was sent.
var strictBase64URL = regexp.MustCompile(`^[A-Za-z0-9_-]*={0,2}$`)

// decodeStrictBase64URL decodes the payload of a DIV1: or SIG1: envelope.
func decodeStrictBase64URL(s string) ([]byte, error) {
	if !strictBase64URL.MatchString(s) {
		return nil, errors.New("not base64url")
	}
	return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
}

// rfc3339DateTime is RFC 3339 §5.6 date-time, strictly — the DIV §6.2 grammar every port applies:
// four-digit year, uppercase T and Z, seconds present, a 1–9 digit fraction and an explicit zone.
// It mirrors parseSignedTime in verify-go (unexported there) and parseRfc3339Ms in @intyga/verify;
// change them together.
var rfc3339DateTime = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([0-9]{2}):([0-9]{2}))$`)

// parseTimestampMillis parses a strict RFC 3339 timestamp (DIV §6.2) to epoch milliseconds, the
// resolution of the reference. A bare date, a zone-less time, a date that does not exist, hour 24, a
// leap second and an offset beyond ±23:59 are all refused. time.RFC3339 alone accepts several of
// those, which the other ports refuse.
func parseTimestampMillis(s string) (int64, bool) {
	m := rfc3339DateTime.FindStringSubmatch(s)
	if m == nil {
		return 0, false
	}
	if m[3] != "" {
		h, _ := strconv.Atoi(m[3])
		mi, _ := strconv.Atoi(m[4])
		if h > 23 || mi > 59 {
			return 0, false
		}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return 0, false
	}
	return t.UnixMilli(), true
}

// isoMillis formats t exactly as JavaScript's Date.prototype.toISOString: UTC, three fractional digits
// always, `Z`. time.RFC3339Nano would trim trailing zeros, and the signed bytes must not depend on
// whether the clock happened to land on a whole second.
func isoMillis(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

func nowOr(asOf time.Time) time.Time {
	if asOf.IsZero() {
		return time.Now()
	}
	return asOf
}

func policyRules(policy []BundlePolicy) []PolicyRule {
	rules := make([]PolicyRule, len(policy))
	for i, p := range policy {
		rules[i] = p.PolicyRule
	}
	return rules
}

func hasBaseline(policy []BundlePolicy) bool {
	for _, p := range policy {
		if p.ActionPattern == "*" {
			return true
		}
	}
	return false
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func distinctStrings(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
