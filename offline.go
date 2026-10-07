package intyga

// Offline approval (docs/DIV.md §5a) — the relying-party half. Ported from packages/sdk/src/offline.ts;
// docs/OFFLINE-APPROVAL-SDK.md is the contract and packages/mcp-schemas/vectors/
// offline-approval-vectors.json the conformance suite.
//
// When the gateway is unreachable, the relying party builds the challenge ITSELF, the humans review
// and sign it on a disconnected device, and the result is verified by the ordinary §5 procedure. The
// signing ceremony moves off the network; it does not move earlier in time. Pre-signing approvals
// and holding them until needed would put a bearer capability on disk and capture a human judgment
// about a hypothetical rather than the incident in progress (DIV §5a.1).
//
// Four properties are enforced structurally, because each is the kind of thing a reasonable-looking
// refactor would quietly remove:
//
//  1. IT ONLY APPLIES WHEN WE COULD NOT ASK. The client's fallback is reachable only from a transport
//     failure. DENIED or EXPIRED means a human was reached and did not approve.
//  2. IT RETURNS A DISTINCT STATUS, StatusOfflineApproved, never StatusApproved.
//  3. THE POLICY COMES FROM THE BUNDLE, NOT FROM HERE. The requirement is read from the signed trust
//     bundle, with no local default to fall back on.
//  4. NOTHING PERSISTS THAT AUTHORIZES ANYTHING. What is written to disk records that an approval
//     HAPPENED, for reconciliation. No file written here can authorize a future action.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	verify "github.com/intyga-dev/sdk-go/verify"
)

const (
	// ChallengeEnvelopePrefix marks a challenge travelling OUT to the approvers.
	ChallengeEnvelopePrefix = "DIV1:"
	// SignatureEnvelopePrefix marks a signature coming BACK from an approver.
	SignatureEnvelopePrefix = "SIG1:"
	// DefaultOfflineWindowMinutes is the default validity window. Deliberately short: an offline
	// approval is created and redeemed inside one incident, and the window is the only bound on a
	// proof that no one can revoke. It is capped at verify.MaxOfflineWindowMinutes.
	DefaultOfflineWindowMinutes = 15
)

var pathSafeNonce = regexp.MustCompile(`^[A-Za-z0-9._-]{1,200}$`)

// isPathSafeNonce: nonces become path segments in the redemption store and the reconciliation
// buffer, so anything that could traverse out of those directories is refused.
func isPathSafeNonce(nonce string) bool { return pathSafeNonce.MatchString(nonce) }

// OfflineChallenge is a locally generated offline challenge, ready to hand to the approvers.
type OfflineChallenge struct {
	// Nonce is generated HERE, by the party that will redeem it (DIV §5a.2).
	Nonce string `json:"nonce"`
	// CanonicalPayload is the exact text the approvers sign (its UTF-8 bytes).
	CanonicalPayload string `json:"canonicalPayload"`
	// VerificationCode is the short code the approver MUST read back to the operator before
	// signing (DIV §5a.8).
	VerificationCode string `json:"verificationCode"`
	// Envelope is `DIV1:<base64url>` — what travels to the approver, by QR or copy-paste.
	Envelope     string                     `json:"envelope"`
	ChallengedAt string                     `json:"challengedAt"`
	ExpiresAt    string                     `json:"expiresAt"`
	Target       string                     `json:"target"`
	ActionType   string                     `json:"actionType"`
	Display      string                     `json:"display"`
	Params       map[string]interface{}     `json:"params"`
	Requester    verify.RequesterIdentity   `json:"requester"`
	Requirement  verify.ApprovalRequirement `json:"requirement"`
	// ApproverDids are the approvers eligible to sign, per the bundle rule (or the delegation).
	ApproverDids []string `json:"approverDids"`
}

// OfflineChallengeInput is the input to CreateOfflineChallenge. There is no requirement field: the
// requirement comes from Bundle, never from the caller.
type OfflineChallengeInput struct {
	Bundle     *TrustBundle
	Target     string
	ActionType string
	Display    string
	Params     map[string]interface{}
	Requester  verify.RequesterIdentity
	// WindowMinutes is the validity window in whole minutes; nil means DefaultOfflineWindowMinutes.
	// It is clamped to [1, verify.MaxOfflineWindowMinutes]. (The reference also refuses a fractional
	// window; an int cannot carry one.)
	WindowMinutes *int
	// AsOf overrides "now", for tests and deterministic replay. The zero time means time.Now().
	AsOf time.Time
	// Nonce overrides the generated nonce, for conformance vectors and deterministic replay.
	// Production callers leave it nil, which generates `off_<random UUID>`. A supplied nonce is used
	// as is — never replaced, so a supplied empty one is refused — and must be a safe path segment
	// (^[A-Za-z0-9._-]{1,200}$).
	Nonce *string
	// Delegation is a delegation already verified by verify.VerifyDelegation, for when the ordinary
	// approvers are unreachable too. Its DelegatedQuorum becomes the signed requiredApprovals and its
	// DelegatedTo the eligible set (DIV §5a.6 step 3).
	Delegation *verify.VerifiedDelegation
}

// CreateOfflineChallenge builds an offline challenge for an action, taking the approval requirement
// from the trust bundle.
//
// The requirement is NOT a parameter: a relying party that supplied its own would be choosing the
// quorum its own action must clear (DIV §5a.3). It refuses when the bundle has no rule for the action
// (there is no implicit 1-of-1 fallback), when the rule requires a hardware credential (which cannot
// be produced offline), when a delegation would lower the rule's quorum, on a blank target, and on
// an unsafe or empty nonce.
func CreateOfflineChallenge(in OfflineChallengeInput) (*OfflineChallenge, error) {
	// DIV §3 Invariant 5 (Target Isolation): a blank target binds no execution environment, so the
	// approval would verify at every relying party that also asserts it.
	if jsTrim(in.Target) == "" {
		return nil, errors.New("target is required (DIV Target Isolation)")
	}
	resolved, ok := RequirementFor(in.Bundle, in.ActionType, in.Display)
	if !ok {
		return nil, fmt.Errorf(`the trust bundle has no approval rule matching "%s" that can be selected unambiguously — configure the rule or export a fresh bundle with rule-selection metadata (DIV §5a.3)`, in.ActionType)
	}
	// Refused at CHALLENGE time as well as at verification: sending approvers a payload nobody can
	// produce a valid signature for wastes the one resource an incident is short of.
	if resolved.Requirement.RequiresHardwareCredential() {
		return nil, fmt.Errorf(`"%s" requires a hardware-backed WebAuthn credential, which cannot be produced offline — this action cannot be approved out of band (DIV §5a.3)`, in.ActionType)
	}

	window := DefaultOfflineWindowMinutes
	if in.WindowMinutes != nil {
		window = *in.WindowMinutes
		// Number.isSafeInteger in the reference: anything wider is refused there, so it is here.
		// Compared as int64 so the check compiles, and means the same, on 32-bit builds.
		if int64(window) > maxSafeInteger || int64(window) < -maxSafeInteger {
			return nil, errors.New("windowMinutes must be a whole number of minutes")
		}
	}
	window = min(verify.MaxOfflineWindowMinutes, max(1, window))
	// Millisecond resolution, as the reference's Date, so expiresAt − challengedAt is exactly the window.
	now := time.UnixMilli(nowOr(in.AsOf).UnixMilli()).UTC()
	challengedAt := isoMillis(now)
	expiresAt := isoMillis(now.Add(time.Duration(window) * time.Minute))
	var nonce string
	if in.Nonce != nil {
		nonce = *in.Nonce
	} else {
		id, err := randomUUID()
		if err != nil {
			return nil, err
		}
		nonce = "off_" + id
	}
	if !isPathSafeNonce(nonce) {
		return nil, errors.New("nonce must be a safe path segment")
	}

	// "Narrows who may approve, never the policy" has to be enforced, not merely intended (DIV §5a.5).
	// Without this the substitution below silently LOWERS the quorum: display is free to differ
	// between sealing and use, so a delegation sealed against a permissive rule could be presented
	// against a strict one and overwrite its quorum.
	if in.Delegation != nil && in.Delegation.DelegatedQuorum < resolved.Requirement.RequiredApprovals {
		return nil, fmt.Errorf(`this delegation would lower the quorum for "%s" from %d to %d. A delegation may narrow WHO approves, never HOW MANY (DIV §5a.5)`,
			in.ActionType, resolved.Requirement.RequiredApprovals, in.Delegation.DelegatedQuorum)
	}

	// Under a delegation the eligible set and the quorum are the DELEGATED ones. Everything else in
	// the requirement still comes from the bundle.
	requirement := resolved.Requirement
	approverDids := resolved.ApproverDids
	if in.Delegation != nil {
		requirement.RequiredApprovals = in.Delegation.DelegatedQuorum
		approverDids = append([]string{}, in.Delegation.DelegatedTo...)
	}
	params := in.Params
	if params == nil {
		params = map[string]interface{}{}
	}

	canonical, err := verify.CanonicalOfflineIntentPayload(in.Target, in.ActionType, in.Display, params,
		in.Requester, requirement, nonce, challengedAt, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("the action cannot be canonicalized: %w", err)
	}
	return &OfflineChallenge{
		Nonce:            nonce,
		CanonicalPayload: canonical,
		VerificationCode: VerificationCode(canonical),
		Envelope:         ChallengeEnvelopePrefix + base64.RawURLEncoding.EncodeToString([]byte(canonical)),
		ChallengedAt:     challengedAt,
		ExpiresAt:        expiresAt,
		Target:           in.Target,
		ActionType:       in.ActionType,
		Display:          in.Display,
		Params:           params,
		Requester:        in.Requester,
		Requirement:      requirement,
		ApproverDids:     approverDids,
	}, nil
}

// VerificationCode is the short code shown to the approver and the operator: the first 8 hex digits of
// SHA-256 over the canonical payload, uppercase, grouped XXXX-XXXX.
func VerificationCode(canonicalPayload string) string {
	sum := sha256.Sum256([]byte(canonicalPayload))
	h := strings.ToUpper(hex.EncodeToString(sum[:4]))
	return h[:4] + "-" + h[4:]
}

// DecodedChallenge is what an approver's signing tool shows before asking for confirmation.
type DecodedChallenge struct {
	CanonicalPayload string                     `json:"canonicalPayload"`
	VerificationCode string                     `json:"verificationCode"`
	Target           string                     `json:"target"`
	ActionType       string                     `json:"actionType"`
	Display          string                     `json:"display"`
	Params           map[string]interface{}     `json:"params"`
	Requester        verify.RequesterIdentity   `json:"requester"`
	Requirement      verify.ApprovalRequirement `json:"requirement"`
	Nonce            string                     `json:"nonce"`
	ChallengedAt     string                     `json:"challengedAt"`
	ExpiresAt        string                     `json:"expiresAt"`
}

// DecodeChallengeEnvelope decodes a `DIV1:` envelope for review by a signing tool.
//
// It refuses anything but a canonical div-offline-intent: an approver's tool must not be usable to
// sign an ORDINARY intent someone pasted in (that signature would be a live approval outside the
// gateway's single-use accounting), and re-serializing the payload must reproduce its bytes exactly,
// or a signature over them would verify nowhere.
func DecodeChallengeEnvelope(envelope string) (*DecodedChallenge, error) {
	trimmed := jsTrim(envelope)
	if !strings.HasPrefix(trimmed, ChallengeEnvelopePrefix) {
		return nil, fmt.Errorf("not a challenge envelope (expected a %s prefix)", ChallengeEnvelopePrefix)
	}
	payload, err := decodeStrictBase64URL(trimmed[len(ChallengeEnvelopePrefix):])
	if err != nil {
		return nil, errors.New("challenge envelope is not valid base64url")
	}
	if !json.Valid(payload) {
		return nil, errors.New("challenge envelope does not contain a JSON payload (truncated paste?)")
	}
	// Decoded straight into an object: a valid null, array or scalar is not a challenge.
	var parsed map[string]interface{}
	if err := json.Unmarshal(payload, &parsed); err != nil || parsed == nil {
		return nil, errors.New("challenge payload is not a JSON object")
	}
	if parsed["type"] != verify.DivOfflineIntentType {
		return nil, fmt.Errorf("this is a %s payload, not an offline approval challenge — refusing to sign it", fmt.Sprint(parsed["type"]))
	}
	// Shapes before bytes. Canonicalization alone would accept a "target": 5 or a blank target
	// whenever it re-serializes identically, and the approver would then review — and sign —
	// something no relying party builds. Every SDK refuses the same shapes.
	if problem := challengeShapeProblem(parsed); problem != "" {
		return nil, fmt.Errorf("challenge payload %s — refusing to sign it", problem)
	}
	const notCanonicalizable = "challenge payload carries values that cannot be canonicalized — refusing to sign it"
	var fields struct {
		Target       string                     `json:"target"`
		ActionType   string                     `json:"actionType"`
		Display      string                     `json:"display"`
		Params       map[string]interface{}     `json:"params"`
		Requester    verify.RequesterIdentity   `json:"requester"`
		Requirement  verify.ApprovalRequirement `json:"requirement"`
		Nonce        string                     `json:"nonce"`
		ChallengedAt string                     `json:"challengedAt"`
		ExpiresAt    string                     `json:"expiresAt"`
	}
	if err := json.Unmarshal(payload, &fields); err != nil {
		return nil, errors.New(notCanonicalizable)
	}
	rebuilt, err := verify.CanonicalOfflineIntentPayload(fields.Target, fields.ActionType, fields.Display,
		fields.Params, fields.Requester, fields.Requirement, fields.Nonce, fields.ChallengedAt, fields.ExpiresAt)
	if err != nil {
		return nil, errors.New(notCanonicalizable)
	}
	canonical := string(payload)
	if !utf8.Valid(payload) || rebuilt != canonical {
		return nil, errors.New("challenge payload is not canonical — re-serializing it produces different bytes, so a signature over it would verify nowhere")
	}
	return &DecodedChallenge{
		CanonicalPayload: canonical,
		VerificationCode: VerificationCode(canonical),
		Target:           fields.Target,
		ActionType:       fields.ActionType,
		Display:          fields.Display,
		Params:           fields.Params,
		Requester:        fields.Requester,
		Requirement:      fields.Requirement,
		Nonce:            fields.Nonce,
		ChallengedAt:     fields.ChallengedAt,
		ExpiresAt:        fields.ExpiresAt,
	}, nil
}

// challengeShapeProblem says why a decoded challenge payload has the wrong shape, or "" when every
// field is well-typed: the six text fields are strings, the target is not blank, params and
// requirement are objects, and requester is an object with a string did.
func challengeShapeProblem(p map[string]interface{}) string {
	for _, field := range []string{"target", "actionType", "display", "nonce", "challengedAt", "expiresAt"} {
		if _, ok := p[field].(string); !ok {
			return "field " + field + " is not a string"
		}
	}
	if jsTrim(p["target"].(string)) == "" {
		return "has a blank target"
	}
	if _, ok := p["params"].(map[string]interface{}); !ok {
		return "params is not a JSON object"
	}
	requester, ok := p["requester"].(map[string]interface{})
	if !ok {
		return "requester is not an identity"
	}
	if _, ok := requester["did"].(string); !ok {
		return "requester is not an identity"
	}
	if _, ok := p["requirement"].(map[string]interface{}); !ok {
		return "requirement is not a JSON object"
	}
	return ""
}

// EncodeSignatureEnvelope encodes one approver's signature for the trip back to the relying party:
// `SIG1:` + base64url (no padding) of {"did":…,"key":…,"sig":…,"alg":…} — that key order, no
// whitespace, strings escaped exactly as JSON.stringify escapes them (encoding/json would escape
// <, > and &, and the envelope must be byte-identical in every SDK). A missing SigAlg is "ES256".
func EncodeSignatureEnvelope(w verify.ApprovalWitness) string {
	alg := "ES256"
	if w.SigAlg != nil {
		alg = *w.SigAlg
	}
	compact := `{"did":` + jsString(w.SignerDID) + `,"key":` + jsString(w.SignerPublicKey) +
		`,"sig":` + jsString(w.Signature) + `,"alg":` + jsString(alg) + `}`
	return SignatureEnvelopePrefix + base64.RawURLEncoding.EncodeToString([]byte(compact))
}

// DecodeSignatureEnvelope decodes a `SIG1:` envelope back into a witness. The payload must be strict
// base64url of a JSON object. A did, key or sig that is missing, empty or not a string is refused, and
// so is an alg that is present but not a non-empty string; a missing alg defaults to ES256.
func DecodeSignatureEnvelope(envelope string) (verify.ApprovalWitness, error) {
	trimmed := jsTrim(envelope)
	if !strings.HasPrefix(trimmed, SignatureEnvelopePrefix) {
		return verify.ApprovalWitness{}, fmt.Errorf("not a signature envelope (expected a %s prefix)", SignatureEnvelopePrefix)
	}
	const unreadable = "signature envelope is not valid base64url JSON (truncated paste?)"
	raw, err := decodeStrictBase64URL(trimmed[len(SignatureEnvelopePrefix):])
	if err != nil {
		return verify.ApprovalWitness{}, errors.New(unreadable)
	}
	if !json.Valid(raw) {
		return verify.ApprovalWitness{}, errors.New(unreadable)
	}
	// A pasted null, array or scalar is a refusal of THIS envelope; the ceremony discards it and
	// counts the rest.
	var compact map[string]interface{}
	if err := json.Unmarshal(raw, &compact); err != nil || compact == nil {
		return verify.ApprovalWitness{}, errors.New("signature envelope is not a JSON object")
	}
	did, _ := compact["did"].(string)
	key, _ := compact["key"].(string)
	sig, _ := compact["sig"].(string)
	if did == "" || key == "" || sig == "" {
		return verify.ApprovalWitness{}, errors.New("signature envelope is missing did, key or sig")
	}
	alg := "ES256"
	if rawAlg, present := compact["alg"]; present {
		s, ok := rawAlg.(string)
		if !ok || s == "" {
			return verify.ApprovalWitness{}, errors.New("signature envelope alg must be a string")
		}
		alg = s
	}
	return verify.ApprovalWitness{SignerDID: did, SignerPublicKey: key, Signature: sig, SigAlg: &alg}, nil
}

// SignChallengeOptions configures SignChallengeEnvelope.
type SignChallengeOptions struct {
	// PrivateKey is the approver's offline signing key, a P-256 private key: any crypto.Signer whose
	// public key is P-256 (*ecdsa.PrivateKey, or a KMS/HSM-backed signer), a PEM string or []byte
	// (PKCS#8 "PRIVATE KEY" or SEC 1 "EC PRIVATE KEY"), or DER PKCS#8 []byte.
	PrivateKey interface{}
	// SignerDID is the approver's DID, as the trust bundle names them.
	SignerDID string
	// AsOf overrides "now" for the expiry check. The zero time means time.Now().
	AsOf time.Time
}

// SignedChallenge is the result of SignChallengeEnvelope.
type SignedChallenge struct {
	// Envelope is the `SIG1:` envelope to send back to the relying party.
	Envelope string
	// Challenge is the decoded challenge that was signed.
	Challenge *DecodedChallenge
}

// SignChallengeEnvelope signs a `DIV1:` challenge as an approver — the library half of `intyga sign`.
//
// It decodes first (DecodeChallengeEnvelope), so only a canonical div-offline-intent is ever signed,
// and refuses a challenge whose expiresAt is unreadable or already past, a SignerDID that is not a
// DID, and any key that is not a P-256 private key. The signature is ES256 over the canonical
// payload's UTF-8 bytes, IEEE P1363 (r‖s), base64; the envelope's key is the signer's SPKI.
//
// It shows nothing. The caller MUST have shown the decoded challenge to the approver and had them
// confirm the verification code with the operator before calling this (DIV §5a.8) — an approver who
// signs an opaque blob has approved nothing. DecodeChallengeEnvelope is how to show it.
func SignChallengeEnvelope(envelope string, opts SignChallengeOptions) (*SignedChallenge, error) {
	challenge, err := DecodeChallengeEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	// A timestamp we cannot read is not one we can say is still valid (DIV §6.2).
	expiry, ok := parseTimestampMillis(challenge.ExpiresAt)
	if !ok {
		return nil, errors.New("expiresAt is not a valid RFC3339 timestamp — refusing to sign")
	}
	if expiry <= nowOr(opts.AsOf).UnixMilli() {
		return nil, errors.New("this challenge has already expired — ask for a fresh one")
	}
	if !strings.HasPrefix(opts.SignerDID, "did:") {
		return nil, errors.New("signerDid must be a DID")
	}
	signer, err := p256Signer(opts.PrivateKey)
	if err != nil {
		return nil, err
	}
	signature, err := signP1363(signer, []byte(challenge.CanonicalPayload))
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("could not encode the public key: %w", err)
	}
	alg := "ES256"
	return &SignedChallenge{
		Challenge: challenge,
		Envelope: EncodeSignatureEnvelope(verify.ApprovalWitness{
			SignerDID:       opts.SignerDID,
			SignerPublicKey: base64.StdEncoding.EncodeToString(spki),
			Signature:       signature,
			SigAlg:          &alg,
		}),
	}, nil
}

// p256Signer turns the accepted key forms into a crypto.Signer and pins the curve to P-256.
func p256Signer(key interface{}) (crypto.Signer, error) {
	var parsed interface{}
	switch k := key.(type) {
	case crypto.Signer:
		parsed = k
	case string:
		p, err := parsePEMPrivateKey([]byte(k))
		if err != nil {
			return nil, fmt.Errorf("could not read the private key: %w", err)
		}
		parsed = p
	case []byte:
		var p interface{}
		var err error
		if strings.Contains(string(k), "-----BEGIN") {
			p, err = parsePEMPrivateKey(k)
		} else {
			p, err = x509.ParsePKCS8PrivateKey(k)
		}
		if err != nil {
			return nil, fmt.Errorf("could not read the private key: %w", err)
		}
		parsed = p
	default:
		return nil, fmt.Errorf("could not read the private key: unsupported key type %T", key)
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, errors.New("the signing key must be a P-256 (prime256v1) private key")
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("the signing key must be a P-256 (prime256v1) private key")
	}
	return signer, nil
}

func parsePEMPrivateKey(data []byte) (interface{}, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	}
	return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
}

// signP1363 signs SHA-256(message) and returns the IEEE P1363 (r‖s) signature, base64.
func signP1363(signer crypto.Signer, message []byte) (string, error) {
	digest := sha256.Sum256(message)
	der, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return "", err
	}
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil || len(rest) != 0 || sig.R == nil || sig.S == nil ||
		sig.R.Sign() <= 0 || sig.S.Sign() <= 0 || sig.R.BitLen() > 256 || sig.S.BitLen() > 256 {
		return "", errors.New("signer returned a malformed ECDSA signature")
	}
	raw := make([]byte, 64)
	sig.R.FillBytes(raw[:32])
	sig.S.FillBytes(raw[32:])
	return base64.StdEncoding.EncodeToString(raw), nil
}

// AssembleOfflineReceipt assembles the collected witnesses into a receipt the ordinary verifier can
// check (verify.VerifyApprovalReceipt with AllowOffline).
func AssembleOfflineReceipt(challenge *OfflineChallenge, witnesses []verify.ApprovalWitness) verify.ApprovalReceipt {
	target, actionType := challenge.Target, challenge.ActionType
	requester := challenge.Requester
	return verify.ApprovalReceipt{
		CanonicalPayload:  challenge.CanonicalPayload,
		Target:            &target,
		ActionType:        &actionType,
		ActionDescription: challenge.Display,
		Params:            challenge.Params,
		Signatures:        append([]verify.ApprovalWitness(nil), witnesses...),
		Requester:         &requester,
		VerificationCode:  challenge.VerificationCode,
	}
}

// RedemptionStore records which offline nonces this relying party has already redeemed.
//
// Single use is inherently stateful and LOCAL (DIV §5 steps 9-10). Because the relying party
// generates its own nonce, single use within it is fully enforceable — unlike a pre-signed token,
// which two relying parties could each redeem unaware.
type RedemptionStore interface {
	// Redeem claims nonce. It MUST be atomic and MUST return false if the nonce was already claimed.
	Redeem(nonce string) bool
}

// FileRedemptionStore is the default RedemptionStore: one `<nonce>.used` file per redeemed nonce,
// created with O_CREATE|O_EXCL so two processes racing the same nonce cannot both succeed.
type FileRedemptionStore struct {
	dir string
}

// NewFileRedemptionStore opens (creating it as a private directory if needed) a redemption store.
func NewFileRedemptionStore(dir string) (*FileRedemptionStore, error) {
	if err := ensurePrivateDir(dir); err != nil {
		return nil, err
	}
	return &FileRedemptionStore{dir: dir}, nil
}

// Redeem claims nonce, and reports false when it was already claimed, is not a safe path segment, or
// cannot be recorded.
func (s *FileRedemptionStore) Redeem(nonce string) bool {
	if !isPathSafeNonce(nonce) {
		return false
	}
	return createPrivateMarker(filepath.Join(s.dir, nonce+".used"), isoMillis(time.Now()))
}

// OfflineAction is the action an offline approval is for, asserted by the relying party itself.
type OfflineAction struct {
	Target     string
	ActionType string
	// Display is the human-readable description the approvers review.
	Display string
	Params  map[string]interface{}
}

// OfflineApprovalOptions configures UseOfflineApproval, and the client's offline fallback.
type OfflineApprovalOptions struct {
	// BundleDir holds the signed trust bundle and the pinned gateway key (see SaveTrustBundle).
	BundleDir string
	// RequesterDID is this workload's own identity, bound into the signed bytes.
	RequesterDID string
	// CollectSignatures gets the challenge to the approvers and their `SIG1:` envelopes back. It is a
	// seam, not a default: transporting the envelope is a human, site-specific act (a terminal
	// prompt, a QR code, a phone call), and inventing one here would quietly assume connectivity.
	CollectSignatures func(ctx context.Context, challenge *OfflineChallenge) ([]string, error)
	// DelegationDir holds pre-signed delegation receipts (`*.json`), for when the approvers are
	// unreachable too. Empty means no delegation is considered.
	DelegationDir string
	// Store records redeemed nonces. Nil means a FileRedemptionStore at <BundleDir>/.redeemed.
	Store RedemptionStore
	// BufferDir is where approvals are buffered for reconciliation. Empty means <BundleDir>/.pending.
	BufferDir string
	// WindowMinutes is the validity window; nil means DefaultOfflineWindowMinutes.
	WindowMinutes *int
	// Warn receives the loud warnings. Nil means standard error — this must never be quiet.
	Warn func(message string)
	// AsOf overrides "now", for tests and deterministic replay. The zero time means time.Now().
	AsOf time.Time
}

// OfflineApprovalResult is a completed offline approval.
type OfflineApprovalResult struct {
	Receipt verify.ApprovalReceipt
	Nonce   string
	// Signers are who actually signed, as verified against the trust bundle, sorted.
	Signers []string
	// ViaDelegation is the delegation's nonce when a delegation supplied the approver set.
	ViaDelegation string
}

// UseOfflineApproval runs a full offline approval: load and verify the bundle, pick up a delegation if
// one applies, build the challenge, collect signatures out of band, verify, buffer the record for
// reconciliation, and redeem the nonce.
//
// Verification is verify.VerifyApprovalReceipt with AllowOffline, so every ordinary control still
// applies — target isolation, exact parameter binding, the signed quorum, four-eyes, the trusted
// signer set, expiry and the window cap. This widens WHEN an approval may be obtained, never WHAT it
// authorizes. The nonce is redeemed before success is returned; a proof that verifies but cannot be
// claimed has already been used here, and is refused. Any refusal is returned as an error.
func UseOfflineApproval(ctx context.Context, expected OfflineAction, opts OfflineApprovalOptions) (*OfflineApprovalResult, error) {
	warn := opts.Warn
	if warn == nil {
		warn = func(m string) { fmt.Fprintln(os.Stderr, m) }
	}
	if opts.CollectSignatures == nil {
		return nil, errors.New("CollectSignatures is required: it is how the challenge reaches the approvers")
	}
	bundle, err := LoadTrustBundle(opts.BundleDir, opts.AsOf)
	if err != nil {
		return nil, err
	}
	params := expected.Params
	if params == nil {
		params = map[string]interface{}{}
	}
	expected.Params = params

	// A delegation is the TIER-3 path: only consulted when one is present on disk. It is verified
	// against the bundle's ORDINARY approver set — the people entitled to approve this action are the
	// ones who must have signed that entitlement away.
	var delegation *verify.VerifiedDelegation
	if opts.DelegationDir != "" {
		found, reason := findDelegation(opts.DelegationDir, bundle, expected, opts.AsOf)
		if reason != "" {
			warn("⚠ OFFLINE APPROVAL: " + reason)
		}
		delegation = found
	}

	challenge, err := CreateOfflineChallenge(OfflineChallengeInput{
		Bundle:        bundle,
		Target:        expected.Target,
		ActionType:    expected.ActionType,
		Display:       expected.Display,
		Params:        params,
		Requester:     verify.RequesterIdentity{DID: opts.RequesterDID},
		WindowMinutes: opts.WindowMinutes,
		AsOf:          opts.AsOf,
		Delegation:    delegation,
	})
	if err != nil {
		return nil, err
	}

	raw, err := opts.CollectSignatures(ctx, challenge)
	if err != nil {
		return nil, fmt.Errorf("collecting signatures failed: %w", err)
	}
	if err := CheckTrustBundleFreshness(bundle, opts.AsOf); err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("no signatures were collected — the action is not approved")
	}
	var witnesses []verify.ApprovalWitness
	var rejected []string
	for _, envelope := range raw {
		w, err := DecodeSignatureEnvelope(envelope)
		if err != nil {
			rejected = append(rejected, err.Error())
			continue
		}
		witnesses = append(witnesses, w)
	}
	if len(witnesses) == 0 {
		return nil, fmt.Errorf("no usable signatures (%s)", strings.Join(rejected, "; "))
	}

	receipt := AssembleOfflineReceipt(challenge, witnesses)
	// DIV §5 step 3d. The signed requirement is the signers' own statement, so it is held to the
	// bundle's ORDINARY rule, re-resolved here rather than read back from the challenge. Under a
	// delegation that is still the right floor: CreateOfflineChallenge refused a delegated quorum
	// below the ordinary one, and the rest of the requirement is copied from the rule.
	ordinary, ok := RequirementFor(bundle, expected.ActionType, expected.Display)
	if !ok {
		return nil, errors.New("no unambiguous approval rule applies to this action")
	}
	floor := requirementFloorOf(ordinary.Requirement)
	result := verify.VerifyApprovalReceipt(receipt, verify.Expected{
		Target:     expected.Target,
		ActionType: expected.ActionType,
		Params:     params,
		Nonce:      challenge.Nonce,
		// Restricted to the approvers eligible for THIS action. The one place offline signing keys
		// count: this receipt is a div-offline-intent.
		Approvers:   ApproverAnchor(bundle, challenge.ApproverDids, BundleAnchorOfflineIntent),
		Requirement: &floor,
	}, verify.VerifyOptions{AllowOffline: true, Delegation: delegation, AsOf: opts.AsOf})
	if !result.OK {
		if len(rejected) > 0 {
			return nil, fmt.Errorf("%s (also discarded: %s)", result.Reason, strings.Join(rejected, "; "))
		}
		return nil, errors.New(result.Reason)
	}

	store := opts.Store
	if store == nil {
		fileStore, err := NewFileRedemptionStore(filepath.Join(opts.BundleDir, ".redeemed"))
		if err != nil {
			return nil, fmt.Errorf("cannot open the redemption store: %w", err)
		}
		store = fileStore
	}
	// Buffer BEFORE redeeming: a crash between the two must leave a pending record behind. A spurious
	// record reconciles harmlessly; the opposite order could leave a redeemed, executed approval
	// invisible to reconciliation forever.
	bufferForReconciliation(challenge, receipt, delegation, opts, warn)
	pending := PendingOptions{BundleDir: opts.BundleDir, BufferDir: opts.BufferDir}
	if !store.Redeem(challenge.Nonce) {
		ClearPendingApproval(challenge.Nonce, pending)
		return nil, fmt.Errorf("nonce %s has already been redeemed here", challenge.Nonce)
	}
	viaDelegation := ""
	if delegation != nil {
		viaDelegation = delegation.Nonce
		warn(fmt.Sprintf(`⚠ OFFLINE APPROVAL USED — "%s" (%s on %s). Approved out of band by %s because Intyga was unreachable, under delegation %s. Nonce %s is buffered for reconciliation; report it when connectivity returns.`,
			expected.Display, expected.ActionType, expected.Target, strings.Join(result.Signers, ", "), delegation.Nonce, challenge.Nonce))
	} else {
		warn(fmt.Sprintf(`⚠ OFFLINE APPROVAL USED — "%s" (%s on %s). Approved out of band by %s because Intyga was unreachable. Nonce %s is buffered for reconciliation; report it when connectivity returns.`,
			expected.Display, expected.ActionType, expected.Target, strings.Join(result.Signers, ", "), challenge.Nonce))
	}
	return &OfflineApprovalResult{
		Receipt:       receipt,
		Nonce:         challenge.Nonce,
		Signers:       result.Signers,
		ViaDelegation: viaDelegation,
	}, nil
}

// findDelegation finds and verifies a delegation covering this exact action, trying each `*.json`
// file in dir in name order (jsonFilesIn). A file that fails to verify is REPORTED, not silently skipped: a
// delegation the operator believes they hold but which does not apply is exactly what they need to
// be told during an incident.
func findDelegation(dir string, bundle *TrustBundle, expected OfflineAction, asOf time.Time) (*verify.VerifiedDelegation, string) {
	resolved, ok := RequirementFor(bundle, expected.ActionType, expected.Display)
	if !ok {
		return nil, "no unambiguous ordinary approval rule applies to this delegation — export a fresh trust bundle"
	}
	names, err := jsonFilesIn(dir)
	if err != nil {
		return nil, ""
	}
	var rejected []string
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		var receipt verify.ApprovalReceipt
		if err != nil || json.Unmarshal(data, &receipt) != nil {
			rejected = append(rejected, name+": unreadable")
			continue
		}
		floor := requirementFloorOf(resolved.Requirement)
		res, d := verify.VerifyDelegation(receipt, verify.Expected{
			Target:     expected.Target,
			ActionType: expected.ActionType,
			Params:     expected.Params,
			// The ORDINARY approver set — not the delegates. Ordinary keys only: an offline signing
			// key must never seal a delegation.
			Approvers: ApproverAnchor(bundle, resolved.ApproverDids, BundleAnchorOrdinary),
			// DIV §5 step 3d / §5a.5: the sealing requirement may not be weaker than the ordinary
			// rule. The AAGUID comparison below stays, because the floor does not cover allowedAaguids.
			Requirement: &floor,
		}, verify.VerifyOptions{AsOf: asOf})
		if !res.OK || d == nil {
			rejected = append(rejected, name+": "+res.Reason)
			continue
		}
		// The verification above binds this requirement to the seal's signatures. An eligible person
		// must not seal a 3-of-N delegation with a 1-of-N ceremony, nor omit an ordinary four-eyes or
		// hardware restriction (DIV §5a.5).
		var payload struct {
			Requirement verify.ApprovalRequirement `json:"requirement"`
		}
		if err := json.Unmarshal([]byte(receipt.CanonicalPayload), &payload); err != nil {
			rejected = append(rejected, name+": unreadable")
			continue
		}
		sealed, rule := payload.Requirement, resolved.Requirement
		weakerAaguids := false
		if len(rule.AllowedAaguids) > 0 {
			weakerAaguids = len(sealed.AllowedAaguids) == 0 || !subset(sealed.AllowedAaguids, rule.AllowedAaguids)
		}
		if sealed.RequiredApprovals < rule.RequiredApprovals ||
			(rule.RequireHardwareKey && !sealed.RequireHardwareKey) ||
			(rule.RequesterCannotApprove && !sealed.RequesterCannotApprove) ||
			weakerAaguids {
			rejected = append(rejected, name+": delegation sealing requirement is weaker than the ordinary approval rule")
			continue
		}
		return d, ""
	}
	if len(rejected) > 0 {
		return nil, fmt.Sprintf("no delegation applies (%s)", strings.Join(rejected, "; "))
	}
	return nil, ""
}

// requirementFloorOf is the DIV §5 step 3d floor a bundle rule imposes on a signed requirement.
func requirementFloorOf(rule verify.ApprovalRequirement) verify.RequirementFloor {
	return verify.RequirementFloor{
		RequiredApprovals:      rule.RequiredApprovals,
		RequesterCannotApprove: rule.RequesterCannotApprove,
		RequireHardwareKey:     rule.RequireHardwareKey,
	}
}

// PendingApproval is a buffered offline approval awaiting reconciliation, stored as
// `<bufferDir>/<nonce>.json`.
type PendingApproval struct {
	Nonce      string `json:"nonce"`
	Target     string `json:"target"`
	ActionType string `json:"actionType"`
	Display    string `json:"display"`
	UsedAt     string `json:"usedAt"`
	// Receipt is the full receipt, so the gateway can re-verify the approval rather than take the
	// reporter's word for it.
	Receipt verify.ApprovalReceipt `json:"receipt"`
	// DelegationNonce is set when a delegation supplied the approver set.
	DelegationNonce string `json:"delegationNonce,omitempty"`
}

// PendingOptions locates the reconciliation buffer.
type PendingOptions struct {
	BundleDir string
	// BufferDir overrides the default <BundleDir>/.pending.
	BufferDir string
}

func (o PendingOptions) dir() string {
	if o.BufferDir != "" {
		return o.BufferDir
	}
	return filepath.Join(o.BundleDir, ".pending")
}

// bufferForReconciliation records the approval so it can be reported when the gateway is reachable
// again. Best-effort by design — a buffering failure must never block the emergency action — and
// warned about loudly instead, because an unrecorded approval is exactly what reconciliation exists
// to surface.
func bufferForReconciliation(challenge *OfflineChallenge, receipt verify.ApprovalReceipt, delegation *verify.VerifiedDelegation, opts OfflineApprovalOptions, warn func(string)) {
	record := PendingApproval{
		Nonce:      challenge.Nonce,
		Target:     challenge.Target,
		ActionType: challenge.ActionType,
		Display:    challenge.Display,
		UsedAt:     isoMillis(time.Now()),
		Receipt:    receipt,
	}
	if delegation != nil {
		record.DelegationNonce = delegation.Nonce
	}
	err := func() error {
		if !isPathSafeNonce(challenge.Nonce) {
			return errors.New("nonce is not a safe path segment")
		}
		var buf strings.Builder
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(record); err != nil {
			return err
		}
		dir := PendingOptions{BundleDir: opts.BundleDir, BufferDir: opts.BufferDir}.dir()
		return writePrivateFile(filepath.Join(dir, challenge.Nonce+".json"), []byte(buf.String()))
	}()
	if err != nil {
		warn(fmt.Sprintf("⚠ OFFLINE APPROVAL: could not buffer %s for reconciliation (%v). Report this manually — an unreported approval is indistinguishable from an unauthorized one.", challenge.Nonce, err))
	}
}

// PendingApprovals reads the offline approvals buffered by UseOfflineApproval but not yet reported, in
// file-name order. A missing buffer means none. A record that cannot be read is not dropped silently:
// the readable records are returned together with an error naming each unreadable one.
func PendingApprovals(opts PendingOptions) ([]PendingApproval, error) {
	records, problems := readPending(opts.dir())
	if len(problems) > 0 {
		return records, errors.New(strings.Join(problems, "; "))
	}
	return records, nil
}

// readPending reads every record on its own, in file-name order: one unreadable file must not hide the
// others. A record is unreadable when it cannot be read or parsed, is not a JSON object, or names no
// nonce. Each unreadable file is returned as a problem naming it.
func readPending(dir string) ([]PendingApproval, []string) {
	names, err := jsonFilesIn(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, []string{fmt.Sprintf("cannot read the reconciliation buffer %s: %v", dir, err)}
	}
	var records []PendingApproval
	var problems []string
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(dir, name))
		var record *PendingApproval
		if err == nil {
			err = json.Unmarshal(data, &record)
		}
		if err != nil || record == nil || record.Nonce == "" {
			problems = append(problems, name+": unreadable pending record — report it by hand")
			continue
		}
		records = append(records, *record)
	}
	return records, problems
}

// jsonFilesIn lists the `*.json` file names in dir in the reference's order: sorted by UTF-16 code
// units, as JavaScript's Array.prototype.sort does, so every SDK tries delegation files in the same
// order. (os.ReadDir sorts by bytes, which differs for characters outside the Basic Multilingual Plane.)
func jsonFilesIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			names = append(names, entry.Name())
		}
	}
	sort.SliceStable(names, func(i, j int) bool { return utf16Less(names[i], names[j]) })
	return names, nil
}

// utf16Less orders strings by UTF-16 code units, as JavaScript's default sort does.
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// ClearPendingApproval removes a buffered approval once the gateway has acknowledged it.
//
// Call it only on a definite acknowledgement: dropping the record on a network error would turn a
// retryable report into a permanently unreported approval. A nonce that is not a safe path segment
// is ignored — it may have been echoed back by a gateway, and must never name a path outside the
// buffer.
func ClearPendingApproval(nonce string, opts PendingOptions) {
	if !isPathSafeNonce(nonce) {
		return
	}
	_ = os.Remove(filepath.Join(opts.dir(), nonce+".json"))
}

// jsString serializes s exactly as JSON.stringify does (verify.StableStringify's string form). A Go
// string that is not valid UTF-8 has its bad bytes replaced by U+FFFD first, as a JavaScript string
// round-tripped through UTF-8 would.
func jsString(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "\uFFFD")
	}
	out, err := verify.StableStringify(s)
	if err != nil {
		b, _ := json.Marshal(s)
		return string(b)
	}
	return out
}
