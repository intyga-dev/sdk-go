package intyga

// The customer-authored trust-anchor file — the DID-mode counterpart of a key list. Ported from
// packages/sdk/src/trust-anchor.ts.
//
// This file IS the relying party's pinning (DIV §4.4.6, identity-associating anchor): it names the
// approver identities that may sign and, for each stable DID, the public keys that speak for it. It
// is exported from the console (or written by hand) and carried in the relying party's own
// configuration, so — unlike the offline trust bundle, which travels through the gateway at incident
// time and is therefore gateway-SIGNED — it carries no signature: adopting the file into your
// configuration is itself the act of trust, like pinning a CA bundle.
//
// Self-certifying entries (did:intyga:key:…) may list no keys in an online anchor: the DID itself
// commits to the enrolled key, and the verifier checks the receipt-carried key against it.

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"strings"

	verify "github.com/intyga-dev/sdk-go/verify"
)

// TrustAnchorFileType is the `type` of a trust-anchor file.
const TrustAnchorFileType = "intyga-trust-anchor"

// TrustAnchorPurpose says what an anchor is FOR, and so which keys it may pin.
//
// Two files, never one: a bare offline key — no origin binding, no user verification — must not
// satisfy a relying party that verifies online approvals.
type TrustAnchorPurpose string

const (
	// TrustAnchorOnline pins passkeys and node keys and verifies ordinary approval receipts. A file
	// with no `purpose` predates the field and is read as online.
	TrustAnchorOnline TrustAnchorPurpose = "online"
	// TrustAnchorOffline pins offline signing keys only and verifies DIV §5a offline approvals.
	TrustAnchorOffline TrustAnchorPurpose = "offline"
)

// TrustAnchorWebAuthn carries the WebAuthn expectations of the approval console the approvers sign
// in. Passkey receipts cannot verify without them (the verifier fails closed).
type TrustAnchorWebAuthn struct {
	Origin string `json:"origin"`
	RpID   string `json:"rpId"`
}

// TrustAnchorFile is a parsed, validated trust-anchor file.
type TrustAnchorFile struct {
	Type string `json:"type"`
	V    int    `json:"v"`
	// Purpose is always set after parsing; absent in the file means online.
	Purpose TrustAnchorPurpose `json:"purpose"`
	// Epoch is a monotonic export counter. It carries no cryptographic weight.
	Epoch int64 `json:"epoch"`
	// Label is what the export was scoped to. Display only.
	Label string `json:"label,omitempty"`
	// Approvers are the identities this relying party trusts, each with every public key bound to
	// them at export time.
	Approvers  []BundleApprover     `json:"approvers"`
	WebAuthn   *TrustAnchorWebAuthn `json:"webauthn,omitempty"`
	ExportedAt string               `json:"exportedAt,omitempty"`
}

var (
	trustAnchorKeyPattern = regexp.MustCompile(`^[A-Za-z0-9+/_-]+={0,2}$`)
	httpOriginPattern     = regexp.MustCompile(`^https?://`)
)

// ParseTrustAnchorFile parses and validates a trust-anchor file, and returns an error naming the one
// problem found — a trust anchor is security configuration, so a malformed one must fail at load time
// rather than surface later as an unverifiable receipt.
//
// purpose is what the CALLER is about to verify, and the file must say the same: an offline anchor
// handed to an online verifier (or the reverse) is refused. The empty purpose means online, so a
// caller that does not think about it can never pin offline keys by accident.
func ParseTrustAnchorFile(jsonText string, purpose TrustAnchorPurpose) (*TrustAnchorFile, error) {
	expected := purpose
	if expected == "" {
		expected = TrustAnchorOnline
	}
	fail := func(format string, args ...interface{}) (*TrustAnchorFile, error) {
		return nil, fmt.Errorf("invalid trust-anchor file: "+format, args...)
	}
	if !json.Valid([]byte(jsonText)) {
		var probe json.RawMessage
		return fail("not valid JSON (%v)", json.Unmarshal([]byte(jsonText), &probe))
	}
	var obj map[string]interface{}
	if err := json.Unmarshal([]byte(jsonText), &obj); err != nil || obj == nil {
		return fail("root must be an object")
	}
	if obj["type"] != TrustAnchorFileType {
		return fail("type must be %q — a div-trust-bundle JWS (offline approval) is a different, gateway-signed artifact and cannot be used here", TrustAnchorFileType)
	}
	if v, ok := obj["v"].(float64); !ok || v != 1 {
		return fail("unsupported version %s (expected 1)", jsonRepr(obj["v"]))
	}
	filePurpose := TrustAnchorOnline
	if rawPurpose, present := obj["purpose"]; present {
		p, _ := rawPurpose.(string)
		if p != string(TrustAnchorOnline) && p != string(TrustAnchorOffline) {
			return fail(`purpose must be "online" or "offline", got %s`, jsonRepr(rawPurpose))
		}
		filePurpose = TrustAnchorPurpose(p)
	}
	if filePurpose != expected {
		return fail("this is an %s anchor, but it is being loaded to verify %s approvals — export the %s anchor instead", filePurpose, expected, expected)
	}
	epoch, ok := obj["epoch"].(float64)
	if !ok || epoch != math.Trunc(epoch) || epoch < 0 || epoch > maxSafeInteger {
		return fail("epoch must be a non-negative integer")
	}
	label, ok := obj["label"].(string)
	if _, present := obj["label"]; present && !ok {
		return fail("label must be a string")
	}
	exportedAt, ok := obj["exportedAt"].(string)
	if _, present := obj["exportedAt"]; present && !ok {
		return fail("exportedAt must be a string")
	}

	entries, ok := obj["approvers"].([]interface{})
	if !ok || len(entries) == 0 {
		return fail("approvers must be a non-empty array — an empty anchor would trust nobody")
	}
	seen := map[string]bool{}
	approvers := make([]BundleApprover, 0, len(entries))
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok {
			return fail("every approvers[] entry must be an object")
		}
		did, ok := entry["did"].(string)
		if !ok || !strings.HasPrefix(did, "did:") {
			return fail(`approver did %s must be a string starting with "did:"`, jsonRepr(entry["did"]))
		}
		if seen[did] {
			return fail("duplicate approver did %s", did)
		}
		seen[did] = true
		rawKeys, ok := entry["publicKeys"].([]interface{})
		if !ok {
			return fail("approver %s: publicKeys must be an array", did)
		}
		keys := make([]string, 0, len(rawKeys))
		for _, rk := range rawKeys {
			k, ok := rk.(string)
			if !ok || !isBase64Key(k) {
				return fail("approver %s: every publicKeys[] entry must be a base64 SPKI or COSE key", did)
			}
			keys = append(keys, k)
		}
		// A stable DID with no keys can never satisfy verification. Self-certifying DIDs are the
		// deliberate exception online; an offline anchor has none, because a DID commits to its
		// ONLINE key, not to an offline signing key its owner chose to register.
		if len(keys) == 0 && filePurpose == TrustAnchorOffline {
			return fail("approver %s has no publicKeys — an offline anchor must pin every offline key", did)
		}
		if len(keys) == 0 && !strings.HasPrefix(did, verify.SelfCertifyingDIDPrefix) {
			return fail("approver %s has no publicKeys and is not self-certifying (%s…) — a receipt from them could never verify", did, verify.SelfCertifyingDIDPrefix)
		}
		approver := BundleApprover{DID: did, PublicKeys: keys}
		if offline, ok := nonEmptyStrings(entry["offlinePublicKeys"]); ok && len(offline) > 0 {
			approver.OfflinePublicKeys = offline
		}
		approvers = append(approvers, approver)
	}

	var webauthn *TrustAnchorWebAuthn
	if rawW, present := obj["webauthn"]; present {
		w, ok := rawW.(map[string]interface{})
		if !ok {
			return fail("webauthn must be an object")
		}
		origin, ok := w["origin"].(string)
		if !ok || !httpOriginPattern.MatchString(origin) {
			return fail("webauthn.origin must be an http(s) origin string")
		}
		rpID, ok := w["rpId"].(string)
		if !ok || rpID == "" {
			return fail("webauthn.rpId must be a non-empty string")
		}
		webauthn = &TrustAnchorWebAuthn{Origin: origin, RpID: rpID}
	}

	return &TrustAnchorFile{
		Type:       TrustAnchorFileType,
		V:          1,
		Purpose:    filePurpose,
		Epoch:      int64(epoch),
		Label:      label,
		Approvers:  approvers,
		WebAuthn:   webauthn,
		ExportedAt: exportedAt,
	}, nil
}

// TrustAnchorApprovers builds the verifier's trust anchor from a parsed file: DID mode, one identity
// per approver however many keys they hold. limitToDids narrows the eligible set (nil means every
// approver in the file) without widening anything — a DID not in the file resolves to nothing, and so
// does a keyless self-certifying entry, whose key the verifier takes from the receipt instead.
func TrustAnchorApprovers(file *TrustAnchorFile, limitToDids []string) verify.ApproverTrustAnchor {
	var order []string
	byDID := map[string][]string{}
	if file != nil {
		for _, a := range file.Approvers {
			if limitToDids != nil && !containsString(limitToDids, a.DID) {
				continue
			}
			if _, seen := byDID[a.DID]; !seen {
				order = append(order, a.DID)
			}
			byDID[a.DID] = append([]string(nil), a.PublicKeys...)
		}
	}
	return verify.ApproverTrustAnchor{
		DIDs: order,
		ResolveKeys: func(did string) []string {
			keys := byDID[did]
			if len(keys) == 0 {
				return nil
			}
			return append([]string(nil), keys...)
		},
	}
}

// isBase64Key mirrors the reference: base64 or base64url characters with at most two trailing `=`,
// decoding to at least one byte (two or more significant characters).
func isBase64Key(s string) bool {
	return trustAnchorKeyPattern.MatchString(s) && len(strings.TrimRight(s, "=")) >= 2
}

// jsonRepr renders a JSON value for an error message, as JSON.stringify would.
func jsonRepr(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
