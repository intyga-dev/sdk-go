package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"errors"
	"regexp"
	"strconv"
	"time"
	"unicode/utf8"
)

// rfc3339DateTime is RFC 3339 §5.6 `date-time`, strictly: four-digit year, uppercase T and Z,
// seconds present, an optional 1–9 digit fraction and an explicit zone. time.RFC3339 alone also
// accepts a comma fraction, any number of fraction digits and offsets such as +24:00 or +05:60,
// which the other ports refuse — so the verdict on one signed string differed by language.
var rfc3339DateTime = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-]([0-9]{2}):([0-9]{2}))$`)

// parseSignedTime parses a signed DIV timestamp (expiresAt, challengedAt, sealedAt, signedAt) under
// the one grammar every port applies (DIV §6.2): the date must exist, hours 00–23, minutes and
// seconds 00–59 (no leap second), offset hours 00–23 and minutes 00–59. time.Parse checks the
// calendar and clock ranges; the pattern and the offset bounds are checked here first.
func parseSignedTime(s string) (time.Time, error) {
	m := rfc3339DateTime.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, errors.New("not a strict RFC 3339 date-time")
	}
	if m[3] != "" {
		h, _ := strconv.Atoi(m[3])
		mi, _ := strconv.Atoi(m[4])
		if h > 23 || mi > 59 {
			return time.Time{}, errors.New("RFC 3339 offset out of range")
		}
	}
	return time.Parse(time.RFC3339, s)
}

// errInvalidUTF8: a Go string need not be valid UTF-8, and ranging over one silently turns each bad
// byte into U+FFFD, so the canonical bytes would say something the caller never wrote (DIV §4.1).
var errInvalidUTF8 = errors.New("a string is not valid UTF-8 (RFC 8785 / I-JSON require valid Unicode)")

// sharedKeyProblem enforces one key, one person (DIV §4.4.6). An identity-associating anchor that
// maps the SAME key to two DIDs would otherwise let that key's holder count as two approvers, since
// quorum counts distinct identities. A key already counted for one identity cannot count for another.
// P-256 keys compare by public point, so COSE and SPKI encodings of one credential match. Other
// encodings compare by decoded bytes. Records the key when it is free.
func sharedKeyProblem(counted map[string]string, key, identity string) string {
	fingerprint := signingKeyIdentity(key)
	if owner, ok := counted[fingerprint]; ok && owner != identity {
		return "signer " + identity + " verified under a key already counted for " + owner + "; two approver identities sharing one key count once (DIV §4.4.6)"
	}
	counted[fingerprint] = identity
	return ""
}

// canonicalTextProblem refuses signed JSON text that is not I-JSON (RFC 7493 §2.1, which RFC 8785
// builds on): invalid UTF-8, or a \u escape naming an unpaired UTF-16 surrogate. encoding/json
// would otherwise decode either to U+FFFD without complaint, so a payload the other ports refuse
// (or, before the TS fix, accepted as the escape itself) would be read here as different text.
// Returns "" when the text is acceptable.
func canonicalTextProblem(text string) string {
	if !utf8.ValidString(text) {
		return "canonicalPayload is not valid UTF-8"
	}
	hex4 := func(i int) (uint16, bool) {
		if i+6 > len(text) || text[i] != '\\' || text[i+1] != 'u' {
			return 0, false
		}
		v, err := strconv.ParseUint(text[i+2:i+6], 16, 16)
		return uint16(v), err == nil
	}
	for i := 0; i < len(text); i++ {
		if text[i] != '\\' {
			continue
		}
		if i+1 >= len(text) {
			break
		}
		if text[i+1] != 'u' {
			i++ // skip the escaped character, so `\\u` is a backslash followed by a plain `u`
			continue
		}
		cu, ok := hex4(i)
		if !ok {
			i++
			continue
		}
		switch {
		case cu >= 0xD800 && cu <= 0xDBFF:
			low, ok := hex4(i + 6)
			if !ok || low < 0xDC00 || low > 0xDFFF {
				return "canonicalPayload contains an unpaired UTF-16 surrogate escape, which is not I-JSON"
			}
			i += 11
		case cu >= 0xDC00 && cu <= 0xDFFF:
			return "canonicalPayload contains an unpaired UTF-16 surrogate escape, which is not I-JSON"
		default:
			i += 5
		}
	}
	return ""
}

// signingKeyIdentity fingerprints a trusted key for the one-key-one-person rule (DIV §4.4.6). P-256
// keys compare by public point, so COSE and SPKI encodings of one credential match; other encodings
// compare by decoded bytes, and undecodable text by itself (signature verification fails closed).
func signingKeyIdentity(key string) string {
	fingerprint := key
	if b, err := decodeBase64Flexible(key); err == nil {
		fingerprint = string(b)
		var pub *ecdsa.PublicKey
		if len(b) > 0 && b[0] == 0x30 {
			pub, _ = parseSpkiP256(b)
		} else {
			pub, _ = parseCoseP256Key(b)
		}
		if pub != nil && pub.Curve == elliptic.P256() {
			fingerprint = hex.EncodeToString(elliptic.Marshal(elliptic.P256(), pub.X, pub.Y))
		}
	}
	return fingerprint
}

// excludedIdentityDIDs is every identity the signed requirement bars from approving: the signed
// excludedSignerDids plus, under requesterCannotApprove, the requester and its credential issuer.
func excludedIdentityDIDs(requirement ApprovalRequirement, requester RequesterIdentity) []string {
	var out []string
	seen := map[string]bool{}
	add := func(did string) {
		if !seen[did] {
			seen[did] = true
			out = append(out, did)
		}
	}
	if requirement.ExcludedSignerDIDs != nil {
		for _, did := range *requirement.ExcludedSignerDIDs {
			add(did)
		}
	}
	if requirement.RequesterCannotApprove {
		add(requester.DID)
		if requester.CredentialIssuerDID != nil {
			add(*requester.CredentialIssuerDID)
		}
	}
	return out
}

// resolveExcludedAnchorKeys asks a DID-mode anchor for one excluded DID's keys. A panicking resolver
// reports ok=false: the caller refuses the receipt rather than ignoring the identity's keys, since a
// lookup outage would otherwise let an eligible alias sign under an excluded identity's key. A
// resolver that returns no keys is not a failure.
func resolveExcludedAnchorKeys(anchor ApproverTrustAnchor, did string) (keys []string, ok bool) {
	defer func() {
		if recover() != nil {
			keys, ok = nil, false
		}
	}()
	if anchor.ResolveKeys != nil {
		return anchor.ResolveKeys(did), true
	}
	if anchor.ResolveKey != nil {
		if key := anchor.ResolveKey(did); key != "" {
			return []string{key}, true
		}
	}
	return nil, true
}

// seedExcludedSigningKeys pre-counts every key the anchor resolves for an excluded identity, so a
// witness verifying under one of them — even through an eligible alias DID — is refused as a shared
// key (DIV §4.4.6). Eligibility stays anchor.DIDs; the resolver may know keys for excluded identities.
// It returns a refusal reason when the resolver fails for an excluded identity, as in the reference.
func seedExcludedSigningKeys(counted map[string]string, anchor ApproverTrustAnchor, requirement ApprovalRequirement, requester RequesterIdentity) string {
	if len(anchor.PublicKeys) > 0 || len(anchor.DIDs) == 0 || (anchor.ResolveKey == nil && anchor.ResolveKeys == nil) {
		return ""
	}
	for _, did := range excludedIdentityDIDs(requirement, requester) {
		keys, ok := resolveExcludedAnchorKeys(anchor, did)
		if !ok {
			return "could not resolve keys for excluded identity " + did + "; refusing rather than ignoring its keys (DIV §4.4.6)"
		}
		for _, key := range keys {
			if key != "" {
				counted[signingKeyIdentity(key)] = "excluded identity " + did
			}
		}
	}
	return ""
}
