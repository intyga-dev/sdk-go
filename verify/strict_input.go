package verify

import (
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
// Keys compare by decoded bytes (padding and base64/base64url spellings of one encoding match; the
// same key in another encoding, COSE vs SPKI, is not detected). Records the key when it is free.
func sharedKeyProblem(counted map[string]string, key, identity string) string {
	fingerprint := key
	if b, err := decodeBase64Flexible(key); err == nil {
		fingerprint = string(b)
	}
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
