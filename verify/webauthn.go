package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ─── Minimal CBOR reader (COSE_Key only) ─────────────────────────────────────
// Just enough CBOR to walk a COSE_Key map: ints, byte/text strings, arrays, maps. Deliberately NOT a
// general decoder — anything outside that subset is rejected rather than guessed. Mirrors the reader in
// @intyga/verify so all languages parse identical bytes.

type cborValue interface{}

type cborReader struct {
	buf []byte
	pos int
}

func (r *cborReader) require(n int) error {
	if r.pos+n > len(r.buf) {
		return errors.New("truncated CBOR item")
	}
	return nil
}

// readHead returns the CBOR major type and its argument value.
func (r *cborReader) readHead() (major int, value uint64, err error) {
	if err = r.require(1); err != nil {
		return
	}
	initial := r.buf[r.pos]
	r.pos++
	major = int(initial >> 5)
	info := initial & 0x1f
	switch {
	case info < 24:
		value = uint64(info)
	case info == 24:
		if err = r.require(1); err != nil {
			return
		}
		value = uint64(r.buf[r.pos])
		r.pos++
	case info == 25:
		if err = r.require(2); err != nil {
			return
		}
		value = uint64(r.buf[r.pos])<<8 | uint64(r.buf[r.pos+1])
		r.pos += 2
	case info == 26:
		if err = r.require(4); err != nil {
			return
		}
		value = uint64(r.buf[r.pos])<<24 | uint64(r.buf[r.pos+1])<<16 | uint64(r.buf[r.pos+2])<<8 | uint64(r.buf[r.pos+3])
		r.pos += 4
	default:
		// 27 = 64-bit, 28-30 reserved, 31 = indefinite. No COSE_Key needs any of them.
		err = errors.New("unsupported CBOR length encoding")
	}
	return
}

// decodeItem decodes a single CBOR item (recursively for arrays/maps).
func (r *cborReader) decodeItem() (cborValue, error) {
	major, value, err := r.readHead()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0: // unsigned int
		return int64(value), nil
	case 1: // negative int — COSE labels like -1 (crv), -2 (x), -3 (y)
		return -1 - int64(value), nil
	case 2: // byte string
		if err := r.require(int(value)); err != nil {
			return nil, err
		}
		b := make([]byte, value)
		copy(b, r.buf[r.pos:r.pos+int(value)])
		r.pos += int(value)
		return b, nil
	case 3: // text string
		if err := r.require(int(value)); err != nil {
			return nil, err
		}
		s := string(r.buf[r.pos : r.pos+int(value)])
		r.pos += int(value)
		return s, nil
	case 4: // array
		items := make([]cborValue, 0, value)
		for i := uint64(0); i < value; i++ {
			item, err := r.decodeItem()
			if err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		return items, nil
	case 5: // map
		m := map[int64]cborValue{}
		for i := uint64(0); i < value; i++ {
			key, err := r.decodeItem()
			if err != nil {
				return nil, err
			}
			val, err := r.decodeItem()
			if err != nil {
				return nil, err
			}
			// COSE_Key labels are all integers; non-integer keys are not part of the subset we accept.
			ik, ok := key.(int64)
			if !ok {
				return nil, errors.New("expected integer COSE label")
			}
			m[ik] = val
		}
		return m, nil
	default:
		return nil, fmt.Errorf("unsupported CBOR major type %d", major)
	}
}

// parseCoseP256Key extracts the P-256 public key from a WebAuthn COSE_Key. It pins kty EC2 (2),
// crv P-256 (1) and, if present, alg ES256 (-7), so a key for another curve can never be
// reinterpreted as P-256. Trailing bytes after the leading map are tolerated.
func parseCoseP256Key(coseBuf []byte) (*ecdsa.PublicKey, error) {
	r := &cborReader{buf: coseBuf}
	item, err := r.decodeItem()
	if err != nil {
		return nil, fmt.Errorf("invalid COSE public key format: %w", err)
	}
	m, ok := item.(map[int64]cborValue)
	if !ok {
		return nil, errors.New("invalid COSE public key format: expected a CBOR map")
	}
	if kty, _ := m[1].(int64); kty != 2 {
		return nil, errors.New("invalid COSE public key format: expected kty EC2 (2)")
	}
	if crv, _ := m[-1].(int64); crv != 1 {
		return nil, errors.New("invalid COSE public key format: expected crv P-256 (1)")
	}
	if alg, present := m[3]; present {
		if a, _ := alg.(int64); a != -7 {
			return nil, errors.New("invalid COSE public key format: expected alg ES256 (-7)")
		}
	}
	coord := func(label int64, name string) (*big.Int, error) {
		raw, ok := m[label].([]byte)
		if !ok {
			return nil, fmt.Errorf("invalid COSE public key format: missing %s coordinate", name)
		}
		if len(raw) != 32 {
			return nil, fmt.Errorf("invalid COSE public key format: %s coordinate must be 32 bytes, got %d", name, len(raw))
		}
		return new(big.Int).SetBytes(raw), nil
	}
	x, err := coord(-2, "x")
	if err != nil {
		return nil, err
	}
	y, err := coord(-3, "y")
	if err != nil {
		return nil, err
	}
	curve := elliptic.P256()
	if !curve.IsOnCurve(x, y) {
		return nil, errors.New("invalid COSE public key format: point is not on the P-256 curve")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// base64urlNoPad encodes bytes as base64url without padding (WebAuthn challenge encoding).
func base64urlNoPad(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeBase64Flexible accepts both base64url — the DIV §4.4.2 wire form, which browsers and the
// gateway emit unpadded — and standard base64 (legacy receipts, older vectors), padded or not. The
// alphabets differ only in characters 62/63 (+/ vs -_), so normalizing is lossless and cannot make
// an invalid encoding valid.
func decodeBase64Flexible(s string) ([]byte, error) {
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return base64.StdEncoding.DecodeString(s)
}

// verifyWebAuthnWitness pins the assertion to the expected origin and RP ID, confirms user
// presence/verification, checks the challenge equals base64url(canonicalPayload), and verifies the
// ES256 signature over authenticatorData ‖ SHA-256(clientDataJSON).
//
// verifyWebAuthnWitness verifies one WEBAUTHN witness against an already-TRUSTED key. The key comes
// from the caller's trust anchor — never from the receipt. Returns "" on success.
func verifyWebAuthnWitness(w ApprovalWitness, trustedKey string, receipt ApprovalReceipt, opts VerifyOptions) string {
	if w.AuthenticatorData == nil || w.ClientDataJSON == nil || *w.AuthenticatorData == "" || *w.ClientDataJSON == "" {
		return "WebAuthn witness missing authenticatorData or clientDataJSON"
	}
	// FAIL CLOSED: without an expected origin and RP ID there is nothing to pin the assertion to.
	if opts.ExpectedOrigin == "" || opts.ExpectedRpID == "" {
		return "WebAuthn receipts require ExpectedOrigin and ExpectedRpID — without them an assertion from any relying party would verify"
	}

	return verifyWebAuthnAssertion(*w.ClientDataJSON, *w.AuthenticatorData, w.Signature, receipt.CanonicalPayload,
		[]string{opts.ExpectedOrigin}, opts.ExpectedRpID,
		opts.RequireUserVerification == nil || *opts.RequireUserVerification, opts.AllowCrossOrigin,
		func() (*ecdsa.PublicKey, error) {
			coseBuf, err := decodeBase64Flexible(trustedKey)
			if err != nil {
				return nil, errors.New("invalid trusted key base64")
			}
			return parseCoseP256Key(coseBuf)
		})
}

// verifyWebAuthnAssertion is the §4.4.5 assertion check shared by the receipt verifiers and
// VerifyWebAuthnWitness, as the reference shares its verifyWebAuthnAssertion. Returns "" on success
// and never panics: anything unexpected is a "WebAuthn verification failed: " refusal.
func verifyWebAuthnAssertion(clientDataJSON, authenticatorData, signature, signedPayload string,
	expectedOrigins []string, expectedRpID string, requireUV, allowCrossOrigin bool,
	keyOf func() (*ecdsa.PublicKey, error)) (reason string) {
	defer func() {
		if r := recover(); r != nil {
			reason = webAuthnFailed + fmt.Sprint(r)
		}
	}()
	clientDataBuf, err := decodeBase64Flexible(clientDataJSON)
	if err != nil {
		return webAuthnFailed + "invalid clientDataJSON base64"
	}
	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
		// CrossOrigin is the only signal that separates "approved on our page" from "approved
		// inside someone else's page": an embedded RP frame reports the RP's OWN origin and its
		// rpIdHash matches too (W3C WebAuthn L3 §7.2 step 9).
		CrossOrigin bool `json:"crossOrigin"`
		// TopOrigin (WebAuthn L3) names the top-level page when the ceremony ran in a frame.
		TopOrigin *string `json:"topOrigin"`
	}
	if err := json.Unmarshal(clientDataBuf, &clientData); err != nil {
		return webAuthnFailed + "clientDataJSON is not valid JSON"
	}

	// An assertion, not a registration: webauthn.create signs a different ceremony over the same
	// challenge bytes and must never be accepted as approval.
	if clientData.Type != "webauthn.get" {
		return "clientDataJSON is not a webauthn.get assertion"
	}
	if !containsDID(expectedOrigins, clientData.Origin) {
		return "assertion origin does not match ExpectedOrigin"
	}
	if clientData.CrossOrigin && !allowCrossOrigin {
		return "assertion was produced in a cross-origin frame (crossOrigin=true)"
	}
	// A topOrigin that differs from origin is the same embedding reported another way, refused
	// exactly like crossOrigin=true (DIV §4.4.5 rule 5) — the gateway refuses it at ingest.
	if clientData.TopOrigin != nil && *clientData.TopOrigin != clientData.Origin && !allowCrossOrigin {
		return "assertion was produced in a frame embedded by another origin (topOrigin differs from origin)"
	}
	expectedChallenge := base64urlNoPad([]byte(signedPayload))
	if stripBase64Padding(clientData.Challenge) != expectedChallenge {
		return "clientDataJSON challenge does not match canonical payload"
	}

	authData, err := decodeBase64Flexible(authenticatorData)
	if err != nil {
		return webAuthnFailed + "invalid authenticatorData base64"
	}
	if len(authData) < 37 {
		return "authenticatorData is too short"
	}
	rpIdHash := sha256.Sum256([]byte(expectedRpID))
	if subtle.ConstantTimeCompare(authData[:32], rpIdHash[:]) != 1 {
		return "authenticatorData rpIdHash does not match ExpectedRpID"
	}
	flags := authData[32]
	if flags&authDataFlagUP == 0 {
		return "authenticatorData user-present flag is not set"
	}
	if requireUV && flags&authDataFlagUV == 0 {
		return "authenticatorData user-verified flag is not set"
	}

	// The key is the TRUSTED key, never the receipt's copy.
	pub, err := keyOf()
	if err != nil {
		return webAuthnFailed + err.Error()
	}
	sigBytes, err := decodeBase64Flexible(signature)
	if err != nil {
		return webAuthnFailed + "invalid signature base64"
	}

	clientDataHash := sha256.Sum256(clientDataBuf)
	signedData := append(append([]byte{}, authData...), clientDataHash[:]...)
	// A WebAuthn ES256 assertion signature is ASN.1 DER (WebAuthn §6.5.6), and DER only, as in the
	// reference: a raw r‖s encoding is refused like any other signature that does not verify.
	digest := sha256.Sum256(signedData)
	if !ecdsa.VerifyASN1(pub, digest[:], sigBytes) {
		return "WebAuthn signature does not verify against the trusted signer key"
	}
	return ""
}

// webAuthnFailed prefixes a failure the reference reports from its catch-all, whose detail is the
// platform library's own message ("WebAuthn verification failed: <message>").
const webAuthnFailed = "WebAuthn verification failed: "

// stripBase64Padding removes trailing '=' so a padded challenge compares equal to the unpadded form.
func stripBase64Padding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}

// WebAuthnWitness is one WebAuthn assertion and the exact payload it claims to sign — a single
// stored witness row, outside any receipt.
type WebAuthnWitness struct {
	// SignedPayload is the string whose UTF-8 bytes were the assertion challenge, as signed.
	SignedPayload string `json:"signedPayload"`
	// PublicKey is the credential's P-256 key, base64 or base64url: a COSE_Key (as recorded at
	// registration) or DER SubjectPublicKeyInfo. Supply it from YOUR record of the credential —
	// never from the thing being verified.
	PublicKey string `json:"publicKey"`
	// AuthenticatorData and ClientDataJSON are base64 or base64url, as the browser returned them.
	AuthenticatorData string `json:"authenticatorData"`
	ClientDataJSON    string `json:"clientDataJSON"`
	// Signature is the DER ECDSA assertion signature.
	Signature string `json:"signature"`
}

// WebAuthnWitnessExpectation pins what VerifyWebAuthnWitness accepts.
type WebAuthnWitnessExpectation struct {
	// ExpectedOrigin lists the origin(s) the assertion may carry, e.g. "https://app.example.com".
	// Required: at least one, none empty.
	ExpectedOrigin []string
	// ExpectedRpID is the RP ID the authenticatorData must hash to. Required.
	ExpectedRpID string
	// RequireUserVerification demands the User-Verified flag; nil means true. User-Present is
	// always required.
	RequireUserVerification *bool
	// AllowCrossOrigin accepts clientDataJSON.crossOrigin=true or a differing topOrigin. Defaults to
	// false (DIV §4.4.5 rule 5).
	AllowCrossOrigin bool
}

// VerifyWebAuthnWitness verifies ONE WebAuthn assertion on its own — the §4.4.5 checks every
// receipt verifier here applies to each WEBAUTHN witness, without a receipt around it: one approver
// of a quorum, a console step-up, a row read back out of an audit ledger. Same implementation as
// the receipt path, not a copy. It mirrors verifyWebAuthnWitness in @intyga/verify.
//
// It answers only "did the holder of THIS key sign THIS payload, at THIS relying party, with the
// user present". It knows nothing of quorum, validity windows, payload type, the signed requirement
// or who the key belongs to: verify an approval with VerifyApprovalReceipt (or the delegation,
// agent-authority and platform verifiers), which also enforce those. It fails closed on missing
// expectations or fields and never panics.
func VerifyWebAuthnWitness(witness WebAuthnWitness, expectation WebAuthnWitnessExpectation) VerifyResult {
	if len(expectation.ExpectedOrigin) == 0 || containsDID(expectation.ExpectedOrigin, "") || expectation.ExpectedRpID == "" {
		return VerifyResult{Reason: "a WebAuthn witness requires ExpectedOrigin and ExpectedRpID — without them an assertion from any relying party would verify"}
	}
	for _, field := range []struct{ name, value string }{
		{"signedPayload", witness.SignedPayload},
		{"publicKey", witness.PublicKey},
		{"authenticatorData", witness.AuthenticatorData},
		{"clientDataJSON", witness.ClientDataJSON},
		{"signature", witness.Signature},
	} {
		if field.value == "" {
			return VerifyResult{Reason: "WebAuthn witness missing " + field.name}
		}
	}
	reason := verifyWebAuthnAssertion(witness.ClientDataJSON, witness.AuthenticatorData, witness.Signature,
		witness.SignedPayload, expectation.ExpectedOrigin, expectation.ExpectedRpID,
		expectation.RequireUserVerification == nil || *expectation.RequireUserVerification,
		expectation.AllowCrossOrigin, func() (*ecdsa.PublicKey, error) { return webAuthnPublicKey(witness.PublicKey) })
	if reason != "" {
		return VerifyResult{Reason: reason}
	}
	return VerifyResult{OK: true}
}

// webAuthnPublicKey reads a caller-supplied P-256 credential key: DER SPKI (a SEQUENCE, 0x30) or a
// COSE_Key (a CBOR map), as the reference does.
func webAuthnPublicKey(encoded string) (*ecdsa.PublicKey, error) {
	der, err := decodeBase64Flexible(encoded)
	if err != nil {
		return nil, errors.New("invalid public key base64")
	}
	if len(der) == 0 || der[0] != 0x30 {
		return parseCoseP256Key(der)
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errors.New("failed to parse SPKI public key")
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok || ecdsaPub.Curve != elliptic.P256() {
		return nil, errors.New("public key is not a P-256 key")
	}
	return ecdsaPub, nil
}
