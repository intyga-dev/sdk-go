package verify

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// ─── Minimal CBOR reader (COSE_Key only) ─────────────────────────────────────
// Just enough CBOR to walk a COSE_Key map: ints, byte/text strings, arrays, maps. Deliberately NOT a
// general decoder — anything outside that subset is rejected rather than guessed. Mirrors the reader in
// @sakra-trust/verify so all languages parse identical bytes.

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

// verifyWebAuthn verifies a WEBAUTHN receipt: it pins the assertion to the expected origin and RP ID,
// confirms user presence/verification, checks the challenge equals base64url(canonicalPayload), and
// verifies the ES256 signature over authenticatorData ‖ SHA-256(clientDataJSON).
func verifyWebAuthn(receipt ApprovalReceipt, opts VerifyOptions) VerifyResult {
	if receipt.AuthenticatorData == nil || receipt.ClientDataJSON == nil {
		return VerifyResult{OK: false, Reason: "WebAuthn receipt missing authenticatorData or clientDataJSON"}
	}
	// FAIL CLOSED: without an expected origin and RP ID there is nothing to pin the assertion to.
	if opts.ExpectedOrigin == "" || opts.ExpectedRpID == "" {
		return VerifyResult{OK: false, Reason: "WebAuthn receipts require ExpectedOrigin and ExpectedRpID — without them an assertion from any relying party would verify"}
	}

	clientDataBuf, err := base64.StdEncoding.DecodeString(*receipt.ClientDataJSON)
	if err != nil {
		return VerifyResult{OK: false, Reason: "invalid clientDataJSON base64"}
	}
	var clientData struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
	}
	if err := json.Unmarshal(clientDataBuf, &clientData); err != nil {
		return VerifyResult{OK: false, Reason: "clientDataJSON is not valid JSON"}
	}

	// An assertion, not a registration: webauthn.create signs a different ceremony over the same
	// challenge bytes and must never be accepted as approval.
	if clientData.Type != "webauthn.get" {
		return VerifyResult{OK: false, Reason: "clientDataJSON is not a webauthn.get assertion"}
	}
	if clientData.Origin != opts.ExpectedOrigin {
		return VerifyResult{OK: false, Reason: "assertion origin does not match ExpectedOrigin"}
	}
	expectedChallenge := base64urlNoPad([]byte(receipt.CanonicalPayload))
	if stripBase64Padding(clientData.Challenge) != expectedChallenge {
		return VerifyResult{OK: false, Reason: "clientDataJSON challenge does not match canonical payload"}
	}

	authData, err := base64.StdEncoding.DecodeString(*receipt.AuthenticatorData)
	if err != nil {
		return VerifyResult{OK: false, Reason: "invalid authenticatorData base64"}
	}
	if len(authData) < 37 {
		return VerifyResult{OK: false, Reason: "authenticatorData is too short"}
	}
	rpIdHash := sha256.Sum256([]byte(opts.ExpectedRpID))
	if subtle.ConstantTimeCompare(authData[:32], rpIdHash[:]) != 1 {
		return VerifyResult{OK: false, Reason: "authenticatorData rpIdHash does not match ExpectedRpID"}
	}
	flags := authData[32]
	if flags&authDataFlagUP == 0 {
		return VerifyResult{OK: false, Reason: "authenticatorData user-present flag is not set"}
	}
	requireUV := opts.RequireUserVerification == nil || *opts.RequireUserVerification
	if requireUV && flags&authDataFlagUV == 0 {
		return VerifyResult{OK: false, Reason: "authenticatorData user-verified flag is not set"}
	}

	coseBuf, err := base64.StdEncoding.DecodeString(*receipt.SignerPublicKey)
	if err != nil {
		return VerifyResult{OK: false, Reason: "invalid signerPublicKey base64"}
	}
	pub, err := parseCoseP256Key(coseBuf)
	if err != nil {
		return VerifyResult{OK: false, Reason: err.Error()}
	}
	sigBytes, err := base64.StdEncoding.DecodeString(*receipt.Signature)
	if err != nil {
		return VerifyResult{OK: false, Reason: "invalid signature base64"}
	}

	clientDataHash := sha256.Sum256(clientDataBuf)
	signedData := append(append([]byte{}, authData...), clientDataHash[:]...)
	if !verifyEcdsaSignature(pub, signedData, sigBytes) {
		return VerifyResult{OK: false, Reason: "WebAuthn signature does not verify against signer key"}
	}
	return VerifyResult{OK: true}
}

// stripBase64Padding removes trailing '=' so a padded challenge compares equal to the unpadded form.
func stripBase64Padding(s string) string {
	for len(s) > 0 && s[len(s)-1] == '=' {
		s = s[:len(s)-1]
	}
	return s
}
