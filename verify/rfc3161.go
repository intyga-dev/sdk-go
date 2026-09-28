package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const rfc3161MaxInput = 1 << 20
const rfc3161MaxEncodedToken = ((rfc3161MaxInput + 2) / 3) * 4

type Rfc3161Trust struct {
	CAPem                   string `json:"caPem"`
	SignerCertificateSHA256 string `json:"signerCertificateSha256"`
	Revocation              string `json:"revocation"`
	CRLPem                  string `json:"crlPem,omitempty"`
	UntrustedPem            string `json:"untrustedPem,omitempty"`
	VerificationTime        *int64 `json:"verificationTime,omitempty"`
	OpenSSLPath             string `json:"opensslPath,omitempty"`
}

type Rfc3161Verification struct {
	OK      bool   `json:"ok"`
	Reason  string `json:"reason,omitempty"`
	GenTime *int64 `json:"genTime,omitempty"`
}

func rfcFailure() Rfc3161Verification {
	return Rfc3161Verification{Reason: "RFC 3161 verification failed"}
}

// VerifyRfc3161Anchor verifies an RFC 3161 CMS token using caller-supplied TSA trust and OpenSSL 3.
// It performs no network access and never consults the host certificate store.
func VerifyRfc3161Anchor(anchor SignedAnchor, trust Rfc3161Trust) (out Rfc3161Verification) {
	out = rfcFailure()
	validAlgorithm := anchor.Algorithm == "ES256" || anchor.Algorithm == "Ed25519" || anchor.Algorithm == "RSA-PSS"
	if anchor.Kind != "RFC3161" || anchor.Evidence == nil || len(*anchor.Evidence) > rfc3161MaxEncodedToken || !IsWellFormedAnchor(anchor.AnchorInput) || !validAlgorithm ||
		len(trust.CAPem) == 0 || len(trust.CAPem) > rfc3161MaxInput || len(trust.CRLPem) > rfc3161MaxInput ||
		len(trust.UntrustedPem) > rfc3161MaxInput || !isHash64(trust.SignerCertificateSHA256) ||
		(trust.Revocation != "unchecked" && trust.Revocation != "crl") || (trust.Revocation == "crl" && strings.TrimSpace(trust.CRLPem) == "") {
		return out
	}
	token, err := base64.StdEncoding.Strict().DecodeString(*anchor.Evidence)
	if err != nil || base64.StdEncoding.EncodeToString(token) != *anchor.Evidence || len(token) == 0 || len(token) > rfc3161MaxInput || !singleDERSequence(token) || !validCMSSignerDigest(token) {
		return out
	}
	now := time.Now().Unix() + 1 // ceil wall-clock seconds so a fresh fractional genTime is not rejected
	if trust.VerificationTime != nil {
		now = *trust.VerificationTime
	}
	if now < 0 || now > 253402300799 {
		return out
	}
	dir, err := os.MkdirTemp("", "intyga-rfc3161-")
	if err != nil {
		return out
	}
	defer os.RemoveAll(dir)
	if os.Chmod(dir, 0700) != nil {
		return out
	}
	empty := filepath.Join(dir, "empty")
	if os.Mkdir(empty, 0700) != nil {
		return out
	}
	write := func(name string, data []byte) (string, error) {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0600); err != nil {
			return "", err
		}
		return p, nil
	}
	tokenPath, err := write("token.der", token)
	if err != nil {
		return out
	}
	d := anchorDigest(anchor.AnchorInput)
	queryPrefix, _ := hex.DecodeString("30360201013031300d060960864801650304020105000420")
	queryPath, err := write("query.tsq", append(queryPrefix, d[:]...))
	if err != nil {
		return out
	}
	trustPath, err := write("trust.pem", []byte(trust.CAPem+"\n"+trust.CRLPem))
	if err != nil {
		return out
	}
	configPath, err := write("openssl.cnf", []byte("# isolated Intyga verification config\n"))
	if err != nil {
		return out
	}
	signerPath := filepath.Join(dir, "signer.pem")
	infoPath := filepath.Join(dir, "info.der")
	openssl := trust.OpenSSLPath
	if openssl == "" {
		openssl = "openssl"
	} else if !filepath.IsAbs(openssl) && strings.ContainsRune(openssl, os.PathSeparator) {
		var absErr error
		openssl, absErr = filepath.Abs(openssl)
		if absErr != nil {
			return out
		}
	}
	env := append(os.Environ(), "OPENSSL_CONF="+configPath, "SSL_CERT_FILE="+filepath.Join(empty, "cert.pem"), "SSL_CERT_DIR="+empty)
	run := func(args ...string) bool {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, openssl, args...)
		cmd.Env = env
		cmd.Dir = dir
		return cmd.Run() == nil && ctx.Err() == nil
	}
	if !run("cms", "-verify", "-binary", "-inform", "DER", "-in", tokenPath, "-noverify", "-signer", signerPath, "-out", infoPath) {
		return out
	}
	signerPEM, err := os.ReadFile(signerPath)
	if err != nil || len(signerPEM) > rfc3161MaxInput {
		return out
	}
	certDER, ok := strictSingleCertificatePEM(signerPEM)
	if !ok {
		return out
	}
	certHash := sha256.Sum256(certDER)
	if hex.EncodeToString(certHash[:]) != trust.SignerCertificateSHA256 {
		return out
	}
	info, err := os.ReadFile(infoPath)
	if err != nil || len(info) > rfc3161MaxInput {
		return out
	}
	gen, fractional, err := parseTSTInfoGenTime(info)
	if err != nil || gen < 0 || gen > now || (fractional && now <= gen) {
		return out
	}
	// `ts -verify` never loads OpenSSL's default trust locations; it trusts only what is passed. No
	// `-CAstore`: OpenSSL 3.0 loads a store URI eagerly and fails on an empty one (3.5 is lazy), which
	// made every valid token fail closed on Ubuntu 24.04's 3.0.13.
	args := []string{"ts", "-verify", "-token_in", "-in", tokenPath, "-queryfile", queryPath, "-CAfile", trustPath, "-CApath", empty}
	if trust.UntrustedPem != "" {
		p, e := write("intermediates.pem", []byte(trust.UntrustedPem))
		if e != nil {
			return out
		}
		args = append(args, "-untrusted", p)
	}
	args = append(args, "-attime", strconv.FormatInt(now, 10), "-auth_level", "2", "-x509_strict")
	if trust.Revocation == "crl" {
		args = append(args, "-crl_check_all")
	}
	if !run(args...) {
		return out
	}
	issuanceArgs := append([]string{}, args...)
	// Rebuild to omit current-time CRL enforcement at historical issuance time.
	issuanceArgs = []string{"ts", "-verify", "-token_in", "-in", tokenPath, "-queryfile", queryPath, "-CAfile", trustPath, "-CApath", empty}
	if trust.UntrustedPem != "" {
		issuanceArgs = append(issuanceArgs, "-untrusted", filepath.Join(dir, "intermediates.pem"))
	}
	issuanceArgs = append(issuanceArgs, "-attime", strconv.FormatInt(gen, 10), "-auth_level", "2", "-x509_strict")
	if !run(issuanceArgs...) {
		return out
	}
	return Rfc3161Verification{OK: true, GenTime: &gen}
}

func strictSingleCertificatePEM(p []byte) ([]byte, bool) {
	s := strings.TrimSpace(string(p))
	const begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	if strings.Count(s, begin) != 1 || strings.Count(s, end) != 1 || !strings.HasPrefix(s, begin) {
		return nil, false
	}
	rest := s[len(begin):]
	pos := strings.Index(rest, end)
	if pos < 0 || strings.TrimSpace(rest[pos+len(end):]) != "" {
		return nil, false
	}
	b64 := strings.Join(strings.Fields(rest[:pos]), "")
	der, err := base64.StdEncoding.Strict().DecodeString(b64)
	return der, err == nil && base64.StdEncoding.EncodeToString(der) == b64
}

func singleDERSequence(b []byte) bool {
	if len(b) < 2 || b[0] != 0x30 {
		return false
	}
	_, n, ok := derLength(b[1:])
	return ok && 1+n < len(b) && 1+n+mustDERLen(b[1:]) == len(b)
}
func mustDERLen(b []byte) int { v, _, _ := derLength(b); return v }
func derLength(b []byte) (int, int, bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	if b[0] < 0x80 {
		return int(b[0]), 1, true
	}
	n := int(b[0] & 0x7f)
	if n == 0 || n > 4 || len(b) < n+1 || b[1] == 0 {
		return 0, 0, false
	}
	v := 0
	for _, x := range b[1 : n+1] {
		v = v<<8 | int(x)
	}
	if v < 128 {
		return 0, 0, false
	}
	return v, n + 1, true
}

type derReader struct {
	b   []byte
	off int
}

func (r *derReader) anyItem() (byte, []byte, error) {
	if r.off >= len(r.b) {
		return 0, nil, errors.New("tag")
	}
	tag := r.b[r.off]
	r.off++
	l, n, ok := derLength(r.b[r.off:])
	if !ok {
		return 0, nil, errors.New("length")
	}
	r.off += n
	if l > len(r.b)-r.off {
		return 0, nil, errors.New("bounds")
	}
	v := r.b[r.off : r.off+l]
	r.off += l
	return tag, v, nil
}

// validCMSSignerDigest bounds the CMS profile to one SHA-2 digest in both SignedData's
// digestAlgorithms set and its sole SignerInfo. OpenSSL validates all cryptographic semantics.
func validCMSSignerDigest(b []byte) bool {
	r := derReader{b: b}
	outer, e := r.item(0x30)
	if e != nil || r.off != len(b) {
		return false
	}
	c := derReader{b: outer}
	oid, e := c.item(0x06)
	if e != nil || !bytes.Equal(oid, []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02}) {
		return false
	}
	explicit, e := c.item(0xa0)
	if e != nil || c.off != len(outer) {
		return false
	}
	x := derReader{b: explicit}
	signed, e := x.item(0x30)
	if e != nil || x.off != len(explicit) {
		return false
	}
	sd := derReader{b: signed}
	if _, e = sd.item(0x02); e != nil {
		return false
	}
	set, e := sd.item(0x31)
	if e != nil {
		return false
	}
	sr := derReader{b: set}
	setAlg, ok := readCMSDigestAlgorithm(&sr)
	if !ok || sr.off != len(set) {
		return false
	}
	if _, e = sd.item(0x30); e != nil {
		return false
	}
	for sd.off < len(signed) && (sd.b[sd.off] == 0xa0 || sd.b[sd.off] == 0xa1) {
		if _, _, e = sd.anyItem(); e != nil {
			return false
		}
	}
	signers, e := sd.item(0x31)
	if e != nil || sd.off != len(signed) {
		return false
	}
	ss := derReader{b: signers}
	signer, e := ss.item(0x30)
	if e != nil || ss.off != len(signers) {
		return false
	}
	si := derReader{b: signer}
	if _, e = si.item(0x02); e != nil {
		return false
	}
	tag, _, e := si.anyItem()
	if e != nil || (tag != 0x30 && tag != 0x80) {
		return false
	}
	signerAlg, ok := readCMSDigestAlgorithm(&si)
	return ok && signerAlg == setAlg && si.off < len(signer)
}

func readCMSDigestAlgorithm(r *derReader) (byte, bool) {
	seq, e := r.item(0x30)
	if e != nil {
		return 0, false
	}
	a := derReader{b: seq}
	oid, e := a.item(0x06)
	if e != nil {
		return 0, false
	}
	var alg byte
	if bytes.Equal(oid, []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}) {
		alg = 1
	} else if bytes.Equal(oid, []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02}) {
		alg = 2
	} else if bytes.Equal(oid, []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03}) {
		alg = 3
	} else {
		return 0, false
	}
	if a.off < len(seq) {
		null, e := a.item(0x05)
		if e != nil || len(null) != 0 {
			return 0, false
		}
	}
	return alg, a.off == len(seq)
}

func (r *derReader) item(tag byte) ([]byte, error) {
	if r.off >= len(r.b) || r.b[r.off] != tag {
		return nil, errors.New("tag")
	}
	r.off++
	l, n, ok := derLength(r.b[r.off:])
	if !ok {
		return nil, errors.New("length")
	}
	r.off += n
	if l > len(r.b)-r.off {
		return nil, errors.New("bounds")
	}
	v := r.b[r.off : r.off+l]
	r.off += l
	return v, nil
}
func parseTSTInfoGenTime(b []byte) (int64, bool, error) {
	r := derReader{b: b}
	outer, e := r.item(0x30)
	if e != nil || r.off != len(b) {
		return 0, false, errors.New("outer")
	}
	x := derReader{b: outer}
	version, e := x.item(0x02)
	if e != nil || len(version) != 1 || version[0] != 1 {
		return 0, false, errors.New("version")
	}
	if _, e = x.item(0x06); e != nil {
		return 0, false, e
	}
	imprint, e := x.item(0x30)
	if e != nil {
		return 0, false, e
	}
	i := derReader{b: imprint}
	alg, e := i.item(0x30)
	if e != nil {
		return 0, false, e
	}
	ar := derReader{b: alg}
	oid, e := ar.item(0x06)
	if e != nil || !bytes.Equal(oid, []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01}) {
		return 0, false, errors.New("sha256")
	}
	if _, e = i.item(0x04); e != nil || i.off != len(imprint) {
		return 0, false, errors.New("imprint")
	}
	if _, e = x.item(0x02); e != nil {
		return 0, false, e
	}
	gt, e := x.item(0x18)
	if e != nil {
		return 0, false, e
	}
	return parseGeneralizedTime(string(gt))
}
func parseGeneralizedTime(s string) (int64, bool, error) {
	if !strings.HasSuffix(s, "Z") {
		return 0, false, errors.New("time")
	}
	body := s[:len(s)-1]
	frac := false
	if p := strings.IndexByte(body, '.'); p >= 0 {
		f := body[p+1:]
		if p != 14 || f == "" || strings.HasSuffix(f, "0") {
			return 0, false, errors.New("fraction")
		}
		for _, c := range f {
			if c < '0' || c > '9' {
				return 0, false, errors.New("fraction")
			}
		}
		body = body[:p]
		frac = true
	}
	if len(body) != 14 {
		return 0, false, errors.New("time")
	}
	t, e := time.Parse("20060102150405", body)
	if e != nil {
		return 0, false, e
	}
	if t.UTC().Format("20060102150405") != body {
		return 0, false, fmt.Errorf("calendar")
	}
	return t.Unix(), frac, nil
}
