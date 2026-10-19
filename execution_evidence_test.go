package intyga

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"

	verify "github.com/intyga-dev/sdk-go/v2/verify"
)

const evidenceApprovalPayload = `{"nonce":"n-1","type":"div-intent-verification","v":1}`

func TestEvidenceSourceBuildsAndSignsAStatement(t *testing.T) {
	statement, err := BuildExecutionEvidence(ExecutionEvidenceInput{
		ApprovalPayload: evidenceApprovalPayload, Nonce: "n-1", Source: "did:example:relay-7", Verdict: "confirmed",
		Observation: map[string]interface{}{"breaker": "open", "currentA": 0},
		ObservedAt:  "2026-10-05T14:02:11.000Z", SampledAt: "2026-10-05T14:02:09.500Z", Sequence: 418,
	})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := verify.ParseExecutionEvidenceStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.PayloadSha256 != verify.ExecutionPayloadSha256(evidenceApprovalPayload) || parsed.SampledAt != "2026-10-05T14:02:09.500Z" || parsed.Sequence != 418 {
		t.Fatalf("%+v", parsed)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignExecutionEvidence(statement, key)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(signature)
	if err != nil || len(raw) != 64 {
		t.Fatalf("expected a 64-byte P1363 signature: %v %d", err, len(raw))
	}
	digest := sha256.Sum256([]byte(statement))
	if !ecdsa.Verify(&key.PublicKey, digest[:], new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])) {
		t.Fatal("signature does not verify")
	}
	// PEM works too; a non-P-256 key is refused rather than producing a signature nobody verifies.
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if sig, err := SignExecutionEvidence(statement, pemText); err != nil || len(sig) == 0 {
		t.Fatalf("PEM key: %v", err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignExecutionEvidence(statement, ed); err == nil {
		t.Fatal("an Ed25519 key must be refused")
	}
}

func TestEvidenceDefaultsAndRefusals(t *testing.T) {
	base := ExecutionEvidenceInput{ApprovalPayload: evidenceApprovalPayload, Nonce: "n-1", Source: "s", Verdict: "contradicted", Observation: map[string]interface{}{}, Sequence: 1}
	statement, err := BuildExecutionEvidence(base)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := verify.ParseExecutionEvidenceStatement(statement)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SampledAt != parsed.ObservedAt {
		t.Fatalf("sampledAt defaults to observedAt: %+v", parsed)
	}
	// A nil observation serializes as an empty object.
	if parsed.Observation == nil {
		t.Fatal("observation must be an object")
	}
	for name, mutate := range map[string]func(in *ExecutionEvidenceInput){
		"non-portable number": func(in *ExecutionEvidenceInput) { in.Observation = map[string]interface{}{"x": 1e16} },
		"sequence zero":       func(in *ExecutionEvidenceInput) { in.Sequence = 0 },
		"sequence negative":   func(in *ExecutionEvidenceInput) { in.Sequence = -7 },
		"sample after report": func(in *ExecutionEvidenceInput) {
			in.ObservedAt = "2026-10-05T14:02:11.000Z"
			in.SampledAt = "2099-01-01T00:00:00.000Z"
		},
		"unknown verdict":          func(in *ExecutionEvidenceInput) { in.Verdict = "maybe" },
		"empty nonce":              func(in *ExecutionEvidenceInput) { in.Nonce = "" },
		"timestamp without millis": func(in *ExecutionEvidenceInput) { in.ObservedAt = "2026-10-05T14:02:11Z" },
	} {
		in := base
		mutate(&in)
		if _, err := BuildExecutionEvidence(in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
