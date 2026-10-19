package intyga

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	verify "github.com/intyga-dev/sdk-go/v2/verify"
)

// The shared trust-file contract every SDK's loader is held to (docs/API.md §2e, "The
// evidence-source trust file"). TypeScript, Python, Rust and Java run the same cases.
const verifierParityVectorsPath = "vectors/verifier-parity-vectors.json"

type trustFileCase struct {
	Name   string                       `json:"name"`
	Text   string                       `json:"text"`
	OK     bool                         `json:"ok"`
	Policy map[string][]json.RawMessage `json:"policy"`
}

func loadTrustFileCases(t *testing.T) []trustFileCase {
	t.Helper()
	data, err := os.ReadFile(verifierParityVectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v struct {
		ExecutionEvidence struct {
			TrustFiles []trustFileCase `json:"trustFiles"`
		} `json:"executionEvidence"`
	}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return v.ExecutionEvidence.TrustFiles
}

// normalizedJSON re-encodes a value through interface{}, so two encodings of the same JSON compare
// equal as strings (object members sorted, escapes normalized).
func normalizedJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	// Test helper normalising our own marshalled bytes for comparison; nothing untrusted is decoded.
	// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface
	var generic interface{}
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(generic)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func sameStringPtr(a, b *string) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func TestEvidenceSourcesTrustFileVectors(t *testing.T) {
	cases := loadTrustFileCases(t)
	accepted, refused := 0, 0
	for _, c := range cases {
		c := c
		if c.OK {
			accepted++
		} else {
			refused++
		}
		t.Run(c.Name, func(t *testing.T) {
			file, err := ParseEvidenceSourcesFile([]byte(c.Text))
			// A struct decode runs the same checks, so it cannot be used to load around them.
			var decoded EvidenceSourcesFile
			decodeErr := json.Unmarshal([]byte(c.Text), &decoded)
			if !c.OK {
				if err == nil || !strings.HasPrefix(err.Error(), "invalid evidence-sources file: ") {
					t.Fatalf("accepted a file every loader refuses (err %v)", err)
				}
				if decodeErr == nil {
					t.Fatal("json.Unmarshal into EvidenceSourcesFile accepted a refused file")
				}
				return
			}
			if err != nil {
				t.Fatalf("refused a file every loader accepts: %v", err)
			}
			if decodeErr != nil || !reflect.DeepEqual(*file, decoded) {
				t.Fatalf("json.Unmarshal disagrees with ParseEvidenceSourcesFile: %v %+v", decodeErr, decoded)
			}

			// The file keeps every key exactly as written: a bare string, or the object form.
			asWritten := map[string][]EvidenceSourceKey{}
			for _, s := range file.Sources {
				asWritten[s.DID] = s.PublicKeys
			}
			if got, want := normalizedJSON(t, asWritten), normalizedJSON(t, c.Policy); got != want {
				t.Fatalf("keys as written:\n got %s\nwant %s", got, want)
			}

			// The policy maps each did to the same keys in file order, none marked malformed.
			policy := EvidencePolicyFromFile(file)
			if len(policy.TrustedSources) != len(c.Policy) {
				t.Fatalf("policy has %d sources, want %d", len(policy.TrustedSources), len(c.Policy))
			}
			for did, want := range c.Policy {
				got, present := policy.TrustedSources[did]
				if !present || len(got) != len(want) {
					t.Fatalf("source %q: got %d keys, want %d", did, len(got), len(want))
				}
				for i, raw := range want {
					var w verify.TrustedSourceKey
					if err := json.Unmarshal(raw, &w); err != nil {
						t.Fatal(err)
					}
					g := got[i]
					if g.Malformed() != "" {
						t.Fatalf("source %q key %d is marked malformed: %s", did, i, g.Malformed())
					}
					if g.Key != w.Key || !sameStringPtr(g.NotBefore, w.NotBefore) || !sameStringPtr(g.NotAfter, w.NotAfter) {
						t.Fatalf("source %q key %d: got %+v, want %s", did, i, g, raw)
					}
				}
			}

			// Marshalling the file and loading it again gives back the same file.
			out, err := json.Marshal(file)
			if err != nil {
				t.Fatal(err)
			}
			again, err := ParseEvidenceSourcesFile(out)
			if err != nil || !reflect.DeepEqual(file, again) {
				t.Fatalf("round trip through JSON changed the file: %v\n%s", err, out)
			}
		})
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("expected both accepted and refused cases, got %d and %d", accepted, refused)
	}
	t.Logf("%d trust-file cases (%d accepted, %d refused)", len(cases), accepted, refused)
}

func TestEvidenceSourcesFileCannotBeDecodedAroundTheChecks(t *testing.T) {
	// Embedded in a larger configuration, a misspelt bound is still a refusal, never "no bound".
	var config struct {
		Evidence EvidenceSourcesFile `json:"evidence"`
	}
	text := `{"evidence":{"type":"intyga-evidence-sources","v":1,"sources":[{"did":"d","publicKeys":[{"key":"AAAA","notafter":"2026-10-05T18:00:00.000Z"}]}]}}`
	if err := json.Unmarshal([]byte(text), &config); err == nil || !strings.Contains(err.Error(), `unexpected member "notafter"`) {
		t.Fatalf("a misspelt bound was decoded: %v", err)
	}
	// Trailing data after the root value is not a file.
	if _, err := ParseEvidenceSourcesFile([]byte(`{"type":"intyga-evidence-sources","v":1,"sources":[{"did":"d","publicKeys":["AAAA"]}]} {}`)); err == nil {
		t.Fatal("accepted trailing data")
	}
	// v is the number 1, as JSON.parse reads it.
	for _, v := range []string{`1.0`, `1e0`} {
		if _, err := ParseEvidenceSourcesFile([]byte(`{"type":"intyga-evidence-sources","v":` + v + `,"sources":[{"did":"d","publicKeys":["AAAA"]}]}`)); err != nil {
			t.Errorf("v %s: %v", v, err)
		}
	}
	if p := EvidencePolicyFromFile(nil); p.TrustedSources == nil || len(p.TrustedSources) != 0 {
		t.Fatalf("a nil file must trust nobody: %+v", p)
	}
}

func spkiBase64(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

func anchoredMs(t *testing.T, ts string) *int64 {
	t.Helper()
	ms, ok := verify.ParseAnchorTimestampMs(ts)
	if !ok {
		t.Fatalf("bad timestamp %s", ts)
	}
	return &ms
}

// A loaded file is what verify-go trusts: a statement signed by a key in it establishes trust, a
// bounded key only at an anchored time inside its interval, and any other key or source nothing.
func TestEvidenceSourcesFileTrustsItsKeyInTheVerifier(t *testing.T) {
	const did = "did:example:relay-7"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki := spkiBase64(t, key)
	statement, err := BuildExecutionEvidence(ExecutionEvidenceInput{
		ApprovalPayload: evidenceApprovalPayload, Nonce: "n-1", Source: did, Verdict: "confirmed",
		Observation: map[string]interface{}{"breaker": "open"},
		ObservedAt:  "2026-10-05T14:02:11.000Z", SampledAt: "2026-10-05T14:02:09.500Z", Sequence: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	signature, err := SignExecutionEvidence(statement, key)
	if err != nil {
		t.Fatal(err)
	}
	event, outcome, sigAlg, signer := verify.ExecutionConfirmed, "SUCCESS", "ES256", did
	leaf := verify.AuditLeaf{
		Event: &event, Outcome: &outcome, SignerDid: &signer, SignerPublicKey: &spki,
		SignedPayload: &statement, Signature: &signature, SigAlg: &sigAlg,
	}
	load := func(sourceDid, publicKeys string) verify.ExecutionEvidencePolicy {
		t.Helper()
		file, err := ParseEvidenceSourcesFile([]byte(`{"type":"intyga-evidence-sources","v":1,"sources":[{"did":"` +
			sourceDid + `","label":"Relay 7","publicKeys":[` + publicKeys + `]}]}`))
		if err != nil {
			t.Fatal(err)
		}
		return EvidencePolicyFromFile(file)
	}

	bare := load(did, `"`+spki+`"`)
	check := verify.CheckExecutionEvidenceLeaf(leaf, &bare, nil)
	if check.Status != "unbound" || !check.Trusted || check.Source == nil || *check.Source != did {
		t.Fatalf("a bare key from the file is not trusted: %+v", check)
	}

	bounded := load(did, `{"key":"`+spki+`","notBefore":"2026-10-01T00:00:00.000Z","notAfter":"2026-10-05T18:00:00.000Z"}`)
	if sig := verify.VerifyEvidenceSignature(leaf, &bounded, anchoredMs(t, "2026-10-05T14:05:00.000Z")); sig.Status != "verified" || !sig.Trusted {
		t.Fatalf("a bounded key is not trusted inside its interval: %+v", sig)
	}
	for name, at := range map[string]*int64{
		"no anchored time": nil,
		"after notAfter":   anchoredMs(t, "2026-10-05T18:00:00.001Z"),
		"before notBefore": anchoredMs(t, "2026-09-30T23:59:59.999Z"),
	} {
		if sig := verify.VerifyEvidenceSignature(leaf, &bounded, at); sig.Status != "verified" || sig.Trusted {
			t.Errorf("%s: a bounded key established trust: %+v", name, sig)
		}
	}

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherKey := load(did, `"`+spkiBase64(t, other)+`"`)
	if sig := verify.VerifyEvidenceSignature(leaf, &otherKey, nil); sig.Trusted {
		t.Fatalf("another key established trust: %+v", sig)
	}
	otherSource := load("did:example:meter-3", `"`+spki+`"`)
	if sig := verify.VerifyEvidenceSignature(leaf, &otherSource, nil); sig.Trusted || sig.Status != "not_checked" {
		t.Fatalf("a key trusted for another source established trust: %+v", sig)
	}
}
