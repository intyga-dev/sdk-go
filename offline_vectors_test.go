package intyga

// The Go SDK against the shared offline-approval conformance vectors
// (packages/mcp-schemas/vectors/offline-approval-vectors.json, docs/OFFLINE-APPROVAL-SDK.md), run
// section by section the way the reference harness packages/sdk/src/offline-vectors.test.ts runs them.
// It reads the COMMITTED file, so a reference change that is not regenerated and ported fails here.

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	verify "github.com/intyga-dev/sdk-go/verify"
)

const offlineVectorsPath = "vectors/offline-approval-vectors.json"

type vectorKey struct {
	Seed string `json:"seed"`
	SPKI string `json:"spki"`
}

type vectorPerson struct {
	DID  string               `json:"did"`
	Keys map[string]vectorKey `json:"keys"`
}

type offlineVectors struct {
	KeyDerivation string                  `json:"keyDerivation"`
	People        map[string]vectorPerson `json:"people"`
	GatewayJWK    json.RawMessage         `json:"gatewayJwk"`
	Bundle        json.RawMessage         `json:"bundle"`
	BundleJWS     string                  `json:"bundleJws"`
	TrustBundle   []struct {
		Name   string          `json:"name"`
		JWS    string          `json:"jws"`
		AsOf   string          `json:"asOf"`
		OK     bool            `json:"ok"`
		Bundle json.RawMessage `json:"bundle"`
		// GatewayJWK, when present, replaces the top-level pinned key for this case.
		GatewayJWK json.RawMessage `json:"gatewayJwk"`
	} `json:"trustBundle"`
	BundleAnchor []struct {
		Purpose     BundleAnchorPurpose `json:"purpose"`
		LimitToDids []string            `json:"limitToDids"`
		Expect      struct {
			DIDs []string            `json:"dids"`
			Keys map[string][]string `json:"keys"`
		} `json:"expect"`
	} `json:"bundleAnchor"`
	RequirementFor []struct {
		Name                  string          `json:"name"`
		Policy                []BundlePolicy  `json:"policy"`
		UnmatchedActionPolicy string          `json:"unmatchedActionPolicy"`
		ActionType            string          `json:"actionType"`
		Display               string          `json:"display"`
		Expect                json.RawMessage `json:"expect"`
	} `json:"requirementFor"`
	TrustAnchorFile []struct {
		Name    string             `json:"name"`
		Text    string             `json:"text"`
		Purpose TrustAnchorPurpose `json:"purpose"`
		OK      bool               `json:"ok"`
		Expect  json.RawMessage    `json:"expect"`
	} `json:"trustAnchorFile"`
	CreateChallenge []struct {
		Name  string `json:"name"`
		Input struct {
			Target        string                   `json:"target"`
			ActionType    string                   `json:"actionType"`
			Display       string                   `json:"display"`
			Params        map[string]interface{}   `json:"params"`
			WindowMinutes *float64                 `json:"windowMinutes"`
			Nonce         *string                  `json:"nonce"`
			Requester     verify.RequesterIdentity `json:"requester"`
			AsOf          string                   `json:"asOf"`
			Delegation    *struct {
				DelegatedTo     []string `json:"delegatedTo"`
				DelegatedQuorum int      `json:"delegatedQuorum"`
				Nonce           string   `json:"nonce"`
			} `json:"delegation"`
		} `json:"input"`
		OK     bool                       `json:"ok"`
		Expect map[string]json.RawMessage `json:"expect"`
	} `json:"createChallenge"`
	ChallengeEnvelope []struct {
		Name     string          `json:"name"`
		Envelope string          `json:"envelope"`
		OK       bool            `json:"ok"`
		Expect   json.RawMessage `json:"expect"`
	} `json:"challengeEnvelope"`
	SignatureEnvelope struct {
		Encode []struct {
			Witness  verify.ApprovalWitness `json:"witness"`
			Envelope string                 `json:"envelope"`
		} `json:"encode"`
		Decode []struct {
			Name     string          `json:"name"`
			Envelope string          `json:"envelope"`
			OK       bool            `json:"ok"`
			Witness  json.RawMessage `json:"witness"`
		} `json:"decode"`
	} `json:"signatureEnvelope"`
	SignChallenge []struct {
		Name     string `json:"name"`
		Envelope string `json:"envelope"`
		Signer   struct {
			Person string `json:"person"`
			Key    string `json:"key"`
		} `json:"signer"`
		SignerDID string `json:"signerDid"`
		AsOf      string `json:"asOf"`
		OK        bool   `json:"ok"`
		Expect    struct {
			SignerDID       string `json:"signerDid"`
			SignerPublicKey string `json:"signerPublicKey"`
			SigAlg          string `json:"sigAlg"`
		} `json:"expect"`
	} `json:"signChallenge"`
	Delegations     map[string]json.RawMessage `json:"delegations"`
	RequesterDID    string                     `json:"requesterDid"`
	OfflineApproval []struct {
		Name   string `json:"name"`
		Action struct {
			Target     string                 `json:"target"`
			ActionType string                 `json:"actionType"`
			Display    string                 `json:"display"`
			Params     map[string]interface{} `json:"params"`
		} `json:"action"`
		Signers []struct {
			Raw      *string `json:"raw"`
			Person   string  `json:"person"`
			Key      string  `json:"key"`
			ClaimDid string  `json:"claimDid"`
		} `json:"signers"`
		Delegation string `json:"delegation"`
		AsOf       string `json:"asOf"`
		OK         bool   `json:"ok"`
		Expect     struct {
			Signers       []string `json:"signers"`
			ViaDelegation *string  `json:"viaDelegation"`
		} `json:"expect"`
	} `json:"offlineApproval"`
}

func loadOfflineVectors(t *testing.T) *offlineVectors {
	t.Helper()
	data, err := os.ReadFile(offlineVectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v offlineVectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

var p256Order, _ = new(big.Int).SetString("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)

// keyFromSeed derives an approver key as keyDerivation states:
// d = (uint256_be(SHA-256(utf8(seed))) mod (n − 1)) + 1.
func keyFromSeed(t *testing.T, seed string) *ecdsa.PrivateKey {
	t.Helper()
	h := sha256.Sum256([]byte(seed))
	d := new(big.Int).SetBytes(h[:])
	d.Mod(d, new(big.Int).Sub(p256Order, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	ek, err := ecdh.P256().NewPrivateKey(d.FillBytes(make([]byte, 32)))
	if err != nil {
		t.Fatalf("derive %q: %v", seed, err)
	}
	point := ek.PublicKey().Bytes() // 0x04 ‖ X ‖ Y
	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(point[1:33]),
			Y:     new(big.Int).SetBytes(point[33:]),
		},
		D: d,
	}
}

func (v *offlineVectors) key(t *testing.T, person, kind string) vectorKey {
	t.Helper()
	k, ok := v.People[person].Keys[kind]
	if !ok {
		t.Fatalf("%s has no %s key", person, kind)
	}
	return k
}

// signES256 signs payload as the vectors' signers do: ES256, IEEE P1363 (r‖s), base64.
func signES256(t *testing.T, key *ecdsa.PrivateKey, payload string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return base64.StdEncoding.EncodeToString(raw)
}

func (v *offlineVectors) bundle(t *testing.T) *TrustBundle {
	t.Helper()
	var b TrustBundle
	if err := json.Unmarshal(v.Bundle, &b); err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	return &b
}

// wholeMinutes converts a JSON window to the int CreateOfflineChallenge takes, refusing a fractional
// one as the reference does (Number.isSafeInteger).
func wholeMinutes(f *float64) (*int, error) {
	if f == nil {
		return nil, nil
	}
	if *f != math.Trunc(*f) || math.Abs(*f) > maxSafeInteger {
		return nil, errors.New("windowMinutes must be a whole number of minutes")
	}
	w := int(*f)
	return &w, nil
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
	}
	return tm
}

// sameJSON compares a Go value with expected JSON the way assert.deepEqual compares parsed objects:
// both sides are reduced to generic JSON values first.
func sameJSON(t *testing.T, got interface{}, want json.RawMessage) bool {
	t.Helper()
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// Generic on purpose: this compares arbitrary JSON values of test fixtures, never input to the SDK.
	// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface
	var g, w interface{}
	if err := json.Unmarshal(encoded, &g); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if err := json.Unmarshal(want, &w); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	return reflect.DeepEqual(g, w)
}

func TestOfflineVectors(t *testing.T) {
	V := loadOfflineVectors(t)
	gatewayJWK := V.GatewayJWK
	cases := 0

	t.Run("derives every published key from its seed", func(t *testing.T) {
		for id, p := range V.People {
			for kind, k := range p.Keys {
				spki, err := x509.MarshalPKIXPublicKey(&keyFromSeed(t, k.Seed).PublicKey)
				if err != nil {
					t.Fatal(err)
				}
				if got := base64.StdEncoding.EncodeToString(spki); got != k.SPKI {
					t.Errorf("%s/%s: derived %s, published %s", id, kind, got, k.SPKI)
				}
				cases++
			}
		}
	})

	t.Run("trustBundle", func(t *testing.T) {
		for _, c := range V.TrustBundle {
			cases++
			jwk := gatewayJWK
			if len(c.GatewayJWK) > 0 {
				jwk = c.GatewayJWK
			}
			b, err := VerifyTrustBundle(c.JWS, jwk, mustTime(t, c.AsOf))
			if (err == nil) != c.OK {
				t.Errorf("%s: ok=%v want %v (%v)", c.Name, err == nil, c.OK, err)
				continue
			}
			if err != nil {
				t.Logf("%s: refused as expected: %v", c.Name, err)
			}
			if c.OK && !sameJSON(t, b, c.Bundle) {
				got, _ := json.Marshal(b)
				t.Errorf("%s: bundle differs\n got %s\nwant %s", c.Name, got, c.Bundle)
			}
		}
	})

	t.Run("bundleAnchor", func(t *testing.T) {
		bundle := V.bundle(t)
		for i, c := range V.BundleAnchor {
			cases++
			anchor := ApproverAnchor(bundle, c.LimitToDids, c.Purpose)
			if !reflect.DeepEqual(anchor.DIDs, c.Expect.DIDs) {
				t.Errorf("case %d: dids %v want %v", i, anchor.DIDs, c.Expect.DIDs)
			}
			for did, keys := range c.Expect.Keys {
				if got := anchor.ResolveKeys(did); !reflect.DeepEqual(got, keys) {
					t.Errorf("case %d: %s keys %v want %v", i, did, got, keys)
				}
			}
		}
	})

	t.Run("requirementFor", func(t *testing.T) {
		for _, c := range V.RequirementFor {
			cases++
			bundle := V.bundle(t)
			bundle.Policy = c.Policy
			bundle.UnmatchedActionPolicy = c.UnmatchedActionPolicy
			got, ok := RequirementFor(bundle, c.ActionType, c.Display)
			if string(c.Expect) == "null" {
				if ok {
					t.Errorf("%s: resolved %+v, want a refusal", c.Name, got)
				}
				continue
			}
			if !ok || !sameJSON(t, got, c.Expect) {
				encoded, _ := json.Marshal(got)
				t.Errorf("%s: ok=%v got %s want %s", c.Name, ok, encoded, c.Expect)
			}
		}
	})

	t.Run("trustAnchorFile", func(t *testing.T) {
		for _, c := range V.TrustAnchorFile {
			cases++
			parsed, err := ParseTrustAnchorFile(c.Text, c.Purpose)
			if (err == nil) != c.OK {
				t.Errorf("%s: ok=%v want %v (%v)", c.Name, err == nil, c.OK, err)
				continue
			}
			if err != nil {
				t.Logf("%s: refused as expected: %v", c.Name, err)
			}
			if !c.OK {
				continue
			}
			anchor := TrustAnchorApprovers(parsed, nil)
			keys := map[string][]string{}
			for _, did := range anchor.DIDs {
				keys[did] = anchor.ResolveKeys(did)
			}
			got := map[string]interface{}{
				"purpose": parsed.Purpose,
				"epoch":   parsed.Epoch,
				"dids":    anchor.DIDs,
				"keys":    keys,
			}
			if !sameJSON(t, got, c.Expect) {
				encoded, _ := json.Marshal(got)
				t.Errorf("%s: got %s want %s", c.Name, encoded, c.Expect)
			}
		}
	})

	t.Run("createChallenge", func(t *testing.T) {
		bundle := V.bundle(t)
		for _, c := range V.CreateChallenge {
			cases++
			in := c.Input
			// WindowMinutes is an int in Go, so a fractional window (2.5) cannot reach
			// CreateOfflineChallenge at all: it is refused where the JSON number becomes an int.
			window, err := wholeMinutes(in.WindowMinutes)
			if err != nil {
				if c.OK {
					t.Errorf("%s: %v", c.Name, err)
				} else {
					t.Logf("%s: refused as expected: %v", c.Name, err)
				}
				continue
			}
			input := OfflineChallengeInput{
				Bundle:        bundle,
				Target:        in.Target,
				ActionType:    in.ActionType,
				Display:       in.Display,
				Params:        in.Params,
				Requester:     in.Requester,
				WindowMinutes: window,
				AsOf:          mustTime(t, in.AsOf),
				Nonce:         in.Nonce,
			}
			if in.Delegation != nil {
				input.Delegation = &verify.VerifiedDelegation{
					DelegatedTo:     in.Delegation.DelegatedTo,
					DelegatedQuorum: in.Delegation.DelegatedQuorum,
					Nonce:           in.Delegation.Nonce,
					Target:          in.Target,
					ActionType:      in.ActionType,
					Params:          in.Params,
					Signers:         []string{},
				}
			}
			ch, err := CreateOfflineChallenge(input)
			if (err == nil) != c.OK {
				t.Errorf("%s: ok=%v want %v (%v)", c.Name, err == nil, c.OK, err)
				continue
			}
			if err != nil {
				t.Logf("%s: refused as expected: %v", c.Name, err)
			}
			if !c.OK {
				continue
			}
			encoded, _ := json.Marshal(ch)
			var fields map[string]json.RawMessage
			_ = json.Unmarshal(encoded, &fields)
			for field, want := range c.Expect {
				if !sameJSON(t, fields[field], want) {
					t.Errorf("%s.%s: got %s want %s", c.Name, field, fields[field], want)
				}
			}
		}
	})

	t.Run("challengeEnvelope", func(t *testing.T) {
		for _, c := range V.ChallengeEnvelope {
			cases++
			got, err := DecodeChallengeEnvelope(c.Envelope)
			if (err == nil) != c.OK {
				t.Errorf("%s: ok=%v want %v (%v)", c.Name, err == nil, c.OK, err)
				continue
			}
			if err != nil {
				t.Logf("%s: refused as expected: %v", c.Name, err)
			}
			if c.OK && !sameJSON(t, got, c.Expect) {
				encoded, _ := json.Marshal(got)
				t.Errorf("%s: got %s want %s", c.Name, encoded, c.Expect)
			}
		}
	})

	t.Run("signatureEnvelope", func(t *testing.T) {
		for i, c := range V.SignatureEnvelope.Encode {
			cases++
			if got := EncodeSignatureEnvelope(c.Witness); got != c.Envelope {
				t.Errorf("encode %d: got %s want %s", i, got, c.Envelope)
			}
		}
		for _, c := range V.SignatureEnvelope.Decode {
			cases++
			w, err := DecodeSignatureEnvelope(c.Envelope)
			if (err == nil) != c.OK {
				t.Errorf("%s: ok=%v want %v (%v)", c.Name, err == nil, c.OK, err)
				continue
			}
			if err != nil {
				t.Logf("%s: refused as expected: %v", c.Name, err)
			}
			if c.OK && !sameJSON(t, w, c.Witness) {
				encoded, _ := json.Marshal(w)
				t.Errorf("%s: got %s want %s", c.Name, encoded, c.Witness)
			}
		}
	})

	t.Run("signChallenge", func(t *testing.T) {
		for _, c := range V.SignChallenge {
			cases++
			signed, err := SignChallengeEnvelope(c.Envelope, SignChallengeOptions{
				PrivateKey: keyFromSeed(t, V.key(t, c.Signer.Person, c.Signer.Key).Seed),
				SignerDID:  c.SignerDID,
				AsOf:       mustTime(t, c.AsOf),
			})
			if (err == nil) != c.OK {
				t.Errorf("%s: ok=%v want %v (%v)", c.Name, err == nil, c.OK, err)
				continue
			}
			if err != nil {
				t.Logf("%s: refused as expected: %v", c.Name, err)
			}
			if !c.OK {
				continue
			}
			w, err := DecodeSignatureEnvelope(signed.Envelope)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			if w.SignerDID != c.Expect.SignerDID || w.SignerPublicKey != c.Expect.SignerPublicKey ||
				w.SigAlg == nil || *w.SigAlg != c.Expect.SigAlg {
				t.Errorf("%s: witness %+v want %+v", c.Name, w, c.Expect)
			}
			decoded, err := DecodeChallengeEnvelope(c.Envelope)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			pubDER, _ := base64.StdEncoding.DecodeString(c.Expect.SignerPublicKey)
			pub, err := x509.ParsePKIXPublicKey(pubDER)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			sig, _ := base64.StdEncoding.DecodeString(w.Signature)
			digest := sha256.Sum256([]byte(decoded.CanonicalPayload))
			if len(sig) != 64 || !ecdsa.Verify(pub.(*ecdsa.PublicKey), digest[:],
				new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
				t.Errorf("%s: signature does not verify", c.Name)
			}
		}
	})

	t.Run("offlineApproval", func(t *testing.T) {
		for _, c := range V.OfflineApproval {
			cases++
			c := c
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "trust-bundle.jws"), []byte(V.BundleJWS), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "gateway-key.jwk.json"), V.GatewayJWK, 0o600); err != nil {
				t.Fatal(err)
			}
			delegationDir := ""
			if c.Delegation != "" {
				delegationDir = filepath.Join(dir, "delegations")
				if err := os.Mkdir(delegationDir, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(delegationDir, c.Delegation+".json"), V.Delegations[c.Delegation], 0o600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := UseOfflineApproval(context.Background(), OfflineAction{
				Target:     c.Action.Target,
				ActionType: c.Action.ActionType,
				Display:    c.Action.Display,
				Params:     c.Action.Params,
			}, OfflineApprovalOptions{
				BundleDir:     dir,
				DelegationDir: delegationDir,
				RequesterDID:  V.RequesterDID,
				AsOf:          mustTime(t, c.AsOf),
				Warn:          func(string) {},
				CollectSignatures: func(_ context.Context, ch *OfflineChallenge) ([]string, error) {
					out := make([]string, 0, len(c.Signers))
					for _, s := range c.Signers {
						if s.Raw != nil {
							out = append(out, *s.Raw)
							continue
						}
						claim := s.Person
						if s.ClaimDid != "" {
							claim = s.ClaimDid
						}
						k := V.key(t, s.Person, s.Key)
						alg := "ES256"
						out = append(out, EncodeSignatureEnvelope(verify.ApprovalWitness{
							SignerDID:       V.People[claim].DID,
							SignerPublicKey: k.SPKI,
							Signature:       signES256(t, keyFromSeed(t, k.Seed), ch.CanonicalPayload),
							SigAlg:          &alg,
						}))
					}
					return out, nil
				},
			})
			if (err == nil) != c.OK {
				t.Errorf("%s: ok=%v want %v (%v)", c.Name, err == nil, c.OK, err)
				continue
			}
			if err != nil {
				t.Logf("%s: refused as expected: %v", c.Name, err)
			}
			if !c.OK {
				continue
			}
			signers := append([]string(nil), r.Signers...)
			sort.Strings(signers)
			if !reflect.DeepEqual(signers, c.Expect.Signers) {
				t.Errorf("%s: signers %v want %v", c.Name, signers, c.Expect.Signers)
			}
			want := ""
			if c.Expect.ViaDelegation != nil {
				want = *c.Expect.ViaDelegation
			}
			if r.ViaDelegation != want {
				t.Errorf("%s: viaDelegation %q want %q", c.Name, r.ViaDelegation, want)
			}
		}
	})

	// Every section must have run, so a renamed key in the vector file cannot pass by matching nothing.
	sections := map[string]int{
		"trustBundle":       len(V.TrustBundle),
		"bundleAnchor":      len(V.BundleAnchor),
		"requirementFor":    len(V.RequirementFor),
		"trustAnchorFile":   len(V.TrustAnchorFile),
		"createChallenge":   len(V.CreateChallenge),
		"challengeEnvelope": len(V.ChallengeEnvelope),
		"signatureEnvelope": len(V.SignatureEnvelope.Encode) + len(V.SignatureEnvelope.Decode),
		"signChallenge":     len(V.SignChallenge),
		"offlineApproval":   len(V.OfflineApproval),
	}
	for name, n := range sections {
		if n == 0 {
			t.Errorf("vector section %s is empty — the file shape changed", name)
		}
	}
	t.Logf("ran %d offline-approval vector cases", cases)
}
