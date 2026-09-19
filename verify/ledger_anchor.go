package verify

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
)

type AnchorPolicy struct {
	RequiredAnchors int      `json:"requiredAnchors"`
	TrustedIssuers  []string `json:"trustedIssuers"`
	Quorum          string   `json:"quorum"`
}
type AnchorKeyResolver func(SignedAnchor) string
type ExternalAnchorKeys struct {
	Rekor string `json:"rekor,omitempty"`
}
type AnchorQuorumResult struct {
	OK              bool     `json:"ok"`
	VerifiedIssuers []string `json:"verifiedIssuers"`
	Divergence      bool     `json:"divergence"`
	Reason          string   `json:"reason,omitempty"`
	Note            string   `json:"note,omitempty"`
}

func VerifyAnchorQuorum(anchors []SignedAnchor, root string, policy AnchorPolicy, resolve AnchorKeyResolver, divergence []SignedAnchor, external ExternalAnchorKeys) AnchorQuorumResult {
	trusted := map[string]bool{}
	for _, i := range policy.TrustedIssuers {
		trusted[i] = true
	}
	for _, a := range divergence {
		if trusted[a.Issuer] && a.DailyRoot != root && resolve != nil && VerifyAnchorSignature(a, resolve(a)) {
			return AnchorQuorumResult{Reason: fmt.Sprintf("anchor divergence: issuer %s signed a different root for this checkpoint", a.Issuer), Divergence: true}
		}
	}
	verified := map[string]bool{}
	present := map[string]bool{}
	tsa := 0
	for _, a := range anchors {
		if !trusted[a.Issuer] || a.DailyRoot != root {
			continue
		}
		present[a.Issuer] = true
		switch a.Kind {
		case "REKOR":
			if external.Rekor != "" && a.Evidence != nil {
				if e := ParseRekorEvidence(*a.Evidence); e != nil && VerifyRekorAnchor(*e, a.AnchorInput, external.Rekor).OK {
					verified[a.Issuer] = true
				}
			}
		case "RFC3161":
			tsa++
		case "WEBHOOK":
			continue
		default:
			if a.Kind != "" && a.Kind != "SELF" {
				continue
			}
			if resolve != nil && VerifyAnchorSignature(a, resolve(a)) {
				verified[a.Issuer] = true
			}
		}
	}
	need := policy.RequiredAnchors
	if policy.Quorum == "ALL_MUST_AGREE" && len(present) > need {
		need = len(present)
	}
	issuers := make([]string, 0, len(verified))
	for i := range verified {
		issuers = append(issuers, i)
	}
	sort.Strings(issuers)
	r := AnchorQuorumResult{OK: len(verified) >= need && len(verified) >= 1, VerifiedIssuers: issuers}
	if !r.OK {
		r.Reason = fmt.Sprintf("anchor quorum not met (%d/%d)", len(verified), need)
	}
	if tsa > 0 {
		r.Note = fmt.Sprintf("%d RFC 3161 TSA anchor(s) over this root are present but not verifiable offline by this tool", tsa)
	}
	return r
}

type RekorEvidence struct {
	UUID           string `json:"uuid,omitempty"`
	Body           string `json:"body,omitempty"`
	LogID          string `json:"logID,omitempty"`
	LogIndex       *int64 `json:"logIndex,omitempty"`
	IntegratedTime *int64 `json:"integratedTime,omitempty"`
	Verification   struct {
		SignedEntryTimestamp string      `json:"signedEntryTimestamp,omitempty"`
		InclusionProof       interface{} `json:"inclusionProof,omitempty"`
	} `json:"verification,omitempty"`
}
type RekorVerification struct {
	OK             bool   `json:"ok"`
	Reason         string `json:"reason,omitempty"`
	LogIndex       *int64 `json:"logIndex,omitempty"`
	LogID          string `json:"logID,omitempty"`
	IntegratedTime *int64 `json:"integratedTime,omitempty"`
}

func ParseRekorEvidence(v string) *RekorEvidence {
	b, e := base64.StdEncoding.DecodeString(v)
	if e != nil {
		return nil
	}
	var r RekorEvidence
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	return &r
}
func RekorPayloadHashFor(a AnchorInput) string {
	d := anchorDigest(a)
	h := sha256.Sum256(d[:])
	return hex.EncodeToString(h[:])
}
func VerifyRekorAnchor(e RekorEvidence, a AnchorInput, keyText string) RekorVerification {
	if e.Body == "" {
		return RekorVerification{Reason: "rekor evidence carries no entry body"}
	}
	if e.Verification.SignedEntryTimestamp == "" {
		return RekorVerification{Reason: "rekor evidence carries no signedEntryTimestamp (SET)"}
	}
	if e.LogIndex == nil || e.IntegratedTime == nil {
		return RekorVerification{Reason: "rekor evidence is missing logIndex/integratedTime"}
	}
	body, err := base64.StdEncoding.DecodeString(e.Body)
	if err != nil {
		return RekorVerification{Reason: "rekor entry body is not a readable hashedrekord"}
	}
	var hr struct {
		Kind string `json:"kind"`
		Spec struct {
			Data struct {
				Hash struct{ Algorithm, Value string } `json:"hash"`
			} `json:"data"`
		} `json:"spec"`
	}
	if json.Unmarshal(body, &hr) != nil || hr.Kind != "hashedrekord" || hr.Spec.Data.Hash.Algorithm != "sha256" || stringsLower(hr.Spec.Data.Hash.Value) != RekorPayloadHashFor(a) {
		return RekorVerification{Reason: "rekor entry attests a different payload"}
	}
	// Rekor's SET fixture and producer sign this compact JSON in insertion order.
	payloadBytes, _ := json.Marshal(struct {
		Body           string `json:"body"`
		IntegratedTime int64  `json:"integratedTime"`
		LogID          string `json:"logID"`
		LogIndex       int64  `json:"logIndex"`
	}{e.Body, *e.IntegratedTime, e.LogID, *e.LogIndex})
	payload := string(payloadBytes)
	sig, err := base64.StdEncoding.DecodeString(e.Verification.SignedEntryTimestamp)
	if err != nil {
		return RekorVerification{Reason: "rekor SET verification failed"}
	}
	var der []byte
	if b, _ := pem.Decode([]byte(keyText)); b != nil {
		der = b.Bytes
	} else {
		der, err = base64.StdEncoding.DecodeString(keyText)
		if err != nil {
			return RekorVerification{Reason: "rekor public key is invalid"}
		}
	}
	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return RekorVerification{Reason: "rekor public key is invalid"}
	}
	pub, ok := k.(*ecdsa.PublicKey)
	if !ok || pub.Curve.Params().Name != "P-256" {
		return RekorVerification{Reason: "rekor public key is not an EC P-256 key"}
	}
	if !verifyEcdsaSignature(pub, []byte(payload), sig) {
		return RekorVerification{Reason: "rekor SET does not verify under the supplied log key"}
	}
	return RekorVerification{OK: true, LogIndex: e.LogIndex, LogID: e.LogID, IntegratedTime: e.IntegratedTime}
}
func stringsLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
