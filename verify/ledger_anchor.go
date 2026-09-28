package verify

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"sort"
	"strings"
)

type AnchorPolicy struct {
	RequiredAnchors int      `json:"requiredAnchors"`
	TrustedIssuers  []string `json:"trustedIssuers"`
	Quorum          string   `json:"quorum"`
	// MaxAnchorLagSeconds bounds how long after the checkpoint's claimed time an EXTERNAL witness
	// (Rekor integratedTime, TSA genTime) may first have seen the anchor. nil ⇒ DefaultMaxAnchorLagSeconds.
	MaxAnchorLagSeconds *int64 `json:"maxAnchorLagSeconds,omitempty"`
}

// DefaultMaxAnchorLagSeconds is the DEWP §5.3 default time bound: an anchor witnessed later than
// this proves only that the root existed when finally witnessed, which is exactly what re-anchoring a
// rewritten old root today produces.
const DefaultMaxAnchorLagSeconds int64 = 86400

// AnchorClockSkewSeconds tolerates a witness time slightly BEFORE the checkpoint's claimed time.
const AnchorClockSkewSeconds int64 = 300

type AnchorKeyResolver func(SignedAnchor) string
type ExternalAnchorKeys struct {
	Rekor       string `json:"rekor,omitempty"`
	RekorIssuer string `json:"rekorIssuer,omitempty"`
	// RekorSubmitterKeys pins the producer's Rekor submission key(s) (PEM or base64 SPKI). When set,
	// an entry counts only if it was submitted under one of them with a valid ES256 signature over the
	// anchor digest — Rekor itself logs a submission under any key.
	RekorSubmitterKeys []string                `json:"rekorSubmitterKeys,omitempty"`
	RFC3161            map[string]Rfc3161Trust `json:"rfc3161,omitempty"`
}

// ExpectedCheckpoint is the checkpoint anchors are counted FOR; every known field must equal the
// anchor's signed field (AnchoredAt against the anchor's timestamp). A non-nil ExpectedCheckpoint
// with a nil AnchoredAt counts no EXTERNAL witness: its time bound would have nothing trusted to be
// measured against.
type ExpectedCheckpoint struct {
	SeqStart, SeqEnd, ChainHash, AnchoredAt *string
}

// TrustedCheckpoint is a checkpoint record the CALLER holds — normally a chain-verified line of the
// published roots file (DEWP §5.4.1). Every field but Root is optional; a present field is binding.
type TrustedCheckpoint struct {
	Root       string  `json:"root"`
	SeqStart   *string `json:"seqStart,omitempty"`
	SeqEnd     *string `json:"seqEnd,omitempty"`
	EntryCount *int    `json:"entryCount,omitempty"`
	AnchoredAt *string `json:"anchoredAt,omitempty"`
	ChainHash  *string `json:"chainHash,omitempty"`
}

// LeafCountMismatch reports why a proof's prover-supplied leaf counts cannot belong to a checkpoint
// committing entryCount events (the sum of its blocks' leaf counts), or "" (DEWP §17.3).
func LeafCountMismatch(p InclusionProof, entryCount *int) string {
	if entryCount == nil || *entryCount < 0 {
		return ""
	}
	n, block, cps := *entryCount, p.BlockLeafCount, p.CheckpointLeafCount
	if cps > n || block+cps-1 > n || (cps == 1 && block != n) {
		return fmt.Sprintf("proof claims %d leaves in its block and %d block(s) under the checkpoint, which cannot sum to the checkpoint's %d committed events", block, cps, n)
	}
	return ""
}

type AnchorQuorumResult struct {
	OK              bool     `json:"ok"`
	VerifiedIssuers []string `json:"verifiedIssuers"`
	Divergence      bool     `json:"divergence"`
	Reason          string   `json:"reason,omitempty"`
	Note            string   `json:"note,omitempty"`
	// WitnessTimes is the authenticated external witness time per issuer (Unix seconds, earliest per
	// issuer), including witnesses refused by the time bound.
	WitnessTimes map[string]int64 `json:"witnessTimes"`
}

func positionMismatch(a AnchorInput, e *ExpectedCheckpoint) string {
	if e == nil {
		return ""
	}
	if e.SeqStart != nil && a.SeqStart != *e.SeqStart {
		return "seqStart"
	}
	if e.SeqEnd != nil && a.SeqEnd != *e.SeqEnd {
		return "seqEnd"
	}
	if e.ChainHash != nil && a.ChainHash != *e.ChainHash {
		return "chainHash"
	}
	if e.AnchoredAt != nil && a.Timestamp != *e.AnchoredAt {
		return "timestamp"
	}
	return ""
}

// VerifyAnchorQuorum evaluates the quorum with no expected checkpoint position.
func VerifyAnchorQuorum(anchors []SignedAnchor, root string, policy AnchorPolicy, resolve AnchorKeyResolver, divergence []SignedAnchor, external ExternalAnchorKeys) AnchorQuorumResult {
	return VerifyAnchorQuorumFor(anchors, root, policy, resolve, divergence, external, nil)
}

// VerifyAnchorQuorumFor counts an anchor only when its evidence verifies under caller trust, its
// signed position matches `expected` where known, and an external witness time lies within
// [-AnchorClockSkewSeconds, MaxAnchorLagSeconds] of the checkpoint's claimed time (DEWP §5.3).
func VerifyAnchorQuorumFor(anchors []SignedAnchor, root string, policy AnchorPolicy, resolve AnchorKeyResolver, divergence []SignedAnchor, external ExternalAnchorKeys, expected *ExpectedCheckpoint) AnchorQuorumResult {
	trusted := map[string]bool{}
	for _, i := range policy.TrustedIssuers {
		trusted[i] = true
	}
	verify := func(a SignedAnchor) (bool, *int64) {
		if !IsWellFormedAnchor(a.AnchorInput) {
			return false, nil
		}
		switch a.Kind {
		case "REKOR":
			rekorScoped := rekorIssuerAllowed(external.RekorIssuer, a.Issuer, len(trusted))
			if external.Rekor != "" && rekorScoped && a.Evidence != nil {
				if e := ParseRekorEvidence(*a.Evidence); e != nil {
					v := VerifyRekorAnchorPinned(*e, a.AnchorInput, external.Rekor, external.RekorSubmitterKeys)
					return v.OK && v.IntegratedTime != nil, v.IntegratedTime
				}
			}
		case "RFC3161":
			if trust, ok := external.RFC3161[a.Issuer]; ok {
				v := VerifyRfc3161Anchor(a, trust)
				return v.OK && v.GenTime != nil, v.GenTime
			}
		case "WEBHOOK":
			return false, nil
		default:
			return (a.Kind == "" || a.Kind == "SELF") && resolve != nil && VerifyAnchorSignature(a, resolve(a)), nil
		}
		return false, nil
	}
	maxLag := DefaultMaxAnchorLagSeconds
	if policy.MaxAnchorLagSeconds != nil {
		maxLag = *policy.MaxAnchorLagSeconds
	}
	// withinBound is the §5.3 lag window around the anchor's own signed checkpoint time.
	withinBound := func(a SignedAnchor, witness int64) (int64, bool) {
		claimed, _ := ParseAnchorTimestampMs(a.Timestamp)
		lag := witness*1000 - claimed
		return lag, lag >= -AnchorClockSkewSeconds*1000 && lag <= maxLag*1000
	}
	// Divergence is fatal, so its evidence meets the quorum rules (DEWP §5.3): this checkpoint's seq
	// range, an external witness inside the time bound of the anchor's signed time, and — for Rekor,
	// which logs any digest anyone submits — a pinned producer submission key. Chain hash and claimed
	// time are not compared: both commit to the root, so a rewritten checkpoint differs in them.
	for _, a := range divergence {
		if expected != nil && ((expected.SeqStart != nil && a.SeqStart != *expected.SeqStart) || (expected.SeqEnd != nil && a.SeqEnd != *expected.SeqEnd)) {
			continue // its own signed range names another checkpoint
		}
		if !trusted[a.Issuer] || a.DailyRoot == root {
			continue
		}
		if a.Kind == "REKOR" && len(external.RekorSubmitterKeys) == 0 {
			continue
		}
		ok, witness := verify(a)
		if ok && witness != nil {
			if _, in := withinBound(a, *witness); !in {
				continue
			}
		}
		if ok {
			return AnchorQuorumResult{Reason: fmt.Sprintf("anchor divergence: issuer %s signed a different root for this checkpoint", a.Issuer), Divergence: true, WitnessTimes: map[string]int64{}}
		}
	}
	verified := map[string]bool{}
	present := map[string]bool{}
	witnessTimes := map[string]int64{}
	notes := []string{}
	tsa := 0
	for _, a := range anchors {
		if !trusted[a.Issuer] || a.DailyRoot != root {
			continue
		}
		present[a.Issuer] = true
		if m := positionMismatch(a.AnchorInput, expected); m != "" {
			notes = append(notes, fmt.Sprintf("anchor from %s binds a different checkpoint %s; it does not count", a.Issuer, m))
			continue
		}
		ok, witness := verify(a)
		if a.Kind == "RFC3161" && !ok {
			tsa++
		}
		if !ok {
			continue
		}
		if witness != nil {
			if prior, seen := witnessTimes[a.Issuer]; !seen || *witness < prior {
				witnessTimes[a.Issuer] = *witness
			}
			// A checkpoint named without its time leaves only the anchor's producer-chosen timestamp
			// to bound the witness against, which bounds nothing (DEWP §5.3).
			if expected != nil && expected.AnchoredAt == nil {
				notes = append(notes, fmt.Sprintf("anchor from %s has an external witness time but no trusted checkpoint time to hold it to (DEWP §5.3); it does not count", a.Issuer))
				continue
			}
			if lag, in := withinBound(a, *witness); !in {
				notes = append(notes, fmt.Sprintf("anchor from %s was witnessed %ds from its checkpoint time; it does not count", a.Issuer, lag/1000))
				continue
			}
		}
		verified[a.Issuer] = true
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
	r := AnchorQuorumResult{OK: len(verified) >= need && len(verified) >= 1, VerifiedIssuers: issuers, WitnessTimes: witnessTimes}
	if !r.OK {
		r.Reason = fmt.Sprintf("anchor quorum not met (%d/%d)", len(verified), need)
	}
	if tsa > 0 {
		notes = append(notes, fmt.Sprintf("%d RFC 3161 TSA anchor(s) over this root are not verified; configure RFC3161 trust/OpenSSL or inspect evidence", tsa))
	}
	r.Note = strings.Join(notes, "; ")
	return r
}

func rekorIssuerAllowed(configured, anchorIssuer string, trustedIssuerCount int) bool {
	return (configured != "" && configured == anchorIssuer) || (configured == "" && trustedIssuerCount == 1)
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

// VerifyRekorAnchor checks the SET and the logged payload hash, without pinning the submitter.
func VerifyRekorAnchor(e RekorEvidence, a AnchorInput, keyText string) RekorVerification {
	return VerifyRekorAnchorPinned(e, a, keyText, nil)
}

func decodeKeyDER(keyText string) ([]byte, bool) {
	if b, _ := pem.Decode([]byte(keyText)); b != nil {
		return b.Bytes, true
	}
	der, err := base64.StdEncoding.DecodeString(keyText)
	return der, err == nil
}

// VerifyRekorAnchorPinned additionally requires, when submitterKeys is non-empty, that the hashedrekord
// was submitted under one of those keys and that its ES256 signature covers the anchor digest.
func VerifyRekorAnchorPinned(e RekorEvidence, a AnchorInput, keyText string, submitterKeys []string) RekorVerification {
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
			Signature struct {
				Content   string `json:"content"`
				PublicKey struct {
					Content string `json:"content"`
				} `json:"publicKey"`
			} `json:"signature"`
		} `json:"spec"`
	}
	if json.Unmarshal(body, &hr) != nil || hr.Kind != "hashedrekord" || hr.Spec.Data.Hash.Algorithm != "sha256" || stringsLower(hr.Spec.Data.Hash.Value) != RekorPayloadHashFor(a) {
		return RekorVerification{Reason: "rekor entry attests a different payload"}
	}
	if len(submitterKeys) > 0 && !submittedByPinnedKey(hr.Spec.Signature.PublicKey.Content, hr.Spec.Signature.Content, a, submitterKeys) {
		return RekorVerification{Reason: "rekor entry was not submitted under a pinned producer key with a valid signature over this anchor"}
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
	der, okKey := decodeKeyDER(keyText)
	if !okKey {
		return RekorVerification{Reason: "rekor public key is invalid"}
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

// submittedByPinnedKey: hashedrekord `publicKey.content` is base64 of the PEM text.
func submittedByPinnedKey(publicKeyB64, signatureB64 string, a AnchorInput, pinned []string) bool {
	pemText, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return false
	}
	submitted, ok := decodeKeyDER(string(pemText))
	if !ok {
		return false
	}
	match := false
	for _, k := range pinned {
		if der, ok := decodeKeyDER(k); ok && bytes.Equal(der, submitted) {
			match = true
			break
		}
	}
	if !match {
		return false
	}
	pub, err := parseSpkiP256(submitted)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return false
	}
	digest := anchorDigest(a)
	return verifyEcdsaSignature(pub, digest[:], sig)
}
