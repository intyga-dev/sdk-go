package verify

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const BundleKind = "dewp.audit.inclusion-proof"
const EvidenceBundleKind = "dewp.audit.evidence-bundle"
const AuditProfile = "trust.intyga.audit.v1"

type BundleEvent struct {
	Seq        string     `json:"seq"`
	ID         string     `json:"id,omitempty"`
	CreatedAt  string     `json:"createdAt"`
	Type       string     `json:"type"`
	Outcome    string     `json:"outcome"`
	Detail     *string    `json:"detail"`
	ActorDID   *string    `json:"actorDid"`
	SubjectDID *string    `json:"subjectDid"`
	SignerDID  *string    `json:"signerDid"`
	Signature  *string    `json:"signature"`
	SigAlg     *string    `json:"sigAlg"`
	Canonical  *AuditLeaf `json:"canonical,omitempty"`
}
type ProofBundle struct {
	invalidProtocol   bool
	Protocol          string          `json:"protocol,omitempty"`
	AlgorithmRegistry json.RawMessage `json:"algorithmRegistry,omitempty"`
	Kind              string          `json:"kind"`
	Version           interface{}     `json:"version"`
	Profile           string          `json:"profile,omitempty"`
	ExportedAt        string          `json:"exportedAt"`
	Event             BundleEvent     `json:"event"`
	Proof             InclusionProof  `json:"proof"`
	Anchor            *SignedAnchor   `json:"anchor,omitempty"`
	Anchors           []SignedAnchor  `json:"anchors,omitempty"`
	AnchorRef         *string         `json:"anchorRef,omitempty"`
	Anchored          *bool           `json:"anchored,omitempty"`
	LegacyAnchor      *struct {
		DailyRoot *string `json:"dailyRoot"`
		AnchorRef *string `json:"anchorRef"`
		Anchored  bool    `json:"anchored"`
	} `json:"legacyAnchor,omitempty"`
	ExternallyAnchored         *bool `json:"externallyAnchored,omitempty"`
	ExternallyAnchoredRequired *int  `json:"externallyAnchoredRequired,omitempty"`
}
type CheckResult struct {
	Pass   *bool  `json:"pass"`
	Detail string `json:"detail"`
}
type VerificationProperties struct {
	CommitmentVerified bool `json:"commitmentVerified"`
	ContentVerified    bool `json:"contentVerified"`
	SignatureVerified  bool `json:"signatureVerified"`
	AnchorVerified     bool `json:"anchorVerified"`
}
type BundleChecks struct{ Inclusion, RootConsistency, LeafBinding, HeaderBinding, Anchored CheckResult }
type BundleVerification struct {
	Signature AuditSignatureCheck `json:"signature"`
	OK        bool                `json:"ok"`
	DailyRoot *string             `json:"dailyRoot"`
	// RootSource is "caller-supplied", "self-asserted" or "none". A supplied root is never labelled
	// "independent": the verifier cannot tell one recorded independently from one copied out of the
	// bundle itself.
	RootSource string `json:"rootSource"`
	// WitnessTimes: authenticated external witness time per anchor issuer (Unix seconds).
	WitnessTimes      map[string]int64       `json:"witnessTimes"`
	Properties        VerificationProperties `json:"properties"`
	VerificationLevel string                 `json:"verificationLevel"`
	Checks            BundleChecks           `json:"checks"`
	Notes             []string               `json:"notes"`
}
type BundleVerifyOptions struct {
	SignaturePolicy   *AuditSignaturePolicy
	RequireSignatures bool
	TrustedRoot       string
	Anchors           []SignedAnchor
	AnchorPolicy      *AnchorPolicy
	ResolveAnchorKey  AnchorKeyResolver
	ExternalKeys      ExternalAnchorKeys
	// TrustedCheckpoint is the caller's record of the proof's checkpoint (its roots-file line). A single
	// proof carries no checkpoint, so without it no EXTERNAL anchor counts: the §5.3 time bound would be
	// measured against the anchor's own producer-chosen timestamp. Its Root stands in for TrustedRoot
	// when that is empty and must equal it otherwise; its EntryCount bounds the proof's leaf counts.
	TrustedCheckpoint *TrustedCheckpoint
}

// Retain the distinction between an absent legacy declaration and an explicit empty protocol.
func (b *ProofBundle) UnmarshalJSON(data []byte) error {
	type wire ProofBundle
	var value wire
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	var envelope struct {
		Protocol *string `json:"protocol"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	value.invalidProtocol = envelope.Protocol != nil && *envelope.Protocol == ""
	*b = ProofBundle(value)
	return nil
}

func check(pass *bool, detail string) CheckResult { return CheckResult{pass, detail} }
func bp(v bool) *bool                             { return &v }
func VerifyEmbeddedSignature(c AuditLeaf) bool {
	if c.SigAlg == nil || *c.SigAlg != "ES256" || c.SignerPublicKey == nil || c.Signature == nil || c.SignedPayload == nil {
		return false
	}
	der, e := base64.StdEncoding.DecodeString(*c.SignerPublicKey)
	if e != nil {
		return false
	}
	pub, e := parseSpkiP256(der)
	if e != nil {
		return false
	}
	sig, e := base64.StdEncoding.DecodeString(*c.Signature)
	if e != nil {
		return false
	}
	return verifyEcdsaSignature(pub, []byte(*c.SignedPayload), sig)
}
func DeriveVerificationLevel(p VerificationProperties, hasSigner bool) string {
	if !p.CommitmentVerified {
		return "INVALID"
	}
	if !p.ContentVerified {
		return "COMMITMENT_VERIFIED"
	}
	if p.AnchorVerified && (p.SignatureVerified || !hasSigner) {
		return "FULLY_VERIFIED"
	}
	if p.SignatureVerified {
		return "SIGNATURE_VERIFIED"
	}
	return "CONTENT_VERIFIED"
}

// DEWP §7/§12; numeric revisions 1 and 2 are accepted only for pre-envelope legacy exports.
func supportedEnvelope(protocol string, version interface{}, registry json.RawMessage) bool {
	if protocol != "" && protocol != "DEWP" {
		return false
	}
	validVersion := version == "1.0"
	if protocol == "" {
		switch v := version.(type) {
		case int:
			validVersion = v == 1 || v == 2
		case float64:
			validVersion = v == 1 || v == 2
		}
	}
	if !validVersion {
		return false
	}
	if len(registry) == 0 {
		return true
	}
	var a map[string]interface{}
	return json.Unmarshal(registry, &a) == nil && a["hashAlgorithm"] == "SHA-256" && a["serialization"] == "RFC8785-JCS" && a["merkleVersion"] == float64(1)
}

func VerifyBundle(b ProofBundle, o BundleVerifyOptions) BundleVerification {
	notes := []string{}
	kindBad := b.Kind != BundleKind || (b.invalidProtocol || !supportedEnvelope(b.Protocol, b.Version, b.AlgorithmRegistry))
	if kindBad {
		notes = append(notes, fmt.Sprintf("Refusing DEWP envelope (kind %q): unsupported kind, protocol, version or algorithm registry.", b.Kind))
	}
	unknown := b.Profile != "" && b.Profile != AuditProfile
	tc := o.TrustedCheckpoint
	root := o.TrustedRoot
	conflict := tc != nil && root != "" && tc.Root != root
	if conflict {
		notes = append(notes, "The supplied trusted checkpoint names a different root than the trusted root; refusing to pick one.")
	}
	if root == "" && tc != nil {
		root = tc.Root
	}
	source := "caller-supplied"
	if root == "" {
		source = "self-asserted"
		if b.Anchor != nil {
			root = b.Anchor.DailyRoot
		}
		if root == "" && b.LegacyAnchor != nil && b.LegacyAnchor.DailyRoot != nil {
			root = *b.LegacyAnchor.DailyRoot
		}
		if root == "" {
			root = b.Proof.CheckpointRoot
		}
		notes = append(notes, "No root supplied — verifying against the root inside the bundle; use a root obtained earlier or from the published roots file.")
	}
	var rp *string
	if root != "" {
		rp = &root
	} else {
		source = "none"
	}
	incl := root != "" && VerifyInclusionProof(b.Proof, root)
	if tc != nil && root == tc.Root {
		if m := LeafCountMismatch(b.Proof, tc.EntryCount); m != "" {
			incl = false
			notes = append(notes, m)
		}
	}
	cons := root != "" && b.Proof.CheckpointRoot == root
	ci := check(bp(incl), "inclusion proof verification")
	cr := check(bp(cons), "checkpoint root consistency")
	var leaf, header CheckResult
	content := false
	if b.Event.Canonical == nil {
		leaf = check(nil, "No canonical event preimage")
		header = check(nil, "No canonical preimage")
	} else if unknown {
		leaf = check(nil, "unknown canonical profile")
		header = check(bp(false), "unknown canonical profile")
	} else {
		h, e := LeafHash(*b.Event.Canonical)
		good := e == nil && h == b.Proof.Leaf
		leaf = check(bp(good), "leaf binding")
		hg := displayBundleMatches(b.Event, b.Proof)
		header = check(bp(hg), "displayed fields match committed preimage")
		content = incl && cons && good && hg
	}
	anchorOK := false
	witnessTimes := map[string]int64{}
	if o.AnchorPolicy != nil && root != "" {
		cands := o.Anchors
		if cands == nil {
			cands = append(cands, b.Anchors...)
			if b.Anchor != nil {
				cands = append(cands, *b.Anchor)
			}
		}
		// The caller's record is the only position and time an anchor over a single proof can be held
		// to; an empty expectation keeps external witnesses from counting without one.
		expected := &ExpectedCheckpoint{}
		if tc != nil {
			expected = &ExpectedCheckpoint{SeqStart: tc.SeqStart, SeqEnd: tc.SeqEnd, ChainHash: tc.ChainHash, AnchoredAt: tc.AnchoredAt}
		}
		q := VerifyAnchorQuorumFor(cands, root, *o.AnchorPolicy, o.ResolveAnchorKey, o.Anchors, o.ExternalKeys, expected)
		anchorOK = incl && cons && q.OK
		witnessTimes = q.WitnessTimes
		if q.Divergence {
			return BundleVerification{DailyRoot: rp, RootSource: source, WitnessTimes: witnessTimes, VerificationLevel: "INVALID", Notes: append(notes, q.Reason)}
		}
		if q.Reason != "" {
			notes = append(notes, q.Reason)
		}
		if q.Note != "" {
			notes = append(notes, q.Note)
		}
	}
	signature := uncheckedSignature()
	if content {
		signature = VerifyAuditSignature(*b.Event.Canonical, o.SignaturePolicy)
	}
	sig := signature.Status == "verified"
	p := VerificationProperties{incl && cons, content, sig, anchorOK}
	has := signature.Status != "not_applicable"
	level := DeriveVerificationLevel(p, has)
	if kindBad {
		level = "INVALID"
	}
	ok := !kindBad && !conflict && source == "caller-supplied" && incl && cons && (b.Event.Canonical == nil || content) && (o.AnchorPolicy == nil || anchorOK)
	return BundleVerification{
		OK: ok && (!o.RequireSignatures || (sig && signature.Trusted)), Signature: signature, DailyRoot: rp, RootSource: source, WitnessTimes: witnessTimes, Properties: p, VerificationLevel: level,
		Checks: BundleChecks{ci, cr, leaf, header, check(nil, "producer claim only")}, Notes: notes,
	}
}
func displayBundleMatches(e BundleEvent, p InclusionProof) bool {
	c := e.Canonical
	if c == nil {
		return true
	}
	eq := func(s string, v *string) bool { return v != nil && s == *v }
	ptrEq := func(v, c *string) bool { return v == nil || (c != nil && *v == *c) }
	return eq(e.Seq, c.Seq) && ptrEq(p.Seq, c.Seq) && eq(e.CreatedAt, c.CreatedAt) && eq(e.Type, c.Event) && eq(e.Outcome, c.Outcome) && (e.Detail == nil || (c.Detail != nil && *e.Detail == *c.Detail)) && ptrEq(e.SignerDID, c.SignerDid) && (e.Signature == nil || (c.Signature != nil && *e.Signature == *c.Signature)) && ptrEq(e.SigAlg, c.SigAlg)
}
