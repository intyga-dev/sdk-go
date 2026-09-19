package verify

import (
	"encoding/base64"
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
	Protocol     string         `json:"protocol,omitempty"`
	Kind         string         `json:"kind"`
	Version      interface{}    `json:"version"`
	Profile      string         `json:"profile,omitempty"`
	ExportedAt   string         `json:"exportedAt"`
	Event        BundleEvent    `json:"event"`
	Proof        InclusionProof `json:"proof"`
	Anchor       *SignedAnchor  `json:"anchor,omitempty"`
	Anchors      []SignedAnchor `json:"anchors,omitempty"`
	AnchorRef    *string        `json:"anchorRef,omitempty"`
	Anchored     *bool          `json:"anchored,omitempty"`
	LegacyAnchor *struct {
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
	OK                bool                   `json:"ok"`
	DailyRoot         *string                `json:"dailyRoot"`
	RootSource        string                 `json:"rootSource"`
	Properties        VerificationProperties `json:"properties"`
	VerificationLevel string                 `json:"verificationLevel"`
	Checks            BundleChecks           `json:"checks"`
	Notes             []string               `json:"notes"`
}
type BundleVerifyOptions struct {
	TrustedRoot      string
	Anchors          []SignedAnchor
	AnchorPolicy     *AnchorPolicy
	ResolveAnchorKey AnchorKeyResolver
	ExternalKeys     ExternalAnchorKeys
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
func VerifyBundle(b ProofBundle, o BundleVerifyOptions) BundleVerification {
	notes := []string{}
	kindBad := b.Kind != BundleKind
	if kindBad {
		notes = append(notes, fmt.Sprintf("Refusing bundle kind %q (expected %q) — DEWP §6.5.", b.Kind, BundleKind))
	}
	unknown := b.Profile != "" && b.Profile != AuditProfile
	root := o.TrustedRoot
	source := "independent"
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
		notes = append(notes, "No independent root supplied — verifying against the root inside the bundle.")
	}
	var rp *string
	if root != "" {
		rp = &root
	} else {
		source = "none"
	}
	incl := root != "" && VerifyInclusionProof(b.Proof, root)
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
	if o.AnchorPolicy != nil && o.ResolveAnchorKey != nil && root != "" {
		cands := o.Anchors
		if cands == nil {
			cands = append(cands, b.Anchors...)
			if b.Anchor != nil {
				cands = append(cands, *b.Anchor)
			}
		}
		q := VerifyAnchorQuorum(cands, root, *o.AnchorPolicy, o.ResolveAnchorKey, o.Anchors, o.ExternalKeys)
		anchorOK = incl && cons && q.OK
		if q.Divergence {
			return BundleVerification{DailyRoot: rp, RootSource: source, VerificationLevel: "INVALID", Notes: append(notes, q.Reason)}
		}
		if q.Reason != "" {
			notes = append(notes, q.Reason)
		}
	}
	has := b.Event.Canonical != nil && b.Event.Canonical.Signature != nil && *b.Event.Canonical.Signature != "" && b.Event.Canonical.SignerPublicKey != nil && *b.Event.Canonical.SignerPublicKey != ""
	sig := content && VerifyEmbeddedSignature(*b.Event.Canonical)
	p := VerificationProperties{incl && cons, content, sig, anchorOK}
	level := DeriveVerificationLevel(p, has)
	if kindBad {
		level = "INVALID"
	}
	ok := !kindBad && source == "independent" && incl && cons && (b.Event.Canonical == nil || content) && (o.AnchorPolicy == nil || anchorOK)
	return BundleVerification{ok, rp, source, p, level, BundleChecks{ci, cr, leaf, header, check(nil, "producer claim only")}, notes}
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
