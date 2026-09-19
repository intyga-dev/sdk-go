package verify

import (
	"fmt"
	"math/big"
	"sort"
)

type RedactionRecord struct {
	Mode          string   `json:"mode"`
	RemovedFields []string `json:"removedFields,omitempty"`
	RedactedAt    string   `json:"redactedAt,omitempty"`
	Reason        string   `json:"reason,omitempty"`
	Commitment    *struct {
		Leaf      string  `json:"leaf"`
		TenantSeq *string `json:"tenantSeq,omitempty"`
	} `json:"commitment,omitempty"`
}
type EvidenceEvent struct {
	Seq       string           `json:"seq"`
	CreatedAt string           `json:"createdAt"`
	Type      string           `json:"type"`
	Outcome   string           `json:"outcome"`
	Redaction *RedactionRecord `json:"redaction,omitempty"`
	Redacted  bool             `json:"redacted,omitempty"`
	TenantSeq *string          `json:"tenantSeq,omitempty"`
	SignerDID *string          `json:"signerDid"`
	SigAlg    *string          `json:"sigAlg"`
	Canonical *AuditLeaf       `json:"canonical,omitempty"`
}
type EvidenceEntry struct {
	Event EvidenceEvent  `json:"event"`
	Proof InclusionProof `json:"proof"`
}
type EvidenceCheckpoint struct {
	ID         string         `json:"id"`
	Root       string         `json:"root"`
	AnchorRef  *string        `json:"anchorRef"`
	AnchoredAt *string        `json:"anchoredAt"`
	SeqStart   string         `json:"seqStart"`
	SeqEnd     string         `json:"seqEnd"`
	Anchors    []SignedAnchor `json:"anchors,omitempty"`
}
type TenantSequenceCommitment struct {
	TenantID       string `json:"tenantId"`
	FirstTenantSeq string `json:"firstTenantSeq"`
	LastTenantSeq  string `json:"lastTenantSeq"`
}
type EvidenceBundle struct {
	Protocol   string      `json:"protocol,omitempty"`
	Kind       string      `json:"kind"`
	Version    interface{} `json:"version"`
	Profile    string      `json:"profile,omitempty"`
	ExportedAt string      `json:"exportedAt"`
	Tenant     struct {
		ID   string  `json:"id"`
		Name *string `json:"name"`
	} `json:"tenant"`
	Range struct {
		From string `json:"from"`
		To   string `json:"to"`
	} `json:"range"`
	TenantSequenceCommitment *TenantSequenceCommitment `json:"tenantSequenceCommitment,omitempty"`
	Entries                  []EvidenceEntry           `json:"entries"`
	Checkpoints              []EvidenceCheckpoint      `json:"checkpoints"`
}
type EvidenceRootVerification struct {
	Root            string   `json:"root"`
	AnchorRef       *string  `json:"anchorRef"`
	AnchorVerified  *bool    `json:"anchorVerified"`
	VerifiedIssuers []string `json:"verifiedIssuers"`
}
type EvidenceFailure struct{ Seq, Reason string }
type EvidenceSignatures struct {
	Verified     int
	Invalid      []struct{ Seq string }
	NotCheckable int
}
type EvidenceVerification struct {
	OK                                     bool
	Total, ContentVerified, CommitmentOnly int
	Failed                                 []EvidenceFailure
	Roots                                  []EvidenceRootVerification
	Signatures                             EvidenceSignatures
	Notes                                  []string
}
type EvidenceVerifyOptions struct {
	TrustedRoots        []string
	Anchors             []SignedAnchor
	AnchorsByCheckpoint map[string][]SignedAnchor
	AnchorPolicy        *AnchorPolicy
	ResolveAnchorKey    AnchorKeyResolver
	ExternalKeys        ExternalAnchorKeys
}

func parseCounter(s string) (*big.Int, bool) {
	digits := s
	if len(digits) > 0 && digits[0] == '-' {
		digits = digits[1:]
	}
	if len(digits) < 1 || len(digits) > 20 {
		return nil, false
	}
	for i, c := range []byte(s) {
		if (c < '0' || c > '9') && (i != 0 || c != '-') {
			return nil, false
		}
	}
	v, ok := new(big.Int).SetString(s, 10)
	return v, ok
}
func matchesPtr(got, want *string) bool {
	return got == nil || (want != nil && *got == *want)
}
func VerifyEvidenceBundle(b EvidenceBundle, o EvidenceVerifyOptions) EvidenceVerification {
	r := EvidenceVerification{Total: len(b.Entries), Failed: []EvidenceFailure{}, Notes: []string{}}
	if b.Kind != EvidenceBundleKind {
		r.Failed = append(r.Failed, EvidenceFailure{"-", fmt.Sprintf("refusing bundle kind %q", b.Kind)})
	}
	unknown := b.Profile != "" && b.Profile != AuditProfile
	trusted := map[string]bool{}
	for _, x := range o.TrustedRoots {
		trusted[x] = true
	}
	if o.TrustedRoots == nil {
		r.Notes = append(r.Notes, "No independent roots supplied")
	}
	cp := map[string]EvidenceCheckpoint{}
	ids := map[string]string{}
	for _, c := range b.Checkpoints {
		cp[c.Root] = c
		ids[c.ID] = c.Root
	}
	for _, c := range b.Checkpoints {
		ids[c.Root] = c.Root
	}
	var first, last *big.Int
	unbound, uncounted := false, false
	redactedCount := 0
	for _, e := range b.Entries {
		seq := e.Event.Seq
		root := e.Proof.CheckpointRoot
		if _, ok := cp[root]; !ok {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "proof's checkpoint root is not in the bundle's checkpoint list"})
			continue
		}
		if o.TrustedRoots != nil && !trusted[root] {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "proof's checkpoint root is not among the supplied trusted roots"})
			continue
		}
		if !VerifyInclusionProof(e.Proof, root) {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "inclusion proof does not recompute to the daily root"})
			continue
		}
		red := e.Event.Redacted
		if e.Event.Redaction != nil {
			red = e.Event.Redaction.Mode == "COMMITMENT_ONLY"
		}
		if red && e.Event.Canonical == nil {
			if e.Event.Redaction != nil && e.Event.Redaction.Commitment != nil && e.Event.Redaction.Commitment.Leaf != "" && e.Event.Redaction.Commitment.Leaf != e.Proof.Leaf {
				r.Failed = append(r.Failed, EvidenceFailure{seq, "redaction commitment leaf does not match the proof leaf"})
				continue
			}
			r.CommitmentOnly++
			redactedCount++
		} else if unknown {
			r.CommitmentOnly++
		} else if e.Event.Canonical == nil {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "unredacted entry is missing its canonical preimage"})
		} else {
			// Displayed headers are part of the exported evidence and must agree with
			// the committed canonical preimage; otherwise a valid leaf can be shown
			// with misleading event metadata.
			c := e.Event.Canonical
			matches := func(got string, want *string) bool { return want != nil && got == *want }
			if !matches(e.Event.Seq, c.Seq) || !matches(e.Event.CreatedAt, c.CreatedAt) ||
				!matches(e.Event.Type, c.Event) || !matches(e.Event.Outcome, c.Outcome) ||
				!matchesPtr(e.Event.TenantSeq, c.TenantSeq) ||
				!matchesPtr(e.Event.SignerDID, c.SignerDid) || !matchesPtr(e.Event.SigAlg, c.SigAlg) {
				r.Failed = append(r.Failed, EvidenceFailure{seq, "displayed event headers do not match canonical preimage"})
				continue
			}
			h, err := LeafHash(*e.Event.Canonical)
			if err != nil || h != e.Proof.Leaf {
				r.Failed = append(r.Failed, EvidenceFailure{seq, "leaf hash does not match the event content"})
				continue
			}
			if e.Event.Canonical.TenantID != nil && *e.Event.Canonical.TenantID != b.Tenant.ID {
				r.Failed = append(r.Failed, EvidenceFailure{seq, "entry belongs to another tenant"})
				continue
			}
			if VerifyEmbeddedSignature(*e.Event.Canonical) {
				r.Signatures.Verified++
			} else if e.Event.Canonical.SigAlg != nil && *e.Event.Canonical.SigAlg == "ES256" && e.Event.Canonical.Signature != nil && e.Event.Canonical.SignerPublicKey != nil {
				r.Signatures.Invalid = append(r.Signatures.Invalid, struct{ Seq string }{seq})
			} else {
				r.Signatures.NotCheckable++
			}
			r.ContentVerified++
		}
	}
	// Completeness is a separate check and reads committed counters before display fallbacks.
	for _, e := range b.Entries {
		seq := e.Event.Seq
		var raw *string
		if e.Event.Canonical != nil {
			raw = e.Event.Canonical.TenantSeq
		}
		if raw == nil && e.Event.Redaction != nil && e.Event.Redaction.Commitment != nil {
			raw = e.Event.Redaction.Commitment.TenantSeq
			unbound = unbound || raw != nil
		}
		if raw == nil {
			raw = e.Event.TenantSeq
			unbound = unbound || raw != nil
		}
		if raw == nil {
			uncounted = true
		}
		if raw != nil {
			cur, ok := parseCounter(*raw)
			if !ok {
				r.Failed = append(r.Failed, EvidenceFailure{seq, "tenantSeq is not a valid integer counter"})
			} else {
				if first == nil {
					first = new(big.Int).Set(cur)
				}
				if last != nil {
					want := new(big.Int).Add(last, big.NewInt(1))
					if cur.Cmp(want) != 0 {
						r.Failed = append(r.Failed, EvidenceFailure{seq, "per-tenant sequence is not contiguous"})
					}
				}
				last = new(big.Int).Set(cur)
			}
		}
	}
	if unknown {
		r.Notes = append(r.Notes, "Unknown canonical profile; content cannot be bound to its leaf")
	}
	if redactedCount > 0 {
		r.Notes = append(r.Notes, "COMMITMENT_ONLY entries prove inclusion, not their displayed details")
	}
	if uncounted {
		r.Notes = append(r.Notes, "Some entries carry no tenantSeq; completeness cannot be checked across them")
	}
	if unbound {
		r.Notes = append(r.Notes, "Some entries' tenantSeq is NOT covered by the Merkle leaf")
	}
	if c := b.TenantSequenceCommitment; c != nil && first != nil && last != nil {
		cf, a := parseCounter(c.FirstTenantSeq)
		cl, z := parseCounter(c.LastTenantSeq)
		if !a || !z || cf.Cmp(first) != 0 || cl.Cmp(last) != 0 {
			r.Failed = append(r.Failed, EvidenceFailure{"-", "tenantSequenceCommitment does not match entries"})
		}
		if c.TenantID != b.Tenant.ID {
			r.Notes = append(r.Notes, "tenantSequenceCommitment names another tenant")
		}
	}
	caller := append([]SignedAnchor{}, o.Anchors...)
	attributed := map[string][]SignedAnchor{}
	if o.AnchorsByCheckpoint != nil && o.Anchors != nil {
		r.Failed = append(r.Failed, EvidenceFailure{"-", "choose keyed or flat caller anchors"})
	}
	for key, list := range o.AnchorsByCheckpoint {
		caller = append(caller, list...)
		if root, ok := ids[key]; ok {
			attributed[root] = append(attributed[root], list...)
		} else if len(list) > 0 {
			r.Notes = append(r.Notes, "Some caller anchor keys identify no checkpoint; those anchors cannot establish divergence")
		}
	}
	for _, c := range cp {
		rv := EvidenceRootVerification{Root: c.Root, AnchorRef: c.AnchorRef, VerifiedIssuers: []string{}}
		if o.AnchorPolicy != nil && o.ResolveAnchorKey != nil {
			cands := caller
			if len(cands) == 0 {
				cands = c.Anchors
			}
			div := []SignedAnchor{}
			if o.AnchorsByCheckpoint != nil {
				div = attributed[c.Root]
			} else {
				for _, a := range caller {
					_, known := cp[a.DailyRoot]
					if a.DailyRoot == c.Root || !known {
						div = append(div, a)
					}
				}
			}
			q := VerifyAnchorQuorum(cands, c.Root, *o.AnchorPolicy, o.ResolveAnchorKey, div, o.ExternalKeys)
			rv.AnchorVerified = bp(q.OK)
			rv.VerifiedIssuers = q.VerifiedIssuers
			if q.Divergence {
				r.Failed = append(r.Failed, EvidenceFailure{"-", "ANCHOR DIVERGENCE: " + q.Reason})
			} else if !q.OK {
				r.Notes = append(r.Notes, q.Reason)
			}
			if q.Note != "" {
				r.Notes = append(r.Notes, q.Note)
			}
		}
		r.Roots = append(r.Roots, rv)
	}
	if o.AnchorPolicy == nil || o.ResolveAnchorKey == nil {
		r.Notes = append(r.Notes, "Both anchor policy and key resolver are required to evaluate root signatures")
	}
	if len(caller) == 0 && o.AnchorPolicy != nil {
		r.Notes = append(r.Notes, "Bundle-carried anchors may count under caller-trusted keys; divergence requires independently fetched anchors")
	}
	if o.AnchorsByCheckpoint == nil && len(caller) > 0 && len(cp) > 1 {
		r.Notes = append(r.Notes, "Flat anchors cannot establish exact checkpoint attribution; key anchors by checkpoint ID or root")
	}
	sort.Slice(r.Roots, func(i, j int) bool { return r.Roots[i].Root < r.Roots[j].Root })
	all := true
	if o.AnchorPolicy != nil {
		for _, x := range r.Roots {
			if x.AnchorVerified == nil || !*x.AnchorVerified {
				all = false
			}
		}
	}
	r.OK = len(r.Failed) == 0 && len(b.Entries) > 0 && o.TrustedRoots != nil && all
	return r
}
