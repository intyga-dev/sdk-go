package verify

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"time"
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
	ID         string  `json:"id"`
	Root       string  `json:"root"`
	AnchorRef  *string `json:"anchorRef"`
	AnchoredAt *string `json:"anchoredAt"`
	SeqStart   string  `json:"seqStart"`
	SeqEnd     string  `json:"seqEnd"`
	// §5.4 chain fields: every anchor binds ChainHash (§5.2), and the verifier recomputes it.
	EntryCount    *int           `json:"entryCount,omitempty"`
	PrevChainHash *string        `json:"prevChainHash,omitempty"`
	ChainHash     *string        `json:"chainHash,omitempty"`
	Anchors       []SignedAnchor `json:"anchors,omitempty"`
}
type TenantSequenceCommitment struct {
	TenantID       string `json:"tenantId"`
	FirstTenantSeq string `json:"firstTenantSeq"`
	LastTenantSeq  string `json:"lastTenantSeq"`
}
type EvidenceBundle struct {
	invalidProtocol   bool
	Protocol          string          `json:"protocol,omitempty"`
	AlgorithmRegistry json.RawMessage `json:"algorithmRegistry,omitempty"`
	Kind              string          `json:"kind"`
	Version           interface{}     `json:"version"`
	Profile           string          `json:"profile,omitempty"`
	ExportedAt        string          `json:"exportedAt"`
	Tenant            struct {
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
	Root            string           `json:"root"`
	AnchorRef       *string          `json:"anchorRef"`
	AnchorVerified  *bool            `json:"anchorVerified"`
	VerifiedIssuers []string         `json:"verifiedIssuers"`
	WitnessTimes    map[string]int64 `json:"witnessTimes"`
}
type EvidenceFailure struct{ Seq, Reason string }
type EvidenceSignatures struct {
	Checks       []AuditEntrySignature
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
	// Execution is DEWP §4.7 over the content-verified entries: what caller-trusted sources observed,
	// never physical truth, and it never changes the properties above.
	Execution ExecutionVerification
	Notes     []string
}
type EvidenceVerifyOptions struct {
	SignaturePolicy   *AuditSignaturePolicy
	RequireSignatures bool
	TrustedRoots      []string
	// TrustedCheckpoints are checkpoint records YOU hold (chain-verified roots-file lines, DEWP §5.4.1).
	// Their roots are trusted roots; a bundle checkpoint over one must agree with it on every field
	// both state, and anchors are held to the record's range, chain hash and time (§5.3).
	TrustedCheckpoints  []TrustedCheckpoint
	Anchors             []SignedAnchor
	AnchorsByCheckpoint map[string][]SignedAnchor
	AnchorPolicy        *AnchorPolicy
	ResolveAnchorKey    AnchorKeyResolver
	ExternalKeys        ExternalAnchorKeys
	// EvidencePolicy is evidence-source trust for DEWP §4.7, separate from approver trust (§4.7.5).
	EvidencePolicy *ExecutionEvidencePolicy
	// RequireExecutionConfirmed fails the bundle unless it reports at least one approval nonce and
	// every one is confirmed.
	RequireExecutionConfirmed bool
	// ExecutionNow is the §4.7.4 evaluation time (nil: the current time).
	ExecutionNow *time.Time
	// EvidenceSkewSeconds is the §4.7.3 step 6 allowance before dispatch (nil: 30).
	EvidenceSkewSeconds *int
	// MaxEvidenceWindowSeconds bounds the §4.7.3 step 6 evidence window, so a Dispatch Record's own
	// far-out deadline cannot keep a nonce pending forever (nil: 86400).
	MaxEvidenceWindowSeconds *int
}

// Retain the distinction between an absent legacy declaration and an explicit empty protocol.
func (b *EvidenceBundle) UnmarshalJSON(data []byte) error {
	type wire EvidenceBundle
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
	*b = EvidenceBundle(value)
	return nil
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
	// Leaf-bound entries, the only ones §4.7 may read.
	contentEntries := []ExecutionEntry{}
	// Each content-verified entry's own checkpoint root, from its inclusion proof.
	entryRootBySeq := map[string]string{}
	if b.Kind != EvidenceBundleKind || (b.invalidProtocol || !supportedEnvelope(b.Protocol, b.Version, b.AlgorithmRegistry)) {
		r.Failed = append(r.Failed, EvidenceFailure{"-", fmt.Sprintf("refusing bundle kind %q", b.Kind)})
	}
	unknown := b.Profile != "" && b.Profile != AuditProfile
	trustedGiven := o.TrustedRoots != nil || o.TrustedCheckpoints != nil
	trusted := map[string]bool{}
	for _, x := range o.TrustedRoots {
		trusted[x] = true
	}
	records := map[string]TrustedCheckpoint{}
	for _, t := range o.TrustedCheckpoints {
		trusted[t.Root] = true
		if _, seen := records[t.Root]; !seen {
			records[t.Root] = t
		}
	}
	if !trustedGiven {
		r.Notes = append(r.Notes, "No roots supplied; use roots obtained earlier or from the published roots file")
	}
	// §5.4 chain fields, where carried: the chain hash every anchor binds must recompute.
	for _, c := range b.Checkpoints {
		if c.ChainHash == nil {
			continue
		}
		if c.PrevChainHash == nil || c.AnchoredAt == nil || c.EntryCount == nil {
			r.Failed = append(r.Failed, EvidenceFailure{"-", fmt.Sprintf("checkpoint %s chainHash lacks the fields it commits to", c.ID)})
			continue
		}
		want := ChainHash(ChainInput{PrevChainHash: *c.PrevChainHash, Root: c.Root, SeqStart: c.SeqStart, SeqEnd: c.SeqEnd, EntryCount: *c.EntryCount, AnchoredAt: *c.AnchoredAt})
		if want != *c.ChainHash {
			r.Failed = append(r.Failed, EvidenceFailure{"-", fmt.Sprintf("checkpoint %s chainHash does not recompute", c.ID)})
		}
	}
	// A checkpoint the caller holds a record for must agree with it on every field both state: a
	// re-dated anchoredAt with a self-consistent chain over a made-up predecessor recomputes above.
	strPtrDiffers := func(shown, held *string) bool { return shown != nil && held != nil && *shown != *held }
	for _, c := range b.Checkpoints {
		t, ok := records[c.Root]
		if !ok {
			continue
		}
		start, end := c.SeqStart, c.SeqEnd
		for _, d := range []struct {
			field   string
			differs bool
		}{
			{"seqStart", strPtrDiffers(&start, t.SeqStart)},
			{"seqEnd", strPtrDiffers(&end, t.SeqEnd)},
			{"entryCount", c.EntryCount != nil && t.EntryCount != nil && *c.EntryCount != *t.EntryCount},
			{"anchoredAt", strPtrDiffers(c.AnchoredAt, t.AnchoredAt)},
			{"chainHash", strPtrDiffers(c.ChainHash, t.ChainHash)},
		} {
			if d.differs {
				r.Failed = append(r.Failed, EvidenceFailure{"-", fmt.Sprintf("checkpoint %s %s contradicts your trusted checkpoint record for its root", c.ID, d.field)})
			}
		}
	}
	// One root, one checkpoint. A second entry for a root the bundle already lists — with a wider seq
	// range, or without the chain fields the first one is held to — would otherwise ride on the first
	// one's anchor verdict: anchors are checked against the FIRST checkpoint for a root, but a record's
	// anchored time (DEWP §4.7.5) would be looked up through whichever copy claimed to cover it.
	// Identical duplicates are tolerated; `anchors` and `anchorRef` are not part of the comparison.
	{
		seen := map[string]string{}
		shape := func(c EvidenceCheckpoint) string {
			s, _ := json.Marshal([]interface{}{c.ID, c.SeqStart, c.SeqEnd, c.EntryCount, c.AnchoredAt, c.ChainHash, c.PrevChainHash})
			return string(s)
		}
		for _, c := range b.Checkpoints {
			if prior, listed := seen[c.Root]; !listed {
				seen[c.Root] = shape(c)
			} else if prior != shape(c) {
				r.Failed = append(r.Failed, EvidenceFailure{"-", fmt.Sprintf("checkpoint %s lists a root the bundle already states with different fields", c.ID)})
			}
		}
	}
	// cp: root → the checkpoint that states it (first wins), for the anchors' expected position.
	// bundleAnchors: the bundle-carried anchors for a root (the last non-empty list wins), and
	// anchorRef the last stated — exactly as the TS reference keeps them.
	cp := map[string]EvidenceCheckpoint{}
	bundleAnchors := map[string][]SignedAnchor{}
	anchorRefs := map[string]*string{}
	ids := map[string]string{}
	for _, c := range b.Checkpoints {
		if _, listed := cp[c.Root]; !listed {
			cp[c.Root] = c
		}
		if len(c.Anchors) > 0 {
			bundleAnchors[c.Root] = c.Anchors
		}
		anchorRefs[c.Root] = c.AnchorRef
		ids[c.ID] = c.Root
	}
	// Roots last: a checkpoint whose id happens to equal another checkpoint's root must not shadow it.
	for _, c := range b.Checkpoints {
		ids[c.Root] = c.Root
	}
	// effective: the position and time anchors over a root are held to — the caller's record where it
	// states a field, the bundle's checkpoint otherwise.
	effective := func(root string) (ExpectedCheckpoint, *int) {
		c := cp[root]
		start, end := c.SeqStart, c.SeqEnd
		e := ExpectedCheckpoint{SeqStart: &start, SeqEnd: &end, ChainHash: c.ChainHash, AnchoredAt: c.AnchoredAt}
		count := c.EntryCount
		if t, ok := records[root]; ok {
			if t.SeqStart != nil {
				e.SeqStart = t.SeqStart
			}
			if t.SeqEnd != nil {
				e.SeqEnd = t.SeqEnd
			}
			if t.ChainHash != nil {
				e.ChainHash = t.ChainHash
			}
			if t.AnchoredAt != nil {
				e.AnchoredAt = t.AnchoredAt
			}
			if t.EntryCount != nil {
				count = t.EntryCount
			}
		}
		return e, count
	}
	var first, last *big.Int
	unbound, uncounted := false, false
	redactedCount := 0
	seenLeaf, seenSeq := map[string]bool{}, map[string]bool{}
	blockCounts, checkpointCounts := map[string]int{}, map[string]int{}
	for _, e := range b.Entries {
		seq := e.Event.Seq
		root := e.Proof.CheckpointRoot
		// One committed event appears once; a genuine leaf used twice can otherwise fill two holes.
		if seenLeaf[e.Proof.Leaf] || seenSeq[seq] {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "duplicate entry: this leaf or seq already appears in the bundle"})
			continue
		}
		seenLeaf[e.Proof.Leaf], seenSeq[seq] = true, true
		if _, ok := cp[root]; !ok {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "proof's checkpoint root is not in the bundle's checkpoint list"})
			continue
		}
		if trustedGiven && !trusted[root] {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "proof's checkpoint root is not among the supplied trusted roots"})
			continue
		}
		if !VerifyInclusionProof(e.Proof, root) {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "inclusion proof does not recompute to the daily root"})
			continue
		}
		// DEWP §17.3: leaf counts are prover-supplied; bind them to each other and to the entry count.
		prevBlock, hasBlock := blockCounts[e.Proof.BlockRoot]
		prevCp, hasCp := checkpointCounts[root]
		_, count := effective(root)
		if (hasBlock && prevBlock != e.Proof.BlockLeafCount) || (hasCp && prevCp != e.Proof.CheckpointLeafCount) {
			r.Failed = append(r.Failed, EvidenceFailure{seq, "proofs into the same block or checkpoint disagree on its leaf count"})
			continue
		}
		if m := LeafCountMismatch(e.Proof, count); m != "" {
			r.Failed = append(r.Failed, EvidenceFailure{seq, m})
			continue
		}
		blockCounts[e.Proof.BlockRoot], checkpointCounts[root] = e.Proof.BlockLeafCount, e.Proof.CheckpointLeafCount
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
		} else if unknown && e.Event.Canonical != nil {
			// A preimage cannot be bound under a layout this verifier does not implement, and passing it
			// would let the producer switch leaf binding off (DEWP §4.5/§7.2 rule 1).
			r.Failed = append(r.Failed, EvidenceFailure{seq, fmt.Sprintf("canonical preimage under unknown profile %q cannot be bound to its leaf", b.Profile)})
			continue
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
			// The redaction record is unsigned and is no counter source where a preimage exists (§7.2).
			if rc := e.Event.Redaction; rc != nil && rc.Commitment != nil && !matchesPtr(rc.Commitment.TenantSeq, c.TenantSeq) {
				r.Failed = append(r.Failed, EvidenceFailure{seq, "redaction record tenantSeq does not match the committed value"})
				continue
			}
			// A bundle naming no tenant (ID "") has none for a tenant-bound entry to belong to.
			if e.Event.Canonical.TenantID != nil && *e.Event.Canonical.TenantID != b.Tenant.ID {
				r.Failed = append(r.Failed, EvidenceFailure{seq, "entry belongs to another tenant"})
				continue
			}
			// §7.1 signatureVerified is checked below, once the anchor quorum has run: the leaf binding
			// above passed, so the signature is provably the committed one, and an evidence-source key
			// with a validity interval needs the record's anchored time (DEWP §4.7.5) to be placed in time.
			contentEntries = append(contentEntries, ExecutionEntry{seq, *e.Event.Canonical})
			entryRootBySeq[seq] = root
			r.ContentVerified++
		}
	}
	// Completeness is a separate check. An entry WITH a preimage reads its counter from it alone — a
	// null there means no counter (§7.2 rule 5); only an entry without one falls back to the unsigned
	// redaction record and display copy (rule 2).
	for _, e := range b.Entries {
		seq := e.Event.Seq
		var raw *string
		if e.Event.Canonical != nil {
			if unknown {
				continue // not leaf-bound under an unknown profile; that entry already failed
			}
			raw = e.Event.Canonical.TenantSeq
		} else {
			if e.Event.Redaction != nil && e.Event.Redaction.Commitment != nil {
				raw = e.Event.Redaction.Commitment.TenantSeq
			}
			if raw == nil {
				raw = e.Event.TenantSeq
			}
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
		r.Notes = append(r.Notes, "Unknown canonical profile; content cannot be bound to its leaf, so an entry carrying a preimage fails")
	}
	if redactedCount > 0 {
		r.Notes = append(r.Notes, "COMMITMENT_ONLY entries prove inclusion, not their displayed details")
	}
	if uncounted {
		r.Notes = append(r.Notes, "Some entries carry no tenantSeq; completeness cannot be checked across them")
	}
	if unbound {
		r.Notes = append(r.Notes, "Some entries carry no canonical preimage (COMMITMENT_ONLY), so their tenantSeq was read from the redaction record or display copy and is NOT covered by the Merkle leaf")
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
		rv := EvidenceRootVerification{Root: c.Root, AnchorRef: anchorRefs[c.Root], VerifiedIssuers: []string{}, WitnessTimes: map[string]int64{}}
		if o.AnchorPolicy != nil {
			cands := caller
			if len(cands) == 0 {
				cands = bundleAnchors[c.Root]
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
			expected, _ := effective(c.Root)
			// §5.3/§6.3: a checkpoint stating no chain hash or time (and no record supplying them) cannot
			// hold its anchors to anything, so it never counts as anchored. Divergence is still evaluated.
			positionUnknown := expected.ChainHash == nil || expected.AnchoredAt == nil
			if positionUnknown {
				r.Notes = append(r.Notes, fmt.Sprintf("checkpoint %s carries no chainHash/anchoredAt and no trusted checkpoint record supplies them; its anchors cannot be held to a position and time (DEWP §5.3), so it is not anchored", c.ID))
			}
			q := VerifyAnchorQuorumFor(cands, c.Root, *o.AnchorPolicy, o.ResolveAnchorKey, div, o.ExternalKeys, &expected)
			rv.AnchorVerified = bp(q.OK && !positionUnknown)
			rv.VerifiedIssuers = q.VerifiedIssuers
			if positionUnknown {
				rv.VerifiedIssuers = []string{}
			}
			rv.WitnessTimes = q.WitnessTimes
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
	if o.AnchorPolicy == nil {
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
	// DEWP §4.7.5: a record's anchored time is the earliest external witness time among the anchors
	// that COUNTED toward quorum for the checkpoint ITS OWN inclusion proof names, and only when its
	// seq lies within the range those anchors were held to. Only issuers in VerifiedIssuers counted;
	// a SELF/ES256 anchor has no witness time and contributes nothing. Never another checkpoint's
	// time: a listed checkpoint claiming a wider range would otherwise backdate every record under
	// it. Used solely to place a caller key's validity interval in time — never a self-claimed
	// `observedAt`/`sampledAt`.
	anchoredRootMs := map[string]int64{}
	for _, x := range r.Roots {
		if x.AnchorVerified == nil || !*x.AnchorVerified {
			continue
		}
		for _, issuer := range x.VerifiedIssuers {
			t, known := x.WitnessTimes[issuer]
			if !known {
				continue
			}
			if prior, seen := anchoredRootMs[x.Root]; !seen || t*1000 < prior {
				anchoredRootMs[x.Root] = t * 1000
			}
		}
	}
	seqNum := func(v *string) *big.Int {
		if v == nil || !digitsPattern.MatchString(*v) {
			return nil
		}
		n, _ := new(big.Int).SetString(*v, 10)
		return n
	}
	anchoredTime := func(seq string) (int64, bool) {
		root, known := entryRootBySeq[seq]
		if !known {
			return 0, false
		}
		t, anchored := anchoredRootMs[root]
		if !anchored {
			return 0, false
		}
		expected, _ := effective(root)
		s, lo, hi := seqNum(&seq), seqNum(expected.SeqStart), seqNum(expected.SeqEnd)
		if s == nil || lo == nil || hi == nil || s.Cmp(lo) < 0 || s.Cmp(hi) > 0 {
			return 0, false
		}
		return t, true
	}
	anchoredTimePtr := func(seq string) *int64 {
		ms, ok := anchoredTime(seq)
		if !ok {
			return nil
		}
		return &ms
	}
	// §7.1 signatureVerified per content-verified entry, with the anchored time now known, so the
	// §4.6.1 report and the §4.7.3 statement check agree on a bounded evidence-source key.
	bySeq := map[string]AuditSignatureCheck{}
	for _, e := range contentEntries {
		signature := VerifyAuditSignatureWithEvidence(e.Leaf, o.SignaturePolicy, o.EvidencePolicy, anchoredTimePtr(e.Seq))
		bySeq[e.Seq] = signature
		if signature.Status == "verified" {
			r.Signatures.Verified++
		} else if signature.Status == "invalid" {
			r.Signatures.Invalid = append(r.Signatures.Invalid, struct{ Seq string }{e.Seq})
		} else {
			r.Signatures.NotCheckable++
		}
	}
	for _, entry := range b.Entries {
		check, found := bySeq[entry.Event.Seq]
		if !found {
			check = uncheckedSignature()
		}
		r.Signatures.Checks = append(r.Signatures.Checks, AuditEntrySignature{entry.Event.Seq, check})
		if o.RequireSignatures && (check.Status != "verified" || !check.Trusted) {
			r.Failed = append(r.Failed, EvidenceFailure{entry.Event.Seq, "Required trusted signature: " + check.Reason})
		}
	}
	r.Execution = EvaluateExecutionEvidence(contentEntries, ExecutionEvaluationOptions{
		Policy: o.EvidencePolicy, Now: o.ExecutionNow, SkewSeconds: o.EvidenceSkewSeconds,
		MaxWindowSeconds: o.MaxEvidenceWindowSeconds, AnchoredTime: anchoredTime,
	})
	if o.RequireExecutionConfirmed {
		if len(r.Execution.ByNonce) == 0 {
			r.Failed = append(r.Failed, EvidenceFailure{"-", "Required confirmed execution: the bundle records no execution"})
		}
		nonces := make([]string, 0, len(r.Execution.ByNonce))
		for n := range r.Execution.ByNonce {
			nonces = append(nonces, n)
		}
		sort.Slice(nonces, func(i, j int) bool { return utf16Less(nonces[i], nonces[j]) })
		for _, n := range nonces {
			item := r.Execution.ByNonce[n]
			if item.Status != "confirmed" {
				seq := "-"
				if item.DispatchSeq != nil {
					seq = *item.DispatchSeq
				} else if len(item.EvidenceSeqs) > 0 {
					seq = item.EvidenceSeqs[0]
				}
				r.Failed = append(r.Failed, EvidenceFailure{seq, fmt.Sprintf("Required confirmed execution: nonce %s is %s", n, item.Status)})
			}
			// §4.7.4: a dispatch conflict means the executing party wrote two accounts of what it sent.
			if len(item.DispatchConflict) > 0 {
				r.Failed = append(r.Failed, EvidenceFailure{item.DispatchConflict[0], fmt.Sprintf("Required confirmed execution: nonce %s has conflicting Dispatch Records (seq %s)", n, strings.Join(item.DispatchConflict, ", "))})
			}
			// §4.7.4: a registered source signed a contradiction the status could not count — after the
			// window the executing party chose, or under a key the bundle cannot place in time. Neither
			// may clear a policy that requires confirmation.
			if len(item.LateContradiction) > 0 {
				r.Failed = append(r.Failed, EvidenceFailure{item.LateContradiction[0], fmt.Sprintf("Required confirmed execution: nonce %s has a late contradiction (seq %s)", n, strings.Join(item.LateContradiction, ", "))})
			}
			if len(item.UntrustedContradiction) > 0 {
				r.Failed = append(r.Failed, EvidenceFailure{item.UntrustedContradiction[0], fmt.Sprintf("Required confirmed execution: nonce %s has a contradiction under a provisioned key that established no trust (seq %s)", n, strings.Join(item.UntrustedContradiction, ", "))})
			}
		}
		// §4.7.3 source continuity: a gap or a divergence means the bundle does not carry the whole
		// account.
		sources := make([]string, 0, len(r.Execution.Sources))
		for s := range r.Execution.Sources {
			sources = append(sources, s)
		}
		sort.Slice(sources, func(i, j int) bool { return utf16Less(sources[i], sources[j]) })
		for _, s := range sources {
			c := r.Execution.Sources[s]
			if len(c.Gaps) > 0 {
				ranges := make([]string, 0, len(c.Gaps))
				for _, g := range c.Gaps {
					if g[0] == g[1] {
						ranges = append(ranges, strconv.FormatInt(g[0], 10))
					} else {
						ranges = append(ranges, fmt.Sprintf("%d–%d", g[0], g[1]))
					}
				}
				r.Failed = append(r.Failed, EvidenceFailure{"-", fmt.Sprintf("Required confirmed execution: source %s is missing statement(s) %s", s, strings.Join(ranges, ", "))})
			}
			if len(c.Divergent) > 0 {
				values := make([]string, 0, len(c.Divergent))
				for _, v := range c.Divergent {
					values = append(values, strconv.FormatInt(v, 10))
				}
				r.Failed = append(r.Failed, EvidenceFailure{"-", fmt.Sprintf("Required confirmed execution: source %s signed two statements under sequence %s", s, strings.Join(values, ", "))})
			}
		}
	}
	r.OK = len(r.Failed) == 0 && len(b.Entries) > 0 && trustedGiven && all
	return r
}
