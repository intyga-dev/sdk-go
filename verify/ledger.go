package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// DEWP audit-ledger verification (docs/DEWP.md) — Go port. Byte-identical to @intyga/verify
// (ledger-*.ts) and the Python/Rust ports, locked by packages/mcp-schemas/vectors/ledger-vectors.json.
//
// Domain separation: 0x00 leaf, 0x01 node, 0x02 empty root, 0x03 anchor. Node children are hex-decoded
// to raw bytes before hashing; the leaf `metadata` element is a JCS (sorted-key) string.

// jsonMarshalNoEscape marshals like JS JSON.stringify: compact, and WITHOUT Go's default HTML escaping
// of <, >, & (which JSON.stringify does not do). Go already sorts map keys, matching JCS for ASCII keys.
//
// NOTE: this is still not a faithful JSON.stringify for STRINGS — encoding/json also escapes U+2028
// and U+2029 unconditionally, which SetEscapeHTML does not control. Use jsMarshalString for any
// string or object key that must be byte-identical to the other ports.
func jsonMarshalNoEscape(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	// Encoder appends a trailing newline; trim it.
	return string(bytes.TrimRight(buf.Bytes(), "\n"))
}

// jsMarshalString serializes a string exactly as JS JSON.stringify does, which is what RFC 8785
// requires: escape only `"` and `\` plus the C0 control range, and emit everything else literally.
//
// Go's encoding/json differs on FIVE characters — <, > and & (SetEscapeHTML) and U+2028/U+2029
// (never configurable, escaped for JSONP safety). All five appear in ordinary approval text: a URL
// query string, "Acme & Co", "<redacted>", or a line separator pasted into a description. Each one
// made this port recompute different bytes than the TS/Rust/Python verifiers and report a valid
// approval as tampering.
func jsMarshalString(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func ledgerSha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// HashLeaf: sha256(0x00 || UTF8(preimage)).
func HashLeaf(preimage string) string {
	return ledgerSha256Hex(append([]byte{0x00}, []byte(preimage)...))
}

// HashPair: sha256(0x01 || rawBytes(left) || rawBytes(right)). Order encodes position.
func HashPair(leftHex, rightHex string) string {
	l, _ := hex.DecodeString(leftHex)
	r, _ := hex.DecodeString(rightHex)
	buf := append([]byte{0x01}, l...)
	buf = append(buf, r...)
	return ledgerSha256Hex(buf)
}

// EmptyRoot: sha256(0x02) (DEWP §5.1.1).
func EmptyRoot() string {
	return ledgerSha256Hex([]byte{0x02})
}

// MerkleRoot over ordered leaves (duplicate-last on odd levels). Empty ⇒ EmptyRoot().
func MerkleRoot(leaves []string) string {
	if len(leaves) == 0 {
		return EmptyRoot()
	}
	level := leaves
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			left := level[i]
			right := left // duplicate-last
			if i+1 < len(level) {
				right = level[i+1]
			}
			next = append(next, HashPair(left, right))
		}
		level = next
	}
	return level[0]
}

// LedgerProofStep is one leaf→root Merkle path step (DEWP §5.1.6).
type LedgerProofStep struct {
	SiblingHash     string `json:"siblingHash"`
	SiblingPosition string `json:"siblingPosition"` // "LEFT" | "RIGHT"
}

// ProofBounds is the leaf's position and its tree's leaf count. REQUIRED, per DEWP §3 invariant 3
// ("The bounds are REQUIRED, not advisory") and §11.1. They turn "is there SOME path from this leaf
// to this root" into "is this leaf at this position".
type ProofBounds struct {
	Index     int
	LeafCount int
}

// ExpectedPathLength is the audit-path length for a duplicate-last tree of leafCount leaves:
// ceil(log2(n)), or 0 when n <= 1 (DEWP §11.1 check 2).
func ExpectedPathLength(leafCount int) int {
	if leafCount <= 1 {
		return 0
	}
	n := 0
	for size := leafCount; size > 1; size = (size + 1) / 2 {
		n++
	}
	return n
}

// isHash64 reports whether s is exactly 64 lowercase hex characters (DEWP §4.4). Go's
// hex.DecodeString error was previously discarded, so a malformed sibling silently hashed whatever
// prefix decoded and distinct proof strings collapsed to the same bytes.
func isHash64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// VerifyMerkleProof recomputes the root from a leaf + its leaf→root proof, bounded by the leaf's
// position (DEWP §11.2 reference implementation).
//
// Bounds are what make this a proof of MEMBERSHIP rather than a proof that A path exists. This tree
// pads an unpaired trailing node by hashing it against ITSELF, so MerkleRoot([a,b,c]) equals
// MerkleRoot([a,b,c,c]) and a path built for the nonexistent index 3 recomputes the 3-leaf root
// exactly. DEWP §11.1 states outright that an implementation stopping at root recomputation is
// non-conformant — this port did exactly that, and its own golden vector encoded the gap.
func VerifyMerkleProof(leaf string, proof []LedgerProofStep, root string, bounds ProofBounds) bool {
	if !isHash64(leaf) || !isHash64(root) {
		return false
	}
	if bounds.LeafCount < 1 || bounds.Index < 0 || bounds.Index >= bounds.LeafCount {
		return false
	}
	if len(proof) != ExpectedPathLength(bounds.LeafCount) {
		return false
	}
	idx := bounds.Index
	levelSize := bounds.LeafCount
	node := leaf
	for _, step := range proof {
		if !isHash64(step.SiblingHash) {
			return false
		}
		// The side follows from the index; a prover-chosen side would restore the flexibility the
		// length check just removed.
		expectedSide := "RIGHT"
		if idx%2 == 1 {
			expectedSide = "LEFT"
		}
		if step.SiblingPosition != expectedSide {
			return false
		}
		// Self-pairing is legitimate ONLY at the unpaired end of an odd-sized level. Anywhere else it
		// is the signature of an index pointing into padding — this is the check that actually closes
		// the forgery, because LeafCount arrives inside the proof and a prover can inflate it.
		selfPaired := step.SiblingHash == node
		legitimatelyUnpaired := idx == levelSize-1 && levelSize%2 == 1
		if selfPaired && !legitimatelyUnpaired {
			return false
		}
		if step.SiblingPosition == "LEFT" {
			node = HashPair(step.SiblingHash, node)
		} else {
			node = HashPair(node, step.SiblingHash)
		}
		idx /= 2
		levelSize = (levelSize + 1) / 2
	}
	return node == root
}

// AuditLeaf is the DEWP intyga.v1 profile row (18 fields, tenantSeq last). Pointers are nullable.
type AuditLeaf struct {
	Seq             *string     `json:"seq"`
	TenantSeq       *string     `json:"tenantSeq"`
	CreatedAt       *string     `json:"createdAt"`
	Event           *string     `json:"event"`
	Outcome         *string     `json:"outcome"`
	Detail          *string     `json:"detail"`
	Metadata        interface{} `json:"metadata"`
	SignerDid       *string     `json:"signerDid"`
	SignerPublicKey *string     `json:"signerPublicKey"`
	SignedPayload   *string     `json:"signedPayload"`
	Signature       *string     `json:"signature"`
	SigAlg          *string     `json:"sigAlg"`
	IsBillable      bool        `json:"isBillable"`
	TenantID        *string     `json:"tenantId"`
	ActorNodeID     *string     `json:"actorNodeId"`
	SubjectNodeID   *string     `json:"subjectNodeId"`
	EdgeID          *string     `json:"edgeId"`
	ChallengeID     *string     `json:"challengeId"`
}

// str returns the value pointed to, or a JSON null placeholder handled by the array marshal.
func nullable(p *string) interface{} {
	if p == nil {
		return nil
	}
	return *p
}

// CanonicalPreimage: the 18-element JCS array. metadata is embedded as its own JCS string.
//
// Errors when metadata carries a number StableStringify refuses as non-portable (DEWP §4.3.1: the
// portable range is |x| < 1e16 for integers, 1e-4 <= |x| < 1e16 otherwise, and never -0).
//
// A conformant producer never commits such a value — the reference producer refuses at ingestion
// (assertPortableJson in packages/db) — so this path is reachable only for a foreign or legacy
// leaf. The spec permits either response, and the ports deliberately differ: this one refuses,
// which surfaces "I cannot canonicalize this" instead of a hash the TS/Rust/Python verifiers would
// compute differently; those three best-effort match the TS reference and report a plain mismatch.
// Neither is a bug in the other. What would be a bug is a port that computes a hash it believes the
// others share when they do not.
func CanonicalPreimage(row AuditLeaf) (string, error) {
	var metadataStr string
	if row.Metadata == nil {
		metadataStr = "null"
	} else {
		s, err := StableStringify(row.Metadata) // sorted keys (JCS) + JS-compatible escaping
		if err != nil {
			return "", err
		}
		metadataStr = s
	}
	arr := []interface{}{
		nullable(row.Seq),
		nullable(row.CreatedAt),
		nullable(row.Event),
		nullable(row.Outcome),
		nullable(row.Detail),
		metadataStr,
		nullable(row.SignerDid),
		nullable(row.SignerPublicKey),
		nullable(row.SignedPayload),
		nullable(row.Signature),
		nullable(row.SigAlg),
		row.IsBillable,
		nullable(row.TenantID),
		nullable(row.ActorNodeID),
		nullable(row.SubjectNodeID),
		nullable(row.EdgeID),
		nullable(row.ChallengeID),
		nullable(row.TenantSeq),
	}
	// StableStringify, not encoding/json: `detail`, `signedPayload` and the DIDs are free text and
	// routinely contain the five characters Go escapes and JS does not.
	return StableStringify(arr)
}

// LeafHash over the full row content. Errors only when CanonicalPreimage does.
func LeafHash(row AuditLeaf) (string, error) {
	preimage, err := CanonicalPreimage(row)
	if err != nil {
		return "", err
	}
	return HashLeaf(preimage), nil
}

// InclusionProof is a two-hop DEWP proof. The four position fields are REQUIRED by the normative
// inclusion-proof JSON Schema and by DEWP §3 invariant 3; a proof that cannot say where its leaf
// sits does not establish inclusion.
type InclusionProof struct {
	Leaf       string            `json:"leaf"`
	BlockRoot  string            `json:"blockRoot"`
	BlockProof []LedgerProofStep `json:"blockProof"`
	// LeafIndex is this event's position within its block, and BlockLeafCount that block's size.
	LeafIndex       int               `json:"leafIndex"`
	BlockLeafCount  int               `json:"blockLeafCount"`
	CheckpointProof []LedgerProofStep `json:"checkpointProof"`
	// CheckpointLeafIndex is the block root's position in the daily tree, and CheckpointLeafCount
	// that tree's size.
	CheckpointLeafIndex int    `json:"checkpointLeafIndex"`
	CheckpointLeafCount int    `json:"checkpointLeafCount"`
	CheckpointRoot      string `json:"checkpointRoot"`
}

// VerifyInclusionProof: leaf → block root, then hashLeaf(block root) → daily root, each hop bounded
// by its position (DEWP §3 invariant 3, steps 1 and 2).
func VerifyInclusionProof(proof InclusionProof, dailyRoot string) bool {
	if !VerifyMerkleProof(proof.Leaf, proof.BlockProof, proof.BlockRoot,
		ProofBounds{Index: proof.LeafIndex, LeafCount: proof.BlockLeafCount}) {
		return false
	}
	return VerifyMerkleProof(HashLeaf(proof.BlockRoot), proof.CheckpointProof, dailyRoot,
		ProofBounds{Index: proof.CheckpointLeafIndex, LeafCount: proof.CheckpointLeafCount})
}

// AnchorInput is the signable part of an anchor (DEWP §5.2).
type AnchorInput struct {
	DailyRoot string `json:"dailyRoot"`
	Timestamp string `json:"timestamp"`
	Issuer    string `json:"issuer"`
	Algorithm string `json:"algorithm"`
}

// AnchorPreimage: JCS of [dailyRoot, timestamp, issuer, algorithm].
func AnchorPreimage(a AnchorInput) string {
	// `issuer` is a URL and can carry a query string, so it needs JS-compatible string escaping too.
	// All four elements are strings, so StableStringify's non-portable-number refusal is
	// structurally unreachable here and the error can be discarded.
	s, _ := StableStringify([]interface{}{a.DailyRoot, a.Timestamp, a.Issuer, a.Algorithm})
	return s
}

// anchorDigest: the RAW 32-byte anchor digest, sha256(0x03 || UTF8(AnchorPreimage)). These bytes —
// never their hex text — are the message an anchor issuer signs (DEWP §5.2).
func anchorDigest(a AnchorInput) [32]byte {
	return sha256.Sum256(append([]byte{0x03}, []byte(AnchorPreimage(a))...))
}

// AnchorDigestHex: sha256(0x03 || UTF8(AnchorPreimage)).
func AnchorDigestHex(a AnchorInput) string {
	d := anchorDigest(a)
	return hex.EncodeToString(d[:])
}

// SignedAnchor is an anchor plus its issuer's signature over the raw anchor digest (DEWP §5.2).
type SignedAnchor struct {
	AnchorInput
	KeyID string `json:"keyId"`
	// Signature is base64 ECDSA over the RAW 32-byte anchor digest, in ASN.1/DER (what producers
	// emit, DEWP §5.2) or raw IEEE-P1363 r‖s (what WebCrypto issuers can only emit).
	Signature string `json:"signature"`
}

// VerifyAnchorSignature verifies one anchor's ES256 signature against a base64 SPKI P-256 public
// key the CALLER resolved from its own trust policy. Core Profile scope, deliberately: single
// anchor, ES256 only — no Ed25519/RSA-PSS, and no §5.3 quorum or issuer-trust evaluation, so
// `anchorVerified` still cannot be established by this port alone. Use the TS reference for those.
//
// The signed MESSAGE is the raw 32-byte digest, never its 64-character hex text; ES256 then applies
// its own SHA-256 internally. An implementation that signs the hex matches every digest vector and
// still fails to interoperate — that is the §5.2 trap the shared signedAnchor vectors exist to catch.
//
// Both DER and raw P1363 are accepted, matching the receipt path and DEWP §5.2. This port used to be
// DER-only on the deliberate reasoning that DER is what the TS producer emits — sound for OUR
// anchors, wrong for the case §5.3 exists to serve: an INDEPENDENT issuer, which may well sign with
// WebCrypto, and WebCrypto emits only P1363. Refusing those meant a genuine third-party anchor
// counted toward quorum for a TS/Rust/Python relying party and read as an invalid signature here.
func VerifyAnchorSignature(anchor SignedAnchor, spkiB64 string) bool {
	if anchor.Algorithm != "ES256" {
		return false
	}
	keyDER, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return false
	}
	pub, err := parseSpkiP256(keyDER)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(anchor.Signature)
	if err != nil {
		return false
	}
	digest := anchorDigest(anchor.AnchorInput)
	return verifyEcdsaSignature(pub, digest[:], sig)
}
