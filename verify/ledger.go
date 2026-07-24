package verify

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// DEWP audit-ledger verification (docs/DEWP.md) — Go port. Byte-identical to @sakra-trust/verify
// (ledger-*.ts) and the Python/Rust ports, locked by packages/mcp-schemas/vectors/ledger-vectors.json.
//
// Domain separation: 0x00 leaf, 0x01 node, 0x02 empty root, 0x03 anchor. Node children are hex-decoded
// to raw bytes before hashing; the leaf `metadata` element is a JCS (sorted-key) string.

// jsonMarshalNoEscape marshals like JS JSON.stringify: compact, and WITHOUT Go's default HTML escaping
// of <, >, & (which JSON.stringify does not do). Go already sorts map keys, matching JCS for ASCII keys.
func jsonMarshalNoEscape(v interface{}) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	// Encoder appends a trailing newline; trim it.
	return string(bytes.TrimRight(buf.Bytes(), "\n"))
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

// VerifyMerkleProof recomputes the root from a leaf + its leaf→root proof.
func VerifyMerkleProof(leaf string, proof []LedgerProofStep, root string) bool {
	h := leaf
	for _, step := range proof {
		if step.SiblingPosition == "LEFT" {
			h = HashPair(step.SiblingHash, h)
		} else {
			h = HashPair(h, step.SiblingHash)
		}
	}
	return h == root
}

// AuditLeaf is the DEWP sakra.v1 profile row (18 fields, tenantSeq last). Pointers are nullable.
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
func CanonicalPreimage(row AuditLeaf) string {
	var metadataStr string
	if row.Metadata == nil {
		metadataStr = "null"
	} else {
		metadataStr = jsonMarshalNoEscape(row.Metadata) // Go sorts map keys → JCS for ASCII
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
	return jsonMarshalNoEscape(arr)
}

// LeafHash over the full row content.
func LeafHash(row AuditLeaf) string {
	return HashLeaf(CanonicalPreimage(row))
}

// InclusionProof is a two-hop DEWP proof.
type InclusionProof struct {
	Leaf            string            `json:"leaf"`
	BlockRoot       string            `json:"blockRoot"`
	BlockProof      []LedgerProofStep `json:"blockProof"`
	CheckpointProof []LedgerProofStep `json:"checkpointProof"`
	CheckpointRoot  string            `json:"checkpointRoot"`
}

// VerifyInclusionProof: leaf → block root, then hashLeaf(block root) → daily root.
func VerifyInclusionProof(proof InclusionProof, dailyRoot string) bool {
	if !VerifyMerkleProof(proof.Leaf, proof.BlockProof, proof.BlockRoot) {
		return false
	}
	return VerifyMerkleProof(HashLeaf(proof.BlockRoot), proof.CheckpointProof, dailyRoot)
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
	return jsonMarshalNoEscape([]string{a.DailyRoot, a.Timestamp, a.Issuer, a.Algorithm})
}

// AnchorDigestHex: sha256(0x03 || UTF8(AnchorPreimage)).
func AnchorDigestHex(a AnchorInput) string {
	return ledgerSha256Hex(append([]byte{0x03}, []byte(AnchorPreimage(a))...))
}
