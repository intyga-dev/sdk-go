package verify

import (
	"fmt"
	"math/big"
)

const ChainTag byte = 0x04
const GenesisPrevChainHash = ""

type RootsChainEntry struct {
	SeqStart      string  `json:"seqStart"`
	SeqEnd        string  `json:"seqEnd"`
	EntryCount    int     `json:"entryCount"`
	Root          string  `json:"root"`
	AnchoredAt    string  `json:"anchoredAt"`
	PrevChainHash *string `json:"prevChainHash,omitempty"`
	ChainHash     *string `json:"chainHash,omitempty"`
}
type ChainInput struct {
	PrevChainHash, Root, SeqStart, SeqEnd string
	EntryCount                            int
	AnchoredAt                            string
}

func ChainPreimage(c ChainInput) string {
	s, _ := StableStringify([]interface{}{c.PrevChainHash, c.Root, c.SeqStart, c.SeqEnd, fmt.Sprint(c.EntryCount), c.AnchoredAt})
	return s
}
func ChainHash(c ChainInput) string {
	return ledgerSha256Hex(append([]byte{ChainTag}, []byte(ChainPreimage(c))...))
}

type ChainVerification struct {
	OK            bool   `json:"ok"`
	VerifiedCount int    `json:"verifiedCount"`
	BrokenAt      int    `json:"brokenAt"`
	Unchained     bool   `json:"unchained"`
	Reason        string `json:"reason,omitempty"`
}

func VerifyRootsChain(es []RootsChainEntry) ChainVerification {
	if len(es) == 0 {
		return ChainVerification{OK: true, BrokenAt: -1}
	}
	n := 0
	for _, e := range es {
		if e.ChainHash != nil {
			n++
		}
	}
	if n == 0 {
		return ChainVerification{BrokenAt: -1, Unchained: true, Reason: "roots file carries no chain hashes (pre-DEWP-5.4 v1 file); continuity cannot be checked"}
	}
	if n != len(es) {
		// Report the FIRST unchained index, not a hardcoded 0 — brokenAt is how an operator
		// locates the splice, and entry 0 of a spliced file is usually intact.
		at := 0
		for i, e := range es {
			if e.ChainHash == nil {
				at = i
				break
			}
		}
		return ChainVerification{BrokenAt: at, Reason: "roots file mixes chained and unchained entries"}
	}
	prev := ""
	var prevEnd *big.Int
	for i, e := range es {
		decl := ""
		if e.PrevChainHash != nil {
			decl = *e.PrevChainHash
		}
		if decl != prev {
			return ChainVerification{VerifiedCount: i, BrokenAt: i, Reason: "chain link broken"}
		}
		if ChainHash(ChainInput{decl, e.Root, e.SeqStart, e.SeqEnd, e.EntryCount, e.AnchoredAt}) != *e.ChainHash {
			return ChainVerification{VerifiedCount: i, BrokenAt: i, Reason: "chain hash mismatch"}
		}
		start, ok1 := new(big.Int).SetString(e.SeqStart, 10)
		end, ok2 := new(big.Int).SetString(e.SeqEnd, 10)
		if !ok1 || !ok2 {
			return ChainVerification{VerifiedCount: i, BrokenAt: i, Reason: "non-integer seq range"}
		}
		if end.Cmp(start) < 0 {
			return ChainVerification{VerifiedCount: i, BrokenAt: i, Reason: "seq range inverted"}
		}
		if prevEnd != nil && start.Cmp(prevEnd) <= 0 {
			return ChainVerification{VerifiedCount: i, BrokenAt: i, Reason: "seq ranges overlap or regress"}
		}
		prev = *e.ChainHash
		prevEnd = end
	}
	return ChainVerification{OK: true, VerifiedCount: len(es), BrokenAt: -1}
}
