package intyga

// The relying party's evidence-source trust file for DEWP §4.7 execution evidence. Ported from
// packages/sdk/src/evidence-sources.ts; the contract is "The evidence-source trust file" in
// docs/API.md §2e, and the cases every SDK's loader agrees on are executionEvidence.trustFiles in
// packages/mcp-schemas/vectors/verifier-parity-vectors.json.
//
// Deliberately a separate file from the approver trust anchor (trust_anchor.go): an approver is not
// an independent observer of the action they approved, and a source key accepted as an approver key
// would let a sensor approve (DEWP §4.7.5). Like the trust anchor, it carries no signature — adopting
// it into your configuration is the act of trust.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"

	verify "github.com/intyga-dev/sdk-go/v2/verify"
)

// EvidenceSourcesFileType is the `type` of an evidence-sources file.
const EvidenceSourcesFileType = "intyga-evidence-sources"

// EvidenceSourceKey is one key of a source as the file wrote it: a bare base64 SPKI P-256 key, or
// the key with a validity interval (DEWP §4.7.5), each bound a DEWP §4.3 timestamp, both inclusive,
// either optional. A bounded key establishes trust only when the Evidence Record's anchored time lies
// inside [NotBefore, NotAfter] — write the source's registration time from the console's Evidence
// Sources page as NotBefore, and as NotAfter the earliest witness time of the first checkpoint
// anchored after its revocation (not the revocation instant, which would refuse every statement
// anchored later), so a statement accepted before the revocation keeps its trust and one after does not.
type EvidenceSourceKey struct {
	Key       string
	NotBefore *string
	NotAfter  *string
	// Bare is true when the file wrote the key as a bare string rather than as {key, …}. It changes
	// nothing about trust (a bare key and an object with no bounds are the same key); it keeps the
	// entry as written, so marshalling the file gives back the form it was loaded from.
	Bare bool
}

// MarshalJSON writes a bare key as a string and every other entry as {key, notBefore?, notAfter?}.
func (k EvidenceSourceKey) MarshalJSON() ([]byte, error) {
	if k.Bare && k.NotBefore == nil && k.NotAfter == nil {
		return json.Marshal(k.Key)
	}
	type wire struct {
		Key       string  `json:"key"`
		NotBefore *string `json:"notBefore,omitempty"`
		NotAfter  *string `json:"notAfter,omitempty"`
	}
	return json.Marshal(wire{k.Key, k.NotBefore, k.NotAfter})
}

// EvidenceSource is one source: its identifier (its statements' `source`, the record's signerDid)
// and the keys that speak for it, in file order.
type EvidenceSource struct {
	DID        string              `json:"did"`
	PublicKeys []EvidenceSourceKey `json:"publicKeys"`
	// Label is display only; nil when the file has none.
	Label *string `json:"label,omitempty"`
}

// EvidenceSourcesFile is a parsed, validated evidence-sources file. Members of the file or of a
// source other than those below are ignored, as the contract says.
type EvidenceSourcesFile struct {
	Type    string           `json:"type"`
	V       int              `json:"v"`
	Sources []EvidenceSource `json:"sources"`
}

// UnmarshalJSON validates exactly as ParseEvidenceSourcesFile does, so a file embedded in a larger
// configuration cannot be decoded around the checks — a plain struct decode would drop a misspelt
// `notafter` and read the key as unbounded. A JSON null is refused like any other non-object.
func (f *EvidenceSourcesFile) UnmarshalJSON(data []byte) error {
	parsed, err := ParseEvidenceSourcesFile(data)
	if err != nil {
		return err
	}
	*f = *parsed
	return nil
}

var (
	// evidenceKeyPattern is the contract's base64 alphabet: standard base64 with up to two `=`.
	// Narrower than the trust anchor's, which also admits base64url.
	evidenceKeyPattern = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	evidenceKeyMembers = map[string]bool{"key": true, "notBefore": true, "notAfter": true}
)

// ParseEvidenceSourcesFile parses and validates an evidence-sources file, failing loudly on the first
// problem: it is security configuration, so a malformed one must fail at load time rather than load
// and then silently trust nothing (or, worse, trust a key past its revocation).
//
// It decodes generically rather than into a struct, so a misspelt or extra member of a key object is
// a refusal, never "no bound", and numbers keep their JSON form until checked.
func ParseEvidenceSourcesFile(data []byte) (*EvidenceSourcesFile, error) {
	fail := func(format string, args ...interface{}) (*EvidenceSourcesFile, error) {
		return nil, fmt.Errorf("invalid evidence-sources file: "+format, args...)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw interface{}
	if err := dec.Decode(&raw); err != nil {
		return fail("not valid JSON (%v)", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fail("not valid JSON (unexpected data after the root value)")
	}
	obj, ok := raw.(map[string]interface{})
	if !ok {
		return fail("root must be an object")
	}
	if obj["type"] != EvidenceSourcesFileType {
		return fail("type must be %q — approver trust (%s) is a separate file", EvidenceSourcesFileType, TrustAnchorFileType)
	}
	// The number 1, as JSON.parse reads it: "1" and 1.5 are refused.
	if n, ok := obj["v"].(json.Number); !ok || !jsonNumberIsOne(n) {
		return fail("unsupported version %s (expected 1)", jsonRepr(obj["v"]))
	}
	entries, ok := obj["sources"].([]interface{})
	if !ok || len(entries) == 0 {
		return fail("sources must be a non-empty array — an empty file would trust nobody")
	}
	seen := map[string]bool{}
	sources := make([]EvidenceSource, 0, len(entries))
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok {
			return fail("every sources[] entry must be an object")
		}
		did, ok := entry["did"].(string)
		if !ok || did == "" {
			return fail("every source needs a non-empty did")
		}
		if seen[did] {
			return fail("duplicate source %q", did)
		}
		seen[did] = true
		rawKeys, ok := entry["publicKeys"].([]interface{})
		if !ok || len(rawKeys) == 0 {
			return fail("source %q: publicKeys must be a non-empty array", did)
		}
		keys := make([]EvidenceSourceKey, 0, len(rawKeys))
		for _, rawKey := range rawKeys {
			key, problem := parseEvidenceSourceKey(rawKey)
			if problem != "" {
				return fail("source %q: %s", did, problem)
			}
			keys = append(keys, key)
		}
		source := EvidenceSource{DID: did, PublicKeys: keys}
		if rawLabel, present := entry["label"]; present {
			label, ok := rawLabel.(string)
			if !ok {
				return fail("source %q: label must be a string", did)
			}
			source.Label = &label
		}
		sources = append(sources, source)
	}
	return &EvidenceSourcesFile{Type: EvidenceSourcesFileType, V: 1, Sources: sources}, nil
}

// parseEvidenceSourceKey reads one publicKeys[] entry, or returns why it is refused.
func parseEvidenceSourceKey(raw interface{}) (EvidenceSourceKey, string) {
	switch v := raw.(type) {
	case string:
		if !evidenceKeyPattern.MatchString(v) {
			return EvidenceSourceKey{}, "every publicKeys[] entry must be a base64 SPKI key"
		}
		return EvidenceSourceKey{Key: v, Bare: true}, ""
	case map[string]interface{}:
		key, ok := v["key"].(string)
		if !ok || !evidenceKeyPattern.MatchString(key) {
			return EvidenceSourceKey{}, "every publicKeys[] entry must carry a base64 SPKI key"
		}
		// Exactly these members: a misspelt bound (`notafter`, `revokedAt`) must not read as "no bound".
		members := make([]string, 0, len(v))
		for member := range v {
			members = append(members, member)
		}
		sort.Strings(members)
		for _, member := range members {
			if !evidenceKeyMembers[member] {
				return EvidenceSourceKey{}, fmt.Sprintf("unexpected member %q in a publicKeys[] entry (only key, notBefore, notAfter)", member)
			}
		}
		out := EvidenceSourceKey{Key: key}
		var fromMs, toMs int64
		var problem string
		if out.NotBefore, fromMs, problem = evidenceKeyBound(v, "notBefore"); problem != "" {
			return EvidenceSourceKey{}, problem
		}
		if out.NotAfter, toMs, problem = evidenceKeyBound(v, "notAfter"); problem != "" {
			return EvidenceSourceKey{}, problem
		}
		if out.NotBefore != nil && out.NotAfter != nil && fromMs > toMs {
			return EvidenceSourceKey{}, "notBefore is later than notAfter"
		}
		return out, ""
	default:
		return EvidenceSourceKey{}, "every publicKeys[] entry must be a base64 SPKI key or { key, notBefore?, notAfter? }"
	}
}

// evidenceKeyBound reads an optional bound. Present, it must be a DEWP §4.3 timestamp naming a real
// instant, read exactly as the verifier reads it (verify-go's §4.3 parser, which also round-trips, so
// 30 February is refused rather than rolled into March): a bound the loader accepted but the verifier
// refused would load cleanly and then silently trust nothing.
func evidenceKeyBound(entry map[string]interface{}, field string) (*string, int64, string) {
	raw, present := entry[field]
	if !present {
		return nil, 0, ""
	}
	value, isString := raw.(string)
	if !isString {
		return nil, 0, field + " must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp"
	}
	ms, ok := verify.ParseAnchorTimestampMs(value)
	if !ok {
		return nil, 0, field + " must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp"
	}
	return &value, ms, ""
}

// jsonNumberIsOne reports whether a JSON number denotes 1, as JavaScript's JSON.parse reads it.
func jsonNumberIsOne(n json.Number) bool {
	f, err := n.Float64()
	return err == nil && f == 1
}

// EvidencePolicyFromFile is the verifier's evidence-source trust from a parsed file: each did mapped
// to its keys in file order. The keys are constructed here, never decoded, so none is ever marked
// malformed; the bounds are copied, so changing the policy never changes the file. A nil file trusts
// nobody.
func EvidencePolicyFromFile(f *EvidenceSourcesFile) verify.ExecutionEvidencePolicy {
	trusted := map[string][]verify.TrustedSourceKey{}
	if f == nil {
		return verify.ExecutionEvidencePolicy{TrustedSources: trusted}
	}
	for _, s := range f.Sources {
		keys := make([]verify.TrustedSourceKey, 0, len(s.PublicKeys))
		for _, k := range s.PublicKeys {
			keys = append(keys, verify.TrustedSourceKey{Key: k.Key, NotBefore: cloneStringPtr(k.NotBefore), NotAfter: cloneStringPtr(k.NotAfter)})
		}
		trusted[s.DID] = keys
	}
	return verify.ExecutionEvidencePolicy{TrustedSources: trusted}
}

func cloneStringPtr(p *string) *string {
	if p == nil {
		return nil
	}
	s := *p
	return &s
}
