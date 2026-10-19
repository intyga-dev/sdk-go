package verify

// DEWP §4.7 — execution evidence, mirroring ledger-execution.ts in @intyga/verify. A Dispatch Record
// says the executing party sent an approved action; an Evidence Record carries a statement an
// independent evidence source signed about whether it took effect. The status derived here reports
// what a CALLER-TRUSTED source observed, never what physically happened (§4.7.6), and it never changes
// commitment, content, signature or anchor verification.
//
// The executing party writes Dispatch Records, so nothing it writes may decide the verdict on its own:
// a statement binds to ANY Dispatch Record whose hash matches (an early record with another hash is a
// reported conflict, not a way to unbind a trusted contradiction), the evidence window is bounded by
// the caller and never by the dispatch alone, every Approval Record's nonce is reported so a silent
// approval shows as `not_reported`, and a trusted `contradicted` sampled after the deadline is its own
// alert rather than a dropped statement.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// DewpExecutionEvidenceType is the signed statement type (DEWP §4.7.2), distinct from every DIV type.
	DewpExecutionEvidenceType = "dewp-execution-evidence"
	ExecutionDispatched       = "EXECUTION_DISPATCHED"
	ExecutionConfirmed        = "EXECUTION_CONFIRMED"
	ExecutionContradicted     = "EXECUTION_CONTRADICTED"
	ExecutionUnconfirmed      = "EXECUTION_UNCONFIRMED"
	// MaxExecutionEvidenceBytes is DEWP §4.7.2 rule 10.
	MaxExecutionEvidenceBytes = 16384
	// DefaultEvidenceSkewSeconds is the §4.7.3 step 6 allowance before the dispatch time, caller-
	// overridable. It covers clock error between the source and the producer and nothing else — it
	// also admits a measurement taken just before dispatch, which for an action with no visible change
	// confirms a no-op — so it is small.
	DefaultEvidenceSkewSeconds = 30
	// DefaultMaxEvidenceWindowSeconds is the §4.7.3 step 6 maximum evidence window, caller-overridable.
	// The executing party chooses `evidenceDeadline`; without this bound a far-out deadline keeps a
	// nonce `pending` forever and `unconfirmed` never fires.
	DefaultMaxEvidenceWindowSeconds = 86400
	// MaxSignedPayloadDepth is the DEWP §4.7.7 nesting bound; the outermost value counts as 1.
	MaxSignedPayloadDepth = 64
	// maxStatementNumber is DEWP §4.7.2 rules 8 and 12: |x| <= 2^53 - 1.
	maxStatementNumber  = 9007199254740991
	dewpTimestampLayout = "2006-01-02T15:04:05.000Z"
)

var (
	hex64Pattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	digitsPattern        = regexp.MustCompile(`^[0-9]+$`)
	dewpTimestampPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$`)
	statementKeys        = []string{"approval", "observation", "observedAt", "sampledAt", "sequence", "source", "type", "v", "verdict"}
	verdictEvent         = map[string]string{"confirmed": ExecutionConfirmed, "contradicted": ExecutionContradicted}
	verdictOutcome       = map[string]string{"confirmed": "SUCCESS", "contradicted": "FAILURE"}
)

// ExecutionEvidenceStatement is the object an evidence source signs (DEWP §4.7.2).
type ExecutionEvidenceStatement struct {
	Nonce         string
	PayloadSha256 string
	Observation   map[string]interface{}
	// ObservedAt is when the source produced the statement (rule 6).
	ObservedAt string
	// SampledAt is when the measurement behind Observation was taken (rule 11); the evidence window
	// is evaluated on it.
	SampledAt string
	// Sequence is the source's own gapless, per-log counter (rule 12).
	Sequence int64
	Source   string
	Verdict  string
}

// TrustedSourceKey is one caller-trusted key for an evidence source: a bare base64 SPKI P-256 key
// (valid at any time), or the key with a validity interval (DEWP §4.7.5), each bound a §4.3
// timestamp, both inclusive, either optional. A bounded key establishes trust only at the record's
// ANCHORED time. It decodes from either JSON form — a string, or an object with exactly the members
// key, notBefore and notAfter (the last two optional). An object with no usable string key decodes
// to an empty Key and is dropped. An object with any OTHER member, or with a bound that is present
// but not a string, is kept with its key and marked malformed: it still verifies a signature but
// establishes no trust — a misspelt `notafter` or a numeric bound must fail closed, never read as
// "no bound". A Go-constructed value is never malformed; only the JSON path can produce one.
type TrustedSourceKey struct {
	Key       string  `json:"key"`
	NotBefore *string `json:"notBefore,omitempty"`
	NotAfter  *string `json:"notAfter,omitempty"`
	// malformed is why this entry can verify a signature but never establish trust (§4.7.5), or "".
	malformed string
	// raw is the entry as received when it is malformed, so marshalling never launders it into a
	// well-formed one.
	raw json.RawMessage
}

var trustedKeyEntryMembers = map[string]bool{"key": true, "notBefore": true, "notAfter": true}

// UnmarshalJSON accepts a bare key string or {key, notBefore?, notAfter?}, as the TS reference reads
// it (`trustedKeysFor`): no usable key drops the entry; an unexpected member or a present non-string
// bound keeps the key and marks the entry malformed; a bound is stored only when it is a string.
func (k *TrustedSourceKey) UnmarshalJSON(data []byte) error {
	// A trust-file entry is a string OR an object, so it is decoded generically and then shape-checked
	// below; a concrete struct cannot express that union. Suppressed by rule id, not a bare nosemgrep.
	// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*k = TrustedSourceKey{}
	switch v := raw.(type) {
	case string:
		k.Key = v
	case map[string]interface{}:
		s, ok := v["key"].(string)
		if !ok || s == "" {
			return nil
		}
		k.Key = s
		unknown := []string{}
		for m := range v {
			if !trustedKeyEntryMembers[m] {
				unknown = append(unknown, m)
			}
		}
		sort.Strings(unknown)
		badBound := ""
		for _, m := range []string{"notBefore", "notAfter"} {
			bound, present := v[m]
			if !present {
				continue
			}
			if s, isString := bound.(string); isString {
				if m == "notBefore" {
					k.NotBefore = &s
				} else {
					k.NotAfter = &s
				}
			} else if badBound == "" {
				badBound = m
			}
		}
		switch {
		case len(unknown) > 0:
			k.malformed = fmt.Sprintf("Caller key entry has unexpected member(s) %s; it does not establish trust.", strings.Join(unknown, ", "))
		case badBound != "":
			k.malformed = fmt.Sprintf("Caller key entry's %s is not a timestamp string; it does not establish trust.", badBound)
		}
		if k.malformed != "" {
			k.raw = append(json.RawMessage(nil), data...)
		}
	}
	return nil
}

// MarshalJSON writes a bare string for an unbounded key, the object form otherwise, and a malformed
// entry exactly as it was received.
func (k TrustedSourceKey) MarshalJSON() ([]byte, error) {
	if k.raw != nil {
		return k.raw, nil
	}
	if k.NotBefore == nil && k.NotAfter == nil {
		return json.Marshal(k.Key)
	}
	type wire struct {
		Key       string  `json:"key"`
		NotBefore *string `json:"notBefore,omitempty"`
		NotAfter  *string `json:"notAfter,omitempty"`
	}
	return json.Marshal(wire{k.Key, k.NotBefore, k.NotAfter})
}

// Malformed reports why a JSON-decoded entry can verify a signature but never establish trust
// (DEWP §4.7.5), or "" for a well-formed entry.
func (k TrustedSourceKey) Malformed() string { return k.malformed }

// ExecutionEvidencePolicy is caller-owned evidence-source trust: source → keys (DEWP §4.7.5). It is
// separate from approver trust.
type ExecutionEvidencePolicy struct {
	TrustedSources map[string][]TrustedSourceKey `json:"trustedSources"`
}

// ExecutionEvidenceCheck is the §4.7.3 result for one Evidence Record.
type ExecutionEvidenceCheck struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
	// Trusted is true only when the statement verified under a caller-provisioned key valid for its
	// source.
	Trusted bool    `json:"trusted"`
	Nonce   *string `json:"nonce"`
	Verdict *string `json:"verdict"`
	// Source and Sequence are the statement's once it parsed; nil before that.
	Source   *string `json:"source"`
	Sequence *int64  `json:"sequence"`
}

// ExecutionEntryCheck is a check with the seq of its record.
type ExecutionEntryCheck struct {
	Seq string `json:"seq"`
	ExecutionEvidenceCheck
}

// SourceContinuity is DEWP §4.7.3 "Source continuity": what one source's counter shows inside the
// bundle.
type SourceContinuity struct {
	// First and Last are the smallest and largest `sequence` seen from this source.
	First int64 `json:"first"`
	Last  int64 `json:"last"`
	// Gaps are inclusive ranges of counter values between First and Last that no record carries.
	Gaps [][2]int64 `json:"gaps"`
	// Divergent lists counter values carried by two or more records whose statement bytes differ.
	Divergent []int64 `json:"divergent"`
}

// ExecutionNonceStatus is the §4.7.4 status of one approval nonce.
type ExecutionNonceStatus struct {
	Status string `json:"status"`
	// DispatchSeq is the governing Dispatch Record (DEWP §4.7.3 step 5 / §4.7.4), or nil.
	DispatchSeq *string `json:"dispatchSeq"`
	// EvidenceDeadline is its own `evidenceDeadline`, as written by the executing party.
	EvidenceDeadline *string `json:"evidenceDeadline"`
	// EffectiveDeadline is the deadline the status was evaluated against: EvidenceDeadline cut to the
	// caller's window.
	EffectiveDeadline *string `json:"effectiveDeadline"`
	// WindowCapped is true when the record's own deadline lay beyond the caller's maximum window.
	WindowCapped bool `json:"windowCapped"`
	// DispatchConflict lists Dispatch Records for this nonce that disagree on `payloadSha256`; empty
	// when they agree (§4.7.4).
	DispatchConflict []string `json:"dispatchConflict"`
	// LateContradiction lists trusted, bound `contradicted` statements sampled after the effective
	// deadline (§4.7.4).
	LateContradiction []string `json:"lateContradiction"`
	// UntrustedContradiction lists bound, in-window or late `contradicted` statements whose signature verified
	// under a caller-provisioned key that did not establish trust — its validity could not be placed
	// in time, or the record lay outside it (§4.7.4, §4.7.5). They cannot decide the status; they are
	// never silent.
	UntrustedContradiction []string `json:"untrustedContradiction"`
	EvidenceSeqs           []string `json:"evidenceSeqs"`
}

// ExecutionVerification is DEWP §4.7 over one evidence bundle.
type ExecutionVerification struct {
	// Checks holds one check per Evidence Record, in bundle order.
	Checks []ExecutionEntryCheck `json:"checks"`
	// ByNonce is the DEWP §4.7.4 status per approval nonce named by an Approval, Dispatch or
	// Evidence Record.
	ByNonce      map[string]ExecutionNonceStatus `json:"byNonce"`
	Confirmed    []string                        `json:"confirmed"`
	Contradicted []string                        `json:"contradicted"`
	Unconfirmed  []string                        `json:"unconfirmed"`
	Pending      []string                        `json:"pending"`
	NotReported  []string                        `json:"notReported"`
	// LateContradicted lists nonces with a late contradiction — the alert that most needs escalation.
	LateContradicted []string `json:"lateContradicted"`
	// UntrustedContradicted lists nonces with a contradiction under a provisioned key that established
	// no trust (§4.7.4).
	UntrustedContradicted []string `json:"untrustedContradicted"`
	// DispatchConflicts lists nonces whose Dispatch Records disagree (§4.7.4).
	DispatchConflicts []string `json:"dispatchConflicts"`
	// Sources is the per-source continuity over the statements whose signature verified (§4.7.3).
	Sources map[string]SourceContinuity `json:"sources"`
}

// ExecutionEntry is a content-verified leaf with its seq.
type ExecutionEntry struct {
	Seq  string
	Leaf AuditLeaf
}

// ExecutionEvaluationOptions configures EvaluateExecutionEvidence.
type ExecutionEvaluationOptions struct {
	Policy *ExecutionEvidencePolicy
	// Now is the evaluation time (nil: the current time). An input, so a status is reproducible.
	Now *time.Time
	// SkewSeconds is the §4.7.3 step 6 allowance before dispatch (nil or negative:
	// DefaultEvidenceSkewSeconds).
	SkewSeconds *int
	// MaxWindowSeconds bounds the evidence window (nil or negative: DefaultMaxEvidenceWindowSeconds).
	MaxWindowSeconds *int
	// AnchoredTime returns the anchored time of the record at seq (epoch ms): the earliest external
	// witness time among anchors that counted toward quorum for a checkpoint covering it — ok false
	// when none does (DEWP §4.7.5). Only consulted for caller keys that carry a validity interval.
	AnchoredTime func(seq string) (ms int64, ok bool)
}

// dewpTimestampMs parses a DEWP §4.3 timestamp naming a real instant; ok=false otherwise.
func dewpTimestampMs(value interface{}) (int64, bool) {
	s, isString := value.(string)
	if !isString || !dewpTimestampPattern.MatchString(s) {
		return 0, false
	}
	t, err := time.Parse(dewpTimestampLayout, s)
	if err != nil {
		return 0, false
	}
	return t.UnixMilli(), true
}

// dewpTimestamp formats epoch milliseconds in the §4.3 form.
func dewpTimestamp(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(dewpTimestampLayout)
}

// nestsDeeperThan reports whether text nests arrays/objects deeper than limit, scanned without parsing.
func nestsDeeperThan(text string, limit int) bool {
	depth, inString := 0, false
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case inString && c == '\\':
			i++
		case inString && c == '"':
			inString = false
		case inString:
		case c == '"':
			inString = true
		case c == '[' || c == '{':
			depth++
			if depth > limit {
				return true
			}
		case c == ']' || c == '}':
			depth--
		}
	}
	return false
}

func everyNumber(v interface{}, ok func(float64) bool) bool {
	switch x := v.(type) {
	case float64:
		return ok(x)
	case []interface{}:
		for _, e := range x {
			if !everyNumber(e, ok) {
				return false
			}
		}
	case map[string]interface{}:
		for _, e := range x {
			if !everyNumber(e, ok) {
				return false
			}
		}
	}
	return true
}

// ParseSignedPayload is DEWP §4.7.7: the one way §4.7 parses a signed payload. encoding/json already
// refuses trailing content, NaN/Infinity literals and numbers outside the double range; the depth
// bound is what other runtimes would otherwise disagree on.
func ParseSignedPayload(text string) (interface{}, bool) {
	if nestsDeeperThan(text, MaxSignedPayloadDepth) {
		return nil, false
	}
	// DEWP §4.7.7: the signed payload is any JSON value, re-serialized under RFC 8785 and compared to
	// the signed bytes before anything reads it, so a generic decode is the specified behaviour; the
	// depth bound above is what keeps it safe. Suppressed by rule id, not a bare nosemgrep.
	// nosemgrep: go.lang.security.deserialization.unsafe-deserialization-interface.go-unsafe-deserialization-interface
	var value interface{}
	if err := json.Unmarshal([]byte(text), &value); err != nil {
		return nil, false
	}
	return value, true
}

func asObject(v interface{}) (map[string]interface{}, bool) {
	m, ok := v.(map[string]interface{})
	return m, ok
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ParseExecutionEvidenceStatement enforces DEWP §4.7.2 rules 1–3 and 5–12. Rule 4 (source equals the
// record's signer) needs the record and is checked by the caller.
func ParseExecutionEvidenceStatement(bytes string) (*ExecutionEvidenceStatement, error) {
	if len(bytes) > MaxExecutionEvidenceBytes {
		return nil, fmt.Errorf("statement exceeds %d bytes", MaxExecutionEvidenceBytes)
	}
	value, parsed := ParseSignedPayload(bytes)
	if !parsed {
		return nil, errors.New("statement does not parse (DEWP §4.7.7)")
	}
	if !everyNumber(value, func(n float64) bool { return math.Abs(n) <= maxStatementNumber }) {
		return nil, errors.New("a statement number exceeds 2^53 - 1")
	}
	// Rules 8 and 9 together: re-serializing under RFC 8785 must reproduce the bytes exactly. This
	// also refuses duplicate members, whitespace, non-portable numbers and invalid Unicode, so every
	// port reads one statement from one byte string.
	canonical, err := StableStringify(value)
	if err != nil {
		return nil, fmt.Errorf("statement is not canonical: %v", err)
	}
	if canonical != bytes {
		return nil, errors.New("statement is not in RFC 8785 canonical form")
	}
	obj, ok := asObject(value)
	if !ok {
		return nil, errors.New("statement is not a JSON object")
	}
	if !equalStrings(sortedKeys(obj), statementKeys) {
		return nil, errors.New("statement must have exactly the members approval, observation, observedAt, sampledAt, sequence, source, type, v, verdict")
	}
	if t, _ := obj["type"].(string); t != DewpExecutionEvidenceType {
		return nil, fmt.Errorf("statement type is not %s", DewpExecutionEvidenceType)
	}
	if v, _ := obj["v"].(float64); v != 1 {
		return nil, errors.New("statement version v must be 1")
	}
	approval, ok := asObject(obj["approval"])
	if !ok {
		return nil, errors.New("approval must be an object")
	}
	if !equalStrings(sortedKeys(approval), []string{"nonce", "payloadSha256"}) {
		return nil, errors.New("approval must have exactly the members nonce, payloadSha256")
	}
	nonce, _ := approval["nonce"].(string)
	if nonce == "" {
		return nil, errors.New("approval.nonce must be a non-empty string")
	}
	digest, _ := approval["payloadSha256"].(string)
	if !hex64Pattern.MatchString(digest) {
		return nil, errors.New("approval.payloadSha256 must be 64 lowercase hex characters")
	}
	source, _ := obj["source"].(string)
	if source == "" {
		return nil, errors.New("source must be a non-empty string")
	}
	verdict, _ := obj["verdict"].(string)
	if verdict != "confirmed" && verdict != "contradicted" {
		return nil, errors.New("verdict must be confirmed or contradicted")
	}
	observedMs, valid := dewpTimestampMs(obj["observedAt"])
	if !valid {
		return nil, errors.New("observedAt must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp")
	}
	sampledMs, valid := dewpTimestampMs(obj["sampledAt"])
	if !valid {
		return nil, errors.New("sampledAt must be a YYYY-MM-DDTHH:mm:ss.sssZ timestamp")
	}
	if sampledMs > observedMs {
		return nil, errors.New("sampledAt must not be later than observedAt")
	}
	// The upper bound was enforced above with every other number; `418.0` never reaches here because
	// canonical re-serialization prints it as `418`.
	sequence, isNumber := obj["sequence"].(float64)
	if !isNumber || sequence != math.Trunc(sequence) || sequence < 1 {
		return nil, errors.New("sequence must be an integer from 1 to 2^53 - 1")
	}
	observation, ok := asObject(obj["observation"])
	if !ok {
		return nil, errors.New("observation must be an object")
	}
	return &ExecutionEvidenceStatement{
		Nonce: nonce, PayloadSha256: digest, Observation: observation,
		ObservedAt: obj["observedAt"].(string), SampledAt: obj["sampledAt"].(string), Sequence: int64(sequence),
		Source: source, Verdict: verdict,
	}, nil
}

// CanonicalExecutionEvidenceStatement returns the statement bytes an evidence source signs (DEWP
// §4.7.2). It errors on input the statement rules refuse, so a source never signs malformed bytes.
func CanonicalExecutionEvidenceStatement(s ExecutionEvidenceStatement) (string, error) {
	observation := map[string]interface{}(s.Observation)
	if observation == nil {
		observation = map[string]interface{}{}
	}
	bytes, err := StableStringify(map[string]interface{}{
		"approval":    map[string]interface{}{"nonce": s.Nonce, "payloadSha256": s.PayloadSha256},
		"observation": observation,
		"observedAt":  s.ObservedAt,
		"sampledAt":   s.SampledAt,
		"sequence":    s.Sequence,
		"source":      s.Source,
		"type":        DewpExecutionEvidenceType,
		"v":           1,
		"verdict":     s.Verdict,
	})
	if err != nil {
		return "", err
	}
	if _, err := ParseExecutionEvidenceStatement(bytes); err != nil {
		return "", err
	}
	return bytes, nil
}

// ExecutionPayloadSha256 is the lowercase hex SHA-256 of a DIV Intent Payload's UTF-8 bytes.
func ExecutionPayloadSha256(canonicalPayload string) string {
	sum := sha256.Sum256([]byte(canonicalPayload))
	return hex.EncodeToString(sum[:])
}

func payloadObject(signedPayload *string) map[string]interface{} {
	if signedPayload == nil || *signedPayload == "" {
		return nil
	}
	value, parsed := ParseSignedPayload(*signedPayload)
	if !parsed {
		return nil
	}
	obj, _ := asObject(value)
	return obj
}

// IsExecutionEvidencePayload reports whether a signed payload is an Execution Evidence Statement.
func IsExecutionEvidencePayload(signedPayload *string) bool {
	t, _ := payloadObject(signedPayload)["type"].(string)
	return t == DewpExecutionEvidenceType
}

// IsExecutionEvidenceLeaf: its event says so, or its payload is a statement — either suffices, so a
// record cannot dodge evidence-source trust by mislabelling one side (§4.7.3, §4.7.5).
func IsExecutionEvidenceLeaf(leaf AuditLeaf) bool {
	if leaf.Event != nil && (*leaf.Event == ExecutionConfirmed || *leaf.Event == ExecutionContradicted) {
		return true
	}
	return IsExecutionEvidencePayload(leaf.SignedPayload)
}

// trustedKeysFor returns the caller's keys for a source. An entry with no usable key is dropped
// (nothing can verify under it); a malformed one is kept, so its signature verifies and its reason
// for establishing no trust is reported.
func trustedKeysFor(p *ExecutionEvidencePolicy, source *string) []TrustedSourceKey {
	if p == nil || source == nil {
		return nil
	}
	var out []TrustedSourceKey
	for _, k := range p.TrustedSources[*source] {
		if k.Key != "" {
			out = append(out, k)
		}
	}
	return out
}

// keyValidAt is DEWP §4.7.5: a bounded key establishes trust only at the record's anchored time.
// `observedAt` and `sampledAt` are the source's own claims and are never used here — a compromised
// key could place a statement inside the period when it was still valid; a witness cannot be
// backdated.
func keyValidAt(k TrustedSourceKey, anchoredTimeMs *int64) (bool, string) {
	if k.malformed != "" {
		return false, k.malformed
	}
	if k.NotBefore == nil && k.NotAfter == nil {
		return true, ""
	}
	from, to := int64(math.MinInt64), int64(math.MaxInt64)
	if k.NotBefore != nil {
		ms, ok := dewpTimestampMs(*k.NotBefore)
		if !ok {
			return false, "Caller key carries a malformed validity interval; it does not establish trust."
		}
		from = ms
	}
	if k.NotAfter != nil {
		ms, ok := dewpTimestampMs(*k.NotAfter)
		if !ok {
			return false, "Caller key carries a malformed validity interval; it does not establish trust."
		}
		to = ms
	}
	if anchoredTimeMs == nil {
		return false, "Caller key carries a validity interval but no counting anchor covers this record, so the key " +
			"cannot be placed in time (DEWP §4.7.5); it does not establish trust."
	}
	if *anchoredTimeMs < from || *anchoredTimeMs > to {
		return false, "Caller key was not valid at this record's anchored time (DEWP §4.7.5); it does not establish trust."
	}
	return true, ""
}

// VerifyEvidenceSignature checks ES256 under caller-provisioned keys for the statement's source.
// Evidence-source trust only: an approver key never verifies a statement, and an evidence key never
// verifies an approval (§4.7.5). A key with a validity interval verifies the signature but establishes
// trust only at the record's anchored time (anchoredTimeMs, nil when no counting anchor covers the
// record).
func VerifyEvidenceSignature(leaf AuditLeaf, p *ExecutionEvidencePolicy, anchoredTimeMs *int64) AuditSignatureCheck {
	if p == nil {
		if VerifyEmbeddedSignature(leaf) {
			return AuditSignatureCheck{"verified", "Signature valid under embedded key; source identity is not established.", false}
		}
		return AuditSignatureCheck{"invalid", "Statement signature does not verify.", false}
	}
	keys := trustedKeysFor(p, leaf.SignerDid)
	if len(keys) == 0 {
		return AuditSignatureCheck{"not_checked", "No caller-trusted key for this evidence source.", false}
	}
	untrustedReason := ""
	for _, k := range keys {
		key := k.Key
		clone := leaf
		clone.SignerPublicKey = &key
		if !VerifyEmbeddedSignature(clone) {
			continue
		}
		if ok, reason := keyValidAt(k, anchoredTimeMs); ok {
			return AuditSignatureCheck{"verified", "Statement valid under caller-trusted source key.", true}
		} else if untrustedReason == "" {
			untrustedReason = reason
		}
	}
	if untrustedReason != "" {
		return AuditSignatureCheck{"verified", untrustedReason, false}
	}
	return AuditSignatureCheck{"invalid", "Statement signature does not verify under caller trust.", false}
}

func decidedCheck(status, reason string, s *ExecutionEvidenceStatement, trusted bool) ExecutionEvidenceCheck {
	c := ExecutionEvidenceCheck{Status: status, Reason: reason, Trusted: trusted}
	if s != nil {
		nonce, verdict, source, sequence := s.Nonce, s.Verdict, s.Source, s.Sequence
		c.Nonce, c.Verdict, c.Source, c.Sequence = &nonce, &verdict, &source, &sequence
	}
	return c
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func withNote(reason, note string) string {
	if note == "" {
		return reason
	}
	return reason + " " + note
}

// checkLeaf runs DEWP §4.7.3 steps 1–4: everything a single leaf can establish on its own. It returns
// a decided check, or the statement, its trust and a note — the reason a verified signature under a
// policy did not establish trust (a bounded key outside its interval, or no anchored time).
func checkLeaf(leaf AuditLeaf, p *ExecutionEvidencePolicy, anchoredTimeMs *int64) (*ExecutionEvidenceCheck, *ExecutionEvidenceStatement, bool, string) {
	if str(leaf.SigAlg) != "ES256" || str(leaf.Signature) == "" || str(leaf.SignerPublicKey) == "" || str(leaf.SignedPayload) == "" {
		c := decidedCheck("invalid", "Evidence Records must carry an ES256 signature, public key and statement.", nil, false)
		return &c, nil, false, ""
	}
	s, err := ParseExecutionEvidenceStatement(*leaf.SignedPayload)
	if err != nil {
		c := decidedCheck("invalid", "Malformed statement: "+err.Error()+".", nil, false)
		return &c, nil, false, ""
	}
	if s.Source != str(leaf.SignerDid) {
		c := decidedCheck("invalid", "Statement source does not match the record's signerDid.", s, false)
		return &c, nil, false, ""
	}
	if str(leaf.Event) != verdictEvent[s.Verdict] || str(leaf.Outcome) != verdictOutcome[s.Verdict] {
		c := decidedCheck("invalid", "Record event/outcome do not match the signed verdict.", s, false)
		return &c, nil, false, ""
	}
	sig := VerifyEvidenceSignature(leaf, p, anchoredTimeMs)
	if sig.Status != "verified" {
		c := decidedCheck(sig.Status, sig.Reason, s, false)
		return &c, nil, false, ""
	}
	note := ""
	if p != nil && !sig.Trusted {
		note = sig.Reason
	}
	return nil, s, sig.Trusted, note
}

// CheckExecutionEvidenceLeaf is DEWP §4.7.3 for a leaf seen alone (a single proof): binding needs
// the dispatch and approval records, which a single proof does not carry, so a statement is never
// verified there, at best unbound. anchoredTimeMs is the proof's anchored time (nil without a
// counting anchor), consulted only for caller keys that carry a validity interval.
func CheckExecutionEvidenceLeaf(leaf AuditLeaf, p *ExecutionEvidencePolicy, anchoredTimeMs *int64) ExecutionEvidenceCheck {
	decided, s, trusted, note := checkLeaf(leaf, p, anchoredTimeMs)
	if decided != nil {
		return *decided
	}
	return decidedCheck("unbound", withNote("A single proof cannot bind a statement to its dispatch and approval records.", note), s, trusted)
}

type dispatchRecord struct {
	nonce, seq, deadline, payloadSha256 string
	createdAtMs, deadlineMs             int64
}

// dispatchOf returns a valid Dispatch Record's governing fields, or nil when the record does not qualify.
func dispatchOf(leaf AuditLeaf) *dispatchRecord {
	if str(leaf.Event) != ExecutionDispatched {
		return nil
	}
	m, ok := asObject(leaf.Metadata)
	if !ok {
		return nil
	}
	nonce, _ := m["nonce"].(string)
	digest, _ := m["payloadSha256"].(string)
	deadline, _ := m["evidenceDeadline"].(string)
	if nonce == "" || !hex64Pattern.MatchString(digest) {
		return nil
	}
	deadlineMs, okDeadline := dewpTimestampMs(deadline)
	var created interface{}
	if leaf.CreatedAt != nil {
		created = *leaf.CreatedAt
	}
	createdMs, okCreated := dewpTimestampMs(created)
	if !okDeadline || !okCreated {
		return nil
	}
	return &dispatchRecord{nonce: nonce, seq: str(leaf.Seq), deadline: deadline, payloadSha256: digest, createdAtMs: createdMs, deadlineMs: deadlineMs}
}

// seqLess orders numeric seqs; a non-numeric seq (which a verified entry cannot have) sorts last.
func seqLess(a, b string) bool {
	// Plain ASCII digits only: big.Int.SetString would also accept a sign such as "+5".
	na, nb := digitsPattern.MatchString(a), digitsPattern.MatchString(b)
	if !na || !nb {
		return na && !nb
	}
	x, _ := new(big.Int).SetString(a, 10)
	y, _ := new(big.Int).SetString(b, 10)
	return x.Cmp(y) < 0
}

// effectiveDeadlineOf is the deadline a status is evaluated against: the record's own, cut to the
// caller's window.
func effectiveDeadlineOf(d *dispatchRecord, maxWindowMs int64) (int64, bool) {
	bound := d.createdAtMs + maxWindowMs
	if d.deadlineMs > bound {
		return bound, true
	}
	return d.deadlineMs, false
}

type continuityRecord struct {
	sequence int64
	bytes    string
}

// continuity is DEWP §4.7.3 "Source continuity" over the records that passed step 4.
func continuity(records map[string][]continuityRecord) map[string]SourceContinuity {
	out := map[string]SourceContinuity{}
	for source, list := range records {
		bySequence := map[int64]map[string]bool{}
		for _, r := range list {
			if bySequence[r.sequence] == nil {
				bySequence[r.sequence] = map[string]bool{}
			}
			bySequence[r.sequence][r.bytes] = true
		}
		seen := make([]int64, 0, len(bySequence))
		for s := range bySequence {
			seen = append(seen, s)
		}
		sort.Slice(seen, func(i, j int) bool { return seen[i] < seen[j] })
		// Gaps as ranges: a source that signed 1 and 2^53 − 1 must not make the verifier enumerate the
		// numbers in between.
		gaps := [][2]int64{}
		for i := 1; i < len(seen); i++ {
			if seen[i]-seen[i-1] > 1 {
				gaps = append(gaps, [2]int64{seen[i-1] + 1, seen[i] - 1})
			}
		}
		divergent := []int64{}
		for _, s := range seen {
			if len(bySequence[s]) > 1 {
				divergent = append(divergent, s)
			}
		}
		out[source] = SourceContinuity{First: seen[0], Last: seen[len(seen)-1], Gaps: gaps, Divergent: divergent}
	}
	return out
}

// EvaluateExecutionEvidence applies DEWP §4.7.3–§4.7.4 to the CONTENT-VERIFIED entries of one bundle.
// opts.Now is the evaluation time (nil: the current time) and is an input so a status is reproducible.
func EvaluateExecutionEvidence(entries []ExecutionEntry, opts ExecutionEvaluationOptions) ExecutionVerification {
	at := time.Now()
	if opts.Now != nil {
		at = *opts.Now
	}
	nowMs := at.UnixMilli()
	// A bound that is negative is no bound at all; fall back to the default rather than let it remove
	// the window cap or the early-sample limit. The TS reference also refuses NaN and ±Infinity; a Go
	// int cannot carry either, so the negative check is the whole of that rule here.
	skew, window := DefaultEvidenceSkewSeconds, DefaultMaxEvidenceWindowSeconds
	if opts.SkewSeconds != nil && *opts.SkewSeconds >= 0 {
		skew = *opts.SkewSeconds
	}
	if opts.MaxWindowSeconds != nil && *opts.MaxWindowSeconds >= 0 {
		window = *opts.MaxWindowSeconds
	}
	skewMs, maxWindowMs := int64(skew)*1000, int64(window)*1000
	anchoredTime := func(seq string) *int64 {
		if opts.AnchoredTime == nil {
			return nil
		}
		ms, ok := opts.AnchoredTime(seq)
		if !ok {
			return nil
		}
		return &ms
	}
	ordered := append([]ExecutionEntry(nil), entries...)
	sort.SliceStable(ordered, func(i, j int) bool { return seqLess(ordered[i].Seq, ordered[j].Seq) })
	// Every valid Dispatch Record per nonce, in seq order.
	dispatches := map[string][]*dispatchRecord{}
	approvalHashes := map[string]map[string]bool{}
	for _, e := range ordered {
		if d := dispatchOf(e.Leaf); d != nil {
			dispatches[d.nonce] = append(dispatches[d.nonce], d)
		}
		obj := payloadObject(e.Leaf.SignedPayload)
		if t, _ := obj["type"].(string); t == DivIntentType {
			if nonce, isString := obj["nonce"].(string); isString {
				if approvalHashes[nonce] == nil {
					approvalHashes[nonce] = map[string]bool{}
				}
				approvalHashes[nonce][ExecutionPayloadSha256(*e.Leaf.SignedPayload)] = true
			}
		}
	}

	result := ExecutionVerification{
		Checks: []ExecutionEntryCheck{}, ByNonce: map[string]ExecutionNonceStatus{},
		Confirmed: []string{}, Contradicted: []string{}, Unconfirmed: []string{}, Pending: []string{}, NotReported: []string{},
		LateContradicted: []string{}, UntrustedContradicted: []string{}, DispatchConflicts: []string{},
	}
	evidenceSeqs := map[string][]string{}
	// Per nonce: the governing Dispatch Record of its bound statements (first seen).
	governingByNonce := map[string]*dispatchRecord{}
	lateContradictions := map[string][]string{}
	untrustedContradictions := map[string][]string{}
	continuityRecords := map[string][]continuityRecord{}
	for _, e := range entries {
		if !IsExecutionEvidenceLeaf(e.Leaf) {
			continue
		}
		decided, s, trusted, note := checkLeaf(e.Leaf, opts.Policy, anchoredTime(e.Seq))
		var check ExecutionEvidenceCheck
		if decided != nil {
			check = *decided
		} else {
			continuityRecords[s.Source] = append(continuityRecords[s.Source], continuityRecord{s.Sequence, *e.Leaf.SignedPayload})
			all := dispatches[s.Nonce]
			var governing *dispatchRecord
			for _, d := range all {
				if d.payloadSha256 == s.PayloadSha256 {
					governing = d
					break
				}
			}
			switch {
			case governing == nil && len(all) == 0:
				check = decidedCheck("unbound", withNote("No Dispatch Record for this approval nonce.", note), s, trusted)
			case governing == nil:
				check = decidedCheck("unbound", withNote("No Dispatch Record for this nonce carries the statement's payload hash.", note), s, trusted)
			case !approvalHashes[s.Nonce][s.PayloadSha256]:
				check = decidedCheck("unbound", withNote("No Approval Record with this nonce and payload hash.", note), s, trusted)
			default:
				if _, seen := governingByNonce[s.Nonce]; !seen {
					governingByNonce[s.Nonce] = governing
				}
				sampledMs, _ := dewpTimestampMs(s.SampledAt)
				deadlineMs, _ := effectiveDeadlineOf(governing, maxWindowMs)
				// A provisioned key signed this contradiction but established no trust (`note` is set
				// only then). In-window or late, it cannot decide the status and must not be silent (§4.7.4).
				if sampledMs >= governing.createdAtMs-skewMs && !trusted && note != "" && s.Verdict == "contradicted" {
					untrustedContradictions[s.Nonce] = append(untrustedContradictions[s.Nonce], e.Seq)
				}
				switch {
				case sampledMs < governing.createdAtMs-skewMs:
					check = decidedCheck("stale", withNote("Sampled before the dispatch evidence window (early).", note), s, trusted)
				case sampledMs > deadlineMs:
					check = decidedCheck("stale", withNote("Sampled after the dispatch evidence window (late).", note), s, trusted)
					if trusted && s.Verdict == "contradicted" {
						lateContradictions[s.Nonce] = append(lateContradictions[s.Nonce], e.Seq)
					}
				default:
					check = decidedCheck("verified", withNote("Statement verified and bound to its dispatch and approval.", note), s, trusted)
				}
			}
		}
		result.Checks = append(result.Checks, ExecutionEntryCheck{e.Seq, check})
		if check.Nonce != nil {
			evidenceSeqs[*check.Nonce] = append(evidenceSeqs[*check.Nonce], e.Seq)
		}
	}
	result.Sources = continuity(continuityRecords)

	nonces := map[string]bool{}
	for n := range approvalHashes {
		nonces[n] = true
	}
	for n := range dispatches {
		nonces[n] = true
	}
	for n := range evidenceSeqs {
		nonces[n] = true
	}
	sortedNonces := make([]string, 0, len(nonces))
	for n := range nonces {
		sortedNonces = append(sortedNonces, n)
	}
	sort.Slice(sortedNonces, func(i, j int) bool { return utf16Less(sortedNonces[i], sortedNonces[j]) })
	for _, nonce := range sortedNonces {
		confirmed, contradicted := false, false
		for _, c := range result.Checks {
			if c.Nonce != nil && *c.Nonce == nonce && c.Status == "verified" && c.Trusted {
				confirmed = confirmed || *c.Verdict == "confirmed"
				contradicted = contradicted || *c.Verdict == "contradicted"
			}
		}
		all := dispatches[nonce]
		// The governing record: the one the nonce's bound statements bound to, else the first that
		// names it.
		d := governingByNonce[nonce]
		if d == nil && len(all) > 0 {
			d = all[0]
		}
		var deadlineMs int64
		capped := false
		if d != nil {
			deadlineMs, capped = effectiveDeadlineOf(d, maxWindowMs)
		}
		status := "pending"
		switch {
		case contradicted:
			status = "contradicted"
		case confirmed:
			status = "confirmed"
		case d == nil:
			status = "not_reported"
		case deadlineMs < nowMs:
			status = "unconfirmed"
		}
		conflict := []string{}
		hashes := map[string]bool{}
		for _, x := range all {
			hashes[x.payloadSha256] = true
		}
		if len(hashes) > 1 {
			for _, x := range all {
				conflict = append(conflict, x.seq)
			}
		}
		late := lateContradictions[nonce]
		if late == nil {
			late = []string{}
		}
		untrusted := untrustedContradictions[nonce]
		if untrusted == nil {
			untrusted = []string{}
		}
		entry := ExecutionNonceStatus{
			Status: status, WindowCapped: capped, DispatchConflict: conflict, LateContradiction: late,
			UntrustedContradiction: untrusted, EvidenceSeqs: evidenceSeqs[nonce],
		}
		if entry.EvidenceSeqs == nil {
			entry.EvidenceSeqs = []string{}
		}
		if d != nil {
			seq, deadline, effective := d.seq, d.deadline, dewpTimestamp(deadlineMs)
			entry.DispatchSeq, entry.EvidenceDeadline, entry.EffectiveDeadline = &seq, &deadline, &effective
		}
		result.ByNonce[nonce] = entry
		switch status {
		case "contradicted":
			result.Contradicted = append(result.Contradicted, nonce)
		case "confirmed":
			result.Confirmed = append(result.Confirmed, nonce)
		case "not_reported":
			result.NotReported = append(result.NotReported, nonce)
		case "unconfirmed":
			result.Unconfirmed = append(result.Unconfirmed, nonce)
		default:
			result.Pending = append(result.Pending, nonce)
		}
		if len(conflict) > 0 {
			result.DispatchConflicts = append(result.DispatchConflicts, nonce)
		}
		if len(untrusted) > 0 {
			result.UntrustedContradicted = append(result.UntrustedContradicted, nonce)
		}
		if len(late) > 0 {
			result.LateContradicted = append(result.LateContradicted, nonce)
		}
	}
	return result
}
