package intyga

// DEWP §4.7 execution evidence — the evidence source's side. Ported from
// packages/sdk/src/execution-evidence.ts.
//
// An evidence source (a protection relay, a meter, a measured-boot attester) is a party independent
// of the service that executed an approved action. It observes the effect and signs a statement; your
// service relays it with Client.SubmitEvidence. The service never signs one itself: it does not hold
// the source's key.

import (
	"time"

	verify "github.com/intyga-dev/sdk-go/v2/verify"
)

// ExecutionEvidenceInput is one observation an evidence source is about to sign.
type ExecutionEvidenceInput struct {
	// ApprovalPayload is the approved DIV Intent Payload (the receipt's CanonicalPayload). Its SHA-256
	// binds the statement to exactly those bytes, so a statement cannot be moved to another approval.
	ApprovalPayload string
	// Nonce is the approval's DIV nonce.
	Nonce string
	// Source names the evidence source; it must equal the signerDid the relay records.
	Source string
	// Verdict is "confirmed" (the approved effect was observed) or "contradicted" (it was not, or a
	// different effect was). A source that cannot decide signs nothing.
	Verdict string
	// Observation is domain-specific, covered by the signature and not interpreted by verifiers.
	Observation map[string]interface{}
	// Sequence is the source's own gapless counter of statements it has signed for this log — one
	// counter per log, incremented by exactly one per statement, never reused (DEWP §4.7.2 rule 12).
	// It is what lets a verifier see a statement that was withheld. Keep it durable: a source that
	// restarts from 1 signs a divergence.
	Sequence int64
	// SampledAt is when the measurement was taken (rule 11), in the DEWP §4.3 form. Empty: ObservedAt.
	SampledAt string
	// ObservedAt is when the source produced the statement, in the DEWP §4.3 form. Empty: now.
	ObservedAt string
}

// BuildExecutionEvidence returns the canonical statement bytes for one observation (DEWP §4.7.2).
// It errors on input a verifier would refuse (non-portable numbers, more than 64 levels, a sequence
// below 1, a sample time later than the observation, …), so a source never signs malformed bytes.
func BuildExecutionEvidence(in ExecutionEvidenceInput) (string, error) {
	observedAt := in.ObservedAt
	if observedAt == "" {
		observedAt = time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	}
	sampledAt := in.SampledAt
	if sampledAt == "" {
		sampledAt = observedAt
	}
	return verify.CanonicalExecutionEvidenceStatement(verify.ExecutionEvidenceStatement{
		Nonce:         in.Nonce,
		PayloadSha256: verify.ExecutionPayloadSha256(in.ApprovalPayload),
		Observation:   in.Observation,
		ObservedAt:    observedAt,
		SampledAt:     sampledAt,
		Sequence:      in.Sequence,
		Source:        in.Source,
		Verdict:       in.Verdict,
	})
}

// SignExecutionEvidence returns the ES256 (P-256, IEEE P1363) signature over statement bytes,
// base64 — what Client.SubmitEvidence relays. privateKey takes the forms SignChallengeOptions
// accepts: a crypto.Signer whose public key is P-256, a PEM string or []byte, or DER PKCS#8. Any
// other curve is refused rather than producing a signature nobody verifies.
func SignExecutionEvidence(statement string, privateKey interface{}) (string, error) {
	signer, err := p256Signer(privateKey)
	if err != nil {
		return "", err
	}
	return signP1363(signer, []byte(statement))
}
