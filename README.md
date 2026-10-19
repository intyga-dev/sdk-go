# sdk-go — INTYGA client for Go

[![Release gated by INTYGA](https://www.intyga.com/badges/release-gated-by-intyga.svg)](https://www.intyga.com/use-cases/package-publishing)

Gate any high-risk backend action behind a real human approval. The primitive is uniform: **request a challenge → a human approves with a passkey or security key → poll until resolved** — the same client works for scripts, pipelines, and AI agents.

This package **bundles the offline verifier** (`github.com/intyga-dev/sdk-go/v2/verify`), so you can request an approval *and* independently verify the receipt without adding a second dependency.

> The standalone verifier also ships on its own as [`verify-go`](https://github.com/intyga-dev/verify-go).

## Install

```sh
go get github.com/intyga-dev/sdk-go/v2
```

## Require a human approval before a high-risk action

```go
import (
	"context"

	intyga "github.com/intyga-dev/sdk-go/v2"
	verify "github.com/intyga-dev/sdk-go/v2/verify"
)

client, err := intyga.NewClient(intyga.ClientOptions{
	GatewayURL:   "https://api.intyga.com",
	ClientID:     os.Getenv("INTYGA_CLIENT_ID"),
	ClientSecret: os.Getenv("INTYGA_CLIENT_SECRET"),
})
if err != nil {
	log.Fatal(err) // GatewayURL must be https:// (http:// only to a loopback host)
}

params := map[string]interface{}{"cluster": "prod-db-1"}

// Blocks until the human approves with their passkey / security key (or times out).
// Target names THIS relying party. It is required: it is what stops an approval minted here from
// being replayed at a different service (DIV §3 Invariant 5, Target Isolation).
r, err := client.RequireApproval(context.Background(), "Delete production database",
	intyga.RequireApprovalOptions{
		AuthorizeOptions: intyga.AuthorizeOptions{
			Target:     "prod-db-cluster-01",
			ActionType: "wipe_production",
			Params:     params,
		},
	})
if err != nil || r.Status != intyga.StatusApproved {
	log.Fatal("not authorized")
}

// Re-verify locally before executing. This is not optional under DIV §5: the relying party checks
// the signature itself, against a key IT resolved. Approvers is required for exactly that reason —
// a receipt checked against its own embedded key proves only that the receipt is self-consistent.
tenantID := os.Getenv("INTYGA_TENANT_ID")
if tenantID == "" {
	log.Fatal("INTYGA_TENANT_ID must name the expected workspace")
}
res := verify.VerifyApprovalReceipt(*r.Receipt, verify.Expected{
	// Independently configured tenant identity. DIV v2 refuses to infer this from the receipt.
	TenantID:   &tenantID,
	Target:     "prod-db-cluster-01",
	Nonce:      r.Nonce,
	ActionType: "wipe_production",
	Params:     params,
	Approvers:  verify.ApproverTrustAnchor{PublicKeys: trustedApproverKeys()},
}, verify.VerifyOptions{
	// REQUIRED for passkey receipts (the normal flow): the approval console's exact origin and
	// RP ID, from the trust-anchor file exported in the console (its `webauthn` block).
	ExpectedOrigin: os.Getenv("INTYGA_WEBAUTHN_ORIGIN"),
	ExpectedRpID:   os.Getenv("INTYGA_WEBAUTHN_RP_ID"),
})
if !res.OK {
	log.Fatalf("refusing to proceed: %s", res.Reason)
}

// Redeem it exactly once, immediately before the action runs. Same target, same params: this is
// what makes the approval single-use and re-binds it to what is about to execute.
c, err := client.Consume(context.Background(), r.Nonce, "prod-db-cluster-01", "wipe_production", params)
if err != nil || !c.OK {
	log.Fatal("could not consume the approval")
}
```

> **Quorum caveat.** In `PublicKeys` mode the identity IS the key, so an M-of-N quorum counts credentials, not people — one approver whose two credentials are both listed satisfies a 2-of-N alone. For `requiredApprovals` > 1 use the DID/identity form (DIV §4.4.6).

This example uses a **human or SERVICE key**. An `AI_AGENT` key must supply
`AuthorizeOptions.AgentContext` and verify the signed context against independent runtime and
session state before executing (DIV §4.3.6). The configuration digest is an RP assertion, not
proof of agent integrity.

## Guard a tool callback

`NewApprovalGuard` packages the approval, local verification and single-use consumption steps into
a callable wrapper. Register **the returned callback** with your tool framework. It requires your
own approver trust and passes a detached JSON object to the tool, so changes to the original map
while approval is pending cannot change the operation that executes.

```go
guarded, err := intyga.NewApprovalGuard(client, intyga.ApprovalGuardOptions{
	Target: "prod-db-cluster-01", ActionType: "db.restart",
	Approvers: verify.ApproverTrustAnchor{PublicKeys: trustedApproverKeys()},
	Requirement: &verify.RequirementFloor{RequiredApprovals: 1},
	ExpectedOrigin: os.Getenv("INTYGA_WEBAUTHN_ORIGIN"),
	ExpectedRpID: os.Getenv("INTYGA_WEBAUTHN_RP_ID"),
	TenantID: os.Getenv("INTYGA_TENANT_ID"), // Independently trusted workspace; never read from the receipt.
	ReportDispatch: 600, // Optional DEWP evidence window; zero disables reporting.
	OnDispatchError: func(nonce string, err error) {
		queueDispatchRetry(nonce, 600) // Persist a retry of the report, not the tool.
	},
}, func(ctx context.Context, args map[string]interface{}) (string, error) {
	return restartDatabase(ctx, args["cluster"].(string))
})
if err != nil { return err }
result, err := guarded(context.Background(), map[string]interface{}{"cluster": "prod-db-1"})
```

Supply `trustedApproverKeys`, `queueDispatchRetry` and `restartDatabase` from your application.
Use the DID trust form for a quorum of distinct people. Pass `TenantID` from your trust anchor or
other independently trusted configuration; DIV v2 receipts are refused without it, and it is never
inferred from the receipt. The callback must use `args`, not captured
mutable inputs; numbers in the detached object are `float64`, following JSON/JavaScript semantics.
Missing/invalid receipts, binding changes, failed verification or `consume.ok != true` prevent the
callback. It returns the tool's original result/error; optional dispatch reporting runs even after a
tool error or panic, and reporting/diagnostic failures cannot replace that outcome. Reporting is
best effort, not a durable outbox; a process exit can prevent it. The report window is 10–86400
seconds, and a failed report is retried with its nonce without executing the tool again.

This ordinary approval guard uses a human or `SERVICE` key. It does not implement the `AI_AGENT`
v1 runtime, session and budget gate; that integration remains in the TypeScript MCP adapter.

## API

- `NewClient(ClientOptions)` — construct a client (no I/O). It returns an error unless `GatewayURL`
  is `https://`; plain `http://` is accepted only for a loopback host (`localhost`, `127.0.0.0/8`,
  `::1`) for local development, and the default transport never follows redirects.
- `RequireApproval(ctx, description, opts)` — create a challenge and block until resolved.
- `NewApprovalGuard(client, options, tool)` — create a verified, consuming callable tool guard.
- `Authorize` / `Status` / `Consume` — the individual steps (create, poll, execution-time re-bind).
  `Authorize` requires `Target`; `Consume` takes `(ctx, nonce, target, actionType, params)` and must be
  given the same target the approval was bound to.
- `Verify(ctx, documentHash)` — public witness lookup.
- `ReportDispatched(ctx, nonce, evidenceWithinSeconds)` / `SubmitEvidence(ctx, nonce, statement, signature)`
  — DEWP 1.1 §4.7 execution evidence: report that the consumed action was sent, then relay a statement
  an evidence source signed. The service relays; it never signs one.
- `BuildExecutionEvidence(ExecutionEvidenceInput)` / `SignExecutionEvidence(statement, privateKey)` —
  the evidence source's side: the canonical statement bytes for one observation (`Sequence` is the
  source's gapless per-log counter; `SampledAt` is when the measurement was taken and defaults to
  `ObservedAt`, which defaults to now) and the ES256 signature `SubmitEvidence` relays. The builder
  refuses anything a verifier would.
- `Status(...).Execution` — the gateway's fold of that evidence for a consumed approval. Each
  `Evidence[]` record carries the statement's own `SampledAt` and `Sequence` (nil when the gateway
  could not read the statement) and `Late`: sampled after the evidence window closed, so witnessed but
  never counted. A late `contradicted` is the `challenge.execution_late_contradiction` alert — route it
  to escalation, not investigation.
- `ParseEvidenceSourcesFile(data)` / `EvidencePolicyFromFile(file)` — load the relying party's
  `intyga-evidence-sources` trust file (docs/API.md §2e) into verify-go's
  `ExecutionEvidencePolicy`. It is a separate file from the approver trust anchor, because an approver
  is not an independent observer of the action they approved. A key is a base64 SPKI string or
  `{key, notBefore?, notAfter?}`, a validity interval the verifier checks at the record's anchored
  time; any other member in a key object (a misspelt `notafter`) refuses the whole file, so it can
  never read as "no bound". Decoding into `EvidenceSourcesFile` with `json.Unmarshal` runs the same
  checks. It passes every case of the shared `executionEvidence.trustFiles` vectors.
- Tokens exchanged from `ClientID`/`ClientSecret` are re-exchanged automatically shortly before the
  gateway's `expires_in` (and once more on a 401), so a long-lived client needs no refresh logic of
  its own; an explicit `Token` is used as-is.
- A non-2xx gateway answer is returned as a `*GatewayRefusedError` (status code and body), and a
  gateway that could not be reached at all as a `*GatewayUnreachableError`.

### Offline approval (DIV §5a)

When the gateway cannot be reached, a relying party can build the challenge itself, have the
approvers sign it on a disconnected device, and verify the result locally against a trust bundle
exported while the gateway was reachable. The challenge (`DIV1:`) and signature (`SIG1:`) envelopes
and the on-disk layout are a shared format, pinned by the conformance vectors in
`vectors/offline-approval-vectors.json`.

- `RequireApprovalOptions.Offline` opts in to the fallback **for that call only**. It runs only when
  the gateway could not be asked (connection failure, timeout, 5xx, five consecutive polling failures
  of those kinds), never on a 4xx, `DENIED`, `EXPIRED` or a local error, and the result's status is
  `StatusOfflineApproved`, never `StatusApproved`.
- `UseOfflineApproval(ctx, action, opts)` runs the whole ceremony: loads and verifies the bundle,
  builds the challenge, calls your `CollectSignatures`, verifies the signatures, buffers a record for
  reconciliation and redeems the nonce once.
- `ReconcileOfflineApprovals(ctx, opts)` reports buffered approvals when connectivity returns.
- Building blocks: `VerifyTrustBundle`, `SaveTrustBundle`/`LoadTrustBundle`, `ApproverAnchor`,
  `RequirementFor`, `ParseTrustAnchorFile`, `CreateOfflineChallenge`, `DecodeChallengeEnvelope`,
  `EncodeSignatureEnvelope`/`DecodeSignatureEnvelope`, `SignChallengeEnvelope` (the approver's side),
  `AssembleOfflineReceipt`, `FileRedemptionStore`, `PendingApprovals`/`ClearPendingApproval`.

`ApproverAnchor` requires a non-nil eligible DID slice for `BundleAnchorOfflineIntent`; nil returns
an empty anchor. `BundleAnchorOrdinary` retains nil as an intentional unrestricted anchor.

## Also available in
- TypeScript — [`@intyga/sdk`](https://github.com/intyga-dev/sdk)
- Python — [`sdk-python`](https://github.com/intyga-dev/sdk-python)
- Rust — [`sdk-rust`](https://github.com/intyga-dev/sdk-rust)
- Java — [`sdk-java`](https://github.com/intyga-dev/sdk-java)

## License

Apache-2.0.
