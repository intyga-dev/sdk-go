# Changelog

All notable changes to `github.com/intyga-dev/sdk-go` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [2.1.0]

- `Client.ReportDispatched` / `SubmitEvidence` (DEWP 1.1 §4.7) and `ApprovalResult.Execution`.
- `BuildExecutionEvidence` / `SignExecutionEvidence` — the evidence source's side of DEWP 1.1 §4.7,
  after the pre-publication review: the statement carries `SampledAt` (defaults to `ObservedAt`) and a
  required per-log `Sequence`; the builder refuses what a verifier would, and the signer takes the key
  forms `SignChallengeOptions` accepts (P-256 only). Mirrors `buildExecutionEvidence` /
  `signExecutionEvidence` in `@intyga/sdk`.
- `ParseEvidenceSourcesFile` / `EvidencePolicyFromFile` — the `intyga-evidence-sources` trust file
  (docs/API.md §2e) loaded into verify-go's `ExecutionEvidencePolicy`, separate from the approver trust
  anchor. A key may be `{key, notBefore?, notAfter?}`, a validity interval the verifier checks at the
  record's anchored time; an entry with any other member (a misspelt bound) refuses the file, so it can
  never read as "no bound", and `json.Unmarshal` into `EvidenceSourcesFile` runs the same checks.
  Passes every case of the shared `executionEvidence.trustFiles` vectors. Mirrors
  `parseEvidenceSourcesFile` / `evidencePolicyFromFile` in `@intyga/sdk`.
- `ExecutionState.Evidence` is now `[]ExecutionEvidenceRecord`, which adds `SampledAt` and `Sequence`
  (nil when the gateway could not read the statement) and `Late` (sampled after the evidence window
  closed: witnessed, never counted; a late `contradicted` is the
  `challenge.execution_late_contradiction` alert).
- `NewApprovalGuard` for framework-neutral JSON tool callbacks: detached arguments, caller-trusted
  local receipt verification and checked single-use consumption before execution. Optional DEWP
  dispatch reporting preserves the tool's result/error and exposes the nonce for report retries.
  `TenantID` is the independently trusted tenant DIV v2 receipts require, as in the Python guard.

## [2.0.0]

- Bind delegation verification to the independently expected requester; a workload cannot reuse
  another workload's otherwise valid delegation.

- **Breaking: tenant-bound DIV v2 approvals.** Requests and offline approvals carry the tenant
  established by authenticated credentials or a verified trust bundle. Receipt verification requires
  an independently trusted tenant; a receipt cannot choose its own verification context.
- Trust bundles require a nonempty signed `tenantId`; trust-anchor files may pin the expected tenant.
  Offline-intent anchors require an explicit eligible-DID restriction, so delegate keys cannot
  broaden a selected rule's approver set. Ordinary anchors keep their existing behavior.
- Includes the matched 2.0.0 verifier and shared tenant-binding and offline-approval vectors.
  Historical v1 receipts remain verifiable without a tenant expectation; new tenant-bound execution
  refuses them. Publish the full matched set and upgrade consumers before the gateway cutover.
- **Go import migration:** use `github.com/intyga-dev/sdk-go/v2` (bundled verifier:
  `github.com/intyga-dev/sdk-go/v2/verify`). `Expected.TenantID` is a pointer so an explicitly
  empty expectation fails closed.

## [1.2.0]

- **Offline approval (DIV §5a), the SDK half**, to the contract in `docs/OFFLINE-APPROVAL-SDK.md`.
  It passes every section of the shared `offline-approval-vectors.json`. Standard library only.
  - Trust bundles: `VerifyTrustBundle` (RS256 compact JWS against a pinned JWK; the header cannot
    choose the algorithm), `CheckTrustBundleFreshness` (expiry plus a 30-day age cap),
    `SaveTrustBundle` / `LoadTrustBundle`, `ApproverAnchor` (offline signing keys only under
    `BundleAnchorOfflineIntent`) and `RequirementFor` (exact-ID v3 selection; refuses on any conflict).
    The exact-ID policy checks are exported too: `ValidateExactApprovalPolicy`,
    `SelectExactApprovalRule`, `LostApprovalConstraints`, `ValidApprovalActionID`.
  - Trust-anchor files: `ParseTrustAnchorFile` with an `online`/`offline` purpose, and
    `TrustAnchorApprovers`.
  - Ceremony: `CreateOfflineChallenge` (requirement from the bundle, never the caller; a blank
    target is refused; a supplied nonce — `*string` — is used as is, so an empty one is refused),
    `DecodeChallengeEnvelope` (checks every field's shape before re-canonicalizing),
    `EncodeSignatureEnvelope` / `DecodeSignatureEnvelope` (byte-identical `SIG1:` JSON across SDKs;
    decoding takes strict base64url of a JSON object only, trimmed as JavaScript's `trim()` does),
    `SignChallengeEnvelope` (P-256 `crypto.Signer`, PKCS#8 or SEC1 PEM, DER PKCS#8),
    `AssembleOfflineReceipt`, `VerificationCode`. Timestamps follow the strict RFC 3339 grammar of
    DIV §6.2. Builds and behaves identically on 32- and 64-bit platforms.
  - `UseOfflineApproval` runs the whole approval: delegation pick-up, signature collection,
    verification with the offline opt-in, buffering, then single-use redemption through
    `FileRedemptionStore` (exclusive create). `PendingApprovals` / `ClearPendingApproval` read and
    clear the reconciliation buffer. On-disk layout matches every other SDK.
  - Client: `RequireApprovalOptions.Offline` opts in per call. The fallback runs only when the gateway
    could not be asked (a connection failure or timeout, a 5xx, or five consecutive polling failures
    of those kinds), never on a 4xx — a polling streak containing one returns it — `DENIED`,
    `EXPIRED`, a local error or an agent-continuity request, and returns the new
    `StatusOfflineApproved`, never `StatusApproved`. `ReconcileOfflineApprovals` reports buffered
    approvals, clears each only on a 2xx, and counts and names unreadable records instead of
    skipping them.
- Gateway failures are typed: a non-2xx answer is a `*GatewayRefusedError` (status and body; its
  message is unchanged) and no answer at all is a `*GatewayUnreachableError`, so a caller can tell an
  outage from a refusal with `errors.As`.

## [1.1.0]

- No code change. The matched set moves together (`pnpm test:versions`); this release carries the
  new `@intyga/sdk` CLI options and the `require-approval` Action update.

## [1.0.0]

- **Breaking (I11):** `NewClient` now returns `(*Client, error)` and refuses a `GatewayURL` that is
  not `https://`, except `http://` to a loopback host (`localhost`, `127.0.0.0/8`, `::1`) for local
  development, so a misconfiguration fails before any credential is sent.

- Refuse approvals received after the caller's monotonic wait deadline; include challenge creation
  in the wait window and cap polling sleeps to its remaining duration.

- Preserve challenge-issued agent context through approval polling for DIV continuity checks.
- Public witness lookups require no credentials and refuse non-success HTTP responses.
- Default HTTP transports use finite request timeouts and refuse redirects; caller-supplied
  transports remain the caller's responsibility.
- Propagate response-body read failures instead of accepting truncated responses.

- Rebuilt against the DIV Intent Payload's new REQUIRED `evidence` field (DIV §4.3.4), which is
  `null` in this version. No API change; receipts carry the field inside `canonicalPayload` only.

- `Authorize` now omits `actionType` when unset, matching the gateway's optional field schema.
- **Tokens are refreshed automatically.** `Client` now reads `expires_in` from the client-credentials
  exchange and re-exchanges `min(60s, expires_in / 10)` before expiry, so a long-lived client (or a
  `RequireApproval` wait longer than the token's life) no longer fails every call once the token
  has expired. A 401 on an exchanged token is retried exactly once with a fresh exchange. A response
  without a numeric `expires_in` is cached for the life of the client, as before.
- An explicit `ClientOptions.Token` is never re-exchanged; a 401 on it is returned to the caller.
- The token cache is now guarded by a mutex, so `Client` is safe for concurrent use and concurrent
  callers on a cold cache share one exchange (previously an acknowledged benign race).


Initial public release.

- Client with `Authorize` / `Status` / `Consume` / `RequireApproval`; `Target` is required
  (DIV Target Isolation).
- The public module bundles the offline verifier as the `verify` subpackage, so one `go get`
  covers request and independent receipt verification.
