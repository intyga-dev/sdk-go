# Changelog

All notable changes to `github.com/intyga-dev/sdk-go` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

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
