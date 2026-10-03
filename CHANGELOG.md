# Changelog

All notable changes to `github.com/intyga-dev/sdk-go` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

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
