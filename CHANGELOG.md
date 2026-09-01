# Changelog

All notable changes to `github.com/intyga-dev/sdk-go` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **Tokens are refreshed automatically.** `Client` now reads `expires_in` from the client-credentials
  exchange and re-exchanges `min(60s, expires_in / 10)` before expiry, so a long-lived client (or a
  `RequireApproval` wait longer than the token's life) no longer fails every call once the token
  has expired. A 401 on an exchanged token is retried exactly once with a fresh exchange. A response
  without a numeric `expires_in` is cached for the life of the client, as before.
- An explicit `ClientOptions.Token` is never re-exchanged; a 401 on it is returned to the caller.
- The token cache is now guarded by a mutex, so `Client` is safe for concurrent use and concurrent
  callers on a cold cache share one exchange (previously an acknowledged benign race).

## [1.0.0]

Initial public release.

- Client with `Authorize` / `Status` / `Consume` / `RequireApproval`; `Target` is required
  (DIV Target Isolation).
- The public module bundles the offline verifier as the `verify` subpackage, so one `go get`
  covers request and independent receipt verification.
