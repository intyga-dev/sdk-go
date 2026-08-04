# sdk-go — Intyga client for Go

Gate any high-risk backend action behind a real human approval. The primitive is uniform: **request a challenge → a human approves with a passkey or security key → poll until resolved** — the same client works for scripts, pipelines, and AI agents.

This package **bundles the offline verifier** (`github.com/intyga-dev/sdk-go/verify`), so you can request an approval *and* independently verify the receipt without adding a second dependency.

> The standalone verifier also ships on its own as [`verify-go`](https://github.com/intyga-dev/verify-go).

## Install

```sh
go get github.com/intyga-dev/sdk-go
```

## Require a human approval before a high-risk action

```go
import (
	"context"

	intyga "github.com/intyga-dev/sdk-go"
	verify "github.com/intyga-dev/sdk-go/verify"
)

client := intyga.NewClient(intyga.ClientOptions{
	GatewayURL:   "https://api.intyga.com",
	ClientID:     os.Getenv("INTYGA_CLIENT_ID"),
	ClientSecret: os.Getenv("INTYGA_CLIENT_SECRET"),
})

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
res := verify.VerifyApprovalReceipt(*r.Receipt, verify.Expected{
	Target:     "prod-db-cluster-01",
	Nonce:      r.Nonce,
	ActionType: "wipe_production",
	Params:     params,
	Approvers:  verify.ApproverTrustAnchor{PublicKeys: trustedApproverKeys()},
}, verify.VerifyOptions{})
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

Works identically whether the token is a **human key** (backend/service) or an **agent key** — Intyga is a general zero-trust gate for *any* backend action, not just agents.

## API

- `NewClient(ClientOptions)` — construct a client (no I/O).
- `RequireApproval(ctx, description, opts)` — create a challenge and block until resolved.
- `Authorize` / `Status` / `Consume` — the individual steps (create, poll, execution-time re-bind).
  `Authorize` requires `Target`; `Consume` takes `(ctx, nonce, target, actionType, params)` and must be
  given the same target the approval was bound to.
- `Verify(ctx, documentHash)` — public witness lookup.

## Also available in
- TypeScript — [`@intyga/sdk`](https://github.com/intyga-dev/sdk)
- Python — [`sdk-python`](https://github.com/intyga-dev/sdk-python)
- Rust — [`sdk-rust`](https://github.com/intyga-dev/sdk-rust)

## License

Apache-2.0.
