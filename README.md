# sdk-go — SÄKRA client for Go

Gate any high-risk backend action behind a real human approval. The primitive is uniform: **request a challenge → a human approves with a passkey or security key → poll until resolved** — the same client works for scripts, pipelines, and AI agents.

This package **bundles the offline verifier** (`github.com/sakra-trust/sdk-go/verify`), so you can request an approval *and* independently verify the receipt without adding a second dependency.

> Status: **not yet published**. The standalone verifier also ships on its own as [`verify-go`](https://github.com/SAKRA-trust/verify-go).

## Install

```sh
go get github.com/sakra-trust/sdk-go
```

## Require a human approval before a high-risk action

```go
import (
	"context"

	sakra "github.com/sakra-trust/sdk-go"
	verify "github.com/sakra-trust/sdk-go/verify"
)

client := sakra.NewClient(sakra.ClientOptions{
	GatewayURL:   "https://api.sakra.com",
	ClientID:     os.Getenv("SAKRA_CLIENT_ID"),
	ClientSecret: os.Getenv("SAKRA_CLIENT_SECRET"),
})

// Blocks until the human approves with their passkey / security key (or times out):
r, err := client.RequireApproval(context.Background(), "Delete production database",
	sakra.RequireApprovalOptions{
		AuthorizeOptions: sakra.AuthorizeOptions{
			ActionType: "wipe_production",
			Params:     map[string]interface{}{"target": "prod-db-1"},
		},
	})
if err != nil || r.Status != sakra.StatusApproved {
	log.Fatal("not authorized")
}

// Optional hard binding before executing — no SÄKRA secret involved:
res := verify.VerifyApprovalReceipt(*r.Receipt, verify.Expected{
	Nonce: r.Nonce, ActionType: "wipe_production",
	Params: map[string]interface{}{"target": "prod-db-1"},
}, verify.VerifyOptions{})
if !res.OK {
	log.Fatalf("refusing to proceed: %s", res.Reason)
}
```

Works identically whether the token is a **human key** (backend/service) or an **agent key** — SÄKRA is a general zero-trust gate for *any* backend action, not just agents.

## API

- `NewClient(ClientOptions)` — construct a client (no I/O).
- `RequireApproval(ctx, description, opts)` — create a challenge and block until resolved.
- `Authorize` / `Status` / `Consume` — the individual steps (create, poll, execution-time re-bind).
- `Verify(ctx, documentHash)` — public witness lookup.

## Also available in
- TypeScript — [`@sakra-trust/sdk`](https://github.com/SAKRA-trust/sdk)
- Python — [`sdk-python`](https://github.com/SAKRA-trust/sdk-python)
- Rust — [`sdk-rust`](https://github.com/SAKRA-trust/sdk-rust)

## License

Apache-2.0.
