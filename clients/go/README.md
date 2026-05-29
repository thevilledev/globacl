# globacl Go Client

Generated models live in `globacl/client.gen.go`. The ergonomic wrapper is in
`globacl/client.go`.

Use:

```go
client, err := globacl.NewClient(
    "http://127.0.0.1:7000",
    globacl.WithBearerToken("admin-token"),
)
if err != nil {
    panic(err)
}

outcome, err := client.Deny(context.Background(), globacl.DenyMutationRequest{
    OpId:     "demo-1",
    TenantId: "tenant-a",
    Namespace: "user",
    Key:      "user-123",
    Action:   globacl.ActionDeny,
})
```

Regenerate from `docs/openapi.yaml` at the repo root:

```sh
scripts/generate-clients.sh
```

The k3s e2e tests use `cmd/globacl-e2e` as their API assertion runner:

```sh
go run ./cmd/globacl-e2e wait-health --base-url http://127.0.0.1:7000
go run ./cmd/globacl-e2e deny --base-url http://127.0.0.1:7000 \
  --op-id demo-1 --tenant-id tenant-a --namespace user --key user-123
```

For auth-enabled environments, set `GLOBACL_BEARER_TOKEN` before running the
e2e runner.
