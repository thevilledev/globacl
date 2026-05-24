# globacl Go Client

Generated models live in `globacl/client.gen.go`. The ergonomic wrapper is in
`globacl/client.go`.

Use:

```go
client, err := globacl.NewClient("http://127.0.0.1:7000")
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

Regenerate from `docs/openapi.yaml`:

```sh
scripts/generate-clients.sh
```
