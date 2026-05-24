# Client Generation Plan

`docs/openapi.yaml` is the source of truth for generated clients. The public client
surface is:

```text
authoring clients -> globacl-control
runtime applications -> local globacl-agent
relays and agents -> propagation and repair APIs
```

Direct commitd internals stay out of the generated public clients.

## Current Contract

The OpenAPI spec uses named schemas for request and response bodies instead of
generic JSON maps. Binary endpoints remain typed as byte payloads:

```text
GET /v1/mutations
GET /v1/delta_bundle
GET /v1/snapshot
GET /v1/snapshot_artifact
```

Generated clients should expose those as bytes and leave binary snapshot/mutation
decoding to dedicated codec libraries.

## Go Client

Use `oapi-codegen` for the Go client.

Planned layout:

```text
clients/go/
  go.mod
  globacl/
    client.gen.go
    types.gen.go
  oapi-codegen.yaml
```

Generation command:

```text
oapi-codegen -config clients/go/oapi-codegen.yaml docs/openapi.yaml
```

The generated package should include:

```text
typed request/response structs
net/http client
context-aware methods
raw []byte returns for binary endpoints
small handwritten helpers for common deny, rule, lookup, and check calls
```

## TypeScript Client

Use `openapi-typescript` for schema types and `openapi-fetch` for a lightweight
typed fetch client.

Planned layout:

```text
clients/typescript/
  package.json
  src/
    generated/schema.d.ts
    client.ts
    index.ts
  tsconfig.json
```

Generation command:

```text
pnpm exec openapi-typescript docs/openapi.yaml \
  -o clients/typescript/src/generated/schema.d.ts
```

The handwritten wrapper should expose:

```text
createControlClient(baseUrl)
createAgentClient(baseUrl)
deny(request)
rule(request)
lookup(params)
check(params)
getWatermarks()
getSnapshot()
getMutations(params)
```

Binary endpoints should return `ArrayBuffer`.

## Version Pinning

When generation is implemented, pin tool versions in repo config:

```text
.mise.toml:
  Go runtime/tooling for oapi-codegen
  Node/pnpm for TypeScript generation

clients/typescript/package.json:
  exact devDependency versions

clients/go/tools.go or mise task:
  exact oapi-codegen version
```

Do not rely on globally installed generators in CI.

## OpenAPI Dialect

The checked-in contract currently uses OpenAPI 3.1. TypeScript tooling generally
handles this well. If the chosen Go generator rejects 3.1 features such as
`patternProperties`, add a generated compatibility artifact instead of weakening
the source contract:

```text
docs/openapi.yaml          source contract
docs/openapi.codegen.yaml  generated 3.0-compatible client input
```

The compatibility artifact must be produced by a pinned task and checked by CI so
the generated clients always match the source contract.

## Int64 Policy

The HTTP API currently emits sequence numbers, key hashes, and timestamps as JSON
numbers. Go can represent these as `int64` or `uint64` cleanly. TypeScript clients
must treat them carefully because JSON numbers can exceed `Number.MAX_SAFE_INTEGER`.

Initial TypeScript client behavior:

```text
use generated number types from the current JSON wire format
add runtime helpers that reject unsafe integer values where exactness matters
document that seq/key_hash values are opaque identifiers, not arithmetic inputs
```

If the API needs JavaScript-safe exactness later, introduce a versioned wire-format
change that serializes large IDs as strings.

## CI Plan

Add a generated-client check after the first clients are committed:

```text
mise run openapi
mise run generate-go-client
mise run generate-typescript-client
cargo test -p globacl-contract-tests --locked
git diff --exit-code clients/
```

The generated-client check should run in normal CI. k3s smoke tests remain manual.
