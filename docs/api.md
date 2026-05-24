# API

The API uses JSON request and response bodies for the documented HTTP contract. Binary snapshot and mutation-stream endpoints still use `application/octet-stream`.

The machine-readable contract is [OpenAPI](openapi.yaml). It documents the current HTTP surface as it exists today:
`application/json` for control, lookup, status, signature, acknowledgement, and audit endpoints, plus `application/octet-stream` for binary snapshots and mutation streams.
The generated-client plan is in [client-generation.md](client-generation.md).

Required fields for `POST /v1/deny`:

```text
op_id
tenant_id
namespace
key
action=deny|allow_override|delete
```

Optional fields:

```text
delivery_priority=p0|p1|p2
priority=0
reason_code=unspecified
expires_at=0
created_by=unknown
```

Useful endpoints:

```text
GET  /health
POST /v1/deny
POST /v1/rule
POST /v1/canary
GET  /v1/canary/latest
GET  /v1/mutations?shard=0&from_seq=0
GET  /v1/mutations?shard=0&from_seq=0&delivery_priority=p0
GET  /v1/mutations.sig?shard=0&from_seq=0
GET  /v1/watermarks
GET  /v1/delta_bundle?shard=0&from_seq=0&to_seq=10
GET  /v1/delta_bundle.sig?shard=0&from_seq=0&to_seq=10
GET  /v1/snapshot
GET  /v1/snapshot.sig
GET  /v1/snapshot_manifest
GET  /v1/snapshot_manifest.sig
GET  /v1/snapshot_artifact?object=snapshots/max_seq_...
GET  /v1/snapshot_artifact.sig?object=snapshots/max_seq_...
GET  /v1/snapshots
POST /v1/rollback
GET  /v1/audit
GET  /v1/lookup?tenant_id=...&namespace=...&key=...
GET  /v1/check?tenant_id=...&namespace=ip&value=...
POST /v1/ack
GET  /v1/acks
```

Request bodies are capped at 1 MiB by the dependency-free HTTP parser.

## Authentication

Authentication is opt-in for local development. Set `GLOBACL_AUTH_TOKENS` on
`globacl-control` and `globacl-commitd` to require bearer tokens on write and
admin endpoints:

```sh
export GLOBACL_AUTH_TOKENS='admin-token=admin:acl:write,snapshot:write,admin:rollback,audit:read'
```

Clients then send:

```text
Authorization: Bearer admin-token
```

Current scopes:

```text
acl:write       POST /v1/deny, /v1/mutation, /v1/rule, /v1/canary
snapshot:write  POST /v1/snapshot
admin:rollback  POST /v1/rollback
audit:read      GET  /v1/audit
```

The committed audit log records the authenticated actor when auth is enabled.
When auth is disabled, audit entries fall back to the request's `created_by`
field for local demos.

Control `/health` reports gateway health and whether commitd is reachable:

```json
{
  "status": "ok",
  "role": "control",
  "commitd": "ok",
  "commit_addr": "127.0.0.1:7003"
}
```

Commitd `/health` includes quorum state in HA deployments:

```text
role=leader|candidate|follower
node_id=...
cluster_id=...
leader_id=...
term=...
voted_for=...
write_authority=true|false
quorum=2
peer_count=3
last_peer_sync_unix=...
sync_errors=...
```

Commitd followers proxy write requests to the elected leader. The leader assigns the per-shard sequence and only makes the mutation locally visible after a quorum of commit peers prepares it.

Commitd exposes the current compacted mutation-log floor:

```text
GET /v1/compaction_watermarks
```

The response uses the same format as `/v1/watermarks`. If a caller asks `/v1/mutations` or `/v1/delta_bundle` for a `from_seq` older than the compacted floor for that shard, commitd returns `409` with `reason=history_compacted`; agents and relays should repair from `/v1/snapshot`.

The demo consumer app exposes:

```text
GET /health
GET /access?tenant_id=...&namespace=...&key=...
GET /check?tenant_id=...&namespace=ip&value=...
```

It calls the local agent and maps deny decisions to `HTTP 403` with `"access": "denied"`.

## Rule Authoring

`POST /v1/rule` compiles non-point policies into specialized edge indices.

Required fields:

```text
op_id
tenant_id
kind=ipv4_cidr|domain_suffix
pattern
action=deny|allow_override|delete
```

Optional fields are the same as point denies:

```text
delivery_priority=p0|p1|p2
priority=0
reason_code=unspecified
expires_at=0
created_by=unknown
```

## Blast Radius Controls

The control API rejects obviously broad deny requests unless an override flag is present:

```text
override_blast_radius=true
```

The current guard catches point-deny requests for tenant/global wildcards, IPv4 `0.0.0.0/0`, invalid broad rule patterns, and single-label domain suffixes such as `com`. Rejected requests are written to the audit log.

Example broad rule requiring override:

```sh
curl -sS http://127.0.0.1:7000/v1/rule \
  --header 'Content-Type: application/json' \
  --data-binary '{"op_id":"net-all","tenant_id":"tenant-a","kind":"ipv4_cidr","pattern":"0.0.0.0/0","action":"deny","override_blast_radius":true,"reason_code":"emergency_all_ipv4"}'
```

IPv4 CIDR example:

```sh
curl -sS http://127.0.0.1:7000/v1/rule \
  --header 'Content-Type: application/json' \
  --data-binary '{"op_id":"net-1","tenant_id":"tenant-a","kind":"ipv4_cidr","pattern":"10.0.0.0/8","action":"deny","reason_code":"blocked_network"}'
```

Domain suffix example:

```sh
curl -sS http://127.0.0.1:7000/v1/rule \
  --header 'Content-Type: application/json' \
  --data-binary '{"op_id":"domain-1","tenant_id":"tenant-a","kind":"domain_suffix","pattern":"*.example.com","action":"deny","reason_code":"blocked_domain"}'
```

Runtime checks use `/v1/check`:

```text
GET /v1/check?tenant_id=tenant-a&namespace=ip&value=10.1.2.3
GET /v1/check?tenant_id=tenant-a&namespace=domain&value=api.example.com
```

`/v1/lookup` remains the exact point-key lookup endpoint. `/v1/check` evaluates exact point denies first, then compiled rule classes.

## Propagation Fields

`delivery_priority` tags the mutation stream:

```text
p0 emergency deny
p1 normal mutation
p2 repair/snapshot work
```

The exact edge apply path still uses contiguous per-shard sequence numbers. Priority filtering on `/v1/mutations` is intended for inspection and relay/channel work, not for applying out-of-order mutations.

## Relay Sources

The relay exposes the same HTTP API to agents in both source modes:

```text
GLOBACL_RELAY_SOURCE=http       proxy/pull from control or parent relay
GLOBACL_RELAY_SOURCE=jetstream  consume NATS JetStream into relay-local cache
```

In JetStream mode, commitd must publish committed mutations by setting `GLOBACL_COMMITD_PUBLISHER=jetstream`. The relay still uses its HTTP upstream as the bootstrap and repair path for snapshots, signatures, old gaps, canaries, and writes.

## Relay Acknowledgements

PoP agents report applied watermarks to relays with `POST /v1/ack`:

```json
{
  "agent_id": "agent-local",
  "shard_id": 7,
  "seq": 42,
  "entries": 100,
  "applied_at_unix": 1760000000
}
```

Relays expose the current in-memory ack table at `GET /v1/acks`.

Relays also enrich those acks with relay metadata and forward them upstream. The control plane stores the latest ack per `{relay_id, agent_id, shard_id}` in commitd's durable ack log.

```text
GET /v1/propagation/status
```

The central status endpoint returns aggregate propagation coverage:

```json
{
  "status": "ok",
  "shard_count": 64,
  "source_max_seq": 42,
  "ack_count": 3,
  "relay_count": 3,
  "agent_count": 3,
  "acked_shards": 1,
  "max_seq_lag": 0,
  "lagging_ack_count": 0,
  "acks": [
    {
      "relay_id": "relay-region-a",
      "location": "region-a",
      "agent_id": "agent-region-a",
      "shard_id": 7,
      "seq": 42,
      "source_seq": 42,
      "seq_lag": 0
    }
  ]
}
```

In clustered commitd deployments, ack writes and propagation-status reads are routed to the current commit leader.

## Delta Bundles

Commitd writes per-mutation delta bundle files under its data directory and also serves bundle ranges through the control gateway:

```text
GET /v1/delta_bundle?shard=7&from_seq=41&to_seq=42
```

Agents try this repair path when they detect a sequence gap, then fall back to the latest snapshot if bundle repair cannot recover the missing range.

## Snapshots And Rollback

Commitd writes:

```text
data/commitd/snapshots/latest.gacl
data/commitd/snapshots/latest.gacl.sig
data/commitd/snapshots/epoch_<time>_shard_<id>_seq_<seq>.gacl
data/commitd/snapshots/epoch_<time>_shard_<id>_seq_<seq>.gacl.sig
data/commitd/snapshots/objects/snapshots/max_seq_<seq>_sha256_<hash>.gacl
data/commitd/snapshots/objects/snapshots/max_seq_<seq>_sha256_<hash>.gacl.sig
data/commitd/snapshots/manifests/latest.manifest
data/commitd/snapshots/manifests/latest.manifest.sig
data/commitd/snapshots/manifests/epoch_<time>_seq_<seq>_sha256_<hash-prefix>.manifest
data/commitd/snapshots/manifests/epoch_<time>_seq_<seq>_sha256_<hash-prefix>.manifest.sig
```

The manifest is a signed, object-store-compatible pointer to an immutable snapshot artifact. It includes the artifact object name, byte length, SHA-256, schema version, entry/rule counts, and per-shard watermarks. Agents prefer the manifest/artifact path for bootstrap and snapshot repair, then fall back to `GET /v1/snapshot` for compatibility.

`GET /v1/snapshot.sig`, `GET /v1/snapshot_manifest.sig`, `GET /v1/snapshot_artifact.sig`, `GET /v1/mutations.sig`, and `GET /v1/delta_bundle.sig` return Ed25519 signature envelopes:

```text
algorithm=ed25519
key_id=dev-ed25519
key_version=1
signature=<hex-encoded 64-byte signature>
```

Set `GLOBACL_SIGNATURE_KEY_ID`, `GLOBACL_SIGNATURE_KEY_VERSION`, and `GLOBACL_SIGNATURE_PRIVATE_KEY` on commitd and JetStream-backed relays. `GLOBACL_SIGNATURE_PRIVATE_KEY_FILE` can point to key material on disk, or `GLOBACL_SIGNATURE_SIGN_COMMAND` can point to an external signer that reads the payload from stdin and writes a hex Ed25519 signature to stdout.

Agents accept either a single key through `GLOBACL_SIGNATURE_KEY_ID`, `GLOBACL_SIGNATURE_KEY_VERSION`, and `GLOBACL_SIGNATURE_PUBLIC_KEY`, or a keyring through `GLOBACL_SIGNATURE_PUBLIC_KEYS` / `GLOBACL_SIGNATURE_PUBLIC_KEYS_FILE`. Keyring entries use `key_id:key_version:public_key_hex`. Set `GLOBACL_SIGNATURE_MIN_KEY_VERSION` to reject older signed payloads during rotation.

The demo manifests use a public RFC 8032 test key; production deployments should use managed key material and rotate key IDs deliberately.

List available rollback targets:

```sh
curl -sS http://127.0.0.1:7000/v1/snapshots
```

Rollback creates new P0 compensating mutations instead of moving watermarks backwards:

```sh
curl -sS http://127.0.0.1:7000/v1/rollback \
  --header 'Content-Type: application/json' \
  --data-binary '{"snapshot":"epoch_00000000001760000000_shard_0007_seq_00000000000000000042.gacl"}'
```

Agents receive rollback as ordinary forward mutation stream entries.

## Audit Log

Commitd appends audit lines to `data/commitd/audit.log` for committed denies, committed rules, canaries, snapshot uploads, and rollbacks. The public control gateway rejects broad requests before proxying them to commitd.

```sh
curl -sS http://127.0.0.1:7000/v1/audit
```

## Watermarks

`GET /v1/watermarks` returns the latest source-of-truth sequence for every shard:

```json
{
  "shard_count": 4096,
  "shard_0000": 0,
  "shard_0001": 42
}
```

Agents use this to avoid scanning every shard when nothing changed.

## Agent Health State

Agent `/health` includes edge-state sizing and overlay counters:

```json
{
  "status": "ok",
  "base_entries": 100,
  "delta_adds": 1,
  "delta_removes": 0,
  "filter_bits": 2048,
  "filter_hashes": 8,
  "estimated_state_bytes": 8192,
  "stale": false
}
```

The steady-state lookup path checks the exact delta overlay first, then uses the immutable base filter as a negative accelerator before probing the sorted exact base index.

Compiled rule checks use:

```text
IPv4 CIDR: prefix-indexed IPv4 table
domain suffix: canonical suffix table
```

## Canaries

`POST /v1/canary` commits a synthetic P0 deny under:

```text
tenant_id: globacl
namespace: canary
```

`GET /v1/canary/latest` returns the most recent canary key and sequence. Agents poll this endpoint and expose the last observed canary in `/health`.
