# API

The API uses newline-delimited `key=value` request bodies instead of JSON.

Required fields for `POST /v1/deny`:

```text
op_id
tenant_id
namespace
key
```

Optional fields:

```text
action=deny|allow_override|delete
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
POST /v1/canary
GET  /v1/canary/latest
GET  /v1/mutations?shard=0&from_seq=0
GET  /v1/mutations?shard=0&from_seq=0&delivery_priority=p0
GET  /v1/watermarks
GET  /v1/delta_bundle?shard=0&from_seq=0&to_seq=10
GET  /v1/snapshot
GET  /v1/lookup?tenant_id=...&namespace=...&key=...
POST /v1/ack
GET  /v1/acks
```

## Propagation Fields

`delivery_priority` tags the mutation stream:

```text
p0 emergency deny
p1 normal mutation
p2 repair/snapshot work
```

The exact edge apply path still uses contiguous per-shard sequence numbers. Priority filtering on `/v1/mutations` is intended for inspection and relay/channel work, not for applying out-of-order mutations.

## Relay Acknowledgements

PoP agents report applied watermarks to relays with `POST /v1/ack`:

```text
agent_id=agent-local
shard_id=7
seq=42
entries=100
applied_at_unix=1760000000
```

Relays expose the current in-memory ack table at `GET /v1/acks`.

## Delta Bundles

Control writes per-mutation delta bundle files under its data directory and also serves bundle ranges:

```text
GET /v1/delta_bundle?shard=7&from_seq=41&to_seq=42
```

Agents try this repair path when they detect a sequence gap, then fall back to the latest snapshot if bundle repair cannot recover the missing range.

## Watermarks

`GET /v1/watermarks` returns the latest source-of-truth sequence for every shard:

```text
shard_count=4096
shard_0000=0
shard_0001=42
...
```

Agents use this to avoid scanning every shard when nothing changed.

## Agent Health State

Agent `/health` includes edge-state sizing and overlay counters:

```text
base_entries=...
delta_adds=...
delta_removes=...
filter_bits=...
estimated_state_bytes=...
```

The steady-state lookup path checks the exact delta overlay first, then uses the immutable base filter as a negative accelerator before probing the sorted exact base index.

## Canaries

`POST /v1/canary` commits a synthetic P0 deny under:

```text
tenant_id=globacl
namespace=canary
```

`GET /v1/canary/latest` returns the most recent canary key and sequence. Agents poll this endpoint and expose the last observed canary in `/health`.
