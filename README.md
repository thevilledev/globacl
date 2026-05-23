# globacl

globacl is an implementation of a globally distributed denylist/blocklist design.

## Problem

The motivating system-design problem is:

> One of the most common system design question at Google is to design a distributed denylist/blocklist with SLA of deny configs propagating globally in < 1 min time at 100M+ user scale.

globacl implements the core shape of that system:

```text
ACL API
  -> linearized source of truth
  -> durable per-shard append log
  -> relay fanout
  -> PoP agent
  -> local exact lookup engine
  -> binary snapshots for bootstrap and repair
```

The request path evaluates denies locally. Updates are committed to the source of truth, assigned per-shard sequence numbers, exposed through a mutation stream, pulled by the relay/agent path, and applied to the local edge state. Snapshots provide cold-start and repair without relying on JSON polling as the main propagation mechanism.

The propagation path also records per-agent acknowledgements, writes per-mutation delta bundles for repair, tags updates as P0/P1/P2 delivery priority, and supports synthetic canaries for measuring propagation.

## Components

This workspace intentionally has no third-party crate dependencies yet, so it can build in restricted environments.

- `globacl-core`: domain model, idempotent source-of-truth state, exact lookup engine, binary mutation stream, binary snapshot format, per-shard append log, delta bundle, and ack helpers.
- `globacl-control`: ACL authoring/API service with a linearized in-process source of truth and durable per-shard append logs.
- `globacl-relay`: regional relay that proxies mutation/snapshot fetches, records PoP acknowledgements, and can be chained as a location-aware relay tree.
- `globacl-agent`: PoP agent that cold-starts from a snapshot, polls deltas through the relay, repairs gaps, acknowledges watermarks, checks canaries, applies exact local state, and exposes local lookup.

## Docs

- [Getting started](docs/getting-started.md)
- [API](docs/api.md)
- [Testing](docs/testing.md)
