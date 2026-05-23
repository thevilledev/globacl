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

The control plane now includes production-hardening hooks around that path: broad-deny blast-radius gates, an append-only audit log, keyed integrity seals for snapshots and update payloads, archived snapshot artifacts, forward-only rollback via new mutations, bounded request bodies, and stale-agent health reporting.

## Components

This workspace intentionally has no third-party crate dependencies yet, so it can build in restricted environments.

- `globacl-core`: domain model, idempotent source-of-truth state, immutable sorted edge index, negative filter, exact delta overlay, compiled IPv4/domain rule indices, binary mutation stream, binary snapshot format, per-shard append log, delta bundle, and ack helpers.
- `globacl-control`: ACL authoring/API service with point-deny and compiled-rule authoring, blast-radius checks, audit logging, signed snapshot archives, rollback by compensating mutations, a linearized in-process source of truth, and durable per-shard append logs.
- `globacl-relay`: regional relay that proxies mutation/snapshot fetches, records PoP acknowledgements, and can be chained as a location-aware relay tree.
- `globacl-agent`: PoP agent that cold-starts from a snapshot, verifies snapshot/mutation integrity seals when present, polls deltas through the relay, repairs gaps, acknowledges watermarks, checks canaries, reports stale health, applies exact local state, and exposes local lookup.
- `globacl-bench`: dependency-free benchmark runner for edge state build time, positive lookups, negative lookups, and memory estimates.

## Docs

- [Getting started](docs/getting-started.md)
- [API](docs/api.md)
- [Testing](docs/testing.md)
