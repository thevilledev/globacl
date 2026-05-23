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

| Component | Role | What it owns |
| --- | --- | --- |
| `globacl-core` | Shared engine/library | Domain model, per-shard sequencing, binary snapshots, mutation streams, append logs, delta bundles, edge lookup state, compiled IPv4/domain rules, integrity seals, and tests. |
| `globacl-control` | ACL authoring and source of truth | Accepts deny/rule writes, assigns shard sequences, persists mutation logs, writes snapshot archives, applies blast-radius checks, records audit entries, and performs rollback through forward mutations. |
| `globacl-relay` | Distribution fanout layer | Proxies mutations, watermarks, snapshots, and delta bundles from an upstream control/relay; records PoP acknowledgements; can be chained into a relay tree. |
| `globacl-agent` | PoP edge updater and lookup service | Boots from snapshots, verifies integrity seals, polls/apply deltas, repairs gaps, sends acks, checks canaries, reports stale health, and serves local lookups. |
| `globacl-bench` | Local benchmark tool | Measures edge-state build time, positive lookups, negative lookups, and memory estimates without external dependencies. |

## Docs

- [Getting started](docs/getting-started.md)
- [API](docs/api.md)
- [Testing](docs/testing.md)
