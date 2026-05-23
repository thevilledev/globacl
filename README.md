# globacl

globacl is an implementation of a globally distributed denylist/blocklist design.

## Problem

The motivating system-design problem is:

> One of the most common system design question at Google is to design a distributed denylist/blocklist with SLA of deny configs propagating globally in < 1 min time at 100M+ user scale.

globacl implements the core shape of that system:

```text
ACL API
  -> ACL commit service
  -> durable per-shard append log
  -> HTTP pull-proxy or NATS JetStream relay source
  -> relay fanout
  -> PoP agent
  -> local exact lookup engine
  -> binary snapshots for bootstrap and repair
```

The request path evaluates denies locally. Updates enter the stateless control API, are committed by the separate ACL commit service, assigned per-shard sequence numbers, replicated across commit peers in the HA deployment, exposed through a mutation stream, pulled or consumed by the relay/agent path, and applied to the local edge state. Snapshots provide cold-start and repair without relying on JSON polling as the main propagation mechanism.

The relay can run in the default HTTP pull-proxy mode or in NATS JetStream mode. Pull-proxy mode keeps the repo easy to run locally. JetStream mode lets commitd publish committed mutations to a durable stream while relays consume into a local cache and keep the agent-facing HTTP API unchanged.

The propagation path also records per-agent acknowledgements, writes per-mutation delta bundles for repair, tags updates as P0/P1/P2 delivery priority, and supports synthetic canaries for measuring propagation.

The control plane now includes production-hardening hooks around that path: broad-deny blast-radius gates, an append-only audit log, keyed integrity seals for snapshots and update payloads, archived snapshot artifacts, forward-only rollback via new mutations, bounded request bodies, and stale-agent health reporting.

## Architecture

```text
                 +---------------------+
                 | ACL Authoring/API   |
                 | validation + audit  |
                 +----------+----------+
                            |
                            | linearizable commit
                            v
                 +---------------------+
                 | Source of Truth     |
                 | ACL-specific Raft   |
                 | commit service      |
                 +----------+----------+
                            |
                            | append-only per-shard log
                            v
                 +---------------------+
                 | Relay Source        |
                 | HTTP pull / NATS JS |
                 +----------+----------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
      +---------------+           +---------------+
      | Region Relay  |           | Region Relay  |
      +-------+-------+           +-------+-------+
              | location-aware tree       |
              v                           v
      +---------------+           +---------------+
      | PoP Relay     |           | PoP Relay     |
      +-------+-------+           +-------+-------+
              | local fanout              |
              v                           v
      +-------------------------------------------+
      | Edge ACL Engine                           |
      | immutable base + mutable delta overlay    |
      | lock-free/RCU lookup                      |
      +-------------------------------------------+

 CDN/object store:
   immutable snapshots, delta bundles, manifests, repair path
```

## Components

This workspace intentionally has no third-party crate dependencies yet, so it can build in restricted environments.

| Component | Role | What it owns |
| --- | --- | --- |
| `globacl-core` | Shared engine/library | Domain model, per-shard sequencing, binary snapshots, mutation streams, append logs, delta bundles, edge lookup state, compiled IPv4/domain rules, integrity seals, and tests. |
| `globacl-control` | ACL authoring/API gateway | Validates public deny/rule requests, rejects broad updates without override, proxies committed-state reads and writes to `globacl-commitd`, and gives clients a stable API endpoint. |
| `globacl-commitd` | ACL commit service and source of truth | Elects a Raft-style leader, assigns shard sequences, replicates committed mutations through quorum, persists mutation logs, optionally publishes committed mutations to NATS JetStream, writes snapshot archives, records audit entries, serves snapshots/deltas, and performs rollback through forward mutations. |
| `globacl-relay` | Distribution fanout layer | Uses a pluggable source: HTTP pull-proxy from an upstream control/relay or NATS JetStream consumption into a local mutation cache. It serves the same agent-facing HTTP API in both modes, records PoP acknowledgements, and can be chained into a relay tree. |
| `globacl-agent` | PoP edge updater and lookup service | Boots from snapshots, verifies integrity seals, polls/apply deltas, repairs gaps, sends acks, checks canaries, reports stale health, and serves local lookups. |
| `globacl-demo-app` | Example consumer service | Calls the local agent for request-time ACL decisions and returns `access=allowed` or `access=denied`. |
| `globacl-bench` | Local benchmark tool | Measures edge-state build time, positive lookups, negative lookups, and memory estimates without external dependencies. |

## Docs

- [Getting started](docs/getting-started.md)
- [API](docs/api.md)
- [Deployment](docs/deployment.md)
- [Testing](docs/testing.md)
- [Architecture gaps](docs/architecture-gaps.md)
- [Research sources](docs/research.md)
