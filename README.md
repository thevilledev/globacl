# globacl

globacl is a prototype implementation of a globally distributed denylist/blocklist design.

## Problem

The motivating system-design problem is from [this X post](https://x.com/championswimmer/status/2057970499389464641):

> One of the most common system design question at Google is to design a distributed denylist/blocklist with SLA of deny configs propagating globally in < 1 min time at 100M+ user scale.

A real-world analogue is [Google Safe Browsing](https://safebrowsing.google.com/): a large blocklist-style system where local lookups, fast updates, and server-backed verification all matter. Google SRE's [Managing Critical State](https://sre.google/sre-book/managing-critical-state/) is useful background for why global deny config needs auditability, rollback, and blast-radius checks.

## Implementation

globacl currently implements this:

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

The propagation path also records per-agent acknowledgements, forwards them into a quorum-replicated central propagation status view, writes per-mutation delta bundles for repair, tags updates as P0/P1/P2 delivery priority, and supports synthetic canaries for measuring propagation.

The control plane includes production-oriented safety hooks around that path: broad-deny blast-radius gates, an append-only audit log, versioned Ed25519 signatures with verifier keyrings, archived snapshot artifacts, forward-only rollback via new mutations, bounded request bodies, stale-agent health reporting, and Prometheus-style metrics listeners that are separate from client-facing APIs.

## Architecture

```text
                 +---------------------+
                 | ACL Authoring/API   |
                 | validation + audit  |
                 +----------+----------+
                            |
                            | sequenced commit
                            v
                 +---------------------+
                 | Source of Truth     |
                 | ACL-specific quorum |
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
              | relay chain/tree          |
              v                           v
      +---------------+           +---------------+
      | PoP Relay     |           | PoP Relay     |
      +-------+-------+           +-------+-------+
              | local fanout              |
              v                           v
      +-------------------------------------------+
      | Edge ACL Engine                           |
      | immutable base + mutable delta overlay    |
      | local exact lookup                        |
      +-------------------------------------------+

 Snapshot/delta artifact store:
   immutable snapshots, delta bundles, repair path
```

## Components

This workspace keeps runtime dependencies small. The shared core uses `ed25519-dalek` for payload signatures; the rest of the implementation stays dependency-light and uses blocking I/O for the prototype.

| Component | Role | What it owns |
| --- | --- | --- |
| `globacl-core` | Shared engine/library | Domain model, per-shard sequencing, binary snapshots, mutation streams, append/compacted logs, delta bundles, compact immutable edge lookup state with an RCU-style handle, compiled IPv4/domain rules, Ed25519 signing helpers, and tests. |
| `globacl-control` | ACL authoring/API gateway | Validates public deny/rule requests, rejects broad updates without override, proxies committed-state reads and writes to `globacl-commitd`, and gives clients a stable API endpoint. |
| `globacl-commitd` | ACL commit service and source of truth | Elects a fenced leader, assigns shard sequences, authenticates internal peer RPCs, replicates committed mutations through quorum, persists and compacts mutation logs behind signed checkpoints, keeps a compacted idempotency stream, aggregates propagation acks through quorum, optionally publishes committed mutations to NATS JetStream, writes snapshot archives plus signed immutable-artifact manifests, records audit entries, serves snapshots/deltas, and performs rollback through forward mutations. |
| `globacl-relay` | Distribution fanout layer | Uses a pluggable source: HTTP pull-proxy from an upstream control/relay or NATS JetStream consumption into a local mutation cache. It serves the same agent-facing HTTP API in both modes, records and forwards PoP acknowledgements, and can be chained into a relay tree. |
| `globacl-agent` | PoP edge updater and lookup library/service | Boots from snapshots, verifies Ed25519 signatures, polls/apply deltas, repairs gaps, sends acks, checks canaries, reports stale health, serves local lookups over HTTP, and exposes an in-process `AgentHandle` for latency-sensitive Rust services. |
| `globacl-demo-app` | Example consumer service | Calls the local agent for request-time ACL decisions by default, or embeds the agent lookup handle directly with `GLOBACL_DEMO_LOOKUP_MODE=embedded`. |
| `globacl-bench` | Local benchmark tool | Measures edge-state build time, process RSS, sampled p50/p95/p99 lookup latency, filter-positive rate, and memory estimates without external dependencies. |

## Docs

- [Getting started](docs/getting-started.md)
- [API](docs/api.md)
- [OpenAPI contract](docs/openapi.yaml)
- [Client generation](docs/client-generation.md)
- [Deployment](docs/deployment.md)
- [Testing](docs/testing.md)

## Clients

- [Go client](clients/go)
- [TypeScript client](clients/typescript)

Regenerate checked-in clients after OpenAPI changes:

```sh
scripts/generate-clients.sh
```

## License

MIT
