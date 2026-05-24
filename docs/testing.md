# Testing

Run all tests:

```sh
cargo test
```

Run OpenAPI/backend contract tests:

```sh
cargo test -p globacl-contract-tests --locked
```

The contract tests start real commitd, control, relay, and agent processes on loopback ports with a non-default signature keypair. They check the documented OpenAPI paths against backend status codes, `Content-Type` headers, key response fields, binary snapshot/mutation decoding, signatures, propagation acknowledgements, and audit output.

Run the edge lookup benchmark:

```sh
cargo run -p globacl-bench --release -- 100000 1000000 4096
```

The positional arguments are still accepted:

```text
entry_count lookup_count shard_count
```

The benchmark also supports named options and a CI-sized profile:

```sh
cargo run -p globacl-bench --release -- --ci
cargo run -p globacl-bench --release -- --entries 10000000 --lookups 10000000 --shards 4096
```

It reports snapshot/build time, process RSS where supported, estimated state bytes, filter bit/hash settings, sampled p50/p95/p99/p99.9 lookup latency, and negative-filter-positive rate. Use `--sample-limit` to cap latency samples for very large runs.

The core tests cover:

- duplicate `op_id` idempotency
- prepared commits remaining invisible until replicated application
- exact add/delete lookup behavior
- binary snapshot roundtrip
- snapshot manifest roundtrip and artifact validation
- binary mutation-stream roundtrip
- delivery-priority roundtrip
- gap detection for out-of-order mutation apply
- per-shard append-log replay
- checkpointed log compaction and snapshot-plus-tail replay
- delta-bundle file roundtrip
- PoP acknowledgement parsing/formatting
- central propagation acknowledgement log replay and follower rehydration
- source watermark formatting/parsing
- commitd vote/heartbeat, restart, catch-up, pending-entry, quorum-loss, and stale-leader consensus invariants
- commitd log compaction with persisted idempotency replay
- multi-process commitd leader-isolation partition behavior
- immutable base plus exact delta overlay behavior
- RCU-style active-state handle swaps
- IPv4 CIDR rule compilation and matching
- domain suffix rule compilation and matching
- rule delete overlays
- broad-deny blast-radius detection
- snapshot rollback through forward compensating mutations
- Ed25519 payload signature verification
- signature keyring parsing and minimum-version downgrade rejection

For an end-to-end smoke test, run the services from [Getting started](getting-started.md), commit a deny, query the agent, commit an IPv4/domain rule, check it through `/v1/check`, inspect relay acknowledgements, verify `/v1/audit`, list `/v1/snapshots`, then commit a delete and confirm the agent returns `"decision": "allow"`.

Run k3d-backed k3s smoke tests:

```sh
./deploy/k3s/local-smoke.sh
./deploy/k3s/jetstream-smoke.sh
./deploy/k3s/global-smoke.sh
```

The local smoke deploys one commitd, one control gateway, one relay, one agent, and one demo app in a single k3s cluster. The JetStream smoke uses the same local shape, adds NATS JetStream, enables commitd publishing, switches the relay to `GLOBACL_RELAY_SOURCE=jetstream`, and verifies that the demo app observes a deny through the agent. The global smoke deploys a three-replica central commitd StatefulSet with persistent volumes, stateless central control gateways, plus three regional k3s clusters with HA relays and demo apps.

The global smoke also exercises the custom control-plane consensus path: the three central commitd pods elect a leader, writes can arrive through any control gateway pod, and committed mutations are replicated to the commitd quorum before regional relays and agents observe them.

Run the focused multi-process partition test:

```sh
cargo test -p globacl-commitd --test multi_process_partition --locked
```

This starts three real `globacl-commitd` processes behind per-link loopback TCP proxies, isolates the current leader, verifies the isolated leader cannot commit or apply a mutation without quorum, and verifies the remaining two-node majority elects a leader and commits.

Rollback smoke test:

```text
1. Start control, relay, and agent.
2. Commit a deny and wait for the agent to return `"decision": "deny"`.
3. Pick an older snapshot from GET /v1/snapshots.
4. POST /v1/rollback with that snapshot filename.
5. Confirm the agent receives forward rollback mutations and returns the snapshot's expected decision.
```

Stale-agent smoke test:

```text
1. Start the agent with stale_after_secs=2.
2. Stop or block the relay.
3. Wait more than 2 seconds.
4. GET /health from the agent and confirm `"status": "stale"`.
```
