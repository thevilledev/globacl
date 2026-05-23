# Testing

Run all tests:

```sh
cargo test
```

Run the edge lookup benchmark:

```sh
cargo run -p globacl-bench --release -- 100000 1000000 4096
```

Arguments are:

```text
entry_count lookup_count shard_count
```

The core tests cover:

- duplicate `op_id` idempotency
- exact add/delete lookup behavior
- binary snapshot roundtrip
- binary mutation-stream roundtrip
- delivery-priority roundtrip
- gap detection for out-of-order mutation apply
- per-shard append-log replay
- delta-bundle file roundtrip
- PoP acknowledgement parsing/formatting
- source watermark formatting/parsing
- immutable base plus exact delta overlay behavior
- IPv4 CIDR rule compilation and matching
- domain suffix rule compilation and matching
- rule delete overlays
- broad-deny blast-radius detection
- snapshot rollback through forward compensating mutations
- dependency-free payload signature verification

For an end-to-end smoke test, run the services from [Getting started](getting-started.md), commit a deny, query the agent, commit an IPv4/domain rule, check it through `/v1/check`, inspect relay acknowledgements, verify `/v1/audit`, list `/v1/snapshots`, then commit a delete and confirm the agent returns `decision=allow`.

Run k3d-backed k3s smoke tests:

```sh
./deploy/k3s/local-smoke.sh
./deploy/k3s/global-smoke.sh
```

The local smoke deploys one control, one relay, one agent, and one demo app in a single k3s cluster. The global smoke deploys central control in one k3s cluster plus three regional k3s clusters with HA relays and demo apps.

Rollback smoke test:

```text
1. Start control, relay, and agent.
2. Commit a deny and wait for the agent to return decision=deny.
3. Pick an older snapshot from GET /v1/snapshots.
4. POST /v1/rollback with that snapshot filename.
5. Confirm the agent receives forward rollback mutations and returns the snapshot's expected decision.
```

Stale-agent smoke test:

```text
1. Start the agent with stale_after_secs=2.
2. Stop or block the relay.
3. Wait more than 2 seconds.
4. GET /health from the agent and confirm status=stale.
```
