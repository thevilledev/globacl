# Testing

Run all tests:

```sh
cargo test
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

For an end-to-end smoke test, run the services from [Getting started](getting-started.md), commit a deny, query the agent, inspect relay acknowledgements, then commit a delete and confirm the agent returns `decision=allow`.
