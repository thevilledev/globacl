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

For an end-to-end smoke test, run the services from [Getting started](getting-started.md), commit a deny, query the agent, inspect relay acknowledgements, then commit a delete and confirm the agent returns `decision=allow`.
