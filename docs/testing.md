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
- gap detection for out-of-order mutation apply
- per-shard append-log replay
