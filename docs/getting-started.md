# Getting Started

Start the control plane:

```sh
cargo run -p globacl-control -- data/control 127.0.0.1:7000 4096 0
```

The final argument is the synthetic canary interval in seconds. Use `0` to disable automatic canaries, or a positive value such as `60` to inject a P0 canary every minute.

Start one regional relay:

```sh
cargo run -p globacl-relay -- 127.0.0.1:7000 127.0.0.1:7001 relay-local local
```

The relay can point at control or at another relay, which lets you chain `global -> region -> PoP` in the local model.

Start one PoP agent:

```sh
cargo run -p globacl-agent -- 127.0.0.1:7001 127.0.0.1:7002 data/agent/latest.gacl 1000 agent-local
```

Commit a deny mutation:

```sh
curl -sS http://127.0.0.1:7000/v1/deny \
  --data-binary $'op_id=demo-1\ntenant_id=tenant-a\nnamespace=user\nkey=user-123\naction=deny\ndelivery_priority=p0\npriority=100\nreason_code=abuse\ncreated_by=demo\n'
```

Query the agent:

```sh
curl -sS 'http://127.0.0.1:7002/v1/lookup?tenant_id=tenant-a&namespace=user&key=user-123'
```

Delete/unblock with a higher sequence:

```sh
curl -sS http://127.0.0.1:7000/v1/deny \
  --data-binary $'op_id=demo-2\ntenant_id=tenant-a\nnamespace=user\nkey=user-123\naction=delete\ncreated_by=demo\n'
```

Inspect relay acknowledgements:

```sh
curl -sS http://127.0.0.1:7001/v1/acks
```

Commit a synthetic P0 canary manually:

```sh
curl -sS -X POST http://127.0.0.1:7000/v1/canary
```

Then check the latest canary status through the agent:

```sh
curl -sS http://127.0.0.1:7002/health
```
