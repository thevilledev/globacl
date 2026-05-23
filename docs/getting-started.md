# Getting Started

Start the control plane:

```sh
cargo run -p globacl-control -- data/control 127.0.0.1:7000 4096
```

Start one regional relay:

```sh
cargo run -p globacl-relay -- 127.0.0.1:7000 127.0.0.1:7001
```

Start one PoP agent:

```sh
cargo run -p globacl-agent -- 127.0.0.1:7001 127.0.0.1:7002 data/agent/latest.gacl 1000
```

Commit a deny mutation:

```sh
curl -sS http://127.0.0.1:7000/v1/deny \
  --data-binary $'op_id=demo-1\ntenant_id=tenant-a\nnamespace=user\nkey=user-123\naction=deny\npriority=100\nreason_code=abuse\ncreated_by=demo\n'
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
