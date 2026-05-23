# Getting Started

Start the ACL commit service:

```sh
cargo run -p globacl-commitd -- data/commitd 127.0.0.1:7003 4096 0
```

The final argument is the synthetic canary interval in seconds. Use `0` to disable automatic canaries, or a positive value such as `60` to inject a P0 canary every minute.

Optional Ed25519 signing keys can be set on commitd, relays, and agents:

```sh
export GLOBACL_SIGNATURE_KEY_ID=dev-ed25519
export GLOBACL_SIGNATURE_PRIVATE_KEY=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
export GLOBACL_SIGNATURE_PUBLIC_KEY=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

`globacl-commitd` and JetStream-backed relays need the private key to sign payloads. `globacl-agent` needs only the public key to verify payloads.

Start the public control API gateway:

```sh
cargo run -p globacl-control -- 127.0.0.1:7003 127.0.0.1:7000
```

The control process is stateless. It validates public authoring requests and proxies committed-state APIs to `globacl-commitd`.

Start one regional relay:

```sh
cargo run -p globacl-relay -- 127.0.0.1:7000 127.0.0.1:7001 relay-local local
```

The relay can point at control or at another relay, which lets you chain `global -> region -> PoP` in the local model.

The default relay source is HTTP pull-proxy. To use NATS JetStream instead, run NATS separately with JetStream enabled, start commitd with publishing enabled, and start the relay with `GLOBACL_RELAY_SOURCE=jetstream`:

```sh
GLOBACL_COMMITD_PUBLISHER=jetstream \
GLOBACL_NATS_ADDR=127.0.0.1:4222 \
cargo run -p globacl-commitd -- data/commitd 127.0.0.1:7003 4096 0

GLOBACL_RELAY_SOURCE=jetstream \
GLOBACL_NATS_ADDR=127.0.0.1:4222 \
cargo run -p globacl-relay -- 127.0.0.1:7000 127.0.0.1:7001 relay-local local
```

In JetStream mode, the relay still exposes the same HTTP API to agents. It uses control as the bootstrap/repair path for snapshots, signatures, and old gaps.

Start one PoP agent:

```sh
cargo run -p globacl-agent -- 127.0.0.1:7001 127.0.0.1:7002 data/agent/latest.gacl 1000 agent-local 60
```

The final argument is `stale_after_secs`; the agent reports `status=stale` if it cannot successfully poll the relay within that window.

Start the demo consumer app:

```sh
cargo run -p globacl-demo-app -- 127.0.0.1:7002 127.0.0.1:8080
```

The demo app calls the local agent on every request. It does not call control.

Commit a deny mutation:

```sh
curl -sS http://127.0.0.1:7000/v1/deny \
  --data-binary $'op_id=demo-1\ntenant_id=tenant-a\nnamespace=user\nkey=user-123\naction=deny\ndelivery_priority=p0\npriority=100\nreason_code=abuse\ncreated_by=demo\n'
```

Query the agent:

```sh
curl -sS 'http://127.0.0.1:7002/v1/lookup?tenant_id=tenant-a&namespace=user&key=user-123'
```

Query through the demo app:

```sh
curl -sS 'http://127.0.0.1:8080/access?tenant_id=tenant-a&namespace=user&key=user-123'
```

Commit an IPv4 CIDR rule:

```sh
curl -sS http://127.0.0.1:7000/v1/rule \
  --data-binary $'op_id=net-1\ntenant_id=tenant-a\nkind=ipv4_cidr\npattern=10.0.0.0/8\naction=deny\nreason_code=blocked_network\n'
```

Check the compiled rule at the agent:

```sh
curl -sS 'http://127.0.0.1:7002/v1/check?tenant_id=tenant-a&namespace=ip&value=10.1.2.3'
```

Commit a domain suffix rule:

```sh
curl -sS http://127.0.0.1:7000/v1/rule \
  --data-binary $'op_id=domain-1\ntenant_id=tenant-a\nkind=domain_suffix\npattern=*.example.com\naction=deny\nreason_code=blocked_domain\n'
```

Check the domain rule:

```sh
curl -sS 'http://127.0.0.1:7002/v1/check?tenant_id=tenant-a&namespace=domain&value=api.example.com'
```

Broad denies require an explicit blast-radius override:

```sh
curl -sS http://127.0.0.1:7000/v1/rule \
  --data-binary $'op_id=net-all\ntenant_id=tenant-a\nkind=ipv4_cidr\npattern=0.0.0.0/0\naction=deny\noverride_blast_radius=true\nreason_code=emergency_all_ipv4\n'
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

Inspect snapshot archives and audit entries:

```sh
curl -sS http://127.0.0.1:7000/v1/snapshots
curl -sS http://127.0.0.1:7000/v1/audit
```

Rollback to a listed snapshot by filename:

```sh
curl -sS http://127.0.0.1:7000/v1/rollback \
  --data-binary $'snapshot=<snapshot-from-v1-snapshots>\n'
```

Commit a synthetic P0 canary manually:

```sh
curl -sS -X POST http://127.0.0.1:7000/v1/canary
```

Then check the latest canary status through the agent:

```sh
curl -sS http://127.0.0.1:7002/health
```
