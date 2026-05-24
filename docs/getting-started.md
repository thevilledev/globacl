# Getting Started

Start the ACL commit service:

```sh
cargo run -p globacl-commitd -- data/commitd 127.0.0.1:7003 4096 0
```

The final argument is the synthetic canary interval in seconds. Use `0` to disable automatic canaries, or a positive value such as `60` to inject a P0 canary every minute.

Optional bearer-token auth can be enabled on `globacl-control` and
`globacl-commitd`:

```sh
export GLOBACL_AUTH_TOKENS='admin-token=admin:acl:write,snapshot:write,admin:rollback,audit:read'
```

When this is set, protected write/admin requests need
`Authorization: Bearer admin-token`. Leave it unset for the simplest local
walkthrough.

Optional Ed25519 signing keys can be set on commitd, relays, and agents:

```sh
export GLOBACL_SIGNATURE_KEY_ID=dev-ed25519
export GLOBACL_SIGNATURE_KEY_VERSION=1
export GLOBACL_SIGNATURE_PRIVATE_KEY=9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
export GLOBACL_SIGNATURE_PUBLIC_KEY=d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
```

`globacl-commitd` and JetStream-backed relays need the private key to sign payloads. `globacl-agent` needs only the public key to verify payloads.

For rotation tests, agents can trust multiple public keys with `GLOBACL_SIGNATURE_PUBLIC_KEYS='dev-ed25519:1:<public_key>,next-ed25519:2:<public_key>'` and reject old payloads with `GLOBACL_SIGNATURE_MIN_KEY_VERSION=2`. Commitd and JetStream relays can read private keys from `GLOBACL_SIGNATURE_PRIVATE_KEY_FILE` or call an external signer through `GLOBACL_SIGNATURE_SIGN_COMMAND`.

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

For the in-process edge hot path, run the demo app in embedded mode and point
its first argument at the relay instead of the sidecar agent:

```sh
GLOBACL_DEMO_LOOKUP_MODE=embedded \
GLOBACL_DEMO_AGENT_ID=demo-embedded \
cargo run -p globacl-demo-app -- 127.0.0.1:7001 127.0.0.1:8080
```

In this mode the demo app embeds `globacl-agent`, keeps its own local
`ActiveStateHandle`, and performs request-time lookups without a localhost HTTP
hop.

Commit a deny mutation:

```sh
curl -sS http://127.0.0.1:7000/v1/deny \
  --header 'Content-Type: application/json' \
  --data-binary '{"op_id":"demo-1","tenant_id":"tenant-a","namespace":"user","key":"user-123","action":"deny","delivery_priority":"p0","priority":100,"reason_code":"abuse","created_by":"demo"}'
```

If auth is enabled, add `--header 'Authorization: Bearer admin-token'` to
write/admin requests.

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
  --header 'Content-Type: application/json' \
  --data-binary '{"op_id":"net-1","tenant_id":"tenant-a","kind":"ipv4_cidr","pattern":"10.0.0.0/8","action":"deny","reason_code":"blocked_network"}'
```

Check the compiled rule at the agent:

```sh
curl -sS 'http://127.0.0.1:7002/v1/check?tenant_id=tenant-a&namespace=ip&value=10.1.2.3'
```

Commit a domain suffix rule:

```sh
curl -sS http://127.0.0.1:7000/v1/rule \
  --header 'Content-Type: application/json' \
  --data-binary '{"op_id":"domain-1","tenant_id":"tenant-a","kind":"domain_suffix","pattern":"*.example.com","action":"deny","reason_code":"blocked_domain"}'
```

Check the domain rule:

```sh
curl -sS 'http://127.0.0.1:7002/v1/check?tenant_id=tenant-a&namespace=domain&value=api.example.com'
```

Broad denies require an explicit blast-radius override:

```sh
curl -sS http://127.0.0.1:7000/v1/rule \
  --header 'Content-Type: application/json' \
  --data-binary '{"op_id":"net-all","tenant_id":"tenant-a","kind":"ipv4_cidr","pattern":"0.0.0.0/0","action":"deny","override_blast_radius":true,"reason_code":"emergency_all_ipv4"}'
```

Delete/unblock with a higher sequence:

```sh
curl -sS http://127.0.0.1:7000/v1/deny \
  --header 'Content-Type: application/json' \
  --data-binary '{"op_id":"demo-2","tenant_id":"tenant-a","namespace":"user","key":"user-123","action":"delete","created_by":"demo"}'
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
  --header 'Content-Type: application/json' \
  --data-binary '{"snapshot":"<snapshot-from-v1-snapshots>"}'
```

Commit a synthetic P0 canary manually:

```sh
curl -sS -X POST http://127.0.0.1:7000/v1/canary
```

Then check the latest canary status through the agent:

```sh
curl -sS http://127.0.0.1:7002/health
```
