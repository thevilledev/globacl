# Deployment

This repo includes Kubernetes manifests and k3d-backed k3s e2e scripts for proving the propagation path end to end.

The manifests are intentionally small and dependency-free:

```text
Docker image:      ghcr.io/thevilledev/globacl:ci
Namespace:         globacl
Control port:      7000
Commitd port:      7003
Relay port:        7001
Agent port:        7002
Demo app port:     8080
```

The demo app is a normal service consumer. It calls the local PoP agent, not the control plane:

```text
client -> demo app -> local globacl-agent -> local in-memory ACL state
```

## Simple Local Topology

Use this when you want the smallest runnable deployment:

```text
one k3s cluster
  globacl-commitd replicas=1
  globacl-control replicas=1
  globacl-relay   replicas=1
  globacl-agent   replicas=1
  globacl-demo    replicas=1
```

Manifest:

```text
deploy/k8s/local.yaml
```

Run it in CI or locally with k3d:

```sh
./deploy/k3s/local-e2e.sh
```

The script:

```text
1. Builds Docker image ghcr.io/thevilledev/globacl:ci.
2. Creates one k3d-backed k3s cluster.
3. Imports the image into the cluster.
4. Deploys commitd, control, relay, agent, and demo app.
5. Commits a P0 deny to control.
6. Calls the demo app until it returns `"access": "denied"`.
```

## Local Observability Topology

Use this when you want one local cluster that looks closer to the production
component shape and proves scrape-based observability:

```text
one k3s cluster
  globacl-commitd StatefulSet replicas=3
  globacl-control Deployment replicas=3
  globacl-relay   Deployment replicas=3
  globacl-agent   Deployment replicas=3
  globacl-demo    Deployment replicas=3
  prometheus      Deployment replicas=1
```

The Prometheus deployment discovers pods in the `globacl` namespace through
pod annotations and scrapes only the dedicated metrics listeners. The
client-facing Services still expose only application ports.

Manifest:

```text
deploy/k8s/local-observability.yaml
```

Run it in CI or locally with k3d:

```sh
./deploy/k3s/observability-e2e.sh
```

The script:

```text
1. Builds Docker image ghcr.io/thevilledev/globacl:ci.
2. Creates one k3d-backed k3s cluster with two worker agents.
3. Imports the image into the cluster.
4. Deploys the three-node commitd quorum, three control pods, three relays,
   three agents, three demo apps, and Prometheus.
5. Commits a P0 deny to control.
6. Calls the demo app until it returns `"access": "denied"`.
7. Waits for central ack aggregation from all three agents.
8. Queries Prometheus for discovered scrape targets, commit leadership, relay
   source health, agent entries, applied mutations, and central ack counts.
```

## Object Storage Topology

Use this when you want to prove S3-compatible snapshot publication and restore:

```text
one k3s cluster
  SeaweedFS single-node S3 endpoint replicas=1
  globacl-commitd replicas=1 with S3 snapshot storage enabled
  globacl-control replicas=1
  globacl-relay   replicas=1
  globacl-agent   replicas=1
  globacl-demo    replicas=1
```

Manifests:

```text
deploy/k8s/local.yaml
deploy/k8s/seaweedfs-s3.yaml
```

Run it in CI or locally with k3d:

```sh
./deploy/k3s/object-storage-e2e.sh
```

The script:

```text
1. Builds Docker image ghcr.io/thevilledev/globacl:ci.
2. Pulls and imports chrislusf/seaweedfs:4.29.
3. Creates one k3d-backed k3s cluster.
4. Deploys SeaweedFS with a pre-created globacl-snapshots bucket.
5. Configures commitd to publish signed snapshots to the SeaweedFS S3 API.
6. Commits a P0 deny and waits for the demo app to observe it.
7. Deletes the commitd pod so its emptyDir source state is lost.
8. Waits for commitd to restore from object storage and checks the deny
   through the control-plane `/v1/check` API.
```

## Local Dev Cluster

Use this when you want to keep the observability topology running while you
iterate on code:

```sh
./deploy/k3s/dev-cluster.sh up
```

That command creates or reuses one k3d cluster, builds
`ghcr.io/thevilledev/globacl:ci`, imports it into the cluster, applies
`deploy/k8s/local-observability.yaml`, restarts the runtime workloads, waits
for rollout, and then keeps these local port-forwards open:

```text
control:    http://127.0.0.1:17200
demo:       http://127.0.0.1:18280
prometheus: http://127.0.0.1:19090
```

By default the dev cluster uses the HTTP pull-proxy relay source. To iterate on
the NATS JetStream path instead, pass the messaging parameter:

```sh
./deploy/k3s/dev-cluster.sh up --messaging jetstream
```

That applies `deploy/k8s/nats-jetstream.yaml`, waits for NATS, configures
commitd to publish committed mutations to JetStream, and configures relays to
consume JetStream instead of polling the control API. To switch the same dev
cluster back to pull-proxy mode, redeploy with:

```sh
./deploy/k3s/dev-cluster.sh deploy --messaging pull
```

Leave that process running for local access. The port-forward loops restart
automatically if a selected pod is replaced during rollout. After changing
code, redeploy the current tree from another terminal:

```sh
./deploy/k3s/dev-cluster.sh deploy
```

`deploy` reuses the same cluster and persistent volumes. It rebuilds the
image, imports it into k3d, reapplies the manifest, restarts the runtime
workloads, waits for rollout, and exits. Pass the same `--messaging` value you
want active after the redeploy. Prometheus stays in the cluster.

Useful commands:

```sh
./deploy/k3s/dev-cluster.sh ports     # reopen port-forwards only
./deploy/k3s/dev-cluster.sh status    # show pods and services
./deploy/k3s/dev-cluster.sh delete    # delete the dev cluster
```

Useful environment overrides:

```text
CLUSTER=globacl-dev
IMAGE=ghcr.io/thevilledev/globacl:ci
CONTROL_PORT=17200
DEMO_PORT=18280
PROMETHEUS_PORT=19090
SKIP_BUILD=1
SKIP_RESTART=1
```

## Global Topology

Use this to demonstrate the intended production shape with one central source of truth and three independent regions:

```text
central k3s cluster
  globacl-commitd StatefulSet replicas=3
  one persistent volume per commitd replica
  automatic Raft-style leader election
  quorum 2 of 3
  globacl-control Deployment replicas=2

region-a k3s cluster
  globacl-relay replicas=2
  globacl-agent replicas=1
  globacl-demo  replicas=1

region-b k3s cluster
  globacl-relay replicas=2
  globacl-agent replicas=1
  globacl-demo  replicas=1

region-c k3s cluster
  globacl-relay replicas=2
  globacl-agent replicas=1
  globacl-demo  replicas=1
```

The central commit deployment is HA for storage: each `globacl-commitd` pod has a stable identity and durable volume, nodes persist term/vote state, elect a leader with majority votes, and forward writes to the current leader. The leader commits only after a quorum of commit peers prepares the mutation. Followers persist committed mutations and run a catch-up loop against the leader. `globacl-control` is a stateless public API gateway in front of commitd, so regional relays can read through any healthy control pod behind the central Service.

The regional relay deployment is HA inside each region. The relay pods are stateless fanout/cache nodes behind a Kubernetes Service. Agents and demo apps stay regional.

Manifests:

```text
deploy/k8s/global/central.yaml
deploy/k8s/global/region.yaml.tpl
```

Run the global e2e:

```sh
./deploy/k3s/global-e2e.sh
```

The script:

```text
1. Builds Docker image ghcr.io/thevilledev/globacl:ci.
2. Creates a shared Docker network for k3d clusters.
3. Creates one central k3s cluster.
4. Creates three regional k3s clusters.
5. Waits for the three-replica central commitd StatefulSet and control Deployment.
6. Exposes central control on host port 17000.
7. Points regional HA relays at the central k3d server node's NodePort address on the shared Docker network.
8. Commits a P0 deny to central control.
9. Calls every regional demo app until each returns `"access": "denied"`.
```

## CI

The manual GitHub Actions workflow is:

```text
.github/workflows/k3s-e2e.yml
```

It supports:

```text
local
object-storage
jetstream
global
observability
all
```

Run it from GitHub Actions with `workflow_dispatch`. The workflow installs `kubectl` and `k3d`, then runs the same scripts listed above.

## Customization

The e2e scripts are parameterized with environment variables:

```text
IMAGE=ghcr.io/thevilledev/globacl:ci
CLUSTER=globacl-local
CENTRAL_CLUSTER=globacl-central
REGIONS="region-a region-b region-c"
CONTROL_UPSTREAM=<optional-control-hostport>
PROMETHEUS_PORT=19090
SEAWEEDFS_IMAGE=chrislusf/seaweedfs:4.29
KEEP_CLUSTER=1
KEEP_CLUSTERS=1
```

Use `KEEP_CLUSTER=1` or `KEEP_CLUSTERS=1` when debugging locally so the script does not delete the clusters on exit.

When `CONTROL_UPSTREAM` is unset, the global e2e script resolves the central k3d server container IP and uses `<central-server-ip>:30080`. Override it only when your environment has a different routable address for central control.

The central commitd consensus settings are configured in `deploy/k8s/global/central.yaml`:

```text
GLOBACL_COMMITD_NODE_ID       pod name, from metadata.name
GLOBACL_COMMITD_CLUSTER_ID    logical consensus cluster id
GLOBACL_COMMITD_PEERS         node_id=host:port peer list
GLOBACL_COMMITD_QUORUM        majority threshold
GLOBACL_COMMITD_HEARTBEAT_MS  leader heartbeat interval
GLOBACL_COMMITD_ELECTION_MS   follower election timeout base
GLOBACL_COMMITD_SYNC_MS       follower mutation catch-up interval
GLOBACL_COMMITD_COMPACTION_MIN_LOG_ENTRIES
                                  compact retained mutation history after this many entries
GLOBACL_COMMITD_COMPACT_ON_STARTUP
                                  rewrite logs behind latest signed checkpoint on startup
```

Commitd compaction uses the latest signed snapshot as the checkpoint, rewrites per-shard logs to retain only post-checkpoint mutations, and writes `idempotency.glog` so duplicate `op_id` handling survives restarts. If a follower or edge component asks for a compacted range, it repairs from the snapshot channel. When `GLOBACL_COMMITD_PUBLISHER=jetstream` is enabled, compaction is capped by durable per-shard publisher offsets so unpublished JetStream events remain replayable after restart.

Control and commitd can require scoped bearer tokens for write/admin APIs:

```text
GLOBACL_AUTH_TOKENS           token=identity:scope,scope;token2=identity2:scope
```

For example, `admin-token=admin:acl:write,snapshot:write,admin:rollback,audit:read`
allows authoring, snapshot upload, rollback, and audit reads. The k3s e2e
runner reads `GLOBACL_BEARER_TOKEN` when a token-protected environment is used.

Relay source selection is runtime-configurable:

```text
GLOBACL_RELAY_SOURCE          http, pull_proxy, jetstream, or nats
GLOBACL_NATS_ADDR             NATS server address, for example nats://nats:4222
GLOBACL_NATS_STREAM           JetStream stream name, default GLOBACL
GLOBACL_NATS_SUBJECT_PREFIX   subject prefix, default globacl
GLOBACL_NATS_CONSUMER         durable consumer name, default relay id
GLOBACL_NATS_BATCH            pull batch size, default 128
GLOBACL_NATS_AUTOCREATE       create stream/consumer when true
```

When `GLOBACL_COMMITD_PUBLISHER=jetstream` is set on commitd, the leader scans its durable mutation log and publishes committed mutations to JetStream subjects such as `globacl.p0.shard.42`. Relays in JetStream mode consume that durable stream into a local mutation cache. Agents keep using the relay HTTP API in both modes.

## Durable Snapshot Storage

Commitd can publish signed snapshot manifests and artifacts to S3 or an
S3-compatible endpoint such as MinIO. The local filesystem remains the hot
cache and PVC-backed working store. The object store is the durable bootstrap,
repair, backup, and disaster-recovery channel.

Enable it on every commitd pod:

```text
GLOBACL_OBJECT_STORE=s3
GLOBACL_S3_BUCKET=globacl-snapshots
GLOBACL_S3_REGION=us-east-1
GLOBACL_S3_PREFIX=prod/globacl
GLOBACL_S3_ENDPOINT=https://s3.us-east-1.amazonaws.com
GLOBACL_S3_ACCESS_KEY_ID=...
GLOBACL_S3_SECRET_ACCESS_KEY=...
GLOBACL_S3_SESSION_TOKEN=...              optional
GLOBACL_S3_FORCE_PATH_STYLE=true          default, useful for MinIO
GLOBACL_S3_TIMEOUT_MS=10000               default
GLOBACL_OBJECT_STORE_REQUIRE_UPLOAD=false default, log upload failures
```

For AWS S3 virtual-hosted bucket URLs, set:

```text
GLOBACL_S3_FORCE_PATH_STYLE=false
```

For MinIO, use a path-style endpoint:

```text
GLOBACL_OBJECT_STORE=s3
GLOBACL_S3_ENDPOINT=http://minio.minio.svc.cluster.local:9000
GLOBACL_S3_BUCKET=globacl-snapshots
GLOBACL_S3_REGION=us-east-1
GLOBACL_S3_PREFIX=dev/globacl
GLOBACL_S3_FORCE_PATH_STYLE=true
```

On the first ever bootstrap of an empty bucket, explicitly allow an empty
source of truth:

```text
GLOBACL_OBJECT_STORE_ALLOW_EMPTY_BOOTSTRAP=1
```

Remove that setting after the first signed manifest is published. Without this
override, an empty commitd volume with object storage enabled refuses to start
unless it can restore `manifests/latest.manifest`. This prevents a disaster
recovery node from accidentally overwriting a populated remote store with an
empty snapshot.

Snapshot uploads are best-effort by default so an S3 outage does not block
new ACL commits. Set `GLOBACL_OBJECT_STORE_REQUIRE_UPLOAD=1` only if your
operational policy prefers write unavailability over running with local PVC
durability while remote snapshot publication is down.

Commitd writes these objects under `GLOBACL_S3_PREFIX`:

```text
snapshots/max_seq_<seq>_sha256_<sha256>.gacl
snapshots/max_seq_<seq>_sha256_<sha256>.gacl.sig
manifests/epoch_<ts>_seq_<seq>_sha256_<sha16>.manifest
manifests/epoch_<ts>_seq_<seq>_sha256_<sha16>.manifest.sig
manifests/latest.manifest
manifests/latest.manifest.sig
```

The manifest records artifact size, SHA-256, shard count, entry count, rule
count, watermarks, and the artifact object names. Commitd validates the
downloaded artifact against the manifest before restoring it locally. Agents
still verify Ed25519 signatures before activating state.

Recommended bucket controls:

```text
versioning: enabled
server-side encryption: enabled, preferably KMS-backed
public access: blocked
IAM: commitd can PutObject/GetObject only under its environment prefix
retention: keep immutable snapshots/manifests for at least the rollback window
lifecycle: expire old immutable objects after backup/rollback requirements
replication: cross-region replication for production disaster recovery
audit: object write/read events enabled for the commitd prefix
```

Backup and restore flow:

```text
1. Keep commitd PVC backups for fast local recovery.
2. Keep object-store versioning and cross-region replication for site loss.
3. Start replacement commitd pods with the same shard count, cluster id, and
   signature verifier configuration.
4. Configure the same S3 bucket/prefix and do not set
   GLOBACL_OBJECT_STORE_ALLOW_EMPTY_BOOTSTRAP.
5. Commitd downloads latest.manifest, verifies the artifact hash and snapshot
   metadata, writes the local signed snapshot cache, and loads source state.
6. Relays and agents repair from the normal snapshot and delta APIs.
```

Local source state on the commitd PVC takes precedence on restart; commitd
does not replace local state with a remote snapshot. If local state is missing
and object storage is unavailable, startup fails unless the explicit
empty-bootstrap override is set.

## Metrics

All runtime pods expose Prometheus-style metrics on a separate listener from
their client-facing HTTP API:

```text
globacl-control   GET :9100/metrics
globacl-relay     GET :9101/metrics
globacl-agent     GET :9102/metrics
globacl-commitd   GET :9103/metrics
globacl-demo      GET :9180/metrics
```

The Kubernetes Services in this repo expose only the client-facing HTTP ports.
The metrics ports are declared as container ports for pod scraping and should
be reachable only from your monitoring plane.

Use the metrics for scrape-based SLO dashboards and alerts around commit
quorum, stale agents, relay source health, central ack aggregation, publisher
errors, repair activity, and edge-state size.

The local observability setup also deploys Grafana with a provisioned
Prometheus datasource and the checked-in dashboard at
`deploy/grafana/globacl-overview.json`. The dashboard visualizes commitd
leadership, relay source health, propagation progress, central acknowledgements,
agent lag, repair activity, edge-state size, and recent control-plane errors.

When running the dev cluster helper, Grafana is port-forwarded locally:

```sh
./deploy/k3s/dev-cluster.sh up --messaging jetstream
open http://127.0.0.1:13000/d/globacl-overview/globacl-system-overview
```

For direct Kubernetes use, create the dashboard ConfigMap and apply the Grafana
manifests after `local-observability.yaml`:

```sh
kubectl -n globacl create configmap globacl-grafana-dashboard \
  --from-file=globacl-overview.json=deploy/grafana/globacl-overview.json \
  --dry-run=client \
  -o yaml | kubectl apply -f -
kubectl apply -f deploy/k8s/grafana.yaml
```

## Production Notes

These manifests prove the distribution mechanics, but they are intentionally not a complete production platform.

For production:

```text
control: multiple stateless ACL API pods behind a load balancer
commitd: 3 or 5 ACL commit service pods with persistent volumes
source of truth: built-in ACL-specific Raft commit log owned by commitd
logs: HTTP pull-proxy for simple deployments, NATS JetStream in this repo, or Kafka/Pulsar/Redpanda/cloud Pub/Sub behind the same relay-source interface
snapshots: signed local cache plus S3/S3-compatible durable object storage
relays: regional/PoP relay pools with autoscaling
agents: one per node or service workload depending latency needs
edge hot path: embed globacl-agent in Rust services when localhost HTTP latency is too expensive; keep the sidecar API for polyglot services
signing: Ed25519 signatures are implemented; use HSM/KMS-backed key handling and rotation for production
observability: scrape every component's separate metrics listener and alert on stale propagation, quorum loss, publisher errors, and lagging relays
```

The included commitd consensus layer is intentionally ACL-specific rather than a general KV store. It owns term/vote persistence, leader heartbeats, majority election, idempotent mutation application, durable peer replication, and follower catch-up for the committed mutation log.
