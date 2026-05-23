# Deployment

This repo includes Kubernetes manifests and k3d-backed k3s smoke scripts for proving the propagation path end to end.

The manifests are intentionally small and dependency-free:

```text
Docker image:      globacl:ci
Namespace:         globacl
Control port:      7000
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
./deploy/k3s/local-smoke.sh
```

The script:

```text
1. Builds Docker image globacl:ci.
2. Creates one k3d-backed k3s cluster.
3. Imports the image into the cluster.
4. Deploys control, relay, agent, and demo app.
5. Commits a P0 deny to control.
6. Calls the demo app until it returns access=denied.
```

## Global Topology

Use this to demonstrate the intended production shape with one central source of truth and three independent regions:

```text
central k3s cluster
  globacl-control replicas=1

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

The regional relay deployment is HA inside each region. The relay pods are stateless fanout/cache nodes behind a Kubernetes Service. Agents and demo apps stay regional.

Manifests:

```text
deploy/k8s/global/central.yaml
deploy/k8s/global/region.yaml.tpl
```

Run the global smoke:

```sh
./deploy/k3s/global-smoke.sh
```

The script:

```text
1. Builds Docker image globacl:ci.
2. Creates a shared Docker network for k3d clusters.
3. Creates one central k3s cluster.
4. Creates three regional k3s clusters.
5. Exposes central control on host port 17000.
6. Points regional HA relays at the central k3d server node's NodePort address on the shared Docker network.
7. Commits a P0 deny to central control.
8. Calls every regional demo app until each returns access=denied.
```

## CI

The manual GitHub Actions workflow is:

```text
.github/workflows/k3s-smoke.yml
```

It supports:

```text
local
global
all
```

Run it from GitHub Actions with `workflow_dispatch`. The workflow installs `kubectl` and `k3d`, then runs the same scripts listed above.

## Customization

The smoke scripts are parameterized with environment variables:

```text
IMAGE=globacl:ci
CLUSTER=globacl-local
CENTRAL_CLUSTER=globacl-central
REGIONS="region-a region-b region-c"
CONTROL_UPSTREAM=<optional-control-hostport>
KEEP_CLUSTER=1
KEEP_CLUSTERS=1
```

Use `KEEP_CLUSTER=1` or `KEEP_CLUSTERS=1` when debugging locally so the script does not delete the clusters on exit.

When `CONTROL_UPSTREAM` is unset, the global smoke script resolves the central k3d server container IP and uses `<central-server-ip>:30080`. Override it only when your environment has a different routable address for central control.

## Production Notes

These manifests prove the distribution mechanics, but they are intentionally not a complete production platform.

For production:

```text
control: multiple stateless API pods behind a load balancer
source of truth: external replicated DB/consensus store
logs: Kafka/Pulsar/NATS/Redpanda or cloud Pub/Sub
snapshots: durable object storage
relays: regional/PoP relay pools with autoscaling
agents: one per node or service workload depending latency needs
signing: replace fnv64-dev seal with Ed25519/HSM-backed signatures
```
