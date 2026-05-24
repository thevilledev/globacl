#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${CLUSTER:-globacl-jetstream}"
IMAGE="${IMAGE:-ghcr.io/thevilledev/globacl:ci}"
NAMESPACE="${NAMESPACE:-globacl}"
CONTROL_PORT="${CONTROL_PORT:-17100}"
RELAY_PORT="${RELAY_PORT:-17101}"
DEMO_PORT="${DEMO_PORT:-18180}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"

CONTROL_PF_PID=""
RELAY_PF_PID=""
DEMO_PF_PID=""

cleanup() {
  if [[ -n "${CONTROL_PF_PID}" ]]; then
    kill "${CONTROL_PF_PID}" 2>/dev/null || true
    wait "${CONTROL_PF_PID}" 2>/dev/null || true
  fi
  if [[ -n "${RELAY_PF_PID}" ]]; then
    kill "${RELAY_PF_PID}" 2>/dev/null || true
    wait "${RELAY_PF_PID}" 2>/dev/null || true
  fi
  if [[ -n "${DEMO_PF_PID}" ]]; then
    kill "${DEMO_PF_PID}" 2>/dev/null || true
    wait "${DEMO_PF_PID}" 2>/dev/null || true
  fi
  if [[ "${KEEP_CLUSTER}" != "1" ]]; then
    k3d cluster delete "${CLUSTER}" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

k() {
  kubectl --context "k3d-${CLUSTER}" "$@"
}

wait_for_http() {
  local url="$1"
  smoke_client wait-health --base-url "${url}" --timeout 120s
}

wait_for_propagation_ack() {
  local expected_agents="$1"
  smoke_client wait-propagation \
    --base-url "http://127.0.0.1:${CONTROL_PORT}" \
    --expected-agents "${expected_agents}" \
    --timeout 120s
}

smoke_client() {
  (cd "${ROOT_DIR}/clients/go" && go run ./cmd/globacl-smoke "$@")
}

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd go

cd "${ROOT_DIR}"
docker build -t "${IMAGE}" .

k3d cluster delete "${CLUSTER}" >/dev/null 2>&1 || true
k3d cluster create "${CLUSTER}" --agents 1 --wait
k3d image import "${IMAGE}" -c "${CLUSTER}"

k apply -f "${ROOT_DIR}/deploy/k8s/local.yaml"
k apply -f "${ROOT_DIR}/deploy/k8s/nats-jetstream.yaml"
k -n "${NAMESPACE}" rollout status deploy/globacl-nats --timeout=180s

k -n "${NAMESPACE}" set env deploy/globacl-commitd \
  GLOBACL_COMMITD_PUBLISHER=jetstream \
  GLOBACL_NATS_ADDR=globacl-nats.globacl.svc.cluster.local:4222 \
  GLOBACL_NATS_PUBLISH_MS=100
k -n "${NAMESPACE}" set env deploy/globacl-relay \
  GLOBACL_RELAY_SOURCE=jetstream \
  GLOBACL_NATS_ADDR=globacl-nats.globacl.svc.cluster.local:4222 \
  GLOBACL_NATS_BATCH=16

k -n "${NAMESPACE}" rollout status deploy/globacl-commitd --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-control --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-relay --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-agent --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-demo --timeout=180s

k -n "${NAMESPACE}" port-forward svc/globacl-control "${CONTROL_PORT}:7000" >/tmp/globacl-jetstream-control-pf.log 2>&1 &
CONTROL_PF_PID="$!"
wait_for_http "http://127.0.0.1:${CONTROL_PORT}/health"

k -n "${NAMESPACE}" port-forward svc/globacl-relay "${RELAY_PORT}:7001" >/tmp/globacl-jetstream-relay-pf.log 2>&1 &
RELAY_PF_PID="$!"
wait_for_http "http://127.0.0.1:${RELAY_PORT}/health"

k -n "${NAMESPACE}" port-forward svc/globacl-demo "${DEMO_PORT}:8080" >/tmp/globacl-jetstream-demo-pf.log 2>&1 &
DEMO_PF_PID="$!"
wait_for_http "http://127.0.0.1:${DEMO_PORT}/health"

smoke_client require-health-fields \
  --base-url "http://127.0.0.1:${RELAY_PORT}" \
  --fields source_lag_max,consumer_num_pending,consumer_num_ack_pending \
  --timeout 120s

smoke_client deny \
  --base-url "http://127.0.0.1:${CONTROL_PORT}" \
  --op-id ci-jetstream-user \
  --tenant-id tenant-a \
  --namespace user \
  --key user-js-ci \
  --delivery-priority p0 \
  --reason-code ci_jetstream_smoke \
  --created-by ci >/tmp/globacl-jetstream-commit.out

if ! smoke_client wait-demo-deny \
  --base-url "http://127.0.0.1:${DEMO_PORT}" \
  --tenant-id tenant-a \
  --namespace user \
  --key user-js-ci \
  --timeout 120s; then
  echo "jetstream smoke failed: demo app did not observe deny" >&2
  k -n "${NAMESPACE}" get pods -o wide >&2 || true
  k -n "${NAMESPACE}" logs deploy/globacl-commitd --tail=100 >&2 || true
  k -n "${NAMESPACE}" logs deploy/globacl-relay --tail=100 >&2 || true
  k -n "${NAMESPACE}" logs deploy/globacl-agent --tail=100 >&2 || true
  exit 1
fi

wait_for_propagation_ack 1
echo "jetstream smoke passed"
