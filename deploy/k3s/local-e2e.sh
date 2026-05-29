#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${CLUSTER:-globacl-local}"
IMAGE="${IMAGE:-ghcr.io/thevilledev/globacl:ci}"
NAMESPACE="${NAMESPACE:-globacl}"
CONTROL_PORT="${CONTROL_PORT:-17000}"
DEMO_PORT="${DEMO_PORT:-18080}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"

CONTROL_PF_PID=""
DEMO_PF_PID=""

cleanup() {
  if [[ -n "${CONTROL_PF_PID}" ]]; then
    kill "${CONTROL_PF_PID}" 2>/dev/null || true
    wait "${CONTROL_PF_PID}" 2>/dev/null || true
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

render_manifest() {
  sed "s#__GLOBACL_IMAGE__#${IMAGE}#g" "$1"
}

wait_for_http() {
  local url="$1"
  e2e_client wait-health --base-url "${url}" --timeout 120s
}

wait_for_propagation_ack() {
  local expected_agents="$1"
  e2e_client wait-propagation \
    --base-url "http://127.0.0.1:${CONTROL_PORT}" \
    --expected-agents "${expected_agents}" \
    --timeout 120s
}

e2e_client() {
  (cd "${ROOT_DIR}/clients/go" && go run ./cmd/globacl-e2e "$@")
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

render_manifest "${ROOT_DIR}/deploy/k8s/local.yaml" | k apply -f -
k -n "${NAMESPACE}" rollout status deploy/globacl-commitd --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-control --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-relay --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-agent --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-demo --timeout=180s

k -n "${NAMESPACE}" port-forward svc/globacl-control "${CONTROL_PORT}:7000" >/tmp/globacl-local-control-pf.log 2>&1 &
CONTROL_PF_PID="$!"
wait_for_http "http://127.0.0.1:${CONTROL_PORT}/health"

k -n "${NAMESPACE}" port-forward svc/globacl-demo "${DEMO_PORT}:8080" >/tmp/globacl-local-demo-pf.log 2>&1 &
DEMO_PF_PID="$!"
wait_for_http "http://127.0.0.1:${DEMO_PORT}/health"

e2e_client deny \
  --base-url "http://127.0.0.1:${CONTROL_PORT}" \
  --op-id ci-local-user \
  --tenant-id tenant-a \
  --namespace user \
  --key user-ci \
  --delivery-priority p0 \
  --reason-code ci_e2e \
  --created-by ci >/tmp/globacl-local-commit.out

e2e_client wait-demo-deny \
  --base-url "http://127.0.0.1:${DEMO_PORT}" \
  --tenant-id tenant-a \
  --namespace user \
  --key user-ci \
  --timeout 120s

wait_for_propagation_ack 1
echo "local e2e passed"
