#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${CLUSTER:-globacl-local}"
IMAGE="${IMAGE:-globacl:ci}"
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

wait_for_http() {
  local url="$1"
  for _ in $(seq 1 120); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${url}" >&2
  return 1
}

wait_for_propagation_ack() {
  local expected_agents="$1"
  local status
  local ack_count
  for _ in $(seq 1 120); do
    status="$(curl -sS "http://127.0.0.1:${CONTROL_PORT}/v1/propagation/status")"
    ack_count="$(awk -F= '$1 == "agent_count" {print $2}' <<<"${status}")"
    if [[ "${ack_count:-0}" -ge "${expected_agents}" ]] && grep -q "max_seq_lag=0" <<<"${status}"; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for central propagation ack" >&2
  curl -sS "http://127.0.0.1:${CONTROL_PORT}/v1/propagation/status" >&2 || true
  return 1
}

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd curl
require_cmd awk

cd "${ROOT_DIR}"
docker build -t "${IMAGE}" .

k3d cluster delete "${CLUSTER}" >/dev/null 2>&1 || true
k3d cluster create "${CLUSTER}" --agents 1 --wait
k3d image import "${IMAGE}" -c "${CLUSTER}"

k apply -f "${ROOT_DIR}/deploy/k8s/local.yaml"
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

curl -fsS "http://127.0.0.1:${CONTROL_PORT}/v1/deny" \
  --data-binary $'op_id=ci-local-user\ntenant_id=tenant-a\nnamespace=user\nkey=user-ci\naction=deny\ndelivery_priority=p0\nreason_code=ci_smoke\ncreated_by=ci\n' >/tmp/globacl-local-commit.out

for _ in $(seq 1 120); do
  response="$(curl -sS "http://127.0.0.1:${DEMO_PORT}/access?tenant_id=tenant-a&namespace=user&key=user-ci")"
  if grep -q "access=denied" <<<"${response}"; then
    wait_for_propagation_ack 1
    echo "local smoke passed"
    exit 0
  fi
  sleep 1
done

echo "local smoke failed: demo app did not observe deny" >&2
exit 1
