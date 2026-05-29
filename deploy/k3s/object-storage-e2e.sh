#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${CLUSTER:-globacl-object-storage}"
IMAGE="${IMAGE:-ghcr.io/thevilledev/globacl:ci}"
NAMESPACE="${NAMESPACE:-globacl}"
CONTROL_PORT="${CONTROL_PORT:-17300}"
DEMO_PORT="${DEMO_PORT:-18380}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"
PORT_FORWARD_TIMEOUT_SECONDS="${PORT_FORWARD_TIMEOUT_SECONDS:-30}"

CONTROL_PF_PID=""
DEMO_PF_PID=""
E2E_BIN=""
START_PORT_FORWARD_PID=""

CONTROL_PF_LOG="${TMPDIR:-/tmp}/globacl-object-storage-control-pf.log"
DEMO_PF_LOG="${TMPDIR:-/tmp}/globacl-object-storage-demo-pf.log"

cleanup() {
  if [[ -n "${CONTROL_PF_PID}" ]]; then
    kill "${CONTROL_PF_PID}" 2>/dev/null || true
    wait "${CONTROL_PF_PID}" 2>/dev/null || true
  fi
  if [[ -n "${DEMO_PF_PID}" ]]; then
    kill "${DEMO_PF_PID}" 2>/dev/null || true
    wait "${DEMO_PF_PID}" 2>/dev/null || true
  fi
  if [[ -n "${E2E_BIN}" ]]; then
    rm -f "${E2E_BIN}" 2>/dev/null || true
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

e2e_client() {
  "${E2E_BIN}" "$@"
}

build_e2e_client() {
  E2E_BIN="$(mktemp "${TMPDIR:-/tmp}/globacl-e2e.XXXXXX")"
  (cd "${ROOT_DIR}/clients/go" && go build -o "${E2E_BIN}" ./cmd/globacl-e2e)
}

print_port_forward_log() {
  local log_file="$1"
  if [[ -s "${log_file}" ]]; then
    echo "port-forward log (${log_file}):" >&2
    cat "${log_file}" >&2 || true
  else
    echo "port-forward log (${log_file}) is empty" >&2
  fi
}

stop_port_forward_pid() {
  local pid="$1"
  kill "${pid}" 2>/dev/null || true
  wait "${pid}" 2>/dev/null || true
}

start_port_forward() {
  local service="$1"
  local local_port="$2"
  local remote_port="$3"
  local log_file="$4"

  : >"${log_file}"
  k -n "${NAMESPACE}" port-forward "svc/${service}" "${local_port}:${remote_port}" >"${log_file}" 2>&1 &
  START_PORT_FORWARD_PID="$!"

  local deadline=$((SECONDS + PORT_FORWARD_TIMEOUT_SECONDS))
  while ! grep -q "Forwarding from" "${log_file}" 2>/dev/null; do
    if ! kill -0 "${START_PORT_FORWARD_PID}" 2>/dev/null; then
      echo "port-forward for svc/${service} exited before becoming ready" >&2
      print_port_forward_log "${log_file}"
      return 1
    fi
    if ((SECONDS >= deadline)); then
      echo "timed out waiting ${PORT_FORWARD_TIMEOUT_SECONDS}s for port-forward svc/${service} ${local_port}:${remote_port}" >&2
      print_port_forward_log "${log_file}"
      stop_port_forward_pid "${START_PORT_FORWARD_PID}"
      START_PORT_FORWARD_PID=""
      return 1
    fi
    sleep 0.2
  done
}

wait_for_http() {
  local url="$1"
  local log_file="${2:-}"
  if ! e2e_client wait-health --base-url "${url}" --timeout 120s; then
    if [[ -n "${log_file}" ]]; then
      print_port_forward_log "${log_file}"
    fi
    return 1
  fi
}

wait_for_propagation_ack() {
  local expected_agents="$1"
  e2e_client wait-propagation \
    --base-url "http://127.0.0.1:${CONTROL_PORT}" \
    --expected-agents "${expected_agents}" \
    --timeout 120s
}

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd go

build_e2e_client

cd "${ROOT_DIR}"
docker build -t "${IMAGE}" .

k3d cluster delete "${CLUSTER}" >/dev/null 2>&1 || true
k3d cluster create "${CLUSTER}" --agents 1 --wait
k3d image import "${IMAGE}" -c "${CLUSTER}"

render_manifest "${ROOT_DIR}/deploy/k8s/local.yaml" | k apply -f -
k apply -f "${ROOT_DIR}/deploy/k8s/seaweedfs-s3.yaml"
k -n "${NAMESPACE}" rollout status deploy/globacl-seaweedfs --timeout=180s

k -n "${NAMESPACE}" set env deploy/globacl-commitd \
  GLOBACL_OBJECT_STORE=s3 \
  GLOBACL_S3_ENDPOINT=http://globacl-seaweedfs.globacl.svc.cluster.local:8333 \
  GLOBACL_S3_BUCKET=globacl-snapshots \
  GLOBACL_S3_REGION=us-east-1 \
  GLOBACL_S3_PREFIX=e2e/globacl \
  GLOBACL_S3_ACCESS_KEY_ID=admin \
  GLOBACL_S3_SECRET_ACCESS_KEY=secret \
  GLOBACL_S3_FORCE_PATH_STYLE=true \
  GLOBACL_OBJECT_STORE_ALLOW_EMPTY_BOOTSTRAP=1 \
  GLOBACL_OBJECT_STORE_REQUIRE_UPLOAD=1

k -n "${NAMESPACE}" rollout status deploy/globacl-commitd --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-control --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-relay --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-agent --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-demo --timeout=180s

start_port_forward globacl-control "${CONTROL_PORT}" 7000 "${CONTROL_PF_LOG}"
CONTROL_PF_PID="${START_PORT_FORWARD_PID}"
wait_for_http "http://127.0.0.1:${CONTROL_PORT}/health" "${CONTROL_PF_LOG}"

start_port_forward globacl-demo "${DEMO_PORT}" 8080 "${DEMO_PF_LOG}"
DEMO_PF_PID="${START_PORT_FORWARD_PID}"
wait_for_http "http://127.0.0.1:${DEMO_PORT}/health" "${DEMO_PF_LOG}"

e2e_client deny \
  --base-url "http://127.0.0.1:${CONTROL_PORT}" \
  --op-id ci-object-storage-user \
  --tenant-id tenant-a \
  --namespace user \
  --key user-object-storage \
  --delivery-priority p0 \
  --reason-code ci_object_storage_e2e \
  --created-by ci >/tmp/globacl-object-storage-commit.out

e2e_client wait-demo-deny \
  --base-url "http://127.0.0.1:${DEMO_PORT}" \
  --tenant-id tenant-a \
  --namespace user \
  --key user-object-storage \
  --timeout 120s
wait_for_propagation_ack 1

k -n "${NAMESPACE}" delete pod -l app=globacl-commitd --wait=true
k -n "${NAMESPACE}" rollout status deploy/globacl-commitd --timeout=180s
wait_for_http "http://127.0.0.1:${CONTROL_PORT}/health" "${CONTROL_PF_LOG}"

e2e_client wait-check-deny \
  --base-url "http://127.0.0.1:${CONTROL_PORT}" \
  --tenant-id tenant-a \
  --namespace user \
  --key user-object-storage \
  --timeout 120s

echo "object-storage e2e passed"
