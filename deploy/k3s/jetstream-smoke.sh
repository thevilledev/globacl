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
PORT_FORWARD_TIMEOUT_SECONDS="${PORT_FORWARD_TIMEOUT_SECONDS:-30}"

CONTROL_PF_PID=""
RELAY_PF_PID=""
DEMO_PF_PID=""
SMOKE_BIN=""
START_PORT_FORWARD_PID=""

CONTROL_PF_LOG="${TMPDIR:-/tmp}/globacl-jetstream-control-pf.log"
RELAY_PF_LOG="${TMPDIR:-/tmp}/globacl-jetstream-relay-pf.log"
DEMO_PF_LOG="${TMPDIR:-/tmp}/globacl-jetstream-demo-pf.log"

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
  if [[ -n "${SMOKE_BIN}" ]]; then
    rm -f "${SMOKE_BIN}" 2>/dev/null || true
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
  local log_file="${2:-}"
  if ! smoke_client wait-health --base-url "${url}" --timeout 120s; then
    if [[ -n "${log_file}" ]]; then
      print_port_forward_log "${log_file}"
    fi
    return 1
  fi
}

wait_for_propagation_ack() {
  local expected_agents="$1"
  smoke_client wait-propagation \
    --base-url "http://127.0.0.1:${CONTROL_PORT}" \
    --expected-agents "${expected_agents}" \
    --timeout 120s
}

smoke_client() {
  "${SMOKE_BIN}" "$@"
}

build_smoke_client() {
  SMOKE_BIN="$(mktemp "${TMPDIR:-/tmp}/globacl-smoke.XXXXXX")"
  (cd "${ROOT_DIR}/clients/go" && go build -o "${SMOKE_BIN}" ./cmd/globacl-smoke)
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

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd go

build_smoke_client

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

start_port_forward globacl-control "${CONTROL_PORT}" 7000 "${CONTROL_PF_LOG}"
CONTROL_PF_PID="${START_PORT_FORWARD_PID}"
wait_for_http "http://127.0.0.1:${CONTROL_PORT}/health" "${CONTROL_PF_LOG}"

start_port_forward globacl-relay "${RELAY_PORT}" 7001 "${RELAY_PF_LOG}"
RELAY_PF_PID="${START_PORT_FORWARD_PID}"
wait_for_http "http://127.0.0.1:${RELAY_PORT}/health" "${RELAY_PF_LOG}"

start_port_forward globacl-demo "${DEMO_PORT}" 8080 "${DEMO_PF_LOG}"
DEMO_PF_PID="${START_PORT_FORWARD_PID}"
wait_for_http "http://127.0.0.1:${DEMO_PORT}/health" "${DEMO_PF_LOG}"

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
