#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CLUSTER="${CLUSTER:-globacl-observability}"
IMAGE="${IMAGE:-ghcr.io/thevilledev/globacl:ci}"
NAMESPACE="${NAMESPACE:-globacl}"
CONTROL_PORT="${CONTROL_PORT:-17200}"
DEMO_PORT="${DEMO_PORT:-18280}"
PROMETHEUS_PORT="${PROMETHEUS_PORT:-19090}"
GRAFANA_PORT="${GRAFANA_PORT:-13000}"
KEEP_CLUSTER="${KEEP_CLUSTER:-0}"

PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
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

port_forward() {
  local resource="$1"
  local host_port="$2"
  local target_port="$3"
  local log_file="$4"
  k -n "${NAMESPACE}" port-forward "${resource}" "${host_port}:${target_port}" >"${log_file}" 2>&1 &
  PIDS+=("$!")
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

wait_for_prometheus_query() {
  local query="$1"
  local minimum="$2"
  e2e_client wait-prometheus-query \
    --base-url "http://127.0.0.1:${PROMETHEUS_PORT}" \
    --query "${query}" \
    --min "${minimum}" \
    --timeout 180s
}

wait_for_grafana_dashboard() {
  e2e_client wait-grafana-dashboard \
    --base-url "http://127.0.0.1:${GRAFANA_PORT}" \
    --uid globacl-overview \
    --timeout 180s
}

e2e_client() {
  (cd "${ROOT_DIR}/clients/go" && go run ./cmd/globacl-e2e "$@")
}

apply_grafana() {
  k -n "${NAMESPACE}" create configmap globacl-grafana-dashboard \
    --from-file=globacl-overview.json="${ROOT_DIR}/deploy/grafana/globacl-overview.json" \
    --dry-run=client \
    -o yaml | k apply -f -
  k apply -f "${ROOT_DIR}/deploy/k8s/grafana.yaml"
}

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd go

cd "${ROOT_DIR}"
docker build -t "${IMAGE}" .

k3d cluster delete "${CLUSTER}" >/dev/null 2>&1 || true
k3d cluster create "${CLUSTER}" --agents 2 --wait
k3d image import "${IMAGE}" -c "${CLUSTER}"

render_manifest "${ROOT_DIR}/deploy/k8s/local-observability.yaml" | k apply -f -
apply_grafana
k -n "${NAMESPACE}" rollout status statefulset/globacl-commitd --timeout=240s
k -n "${NAMESPACE}" rollout status deploy/globacl-control --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-relay --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-agent --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-demo --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-prometheus --timeout=180s
k -n "${NAMESPACE}" rollout status deploy/globacl-grafana --timeout=180s

port_forward svc/globacl-control "${CONTROL_PORT}" 7000 /tmp/globacl-observability-control-pf.log
wait_for_http "http://127.0.0.1:${CONTROL_PORT}/health"

port_forward svc/globacl-demo "${DEMO_PORT}" 8080 /tmp/globacl-observability-demo-pf.log
wait_for_http "http://127.0.0.1:${DEMO_PORT}/health"

port_forward svc/globacl-prometheus "${PROMETHEUS_PORT}" 9090 /tmp/globacl-observability-prometheus-pf.log
wait_for_prometheus_query "vector(1)" 1

port_forward svc/globacl-grafana "${GRAFANA_PORT}" 3000 /tmp/globacl-observability-grafana-pf.log
wait_for_grafana_dashboard

e2e_client deny \
  --base-url "http://127.0.0.1:${CONTROL_PORT}" \
  --op-id ci-observability-user \
  --tenant-id tenant-a \
  --namespace user \
  --key user-observability \
  --delivery-priority p0 \
  --reason-code ci_observability_e2e \
  --created-by ci >/tmp/globacl-observability-commit.out

e2e_client wait-demo-deny \
  --base-url "http://127.0.0.1:${DEMO_PORT}" \
  --tenant-id tenant-a \
  --namespace user \
  --key user-observability \
  --timeout 120s

wait_for_propagation_ack 3
wait_for_prometheus_query "count(up{job=\"globacl-pods\"} == 1)" 15
wait_for_prometheus_query "sum(globacl_commitd_write_authority)" 1
wait_for_prometheus_query "sum(globacl_relay_source_up)" 3
wait_for_prometheus_query "sum(globacl_agent_entries)" 3
wait_for_prometheus_query "sum(globacl_agent_applied_mutations_total)" 3
wait_for_prometheus_query "sum(globacl_commitd_central_ack_count)" 3

echo "observability e2e passed"
