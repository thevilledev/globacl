#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE:-ghcr.io/thevilledev/globacl:ci}"
NETWORK="${NETWORK:-globacl-k3d}"
CENTRAL_CLUSTER="${CENTRAL_CLUSTER:-globacl-central}"
CENTRAL_HOST_PORT="${CENTRAL_HOST_PORT:-17000}"
CONTROL_UPSTREAM="${CONTROL_UPSTREAM:-}"
NAMESPACE="${NAMESPACE:-globacl}"
KEEP_CLUSTERS="${KEEP_CLUSTERS:-0}"
REGIONS=(${REGIONS:-region-a region-b region-c})
DEMO_BASE_PORT="${DEMO_BASE_PORT:-18100}"
AGENT_BASE_PORT="${AGENT_BASE_PORT:-18200}"
RELAY_BASE_PORT="${RELAY_BASE_PORT:-18300}"
GLOBACL_UI_HOST="${GLOBACL_UI_HOST:-127.0.0.1}"
GLOBACL_UI_PORT="${GLOBACL_UI_PORT:-18000}"
GLOBACL_UI_TENANT_ID="${GLOBACL_UI_TENANT_ID:-tenant-a}"
GLOBACL_UI_NAMESPACE="${GLOBACL_UI_NAMESPACE:-user}"
GLOBACL_UI_KEY="${GLOBACL_UI_KEY:-user-global}"
SEED_DENY="${SEED_DENY:-1}"

PIDS=()
CLUSTERS=("${CENTRAL_CLUSTER}")
CREATED_NETWORK="0"

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
  if [[ "${KEEP_CLUSTERS}" != "1" ]]; then
    for cluster in "${CLUSTERS[@]:-}"; do
      k3d cluster delete "${cluster}" >/dev/null 2>&1 || true
    done
    if [[ "${CREATED_NETWORK}" == "1" ]]; then
      docker network rm "${NETWORK}" >/dev/null 2>&1 || true
    fi
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
  local cluster="$1"
  shift
  kubectl --context "k3d-${cluster}" "$@"
}

wait_for_http() {
  local url="$1"
  e2e_client wait-health --base-url "${url}" --timeout 120s
}

wait_for_propagation_ack() {
  local expected_agents="$1"
  e2e_client wait-propagation \
    --base-url "http://127.0.0.1:${CENTRAL_HOST_PORT}" \
    --expected-agents "${expected_agents}" \
    --timeout 120s
}

e2e_client() {
  (cd "${ROOT_DIR}/clients/go" && go run ./cmd/globacl-e2e "$@")
}

render_manifest() {
  sed "s#__GLOBACL_IMAGE__#${IMAGE}#g" "$1"
}

render_region() {
  local region="$1"
  sed \
    -e "s#__REGION_NAME__#${region}#g" \
    -e "s#__CONTROL_UPSTREAM__#${CONTROL_UPSTREAM}#g" \
    -e "s#__GLOBACL_IMAGE__#${IMAGE}#g" \
    "${ROOT_DIR}/deploy/k8s/global/region.yaml.tpl"
}

port_forward() {
  local cluster="$1"
  local service="$2"
  local host_port="$3"
  local target_port="$4"
  local log_file="$5"
  (
    child_pid=""
    stop_forward() {
      if [[ -n "${child_pid}" ]]; then
        kill "${child_pid}" 2>/dev/null || true
        wait "${child_pid}" 2>/dev/null || true
      fi
      exit 0
    }
    trap stop_forward INT TERM

    while true; do
      k "${cluster}" -n "${NAMESPACE}" port-forward "svc/${service}" "${host_port}:${target_port}" &
      child_pid="$!"
      wait "${child_pid}" || true
      child_pid=""
      sleep 1
    done
  ) >"${log_file}" 2>&1 &
  PIDS+=("$!")
}

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd go
require_cmd pnpm

cd "${ROOT_DIR}"
docker build -t "${IMAGE}" .

if ! docker network inspect "${NETWORK}" >/dev/null 2>&1; then
  docker network create "${NETWORK}" >/dev/null
  CREATED_NETWORK="1"
fi

k3d cluster delete "${CENTRAL_CLUSTER}" >/dev/null 2>&1 || true
k3d cluster create "${CENTRAL_CLUSTER}" \
  --agents 1 \
  --network "${NETWORK}" \
  --port "${CENTRAL_HOST_PORT}:30080@server:0" \
  --wait
k3d image import "${IMAGE}" -c "${CENTRAL_CLUSTER}"
render_manifest "${ROOT_DIR}/deploy/k8s/global/central.yaml" | k "${CENTRAL_CLUSTER}" apply -f -
k "${CENTRAL_CLUSTER}" -n "${NAMESPACE}" rollout status statefulset/globacl-commitd --timeout=180s
k "${CENTRAL_CLUSTER}" -n "${NAMESPACE}" rollout status deploy/globacl-control --timeout=180s
wait_for_http "http://127.0.0.1:${CENTRAL_HOST_PORT}/health"

if [[ -z "${CONTROL_UPSTREAM}" ]]; then
  central_node="k3d-${CENTRAL_CLUSTER}-server-0"
  central_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}" "${central_node}")"
  CONTROL_UPSTREAM="${central_ip}:30080"
fi
echo "Using CONTROL_UPSTREAM=${CONTROL_UPSTREAM}"

for region in "${REGIONS[@]}"; do
  cluster="globacl-${region}"
  CLUSTERS+=("${cluster}")
  k3d cluster delete "${cluster}" >/dev/null 2>&1 || true
  k3d cluster create "${cluster}" --agents 1 --network "${NETWORK}" --wait
  k3d image import "${IMAGE}" -c "${cluster}"
  render_region "${region}" | k "${cluster}" apply -f -
  k "${cluster}" -n "${NAMESPACE}" rollout status deploy/globacl-relay --timeout=180s
  k "${cluster}" -n "${NAMESPACE}" rollout status deploy/globacl-agent --timeout=180s
  k "${cluster}" -n "${NAMESPACE}" rollout status deploy/globacl-demo --timeout=180s
done

index=1
for region in "${REGIONS[@]}"; do
  cluster="globacl-${region}"
  demo_port="$((DEMO_BASE_PORT + index))"
  agent_port="$((AGENT_BASE_PORT + index))"
  relay_port="$((RELAY_BASE_PORT + index))"
  port_forward "${cluster}" globacl-demo "${demo_port}" 8080 "/tmp/globacl-${region}-demo-pf.log"
  port_forward "${cluster}" globacl-agent "${agent_port}" 7002 "/tmp/globacl-${region}-agent-pf.log"
  port_forward "${cluster}" globacl-relay "${relay_port}" 7001 "/tmp/globacl-${region}-relay-pf.log"
  wait_for_http "http://127.0.0.1:${demo_port}/health"
  wait_for_http "http://127.0.0.1:${agent_port}/health"
  wait_for_http "http://127.0.0.1:${relay_port}/health"
  index="$((index + 1))"
done

if [[ "${SEED_DENY}" == "1" ]]; then
  seed_id="ui-global-user-$(date +%s)"
  e2e_client deny \
    --base-url "http://127.0.0.1:${CENTRAL_HOST_PORT}" \
    --op-id "${seed_id}" \
    --tenant-id "${GLOBACL_UI_TENANT_ID}" \
    --namespace "${GLOBACL_UI_NAMESPACE}" \
    --key "${GLOBACL_UI_KEY}" \
    --delivery-priority p0 \
    --reason-code global_ui_seed \
    --created-by global-ui >/tmp/globacl-global-ui-commit.out

  index=1
  for region in "${REGIONS[@]}"; do
    demo_port="$((DEMO_BASE_PORT + index))"
    e2e_client wait-demo-deny \
      --base-url "http://127.0.0.1:${demo_port}" \
      --tenant-id "${GLOBACL_UI_TENANT_ID}" \
      --namespace "${GLOBACL_UI_NAMESPACE}" \
      --key "${GLOBACL_UI_KEY}" \
      --timeout 120s
    echo "${region} observed seeded deny"
    index="$((index + 1))"
  done
  wait_for_propagation_ack "${#REGIONS[@]}"
fi

region_list="${REGIONS[*]}"
cat <<EOF
global UI setup is running
control: http://127.0.0.1:${CENTRAL_HOST_PORT}
ui:      http://${GLOBACL_UI_HOST}:${GLOBACL_UI_PORT}/global-ui/
regions: ${region_list}

Press Ctrl-C to stop port-forwards and delete clusters.
Set KEEP_CLUSTERS=1 to keep k3d clusters after exit.
EOF

(
  cd "${ROOT_DIR}/clients/typescript"
  GLOBACL_UI_HOST="${GLOBACL_UI_HOST}" \
    GLOBACL_UI_PORT="${GLOBACL_UI_PORT}" \
    GLOBACL_UI_CONTROL_URL="http://127.0.0.1:${CENTRAL_HOST_PORT}" \
    GLOBACL_UI_REGIONS="${region_list}" \
    GLOBACL_UI_TENANT_ID="${GLOBACL_UI_TENANT_ID}" \
    GLOBACL_UI_NAMESPACE="${GLOBACL_UI_NAMESPACE}" \
    GLOBACL_UI_KEY="${GLOBACL_UI_KEY}" \
    DEMO_BASE_PORT="${DEMO_BASE_PORT}" \
    AGENT_BASE_PORT="${AGENT_BASE_PORT}" \
    RELAY_BASE_PORT="${RELAY_BASE_PORT}" \
    pnpm run global-ui
)
