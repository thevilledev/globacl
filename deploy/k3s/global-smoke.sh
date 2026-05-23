#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE:-globacl:ci}"
NETWORK="${NETWORK:-globacl-k3d}"
CENTRAL_CLUSTER="${CENTRAL_CLUSTER:-globacl-central}"
CENTRAL_HOST_PORT="${CENTRAL_HOST_PORT:-17000}"
CONTROL_UPSTREAM="${CONTROL_UPSTREAM:-}"
NAMESPACE="${NAMESPACE:-globacl}"
KEEP_CLUSTERS="${KEEP_CLUSTERS:-0}"
REGIONS=(${REGIONS:-region-a region-b region-c})
DEMO_BASE_PORT="${DEMO_BASE_PORT:-18100}"

PIDS=()
CLUSTERS=("${CENTRAL_CLUSTER}")
CREATED_NETWORK="0"

cleanup() {
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
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
  for _ in $(seq 1 120); do
    if curl -fsS "${url}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "timed out waiting for ${url}" >&2
  return 1
}

render_region() {
  local region="$1"
  sed \
    -e "s#__REGION_NAME__#${region}#g" \
    -e "s#__CONTROL_UPSTREAM__#${CONTROL_UPSTREAM}#g" \
    "${ROOT_DIR}/deploy/k8s/global/region.yaml.tpl"
}

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd curl

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
k "${CENTRAL_CLUSTER}" apply -f "${ROOT_DIR}/deploy/k8s/global/central.yaml"
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

curl -fsS "http://127.0.0.1:${CENTRAL_HOST_PORT}/v1/deny" \
  --data-binary $'op_id=ci-global-user\ntenant_id=tenant-a\nnamespace=user\nkey=user-global\naction=deny\ndelivery_priority=p0\nreason_code=ci_global_smoke\ncreated_by=ci\n' >/tmp/globacl-global-commit.out

index=1
for region in "${REGIONS[@]}"; do
  cluster="globacl-${region}"
  port="$((DEMO_BASE_PORT + index))"
  k "${cluster}" -n "${NAMESPACE}" port-forward svc/globacl-demo "${port}:8080" >/tmp/globacl-${region}-demo-pf.log 2>&1 &
  PIDS+=("$!")
  wait_for_http "http://127.0.0.1:${port}/health"

  observed="0"
  for _ in $(seq 1 120); do
    response="$(curl -sS "http://127.0.0.1:${port}/access?tenant_id=tenant-a&namespace=user&key=user-global")"
    if grep -q "access=denied" <<<"${response}"; then
      observed="1"
      break
    fi
    sleep 1
  done
  if [[ "${observed}" != "1" ]]; then
    echo "global smoke failed: ${region} did not observe deny" >&2
    exit 1
  fi
  echo "${region} observed global deny"
  index="$((index + 1))"
done

echo "global smoke passed"
