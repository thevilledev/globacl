#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="${IMAGE:-ghcr.io/thevilledev/globacl:ci}"
NETWORK="${NETWORK:-globacl-scale-k3d}"
CENTRAL_CLUSTER="${CENTRAL_CLUSTER:-globacl-scale-central}"
REGION_CLUSTER_PREFIX="${REGION_CLUSTER_PREFIX:-globacl-scale-}"
CENTRAL_HOST_PORT="${CENTRAL_HOST_PORT:-17400}"
CONTROL_UPSTREAM="${CONTROL_UPSTREAM:-}"
NAMESPACE="${NAMESPACE:-globacl}"
KEEP_CLUSTERS="${KEEP_CLUSTERS:-0}"
REGIONS=(${REGIONS:-region-a region-b region-c})
DEMO_BASE_PORT="${DEMO_BASE_PORT:-18400}"
SKIP_BUILD="${SKIP_BUILD:-0}"

SCALE_USERS="${SCALE_USERS:-100000000}"
SEED_DENIES="${SEED_DENIES:-10000}"
SEED_CONCURRENCY="${SEED_CONCURRENCY:-32}"
SEED_PRIORITY="${SEED_PRIORITY:-p1}"
SEED_RETRIES="${SEED_RETRIES:-5}"
SEED_RETRY_DELAY="${SEED_RETRY_DELAY:-250ms}"
SEED_PROPAGATION_TIMEOUT="${SEED_PROPAGATION_TIMEOUT:-600s}"
LOOKUP_WORKERS="${LOOKUP_WORKERS:-64}"
LOOKUP_DURATION="${LOOKUP_DURATION:-1m}"
LOOKUP_DENY_RATIO="${LOOKUP_DENY_RATIO:-0.001}"
LOAD_MAX_ERROR_RATE="${LOAD_MAX_ERROR_RATE:-0}"
LOAD_ASSERT_DECISIONS="${LOAD_ASSERT_DECISIONS:-1}"
LOAD_REQUEST_TIMEOUT="${LOAD_REQUEST_TIMEOUT:-5s}"
LOAD_RETRIES="${LOAD_RETRIES:-2}"
LOAD_WARMUP="${LOAD_WARMUP:-5}"
CANARY_TIMEOUT="${CANARY_TIMEOUT:-60s}"
RUN_ID="${RUN_ID:-$(date +%s)}"
CANARY_KEY="${CANARY_KEY:-scale-canary-${RUN_ID}}"
CANARY_OP_ID="${CANARY_OP_ID:-scale-canary-${RUN_ID}}"
LOAD_OUTPUT="${LOAD_OUTPUT:-/tmp/globacl-scale-load-${RUN_ID}.out}"

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

wait_for_http() {
  local url="$1"
  e2e_client wait-health --base-url "${url}" --timeout 120s
}

wait_for_propagation_ack() {
  local expected_agents="$1"
  local timeout="$2"
  e2e_client wait-propagation \
    --base-url "http://127.0.0.1:${CENTRAL_HOST_PORT}" \
    --expected-agents "${expected_agents}" \
    --timeout "${timeout}"
}

join_by_comma() {
  local IFS=","
  echo "$*"
}

require_cmd docker
require_cmd k3d
require_cmd kubectl
require_cmd go

if [[ "${#REGIONS[@]}" -lt 1 ]]; then
  echo "REGIONS must contain at least one region" >&2
  exit 1
fi

cd "${ROOT_DIR}"
if [[ "${SKIP_BUILD}" != "1" ]]; then
  docker build -t "${IMAGE}" .
else
  echo "skipping docker build; importing existing ${IMAGE}"
fi

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
k "${CENTRAL_CLUSTER}" -n "${NAMESPACE}" rollout status statefulset/globacl-commitd --timeout=240s
k "${CENTRAL_CLUSTER}" -n "${NAMESPACE}" rollout status deploy/globacl-control --timeout=180s
wait_for_http "http://127.0.0.1:${CENTRAL_HOST_PORT}/health"

if [[ -z "${CONTROL_UPSTREAM}" ]]; then
  central_node="k3d-${CENTRAL_CLUSTER}-server-0"
  central_ip="$(docker inspect -f "{{(index .NetworkSettings.Networks \"${NETWORK}\").IPAddress}}" "${central_node}")"
  CONTROL_UPSTREAM="${central_ip}:30080"
fi
echo "Using CONTROL_UPSTREAM=${CONTROL_UPSTREAM}"

DEMO_URLS=()
index=1
for region in "${REGIONS[@]}"; do
  cluster="${REGION_CLUSTER_PREFIX}${region}"
  CLUSTERS+=("${cluster}")
  k3d cluster delete "${cluster}" >/dev/null 2>&1 || true
  k3d cluster create "${cluster}" --agents 1 --network "${NETWORK}" --wait
  k3d image import "${IMAGE}" -c "${cluster}"
  render_region "${region}" | k "${cluster}" apply -f -
  k "${cluster}" -n "${NAMESPACE}" rollout status deploy/globacl-relay --timeout=180s
  k "${cluster}" -n "${NAMESPACE}" rollout status deploy/globacl-agent --timeout=180s
  k "${cluster}" -n "${NAMESPACE}" rollout status deploy/globacl-demo --timeout=180s

  port="$((DEMO_BASE_PORT + index))"
  k "${cluster}" -n "${NAMESPACE}" port-forward svc/globacl-demo "${port}:8080" >/tmp/globacl-scale-${region}-demo-pf.log 2>&1 &
  PIDS+=("$!")
  wait_for_http "http://127.0.0.1:${port}/health"
  DEMO_URLS+=("http://127.0.0.1:${port}")
  index="$((index + 1))"
done

echo "seeding ${SEED_DENIES} denies across ${SCALE_USERS} virtual users"
e2e_client seed-denies \
  --base-url "http://127.0.0.1:${CENTRAL_HOST_PORT}" \
  --count "${SEED_DENIES}" \
  --keyspace "${SCALE_USERS}" \
  --concurrency "${SEED_CONCURRENCY}" \
  --delivery-priority "${SEED_PRIORITY}" \
  --retries "${SEED_RETRIES}" \
  --retry-delay "${SEED_RETRY_DELAY}" \
  --op-prefix "scale-seed-${RUN_ID}" \
  --reason-code scale_seed \
  --created-by scale-e2e

echo "waiting for seeded deny state to reach ${#REGIONS[@]} agents"
wait_for_propagation_ack "${#REGIONS[@]}" "${SEED_PROPAGATION_TIMEOUT}"

demo_base_urls="$(join_by_comma "${DEMO_URLS[@]}")"
assert_arg="--assert-decisions=true"
if [[ "${LOAD_ASSERT_DECISIONS}" != "1" ]]; then
  assert_arg="--assert-decisions=false"
fi

echo "starting lookup load for ${LOOKUP_DURATION} with ${LOOKUP_WORKERS} workers"
e2e_client load-demo \
  --base-url "${demo_base_urls}" \
  --duration "${LOOKUP_DURATION}" \
  --workers "${LOOKUP_WORKERS}" \
  --keyspace "${SCALE_USERS}" \
  --denied-count "${SEED_DENIES}" \
  --deny-ratio "${LOOKUP_DENY_RATIO}" \
  --max-error-rate "${LOAD_MAX_ERROR_RATE}" \
  --request-timeout "${LOAD_REQUEST_TIMEOUT}" \
  --retries "${LOAD_RETRIES}" \
  "${assert_arg}" >"${LOAD_OUTPUT}" &
LOAD_PID="$!"
PIDS+=("${LOAD_PID}")

sleep "${LOAD_WARMUP}"
echo "committing P0 canary ${CANARY_KEY} during lookup load"
e2e_client deny \
  --base-url "http://127.0.0.1:${CENTRAL_HOST_PORT}" \
  --op-id "${CANARY_OP_ID}" \
  --tenant-id tenant-a \
  --namespace user \
  --key "${CANARY_KEY}" \
  --delivery-priority p0 \
  --reason-code scale_canary \
  --created-by scale-e2e

for url in "${DEMO_URLS[@]}"; do
  e2e_client wait-demo-deny \
    --base-url "${url}" \
    --tenant-id tenant-a \
    --namespace user \
    --key "${CANARY_KEY}" \
    --timeout "${CANARY_TIMEOUT}"
  echo "${url} observed scale canary"
done

wait_for_propagation_ack "${#REGIONS[@]}" "${CANARY_TIMEOUT}"

set +e
wait "${LOAD_PID}"
load_status="$?"
set -e
cat "${LOAD_OUTPUT}"
if [[ "${load_status}" != "0" ]]; then
  echo "scale load failed" >&2
  exit "${load_status}"
fi

echo "scale e2e passed"
