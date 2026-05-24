#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMMAND="up"
MESSAGING="pull"
CLUSTER="${CLUSTER:-globacl-dev}"
IMAGE="${IMAGE:-ghcr.io/thevilledev/globacl:ci}"
NAMESPACE="${NAMESPACE:-globacl}"
CONTROL_PORT="${CONTROL_PORT:-17200}"
DEMO_PORT="${DEMO_PORT:-18280}"
PROMETHEUS_PORT="${PROMETHEUS_PORT:-19090}"
GRAFANA_PORT="${GRAFANA_PORT:-13000}"
AGENTS="${AGENTS:-2}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_RESTART="${SKIP_RESTART:-0}"

PIDS=()

parse_args() {
  local command_seen="0"
  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      up | deploy | redeploy | ports | status | delete | help)
        if [[ "${command_seen}" == "1" ]]; then
          echo "only one command can be provided" >&2
          usage >&2
          exit 1
        fi
        COMMAND="$1"
        command_seen="1"
        shift
        ;;
      -h | --help)
        COMMAND="help"
        shift
        ;;
      --messaging)
        if [[ "$#" -lt 2 ]]; then
          echo "--messaging requires a value" >&2
          usage >&2
          exit 1
        fi
        MESSAGING="$2"
        shift 2
        ;;
      --messaging=*)
        MESSAGING="${1#--messaging=}"
        shift
        ;;
      *)
        echo "unknown argument: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
  normalize_messaging
}

normalize_messaging() {
  case "${MESSAGING}" in
    pull | pull-proxy | http)
      MESSAGING="pull"
      ;;
    jetstream | nats | nats-jetstream)
      MESSAGING="jetstream"
      ;;
    *)
      echo "unsupported --messaging value: ${MESSAGING}" >&2
      usage >&2
      exit 1
      ;;
  esac
}

cleanup_ports() {
  for pid in "${PIDS[@]:-}"; do
    kill "${pid}" 2>/dev/null || true
    wait "${pid}" 2>/dev/null || true
  done
}
trap cleanup_ports EXIT

usage() {
  cat <<EOF
usage: $0 [up|deploy|redeploy|ports|status|delete] [--messaging pull|jetstream]

Commands:
  up       create/reuse the dev cluster, deploy current code, and keep ports open
  deploy   rebuild/import/redeploy current code to the existing cluster, then exit
  redeploy alias for deploy
  ports    attach local port-forwards to an existing cluster, then wait
  status   show pods and services in the dev cluster
  delete   delete the dev cluster

Options:
  --messaging pull       use the HTTP pull-proxy relay source (default)
  --messaging jetstream  deploy NATS JetStream and use it as the relay source

Environment:
  CLUSTER=${CLUSTER}
  IMAGE=${IMAGE}
  CONTROL_PORT=${CONTROL_PORT}
  DEMO_PORT=${DEMO_PORT}
  PROMETHEUS_PORT=${PROMETHEUS_PORT}
  GRAFANA_PORT=${GRAFANA_PORT}
  SKIP_BUILD=1       reuse the current local image tag
  SKIP_RESTART=1     apply manifests without restarting workloads
EOF
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

k() {
  kubectl --context "k3d-${CLUSTER}" "$@"
}

cluster_exists() {
  k3d cluster list "${CLUSTER}" >/dev/null 2>&1
}

ensure_cluster() {
  if cluster_exists; then
    echo "using existing k3d cluster ${CLUSTER}"
    return
  fi

  echo "creating k3d cluster ${CLUSTER}"
  k3d cluster create "${CLUSTER}" --agents "${AGENTS}" --wait
}

build_and_import_image() {
  if [[ "${SKIP_BUILD}" != "1" ]]; then
    echo "building ${IMAGE}"
    docker build -t "${IMAGE}" "${ROOT_DIR}"
  else
    echo "skipping docker build; importing existing ${IMAGE}"
  fi

  echo "importing ${IMAGE} into ${CLUSTER}"
  k3d image import "${IMAGE}" -c "${CLUSTER}"
}

rollout_restart() {
  if [[ "${SKIP_RESTART}" == "1" ]]; then
    return
  fi

  echo "restarting workloads so pods use the imported image"
  k -n "${NAMESPACE}" rollout restart statefulset/globacl-commitd
  k -n "${NAMESPACE}" rollout restart deploy/globacl-control
  k -n "${NAMESPACE}" rollout restart deploy/globacl-relay
  k -n "${NAMESPACE}" rollout restart deploy/globacl-agent
  k -n "${NAMESPACE}" rollout restart deploy/globacl-demo
  k -n "${NAMESPACE}" rollout restart deploy/globacl-prometheus
  k -n "${NAMESPACE}" rollout restart deploy/globacl-grafana
}

wait_for_rollouts() {
  if [[ "${MESSAGING}" == "jetstream" ]]; then
    k -n "${NAMESPACE}" rollout status deploy/globacl-nats --timeout=180s
  fi
  k -n "${NAMESPACE}" rollout status statefulset/globacl-commitd --timeout=240s
  k -n "${NAMESPACE}" rollout status deploy/globacl-control --timeout=180s
  k -n "${NAMESPACE}" rollout status deploy/globacl-relay --timeout=180s
  k -n "${NAMESPACE}" rollout status deploy/globacl-agent --timeout=180s
  k -n "${NAMESPACE}" rollout status deploy/globacl-demo --timeout=180s
  k -n "${NAMESPACE}" rollout status deploy/globacl-prometheus --timeout=180s
  k -n "${NAMESPACE}" rollout status deploy/globacl-grafana --timeout=180s
}

configure_pull_proxy() {
  echo "configuring HTTP pull-proxy relay source"
  k -n "${NAMESPACE}" set env statefulset/globacl-commitd \
    GLOBACL_COMMITD_PUBLISHER- \
    GLOBACL_NATS_ADDR- \
    GLOBACL_NATS_PUBLISH_MS-
  k -n "${NAMESPACE}" set env deploy/globacl-relay \
    GLOBACL_RELAY_SOURCE- \
    GLOBACL_NATS_ADDR- \
    GLOBACL_NATS_BATCH-
  k delete -f "${ROOT_DIR}/deploy/k8s/nats-jetstream.yaml" --ignore-not-found
}

configure_jetstream() {
  echo "deploying NATS JetStream relay source"
  k apply -f "${ROOT_DIR}/deploy/k8s/nats-jetstream.yaml"
  k -n "${NAMESPACE}" rollout status deploy/globacl-nats --timeout=180s
  k -n "${NAMESPACE}" set env statefulset/globacl-commitd \
    GLOBACL_COMMITD_PUBLISHER=jetstream \
    GLOBACL_NATS_ADDR=globacl-nats.globacl.svc.cluster.local:4222 \
    GLOBACL_NATS_PUBLISH_MS=100
  k -n "${NAMESPACE}" set env deploy/globacl-relay \
    GLOBACL_RELAY_SOURCE=jetstream \
    GLOBACL_NATS_ADDR=globacl-nats.globacl.svc.cluster.local:4222 \
    GLOBACL_NATS_BATCH=16
}

configure_messaging() {
  case "${MESSAGING}" in
    pull)
      configure_pull_proxy
      ;;
    jetstream)
      configure_jetstream
      ;;
  esac
}

apply_grafana() {
  k -n "${NAMESPACE}" create configmap globacl-grafana-dashboard \
    --from-file=globacl-overview.json="${ROOT_DIR}/deploy/grafana/globacl-overview.json" \
    --dry-run=client \
    -o yaml | k apply -f -
  k apply -f "${ROOT_DIR}/deploy/k8s/grafana.yaml"
}

deploy_current_code() {
  ensure_cluster
  build_and_import_image

  echo "applying local observability topology"
  k apply -f "${ROOT_DIR}/deploy/k8s/local-observability.yaml"
  apply_grafana
  configure_messaging
  rollout_restart
  wait_for_rollouts
}

port_forward() {
  local resource="$1"
  local host_port="$2"
  local target_port="$3"
  local log_file="$4"
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
      k -n "${NAMESPACE}" port-forward "${resource}" "${host_port}:${target_port}" &
      child_pid="$!"
      wait "${child_pid}" || true
      child_pid=""
      sleep 1
    done
  ) >"${log_file}" 2>&1 &
  PIDS+=("$!")
}

open_ports() {
  echo "opening local ports; press Ctrl-C to stop forwarding"
  port_forward svc/globacl-control "${CONTROL_PORT}" 7000 /tmp/globacl-dev-control-pf.log
  port_forward svc/globacl-demo "${DEMO_PORT}" 8080 /tmp/globacl-dev-demo-pf.log
  port_forward svc/globacl-prometheus "${PROMETHEUS_PORT}" 9090 /tmp/globacl-dev-prometheus-pf.log
  port_forward svc/globacl-grafana "${GRAFANA_PORT}" 3000 /tmp/globacl-dev-grafana-pf.log

  cat <<EOF
control:    http://127.0.0.1:${CONTROL_PORT}
demo:       http://127.0.0.1:${DEMO_PORT}
prometheus: http://127.0.0.1:${PROMETHEUS_PORT}
grafana:    http://127.0.0.1:${GRAFANA_PORT}/d/globacl-overview/globacl-system-overview
messaging:  ${MESSAGING}

Redeploy code from another terminal:
  ./deploy/k3s/dev-cluster.sh deploy --messaging ${MESSAGING}

Delete the cluster:
  ./deploy/k3s/dev-cluster.sh delete
EOF

  wait
}

show_status() {
  k -n "${NAMESPACE}" get pods -o wide
  k -n "${NAMESPACE}" get svc
}

parse_args "$@"

case "${COMMAND}" in
  help)
    usage
    ;;
  up)
    require_cmd docker
    require_cmd k3d
    require_cmd kubectl
    deploy_current_code
    show_status
    open_ports
    ;;
  deploy | redeploy)
    require_cmd docker
    require_cmd k3d
    require_cmd kubectl
    deploy_current_code
    show_status
    ;;
  ports)
    require_cmd k3d
    require_cmd kubectl
    if ! cluster_exists; then
      echo "cluster ${CLUSTER} does not exist; run '$0 up' first" >&2
      exit 1
    fi
    open_ports
    ;;
  status)
    require_cmd k3d
    require_cmd kubectl
    if ! cluster_exists; then
      echo "cluster ${CLUSTER} does not exist" >&2
      exit 1
    fi
    show_status
    ;;
  delete)
    require_cmd k3d
    k3d cluster delete "${CLUSTER}"
    ;;
  *)
    usage >&2
    exit 1
    ;;
esac
