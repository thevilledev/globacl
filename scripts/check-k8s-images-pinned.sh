#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
failed="0"

while IFS= read -r -d "" file; do
  while IFS= read -r line; do
    line_no="${line%%:*}"
    image="${line#*:}"
    image="${image#"${image%%[![:space:]]*}"}"
    image="${image%"${image##*[![:space:]]}"}"
    image="${image%\"}"
    image="${image#\"}"
    image="${image%\'}"
    image="${image#\'}"

    if [[ "${image}" == "__GLOBACL_IMAGE__" ]]; then
      continue
    fi
    if [[ "${image}" =~ @sha256:[0-9a-f]{64}$ ]]; then
      continue
    fi

    echo "${file#${ROOT_DIR}/}:${line_no}: image is not digest-pinned: ${image}" >&2
    failed="1"
  done < <(grep -nE "^[[:space:]]*image:[[:space:]]*" "${file}" | sed -E "s/^([0-9]+):[[:space:]]*image:[[:space:]]*/\\1:/")
done < <(find "${ROOT_DIR}/deploy/k8s" -type f \( -name "*.yaml" -o -name "*.yaml.tpl" \) -print0)

if [[ "${failed}" == "1" ]]; then
  exit 1
fi
