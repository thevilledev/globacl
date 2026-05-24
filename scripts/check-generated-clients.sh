#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

scripts/generate-clients.sh

git diff --exit-code -- \
  clients/go/globacl/client.gen.go \
  clients/go/go.mod \
  clients/go/go.sum \
  clients/typescript/package.json \
  clients/typescript/pnpm-lock.yaml \
  clients/typescript/src/generated/schema.d.ts
