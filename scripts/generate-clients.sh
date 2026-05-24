#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
OAPI_CODEGEN_VERSION="${OAPI_CODEGEN_VERSION:-v2.5.0}"

go run "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@${OAPI_CODEGEN_VERSION}" \
  --config clients/go/oapi-codegen.yaml \
  docs/openapi.yaml

(
  cd clients/go
  go mod tidy
)

(
  cd clients/typescript
  pnpm install --frozen-lockfile
  pnpm run generate
)
