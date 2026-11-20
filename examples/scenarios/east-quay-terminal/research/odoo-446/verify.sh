#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="east-quay-odoo446-verify-$$"
cleanup() {
  docker compose -p "$PROJECT" -f "$HERE/compose.yaml" \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker compose -p "$PROJECT" -f "$HERE/compose.yaml" \
  up --build --abort-on-container-exit --exit-code-from probe
