#!/usr/bin/env bash
# Stop the WorkStream localnet and clean up containers/volumes.
# Usage: ./scripts/localnet-down.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed; nothing to stop."
    exit 0
fi

echo "==> Stopping localnet and removing containers/volumes..."
docker compose -f docker-compose.yml down --volumes

echo "Localnet stopped."
