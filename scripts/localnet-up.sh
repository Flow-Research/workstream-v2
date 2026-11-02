#!/usr/bin/env bash
# Start the WorkStream localnet.
# Usage: ./scripts/localnet-up.sh
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is not installed. Install Docker Desktop or the docker engine first."
    echo "  macOS: https://docs.docker.com/desktop/install/mac/"
    exit 1
fi

if ! docker info >/dev/null 2>&1; then
    echo "docker daemon is not running. Start Docker Desktop and retry."
    exit 1
fi

echo "==> Building and starting localnet (sequencer :8545, prover :8080, node :30303)..."
docker compose -f docker-compose.yml up -d --build

echo
echo "==> Waiting for containers to start..."
sleep 2
docker compose -f docker-compose.yml ps

echo
echo "Localnet is up. Tail logs with: make localnet-logs"
echo "Stop it with: make localnet-down"
