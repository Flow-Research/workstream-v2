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

echo "==> Building connected services and waiting for prover, sequencer, then verifier..."
docker compose build bootstrap
docker compose up -d --no-build --wait --wait-timeout 90 node
docker compose -f docker-compose.yml ps

echo
echo "Localnet is up. Tail logs with: make localnet-logs"
echo "Stop it with: make localnet-down"
