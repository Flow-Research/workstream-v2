#!/usr/bin/env bash
# A fresh project/volume set per invocation; never reset a developer's chain.
set -euo pipefail
cd "$(dirname "$0")/.."
out=$(mktemp -d "${WORKSTREAM_ARTIFACT_PARENT:-${TMPDIR:-/tmp}}/compose-gate.XXXXXXXX")
export COMPOSE_PROJECT_NAME="ws-gate-$(basename "$out" | tr '[:upper:].' '[:lower:]-')"
echo "Gate artifacts: $out"
cleanup() {
  status=$?
  trap - EXIT
  docker compose ps -a > "$out/status.txt" || true
  docker compose logs --no-color > "$out/services.log" 2>&1 || true
  if (( status != 0 )); then cat "$out/status.txt"; tail -100 "$out/services.log"; fi
  docker compose down --volumes --remove-orphans || status=1
  exit "$status"
}
trap cleanup EXIT
docker compose build bootstrap 2>&1 | tee "$out/build.log"
docker compose up -d --no-build --wait --wait-timeout 90 node
docker compose exec -T node python3 - < scripts/compose-receipt.py | tee "$out/receipt.json"
docker compose exec -T node python3 - < scripts/compose-projection.py | tee "$out/projection.json"
docker compose exec -T jobdb sh -c \
  'PGPASSWORD=$(cat /db-secrets/worker) psql -U worker -d proofjobs -Atc \
   "SELECT chain,height,attempts,queue_ms IS NOT NULL,runtime_ms IS NOT NULL,rejection IS NULL,complete FROM proof_job_status"' \
  | tee "$out/job-status.txt"
test "$(wc -l < "$out/job-status.txt" | tr -d ' ')" -ge 1
