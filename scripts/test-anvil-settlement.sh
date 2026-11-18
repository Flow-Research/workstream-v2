#!/usr/bin/env bash
# Requires anvil, cast, jq, Python 3 and solc 0.8.24 (or SOLC=/path/to/solc).
set -euo pipefail
cd "$(dirname "$0")/.."
tmp=$(mktemp -d)
port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')
export WS_ENDPOINT="127.0.0.1:$port" ETH_RPC_URL="http://127.0.0.1:$port"
anvil --host 127.0.0.1 --port "$port" --mnemonic-random >"$tmp/anvil.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
for _ in {1..100}; do
    kill -0 "$pid"
    if cast rpc eth_accounts >"$tmp/accounts" 2>/dev/null; then break; fi
    sleep .1
done
WS_OPERATOR=$(jq -er '.[0]' "$tmp/accounts")
WS_RECIPIENT=$(jq -er '.[1]' "$tmp/accounts")
export WS_OPERATOR WS_RECIPIENT
"${SOLC:-solc}" --bin -o "$tmp" contracts/LocalSettlement.sol >/dev/null
args=$(cast abi-encode 'constructor(bytes32,bytes32)' "0x$(printf '01%.0s' {1..32})" "0x$(printf '02%.0s' {1..32})")
WS_VAULT=$(cast send --unlocked --from "$WS_OPERATOR" --value 1ether --json --create "0x$(cat "$tmp/LocalSettlement.bin")${args#0x}" | jq -er '.contractAddress')
export WS_VAULT
before=$(cast balance "$WS_RECIPIENT")
cargo test -p workstream-core --test anvil_settlement -- --ignored
after=$(cast balance "$WS_RECIPIENT")
events=$(cast logs --from-block 0 --to-block latest --address "$WS_VAULT" --json 'Paid(bytes32,address,uint128)' | jq length)
python3 - "$before" "$after" "$events" <<'PY'
import sys
before, after, events = map(int, sys.argv[1:])
print(f"Anvil: recipient balance delta = {after-before} wei; Paid events = {events}")
if (after-before, events) != (12345, 1):
    sys.exit("Expected exactly one transfer of 12345 wei")
PY
