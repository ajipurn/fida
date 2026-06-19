#!/usr/bin/env bash
#
# examples/demo.sh - the hero demo, runnable and recordable.
#
# Shows the contrast Fida exists for: a coding agent reading `.env` leaks your
# keys; the same read through the Fida gateway preserves useful structure while
# redacting secret values before they reach the agent.
#
# Record it with asciinema/vhs for the README/launch:
#   asciinema rec -c examples/demo.sh fida-demo.cast
#
# No secrets are real. The planted values are synthetic.
set -euo pipefail

if command -v fida >/dev/null 2>&1; then
  FIDA="$(command -v fida)"
else
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  project="$(dirname "$here")"
  (cd "$project" && cargo build -q -p fida-cli)
  FIDA="$project/target/debug/fida"
fi

ws="$(mktemp -d)"
trap 'rm -rf "$ws"' EXIT

secret="demo-secret-value-abcdefghijklmnopqrstuvwxyz"
printf 'API_KEY=%s\n' "$secret" >"$ws/.env"
printf 'deploy notes\nAPI_KEY=%s\n' "$secret" >"$ws/notes.txt"

say() { printf '\033[1m%s\033[0m\n' "$1"; }
rule() { printf '\n%s\n\n' '------------------------------------------------------------'; }

gateway_read() {
  local path="$1"
  printf '%s\n' "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"fida_read\",\"arguments\":{\"path\":\"$path\"}}}" |
    (cd "$ws" && "$FIDA" mcp serve --workspace "$ws" 2>/dev/null)
}

say "1) Without Fida, an agent that reads .env sees your keys:"
echo "   $ cat .env"
sed 's/^/   /' "$ws/.env"

rule
say "2) See the risk before an agent runs:"
(cd "$ws" && "$FIDA" scan) || true

rule
say "3) The same read through the Fida gateway returns a redacted safe view:"
echo "   > fida_read .env"
gateway_read ".env" | sed 's/^/   /'

rule
say "4) A key in an ordinary file is redacted before the agent sees it:"
echo "   > fida_read notes.txt"
gateway_read "notes.txt" | sed 's/^/   /'

rule
say "The secret value never reached the agent. See: fida doctor"
