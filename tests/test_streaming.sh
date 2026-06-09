#!/usr/bin/env bash
set -euo pipefail

# Pruebas de streaming para AgentGuard FastPath.
# Estas pruebas ejercitan tail sin --follow para que sean reproducibles en CI.
# El modo --follow se documenta como validacion manual porque requiere espera activa.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AGFAST="./bin/agfast"
POLICY="examples/policy.json"
BASE_FIXTURE="tests/fixtures/stream_base.jsonl"
APPEND_FIXTURE="tests/fixtures/stream_append.jsonl"
WORKDIR="${TMPDIR:-/tmp}/agfast_streaming_test_$$"

cleanup() {
  rm -rf "$WORKDIR"
}

trap cleanup EXIT

if [ ! -x "$AGFAST" ]; then
  echo "Error: no se encontro ./bin/agfast. Ejecuta make antes de correr test-streaming." >&2
  exit 1
fi

mkdir -p "$WORKDIR"

STREAM_FILE="$WORKDIR/stream.jsonl"
BASE_OUT="$WORKDIR/base.out"
APPEND_OUT="$WORKDIR/appended.out"
EMPTY_OUT="$WORKDIR/empty.out"
CORRUPT_OUT="$WORKDIR/corrupt.out"
WINDOW_OUT="$WORKDIR/window.out"

cp "$BASE_FIXTURE" "$STREAM_FILE"

"$AGFAST" tail "$STREAM_FILE" --policy "$POLICY" > "$BASE_OUT"

grep -q "tail incremental" "$BASE_OUT"
grep -q "Eventos procesados en tail: 3" "$BASE_OUT"
grep -q "CRITICAL" "$BASE_OUT"

: > "$WORKDIR/empty.jsonl"
"$AGFAST" tail "$WORKDIR/empty.jsonl" --policy "$POLICY" > "$EMPTY_OUT"
grep -q "Eventos procesados en tail: 0" "$EMPTY_OUT"

printf '%s\n' "linea corrupta aislada" > "$WORKDIR/corrupt_only.jsonl"
"$AGFAST" tail "$WORKDIR/corrupt_only.jsonl" --policy "$POLICY" > "$CORRUPT_OUT"
grep -q "Eventos procesados en tail: 0" "$CORRUPT_OUT"

cat "$APPEND_FIXTURE" >> "$STREAM_FILE"

"$AGFAST" tail "$STREAM_FILE" --policy "$POLICY" > "$APPEND_OUT"

grep -q "Eventos procesados en tail: 6" "$APPEND_OUT"
grep -q "pid=502" "$APPEND_OUT"
grep -q "CRITICAL" "$APPEND_OUT"

"$AGFAST" tail "$STREAM_FILE" --policy "$POLICY" --window-events 2 > "$WINDOW_OUT"

grep -q "tail incremental" "$WINDOW_OUT"
grep -q "Eventos procesados en tail: 6" "$WINDOW_OUT"

echo "Pruebas de streaming superadas"
