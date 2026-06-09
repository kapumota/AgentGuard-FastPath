#!/usr/bin/env bash
set -euo pipefail

# Pruebas de regresion de AgentGuard FastPath.
# Las pruebas usan fixtures pequenos y salidas temporales.
# No escriben reportes permanentes en la raiz del repositorio.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

AGFAST="./bin/agfast"
FIXTURES="tests/fixtures"
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_file_exists() {
  local path="$1"
  if [ ! -s "$path" ]; then
    echo "Error: archivo esperado no existe o esta vacio: $path" >&2
    exit 1
  fi
}

assert_json_valid() {
  local path="$1"
  python3 -m json.tool "$path" >/dev/null
}

run_allow_alert_exit() {
  set +e
  "$@"
  local status=$?
  set -e
  if [ "$status" -ne 0 ] && [ "$status" -ne 2 ]; then
    echo "Error: comando fallo con estado $status: $*" >&2
    exit "$status"
  fi
}

if [ ! -x "$AGFAST" ]; then
  echo "Error: no existe $AGFAST. Ejecuta make antes de correr estas pruebas." >&2
  exit 1
fi

echo "Prueba: analyze con JSONL"
run_allow_alert_exit "$AGFAST" analyze "$FIXTURES/events_regression.jsonl" \
  --policy "$FIXTURES/policy_regression.json" \
  --risk \
  --window-events 3 \
  --report "$TMP_DIR/analyze_jsonl.json" \
  --html "$TMP_DIR/analyze_jsonl.html" \
  --alerts-csv "$TMP_DIR/analyze_jsonl_alerts.csv" \
  > "$TMP_DIR/analyze_jsonl.out"
assert_file_exists "$TMP_DIR/analyze_jsonl.json"
assert_file_exists "$TMP_DIR/analyze_jsonl.html"
assert_file_exists "$TMP_DIR/analyze_jsonl_alerts.csv"
assert_json_valid "$TMP_DIR/analyze_jsonl.json"
grep -q "severity,pid,process" "$TMP_DIR/analyze_jsonl_alerts.csv"
grep -q "AgentGuard FastPath" "$TMP_DIR/analyze_jsonl.html"

echo "Prueba: analyze con CSV"
run_allow_alert_exit "$AGFAST" analyze "$FIXTURES/events_regression.csv" \
  --policy "$FIXTURES/policy_regression.json" \
  --risk \
  --report "$TMP_DIR/analyze_csv.json" \
  --alerts-csv "$TMP_DIR/analyze_csv_alerts.csv" \
  > "$TMP_DIR/analyze_csv.out"
assert_file_exists "$TMP_DIR/analyze_csv.json"
assert_file_exists "$TMP_DIR/analyze_csv_alerts.csv"
assert_json_valid "$TMP_DIR/analyze_csv.json"

echo "Prueba: stats"
"$AGFAST" stats "$FIXTURES/events_regression.jsonl" \
  --window-events 3 \
  --report "$TMP_DIR/stats.json" \
  --html "$TMP_DIR/stats.html" \
  > "$TMP_DIR/stats.out"
assert_file_exists "$TMP_DIR/stats.json"
assert_file_exists "$TMP_DIR/stats.html"
assert_json_valid "$TMP_DIR/stats.json"
grep -q "Count-Min Sketch" "$TMP_DIR/stats.out"
grep -q "HyperLogLog" "$TMP_DIR/stats.out"

echo "Prueba: graph por PID"
"$AGFAST" graph "$FIXTURES/events_regression.jsonl" \
  --policy "$FIXTURES/policy_regression.json" \
  --pid 123 \
  --timeline \
  --report "$TMP_DIR/graph_pid.json" \
  > "$TMP_DIR/graph_pid.out"
assert_file_exists "$TMP_DIR/graph_pid.json"
assert_json_valid "$TMP_DIR/graph_pid.json"
grep -q "python" "$TMP_DIR/graph_pid.out"

echo "Prueba: graph por process"
"$AGFAST" graph "$FIXTURES/events_regression.jsonl" \
  --policy "$FIXTURES/policy_regression.json" \
  --process bash \
  --timeline \
  --report "$TMP_DIR/graph_process.json" \
  > "$TMP_DIR/graph_process.out"
assert_file_exists "$TMP_DIR/graph_process.json"
assert_json_valid "$TMP_DIR/graph_process.json"
grep -q "bash" "$TMP_DIR/graph_process.out"

echo "Prueba: timeline"
"$AGFAST" timeline "$FIXTURES/events_regression.jsonl" \
  --policy "$FIXTURES/policy_regression.json" \
  --pid 123 \
  --report "$TMP_DIR/timeline.json" \
  > "$TMP_DIR/timeline.out"
assert_file_exists "$TMP_DIR/timeline.json"
assert_json_valid "$TMP_DIR/timeline.json"
grep -q "python" "$TMP_DIR/timeline.out"

echo "Prueba: check-file"
"$AGFAST" check-file /etc/passwd \
  --policy "$FIXTURES/policy_regression.json" \
  --report "$TMP_DIR/check_file.json" \
  > "$TMP_DIR/check_file.out"
assert_file_exists "$TMP_DIR/check_file.json"
assert_json_valid "$TMP_DIR/check_file.json"
grep -q "MATCH" "$TMP_DIR/check_file.out"

echo "Prueba: check-ip"
"$AGFAST" check-ip 45.90.10.2 \
  --policy "$FIXTURES/policy_regression.json" \
  --report "$TMP_DIR/check_ip.json" \
  > "$TMP_DIR/check_ip.out"
assert_file_exists "$TMP_DIR/check_ip.json"
assert_json_valid "$TMP_DIR/check_ip.json"
grep -q "MATCH" "$TMP_DIR/check_ip.out"

echo "Prueba: check-domain"
"$AGFAST" check-domain malicious.example \
  --policy "$FIXTURES/policy_regression.json" \
  --report "$TMP_DIR/check_domain.json" \
  > "$TMP_DIR/check_domain.out"
assert_file_exists "$TMP_DIR/check_domain.json"
assert_json_valid "$TMP_DIR/check_domain.json"
grep -q "MATCH" "$TMP_DIR/check_domain.out"

echo "Prueba: similarity"
"$AGFAST" similarity "$FIXTURES/events_regression.jsonl" \
  --process python \
  --compare-process bash \
  --policy "$FIXTURES/policy_regression.json" \
  --report "$TMP_DIR/similarity.json" \
  > "$TMP_DIR/similarity.out"
assert_file_exists "$TMP_DIR/similarity.json"
assert_json_valid "$TMP_DIR/similarity.json"
grep -q "Odd Sketch" "$TMP_DIR/similarity.out"

echo "Prueba: generate JSONL"
"$AGFAST" generate --events 50 \
  --output "$TMP_DIR/generated.jsonl" \
  --malicious-ratio 0.10 \
  > "$TMP_DIR/generate_jsonl.out"
assert_file_exists "$TMP_DIR/generated.jsonl"
"$AGFAST" stats "$TMP_DIR/generated.jsonl" \
  --report "$TMP_DIR/generated_stats.json" \
  > "$TMP_DIR/generated_stats.out"
assert_json_valid "$TMP_DIR/generated_stats.json"

echo "Prueba: generate CSV"
"$AGFAST" generate --events 50 \
  --format csv \
  --output "$TMP_DIR/generated.csv" \
  --malicious-ratio 0.10 \
  > "$TMP_DIR/generate_csv.out"
assert_file_exists "$TMP_DIR/generated.csv"
"$AGFAST" stats "$TMP_DIR/generated.csv" \
  --report "$TMP_DIR/generated_csv_stats.json" \
  > "$TMP_DIR/generated_csv_stats.out"
assert_json_valid "$TMP_DIR/generated_csv_stats.json"

echo "Prueba: tail sin follow"
"$AGFAST" tail "$FIXTURES/events_tail.jsonl" \
  --policy "$FIXTURES/policy_regression.json" \
  > "$TMP_DIR/tail.out"
grep -q "CRITICAL" "$TMP_DIR/tail.out"
grep -q "Eventos procesados" "$TMP_DIR/tail.out"

echo "Pruebas de regresion superadas"
