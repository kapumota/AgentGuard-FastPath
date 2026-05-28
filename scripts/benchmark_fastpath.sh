#!/usr/bin/env bash
set -euo pipefail

BIN="${1:-./bin/agfast}"
BENCH_DIR="${BENCH_DIR:-/tmp/agfast_bench}"
mkdir -p "$BENCH_DIR"

printf 'AgentGuard FastPath - benchmark 10k / 100k / 1M\n'
printf 'Directorio temporal: %s\n\n' "$BENCH_DIR"
printf '| Eventos | Tiempo análisis | Exacta estimada | Probabilística fija | Relación exacta/prob | Reporte |\n'
printf '|---:|---:|---:|---:|---:|---|\n'

for n in 10000 100000 1000000; do
  events="$BENCH_DIR/events_${n}.jsonl"
  report="$BENCH_DIR/stats_${n}.json"
  log="$BENCH_DIR/stats_${n}.txt"
  python3 scripts/generate_events.py --count "$n" --out "$events" --format jsonl
  "$BIN" stats "$events" --report "$report" > "$log"
  processed=$(grep -E '^Eventos procesados:' "$log" | awk '{print $3}')
  elapsed=$(grep -E '^Tiempo de análisis:' "$log" | awk '{print $4" "$5}')
  exact=$(grep -E '^  Exacta estimada equivalente:' "$log" | awk '{print $4" "$5}')
  approx=$(grep -E '^  Probabilística fija aprox\.:' "$log" | awk '{print $4" "$5}')
  ratio=$(grep -E '^  Relación exacta/probabilística:' "$log" | awk '{print $3}')
  printf '| %s | %s | %s | %s | %s | %s |\n' "$processed" "$elapsed" "$exact" "$approx" "$ratio" "$report"
done

printf '\nPara revisar un reporte: python3 -m json.tool %s/stats_1000000.json | less\n' "$BENCH_DIR"
