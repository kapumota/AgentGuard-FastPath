#!/usr/bin/env bash
set -euo pipefail

# Benchmark reproducible de Fase 4.
# Los resultados se escriben fuera del repositorio por defecto.

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

if [ ! -x ./bin/agfast ]; then
  echo "agfast no existe; ejecutando make"
  make
fi

BENCH_DIR="${BENCH_DIR:-/tmp/agfast_phase4_benchmark}"
SIZES="${SIZES:-1000 5000 10000}"
MALICIOUS_RATIO="${MALICIOUS_RATIO:-0.05}"

mkdir -p "$BENCH_DIR"
SUMMARY_CSV="$BENCH_DIR/resumen_benchmark.csv"
SUMMARY_MD="$BENCH_DIR/resumen_benchmark.md"
rm -f "$SUMMARY_CSV" "$SUMMARY_MD"

echo "Directorio de resultados: $BENCH_DIR"
echo "Tamanos evaluados: $SIZES"

run_agfast_allow_alerts() {
  set +e
  "$@"
  code=$?
  set -e
  if [ "$code" -ne 0 ] && [ "$code" -ne 2 ]; then
    echo "Comando fallo con codigo $code: $*" >&2
    exit "$code"
  fi
}

for n in $SIZES; do
  events="$BENCH_DIR/events_${n}.jsonl"
  report="$BENCH_DIR/report_${n}.json"
  html="$BENCH_DIR/report_${n}.html"
  alerts="$BENCH_DIR/alerts_${n}.csv"
  console="$BENCH_DIR/console_${n}.txt"

  echo "Generando dataset con $n eventos"
  ./bin/agfast generate --events "$n" --output "$events" --malicious-ratio "$MALICIOUS_RATIO" >/dev/null

  echo "Analizando dataset con $n eventos"
  start_ns="$(date +%s%N)"
  run_agfast_allow_alerts ./bin/agfast analyze "$events" \
    --policy examples/policy.json \
    --risk \
    --window-events 1000 \
    --report "$report" \
    --html "$html" \
    --alerts-csv "$alerts" >"$console"
  end_ns="$(date +%s%N)"
  elapsed_ms=$(( (end_ns - start_ns) / 1000000 ))

  python3 benchmarks/compare_exact_vs_sketch.py \
    --events "$events" \
    --report "$report" \
    --csv "$SUMMARY_CSV" \
    --label "eventos_${n}"

  echo "Tiempo externo aproximado para $n eventos: ${elapsed_ms} ms" >> "$console"
done

python3 benchmarks/rank_correlation.py --csv "$SUMMARY_CSV" --markdown "$SUMMARY_MD"

echo "Benchmark finalizado"
echo "CSV: $SUMMARY_CSV"
echo "Markdown: $SUMMARY_MD"
