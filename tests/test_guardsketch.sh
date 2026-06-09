#!/usr/bin/env bash
set -euo pipefail

# Prueba de GuardSketch MVP en userspace.
# Compila el prototipo como unidad autocontenida.
# No modifica el binario principal agfast.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORKDIR="${TMPDIR:-/tmp}/agfast_guardsketch_test_$$"
BIN="$WORKDIR/guardsketch_selftest"
OUT="$WORKDIR/guardsketch.out"

cleanup() {
  rm -rf "$WORKDIR"
}

trap cleanup EXIT

mkdir -p "$WORKDIR"

cc -std=c11 -Wall -Wextra -Wpedantic -O2 \
  -DAGFAST_GUARDSKETCH_SELFTEST \
  src/agfast_parts/guardsketch.c \
  -o "$BIN"

"$BIN" > "$OUT"

grep -q "GuardSketch MVP userspace" "$OUT"
grep -q "Drops simulados:" "$OUT"
grep -q "Top overlap:" "$OUT"
grep -q "Riesgo exacto PID 101:" "$OUT"
grep -q "Riesgo aproximado PID 101:" "$OUT"
grep -q "Pruebas GuardSketch superadas" "$OUT"

echo "Pruebas GuardSketch superadas"
