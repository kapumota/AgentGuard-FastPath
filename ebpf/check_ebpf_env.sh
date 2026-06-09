#!/usr/bin/env bash
set -euo pipefail

# Verificacion opcional de entorno eBPF.
# Este script no falla si faltan dependencias.
# Su objetivo es informar si la maquina esta lista para una fase futura.

missing=0

check_cmd() {
  local cmd="$1"
  local label="$2"

  if command -v "$cmd" >/dev/null 2>&1; then
    printf "[ok] %s: %s\n" "$label" "$(command -v "$cmd")"
  else
    printf "[pendiente] %s: no encontrado\n" "$label"
    missing=1
  fi
}

check_path() {
  local path="$1"
  local label="$2"

  if [ -e "$path" ]; then
    printf "[ok] %s: %s\n" "$label" "$path"
  else
    printf "[pendiente] %s: no encontrado\n" "$label"
    missing=1
  fi
}

echo "### Chequeo opcional de entorno eBPF"
echo ""
echo "Kernel actual:"
uname -r
echo ""

check_cmd clang "clang"
check_cmd llvm-strip "llvm-strip"
check_cmd bpftool "bpftool"
check_cmd pkg-config "pkg-config"

if command -v pkg-config >/dev/null 2>&1; then
  if pkg-config --exists libbpf; then
    printf "[ok] libbpf: disponible mediante pkg-config\n"
  else
    printf "[pendiente] libbpf: no disponible mediante pkg-config\n"
    missing=1
  fi
else
  printf "[pendiente] libbpf: no se puede verificar sin pkg-config\n"
  missing=1
fi

check_path "/lib/modules/$(uname -r)/build" "headers del kernel"

echo ""
if [ "$missing" -eq 0 ]; then
  echo "Entorno eBPF listo para una fase futura."
else
  echo "Entorno eBPF incompleto."
  echo "Esto no afecta la compilacion normal de agfast."
  echo "Instala dependencias solo cuando se vaya a trabajar la fase eBPF real."
fi

exit 0
