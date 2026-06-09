#!/usr/bin/env python3
"""Resumen de correlacion y tabla Markdown para benchmarks de agfast."""

import argparse
import csv
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Genera resumen Markdown desde CSV de benchmark.")
    parser.add_argument("--csv", required=True, help="CSV producido por compare_exact_vs_sketch.py.")
    parser.add_argument("--markdown", required=True, help="Archivo Markdown de salida.")
    return parser.parse_args()


def main():
    args = parse_args()
    rows = []
    with Path(args.csv).open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            rows.append(row)

    lines = []
    lines.append("### Resumen de benchmark")
    lines.append("")
    lines.append("#### Tabla comparativa")
    lines.append("")
    lines.append("| Etiqueta | Eventos | Memoria exacta | Memoria probabilística | Top-5 overlap | Top-10 overlap | Spearman |")
    lines.append("|---|---:|---:|---:|---:|---:|---:|")
    for row in rows:
        lines.append(
            "| {etiqueta} | {eventos} | {memoria_exacta_bytes} | {memoria_probabilistica_bytes} | {top5_overlap_procesos} | {top10_overlap_procesos} | {spearman_procesos} |".format(**row)
        )

    lines.append("")
    lines.append("#### Interpretación")
    lines.append("")
    lines.append("Un top-k overlap alto indica que el ranking aproximado conserva los procesos más frecuentes frente al conteo exacto.")
    lines.append("")
    lines.append("Un valor de Spearman cercano a 1.0 indica que el orden relativo de procesos se mantiene de forma consistente.")
    lines.append("")

    Path(args.markdown).write_text("\n".join(lines), encoding="utf-8")
    print("Resumen Markdown generado:", args.markdown)


if __name__ == "__main__":
    main()
