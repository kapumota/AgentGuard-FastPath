#!/usr/bin/env python3
"""Comparacion exacta contra sketches para reportes de agfast."""

import argparse
import csv
import json
import math
from collections import Counter
from pathlib import Path


def parse_args():
    parser = argparse.ArgumentParser(description="Compara conteos exactos contra estimaciones de sketches.")
    parser.add_argument("--events", required=True, help="Archivo de eventos JSONL generado por agfast.")
    parser.add_argument("--report", required=True, help="Reporte JSON producido por agfast analyze.")
    parser.add_argument("--csv", required=True, help="Archivo CSV de salida. Se agrega una fila.")
    parser.add_argument("--label", default="", help="Etiqueta del experimento.")
    return parser.parse_args()


def read_jsonl(path):
    events = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def top_keys(counter, limit):
    return [key for key, _ in counter.most_common(limit)]


def report_top(report, section, name, key_name="key"):
    values = report.get(section, {}).get(name, [])
    return [str(item.get(key_name, "")) for item in values if item.get(key_name, "")]


def top_overlap(a, b, k):
    left = set(a[:k])
    right = set(b[:k])
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return len(left & right) / float(k)


def rank_map(items):
    return {value: index + 1 for index, value in enumerate(items)}


def spearman_from_lists(a, b):
    universe = list(dict.fromkeys(list(a) + list(b)))
    if len(universe) < 2:
        return 1.0
    missing_rank = len(universe) + 1
    ra = rank_map(a)
    rb = rank_map(b)
    xs = [ra.get(item, missing_rank) for item in universe]
    ys = [rb.get(item, missing_rank) for item in universe]
    mean_x = sum(xs) / len(xs)
    mean_y = sum(ys) / len(ys)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
    den_x = math.sqrt(sum((x - mean_x) ** 2 for x in xs))
    den_y = math.sqrt(sum((y - mean_y) ** 2 for y in ys))
    if den_x == 0 or den_y == 0:
        return 1.0
    return num / (den_x * den_y)


def relative_error(estimated, exact):
    if exact == 0:
        return 0.0 if estimated == 0 else 1.0
    return abs(float(estimated) - float(exact)) / float(exact)


def main():
    args = parse_args()
    events = read_jsonl(args.events)
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))

    process_counter = Counter(str(ev.get("process", "")) for ev in events if ev.get("process"))
    file_counter = Counter(str(ev.get("file", "")) for ev in events if ev.get("file"))
    destination_counter = Counter(str(ev.get("dst", "")) for ev in events if ev.get("dst"))
    event_counter = Counter(str(ev.get("event", "")) for ev in events if ev.get("event"))

    exact_top_processes = top_keys(process_counter, 10)
    cms_top_processes = report_top(report, "count_min_sketch", "top_processes")

    exact_unique_pids = len(set(str(ev.get("pid", "")) for ev in events if "pid" in ev))
    exact_unique_processes = len(process_counter)
    exact_unique_files = len(file_counter)
    exact_unique_destinations = len(destination_counter)

    hll = report.get("hyperloglog", {})
    memory = report.get("memory_comparison", {})
    stats = report.get("stats", {})

    row = {
        "etiqueta": args.label or Path(args.events).stem,
        "eventos": str(stats.get("events_processed", len(events))),
        "memoria_exacta_bytes": str(memory.get("exact_estimated_bytes", 0)),
        "memoria_probabilistica_bytes": str(memory.get("probabilistic_fixed_bytes", 0)),
        "relacion_exacta_probabilistica": "{:.6f}".format(float(memory.get("exact_to_probabilistic_ratio", 0.0))),
        "top5_overlap_procesos": "{:.4f}".format(top_overlap(exact_top_processes, cms_top_processes, 5)),
        "top10_overlap_procesos": "{:.4f}".format(top_overlap(exact_top_processes, cms_top_processes, 10)),
        "spearman_procesos": "{:.4f}".format(spearman_from_lists(exact_top_processes, cms_top_processes)),
        "error_hll_pids": "{:.4f}".format(relative_error(hll.get("unique_pids_estimated", 0), exact_unique_pids)),
        "error_hll_procesos": "{:.4f}".format(relative_error(hll.get("unique_processes_estimated", 0), exact_unique_processes)),
        "error_hll_archivos": "{:.4f}".format(relative_error(hll.get("unique_files_estimated", 0), exact_unique_files)),
        "error_hll_destinos": "{:.4f}".format(relative_error(hll.get("unique_destinations_estimated", 0), exact_unique_destinations)),
        "top_procesos_exactos": "|".join(exact_top_processes[:5]),
        "top_procesos_cms": "|".join(cms_top_processes[:5]),
    }

    output = Path(args.csv)
    exists = output.exists()
    with output.open("a", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(row.keys()))
        if not exists:
            writer.writeheader()
        writer.writerow(row)

    print("Comparacion agregada:", output)


if __name__ == "__main__":
    main()
