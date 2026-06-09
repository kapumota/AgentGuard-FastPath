#!/usr/bin/env bash
set -euo pipefail

# Evaluacion experimental reproducible de AgentGuard FastPath.
# Comentarios y cadenas de texto estan en español.
# Las funciones de shell usan nombres en ingles.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

EVAL_DIR="${AGFAST_EVAL_DIR:-/tmp/agfast_fase9_evaluacion}"
EVENTS="${AGFAST_EVAL_EVENTS:-60000}"
PIDS="${AGFAST_EVAL_PIDS:-800}"

mkdir -p "$EVAL_DIR"

if [ ! -x ./bin/agfast ]; then
  echo "Compilando agfast para evaluacion"
  make
fi

echo "### Evaluacion experimental reproducible"
echo ""
echo "Directorio de resultados: $EVAL_DIR"
echo "Eventos sinteticos: $EVENTS"
echo "PIDs sinteticos: $PIDS"
echo ""

python3 - "$EVAL_DIR" "$EVENTS" "$PIDS" <<'PY'
import json
import random
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
event_count = int(sys.argv[2])
pid_count = int(sys.argv[3])
rng = random.Random(232)

out_dir.mkdir(parents=True, exist_ok=True)

events_path = out_dir / "events_eval.jsonl"
labels_path = out_dir / "labels_eval.json"
policy_path = out_dir / "policy_eval.json"
corrupt_path = out_dir / "events_corrupt_eval.jsonl"

sensitive_files = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
    "/root/.ssh/id_rsa",
]
for idx in range(32):
    sensitive_files.append("/opt/app/secret_%03d.key" % idx)

blocked_ips = ["203.0.113.%d" % idx for idx in range(1, 80)]
blocked_domains = ["malicious-%03d.example" % idx for idx in range(1, 50)]
watched_processes = ["python", "bash", "curl", "nc", "openssl"]

policy = {
    "sensitive_files": sensitive_files,
    "blocked_ips": blocked_ips,
    "blocked_domains": blocked_domains,
    "watched_processes": watched_processes,
    "risk_weights": {
        "watched_process": 10,
        "sensitive_file": 25,
        "blocked_ip": 35,
        "blocked_domain": 35,
        "network_after_file": 30,
        "high_unique_destinations": 15,
        "high_event_volume": 10,
        "high_unique_destination_threshold": 10,
        "high_event_volume_threshold": 100
    }
}

malicious = set(range(1, 31))
noisy = set(range(31, 121))
process_names = ["sshd", "cron", "postgres", "node", "worker", "systemd", "agent"]
malicious_names = ["python", "bash", "curl", "nc", "openssl"]
noisy_names = ["backupd", "crawler", "indexer", "nginx", "java"]

features = {}
for pid in range(1, pid_count + 1):
    features[pid] = {
        "events": 0,
        "sensitive": 0,
        "blocked": 0,
        "network_after_file": 0,
        "unique_destinations": set(),
        "label": 1 if pid in malicious else 0
    }

def weighted_pid():
    items = list(range(1, pid_count + 1))
    weights = []
    for pid in items:
        if pid in malicious:
            weights.append(8.0)
        elif pid in noisy:
            weights.append(22.0)
        else:
            weights.append(1.0)
    total = sum(weights)
    pick = rng.uniform(0.0, total)
    acc = 0.0
    for item, weight in zip(items, weights):
        acc += weight
        if pick <= acc:
            return item
    return items[-1]

def process_for_pid(pid):
    if pid in malicious:
        return malicious_names[pid % len(malicious_names)]
    if pid in noisy:
        return noisy_names[pid % len(noisy_names)]
    return process_names[pid % len(process_names)]

with events_path.open("w", encoding="utf-8") as out:
    for index in range(event_count):
        pid = weighted_pid()
        process = process_for_pid(pid)
        is_malicious = pid in malicious
        is_noisy = pid in noisy

        if is_malicious:
            p_open = 0.45
            p_connect = 0.43
            p_sensitive = 0.16
            p_blocked = 0.18
        elif is_noisy:
            p_open = 0.35
            p_connect = 0.52
            p_sensitive = 0.012
            p_blocked = 0.010
        else:
            p_open = 0.48
            p_connect = 0.18
            p_sensitive = 0.002
            p_blocked = 0.001

        roll = rng.random()
        if roll < p_open:
            event_type = "open"
        elif roll < p_open + p_connect:
            event_type = "connect"
        else:
            event_type = "exec"

        ev = {
            "time": "2026-06-08T%02d:%02d:%02dZ" % ((index // 3600) % 24, (index // 60) % 60, index % 60),
            "pid": pid,
            "process": process,
            "event": event_type
        }

        f = features[pid]
        f["events"] += 1

        if event_type == "open":
            if rng.random() < p_sensitive:
                ev["file"] = rng.choice(sensitive_files)
                f["sensitive"] += 1
            else:
                ev["file"] = "/var/log/app/%04d.log" % rng.randrange(5000)

        elif event_type == "connect":
            if rng.random() < p_blocked:
                if rng.random() < 0.5:
                    ev["ip"] = rng.choice(blocked_ips)
                    ev["domain"] = ""
                    ev["dst"] = ev["ip"]
                else:
                    ev["domain"] = rng.choice(blocked_domains)
                    ev["ip"] = "198.51.100.%d" % rng.randrange(1, 240)
                    ev["dst"] = ev["domain"]
                f["blocked"] += 1
            else:
                ev["domain"] = "cdn-%04d.service.local" % rng.randrange(9000)
                ev["ip"] = "10.%d.%d.%d" % (rng.randrange(1, 240), rng.randrange(1, 240), rng.randrange(1, 240))
                ev["dst"] = ev["domain"]

            f["unique_destinations"].add(ev.get("dst", ev.get("ip", "")))

            if f["sensitive"] > 0:
                f["network_after_file"] += 1

        out.write(json.dumps(ev, sort_keys=True) + "\n")

with corrupt_path.open("w", encoding="utf-8") as out:
    with events_path.open("r", encoding="utf-8") as src:
        for idx, line in enumerate(src):
            if idx % 5000 == 0:
                out.write("linea corrupta para evaluar robustez\n")
            out.write(line)

labels = {}
for pid, f in features.items():
    score = 0
    if f["sensitive"] > 0:
        score += 25
    if f["blocked"] > 0:
        score += 35
    if f["network_after_file"] > 0:
        score += 30
    if len(f["unique_destinations"]) >= 10:
        score += 15
    if f["events"] >= 100:
        score += 10
    labels[str(pid)] = {
        "label": f["label"],
        "exact_score": min(score, 100),
        "events": f["events"],
        "sensitive": f["sensitive"],
        "blocked": f["blocked"],
        "network_after_file": f["network_after_file"],
        "unique_destinations": len(f["unique_destinations"])
    }

with policy_path.open("w", encoding="utf-8") as out:
    json.dump(policy, out, indent=2, sort_keys=True)

with labels_path.open("w", encoding="utf-8") as out:
    json.dump(labels, out, indent=2, sort_keys=True)

print(events_path)
print(policy_path)
print(labels_path)
print(corrupt_path)
PY

EVENTS_FILE="$EVAL_DIR/events_eval.jsonl"
POLICY_FILE="$EVAL_DIR/policy_eval.json"
LABELS_FILE="$EVAL_DIR/labels_eval.json"
CORRUPT_FILE="$EVAL_DIR/events_corrupt_eval.jsonl"

REPORT_JSON="$EVAL_DIR/agfast_report.json"
REPORT_HTML="$EVAL_DIR/agfast_report.html"
ALERTS_CSV="$EVAL_DIR/agfast_alerts.csv"
TAIL_OUT="$EVAL_DIR/tail_corrupt.out"
GUARDSKETCH_OUT="$EVAL_DIR/guardsketch.out"
SKETCH_SIM_OUT="$EVAL_DIR/sketch_rank_simulation.md"
REALISTIC_OUT="$EVAL_DIR/agfast_realistic_sketch_eval.md"
SUMMARY_MD="$EVAL_DIR/evaluation_summary.md"
SUMMARY_JSON="$EVAL_DIR/evaluation_summary.json"

run_timed() {
  local label="$1"
  shift
  local out_file="$EVAL_DIR/time_${label}.txt"
  /usr/bin/time -f "%e %M" -o "$out_file" "$@"
}

echo "Ejecutando agfast sobre dataset de evaluacion"
run_timed agfast ./bin/agfast analyze "$EVENTS_FILE" \
  --policy "$POLICY_FILE" \
  --risk \
  --report "$REPORT_JSON" \
  --html "$REPORT_HTML" \
  --alerts-csv "$ALERTS_CSV"

echo "Evaluando robustez con entradas corruptas usando tail"
run_timed corrupt_tail ./bin/agfast tail "$CORRUPT_FILE" --policy "$POLICY_FILE" > "$TAIL_OUT"

echo "Ejecutando simulacion de ranking de sketches"
python3 experiments/sketch_rank_simulation.py > "$SKETCH_SIM_OUT"

echo "Ejecutando evaluacion realista de sketches"
AGFAST_REALISTIC_DIR="$EVAL_DIR/realistic" python3 experiments/agfast_realistic_sketch_eval.py > "$REALISTIC_OUT"

echo "Ejecutando GuardSketch userspace"
if make test-guardsketch > "$GUARDSKETCH_OUT" 2>&1; then
  GUARDSKETCH_STATUS="ok"
else
  GUARDSKETCH_STATUS="fallo"
fi

python3 - "$EVAL_DIR" "$LABELS_FILE" "$ALERTS_CSV" "$REPORT_JSON" "$TAIL_OUT" "$GUARDSKETCH_STATUS" <<'PY'
import csv
import json
import os
import sys
from pathlib import Path

out_dir = Path(sys.argv[1])
labels_path = Path(sys.argv[2])
alerts_path = Path(sys.argv[3])
report_path = Path(sys.argv[4])
tail_path = Path(sys.argv[5])
guardsketch_status = sys.argv[6]

labels = json.loads(labels_path.read_text(encoding="utf-8"))

exact_rank = sorted(
    ((int(pid), data["exact_score"]) for pid, data in labels.items()),
    key=lambda item: (-item[1], item[0])
)

malicious = {int(pid) for pid, data in labels.items() if data["label"] == 1}
exact_top10 = {pid for pid, _score in exact_rank[:10]}
exact_top25 = {pid for pid, _score in exact_rank[:25]}

alert_pids = set()
if alerts_path.exists():
    with alerts_path.open("r", encoding="utf-8", errors="ignore") as fh:
        sample = fh.read(4096)
        fh.seek(0)
        if "," in sample:
            reader = csv.DictReader(fh)
            for row in reader:
                for key in ["pid", "PID", "process_pid"]:
                    if key in row and str(row[key]).strip().isdigit():
                        alert_pids.add(int(row[key]))
        else:
            for line in fh:
                for token in line.replace(",", " ").split():
                    if token.isdigit():
                        alert_pids.add(int(token))

tp = len(alert_pids & malicious)
fp = len(alert_pids - malicious)
fn = len(malicious - alert_pids)

precision = tp / float(tp + fp) if tp + fp > 0 else 0.0
recall = tp / float(tp + fn) if tp + fn > 0 else 0.0
top10_overlap = len(exact_top10 & alert_pids) / float(len(exact_top10)) if exact_top10 else 0.0
top25_overlap = len(exact_top25 & alert_pids) / float(len(exact_top25)) if exact_top25 else 0.0

def read_time(label):
    p = out_dir / ("time_%s.txt" % label)
    if not p.exists():
        return {"seconds": None, "max_rss_kb": None}
    raw = p.read_text(encoding="utf-8").strip().split()
    if len(raw) >= 2:
        return {"seconds": float(raw[0]), "max_rss_kb": int(raw[1])}
    return {"seconds": None, "max_rss_kb": None}

report_size = report_path.stat().st_size if report_path.exists() else 0
alerts_size = alerts_path.stat().st_size if alerts_path.exists() else 0
tail_text = tail_path.read_text(encoding="utf-8", errors="ignore") if tail_path.exists() else ""
robust_tail = "Eventos procesados en tail" in tail_text

summary = {
    "agfast": read_time("agfast"),
    "corrupt_tail": read_time("corrupt_tail"),
    "precision_alerts_vs_labels": precision,
    "recall_alerts_vs_labels": recall,
    "true_positives": tp,
    "false_positives": fp,
    "false_negatives": fn,
    "alert_pids": sorted(alert_pids)[:25],
    "exact_top10": sorted(exact_top10),
    "top10_overlap_alerts_vs_exact": top10_overlap,
    "top25_overlap_alerts_vs_exact": top25_overlap,
    "report_size_bytes": report_size,
    "alerts_size_bytes": alerts_size,
    "robust_tail_with_corrupt_lines": robust_tail,
    "guardsketch_status": guardsketch_status
}

(out_dir / "evaluation_summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True),
    encoding="utf-8"
)

md = []
md.append("### Resumen de evaluación experimental")
md.append("")
md.append("#### Rendimiento")
md.append("")
md.append("| Componente | Tiempo segundos | Memoria RSS KB |")
md.append("|---|---:|---:|")
md.append("| agfast analyze | {seconds} | {rss} |".format(
    seconds=summary["agfast"]["seconds"],
    rss=summary["agfast"]["max_rss_kb"],
))
md.append("| tail con entradas corruptas | {seconds} | {rss} |".format(
    seconds=summary["corrupt_tail"]["seconds"],
    rss=summary["corrupt_tail"]["max_rss_kb"],
))
md.append("")
md.append("#### Calidad de detección")
md.append("")
md.append("| Métrica | Valor |")
md.append("|---|---:|")
md.append("| precision alertas vs labels | %.4f |" % precision)
md.append("| recall alertas vs labels | %.4f |" % recall)
md.append("| true positives | %d |" % tp)
md.append("| false positives | %d |" % fp)
md.append("| false negatives | %d |" % fn)
md.append("| top-10 overlap alertas vs exacto | %.4f |" % top10_overlap)
md.append("| top-25 overlap alertas vs exacto | %.4f |" % top25_overlap)
md.append("")
md.append("#### Tamaño de reportes")
md.append("")
md.append("| Archivo | Bytes |")
md.append("|---|---:|")
md.append("| reporte JSON | %d |" % report_size)
md.append("| alertas CSV | %d |" % alerts_size)
md.append("")
md.append("#### Robustez")
md.append("")
md.append("| Prueba | Resultado |")
md.append("|---|---|")
md.append("| tail con líneas corruptas | %s |" % ("ok" if robust_tail else "fallo"))
md.append("| GuardSketch userspace | %s |" % guardsketch_status)
md.append("")
md.append("#### Archivos generados")
md.append("")
md.append("```text")
for item in sorted(out_dir.iterdir()):
    md.append(str(item))
md.append("```")

(out_dir / "evaluation_summary.md").write_text("\n".join(md) + "\n", encoding="utf-8")
print(out_dir / "evaluation_summary.md")
PY

echo ""
cat "$SUMMARY_MD"
echo ""
echo "Resultados completos en: $EVAL_DIR"
echo "Resumen JSON: $SUMMARY_JSON"
