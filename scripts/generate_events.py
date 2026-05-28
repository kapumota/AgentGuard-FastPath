#!/usr/bin/env python3
"""Generador determinístico de eventos para benchmarks de AgentGuard FastPath."""
import argparse
import csv
import json
from pathlib import Path

PROCESSES = ["python", "curl", "bash", "nginx", "postgres", "agent", "node", "backup", "java", "go-app"]
EVENTS = ["open", "read", "write", "connect", "spawn", "close"]
DOMAINS = ["api.example.com", "updates.example.org", "cdn.safe.local", "malicious.example"]


def build_event(i: int) -> dict:
    process = PROCESSES[i % len(PROCESSES)]
    event_type = EVENTS[i % len(EVENTS)]
    pid = 1000 + (i % 50000)
    row = {
        "time": f"2026-05-23T10:{(i // 60) % 60:02d}:{i % 60:02d}",
        "pid": pid,
        "process": process,
        "event": event_type,
    }

    if event_type in {"open", "read", "write", "close"}:
        if i % 997 == 0:
            row["file"] = "/etc/passwd"
        elif i % 4511 == 0:
            row["file"] = "/etc/shadow"
        elif i % 503 == 0:
            row["file"] = f"/home/user{i % 4000}/.ssh/id_rsa"
        else:
            row["file"] = f"/var/log/app/{i % 200000}/event-{i}.log"
    elif event_type == "connect":
        if i % 997 == 0:
            row["dst"] = "45.90.10.2"
            row["ip"] = "45.90.10.2"
        elif i % 499 == 0:
            row["dst"] = "malicious.example"
            row["domain"] = "malicious.example"
        else:
            row["dst"] = f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}"
            row["ip"] = row["dst"]
    else:
        row["file"] = f"/tmp/agfast-child-{i % 10000}.tmp"

    return row


def write_jsonl(path: Path, count: int) -> None:
    with path.open("w", encoding="utf-8") as f:
        for i in range(count):
            f.write(json.dumps(build_event(i), separators=(",", ":")) + "\n")


def write_csv(path: Path, count: int) -> None:
    fields = ["time", "pid", "process", "event", "file", "dst", "domain", "ip"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for i in range(count):
            row = build_event(i)
            writer.writerow({k: row.get(k, "") for k in fields})


def main() -> None:
    parser = argparse.ArgumentParser(description="Genera eventos sintéticos JSONL/CSV para AgentGuard FastPath")
    parser.add_argument("--count", type=int, required=True, help="cantidad de eventos")
    parser.add_argument("--out", required=True, help="ruta de salida")
    parser.add_argument("--format", choices=["jsonl", "csv"], default="jsonl")
    args = parser.parse_args()

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.format == "csv":
        write_csv(out, args.count)
    else:
        write_jsonl(out, args.count)


if __name__ == "__main__":
    main()
