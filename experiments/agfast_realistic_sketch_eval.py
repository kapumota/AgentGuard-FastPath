#!/usr/bin/env python3
# Evaluacion realista de sketches orientada a AgentGuard FastPath.
# Los comentarios y cadenas de texto estan en español.
# Las firmas de funcion se mantienen en ingles.

import hashlib
import json
import math
import os
import random
import subprocess
import time
from collections import defaultdict
from pathlib import Path


SEED = int(os.environ.get("AGFAST_REALISTIC_SEED", "232"))
EVENT_COUNT = int(os.environ.get("AGFAST_REALISTIC_EVENTS", "80000"))
PROCESS_COUNT = int(os.environ.get("AGFAST_REALISTIC_PIDS", "900"))
OUTPUT_DIR = Path(os.environ.get("AGFAST_REALISTIC_DIR", "/tmp/agfast_realistic_eval"))

BLOOM_BITS = 1048576
BLOOM_HASHES = 7

RISK_WEIGHTS = {
    "watched_process": 10,
    "sensitive_file": 25,
    "blocked_ip": 35,
    "blocked_domain": 35,
    "network_after_file": 30,
    "high_unique_destinations": 15,
    "high_event_volume": 10,
    "high_unique_destination_threshold": 10,
    "high_event_volume_threshold": 100,
}


def stable_hash(value, seed=0):
    data = (str(seed) + ":" + str(value)).encode("utf-8")
    digest = hashlib.blake2b(data, digest_size=8).digest()
    return int.from_bytes(digest, "little")


def format_probability(value):
    if value == 0.0:
        return "0"
    return "%.3e" % value


def bloom_false_positive(n, m=BLOOM_BITS, k=BLOOM_HASHES):
    if m <= 0:
        return 1.0
    return (1.0 - math.exp((-k * n) / float(m))) ** k


class CountMinSketch:
    def __init__(self, depth, width):
        self.depth = depth
        self.width = width
        self.table = [[0 for _ in range(width)] for _ in range(depth)]

    def add(self, key, amount=1):
        for row in range(self.depth):
            pos = stable_hash(key, row) % self.width
            self.table[row][pos] += amount

    def estimate(self, key):
        values = []
        for row in range(self.depth):
            pos = stable_hash(key, row) % self.width
            values.append(self.table[row][pos])
        return min(values)


class HyperLogLog:
    def __init__(self, precision):
        self.precision = precision
        self.m = 1 << precision
        self.registers = [0 for _ in range(self.m)]

    def add(self, value):
        h = stable_hash(value, 911)
        idx = h & (self.m - 1)
        w = h >> self.precision
        rank = leading_zero_rank(w, 64 - self.precision)
        if rank > self.registers[idx]:
            self.registers[idx] = rank

    def estimate(self):
        m = float(self.m)
        alpha = alpha_for_m(self.m)
        inv_sum = 0.0
        zeros = 0

        for register in self.registers:
            inv_sum += 2.0 ** (-register)
            if register == 0:
                zeros += 1

        estimate = alpha * m * m / inv_sum

        if estimate <= 2.5 * m and zeros > 0:
            estimate = m * math.log(m / float(zeros))

        return estimate


def leading_zero_rank(value, bits):
    if value == 0:
        return bits + 1

    rank = 1
    mask = 1 << (bits - 1)
    while mask > 0 and (value & mask) == 0:
        rank += 1
        mask >>= 1

    return rank


def alpha_for_m(m):
    if m == 16:
        return 0.673
    if m == 32:
        return 0.697
    if m == 64:
        return 0.709
    return 0.7213 / (1.0 + 1.079 / float(m))


def risk_level(score):
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def compute_score(features):
    score = 0

    if features["watched"]:
        score += RISK_WEIGHTS["watched_process"]

    if features["sensitive"] > 0:
        score += RISK_WEIGHTS["sensitive_file"]

    if features["blocked_ip"] > 0:
        score += RISK_WEIGHTS["blocked_ip"]

    if features["blocked_domain"] > 0:
        score += RISK_WEIGHTS["blocked_domain"]

    if features["network_after_file"] > 0:
        score += RISK_WEIGHTS["network_after_file"]

    if features["unique_destinations"] >= RISK_WEIGHTS["high_unique_destination_threshold"]:
        score += RISK_WEIGHTS["high_unique_destinations"]

    if features["events"] >= RISK_WEIGHTS["high_event_volume_threshold"]:
        score += RISK_WEIGHTS["high_event_volume"]

    if score > 100:
        score = 100

    return score


def rank_items(scores):
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def top_overlap(exact_rank, approx_rank, k):
    exact_top = set(pid for pid, _ in exact_rank[:k])
    approx_top = set(pid for pid, _ in approx_rank[:k])
    if not exact_top:
        return 0.0
    return len(exact_top & approx_top) / float(len(exact_top))


def pearson(values_a, values_b):
    if len(values_a) != len(values_b) or len(values_a) < 2:
        return 1.0

    mean_a = sum(values_a) / float(len(values_a))
    mean_b = sum(values_b) / float(len(values_b))

    numerator = 0.0
    den_a = 0.0
    den_b = 0.0

    for a, b in zip(values_a, values_b):
        da = a - mean_a
        db = b - mean_b
        numerator += da * db
        den_a += da * da
        den_b += db * db

    if den_a == 0.0 or den_b == 0.0:
        return 1.0

    value = numerator / math.sqrt(den_a * den_b)
    return max(-1.0, min(1.0, value))


def rank_correlation_top_k(exact_scores, approx_scores, k):
    exact_full = rank_items(exact_scores)
    approx_full = rank_items(approx_scores)

    candidate_set = set(pid for pid, _ in exact_full[:k])
    candidate_set.update(pid for pid, _ in approx_full[:k])

    exact_pos = {pid: idx + 1 for idx, (pid, _) in enumerate(exact_full)}
    approx_pos = {pid: idx + 1 for idx, (pid, _) in enumerate(approx_full)}

    exact_values = []
    approx_values = []

    fallback = len(exact_full) + 1
    for pid in sorted(candidate_set):
        exact_values.append(float(exact_pos.get(pid, fallback)))
        approx_values.append(float(approx_pos.get(pid, fallback)))

    return pearson(exact_values, approx_values)


def make_policy():
    sensitive_files = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/ssh/sshd_config",
        "/root/.ssh/id_rsa",
        "/var/lib/agentguard/secrets.db",
    ]

    for idx in range(45):
        sensitive_files.append("/opt/app/secret_%03d.key" % idx)

    blocked_ips = []
    for idx in range(80):
        blocked_ips.append("203.0.113.%d" % (idx + 1))

    blocked_domains = []
    for idx in range(60):
        blocked_domains.append("malicious-%03d.example" % idx)

    watched_processes = [
        "python",
        "bash",
        "curl",
        "nc",
        "nmap",
        "openssl",
        "scp",
    ]

    return {
        "sensitive_files": sensitive_files,
        "blocked_ips": blocked_ips,
        "blocked_domains": blocked_domains,
        "watched_processes": watched_processes,
        "risk_weights": dict(RISK_WEIGHTS),
    }


def weighted_choice(items, weights, rng):
    total = sum(weights)
    pick = rng.uniform(0.0, total)
    acc = 0.0

    for item, weight in zip(items, weights):
        acc += weight
        if pick <= acc:
            return item

    return items[-1]


def process_name_for_pid(pid, malicious, noisy):
    if pid in malicious:
        names = ["python", "bash", "curl", "nc", "openssl"]
        return names[pid % len(names)]

    if pid in noisy:
        names = ["backupd", "crawler", "indexer", "nginx", "java"]
        return names[pid % len(names)]

    names = ["sshd", "cron", "postgres", "node", "worker", "systemd", "agent"]
    return names[pid % len(names)]


def generate_dataset(policy):
    rng = random.Random(SEED)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    events_path = OUTPUT_DIR / "events_realistic.jsonl"
    policy_path = OUTPUT_DIR / "policy_realistic.json"

    malicious = set(range(1, 31))
    noisy = set(range(31, 111))
    process_ids = list(range(1, PROCESS_COUNT + 1))

    weights = []
    for pid in process_ids:
        if pid in malicious:
            weights.append(8.0)
        elif pid in noisy:
            weights.append(24.0)
        else:
            weights.append(1.0)

    exact = defaultdict(lambda: {
        "events": 0,
        "watched": False,
        "sensitive": 0,
        "blocked_ip": 0,
        "blocked_domain": 0,
        "network_after_file": 0,
        "unique_destinations_set": set(),
        "unique_destinations": 0,
    })

    counters = {
        "open": 0,
        "connect": 0,
        "exec": 0,
        "sensitive": 0,
        "blocked_ip": 0,
        "blocked_domain": 0,
        "network_after_file": 0,
        "file_lookups": 0,
        "destination_lookups": 0,
    }

    touched_sensitive = set()
    observed_files = set()
    observed_destinations = set()

    with events_path.open("w", encoding="utf-8") as out:
        for index in range(EVENT_COUNT):
            pid = weighted_choice(process_ids, weights, rng)
            process = process_name_for_pid(pid, malicious, noisy)

            is_malicious = pid in malicious
            is_noisy = pid in noisy

            if is_malicious:
                p_open = 0.46
                p_connect = 0.42
                p_sensitive = 0.15
                p_blocked_ip = 0.12
                p_blocked_domain = 0.09
            elif is_noisy:
                p_open = 0.34
                p_connect = 0.55
                p_sensitive = 0.015
                p_blocked_ip = 0.008
                p_blocked_domain = 0.006
            else:
                p_open = 0.45
                p_connect = 0.18
                p_sensitive = 0.003
                p_blocked_ip = 0.001
                p_blocked_domain = 0.001

            r = rng.random()
            if r < p_open:
                event = "open"
            elif r < p_open + p_connect:
                event = "connect"
            else:
                event = "exec"

            ev = {
                "time": "2026-06-08T%02d:%02d:%02dZ" % (
                    (index // 3600) % 24,
                    (index // 60) % 60,
                    index % 60,
                ),
                "pid": pid,
                "process": process,
                "event": event,
            }

            features = exact[pid]
            features["events"] += 1
            features["watched"] = process in policy["watched_processes"]

            if event == "open":
                counters["open"] += 1
                counters["file_lookups"] += 1

                if rng.random() < p_sensitive:
                    file_value = rng.choice(policy["sensitive_files"])
                    features["sensitive"] += 1
                    touched_sensitive.add(pid)
                    counters["sensitive"] += 1
                else:
                    file_value = "/var/log/app/%04d.log" % rng.randrange(5000)

                observed_files.add(file_value)
                ev["file"] = file_value

            elif event == "connect":
                counters["connect"] += 1
                counters["destination_lookups"] += 1

                blocked_roll = rng.random()
                if blocked_roll < p_blocked_ip:
                    ip = rng.choice(policy["blocked_ips"])
                    domain = ""
                    features["blocked_ip"] += 1
                    counters["blocked_ip"] += 1
                    destination = ip
                elif blocked_roll < p_blocked_ip + p_blocked_domain:
                    domain = rng.choice(policy["blocked_domains"])
                    ip = "198.51.100.%d" % rng.randrange(1, 240)
                    features["blocked_domain"] += 1
                    counters["blocked_domain"] += 1
                    destination = domain
                else:
                    domain = "cdn-%04d.service.local" % rng.randrange(9000)
                    ip = "10.%d.%d.%d" % (
                        rng.randrange(1, 250),
                        rng.randrange(1, 250),
                        rng.randrange(1, 250),
                    )
                    destination = domain

                if pid in touched_sensitive:
                    features["network_after_file"] += 1
                    counters["network_after_file"] += 1

                features["unique_destinations_set"].add(destination)
                observed_destinations.add(destination)

                ev["ip"] = ip
                ev["domain"] = domain
                ev["dst"] = destination

            else:
                counters["exec"] += 1

            out.write(json.dumps(ev, sort_keys=True) + "\n")

    for pid, features in exact.items():
        features["unique_destinations"] = len(features["unique_destinations_set"])

    with policy_path.open("w", encoding="utf-8") as out:
        json.dump(policy, out, indent=2, sort_keys=True)

    metadata = {
        "events_path": str(events_path),
        "policy_path": str(policy_path),
        "malicious": malicious,
        "noisy": noisy,
        "observed_files": observed_files,
        "observed_destinations": observed_destinations,
        "counters": counters,
    }

    return exact, metadata


def build_exact_scores(exact):
    scores = {}
    levels = {}

    for pid, features in exact.items():
        score = compute_score(features)
        scores[pid] = score
        levels[pid] = risk_level(score)

    return scores, levels


def build_approx_scores(exact, metadata, depth, width, hll_precision):
    cms_events = CountMinSketch(depth, width)
    cms_sensitive = CountMinSketch(depth, width)
    cms_blocked_ip = CountMinSketch(depth, width)
    cms_blocked_domain = CountMinSketch(depth, width)
    cms_network_after_file = CountMinSketch(depth, width)
    hll_by_pid = {}

    for pid, features in exact.items():
        for _ in range(features["events"]):
            cms_events.add("events:%s" % pid)

        for _ in range(features["sensitive"]):
            cms_sensitive.add("sensitive:%s" % pid)

        for _ in range(features["blocked_ip"]):
            cms_blocked_ip.add("blocked_ip:%s" % pid)

        for _ in range(features["blocked_domain"]):
            cms_blocked_domain.add("blocked_domain:%s" % pid)

        for _ in range(features["network_after_file"]):
            cms_network_after_file.add("network_after_file:%s" % pid)

        hll = HyperLogLog(hll_precision)
        for destination in features["unique_destinations_set"]:
            hll.add(destination)
        hll_by_pid[pid] = hll

    scores = {}
    levels = {}
    hll_errors = []

    for pid, features in exact.items():
        estimated_unique = int(round(hll_by_pid[pid].estimate()))
        exact_unique = features["unique_destinations"]

        if exact_unique > 0:
            hll_errors.append(abs(estimated_unique - exact_unique) / float(exact_unique))

        approx_features = {
            "events": cms_events.estimate("events:%s" % pid),
            "watched": features["watched"],
            "sensitive": cms_sensitive.estimate("sensitive:%s" % pid),
            "blocked_ip": cms_blocked_ip.estimate("blocked_ip:%s" % pid),
            "blocked_domain": cms_blocked_domain.estimate("blocked_domain:%s" % pid),
            "network_after_file": cms_network_after_file.estimate("network_after_file:%s" % pid),
            "unique_destinations": estimated_unique,
        }

        score = compute_score(approx_features)
        scores[pid] = score
        levels[pid] = risk_level(score)

    hll_errors.sort()
    if hll_errors:
        avg_hll = sum(hll_errors) / float(len(hll_errors))
        p95_hll = hll_errors[int(0.95 * (len(hll_errors) - 1))]
    else:
        avg_hll = 0.0
        p95_hll = 0.0

    return scores, levels, avg_hll, p95_hll


def count_level_changes(exact_levels, approx_levels):
    changes = 0
    for pid, level in exact_levels.items():
        if approx_levels.get(pid, "none") != level:
            changes += 1
    return changes


def print_dataset_profile(policy, metadata, exact):
    active_pids = len(exact)
    policy_items = (
        len(policy["sensitive_files"])
        + len(policy["blocked_ips"])
        + len(policy["blocked_domains"])
        + len(policy["watched_processes"])
    )

    print("### Perfil del dataset realista")
    print("")
    print("| Metrica | Valor |")
    print("|---|---:|")
    print("| Eventos generados | %d |" % EVENT_COUNT)
    print("| PIDs configurados | %d |" % PROCESS_COUNT)
    print("| PIDs activos | %d |" % active_pids)
    print("| Elementos de policy | %d |" % policy_items)
    print("| Archivos observados | %d |" % len(metadata["observed_files"]))
    print("| Destinos observados | %d |" % len(metadata["observed_destinations"]))
    print("| Eventos open | %d |" % metadata["counters"]["open"])
    print("| Eventos connect | %d |" % metadata["counters"]["connect"])
    print("| Eventos exec | %d |" % metadata["counters"]["exec"])
    print("| Accesos sensibles | %d |" % metadata["counters"]["sensitive"])
    print("| Contactos a IP bloqueada | %d |" % metadata["counters"]["blocked_ip"])
    print("| Contactos a dominio bloqueado | %d |" % metadata["counters"]["blocked_domain"])
    print("| Red despues de archivo sensible | %d |" % metadata["counters"]["network_after_file"])
    print("")


def print_bloom_profile(policy, metadata):
    print("### Bloom Filter orientado a AgentGuard FastPath")
    print("")
    print("| Conjunto medido | n insertados | consultas estimadas | falso positivo | falsos esperados |")
    print("|---|---:|---:|---:|---:|")

    scenarios = [
        (
            "Policy completa",
            len(policy["sensitive_files"]) + len(policy["blocked_ips"]) + len(policy["blocked_domains"]) + len(policy["watched_processes"]),
            metadata["counters"]["file_lookups"] + metadata["counters"]["destination_lookups"],
        ),
        (
            "Archivos sensibles",
            len(policy["sensitive_files"]),
            metadata["counters"]["file_lookups"],
        ),
        (
            "Destinos bloqueados",
            len(policy["blocked_ips"]) + len(policy["blocked_domains"]),
            metadata["counters"]["destination_lookups"],
        ),
        (
            "Archivos observados en ventana",
            len(metadata["observed_files"]),
            metadata["counters"]["file_lookups"],
        ),
        (
            "Destinos observados en ventana",
            len(metadata["observed_destinations"]),
            metadata["counters"]["destination_lookups"],
        ),
    ]

    for name, n, lookups in scenarios:
        fp = bloom_false_positive(n)
        expected = fp * float(lookups)
        print("| %s | %d | %d | %s | %.4f |" % (
            name,
            n,
            lookups,
            format_probability(fp),
            expected,
        ))

    print("")


def run_agfast(metadata):
    agfast = Path("./bin/agfast")
    if not agfast.exists():
        return None

    report = OUTPUT_DIR / "agfast_report.json"
    html = OUTPUT_DIR / "agfast_report.html"
    alerts = OUTPUT_DIR / "agfast_alerts.csv"

    cmd = [
        str(agfast),
        "analyze",
        metadata["events_path"],
        "--policy",
        metadata["policy_path"],
        "--risk",
        "--report",
        str(report),
        "--html",
        str(html),
        "--alerts-csv",
        str(alerts),
    ]

    start = time.perf_counter()
    completed = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    elapsed = time.perf_counter() - start

    return {
        "returncode": completed.returncode,
        "seconds": elapsed,
        "report": str(report),
        "html": str(html),
        "alerts": str(alerts),
    }


def main():
    policy = make_policy()
    exact, metadata = generate_dataset(policy)

    exact_scores, exact_levels = build_exact_scores(exact)
    exact_rank = rank_items(exact_scores)

    print_dataset_profile(policy, metadata, exact)

    print("### Ranking exacto de riesgo")
    print("")
    print("| Posicion | PID | Score exacto | Nivel |")
    print("|---:|---:|---:|---|")
    for index, (pid, score) in enumerate(exact_rank[:10], start=1):
        print("| %d | %d | %d | %s |" % (index, pid, score, exact_levels[pid]))
    print("")

    print("### Comparacion exacta vs aproximada")
    print("")
    print("| Configuracion | Top-5 overlap | Top-10 overlap | Top-25 overlap | Correlacion top-50 | Cambios de nivel | Error HLL promedio | Error HLL p95 |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|")

    configs = [
        ("CMS d=2,w=256 + HLL p=10", 2, 256, 10),
        ("CMS d=3,w=512 + HLL p=12", 3, 512, 12),
        ("CMS d=5,w=4096 + HLL p=14, cercano al proyecto", 5, 4096, 14),
    ]

    for name, depth, width, precision in configs:
        approx_scores, approx_levels, avg_hll, p95_hll = build_approx_scores(
            exact,
            metadata,
            depth,
            width,
            precision,
        )
        approx_rank = rank_items(approx_scores)
        changes = count_level_changes(exact_levels, approx_levels)
        print("| %s | %.4f | %.4f | %.4f | %.4f | %d | %.4f | %.4f |" % (
            name,
            top_overlap(exact_rank, approx_rank, 5),
            top_overlap(exact_rank, approx_rank, 10),
            top_overlap(exact_rank, approx_rank, 25),
            rank_correlation_top_k(exact_scores, approx_scores, 50),
            changes,
            avg_hll,
            p95_hll,
        ))

    print("")
    print_bloom_profile(policy, metadata)

    agfast_result = run_agfast(metadata)
    print("### Ejecucion real de agfast")
    print("")
    if agfast_result is None:
        print("No se encontro `./bin/agfast`. Ejecuta `make` antes de correr esta evaluacion completa.")
    else:
        print("| Metrica | Valor |")
        print("|---|---:|")
        print("| Codigo de salida | %d |" % agfast_result["returncode"])
        print("| Tiempo de ejecucion de agfast | %.4f segundos |" % agfast_result["seconds"])
        print("")
        print("Reportes generados:")
        print("")
        print("```text")
        print(agfast_result["report"])
        print(agfast_result["html"])
        print(agfast_result["alerts"])
        print("```")

    print("")
    print("### Interpretacion")
    print("")
    print("Esta evaluacion esta mas cerca del comportamiento real del proyecto porque usa eventos JSONL, policy JSON, pesos de riesgo y ejecucion opcional de `agfast`.")
    print("La comparacion principal no es solo error matematico, sino preservacion del top-k de PIDs riesgosos y cambios de nivel de riesgo.")
    print("La tabla de Bloom se interpreta con consultas reales del dataset generado, no solo con una probabilidad abstracta.")


if __name__ == "__main__":
    main()
