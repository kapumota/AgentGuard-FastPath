#!/usr/bin/env python3
# Simulacion de ranking de riesgo con Count-Min Sketch.
# Los comentarios y cadenas de texto estan en español.
# Las firmas de funcion se mantienen en ingles.

import hashlib
import math
import random
from collections import defaultdict


SEED = 232
EVENTS = 120000
PROCESS_COUNT = 4096
SENSITIVE_FILES = 160
BLOCKED_DESTINATIONS = 256
NORMAL_DESTINATIONS = 12000
MALICIOUS_PROCESS_COUNT = 48
NOISY_BENIGN_PROCESS_COUNT = 96


def stable_hash(value, seed):
    data = (str(seed) + ":" + str(value)).encode("utf-8")
    digest = hashlib.blake2b(data, digest_size=8).digest()
    return int.from_bytes(digest, "little")


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


def bloom_false_positive(n, m, k):
    if m <= 0:
        return 1.0
    return (1.0 - math.exp((-k * n) / float(m))) ** k


def rank_items(scores):
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def top_overlap(exact_rank, approx_rank, k):
    exact_top = set(pid for pid, _ in exact_rank[:k])
    approx_top = set(pid for pid, _ in approx_rank[:k])
    if not exact_top:
        return 0.0
    return len(exact_top & approx_top) / float(len(exact_top))


def spearman_top_k(exact_scores, approx_scores, k):
    exact_rank = rank_items(exact_scores)[:k]
    approx_rank = rank_items(approx_scores)[:k]

    candidates = []
    seen = set()
    for pid, _ in exact_rank:
        if pid not in seen:
            candidates.append(pid)
            seen.add(pid)
    for pid, _ in approx_rank:
        if pid not in seen:
            candidates.append(pid)
            seen.add(pid)

    if len(candidates) < 2:
        return 1.0

    exact_pos = {pid: idx + 1 for idx, (pid, _) in enumerate(rank_items(exact_scores))}
    approx_pos = {pid: idx + 1 for idx, (pid, _) in enumerate(rank_items(approx_scores))}

    n = len(candidates)
    diff_sum = 0.0
    fallback = n + 1
    for pid in candidates:
        d = exact_pos.get(pid, fallback) - approx_pos.get(pid, fallback)
        diff_sum += d * d

    return 1.0 - (6.0 * diff_sum) / (n * (n * n - 1.0))


def weighted_choice(items, weights, rng):
    total = sum(weights)
    pick = rng.uniform(0.0, total)
    acc = 0.0
    for item, weight in zip(items, weights):
        acc += weight
        if pick <= acc:
            return item
    return items[-1]


def build_process_profile():
    malicious = set(range(1, MALICIOUS_PROCESS_COUNT + 1))
    noisy_start = MALICIOUS_PROCESS_COUNT + 1
    noisy_end = noisy_start + NOISY_BENIGN_PROCESS_COUNT
    noisy_benign = set(range(noisy_start, noisy_end))
    normal = set(range(1, PROCESS_COUNT + 1)) - malicious - noisy_benign
    return malicious, noisy_benign, normal


def simulate_events(scenario):
    rng = random.Random(SEED + scenario["seed_offset"])
    malicious, noisy_benign, normal = build_process_profile()

    process_ids = list(range(1, PROCESS_COUNT + 1))

    # Distribucion sesgada: algunos procesos benignos generan mucho ruido.
    weights = []
    for pid in process_ids:
        if pid in malicious:
            weights.append(7.0)
        elif pid in noisy_benign:
            weights.append(scenario["benign_noise_weight"])
        else:
            weights.append(1.0)

    exact_features = defaultdict(lambda: {
        "events": 0,
        "sensitive": 0,
        "blocked": 0,
        "unique_destinations": set(),
        "network_after_file": 0,
    })

    cms_events = CountMinSketch(scenario["depth"], scenario["width"])
    cms_sensitive = CountMinSketch(scenario["depth"], scenario["width"])
    cms_blocked = CountMinSketch(scenario["depth"], scenario["width"])
    cms_unique_proxy = CountMinSketch(scenario["depth"], scenario["width"])
    cms_network_after_file = CountMinSketch(scenario["depth"], scenario["width"])

    touched_file = set()

    for _ in range(EVENTS):
        pid = weighted_choice(process_ids, weights, rng)
        profile = exact_features[pid]
        profile["events"] += 1
        cms_events.add("events:%s" % pid)

        is_malicious = pid in malicious
        is_noisy = pid in noisy_benign

        if is_malicious:
            sensitive_probability = scenario["malicious_sensitive_probability"]
            blocked_probability = scenario["malicious_blocked_probability"]
            unique_probability = scenario["malicious_unique_probability"]
        elif is_noisy:
            sensitive_probability = scenario["noisy_sensitive_probability"]
            blocked_probability = scenario["noisy_blocked_probability"]
            unique_probability = scenario["noisy_unique_probability"]
        else:
            sensitive_probability = scenario["normal_sensitive_probability"]
            blocked_probability = scenario["normal_blocked_probability"]
            unique_probability = scenario["normal_unique_probability"]

        if rng.random() < sensitive_probability:
            file_id = rng.randrange(SENSITIVE_FILES)
            key = "file:%s:%s" % (pid, file_id)
            profile["sensitive"] += 1
            touched_file.add(pid)
            cms_sensitive.add("sensitive:%s" % pid)
            cms_unique_proxy.add(key)

        if rng.random() < blocked_probability:
            dst_id = rng.randrange(BLOCKED_DESTINATIONS)
            profile["blocked"] += 1
            profile["unique_destinations"].add("blocked:%s" % dst_id)
            cms_blocked.add("blocked:%s" % pid)
            cms_unique_proxy.add("dst:%s:%s" % (pid, dst_id))

            if pid in touched_file:
                profile["network_after_file"] += 1
                cms_network_after_file.add("naf:%s" % pid)

        if rng.random() < unique_probability:
            dst_id = rng.randrange(NORMAL_DESTINATIONS)
            profile["unique_destinations"].add("normal:%s" % dst_id)
            cms_unique_proxy.add("dst:%s:%s" % (pid, dst_id))

    exact_scores = {}
    approx_scores = {}

    for pid in process_ids:
        f = exact_features[pid]
        unique_count = len(f["unique_destinations"])

        exact_score = (
            1.0 * min(f["events"], 600)
            + 22.0 * f["sensitive"]
            + 34.0 * f["blocked"]
            + 28.0 * f["network_after_file"]
            + 4.5 * min(unique_count, 80)
        )

        approx_score = (
            1.0 * min(cms_events.estimate("events:%s" % pid), 600)
            + 22.0 * cms_sensitive.estimate("sensitive:%s" % pid)
            + 34.0 * cms_blocked.estimate("blocked:%s" % pid)
            + 28.0 * cms_network_after_file.estimate("naf:%s" % pid)
            + 4.5 * min(cms_unique_proxy.estimate("dst:%s:%s" % (pid, pid % NORMAL_DESTINATIONS)), 80)
        )

        exact_scores[pid] = exact_score
        approx_scores[pid] = approx_score

    return exact_scores, approx_scores


def run_scenario(scenario):
    exact_scores, approx_scores = simulate_events(scenario)
    exact_rank = rank_items(exact_scores)
    approx_rank = rank_items(approx_scores)

    return {
        "name": scenario["name"],
        "depth": scenario["depth"],
        "width": scenario["width"],
        "top5": top_overlap(exact_rank, approx_rank, 5),
        "top10": top_overlap(exact_rank, approx_rank, 10),
        "top25": top_overlap(exact_rank, approx_rank, 25),
        "spearman50": spearman_top_k(exact_scores, approx_scores, 50),
        "exact_top5": [pid for pid, _ in exact_rank[:5]],
        "approx_top5": [pid for pid, _ in approx_rank[:5]],
    }


def main():
    scenarios = [
        {
            "name": "d=2, w=256, ruido alto",
            "depth": 2,
            "width": 256,
            "seed_offset": 1,
            "benign_noise_weight": 28.0,
            "malicious_sensitive_probability": 0.075,
            "malicious_blocked_probability": 0.060,
            "malicious_unique_probability": 0.28,
            "noisy_sensitive_probability": 0.010,
            "noisy_blocked_probability": 0.006,
            "noisy_unique_probability": 0.45,
            "normal_sensitive_probability": 0.002,
            "normal_blocked_probability": 0.001,
            "normal_unique_probability": 0.08,
        },
        {
            "name": "d=3, w=512, ruido alto",
            "depth": 3,
            "width": 512,
            "seed_offset": 1,
            "benign_noise_weight": 28.0,
            "malicious_sensitive_probability": 0.075,
            "malicious_blocked_probability": 0.060,
            "malicious_unique_probability": 0.28,
            "noisy_sensitive_probability": 0.010,
            "noisy_blocked_probability": 0.006,
            "noisy_unique_probability": 0.45,
            "normal_sensitive_probability": 0.002,
            "normal_blocked_probability": 0.001,
            "normal_unique_probability": 0.08,
        },
        {
            "name": "d=4, w=1024, ruido alto",
            "depth": 4,
            "width": 1024,
            "seed_offset": 1,
            "benign_noise_weight": 28.0,
            "malicious_sensitive_probability": 0.075,
            "malicious_blocked_probability": 0.060,
            "malicious_unique_probability": 0.28,
            "noisy_sensitive_probability": 0.010,
            "noisy_blocked_probability": 0.006,
            "noisy_unique_probability": 0.45,
            "normal_sensitive_probability": 0.002,
            "normal_blocked_probability": 0.001,
            "normal_unique_probability": 0.08,
        },
        {
            "name": "d=2, w=256, colisiones fuertes",
            "depth": 2,
            "width": 256,
            "seed_offset": 9,
            "benign_noise_weight": 40.0,
            "malicious_sensitive_probability": 0.055,
            "malicious_blocked_probability": 0.045,
            "malicious_unique_probability": 0.24,
            "noisy_sensitive_probability": 0.014,
            "noisy_blocked_probability": 0.010,
            "noisy_unique_probability": 0.58,
            "normal_sensitive_probability": 0.003,
            "normal_blocked_probability": 0.002,
            "normal_unique_probability": 0.12,
        },
    ]

    print("### Simulacion de ranking con Count-Min Sketch")
    print("")
    print("| Escenario | Top-5 overlap | Top-10 overlap | Top-25 overlap | Spearman top-50 | Top-5 exacto | Top-5 aproximado |")
    print("|---|---:|---:|---:|---:|---|---|")

    for scenario in scenarios:
        result = run_scenario(scenario)
        print(
            "| {name} | {top5:.4f} | {top10:.4f} | {top25:.4f} | {spearman50:.4f} | {exact_top5} | {approx_top5} |".format(
                **result
            )
        )

    print("")
    print("#### Falso positivo teorico de Bloom")
    print("")
    print("| n insertados | m bits | k hashes | falso positivo |")
    print("|---:|---:|---:|---:|")
    for n in [128, 1024, 10000, 50000, 100000]:
        fp = bloom_false_positive(n, 1048576, 7)
        print("| %d | %d | %d | %.8f |" % (n, 1048576, 7, fp))

    print("")
    print("#### Interpretacion")
    print("")
    print("Un overlap perfecto en datasets pequeños no demuestra robustez.")
    print("Esta simulacion agrega ruido benigno, mayor numero de procesos y presion de colisiones.")
    print("La configuracion d=2, w=256 sirve como limite inferior agresivo.")
    print("Si el ranking se degrada, una fase posterior debe usar una configuracion mayor antes de llevar el sketch a eBPF.")


if __name__ == "__main__":
    main()
