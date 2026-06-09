/*
 * GuardSketch MVP en userspace.
 *
 * Esta unidad implementa un prototipo pequeño para validar la idea antes de
 * llevarla a eBPF. No se integra todavia al CLI principal.
 *
 * Comentarios y cadenas de texto estan en español.
 * Las firmas de funcion se mantienen en ingles.
 */

#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GS_MAX_PIDS 128u
#define GS_BLOOM_BITS 2048u
#define GS_BLOOM_BYTES (GS_BLOOM_BITS / 8u)
#define GS_BLOOM_HASHES 4u
#define GS_CMS_DEPTH 3u
#define GS_CMS_WIDTH 256u
#define GS_DEFAULT_WINDOW 64u

typedef enum {
    GS_SIGNAL_EVENT = 0,
    GS_SIGNAL_SENSITIVE_FILE = 1,
    GS_SIGNAL_BLOCKED_DESTINATION = 2,
    GS_SIGNAL_NETWORK_AFTER_FILE = 3
} guard_sketch_signal_t;

typedef struct {
    int pid;
    bool used;
    uint64_t exact_events;
    uint64_t exact_sensitive;
    uint64_t exact_blocked;
    uint64_t exact_network_after_file;
    uint32_t cms[GS_CMS_DEPTH][GS_CMS_WIDTH];
} guard_sketch_slot_t;

typedef struct {
    guard_sketch_slot_t slots[GS_MAX_PIDS];
    uint8_t pid_bloom[GS_BLOOM_BYTES];
    uint64_t window_limit;
    uint64_t window_events;
    uint64_t dropped_events;
} guard_sketch_t;

static uint64_t guardSketchHash64(uint64_t value, uint64_t seed) {
    uint64_t x = value + seed + 0x9e3779b97f4a7c15ULL;
    x ^= x >> 30;
    x *= 0xbf58476d1ce4e5b9ULL;
    x ^= x >> 27;
    x *= 0x94d049bb133111ebULL;
    x ^= x >> 31;
    return x;
}

static void guardSketchBloomSet(uint8_t *bits, uint64_t value) {
    for (uint64_t i = 0; i < GS_BLOOM_HASHES; ++i) {
        uint64_t h = guardSketchHash64(value, i);
        uint64_t pos = h % GS_BLOOM_BITS;
        bits[pos / 8u] = (uint8_t)(bits[pos / 8u] | (uint8_t)(1u << (pos % 8u)));
    }
}

static bool guardSketchBloomMaybeContains(const uint8_t *bits, uint64_t value) {
    for (uint64_t i = 0; i < GS_BLOOM_HASHES; ++i) {
        uint64_t h = guardSketchHash64(value, i);
        uint64_t pos = h % GS_BLOOM_BITS;
        if ((bits[pos / 8u] & (uint8_t)(1u << (pos % 8u))) == 0u) {
            return false;
        }
    }
    return true;
}

static uint64_t guardSketchSignalKey(int pid, guard_sketch_signal_t signal) {
    return ((uint64_t)(uint32_t)pid << 16) ^ (uint64_t)signal;
}

static void guardSketchCmsAdd(guard_sketch_slot_t *slot, guard_sketch_signal_t signal) {
    uint64_t key = guardSketchSignalKey(slot->pid, signal);

    for (uint64_t row = 0; row < GS_CMS_DEPTH; ++row) {
        uint64_t h = guardSketchHash64(key, row + 17u);
        uint64_t pos = h % GS_CMS_WIDTH;
        if (slot->cms[row][pos] != UINT32_MAX) {
            slot->cms[row][pos] += 1u;
        }
    }
}

static uint32_t guardSketchCmsEstimate(const guard_sketch_slot_t *slot, guard_sketch_signal_t signal) {
    uint64_t key = guardSketchSignalKey(slot->pid, signal);
    uint32_t best = UINT32_MAX;

    for (uint64_t row = 0; row < GS_CMS_DEPTH; ++row) {
        uint64_t h = guardSketchHash64(key, row + 17u);
        uint64_t pos = h % GS_CMS_WIDTH;
        if (slot->cms[row][pos] < best) {
            best = slot->cms[row][pos];
        }
    }

    return best == UINT32_MAX ? 0u : best;
}

static guard_sketch_slot_t *guardSketchFindSlot(guard_sketch_t *sketch, int pid) {
    guard_sketch_slot_t *free_slot = NULL;

    for (uint64_t i = 0; i < GS_MAX_PIDS; ++i) {
        if (sketch->slots[i].used && sketch->slots[i].pid == pid) {
            return &sketch->slots[i];
        }

        if (!sketch->slots[i].used && free_slot == NULL) {
            free_slot = &sketch->slots[i];
        }
    }

    if (free_slot == NULL) {
        sketch->dropped_events += 1u;
        return NULL;
    }

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->pid = pid;
    free_slot->used = true;
    guardSketchBloomSet(sketch->pid_bloom, (uint64_t)(uint32_t)pid);
    return free_slot;
}

static void guardSketchInit(guard_sketch_t *sketch, uint64_t window_limit) {
    memset(sketch, 0, sizeof(*sketch));
    sketch->window_limit = window_limit == 0u ? GS_DEFAULT_WINDOW : window_limit;
}

static bool guardSketchRecord(guard_sketch_t *sketch, int pid, guard_sketch_signal_t signal) {
    guard_sketch_slot_t *slot = NULL;

    if (sketch->window_events >= sketch->window_limit) {
        sketch->dropped_events += 1u;
        return false;
    }

    slot = guardSketchFindSlot(sketch, pid);
    if (slot == NULL) {
        return false;
    }

    sketch->window_events += 1u;
    slot->exact_events += 1u;
    guardSketchCmsAdd(slot, GS_SIGNAL_EVENT);

    if (signal == GS_SIGNAL_SENSITIVE_FILE) {
        slot->exact_sensitive += 1u;
    } else if (signal == GS_SIGNAL_BLOCKED_DESTINATION) {
        slot->exact_blocked += 1u;
    } else if (signal == GS_SIGNAL_NETWORK_AFTER_FILE) {
        slot->exact_network_after_file += 1u;
    }

    guardSketchCmsAdd(slot, signal);
    return true;
}

static uint64_t guardSketchExactRisk(const guard_sketch_slot_t *slot) {
    uint64_t score = 0u;

    score += slot->exact_sensitive * 25u;
    score += slot->exact_blocked * 35u;
    score += slot->exact_network_after_file * 30u;

    if (slot->exact_events >= 8u) {
        score += 10u;
    }

    if (score > 100u) {
        score = 100u;
    }

    return score;
}

static uint64_t guardSketchApproxRisk(const guard_sketch_slot_t *slot) {
    uint64_t events = guardSketchCmsEstimate(slot, GS_SIGNAL_EVENT);
    uint64_t sensitive = guardSketchCmsEstimate(slot, GS_SIGNAL_SENSITIVE_FILE);
    uint64_t blocked = guardSketchCmsEstimate(slot, GS_SIGNAL_BLOCKED_DESTINATION);
    uint64_t network_after_file = guardSketchCmsEstimate(slot, GS_SIGNAL_NETWORK_AFTER_FILE);
    uint64_t score = 0u;

    score += sensitive * 25u;
    score += blocked * 35u;
    score += network_after_file * 30u;

    if (events >= 8u) {
        score += 10u;
    }

    if (score > 100u) {
        score = 100u;
    }

    return score;
}

static const guard_sketch_slot_t *guardSketchFindConstSlot(const guard_sketch_t *sketch, int pid) {
    for (uint64_t i = 0; i < GS_MAX_PIDS; ++i) {
        if (sketch->slots[i].used && sketch->slots[i].pid == pid) {
            return &sketch->slots[i];
        }
    }

    return NULL;
}

static size_t guardSketchTopPids(const guard_sketch_t *sketch, int *out, size_t out_count, bool approx) {
    bool selected[GS_MAX_PIDS];
    memset(selected, 0, sizeof(selected));

    for (size_t out_idx = 0; out_idx < out_count; ++out_idx) {
        uint64_t best_score = 0u;
        int best_pid = -1;
        size_t best_index = 0u;

        for (size_t i = 0; i < GS_MAX_PIDS; ++i) {
            const guard_sketch_slot_t *slot = &sketch->slots[i];
            uint64_t score = 0u;

            if (!slot->used || selected[i]) {
                continue;
            }

            score = approx ? guardSketchApproxRisk(slot) : guardSketchExactRisk(slot);

            if (best_pid < 0 || score > best_score || (score == best_score && slot->pid < best_pid)) {
                best_score = score;
                best_pid = slot->pid;
                best_index = i;
            }
        }

        if (best_pid < 0) {
            return out_idx;
        }

        out[out_idx] = best_pid;
        selected[best_index] = true;
    }

    return out_count;
}

static size_t guardSketchTopOverlap(const int *a, size_t a_count, const int *b, size_t b_count) {
    size_t overlap = 0u;

    for (size_t i = 0; i < a_count; ++i) {
        for (size_t j = 0; j < b_count; ++j) {
            if (a[i] == b[j]) {
                overlap += 1u;
                break;
            }
        }
    }

    return overlap;
}

#ifdef AGFAST_GUARDSKETCH_SELFTEST
int main(void) {
    guard_sketch_t sketch;
    const guard_sketch_slot_t *slot = NULL;
    int exact_top[5];
    int approx_top[5];
    size_t exact_count = 0u;
    size_t approx_count = 0u;
    size_t overlap = 0u;

    guardSketchInit(&sketch, 32u);

    guardSketchRecord(&sketch, 101, GS_SIGNAL_EVENT);
    guardSketchRecord(&sketch, 101, GS_SIGNAL_SENSITIVE_FILE);
    guardSketchRecord(&sketch, 101, GS_SIGNAL_BLOCKED_DESTINATION);
    guardSketchRecord(&sketch, 101, GS_SIGNAL_NETWORK_AFTER_FILE);

    guardSketchRecord(&sketch, 202, GS_SIGNAL_EVENT);
    guardSketchRecord(&sketch, 202, GS_SIGNAL_BLOCKED_DESTINATION);
    guardSketchRecord(&sketch, 202, GS_SIGNAL_BLOCKED_DESTINATION);

    guardSketchRecord(&sketch, 303, GS_SIGNAL_EVENT);
    guardSketchRecord(&sketch, 303, GS_SIGNAL_EVENT);
    guardSketchRecord(&sketch, 303, GS_SIGNAL_SENSITIVE_FILE);

    for (int i = 0; i < 40; ++i) {
        guardSketchRecord(&sketch, 400 + i, GS_SIGNAL_EVENT);
    }

    if (!guardSketchBloomMaybeContains(sketch.pid_bloom, 101u)) {
        fprintf(stderr, "Fallo: Bloom no reconoce PID observado\n");
        return 1;
    }

    if (guardSketchBloomMaybeContains(sketch.pid_bloom, 99999u)) {
        fprintf(stderr, "Advertencia: Bloom reporto posible falso positivo para PID no observado\n");
    }

    slot = guardSketchFindConstSlot(&sketch, 101);
    if (slot == NULL) {
        fprintf(stderr, "Fallo: no se encontro PID 101\n");
        return 1;
    }

    if (guardSketchApproxRisk(slot) < guardSketchExactRisk(slot)) {
        fprintf(stderr, "Fallo: el riesgo aproximado no debe subestimar en este MVP\n");
        return 1;
    }

    if (sketch.dropped_events == 0u) {
        fprintf(stderr, "Fallo: se esperaba contador de drops simulado\n");
        return 1;
    }

    exact_count = guardSketchTopPids(&sketch, exact_top, 5u, false);
    approx_count = guardSketchTopPids(&sketch, approx_top, 5u, true);
    overlap = guardSketchTopOverlap(exact_top, exact_count, approx_top, approx_count);

    printf("GuardSketch MVP userspace\n");
    printf("Ventana configurada: %" PRIu64 "\n", sketch.window_limit);
    printf("Eventos aceptados: %" PRIu64 "\n", sketch.window_events);
    printf("Drops simulados: %" PRIu64 "\n", sketch.dropped_events);
    printf("Top overlap: %zu/%zu\n", overlap, exact_count);
    printf("Riesgo exacto PID 101: %" PRIu64 "\n", guardSketchExactRisk(slot));
    printf("Riesgo aproximado PID 101: %" PRIu64 "\n", guardSketchApproxRisk(slot));
    printf("Pruebas GuardSketch superadas\n");

    return 0;
}
#endif
