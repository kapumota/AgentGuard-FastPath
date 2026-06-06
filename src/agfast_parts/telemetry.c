/**
 * Fragmento modular de agfast: telemetry.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

typedef struct {
    cms_t process_freq;
    cms_t file_freq;
    cms_t dest_freq;
    cms_t event_freq;
    hll_t unique_processes;
    hll_t unique_files;
    hll_t unique_destinations;
    hll_t unique_pids;
    candidate_list_t process_candidates;
    candidate_list_t file_candidates;
    candidate_list_t dest_candidates;
    candidate_list_t event_candidates;
    space_saving_t ss_processes;
    space_saving_t ss_files;
    space_saving_t ss_destinations;
} telemetry_t;

static void telemetry_init(telemetry_t *t) {
    memset(t, 0, sizeof(*t));
    cms_init(&t->process_freq, AGF_CMS_WIDTH, AGF_CMS_DEPTH);
    cms_init(&t->file_freq, AGF_CMS_WIDTH, AGF_CMS_DEPTH);
    cms_init(&t->dest_freq, AGF_CMS_WIDTH, AGF_CMS_DEPTH);
    cms_init(&t->event_freq, AGF_CMS_WIDTH, AGF_CMS_DEPTH);
    candidates_init(&t->process_candidates, AGF_MAX_CANDIDATES);
    candidates_init(&t->file_candidates, AGF_MAX_CANDIDATES);
    candidates_init(&t->dest_candidates, AGF_MAX_CANDIDATES);
    candidates_init(&t->event_candidates, AGF_MAX_CANDIDATES);
    ss_init(&t->ss_processes);
    ss_init(&t->ss_files);
    ss_init(&t->ss_destinations);
}

static void telemetry_update(telemetry_t *t, const event_t *ev) {
    char pid_key[64];
    if (ev->pid >= 0) {
        snprintf(pid_key, sizeof(pid_key), "%ld", ev->pid);
        hll_add(&t->unique_pids, pid_key);
    }
    if (ev->process[0]) {
        cms_add(&t->process_freq, ev->process, 1);
        hll_add(&t->unique_processes, ev->process);
        candidates_add_unique(&t->process_candidates, ev->process);
        ss_update(&t->ss_processes, ev->process);
    }
    if (ev->file[0]) {
        cms_add(&t->file_freq, ev->file, 1);
        hll_add(&t->unique_files, ev->file);
        candidates_add_unique(&t->file_candidates, ev->file);
        ss_update(&t->ss_files, ev->file);
    }
    if (ev->dst[0]) {
        cms_add(&t->dest_freq, ev->dst, 1);
        hll_add(&t->unique_destinations, ev->dst);
        candidates_add_unique(&t->dest_candidates, ev->dst);
        ss_update(&t->ss_destinations, ev->dst);
    }
    if (ev->event[0]) {
        cms_add(&t->event_freq, ev->event, 1);
        candidates_add_unique(&t->event_candidates, ev->event);
    }
}

static size_t telemetry_memory_bytes(void) {
    size_t cms_bytes = 4u * (size_t)AGF_CMS_WIDTH * AGF_CMS_DEPTH * sizeof(uint64_t);
    size_t hll_bytes = 4u * (size_t)AGF_HLL_M * sizeof(uint8_t);
    size_t bloom_bytes = 4u * (((size_t)AGF_BLOOM_BITS + 7u) / 8u);
    size_t space_saving_bytes = 3u * sizeof(space_saving_t);
    size_t cuckoo_bytes = sizeof(cuckoo_filter_t);
    return cms_bytes + hll_bytes + bloom_bytes + space_saving_bytes + cuckoo_bytes;
}

static size_t exact_memory_estimate_bytes(const telemetry_t *t) {
    uint64_t unique_pids = hll_estimate(&t->unique_pids);
    uint64_t unique_processes = hll_estimate(&t->unique_processes);
    uint64_t unique_files = hll_estimate(&t->unique_files);
    uint64_t unique_destinations = hll_estimate(&t->unique_destinations);
    uint64_t event_types = (uint64_t)t->event_candidates.count;
    return (size_t)(unique_pids * 32u + unique_processes * 96u + unique_files * 128u +
                    unique_destinations * 112u + event_types * 80u);
}

static void print_memory_comparison(const telemetry_t *t) {
    size_t approximate = telemetry_memory_bytes();
    size_t exact = exact_memory_estimate_bytes(t);
    double ratio = approximate ? (double)exact / (double)approximate : 0.0;
    printf("\nComparación de memoria - exacta estimada vs probabilística:\n");
    printf("  Exacta estimada equivalente:        %zu bytes\n", exact);
    printf("  Probabilística fija aprox.:         %zu bytes\n", approximate);
    printf("  Relación exacta/probabilística:     %.2fx\n", ratio);
}

static void write_memory_comparison_json(FILE *out, const telemetry_t *t, bool trailing_comma) {
    size_t approximate = telemetry_memory_bytes();
    size_t exact = exact_memory_estimate_bytes(t);
    double ratio = approximate ? (double)exact / (double)approximate : 0.0;
    fprintf(out, "  \"memory_comparison\": {\n");
    fprintf(out, "    \"exact_estimated_bytes\": %zu,\n", exact);
    fprintf(out, "    \"probabilistic_fixed_bytes\": %zu,\n", approximate);
    fprintf(out, "    \"exact_to_probabilistic_ratio\": %.4f,\n", ratio);
    fprintf(out, "    \"note\": ");
    json_write_string(out, "La memoria exacta se estima para mapas/sets exactos; la probabilística corresponde a Bloom, Count-Min Sketch e HyperLogLog.");
    fprintf(out, "\n  }%s\n", trailing_comma ? "," : "");
}

static void telemetry_free(telemetry_t *t) {
    cms_free(&t->process_freq);
    cms_free(&t->file_freq);
    cms_free(&t->dest_freq);
    cms_free(&t->event_freq);
    candidates_free(&t->process_candidates);
    candidates_free(&t->file_candidates);
    candidates_free(&t->dest_candidates);
    candidates_free(&t->event_candidates);
    memset(t, 0, sizeof(*t));
}
