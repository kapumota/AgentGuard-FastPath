/**
 * Fragmento modular de agfast: graph.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

typedef struct {
    char severity[16];
    char reason[128];
    char time[96];
    long pid;
    char process[128];
    char file[AGF_MAX_STR];
    char dst[AGF_MAX_STR];
    int risk_score;
} alert_t;

typedef struct {
    alert_t *items;
    size_t count;
    size_t cap;
} alert_list_t;

static void alert_add(alert_list_t *alerts, const char *severity, const char *reason,
                      const event_t *ev, const char *file, const char *dst) {
    if (alerts->count == alerts->cap) {
        size_t new_cap = alerts->cap ? alerts->cap * 2u : 32u;
        alert_t *new_items = realloc(alerts->items, new_cap * sizeof(alert_t));
        if (!new_items) die_errno("memoria insuficiente");
        alerts->items = new_items;
        alerts->cap = new_cap;
    }
    alert_t *a = &alerts->items[alerts->count++];
    memset(a, 0, sizeof(*a));
    snprintf(a->severity, sizeof(a->severity), "%s", severity);
    snprintf(a->reason, sizeof(a->reason), "%s", reason);
    snprintf(a->time, sizeof(a->time), "%s", safe_str(ev->time));
    a->pid = ev->pid;
    snprintf(a->process, sizeof(a->process), "%s", safe_str(ev->process));
    snprintf(a->file, sizeof(a->file), "%s", safe_str(file));
    snprintf(a->dst, sizeof(a->dst), "%s", safe_str(dst));
}

static void alerts_free(alert_list_t *alerts) {
    free(alerts->items);
    memset(alerts, 0, sizeof(*alerts));
}

typedef struct {
    char time[96];
    char event[64];
    char file[AGF_MAX_STR];
    char dst[AGF_MAX_STR];
} timeline_event_t;

typedef struct {
    long pid;
    char process[128];
    bool watched;
    bool touched_sensitive;
    bool connected;
    bool connected_blocked;
    bool connected_blocked_ip;
    bool connected_blocked_domain;
    bool critical_emitted;
    char first_sensitive_file[AGF_MAX_STR];
    char first_dst[AGF_MAX_STR];
    uint64_t events_seen;
    int risk_score;
    char risk_level[16];
    string_list_t event_types;
    string_list_t files;
    string_list_t destinations;
    string_list_t risk_reasons;
    timeline_event_t *timeline;
    size_t timeline_count;
    size_t timeline_cap;
} proc_node_t;

typedef struct {
    proc_node_t *items;
    size_t count;
    size_t cap;
} graph_t;

typedef struct {
    uint8_t bits[AGF_ODD_BYTES];
} odd_sketch_t;

static void odd_sketch_add(odd_sketch_t *sk, const char *value) {
    if (!value || !value[0]) return;
    size_t bit = (size_t)(mix64(fnv1a64(value)) % AGF_ODD_BITS);
    sk->bits[bit / 8u] ^= (uint8_t)(1u << (bit % 8u));
}

static unsigned popcount8(uint8_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return (unsigned)__builtin_popcount((unsigned)x);
#else
    unsigned c = 0;
    while (x) { c += x & 1u; x >>= 1u; }
    return c;
#endif
}

static size_t odd_sketch_hamming(const odd_sketch_t *a, const odd_sketch_t *b) {
    size_t out = 0;
    for (size_t i = 0; i < AGF_ODD_BYTES; i++) out += popcount8((uint8_t)(a->bits[i] ^ b->bits[i]));
    return out;
}

static double odd_sketch_parity_similarity(const odd_sketch_t *a, const odd_sketch_t *b) {
    size_t dist = odd_sketch_hamming(a, b);
    if (dist > AGF_ODD_BITS) dist = AGF_ODD_BITS;
    return 1.0 - ((double)dist / (double)AGF_ODD_BITS);
}

static void odd_sketch_from_node(const proc_node_t *node, odd_sketch_t *sk) {
    memset(sk, 0, sizeof(*sk));
    if (!node) return;
    for (size_t i = 0; i < node->files.count; i++) odd_sketch_add(sk, node->files.items[i]);
    for (size_t i = 0; i < node->destinations.count; i++) odd_sketch_add(sk, node->destinations.items[i]);
}

static proc_node_t *graph_find_by_pid(graph_t *g, long pid) {
    for (size_t i = 0; i < g->count; i++) if (g->items[i].pid == pid) return &g->items[i];
    return NULL;
}

static const proc_node_t *graph_find_by_pid_const(const graph_t *g, long pid) {
    for (size_t i = 0; i < g->count; i++) if (g->items[i].pid == pid) return &g->items[i];
    return NULL;
}

static proc_node_t *graph_get_or_add(graph_t *g, long pid, const char *process) {
    proc_node_t *existing = graph_find_by_pid(g, pid);
    if (existing) {
        if (process && process[0] && !existing->process[0]) copy_trunc(existing->process, sizeof(existing->process), process);
        return existing;
    }
    if (g->count == g->cap) {
        size_t new_cap = g->cap ? g->cap * 2u : 64u;
        proc_node_t *new_items = realloc(g->items, new_cap * sizeof(proc_node_t));
        if (!new_items) die_errno("memoria insuficiente");
        g->items = new_items;
        g->cap = new_cap;
    }
    proc_node_t *n = &g->items[g->count++];
    memset(n, 0, sizeof(*n));
    n->pid = pid;
    copy_trunc(n->process, sizeof(n->process), safe_str(process));
    copy_trunc(n->risk_level, sizeof(n->risk_level), "none");
    return n;
}

static void graph_add_timeline_event(proc_node_t *node, const event_t *ev) {
    if (node->timeline_count == node->timeline_cap) {
        size_t new_cap = node->timeline_cap ? node->timeline_cap * 2u : 16u;
        timeline_event_t *new_items = realloc(node->timeline, new_cap * sizeof(timeline_event_t));
        if (!new_items) die_errno("memoria insuficiente");
        node->timeline = new_items;
        node->timeline_cap = new_cap;
    }
    timeline_event_t *t = &node->timeline[node->timeline_count++];
    memset(t, 0, sizeof(*t));
    copy_trunc(t->time, sizeof(t->time), ev->time);
    copy_trunc(t->event, sizeof(t->event), ev->event);
    copy_trunc(t->file, sizeof(t->file), ev->file);
    copy_trunc(t->dst, sizeof(t->dst), ev->dst);
}

static void graph_free(graph_t *g) {
    if (!g) return;
    for (size_t i = 0; i < g->count; i++) {
        list_free(&g->items[i].event_types);
        list_free(&g->items[i].files);
        list_free(&g->items[i].destinations);
        list_free(&g->items[i].risk_reasons);
        free(g->items[i].timeline);
    }
    free(g->items);
    memset(g, 0, sizeof(*g));
}
