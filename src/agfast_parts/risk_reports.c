/**
 * Fragmento modular de agfast: risk_reports.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

typedef struct {
    uint64_t events_processed;
    uint64_t malformed_lines;
    uint64_t sensitive_file_hits;
    uint64_t blocked_destination_hits;
    uint64_t watched_process_hits;
    uint64_t correlated_alerts;
    uint64_t sliding_window_size;
    uint64_t sliding_windows_closed;
    uint64_t sliding_window_max_alerts;
    uint64_t sliding_window_last_alerts;
} stats_t;

static bool looks_like_domain(const char *s) {
    if (!s || !s[0]) return false;
    return strchr(s, '.') != NULL && strspn(s, "0123456789.") != strlen(s);
}

static bool looks_like_ip(const char *s) {
    if (!s || !s[0]) return false;
    return strspn(s, "0123456789.") == strlen(s) && strchr(s, '.') != NULL;
}

typedef enum {
    DEST_NONE,
    DEST_BLOCKED_IP,
    DEST_BLOCKED_DOMAIN
} dest_match_type_t;

static bool destination_blocked(const policy_t *policy, const event_t *ev, const char **matched_dst, dest_match_type_t *type) {
    const char *candidates[4] = { ev->dst, ev->ip, ev->domain, NULL };
    for (int i = 0; candidates[i]; i++) {
        const char *d = candidates[i];
        if (!d[0]) continue;
        if (looks_like_ip(d) && policy_is_blocked_ip(policy, d)) {
            *matched_dst = d;
            *type = DEST_BLOCKED_IP;
            return true;
        }
        if (looks_like_domain(d) && policy_is_blocked_domain(policy, d)) {
            *matched_dst = d;
            *type = DEST_BLOCKED_DOMAIN;
            return true;
        }
        if (policy_is_blocked_ip(policy, d)) {
            *matched_dst = d;
            *type = DEST_BLOCKED_IP;
            return true;
        }
        if (policy_is_blocked_domain(policy, d)) {
            *matched_dst = d;
            *type = DEST_BLOCKED_DOMAIN;
            return true;
        }
    }
    *matched_dst = NULL;
    *type = DEST_NONE;
    return false;
}

static void graph_ingest_event(graph_t *graph, const policy_t *policy, bool policy_loaded, const event_t *ev) {
    proc_node_t *node = graph_get_or_add(graph, ev->pid, ev->process);
    node->events_seen++;
    graph_add_timeline_event(node, ev);

    if (ev->event[0]) list_add_unique(&node->event_types, ev->event);
    if (ev->file[0]) {
        list_add_unique(&node->files, ev->file);
        if (policy_loaded && policy_is_sensitive_file(policy, ev->file)) {
            if (!node->touched_sensitive) copy_trunc(node->first_sensitive_file, sizeof(node->first_sensitive_file), ev->file);
            node->touched_sensitive = true;
        }
    }
    if (ev->dst[0]) {
        list_add_unique(&node->destinations, ev->dst);
        node->connected = true;
        if (!node->first_dst[0]) copy_trunc(node->first_dst, sizeof(node->first_dst), ev->dst);
    }
    if (policy_loaded) {
        if (policy_is_watched_process(policy, ev->process)) node->watched = true;
        const char *matched_dst = NULL;
        dest_match_type_t match_type = DEST_NONE;
        if (destination_blocked(policy, ev, &matched_dst, &match_type)) {
            node->connected = true;
            node->connected_blocked = true;
            if (match_type == DEST_BLOCKED_IP) node->connected_blocked_ip = true;
            if (match_type == DEST_BLOCKED_DOMAIN) node->connected_blocked_domain = true;
            list_add_unique(&node->destinations, matched_dst);
            if (!node->first_dst[0]) copy_trunc(node->first_dst, sizeof(node->first_dst), matched_dst);
        }
    }
}

static const char *risk_level_from_score(int score) {
    if (score >= 80) return "critical";
    if (score >= 60) return "high";
    if (score >= 30) return "medium";
    if (score > 0) return "low";
    return "none";
}

static void compute_risk_for_node(proc_node_t *node, const policy_t *policy) {
    list_free(&node->risk_reasons);
    node->risk_score = 0;
    if (node->watched) {
        node->risk_score += policy->weights.watched_process;
        list_add(&node->risk_reasons, "watched_process");
    }
    if (node->touched_sensitive) {
        node->risk_score += policy->weights.sensitive_file;
        list_add(&node->risk_reasons, "sensitive_file_access");
    }
    if (node->connected_blocked_ip) {
        node->risk_score += policy->weights.blocked_ip;
        list_add(&node->risk_reasons, "blocked_ip_contact");
    }
    if (node->connected_blocked_domain) {
        node->risk_score += policy->weights.blocked_domain;
        list_add(&node->risk_reasons, "blocked_domain_contact");
    }
    if (node->touched_sensitive && node->connected) {
        node->risk_score += policy->weights.network_after_file;
        list_add(&node->risk_reasons, "network_after_file_access");
    }
    if (node->destinations.count >= (size_t)policy->weights.high_unique_destination_threshold) {
        node->risk_score += policy->weights.high_unique_destinations;
        list_add(&node->risk_reasons, "high_unique_destinations");
    }
    if (node->events_seen >= (uint64_t)policy->weights.high_event_volume_threshold) {
        node->risk_score += policy->weights.high_event_volume;
        list_add(&node->risk_reasons, "high_event_volume");
    }
    if (node->risk_score > 100) node->risk_score = 100;
    copy_trunc(node->risk_level, sizeof(node->risk_level), risk_level_from_score(node->risk_score));
}

static void compute_risk_all(graph_t *graph, const policy_t *policy) {
    for (size_t i = 0; i < graph->count; i++) compute_risk_for_node(&graph->items[i], policy);
}

static int risk_cmp_desc(const void *a, const void *b) {
    const proc_node_t * const *pa = (const proc_node_t * const *)a;
    const proc_node_t * const *pb = (const proc_node_t * const *)b;
    if ((*pa)->risk_score < (*pb)->risk_score) return 1;
    if ((*pa)->risk_score > (*pb)->risk_score) return -1;
    if ((*pa)->pid > (*pb)->pid) return 1;
    if ((*pa)->pid < (*pb)->pid) return -1;
    return strcmp((*pa)->process, (*pb)->process);
}

static proc_node_t **build_sorted_risk_nodes(const graph_t *graph, size_t *out_count) {
    *out_count = 0;
    if (graph->count == 0) return NULL;
    proc_node_t **nodes = calloc(graph->count, sizeof(proc_node_t *));
    if (!nodes) die_errno("memoria insuficiente");
    for (size_t i = 0; i < graph->count; i++) {
        if (graph->items[i].risk_score > 0) nodes[(*out_count)++] = (proc_node_t *)&graph->items[i];
    }
    qsort(nodes, *out_count, sizeof(proc_node_t *), risk_cmp_desc);
    return nodes;
}

static bool graph_node_matches(const proc_node_t *node, long filter_pid, const char *filter_process) {
    if (filter_pid >= 0 && node->pid != filter_pid) return false;
    if (filter_process && filter_process[0] && strcmp(node->process, filter_process) != 0) return false;
    return true;
}

static void print_timeline_node(const proc_node_t *node, size_t limit) {
    printf("\nTimeline: %s[%ld]\n", safe_str(node->process), node->pid);
    if (node->timeline_count == 0) {
        printf("  sin eventos\n");
        return;
    }
    size_t n = node->timeline_count < limit ? node->timeline_count : limit;
    for (size_t i = 0; i < n; i++) {
        const timeline_event_t *t = &node->timeline[i];
        printf("  %s  %-10s", safe_str(t->time), safe_str(t->event));
        if (t->file[0]) printf(" file=%s", t->file);
        if (t->dst[0]) printf(" dst=%s", t->dst);
        printf("\n");
    }
    if (node->timeline_count > n) printf("  ... %zu eventos adicionales\n", node->timeline_count - n);
}

static void print_graph_node(const proc_node_t *node, bool include_timeline) {
    printf("\nProceso: %s[%ld]\n", safe_str(node->process), node->pid);
    printf("  eventos observados:     %" PRIu64 "\n", node->events_seen);
    printf("  vigilado por política:   %s\n", node->watched ? "sí" : "no");
    printf("  tocó archivo sensible:   %s\n", node->touched_sensitive ? "sí" : "no");
    printf("  conectó a red:           %s\n", node->connected ? "sí" : "no");
    printf("  destino bloqueado:       %s\n", node->connected_blocked ? "sí" : "no");
    printf("  riesgo:                  %d/100 (%s)\n", node->risk_score, node->risk_level);
    if (node->first_sensitive_file[0]) printf("  primer archivo sensible: %s\n", node->first_sensitive_file);
    if (node->first_dst[0]) printf("  primer destino:          %s\n", node->first_dst);
    list_print_limited(&node->risk_reasons, "motivos de riesgo", AGF_TOP_ITEMS_PRINT);
    list_print_limited(&node->event_types, "tipos de evento", AGF_TOP_ITEMS_PRINT);
    list_print_limited(&node->files, "archivos relacionados", AGF_GRAPH_PRINT_LIMIT);
    list_print_limited(&node->destinations, "destinos de red", AGF_GRAPH_PRINT_LIMIT);
    if (include_timeline) print_timeline_node(node, AGF_TIMELINE_PRINT_LIMIT);
}

static void print_risk_summary(const graph_t *graph, size_t limit) {
    size_t count = 0;
    proc_node_t **nodes = build_sorted_risk_nodes(graph, &count);
    printf("\nProcesos de mayor riesgo:\n");
    if (count == 0) {
        printf("  sin riesgo calculado\n");
        free(nodes);
        return;
    }
    if (limit > count) limit = count;
    for (size_t i = 0; i < limit; i++) {
        const proc_node_t *n = nodes[i];
        printf("  %2zu. %-18s pid=%ld riesgo=%d/100 nivel=%s\n", i + 1, n->process, n->pid, n->risk_score, n->risk_level);
    }
    free(nodes);
}

static void update_alert_risks(alert_list_t *alerts, const graph_t *graph) {
    for (size_t i = 0; i < alerts->count; i++) {
        const proc_node_t *node = graph_find_by_pid_const(graph, alerts->items[i].pid);
        if (node) alerts->items[i].risk_score = node->risk_score;
    }
}

static void write_alerts_json(FILE *out, const alert_list_t *alerts) {
    fprintf(out, "  \"alerts\": [\n");
    for (size_t i = 0; i < alerts->count; i++) {
        const alert_t *a = &alerts->items[i];
        fprintf(out, "    {\"severity\": "); json_write_string(out, a->severity);
        fprintf(out, ", \"reason\": "); json_write_string(out, a->reason);
        fprintf(out, ", \"time\": "); json_write_string(out, a->time);
        fprintf(out, ", \"pid\": %ld, \"process\": ", a->pid); json_write_string(out, a->process);
        fprintf(out, ", \"file\": "); json_write_string(out, a->file);
        fprintf(out, ", \"dst\": "); json_write_string(out, a->dst);
        fprintf(out, ", \"risk_score\": %d", a->risk_score);
        fprintf(out, "}%s\n", (i + 1 < alerts->count) ? "," : "");
    }
    fprintf(out, "  ],\n");
}

static void write_timeline_json_array(FILE *out, const proc_node_t *n) {
    fprintf(out, "\"timeline\": [");
    for (size_t i = 0; i < n->timeline_count; i++) {
        const timeline_event_t *t = &n->timeline[i];
        if (i) fprintf(out, ", ");
        fprintf(out, "{\"time\": "); json_write_string(out, t->time);
        fprintf(out, ", \"event\": "); json_write_string(out, t->event);
        fprintf(out, ", \"file\": "); json_write_string(out, t->file);
        fprintf(out, ", \"dst\": "); json_write_string(out, t->dst);
        fprintf(out, "}");
    }
    fprintf(out, "]");
}

static void write_graph_json_core(FILE *out, const graph_t *graph, long filter_pid, const char *filter_process,
                                  bool include_timeline, const char *property_name, bool trailing_comma) {
    fprintf(out, "  \"%s\": [\n", property_name);
    size_t written = 0;
    for (size_t i = 0; i < graph->count; i++) {
        const proc_node_t *n = &graph->items[i];
        if (!graph_node_matches(n, filter_pid, filter_process)) continue;
        if (written > 0) fprintf(out, ",\n");
        fprintf(out, "    {\"pid\": %ld, \"process\": ", n->pid);
        json_write_string(out, n->process);
        fprintf(out, ", \"events_seen\": %" PRIu64, n->events_seen);
        fprintf(out, ", \"risk_score\": %d, \"risk_level\": ", n->risk_score);
        json_write_string(out, n->risk_level);
        fprintf(out, ", \"watched\": %s, \"touched_sensitive\": %s, \"connected\": %s, \"connected_blocked\": %s",
                n->watched ? "true" : "false",
                n->touched_sensitive ? "true" : "false",
                n->connected ? "true" : "false",
                n->connected_blocked ? "true" : "false");
        fprintf(out, ", \"first_sensitive_file\": "); json_write_string(out, safe_str(n->first_sensitive_file));
        fprintf(out, ", \"first_dst\": "); json_write_string(out, safe_str(n->first_dst));
        fprintf(out, ", "); json_write_string_array(out, "risk_reasons", &n->risk_reasons, true);
        fprintf(out, " "); json_write_string_array(out, "event_types", &n->event_types, true);
        fprintf(out, " "); json_write_string_array(out, "files", &n->files, true);
        fprintf(out, " "); json_write_string_array(out, "destinations", &n->destinations, include_timeline);
        if (include_timeline) {
            fprintf(out, " ");
            write_timeline_json_array(out, n);
        }
        fprintf(out, "}");
        written++;
    }
    fprintf(out, "\n  ]%s\n", trailing_comma ? "," : "");
}

static void write_risk_summary_json(FILE *out, const graph_t *graph, size_t limit, bool trailing_comma) {
    size_t count = 0;
    proc_node_t **nodes = build_sorted_risk_nodes(graph, &count);
    if (limit > count) limit = count;
    fprintf(out, "  \"risk_summary\": [\n");
    for (size_t i = 0; i < limit; i++) {
        const proc_node_t *n = nodes[i];
        fprintf(out, "    {\"pid\": %ld, \"process\": ", n->pid);
        json_write_string(out, n->process);
        fprintf(out, ", \"risk_score\": %d, \"risk_level\": ", n->risk_score);
        json_write_string(out, n->risk_level);
        fprintf(out, ", ");
        json_write_string_array(out, "reasons", &n->risk_reasons, false);
        fprintf(out, "}%s\n", (i + 1 < limit) ? "," : "");
    }
    fprintf(out, "  ]%s\n", trailing_comma ? "," : "");
    free(nodes);
}

static void write_alerts_csv(const char *path, const alert_list_t *alerts) {
    if (!path || !path[0]) return;
    FILE *out = fopen(path, "w");
    if (!out) die_errno("no se pudo escribir CSV de alertas");
    fprintf(out, "severity,pid,process,reason,file,dst,time,risk_score\n");
    for (size_t i = 0; i < alerts->count; i++) {
        const alert_t *a = &alerts->items[i];
        fprintf(out, "\"%s\",%ld,\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",%d\n",
                a->severity, a->pid, a->process, a->reason, a->file, a->dst, a->time, a->risk_score);
    }
    fclose(out);
}

static void write_html_report(const char *path, const stats_t *stats, const telemetry_t *telemetry,
                              const alert_list_t *alerts, const graph_t *graph, double elapsed_ms,
                              bool policy_loaded) {
    if (!path || !path[0]) return;
    FILE *out = fopen(path, "w");
    if (!out) die_errno("no se pudo escribir reporte HTML");
    fprintf(out, "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\"><title>AgentGuard FastPath</title>");
    fprintf(out, "<style>body{font-family:system-ui,Arial,sans-serif;margin:32px;line-height:1.45}table{border-collapse:collapse;width:100%%;margin:12px 0}td,th{border:1px solid #ccc;padding:6px;text-align:left}code,pre{background:#f3f3f3;padding:2px 4px}.critical{font-weight:bold}.card{border:1px solid #ddd;border-radius:10px;padding:14px;margin:14px 0}</style></head><body>");
    fprintf(out, "<h1>AgentGuard FastPath v%s</h1>", AGF_VERSION);
    fprintf(out, "<p>Reporte estático de análisis de telemetría de seguridad con estructuras probabilísticas.</p>");
    fprintf(out, "<div class=\"card\"><h2>Resumen</h2><table>");
    fprintf(out, "<tr><th>Métrica</th><th>Valor</th></tr>");
    fprintf(out, "<tr><td>Modo</td><td>%s</td></tr>", policy_loaded ? "analyze" : "stats");
    fprintf(out, "<tr><td>Eventos procesados</td><td>%" PRIu64 "</td></tr>", stats->events_processed);
    fprintf(out, "<tr><td>Líneas mal formadas</td><td>%" PRIu64 "</td></tr>", stats->malformed_lines);
    fprintf(out, "<tr><td>Tiempo de análisis</td><td>%.3f ms</td></tr>", elapsed_ms);
    fprintf(out, "<tr><td>Alertas</td><td>%zu</td></tr>", alerts->count);
    fprintf(out, "</table></div>");

    fprintf(out, "<div class=\"card\"><h2>Cardinalidad aproximada - HyperLogLog</h2><table>");
    fprintf(out, "<tr><td>PIDs únicos estimados</td><td>%" PRIu64 "</td></tr>", hll_estimate(&telemetry->unique_pids));
    fprintf(out, "<tr><td>Procesos únicos estimados</td><td>%" PRIu64 "</td></tr>", hll_estimate(&telemetry->unique_processes));
    fprintf(out, "<tr><td>Archivos únicos estimados</td><td>%" PRIu64 "</td></tr>", hll_estimate(&telemetry->unique_files));
    fprintf(out, "<tr><td>Destinos únicos estimados</td><td>%" PRIu64 "</td></tr>", hll_estimate(&telemetry->unique_destinations));
    fprintf(out, "</table></div>");

    size_t exact = exact_memory_estimate_bytes(telemetry), prob = telemetry_memory_bytes();
    fprintf(out, "<div class=\"card\"><h2>Memoria exacta estimada vs probabilística</h2><table>");
    fprintf(out, "<tr><th>Tipo</th><th>Bytes</th></tr><tr><td>Exacta estimada</td><td>%zu</td></tr><tr><td>Probabilística fija</td><td>%zu</td></tr><tr><td>Relación</td><td>%.2fx</td></tr></table></div>", exact, prob, prob ? (double)exact / (double)prob : 0.0);
    fprintf(out, "<div class=\"card\"><h2>Heavy hitters — Space-Saving</h2><p>Top-k con cotas inferior/superior para telemetría de alta escala.</p></div>");

    size_t risk_count = 0;
    proc_node_t **risk_nodes = build_sorted_risk_nodes(graph, &risk_count);
    fprintf(out, "<div class=\"card\"><h2>Procesos de mayor riesgo</h2><table><tr><th>PID</th><th>Proceso</th><th>Riesgo</th><th>Nivel</th><th>Motivos</th></tr>");
    size_t risk_limit = risk_count < AGF_TOP_ITEMS_PRINT ? risk_count : AGF_TOP_ITEMS_PRINT;
    for (size_t i = 0; i < risk_limit; i++) {
        const proc_node_t *n = risk_nodes[i];
        fprintf(out, "<tr><td>%ld</td><td>", n->pid); html_write_escaped(out, n->process);
        fprintf(out, "</td><td>%d/100</td><td>%s</td><td>", n->risk_score, n->risk_level);
        for (size_t r = 0; r < n->risk_reasons.count; r++) {
            if (r) fprintf(out, ", ");
            html_write_escaped(out, n->risk_reasons.items[r]);
        }
        fprintf(out, "</td></tr>");
    }
    fprintf(out, "</table></div>");
    free(risk_nodes);

    fprintf(out, "<div class=\"card\"><h2>Alertas principales</h2><table><tr><th>Severidad</th><th>PID</th><th>Proceso</th><th>Motivo</th><th>Archivo</th><th>Destino</th><th>Riesgo</th></tr>");
    size_t alert_limit = alerts->count < AGF_TOP_ALERTS_PRINT ? alerts->count : AGF_TOP_ALERTS_PRINT;
    for (size_t i = 0; i < alert_limit; i++) {
        const alert_t *a = &alerts->items[i];
        fprintf(out, "<tr><td>%s</td><td>%ld</td><td>", a->severity, a->pid); html_write_escaped(out, a->process);
        fprintf(out, "</td><td>"); html_write_escaped(out, a->reason);
        fprintf(out, "</td><td>"); html_write_escaped(out, a->file);
        fprintf(out, "</td><td>"); html_write_escaped(out, a->dst);
        fprintf(out, "</td><td>%d</td></tr>", a->risk_score);
    }
    fprintf(out, "</table></div>");

    if (risk_limit > 0) {
        const proc_node_t *n = graph->count ? NULL : NULL;
        size_t top_count = 0;
        proc_node_t **top = build_sorted_risk_nodes(graph, &top_count);
        if (top_count > 0) n = top[0];
        if (n) {
            fprintf(out, "<div class=\"card\"><h2>Timeline del mayor riesgo</h2><pre>");
            fprintf(out, "%s[%ld]\n", n->process, n->pid);
            size_t tl = n->timeline_count < AGF_TIMELINE_PRINT_LIMIT ? n->timeline_count : AGF_TIMELINE_PRINT_LIMIT;
            for (size_t i = 0; i < tl; i++) {
                const timeline_event_t *t = &n->timeline[i];
                html_write_escaped(out, safe_str(t->time)); fprintf(out, "  ");
                html_write_escaped(out, safe_str(t->event));
                if (t->file[0]) { fprintf(out, " file="); html_write_escaped(out, t->file); }
                if (t->dst[0]) { fprintf(out, " dst="); html_write_escaped(out, t->dst); }
                fprintf(out, "\n");
            }
            fprintf(out, "</pre></div>");
        }
        free(top);
    }
    fprintf(out, "</body></html>\n");
    fclose(out);
}

static void write_sliding_window_json(FILE *out, const stats_t *stats, bool trailing_comma) {
    fprintf(out, "  \"sliding_window\": {\n");
    fprintf(out, "    \"window_events\": %" PRIu64 ",\n", stats->sliding_window_size);
    fprintf(out, "    \"windows_closed\": %" PRIu64 ",\n", stats->sliding_windows_closed);
    fprintf(out, "    \"max_alerts_in_window\": %" PRIu64 ",\n", stats->sliding_window_max_alerts);
    fprintf(out, "    \"last_window_alerts\": %" PRIu64 "\n", stats->sliding_window_last_alerts);
    fprintf(out, "  }%s\n", trailing_comma ? "," : "");
}

static void write_risk_weights_json(FILE *out, const risk_weights_t *w, bool trailing_comma) {
    fprintf(out, "  \"risk_weights\": {\n");
    fprintf(out, "    \"watched_process\": %d,\n", w->watched_process);
    fprintf(out, "    \"sensitive_file\": %d,\n", w->sensitive_file);
    fprintf(out, "    \"blocked_ip\": %d,\n", w->blocked_ip);
    fprintf(out, "    \"blocked_domain\": %d,\n", w->blocked_domain);
    fprintf(out, "    \"network_after_file\": %d,\n", w->network_after_file);
    fprintf(out, "    \"high_unique_destinations\": %d,\n", w->high_unique_destinations);
    fprintf(out, "    \"high_event_volume\": %d,\n", w->high_event_volume);
    fprintf(out, "    \"high_unique_destination_threshold\": %d,\n", w->high_unique_destination_threshold);
    fprintf(out, "    \"high_event_volume_threshold\": %d\n", w->high_event_volume_threshold);
    fprintf(out, "  }%s\n", trailing_comma ? "," : "");
}
