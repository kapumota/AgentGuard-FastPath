/**
 * Fragmento modular de agfast: commands.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

static int process_events(const char *events_path, const char *policy_path, const char *report_path,
                          const char *html_path, const char *alerts_csv_path,
                          bool require_policy, bool show_risk, uint64_t window_events) {
    policy_t policy;
    stats_t stats = {0};
    alert_list_t alerts = {0};
    graph_t graph = {0};
    telemetry_t telemetry;
    bool policy_loaded = policy_path && policy_path[0];
    if (require_policy && !policy_loaded) die("falta --policy <policy.json>");

    policy_init(&policy);
    if (policy_loaded) policy_load(&policy, policy_path);
    telemetry_init(&telemetry);
    stats.sliding_window_size = window_events;
    uint64_t current_window_events = 0;
    uint64_t current_window_alerts = 0;

    FILE *fp = fopen(events_path, "r");
    if (!fp) die_errno("no se pudo abrir archivo de eventos");

    clock_t start = clock();
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;

    while ((line_len = getline(&line, &line_cap, fp)) != -1) {
        (void)line_len;
        trim_newline(line);
        if (!line[0] || line[0] == '#') continue;

        event_t ev;
        bool is_header = false;
        if (!parse_event_line(line, &ev, &is_header)) {
            if (!is_header) stats.malformed_lines++;
            continue;
        }
        stats.events_processed++;
        size_t alerts_before_event = alerts.count;
        telemetry_update(&telemetry, &ev);

        if (policy_loaded || show_risk || html_path || alerts_csv_path) {
            graph_ingest_event(&graph, &policy, policy_loaded, &ev);
        }

        if (policy_loaded) {
            proc_node_t *node = graph_get_or_add(&graph, ev.pid, ev.process);
            bool watched = policy_is_watched_process(&policy, ev.process);
            if (watched) {
                stats.watched_process_hits++;
                node->watched = true;
                alert_add(&alerts, "low", "watched_process_executed_or_seen", &ev, NULL, NULL);
            }

            if (ev.file[0] && policy_is_sensitive_file(&policy, ev.file)) {
                stats.sensitive_file_hits++;
                if (!node->touched_sensitive) copy_trunc(node->first_sensitive_file, sizeof(node->first_sensitive_file), ev.file);
                node->touched_sensitive = true;
                alert_add(&alerts, "medium", "sensitive_file_access", &ev, ev.file, NULL);
            }

            const char *matched_dst = NULL;
            dest_match_type_t match_type = DEST_NONE;
            if (destination_blocked(&policy, &ev, &matched_dst, &match_type)) {
                stats.blocked_destination_hits++;
                node->connected = true;
                node->connected_blocked = true;
                if (match_type == DEST_BLOCKED_IP) node->connected_blocked_ip = true;
                if (match_type == DEST_BLOCKED_DOMAIN) node->connected_blocked_domain = true;
                if (!node->first_dst[0]) copy_trunc(node->first_dst, sizeof(node->first_dst), matched_dst);
                alert_add(&alerts, "high", "blocked_destination_contact", &ev, NULL, matched_dst);
            } else if (ev.dst[0]) {
                node->connected = true;
                if (!node->first_dst[0]) copy_trunc(node->first_dst, sizeof(node->first_dst), ev.dst);
            }

            if (node->touched_sensitive && node->connected && node->connected_blocked && !node->critical_emitted) {
                stats.correlated_alerts++;
                node->critical_emitted = true;
                alert_add(&alerts, "critical", "process_touched_sensitive_file_and_contacted_blocked_destination",
                          &ev, node->first_sensitive_file, node->first_dst);
            }
        }
        if (window_events > 0) {
            current_window_events++;
            current_window_alerts += (uint64_t)(alerts.count - alerts_before_event);
            if (current_window_events >= window_events) {
                stats.sliding_windows_closed++;
                if (current_window_alerts > stats.sliding_window_max_alerts) stats.sliding_window_max_alerts = current_window_alerts;
                stats.sliding_window_last_alerts = current_window_alerts;
                current_window_events = 0;
                current_window_alerts = 0;
            }
        }
    }
    if (window_events > 0 && current_window_events > 0) {
        stats.sliding_windows_closed++;
        if (current_window_alerts > stats.sliding_window_max_alerts) stats.sliding_window_max_alerts = current_window_alerts;
        stats.sliding_window_last_alerts = current_window_alerts;
    }

    clock_t end = clock();
    double elapsed_ms = 1000.0 * (double)(end - start) / (double)CLOCKS_PER_SEC;
    free(line);
    fclose(fp);

    if (policy_loaded) {
        compute_risk_all(&graph, &policy);
        update_alert_risks(&alerts, &graph);
    }

    printf("\n%s %s - Reporte final\n", AGF_APP_NAME, AGF_VERSION);
    printf("-------------------------------------------------\n");
    printf("Modo: %s\n", policy_loaded ? "analyze con política" : "stats sin política");
    printf("Eventos procesados:        %" PRIu64 "\n", stats.events_processed);
    printf("Líneas mal formadas:       %" PRIu64 "\n", stats.malformed_lines);
    printf("Procesos observados:       %zu\n", graph.count ? graph.count : (size_t)hll_estimate(&telemetry.unique_pids));
    printf("Tiempo de análisis:        %.3f ms\n", elapsed_ms);
    printf("Memoria estructuras aprox.: %zu bytes\n", telemetry_memory_bytes());
    print_memory_comparison(&telemetry);

    printf("\nCardinalidad aproximada - HyperLogLog:\n");
    printf("  PIDs únicos estimados:     %" PRIu64 "\n", hll_estimate(&telemetry.unique_pids));
    printf("  Procesos únicos estimados: %" PRIu64 "\n", hll_estimate(&telemetry.unique_processes));
    printf("  Archivos únicos estimados: %" PRIu64 "\n", hll_estimate(&telemetry.unique_files));
    printf("  Destinos únicos estimados: %" PRIu64 "\n", hll_estimate(&telemetry.unique_destinations));

    print_top_from_cms("Top procesos - Count-Min Sketch", &telemetry.process_candidates, &telemetry.process_freq, AGF_TOP_ITEMS_PRINT);
    print_top_from_cms("Top archivos - Count-Min Sketch", &telemetry.file_candidates, &telemetry.file_freq, AGF_TOP_ITEMS_PRINT);
    print_top_from_cms("Top destinos - Count-Min Sketch", &telemetry.dest_candidates, &telemetry.dest_freq, AGF_TOP_ITEMS_PRINT);
    print_top_from_cms("Top tipos de evento - Count-Min Sketch", &telemetry.event_candidates, &telemetry.event_freq, AGF_TOP_ITEMS_PRINT);
    print_space_saving("Top procesos", &telemetry.ss_processes, AGF_TOP_ITEMS_PRINT);
    print_space_saving("Top archivos", &telemetry.ss_files, AGF_TOP_ITEMS_PRINT);
    print_space_saving("Top destinos", &telemetry.ss_destinations, AGF_TOP_ITEMS_PRINT);

    if (window_events > 0) {
        printf("\nSliding windows por últimos %" PRIu64 " eventos:\n", window_events);
        printf("  Ventanas cerradas:          %" PRIu64 "\n", stats.sliding_windows_closed);
        printf("  Máx. alertas en ventana:    %" PRIu64 "\n", stats.sliding_window_max_alerts);
        printf("  Última ventana alertas:     %" PRIu64 "\n", stats.sliding_window_last_alerts);
    }

    if (policy_loaded) {
        printf("\nAlertas y política:\n");
        printf("  Coincidencias watched:     %" PRIu64 "\n", stats.watched_process_hits);
        printf("  Archivos sensibles:        %" PRIu64 "\n", stats.sensitive_file_hits);
        printf("  Destinos bloqueados:       %" PRIu64 "\n", stats.blocked_destination_hits);
        printf("  Alertas correlacionadas:   %" PRIu64 "\n", stats.correlated_alerts);
        printf("  Alertas totales:           %zu\n", alerts.count);
        if (show_risk || true) print_risk_summary(&graph, AGF_TOP_ITEMS_PRINT);
    }

    if (alerts.count > 0) {
        printf("\nAlertas principales:\n");
        size_t limit = alerts.count < AGF_TOP_ALERTS_PRINT ? alerts.count : AGF_TOP_ALERTS_PRINT;
        for (size_t i = 0; i < limit; i++) {
            alert_t *a = &alerts.items[i];
            printf("  [%s] pid=%ld process=%s risk=%d reason=%s file=%s dst=%s\n",
                   a->severity, a->pid, a->process, a->risk_score, a->reason, a->file, a->dst);
        }
        if (alerts.count > limit) printf("  ... %zu alertas adicionales no mostradas en consola\n", alerts.count - limit);
    }

    if (report_path && report_path[0]) {
        FILE *out = fopen(report_path, "w");
        if (!out) die_errno("no se pudo escribir reporte JSON");
        fprintf(out, "{\n");
        fprintf(out, "  \"software\": \"AgentGuard FastPath\",\n");
        fprintf(out, "  \"version\": \"%s\",\n", AGF_VERSION);
        fprintf(out, "  \"mode\": \"%s\",\n", policy_loaded ? "analyze" : "stats");
        fprintf(out, "  \"stats\": {\n");
        fprintf(out, "    \"events_processed\": %" PRIu64 ",\n", stats.events_processed);
        fprintf(out, "    \"malformed_lines\": %" PRIu64 ",\n", stats.malformed_lines);
        fprintf(out, "    \"processes_observed\": %zu,\n", graph.count ? graph.count : (size_t)hll_estimate(&telemetry.unique_pids));
        fprintf(out, "    \"elapsed_ms\": %.3f,\n", elapsed_ms);
        fprintf(out, "    \"estimated_structure_memory_bytes\": %zu,\n", telemetry_memory_bytes());
        fprintf(out, "    \"watched_process_hits\": %" PRIu64 ",\n", stats.watched_process_hits);
        fprintf(out, "    \"sensitive_file_hits\": %" PRIu64 ",\n", stats.sensitive_file_hits);
        fprintf(out, "    \"blocked_destination_hits\": %" PRIu64 ",\n", stats.blocked_destination_hits);
        fprintf(out, "    \"correlated_alerts\": %" PRIu64 ",\n", stats.correlated_alerts);
        fprintf(out, "    \"total_alerts\": %zu\n", alerts.count);
        fprintf(out, "  },\n");
        if (policy_loaded) write_risk_weights_json(out, &policy.weights, true);
        write_memory_comparison_json(out, &telemetry, true);
        if (window_events > 0) write_sliding_window_json(out, &stats, true);
        fprintf(out, "  \"hyperloglog\": {\n");
        fprintf(out, "    \"unique_pids_estimated\": %" PRIu64 ",\n", hll_estimate(&telemetry.unique_pids));
        fprintf(out, "    \"unique_processes_estimated\": %" PRIu64 ",\n", hll_estimate(&telemetry.unique_processes));
        fprintf(out, "    \"unique_files_estimated\": %" PRIu64 ",\n", hll_estimate(&telemetry.unique_files));
        fprintf(out, "    \"unique_destinations_estimated\": %" PRIu64 "\n", hll_estimate(&telemetry.unique_destinations));
        fprintf(out, "  },\n");
        fprintf(out, "  \"count_min_sketch\": {\n");
        write_top_json(out, "top_processes", &telemetry.process_candidates, &telemetry.process_freq, AGF_TOP_ITEMS_PRINT, true);
        write_top_json(out, "top_files", &telemetry.file_candidates, &telemetry.file_freq, AGF_TOP_ITEMS_PRINT, true);
        write_top_json(out, "top_destinations", &telemetry.dest_candidates, &telemetry.dest_freq, AGF_TOP_ITEMS_PRINT, true);
        write_top_json(out, "top_event_types", &telemetry.event_candidates, &telemetry.event_freq, AGF_TOP_ITEMS_PRINT, false);
        fprintf(out, "  },\n");
        fprintf(out, "  \"space_saving\": {\n");
        write_space_saving_json(out, "top_processes", &telemetry.ss_processes, AGF_TOP_ITEMS_PRINT, true);
        write_space_saving_json(out, "top_files", &telemetry.ss_files, AGF_TOP_ITEMS_PRINT, true);
        write_space_saving_json(out, "top_destinations", &telemetry.ss_destinations, AGF_TOP_ITEMS_PRINT, false);
        fprintf(out, "  },\n");
        if (policy_loaded) write_risk_summary_json(out, &graph, AGF_TOP_ITEMS_PRINT, true);
        write_alerts_json(out, &alerts);
        write_graph_json_core(out, &graph, -1, NULL, false, "graph_summary", true);
        fprintf(out, "  \"notes\": [\n");
        fprintf(out, "    \"Count-Min Sketch entrega estimaciones de frecuencia que pueden sobreestimar por colisiones.\",\n");
        fprintf(out, "    \"HyperLogLog entrega cardinalidades aproximadas con bajo consumo de memoria.\",\n");
        fprintf(out, "    \"Bloom Filter se usa como prefiltro y luego se confirma contra listas exactas.\",\n");
        fprintf(out, "    \"Risk score prioriza procesos; no sustituye una decisión forense humana.\"\n");
        fprintf(out, "  ]\n");
        fprintf(out, "}\n");
        fclose(out);
        printf("\nReporte JSON guardado en: %s\n", report_path);
    }

    if (alerts_csv_path && alerts_csv_path[0]) {
        write_alerts_csv(alerts_csv_path, &alerts);
        printf("CSV de alertas guardado en: %s\n", alerts_csv_path);
    }
    if (html_path && html_path[0]) {
        write_html_report(html_path, &stats, &telemetry, &alerts, &graph, elapsed_ms, policy_loaded);
        printf("Reporte HTML guardado en: %s\n", html_path);
    }

    size_t alert_count = alerts.count;
    alerts_free(&alerts);
    graph_free(&graph);
    telemetry_free(&telemetry);
    policy_free(&policy);
    return alert_count > 0 ? 2 : 0;
}

static int load_graph_from_events(const char *events_path, const char *policy_path, graph_t *graph,
                                  policy_t *policy, uint64_t *events_processed, uint64_t *malformed_lines,
                                  double *elapsed_ms) {
    bool policy_loaded = policy_path && policy_path[0];
    policy_init(policy);
    if (policy_loaded) policy_load(policy, policy_path);

    FILE *fp = fopen(events_path, "r");
    if (!fp) die_errno("no se pudo abrir archivo de eventos");

    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;
    *events_processed = 0;
    *malformed_lines = 0;
    clock_t start = clock();
    while ((line_len = getline(&line, &line_cap, fp)) != -1) {
        (void)line_len;
        trim_newline(line);
        if (!line[0] || line[0] == '#') continue;
        event_t ev;
        bool is_header = false;
        if (!parse_event_line(line, &ev, &is_header)) {
            if (!is_header) (*malformed_lines)++;
            continue;
        }
        (*events_processed)++;
        graph_ingest_event(graph, policy, policy_loaded, &ev);
    }
    clock_t end = clock();
    *elapsed_ms = 1000.0 * (double)(end - start) / (double)CLOCKS_PER_SEC;
    free(line);
    fclose(fp);
    if (policy_loaded) compute_risk_all(graph, policy);
    return 0;
}

static int run_graph_command(const char *events_path, const char *policy_path, long filter_pid,
                             const char *filter_process, const char *report_path, bool include_timeline) {
    policy_t policy;
    graph_t graph = {0};
    uint64_t events_processed = 0, malformed_lines = 0;
    double elapsed_ms = 0.0;
    load_graph_from_events(events_path, policy_path, &graph, &policy, &events_processed, &malformed_lines, &elapsed_ms);

    printf("\n%s %s - Consulta de grafo\n", AGF_APP_NAME, AGF_VERSION);
    printf("-------------------------------------------------\n");
    printf("Eventos procesados:  %" PRIu64 "\n", events_processed);
    printf("Líneas mal formadas: %" PRIu64 "\n", malformed_lines);
    printf("Nodos de proceso:    %zu\n", graph.count);
    printf("Tiempo de grafo:     %.3f ms\n", elapsed_ms);
    if (filter_pid >= 0) printf("Filtro PID:          %ld\n", filter_pid);
    if (filter_process && filter_process[0]) printf("Filtro proceso:      %s\n", filter_process);

    size_t matches = 0;
    for (size_t i = 0; i < graph.count; i++) {
        const proc_node_t *node = &graph.items[i];
        if (!graph_node_matches(node, filter_pid, filter_process)) continue;
        print_graph_node(node, include_timeline);
        matches++;
        if (filter_pid < 0 && (!filter_process || !filter_process[0]) && matches >= AGF_GRAPH_PRINT_LIMIT) {
            printf("\n... salida limitada a %u procesos. Use --pid o --process para filtrar.\n", AGF_GRAPH_PRINT_LIMIT);
            break;
        }
    }
    if (matches == 0) printf("\nNo se encontraron procesos que coincidan con el filtro.\n");

    if (report_path && report_path[0]) {
        FILE *out = fopen(report_path, "w");
        if (!out) die_errno("no se pudo escribir reporte JSON de grafo");
        fprintf(out, "{\n");
        fprintf(out, "  \"software\": \"AgentGuard FastPath\",\n");
        fprintf(out, "  \"version\": \"%s\",\n", AGF_VERSION);
        fprintf(out, "  \"mode\": \"graph\",\n");
        fprintf(out, "  \"events_processed\": %" PRIu64 ",\n", events_processed);
        fprintf(out, "  \"malformed_lines\": %" PRIu64 ",\n", malformed_lines);
        fprintf(out, "  \"elapsed_ms\": %.3f,\n", elapsed_ms);
        fprintf(out, "  \"filter\": {\"pid\": %ld, \"process\": ", filter_pid); json_write_string(out, safe_str(filter_process)); fprintf(out, "},\n");
        write_graph_json_core(out, &graph, filter_pid, filter_process, include_timeline, "graph_summary", false);
        fprintf(out, "}\n");
        fclose(out);
        printf("\nReporte JSON de grafo guardado en: %s\n", report_path);
    }

    graph_free(&graph);
    policy_free(&policy);
    return matches == 0 ? 3 : 0;
}

static int run_timeline_command(const char *events_path, const char *policy_path, long filter_pid,
                                const char *filter_process, const char *report_path) {
    policy_t policy;
    graph_t graph = {0};
    uint64_t events_processed = 0, malformed_lines = 0;
    double elapsed_ms = 0.0;
    load_graph_from_events(events_path, policy_path, &graph, &policy, &events_processed, &malformed_lines, &elapsed_ms);

    printf("\n%s %s - Timeline por proceso\n", AGF_APP_NAME, AGF_VERSION);
    printf("-------------------------------------------------\n");
    printf("Eventos procesados:  %" PRIu64 "\n", events_processed);
    printf("Líneas mal formadas: %" PRIu64 "\n", malformed_lines);
    printf("Tiempo de timeline:  %.3f ms\n", elapsed_ms);

    size_t matches = 0;
    for (size_t i = 0; i < graph.count; i++) {
        const proc_node_t *node = &graph.items[i];
        if (!graph_node_matches(node, filter_pid, filter_process)) continue;
        print_timeline_node(node, AGF_TIMELINE_PRINT_LIMIT);
        matches++;
        if (filter_pid < 0 && (!filter_process || !filter_process[0]) && matches >= AGF_GRAPH_PRINT_LIMIT) {
            printf("\n... salida limitada. Use --pid o --process para filtrar.\n");
            break;
        }
    }
    if (matches == 0) printf("\nNo se encontraron timelines que coincidan con el filtro.\n");

    if (report_path && report_path[0]) {
        FILE *out = fopen(report_path, "w");
        if (!out) die_errno("no se pudo escribir reporte JSON de timeline");
        fprintf(out, "{\n");
        fprintf(out, "  \"software\": \"AgentGuard FastPath\",\n");
        fprintf(out, "  \"version\": \"%s\",\n", AGF_VERSION);
        fprintf(out, "  \"mode\": \"timeline\",\n");
        fprintf(out, "  \"events_processed\": %" PRIu64 ",\n", events_processed);
        write_graph_json_core(out, &graph, filter_pid, filter_process, true, "timelines", false);
        fprintf(out, "}\n");
        fclose(out);
        printf("Reporte JSON de timeline guardado en: %s\n", report_path);
    }

    graph_free(&graph);
    policy_free(&policy);
    return matches == 0 ? 3 : 0;
}

typedef enum { CHECK_FILE, CHECK_IP, CHECK_DOMAIN } check_kind_t;

static int run_check_command(check_kind_t kind, const char *value, const char *policy_path, const char *report_path, bool delete_test) {
    if (!policy_path || !policy_path[0]) die("falta --policy <policy.json>");
    if (!value || !value[0]) die("falta valor a verificar");
    policy_t policy;
    policy_init(&policy);
    policy_load(&policy, policy_path);

    bool bloom_possible = false;
    bool pattern_match = false;
    bool matched = false;
    bool cuckoo_possible = false;
    bool cuckoo_after_delete = false;
    const char *kind_name = "";
    const char *list_name = "";
    cuckoo_filter_t cf;
    cuckoo_init(&cf);

    switch (kind) {
        case CHECK_FILE:
            kind_name = "file";
            list_name = "sensitive_files";
            matched = policy_check_file_with_details(&policy, value, &bloom_possible, &pattern_match);
            cuckoo_load_from_list(&cf, &policy.sensitive_files);
            break;
        case CHECK_IP:
            kind_name = "ip";
            list_name = "blocked_ips";
            matched = policy_check_ip_with_details(&policy, value, &bloom_possible);
            cuckoo_load_from_list(&cf, &policy.blocked_ips);
            break;
        case CHECK_DOMAIN:
            kind_name = "domain";
            list_name = "blocked_domains";
            matched = policy_check_domain_with_details(&policy, value, &bloom_possible);
            cuckoo_load_from_list(&cf, &policy.blocked_domains);
            break;
    }

    cuckoo_possible = cuckoo_contains(&cf, value);
    if (delete_test && cuckoo_possible) {
        cuckoo_delete(&cf, value);
        cuckoo_after_delete = cuckoo_contains(&cf, value);
    }

    printf("\n%s %s - Verificación de política\n", AGF_APP_NAME, AGF_VERSION);
    printf("-------------------------------------------------\n");
    printf("Tipo:                 %s\n", kind_name);
    printf("Valor:                %s\n", value);
    printf("Lista consultada:      %s\n", list_name);
    printf("Bloom posible:         %s\n", bloom_possible ? "sí" : "no");
    printf("Cuckoo posible:        %s\n", cuckoo_possible ? "sí" : "no");
    if (delete_test) printf("Cuckoo tras borrado:   %s\n", cuckoo_after_delete ? "sí" : "no");
    if (kind == CHECK_FILE) printf("Patrón glob coincide:  %s\n", pattern_match ? "sí" : "no");
    printf("Coincidencia final:    %s\n", matched ? "sí" : "no");
    printf("Decisión:              %s\n", matched ? "WATCH/MATCH" : "NO_MATCH");

    if (report_path && report_path[0]) {
        FILE *out = fopen(report_path, "w");
        if (!out) die_errno("no se pudo escribir reporte JSON de check");
        fprintf(out, "{\n");
        fprintf(out, "  \"software\": \"AgentGuard FastPath\",\n");
        fprintf(out, "  \"version\": \"%s\",\n", AGF_VERSION);
        fprintf(out, "  \"mode\": \"check\",\n");
        fprintf(out, "  \"type\": "); json_write_string(out, kind_name); fprintf(out, ",\n");
        fprintf(out, "  \"value\": "); json_write_string(out, value); fprintf(out, ",\n");
        fprintf(out, "  \"policy_list\": "); json_write_string(out, list_name); fprintf(out, ",\n");
        fprintf(out, "  \"bloom_possible\": %s,\n", bloom_possible ? "true" : "false");
        fprintf(out, "  \"cuckoo_possible\": %s,\n", cuckoo_possible ? "true" : "false");
        fprintf(out, "  \"cuckoo_delete_test_enabled\": %s,\n", delete_test ? "true" : "false");
        fprintf(out, "  \"cuckoo_after_delete\": %s,\n", cuckoo_after_delete ? "true" : "false");
        if (kind == CHECK_FILE) fprintf(out, "  \"glob_pattern_match\": %s,\n", pattern_match ? "true" : "false");
        fprintf(out, "  \"matched\": %s\n", matched ? "true" : "false");
        fprintf(out, "}\n");
        fclose(out);
        printf("Reporte JSON de check guardado en: %s\n", report_path);
    }
    policy_free(&policy);
    return matched ? 0 : 4;
}

static double exact_jaccard_node_relations(const proc_node_t *a, const proc_node_t *b) {
    if (!a || !b) return 0.0;
    size_t inter = 0;
    size_t uni = 0;
    for (size_t i = 0; i < a->files.count; i++) {
        uni++;
        if (list_contains_exact(&b->files, a->files.items[i])) inter++;
    }
    for (size_t i = 0; i < a->destinations.count; i++) {
        uni++;
        if (list_contains_exact(&b->destinations, a->destinations.items[i])) inter++;
    }
    for (size_t i = 0; i < b->files.count; i++) if (!list_contains_exact(&a->files, b->files.items[i])) uni++;
    for (size_t i = 0; i < b->destinations.count; i++) if (!list_contains_exact(&a->destinations, b->destinations.items[i])) uni++;
    return uni ? (double)inter / (double)uni : 1.0;
}

static const proc_node_t *find_first_process_node(const graph_t *graph, const char *name) {
    if (!graph || !name || !name[0]) return NULL;
    for (size_t i = 0; i < graph->count; i++) if (strcmp(graph->items[i].process, name) == 0) return &graph->items[i];
    return NULL;
}

static int run_similarity_command(const char *events_path, const char *policy_path, const char *process_a,
                                  const char *process_b, const char *report_path) {
    if (!process_a || !process_a[0] || !process_b || !process_b[0]) die("similarity requiere --process A --compare-process B");
    policy_t policy;
    graph_t graph = {0};
    uint64_t events_processed = 0, malformed_lines = 0;
    double elapsed_ms = 0.0;
    load_graph_from_events(events_path, policy_path, &graph, &policy, &events_processed, &malformed_lines, &elapsed_ms);
    const proc_node_t *a = find_first_process_node(&graph, process_a);
    const proc_node_t *b = find_first_process_node(&graph, process_b);
    if (!a || !b) {
        printf("No se encontraron ambos procesos para comparar.\n");
        graph_free(&graph); policy_free(&policy); return 3;
    }
    odd_sketch_t ska, skb;
    odd_sketch_from_node(a, &ska);
    odd_sketch_from_node(b, &skb);
    double parity_sim = odd_sketch_parity_similarity(&ska, &skb);
    double exact_j = exact_jaccard_node_relations(a, b);
    size_t hamming = odd_sketch_hamming(&ska, &skb);
    printf("\n%s %s - Similitud de comportamiento\n", AGF_APP_NAME, AGF_VERSION);
    printf("-------------------------------------------------\n");

    printf("Proceso A: %s[%ld] relaciones=%zu\n", a->process, a->pid, a->files.count + a->destinations.count);
    printf("Proceso B: %s[%ld] relaciones=%zu\n", b->process, b->pid, b->files.count + b->destinations.count);
    printf("Jaccard exacto sobre relaciones cargadas: %.4f\n", exact_j);
    printf("Odd Sketch parity similarity:           %.4f\n", parity_sim);
    printf("Distancia de paridad:                   %zu/%u\n", hamming, AGF_ODD_BITS);
    if (report_path && report_path[0]) {
        FILE *out = fopen(report_path, "w");
        if (!out) die_errno("no se pudo escribir reporte JSON de similitud");
        fprintf(out, "{\n  \"software\": \"AgentGuard FastPath\",\n  \"version\": \"%s\",\n  \"mode\": \"similarity\",\n", AGF_VERSION);
        fprintf(out, "  \"process_a\": "); json_write_string(out, process_a); fprintf(out, ",\n");
        fprintf(out, "  \"process_b\": "); json_write_string(out, process_b); fprintf(out, ",\n");
        fprintf(out, "  \"exact_jaccard_relations\": %.6f,\n", exact_j);
        fprintf(out, "  \"odd_sketch_parity_similarity\": %.6f,\n", parity_sim);
        fprintf(out, "  \"parity_hamming_distance\": %zu\n}\n", hamming);
        fclose(out);
        printf("Reporte JSON de similitud guardado en: %s\n", report_path);
    }
    graph_free(&graph);
    policy_free(&policy);
    return 0;
}

static int run_tail_command(const char *events_path, const char *policy_path, bool follow) {
    if (!policy_path || !policy_path[0]) die("tail requiere --policy <policy.json>");
    policy_t policy;
    graph_t graph = {0};
    policy_init(&policy);
    policy_load(&policy, policy_path);
    FILE *fp = fopen(events_path, "r");
    if (!fp) die_errno("no se pudo abrir archivo de eventos para tail");
    printf("%s %s - tail incremental%s\n", AGF_APP_NAME, AGF_VERSION, follow ? " (--follow)" : "");
    printf("-------------------------------------------------\n");
    char *line = NULL;
    size_t line_cap = 0;
    uint64_t processed = 0;
    for (;;) {
        ssize_t n = getline(&line, &line_cap, fp);
        if (n == -1) {
            if (!follow) break;
            clearerr(fp);
            sleep(1);
            continue;
        }
        trim_newline(line);
        if (!line[0] || line[0] == '#') continue;
        event_t ev;
        bool is_header = false;
        if (!parse_event_line(line, &ev, &is_header)) continue;
        processed++;
        graph_ingest_event(&graph, &policy, true, &ev);
        proc_node_t *node = graph_get_or_add(&graph, ev.pid, ev.process);
        const char *matched_dst = NULL;
        dest_match_type_t match_type = DEST_NONE;
        bool watched = policy_is_watched_process(&policy, ev.process);
        bool sensitive = ev.file[0] && policy_is_sensitive_file(&policy, ev.file);
        bool blocked = destination_blocked(&policy, &ev, &matched_dst, &match_type);
        if (watched) printf("[LOW] pid=%ld process=%s proceso vigilado\n", ev.pid, safe_str(ev.process));
        if (sensitive) printf("[MEDIUM] pid=%ld process=%s archivo sensible=%s\n", ev.pid, safe_str(ev.process), ev.file);
        if (blocked) printf("[HIGH] pid=%ld process=%s destino bloqueado=%s\n", ev.pid, safe_str(ev.process), matched_dst);
        if (node->touched_sensitive && node->connected_blocked) {
            compute_risk_for_node(node, &policy);
            printf("[CRITICAL] pid=%ld process=%s riesgo=%d/100 correlación archivo sensible -> red bloqueada\n",
                   ev.pid, safe_str(ev.process), node->risk_score);
        }
    }
    printf("Eventos procesados en tail: %" PRIu64 "\n", processed);
    free(line);
    fclose(fp);
    graph_free(&graph);
    policy_free(&policy);
    return 0;
}

static void json_emit_event(FILE *out, const char *time_s, long pid, const char *process, const char *event,
                            const char *file, const char *dst) {
    fprintf(out, "{\"time\":"); json_write_string(out, time_s);
    fprintf(out, ",\"pid\":%ld,\"process\":", pid); json_write_string(out, process);
    fprintf(out, ",\"event\":"); json_write_string(out, event);
    if (file && file[0]) { fprintf(out, ",\"file\":"); json_write_string(out, file); }
    if (dst && dst[0]) { fprintf(out, ",\"dst\":"); json_write_string(out, dst); }
    fprintf(out, "}\n");
}

static int run_generate_command(uint64_t count, const char *output_path, const char *format, double malicious_ratio) {
    if (!output_path || !output_path[0]) die("generate requiere --output <archivo>");
    if (count == 0) die("generate requiere --events mayor que cero");
    bool csv = format && str_ieq(format, "csv");
    bool jsonl = !format || !format[0] || str_ieq(format, "jsonl") || str_ieq(format, "json");
    if (!csv && !jsonl) die("--format debe ser jsonl o csv");
    if (malicious_ratio < 0.0) malicious_ratio = 0.0;
    if (malicious_ratio > 1.0) malicious_ratio = 1.0;

    FILE *out = fopen(output_path, "w");
    if (!out) die_errno("no se pudo escribir dataset generado");
    const char *procs[] = {"nginx", "postgres", "sshd", "bash", "python", "node", "agent", "curl"};
    const char *events[] = {"open", "read", "write", "connect", "exec", "spawn"};
    const char *files[] = {"/var/log/syslog", "/tmp/cache.db", "/home/alice/app.log", "/etc/hosts", "/srv/app/config.yml"};
    if (csv) fprintf(out, "time,pid,process,event,file,dst,domain,ip\n");

    uint64_t malicious_every = malicious_ratio > 0.0 ? (uint64_t)(1.0 / malicious_ratio) : 0;
    if (malicious_every == 0 && malicious_ratio > 0.0) malicious_every = 1;

    for (uint64_t i = 0; i < count; i++) {
        char time_s[96];
        snprintf(time_s, sizeof(time_s), "2026-05-23T10:%02" PRIu64 ":%02" PRIu64, (i / 60u) % 60u, i % 60u);
        bool malicious = malicious_every && (i % malicious_every == 0);
        long pid = malicious ? 123 : (long)(1000 + (i % 50000));
        const char *process = malicious ? "python" : procs[i % (sizeof(procs) / sizeof(procs[0]))];
        const char *event = malicious ? ((i / malicious_every) % 2u == 0 ? "open" : "connect") : events[i % (sizeof(events) / sizeof(events[0]))];
        char file_buf[AGF_MAX_STR] = "";
        char dst_buf[AGF_MAX_STR] = "";
        const char *file = "";
        const char *dst = "";
        if (malicious) {
            if (strcmp(event, "open") == 0) file = ((i / malicious_every) % 4u == 0) ? "/etc/passwd" : "/home/alice/.ssh/id_rsa";
            else dst = ((i / malicious_every) % 4u == 0) ? "45.90.10.2" : "malicious.example";
        } else {
            if (strcmp(event, "connect") == 0) {
                snprintf(dst_buf, sizeof(dst_buf), "10.%" PRIu64 ".%" PRIu64 ".%" PRIu64, (i / 65536u) % 255u, (i / 256u) % 255u, i % 255u);
                dst = dst_buf;
            } else if (strcmp(event, "open") == 0 || strcmp(event, "read") == 0 || strcmp(event, "write") == 0) {
                snprintf(file_buf, sizeof(file_buf), "%s/%" PRIu64 "/event-%" PRIu64 ".log", files[i % (sizeof(files) / sizeof(files[0]))], i % 1000000u, i);
                file = file_buf;
            }
        }
        if (csv) fprintf(out, "\"%s\",%ld,\"%s\",\"%s\",\"%s\",\"%s\",,\n", time_s, pid, process, event, file, dst);
        else json_emit_event(out, time_s, pid, process, event, file, dst);
    }
    fclose(out);
    printf("Dataset generado: %s\n", output_path);
    printf("Eventos: %" PRIu64 " | formato: %s | malicious_ratio: %.4f\n", count, csv ? "csv" : "jsonl", malicious_ratio);
    return 0;
}
