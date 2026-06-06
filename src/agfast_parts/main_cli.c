/**
 * Fragmento modular de agfast: main_cli.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

static void print_usage(const char *prog) {
    printf("%s %s\n", AGF_APP_NAME, AGF_VERSION);
    printf("Analizador de eventos de seguridad con Bloom Filter, Count-Min Sketch, HyperLogLog, riesgo, timeline, HTML y CSV.\n\n");
    printf("Uso:\n");
    printf("  %s analyze <events.jsonl|events.csv> --policy <policy.json> [--risk] [--window-events <n>] [--report <report.json>] [--html <report.html>] [--alerts-csv <alerts.csv>]\n", prog);
    printf("  %s stats <events.jsonl|events.csv> [--window-events <n>] [--report <report.json>] [--html <report.html>]\n", prog);
    printf("  %s graph <events.jsonl|events.csv> [--policy <policy.json>] [--pid <pid>] [--process <name>] [--timeline] [--report <report.json>]\n", prog);
    printf("  %s timeline <events.jsonl|events.csv> [--policy <policy.json>] [--pid <pid>] [--process <name>] [--report <report.json>]\n", prog);
    printf("  %s generate --events <n> --output <archivo> [--format jsonl|csv] [--malicious-ratio <0..1>]\n", prog);
    printf("  %s tail <events.jsonl|events.csv> --policy <policy.json> [--follow]\n", prog);
    printf("  %s similarity <events.jsonl|events.csv> --process <A> --compare-process <B> [--policy <policy.json>] [--report <report.json>]\n", prog);
    printf("  %s check-file <ruta> --policy <policy.json> [--delete-test] [--report <report.json>]\n", prog);
    printf("  %s check-ip <ip> --policy <policy.json> [--delete-test] [--report <report.json>]\n", prog);
    printf("  %s check-domain <dominio> --policy <policy.json> [--delete-test] [--report <report.json>]\n", prog);
    printf("  %s --help | --version\n\n", prog);
    printf("Ejemplos:\n");
    printf("  %s analyze examples/events.jsonl --policy examples/policy.json --risk --html report.html --alerts-csv alerts.csv\n", prog);
    printf("  %s timeline examples/events_day3.jsonl --policy examples/policy.json --pid 123\n", prog);
    printf("  %s generate --events 100000 --output /tmp/events.jsonl --malicious-ratio 0.05\n", prog);
    printf("  %s similarity examples/events_day3.jsonl --process python --compare-process bash --policy examples/policy.json\n", prog);
}


int main(int argc, char **argv) {
    static struct option opts[] = {
        {"policy", required_argument, 0, 'p'},
        {"report", required_argument, 0, 'r'},
        {"html", required_argument, 0, 'H'},
        {"alerts-csv", required_argument, 0, 'A'},
        {"pid", required_argument, 0, 'P'},
        {"process", required_argument, 0, 'x'},
        {"timeline", no_argument, 0, 't'},
        {"risk", no_argument, 0, 'R'},
        {"events", required_argument, 0, 'n'},
        {"output", required_argument, 0, 'o'},
        {"format", required_argument, 0, 'f'},
        {"malicious-ratio", required_argument, 0, 'm'},
        {"window-events", required_argument, 0, 'w'},
        {"compare-process", required_argument, 0, 'c'},
        {"follow", no_argument, 0, 'F'},
        {"delete-test", no_argument, 0, 'D'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0}
    };

    if (argc < 2) { print_usage(argv[0]); return 1; }
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) { print_usage(argv[0]); return 0; }
    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) { printf("%s %s\n", AGF_APP_NAME, AGF_VERSION); return 0; }

    enum { MODE_ANALYZE, MODE_STATS, MODE_GRAPH, MODE_TIMELINE, MODE_GENERATE, MODE_TAIL, MODE_SIMILARITY, MODE_CHECK_FILE, MODE_CHECK_IP, MODE_CHECK_DOMAIN } mode;
    if (strcmp(argv[1], "analyze") == 0) mode = MODE_ANALYZE;
    else if (strcmp(argv[1], "stats") == 0) mode = MODE_STATS;
    else if (strcmp(argv[1], "graph") == 0) mode = MODE_GRAPH;
    else if (strcmp(argv[1], "timeline") == 0) mode = MODE_TIMELINE;
    else if (strcmp(argv[1], "generate") == 0) mode = MODE_GENERATE;
    else if (strcmp(argv[1], "tail") == 0) mode = MODE_TAIL;
    else if (strcmp(argv[1], "similarity") == 0) mode = MODE_SIMILARITY;
    else if (strcmp(argv[1], "check-file") == 0) mode = MODE_CHECK_FILE;
    else if (strcmp(argv[1], "check-ip") == 0) mode = MODE_CHECK_IP;
    else if (strcmp(argv[1], "check-domain") == 0) mode = MODE_CHECK_DOMAIN;
    else { print_usage(argv[0]); return 1; }

    const char *input_path_or_value = NULL;
    int options_start = 2;
    if (mode != MODE_GENERATE) {
        if (argc < 3) { print_usage(argv[0]); return 1; }
        input_path_or_value = argv[2];
        options_start = 3;
    }

    const char *policy_path = NULL;
    const char *report_path = NULL;
    const char *html_path = NULL;
    const char *alerts_csv_path = NULL;
    const char *output_path = NULL;
    const char *format = "jsonl";
    long filter_pid = -1;
    const char *filter_process = NULL;
    bool include_timeline = false;
    bool show_risk = false;
    bool follow = false;
    bool delete_test = false;
    uint64_t gen_events = 0;
    uint64_t window_events = 0;
    const char *compare_process = NULL;
    double malicious_ratio = 0.02;

    optind = options_start;
    int c;
    while ((c = getopt_long(argc, argv, "p:r:H:A:P:x:tRn:o:f:m:w:c:FDhV", opts, NULL)) != -1) {
        switch (c) {
            case 'p': policy_path = optarg; break;
            case 'r': report_path = optarg; break;
            case 'H': html_path = optarg; break;
            case 'A': alerts_csv_path = optarg; break;
            case 'P': {
                char *end = NULL; errno = 0; filter_pid = strtol(optarg, &end, 10);
                if (errno != 0 || end == optarg || *end != '\0' || filter_pid < 0) die("--pid debe ser un entero no negativo");
                break;
            }
            case 'x': filter_process = optarg; break;
            case 't': include_timeline = true; break;
            case 'R': show_risk = true; break;
            case 'n': {
                char *end = NULL; errno = 0; unsigned long long v = strtoull(optarg, &end, 10);
                if (errno != 0 || end == optarg || *end != '\0') die("--events debe ser un entero no negativo");
                gen_events = (uint64_t)v; break;
            }
            case 'o': output_path = optarg; break;
            case 'f': format = optarg; break;
            case 'm': {
                char *end = NULL; errno = 0; malicious_ratio = strtod(optarg, &end);
                if (errno != 0 || end == optarg || *end != '\0') die("--malicious-ratio debe ser numérico");
                break;
            }
            case 'w': {
                char *end = NULL; errno = 0; unsigned long long v = strtoull(optarg, &end, 10);
                if (errno != 0 || end == optarg || *end != '\0' || v == 0) die("--window-events debe ser entero positivo");
                window_events = (uint64_t)v; break;
            }
            case 'c': compare_process = optarg; break;
            case 'F': follow = true; break;
            case 'D': delete_test = true; break;
            case 'h': print_usage(argv[0]); return 0;
            case 'V': printf("%s %s\n", AGF_APP_NAME, AGF_VERSION); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    if (mode == MODE_GENERATE) return run_generate_command(gen_events, output_path, format, malicious_ratio);
    if (mode == MODE_TAIL) return run_tail_command(input_path_or_value, policy_path, follow);
    if (mode == MODE_SIMILARITY) return run_similarity_command(input_path_or_value, policy_path, filter_process, compare_process, report_path);
    if (mode == MODE_CHECK_FILE) return run_check_command(CHECK_FILE, input_path_or_value, policy_path, report_path, delete_test);
    if (mode == MODE_CHECK_IP) return run_check_command(CHECK_IP, input_path_or_value, policy_path, report_path, delete_test);
    if (mode == MODE_CHECK_DOMAIN) return run_check_command(CHECK_DOMAIN, input_path_or_value, policy_path, report_path, delete_test);
    if (mode == MODE_GRAPH) return run_graph_command(input_path_or_value, policy_path, filter_pid, filter_process, report_path, include_timeline);
    if (mode == MODE_TIMELINE) return run_timeline_command(input_path_or_value, policy_path, filter_pid, filter_process, report_path);
    return process_events(input_path_or_value, policy_path, report_path, html_path, alerts_csv_path, mode == MODE_ANALYZE, show_risk, window_events);
}
