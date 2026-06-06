/**
 * Fragmento modular de agfast: policy.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

typedef struct {
    int watched_process;
    int sensitive_file;
    int blocked_ip;
    int blocked_domain;
    int network_after_file;
    int high_unique_destinations;
    int high_event_volume;
    int high_unique_destination_threshold;
    int high_event_volume_threshold;
} risk_weights_t;

typedef struct {
    string_list_t sensitive_files;
    string_list_t sensitive_file_patterns;
    string_list_t blocked_domains;
    string_list_t blocked_ips;
    string_list_t watched_processes;
    bloom_t sensitive_files_bloom;
    bloom_t blocked_domains_bloom;
    bloom_t blocked_ips_bloom;
    bloom_t watched_processes_bloom;
    risk_weights_t weights;
} policy_t;

static void risk_weights_set_defaults(risk_weights_t *w) {
    w->watched_process = 10;
    w->sensitive_file = 25;
    w->blocked_ip = 35;
    w->blocked_domain = 35;
    w->network_after_file = 30;
    w->high_unique_destinations = 15;
    w->high_event_volume = 10;
    w->high_unique_destination_threshold = 10;
    w->high_event_volume_threshold = 100;
}

static char *read_entire_file(const char *path) {
    FILE *fp = fopen(path, "rb");
    if (!fp) die_errno("no se pudo abrir archivo");
    if (fseek(fp, 0, SEEK_END) != 0) die_errno("fseek falló");
    long size = ftell(fp);
    if (size < 0) die_errno("ftell falló");
    rewind(fp);
    char *buf = calloc((size_t)size + 1u, 1);
    if (!buf) die_errno("memoria insuficiente");
    if (fread(buf, 1, (size_t)size, fp) != (size_t)size && ferror(fp)) die_errno("no se pudo leer archivo");
    fclose(fp);
    return buf;
}

static bool parse_json_string_token(const char **cursor, char *out, size_t out_size) {
    const char *p = skip_ws(*cursor);
    if (*p != '"') return false;
    p++;
    size_t n = 0;
    while (*p && *p != '"') {
        char c = *p++;
        if (c == '\\' && *p) {
            char esc = *p++;
            switch (esc) {
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                default: c = esc; break;
            }
        }
        if (n + 1u < out_size) out[n++] = c;
    }
    if (*p != '"') return false;
    out[n] = '\0';
    *cursor = p + 1;
    return true;
}

static bool json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    char needle[96];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p++;
    return parse_json_string_token(&p, out, out_size);
}

static bool json_get_long(const char *json, const char *key, long *out) {
    char needle[96];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return false;
    p = strchr(p, ':');
    if (!p) return false;
    p = skip_ws(p + 1);
    char *end = NULL;
    errno = 0;
    long v = strtol(p, &end, 10);
    if (errno != 0 || end == p) return false;
    *out = v;
    return true;
}

static bool json_get_int(const char *json, const char *key, int *out) {
    long v;
    if (!json_get_long(json, key, &v)) return false;
    if (v < -1000000L) v = -1000000L;
    if (v > 1000000L) v = 1000000L;
    *out = (int)v;
    return true;
}

static void parse_policy_array(const char *json, const char *key, string_list_t *exact,
                               string_list_t *patterns, bloom_t *bloom) {
    char needle[128];
    snprintf(needle, sizeof(needle), "\"%s\"", key);
    const char *p = strstr(json, needle);
    if (!p) return;
    p = strchr(p, '[');
    if (!p) return;
    p++;
    while (*p) {
        p = skip_ws(p);
        if (*p == ']') break;
        if (*p == ',') { p++; continue; }
        char value[AGF_MAX_STR];
        if (!parse_json_string_token(&p, value, sizeof(value))) break;
        if (contains_glob(value) && patterns) list_add(patterns, value);
        else {
            list_add(exact, value);
            if (bloom) bloom_add(bloom, value);
        }
    }
}

static void parse_risk_weights(const char *json, risk_weights_t *w) {
    json_get_int(json, "watched_process", &w->watched_process);
    json_get_int(json, "sensitive_file", &w->sensitive_file);
    json_get_int(json, "blocked_ip", &w->blocked_ip);
    json_get_int(json, "blocked_domain", &w->blocked_domain);
    json_get_int(json, "network_after_file", &w->network_after_file);
    json_get_int(json, "high_unique_destinations", &w->high_unique_destinations);
    json_get_int(json, "high_event_volume", &w->high_event_volume);
    json_get_int(json, "high_unique_destination_threshold", &w->high_unique_destination_threshold);
    json_get_int(json, "high_event_volume_threshold", &w->high_event_volume_threshold);
}

static void policy_init(policy_t *policy) {
    memset(policy, 0, sizeof(*policy));
    risk_weights_set_defaults(&policy->weights);
    bloom_init(&policy->sensitive_files_bloom, AGF_BLOOM_BITS, AGF_BLOOM_HASHES);
    bloom_init(&policy->blocked_domains_bloom, AGF_BLOOM_BITS, AGF_BLOOM_HASHES);
    bloom_init(&policy->blocked_ips_bloom, AGF_BLOOM_BITS, AGF_BLOOM_HASHES);
    bloom_init(&policy->watched_processes_bloom, AGF_BLOOM_BITS, AGF_BLOOM_HASHES);
}

static void policy_load(policy_t *policy, const char *path) {
    char *json = read_entire_file(path);
    parse_policy_array(json, "sensitive_files", &policy->sensitive_files,
                       &policy->sensitive_file_patterns, &policy->sensitive_files_bloom);
    parse_policy_array(json, "blocked_domains", &policy->blocked_domains, NULL, &policy->blocked_domains_bloom);
    parse_policy_array(json, "blocked_ips", &policy->blocked_ips, NULL, &policy->blocked_ips_bloom);
    parse_policy_array(json, "watched_processes", &policy->watched_processes, NULL, &policy->watched_processes_bloom);
    parse_risk_weights(json, &policy->weights);
    free(json);
}

static bool policy_match_exact_with_bloom(const bloom_t *bloom, const string_list_t *list, const char *value) {
    if (!value || !value[0]) return false;
    if (!bloom_might_contain(bloom, value)) return false;
    return list_contains_exact(list, value);
}

static bool policy_is_sensitive_file(const policy_t *policy, const char *file) {
    return policy_match_exact_with_bloom(&policy->sensitive_files_bloom, &policy->sensitive_files, file) ||
           list_matches_pattern(&policy->sensitive_file_patterns, file);
}

static bool policy_is_blocked_domain(const policy_t *policy, const char *domain) {
    return policy_match_exact_with_bloom(&policy->blocked_domains_bloom, &policy->blocked_domains, domain);
}

static bool policy_is_blocked_ip(const policy_t *policy, const char *ip) {
    return policy_match_exact_with_bloom(&policy->blocked_ips_bloom, &policy->blocked_ips, ip);
}

static bool policy_is_watched_process(const policy_t *policy, const char *process) {
    return policy_match_exact_with_bloom(&policy->watched_processes_bloom, &policy->watched_processes, process);
}

static bool policy_check_file_with_details(const policy_t *policy, const char *file,
                                           bool *bloom_possible, bool *pattern_match) {
    *bloom_possible = bloom_might_contain(&policy->sensitive_files_bloom, file);
    *pattern_match = list_matches_pattern(&policy->sensitive_file_patterns, file);
    return (*bloom_possible && list_contains_exact(&policy->sensitive_files, file)) || *pattern_match;
}

static bool policy_check_ip_with_details(const policy_t *policy, const char *ip, bool *bloom_possible) {
    *bloom_possible = bloom_might_contain(&policy->blocked_ips_bloom, ip);
    return *bloom_possible && list_contains_exact(&policy->blocked_ips, ip);
}

static bool policy_check_domain_with_details(const policy_t *policy, const char *domain, bool *bloom_possible) {
    *bloom_possible = bloom_might_contain(&policy->blocked_domains_bloom, domain);
    return *bloom_possible && list_contains_exact(&policy->blocked_domains, domain);
}

static void policy_free(policy_t *policy) {
    list_free(&policy->sensitive_files);
    list_free(&policy->sensitive_file_patterns);
    list_free(&policy->blocked_domains);
    list_free(&policy->blocked_ips);
    list_free(&policy->watched_processes);
    bloom_free(&policy->sensitive_files_bloom);
    bloom_free(&policy->blocked_domains_bloom);
    bloom_free(&policy->blocked_ips_bloom);
    bloom_free(&policy->watched_processes_bloom);
}
