/**
 * Fragmento modular de agfast: parser.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

typedef struct {
    char time[96];
    long pid;
    char process[128];
    char event[64];
    char file[AGF_MAX_STR];
    char dst[AGF_MAX_STR];
    char domain[AGF_MAX_STR];
    char ip[AGF_MAX_STR];
} event_t;

static bool parse_json_event_line(const char *line, event_t *ev) {
    memset(ev, 0, sizeof(*ev));
    ev->pid = -1;
    json_get_string(line, "time", ev->time, sizeof(ev->time));
    json_get_long(line, "pid", &ev->pid);
    json_get_string(line, "process", ev->process, sizeof(ev->process));
    json_get_string(line, "event", ev->event, sizeof(ev->event));
    json_get_string(line, "file", ev->file, sizeof(ev->file));
    json_get_string(line, "dst", ev->dst, sizeof(ev->dst));
    json_get_string(line, "domain", ev->domain, sizeof(ev->domain));
    json_get_string(line, "ip", ev->ip, sizeof(ev->ip));
    if (!ev->dst[0]) {
        if (ev->ip[0]) copy_trunc(ev->dst, sizeof(ev->dst), ev->ip);
        else if (ev->domain[0]) copy_trunc(ev->dst, sizeof(ev->dst), ev->domain);
    }
    return ev->pid >= 0 || ev->process[0] || ev->event[0];
}

static bool parse_csv_fields(const char *line, char fields[][AGF_MAX_STR], size_t max_fields, size_t *out_count) {
    size_t field = 0;
    const char *p = line;
    while (*p && field < max_fields) {
        size_t n = 0;
        bool quoted = false;
        if (*p == '"') {
            quoted = true;
            p++;
        }
        while (*p) {
            if (quoted) {
                if (*p == '"' && p[1] == '"') {
                    if (n + 1u < AGF_MAX_STR) fields[field][n++] = '"';
                    p += 2;
                    continue;
                }
                if (*p == '"') {
                    p++;
                    quoted = false;
                    break;
                }
            } else if (*p == ',') {
                break;
            }
            if (n + 1u < AGF_MAX_STR) fields[field][n++] = *p;
            p++;
        }
        fields[field][n] = '\0';
        while (*p && *p != ',') p++;
        if (*p == ',') p++;
        field++;
    }
    *out_count = field;
    return field > 0;
}

static bool is_csv_header_fields(char fields[][AGF_MAX_STR], size_t count) {
    if (count < 3) return false;
    return str_ieq(fields[0], "time") && str_ieq(fields[1], "pid") && str_ieq(fields[2], "process");
}

static bool parse_csv_event_line(const char *line, event_t *ev, bool *is_header) {
    char fields[8][AGF_MAX_STR] = {{0}};
    size_t count = 0;
    *is_header = false;
    if (!parse_csv_fields(line, fields, 8, &count)) return false;
    if (is_csv_header_fields(fields, count)) {
        *is_header = true;
        return false;
    }
    memset(ev, 0, sizeof(*ev));
    ev->pid = -1;
    if (count > 0) copy_trunc(ev->time, sizeof(ev->time), fields[0]);
    if (count > 1 && fields[1][0]) {
        char *end = NULL;
        errno = 0;
        long pid = strtol(fields[1], &end, 10);
        if (errno == 0 && end != fields[1]) ev->pid = pid;
    }
    if (count > 2) copy_trunc(ev->process, sizeof(ev->process), fields[2]);
    if (count > 3) copy_trunc(ev->event, sizeof(ev->event), fields[3]);
    if (count > 4) copy_trunc(ev->file, sizeof(ev->file), fields[4]);
    if (count > 5) copy_trunc(ev->dst, sizeof(ev->dst), fields[5]);
    if (count > 6) copy_trunc(ev->domain, sizeof(ev->domain), fields[6]);
    if (count > 7) copy_trunc(ev->ip, sizeof(ev->ip), fields[7]);
    if (!ev->dst[0]) {
        if (ev->ip[0]) copy_trunc(ev->dst, sizeof(ev->dst), ev->ip);
        else if (ev->domain[0]) copy_trunc(ev->dst, sizeof(ev->dst), ev->domain);
    }
    return ev->pid >= 0 || ev->process[0] || ev->event[0];
}

static bool parse_event_line(const char *line, event_t *ev, bool *is_header) {
    *is_header = false;
    const char *p = skip_ws(line);
    if (*p == '{') return parse_json_event_line(p, ev);
    return parse_csv_event_line(p, ev, is_header);
}
