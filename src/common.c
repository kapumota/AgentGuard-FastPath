#include "common.h"

/* Implementaciones compartidas por agfast. */

/**
 * @file fastpath.c
 * @brief AgentGuard FastPath v1.0 - analizador de eventos de seguridad.
 *
 * Complementa al monitor AgentGuard-C original. Procesa eventos JSONL/CSV,
 * carga políticas JSON sencillas, usa Bloom Filter, Count-Min Sketch e
 * HyperLogLog, construye relaciones proceso -> archivo -> red, calcula puntajes
 * de riesgo, emite timelines, genera datasets sintéticos y produce reportes
 * JSON/HTML/CSV.
 */



void die(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

void die_errno(const char *msg) {
    fprintf(stderr, "Error: %s: %s\n", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

char *xstrdup(const char *s) {
    char *out = strdup(s ? s : "");
    if (!out) die_errno("memoria insuficiente");
    return out;
}

void copy_trunc(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return;
    const char *s = src ? src : "";
    size_t n = strlen(s);
    if (n >= dst_size) n = dst_size - 1;
    memcpy(dst, s, n);
    dst[n] = '\0';
}

void trim_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

bool str_ieq(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

bool contains_glob(const char *s) {
    return s && (strchr(s, '*') || strchr(s, '?') || strchr(s, '['));
}

const char *safe_str(const char *s) {
    return (s && s[0]) ? s : "-";
}

const char *skip_ws(const char *p) {
    while (p && *p && isspace((unsigned char)*p)) p++;
    return p ? p : "";
}

void json_write_string(FILE *out, const char *s) {
    fputc('"', out);
    if (s) {
        for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
            switch (*p) {
                case '"': fputs("\\\"", out); break;
                case '\\': fputs("\\\\", out); break;
                case '\n': fputs("\\n", out); break;
                case '\r': fputs("\\r", out); break;
                case '\t': fputs("\\t", out); break;
                default:
                    if (*p < 32) fprintf(out, "\\u%04x", *p);
                    else fputc(*p, out);
                    break;
            }
        }
    }
    fputc('"', out);
}

void html_write_escaped(FILE *out, const char *s) {
    if (!s) return;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        switch (*p) {
            case '&': fputs("&amp;", out); break;
            case '<': fputs("&lt;", out); break;
            case '>': fputs("&gt;", out); break;
            case '"': fputs("&quot;", out); break;
            default: fputc(*p, out); break;
        }
    }
}

uint64_t fnv1a64(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (s && *s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}
