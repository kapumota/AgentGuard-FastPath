/**
 * Fragmento modular de agfast: common.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

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

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <getopt.h>
#include <inttypes.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define AGF_VERSION "1.1.0-final"
#define AGF_BLOOM_BITS (1u << 20)
#define AGF_BLOOM_HASHES 7u
#define AGF_MAX_STR 512
#define AGF_TOP_ALERTS_PRINT 12u
#define AGF_TOP_ITEMS_PRINT 8u
#define AGF_CMS_WIDTH 4096u
#define AGF_CMS_DEPTH 5u
#define AGF_HLL_P 14u
#define AGF_HLL_M (1u << AGF_HLL_P)
#define AGF_MAX_CANDIDATES 4096u
#define AGF_GRAPH_PRINT_LIMIT 32u
#define AGF_TIMELINE_PRINT_LIMIT 64u
#define AGF_SPACE_SAVING_K 16u
#define AGF_CUCKOO_BUCKETS 4096u
#define AGF_CUCKOO_SLOTS 4u
#define AGF_CUCKOO_MAX_KICKS 64u
#define AGF_ODD_BITS 2048u
#define AGF_ODD_BYTES (AGF_ODD_BITS / 8u)

static void die(const char *msg) {
    fprintf(stderr, "Error: %s\n", msg);
    exit(EXIT_FAILURE);
}

static void die_errno(const char *msg) {
    fprintf(stderr, "Error: %s: %s\n", msg, strerror(errno));
    exit(EXIT_FAILURE);
}

static char *xstrdup(const char *s) {
    char *out = strdup(s ? s : "");
    if (!out) die_errno("memoria insuficiente");
    return out;
}

static void copy_trunc(char *dst, size_t dst_size, const char *src) {
    if (!dst || dst_size == 0) return;
    const char *s = src ? src : "";
    size_t n = strlen(s);
    if (n >= dst_size) n = dst_size - 1;
    memcpy(dst, s, n);
    dst[n] = '\0';
}

static void trim_newline(char *s) {
    if (!s) return;
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r')) s[--n] = '\0';
}

static bool str_ieq(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return false;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static bool contains_glob(const char *s) {
    return s && (strchr(s, '*') || strchr(s, '?') || strchr(s, '['));
}

static const char *safe_str(const char *s) {
    return (s && s[0]) ? s : "-";
}

static const char *skip_ws(const char *p) {
    while (p && *p && isspace((unsigned char)*p)) p++;
    return p ? p : "";
}

static void json_write_string(FILE *out, const char *s) {
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

static void html_write_escaped(FILE *out, const char *s) {
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
