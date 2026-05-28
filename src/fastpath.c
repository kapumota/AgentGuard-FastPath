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

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} string_list_t;

static void list_add(string_list_t *list, const char *value) {
    if (!value || !value[0]) return;
    if (list->count == list->cap) {
        size_t new_cap = list->cap ? list->cap * 2u : 16u;
        char **new_items = realloc(list->items, new_cap * sizeof(char *));
        if (!new_items) die_errno("memoria insuficiente");
        list->items = new_items;
        list->cap = new_cap;
    }
    list->items[list->count++] = xstrdup(value);
}

static void list_add_unique(string_list_t *list, const char *value) {
    if (!value || !value[0]) return;
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], value) == 0) return;
    }
    list_add(list, value);
}

static bool list_contains_exact(const string_list_t *list, const char *value) {
    if (!list || !value) return false;
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], value) == 0) return true;
    }
    return false;
}

static bool list_matches_pattern(const string_list_t *patterns, const char *value) {
    if (!patterns || !value) return false;
    for (size_t i = 0; i < patterns->count; i++) {
        if (fnmatch(patterns->items[i], value, 0) == 0) return true;
    }
    return false;
}

static void list_print_limited(const string_list_t *list, const char *label, size_t limit) {
    printf("  %s:\n", label);
    if (!list || list->count == 0) {
        printf("    -\n");
        return;
    }
    size_t n = list->count < limit ? list->count : limit;
    for (size_t i = 0; i < n; i++) printf("    - %s\n", list->items[i]);
    if (list->count > n) printf("    ... %zu elementos adicionales\n", list->count - n);
}

static void json_write_string_array(FILE *out, const char *name, const string_list_t *list, bool trailing_comma) {
    fprintf(out, "\"%s\": [", name);
    if (list) {
        for (size_t i = 0; i < list->count; i++) {
            if (i) fprintf(out, ", ");
            json_write_string(out, list->items[i]);
        }
    }
    fprintf(out, "]%s", trailing_comma ? "," : "");
}

static void list_free(string_list_t *list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) free(list->items[i]);
    free(list->items);
    memset(list, 0, sizeof(*list));
}

static uint64_t fnv1a64(const char *s) {
    uint64_t h = 1469598103934665603ULL;
    while (s && *s) {
        h ^= (unsigned char)*s++;
        h *= 1099511628211ULL;
    }
    return h;
}

static uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

typedef struct {
    uint8_t *bits;
    size_t bit_count;
    unsigned hashes;
    size_t inserted;
} bloom_t;

static void bloom_init(bloom_t *b, size_t bit_count, unsigned hashes) {
    memset(b, 0, sizeof(*b));
    b->bit_count = bit_count;
    b->hashes = hashes;
    b->bits = calloc((bit_count + 7u) / 8u, 1);
    if (!b->bits) die_errno("no se pudo reservar Bloom Filter");
}

static void bloom_set_bit(bloom_t *b, size_t pos) {
    b->bits[pos / 8u] |= (uint8_t)(1u << (pos % 8u));
}

static bool bloom_get_bit(const bloom_t *b, size_t pos) {
    return (b->bits[pos / 8u] & (uint8_t)(1u << (pos % 8u))) != 0;
}

static void bloom_add(bloom_t *b, const char *value) {
    if (!value || !value[0]) return;
    uint64_t h1 = fnv1a64(value);
    uint64_t h2 = mix64(h1 ^ 0x9e3779b97f4a7c15ULL);
    for (unsigned i = 0; i < b->hashes; i++) {
        size_t pos = (size_t)((h1 + (uint64_t)i * h2 + (uint64_t)i * i) % b->bit_count);
        bloom_set_bit(b, pos);
    }
    b->inserted++;
}

static bool bloom_might_contain(const bloom_t *b, const char *value) {
    if (!value || !value[0]) return false;
    uint64_t h1 = fnv1a64(value);
    uint64_t h2 = mix64(h1 ^ 0x9e3779b97f4a7c15ULL);
    for (unsigned i = 0; i < b->hashes; i++) {
        size_t pos = (size_t)((h1 + (uint64_t)i * h2 + (uint64_t)i * i) % b->bit_count);
        if (!bloom_get_bit(b, pos)) return false;
    }
    return true;
}

static void bloom_free(bloom_t *b) {
    if (!b) return;
    free(b->bits);
    memset(b, 0, sizeof(*b));
}

typedef struct {
    uint16_t buckets[AGF_CUCKOO_BUCKETS][AGF_CUCKOO_SLOTS];
    size_t count;
} cuckoo_filter_t;

static uint16_t cuckoo_fingerprint(const char *value) {
    uint16_t fp = (uint16_t)(mix64(fnv1a64(value)) & 0xffffu);
    return fp ? fp : 1u;
}

static size_t cuckoo_index1(const char *value) {
    return (size_t)(mix64(fnv1a64(value) ^ 0x7f4a7c15ULL) % AGF_CUCKOO_BUCKETS);
}

static size_t cuckoo_alt_index(size_t index, uint16_t fp) {
    return (size_t)((index ^ (mix64((uint64_t)fp * 0x9e3779b97f4a7c15ULL) % AGF_CUCKOO_BUCKETS)) % AGF_CUCKOO_BUCKETS);
}

static void cuckoo_init(cuckoo_filter_t *cf) {
    memset(cf, 0, sizeof(*cf));
}

static bool cuckoo_bucket_contains(const cuckoo_filter_t *cf, size_t idx, uint16_t fp) {
    for (size_t i = 0; i < AGF_CUCKOO_SLOTS; i++) if (cf->buckets[idx][i] == fp) return true;
    return false;
}

static bool cuckoo_bucket_insert(cuckoo_filter_t *cf, size_t idx, uint16_t fp) {
    for (size_t i = 0; i < AGF_CUCKOO_SLOTS; i++) {
        if (cf->buckets[idx][i] == 0) {
            cf->buckets[idx][i] = fp;
            cf->count++;
            return true;
        }
    }
    return false;
}

static bool cuckoo_contains(const cuckoo_filter_t *cf, const char *value) {
    if (!value || !value[0]) return false;
    uint16_t fp = cuckoo_fingerprint(value);
    size_t i1 = cuckoo_index1(value);
    size_t i2 = cuckoo_alt_index(i1, fp);
    return cuckoo_bucket_contains(cf, i1, fp) || cuckoo_bucket_contains(cf, i2, fp);
}

static bool cuckoo_insert(cuckoo_filter_t *cf, const char *value) {
    if (!value || !value[0]) return false;
    uint16_t fp = cuckoo_fingerprint(value);
    size_t i1 = cuckoo_index1(value);
    size_t i2 = cuckoo_alt_index(i1, fp);
    if (cuckoo_bucket_insert(cf, i1, fp) || cuckoo_bucket_insert(cf, i2, fp)) return true;
    size_t idx = (mix64(fnv1a64(value) ^ 0xfeedbeefULL) & 1u) ? i1 : i2;
    for (size_t kick = 0; kick < AGF_CUCKOO_MAX_KICKS; kick++) {
        size_t slot = (size_t)(mix64((uint64_t)fp + kick) % AGF_CUCKOO_SLOTS);
        uint16_t old = cf->buckets[idx][slot];
        cf->buckets[idx][slot] = fp;
        fp = old;
        idx = cuckoo_alt_index(idx, fp);
        if (cuckoo_bucket_insert(cf, idx, fp)) return true;
    }
    return false;
}

static bool cuckoo_delete(cuckoo_filter_t *cf, const char *value) {
    if (!value || !value[0]) return false;
    uint16_t fp = cuckoo_fingerprint(value);
    size_t idxs[2];
    idxs[0] = cuckoo_index1(value);
    idxs[1] = cuckoo_alt_index(idxs[0], fp);
    for (size_t k = 0; k < 2; k++) {
        for (size_t i = 0; i < AGF_CUCKOO_SLOTS; i++) {
            if (cf->buckets[idxs[k]][i] == fp) {
                cf->buckets[idxs[k]][i] = 0;
                if (cf->count) cf->count--;
                return true;
            }
        }
    }
    return false;
}

static void cuckoo_load_from_list(cuckoo_filter_t *cf, const string_list_t *list) {
    cuckoo_init(cf);
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) cuckoo_insert(cf, list->items[i]);
}

typedef struct {
    uint32_t width;
    uint32_t depth;
    uint64_t *table;
} cms_t;

static void cms_init(cms_t *cms, uint32_t width, uint32_t depth) {
    memset(cms, 0, sizeof(*cms));
    cms->width = width;
    cms->depth = depth;
    cms->table = calloc((size_t)width * depth, sizeof(uint64_t));
    if (!cms->table) die_errno("no se pudo reservar Count-Min Sketch");
}

static void cms_add(cms_t *cms, const char *key, uint64_t delta) {
    if (!key || !key[0]) return;
    uint64_t h1 = fnv1a64(key);
    uint64_t h2 = mix64(h1 ^ 0xa0761d6478bd642fULL);
    for (uint32_t row = 0; row < cms->depth; row++) {
        uint32_t col = (uint32_t)((h1 + (uint64_t)row * h2 + row * 0x9e3779b9u) % cms->width);
        cms->table[(size_t)row * cms->width + col] += delta;
    }
}

static uint64_t cms_estimate(const cms_t *cms, const char *key) {
    if (!key || !key[0]) return 0;
    uint64_t h1 = fnv1a64(key);
    uint64_t h2 = mix64(h1 ^ 0xa0761d6478bd642fULL);
    uint64_t best = UINT64_MAX;
    for (uint32_t row = 0; row < cms->depth; row++) {
        uint32_t col = (uint32_t)((h1 + (uint64_t)row * h2 + row * 0x9e3779b9u) % cms->width);
        uint64_t v = cms->table[(size_t)row * cms->width + col];
        if (v < best) best = v;
    }
    return best == UINT64_MAX ? 0 : best;
}

static void cms_free(cms_t *cms) {
    if (!cms) return;
    free(cms->table);
    memset(cms, 0, sizeof(*cms));
}

typedef struct {
    uint8_t registers[AGF_HLL_M];
} hll_t;

static uint8_t hll_rank(uint64_t w) {
    const unsigned remaining_bits = 64u - AGF_HLL_P;
    if (w == 0) return (uint8_t)(remaining_bits + 1u);
#if defined(__GNUC__) || defined(__clang__)
    unsigned leading = (unsigned)__builtin_clzll(w);
    unsigned rank = leading - AGF_HLL_P + 1u;
#else
    unsigned rank = 1u;
    uint64_t mask = 1ULL << (remaining_bits - 1u);
    while ((w & mask) == 0 && rank <= remaining_bits) {
        rank++;
        mask >>= 1u;
    }
#endif
    if (rank > remaining_bits + 1u) rank = remaining_bits + 1u;
    return (uint8_t)rank;
}

static void hll_add(hll_t *hll, const char *key) {
    if (!key || !key[0]) return;
    uint64_t h = mix64(fnv1a64(key));
    uint32_t idx = (uint32_t)(h & (AGF_HLL_M - 1u));
    uint64_t w = h >> AGF_HLL_P;
    uint8_t rank = hll_rank(w);
    if (rank > hll->registers[idx]) hll->registers[idx] = rank;
}

static uint64_t hll_estimate(const hll_t *hll) {
    const double m = (double)AGF_HLL_M;
    const double alpha = 0.7213 / (1.0 + 1.079 / m);
    double sum = 0.0;
    uint32_t zeros = 0;
    for (uint32_t i = 0; i < AGF_HLL_M; i++) {
        uint8_t r = hll->registers[i];
        if (r == 0) zeros++;
        sum += ldexp(1.0, -(int)r);
    }
    double raw = alpha * m * m / sum;
    if (raw <= 2.5 * m && zeros > 0) raw = m * log(m / (double)zeros);
    if (raw < 0.0) raw = 0.0;
    return (uint64_t)(raw + 0.5);
}

typedef struct {
    char **items;
    size_t count;
    size_t cap;
    size_t max_items;
} candidate_list_t;

static void candidates_init(candidate_list_t *c, size_t max_items) {
    memset(c, 0, sizeof(*c));
    c->max_items = max_items;
}

static void candidates_add_unique(candidate_list_t *c, const char *value) {
    if (!value || !value[0] || c->count >= c->max_items) return;
    for (size_t i = 0; i < c->count; i++) {
        if (strcmp(c->items[i], value) == 0) return;
    }
    if (c->count == c->cap) {
        size_t new_cap = c->cap ? c->cap * 2u : 64u;
        if (new_cap > c->max_items) new_cap = c->max_items;
        char **new_items = realloc(c->items, new_cap * sizeof(char *));
        if (!new_items) die_errno("memoria insuficiente");
        c->items = new_items;
        c->cap = new_cap;
    }
    c->items[c->count++] = xstrdup(value);
}

static void candidates_free(candidate_list_t *c) {
    if (!c) return;
    for (size_t i = 0; i < c->count; i++) free(c->items[i]);
    free(c->items);
    memset(c, 0, sizeof(*c));
}

typedef struct {
    const char *key;
    uint64_t estimate;
} top_item_t;

static int top_item_cmp_desc(const void *a, const void *b) {
    const top_item_t *ia = (const top_item_t *)a;
    const top_item_t *ib = (const top_item_t *)b;
    if (ia->estimate < ib->estimate) return 1;
    if (ia->estimate > ib->estimate) return -1;
    return strcmp(ia->key, ib->key);
}

static top_item_t *build_top_items(const candidate_list_t *candidates, const cms_t *cms, size_t *out_count) {
    *out_count = candidates->count;
    if (candidates->count == 0) return NULL;
    top_item_t *items = calloc(candidates->count, sizeof(top_item_t));
    if (!items) die_errno("memoria insuficiente");
    for (size_t i = 0; i < candidates->count; i++) {
        items[i].key = candidates->items[i];
        items[i].estimate = cms_estimate(cms, candidates->items[i]);
    }
    qsort(items, candidates->count, sizeof(top_item_t), top_item_cmp_desc);
    return items;
}

static void print_top_from_cms(const char *title, const candidate_list_t *candidates,
                               const cms_t *cms, size_t limit) {
    size_t count = 0;
    top_item_t *items = build_top_items(candidates, cms, &count);
    printf("\n%s:\n", title);
    if (count == 0) {
        printf("  sin datos\n");
        free(items);
        return;
    }
    if (limit > count) limit = count;
    for (size_t i = 0; i < limit; i++) {
        printf("  %2zu. %-36s ~%" PRIu64 "\n", i + 1, items[i].key, items[i].estimate);
    }
    free(items);
}

static void write_top_json(FILE *out, const char *name, const candidate_list_t *candidates,
                           const cms_t *cms, size_t limit, bool trailing_comma) {
    size_t count = 0;
    top_item_t *items = build_top_items(candidates, cms, &count);
    if (limit > count) limit = count;
    fprintf(out, "    \"%s\": [\n", name);
    for (size_t i = 0; i < limit; i++) {
        fprintf(out, "      {\"key\": ");
        json_write_string(out, items[i].key);
        fprintf(out, ", \"estimate\": %" PRIu64 "}%s\n", items[i].estimate,
                (i + 1 < limit) ? "," : "");
    }
    fprintf(out, "    ]%s\n", trailing_comma ? "," : "");
    free(items);
}

typedef struct {
    char key[AGF_MAX_STR];
    uint64_t count;
    uint64_t error;
} space_saving_item_t;

typedef struct {
    space_saving_item_t items[AGF_SPACE_SAVING_K];
    size_t used;
} space_saving_t;

static void ss_init(space_saving_t *ss) {
    memset(ss, 0, sizeof(*ss));
}

static void ss_update(space_saving_t *ss, const char *key) {
    if (!key || !key[0]) return;
    for (size_t i = 0; i < ss->used; i++) {
        if (strcmp(ss->items[i].key, key) == 0) {
            ss->items[i].count++;
            return;
        }
    }
    if (ss->used < AGF_SPACE_SAVING_K) {
        copy_trunc(ss->items[ss->used].key, sizeof(ss->items[ss->used].key), key);
        ss->items[ss->used].count = 1;
        ss->items[ss->used].error = 0;
        ss->used++;
        return;
    }
    size_t min_i = 0;
    for (size_t i = 1; i < ss->used; i++) if (ss->items[i].count < ss->items[min_i].count) min_i = i;
    uint64_t old = ss->items[min_i].count;
    copy_trunc(ss->items[min_i].key, sizeof(ss->items[min_i].key), key);
    ss->items[min_i].count = old + 1;
    ss->items[min_i].error = old;
}

static int ss_cmp_desc(const void *a, const void *b) {
    const space_saving_item_t *ia = (const space_saving_item_t *)a;
    const space_saving_item_t *ib = (const space_saving_item_t *)b;
    if (ia->count < ib->count) return 1;
    if (ia->count > ib->count) return -1;
    return strcmp(ia->key, ib->key);
}

static void ss_sorted_copy(const space_saving_t *ss, space_saving_item_t out[AGF_SPACE_SAVING_K], size_t *out_count) {
    *out_count = ss->used;
    for (size_t i = 0; i < ss->used; i++) out[i] = ss->items[i];
    qsort(out, *out_count, sizeof(space_saving_item_t), ss_cmp_desc);
}

static void print_space_saving(const char *title, const space_saving_t *ss, size_t limit) {
    space_saving_item_t items[AGF_SPACE_SAVING_K];
    size_t count = 0;
    ss_sorted_copy(ss, items, &count);
    printf("\n%s - Space-Saving/Misra-Gries:\n", title);
    if (count == 0) { printf("  sin datos\n"); return; }
    if (limit > count) limit = count;
    for (size_t i = 0; i < limit; i++) {
        printf("  %2zu. %-36s >=%" PRIu64 " <=%" PRIu64 "\n", i + 1, items[i].key,
               items[i].count > items[i].error ? items[i].count - items[i].error : 0,
               items[i].count);
    }
}

static void write_space_saving_json(FILE *out, const char *name, const space_saving_t *ss, size_t limit, bool trailing_comma) {
    space_saving_item_t items[AGF_SPACE_SAVING_K];
    size_t count = 0;
    ss_sorted_copy(ss, items, &count);
    if (limit > count) limit = count;
    fprintf(out, "  \"%s\": [\n", name);
    for (size_t i = 0; i < limit; i++) {
        fprintf(out, "    {\"key\": "); json_write_string(out, items[i].key);
        fprintf(out, ", \"lower_bound\": %" PRIu64 ", \"upper_bound\": %" PRIu64 "}%s\n",
                items[i].count > items[i].error ? items[i].count - items[i].error : 0,
                items[i].count, (i + 1 < limit) ? "," : "");
    }
    fprintf(out, "  ]%s\n", trailing_comma ? "," : "");
}

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

    printf("\nAgentGuard FastPath v%s - Reporte final\n", AGF_VERSION);
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

    printf("\nAgentGuard FastPath v%s - Consulta de grafo\n", AGF_VERSION);
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

    printf("\nAgentGuard FastPath v%s - Timeline por proceso\n", AGF_VERSION);
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

    printf("\nAgentGuard FastPath v%s - Verificación de política\n", AGF_VERSION);
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
    printf("\nAgentGuard FastPath v%s - Similitud de comportamiento\n", AGF_VERSION);
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
    printf("AgentGuard FastPath v%s - tail incremental%s\n", AGF_VERSION, follow ? " (--follow)" : "");
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

static void print_usage(const char *prog) {
    printf("AgentGuard FastPath v%s\n", AGF_VERSION);
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
    if (strcmp(argv[1], "--version") == 0 || strcmp(argv[1], "-V") == 0) { printf("AgentGuard FastPath v%s\n", AGF_VERSION); return 0; }

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
            case 'V': printf("AgentGuard FastPath v%s\n", AGF_VERSION); return 0;
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
