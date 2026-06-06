/**
 * Fragmento modular de agfast: sketches.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

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
