/**
 * Fragmento modular de agfast: string_list.c.
 *
 * Este archivo se incluye desde src/fastpath.c para conservar una sola
 * unidad de traduccion durante la primera etapa de modularizacion.
 * No debe compilarse de forma aislada todavia.
 */

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
