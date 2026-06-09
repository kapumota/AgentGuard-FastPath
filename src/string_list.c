#include "string_list.h"

/* Lista dinamica de cadenas usada por politica, grafo y reportes. */

void list_add(string_list_t *list, const char *value) {
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

void list_add_unique(string_list_t *list, const char *value) {
    if (!value || !value[0]) return;
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], value) == 0) return;
    }
    list_add(list, value);
}

bool list_contains_exact(const string_list_t *list, const char *value) {
    if (!list || !value) return false;
    for (size_t i = 0; i < list->count; i++) {
        if (strcmp(list->items[i], value) == 0) return true;
    }
    return false;
}

bool list_matches_pattern(const string_list_t *patterns, const char *value) {
    if (!patterns || !value) return false;
    for (size_t i = 0; i < patterns->count; i++) {
        if (fnmatch(patterns->items[i], value, 0) == 0) return true;
    }
    return false;
}

void list_print_limited(const string_list_t *list, const char *label, size_t limit) {
    printf("  %s:\n", label);
    if (!list || list->count == 0) {
        printf("    -\n");
        return;
    }
    size_t n = list->count < limit ? list->count : limit;
    for (size_t i = 0; i < n; i++) printf("    - %s\n", list->items[i]);
    if (list->count > n) printf("    ... %zu elementos adicionales\n", list->count - n);
}

void json_write_string_array(FILE *out, const char *name, const string_list_t *list, bool trailing_comma) {
    fprintf(out, "\"%s\": [", name);
    if (list) {
        for (size_t i = 0; i < list->count; i++) {
            if (i) fprintf(out, ", ");
            json_write_string(out, list->items[i]);
        }
    }
    fprintf(out, "]%s", trailing_comma ? "," : "");
}

void list_free(string_list_t *list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) free(list->items[i]);
    free(list->items);
    memset(list, 0, sizeof(*list));
}
