#ifndef AGFAST_STRING_LIST_H
#define AGFAST_STRING_LIST_H

#include "common.h"

typedef struct {
    char **items;
    size_t count;
    size_t cap;
} string_list_t;

void list_add(string_list_t *list, const char *value);
void list_add_unique(string_list_t *list, const char *value);
bool list_contains_exact(const string_list_t *list, const char *value);
bool list_matches_pattern(const string_list_t *patterns, const char *value);
void list_print_limited(const string_list_t *list, const char *label, size_t limit);
void json_write_string_array(FILE *out, const char *name, const string_list_t *list, bool trailing_comma);
void list_free(string_list_t *list);

#endif
