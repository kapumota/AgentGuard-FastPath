#ifndef AGFAST_COMMON_H
#define AGFAST_COMMON_H

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <inttypes.h>
#include <getopt.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define AGF_APP_NAME "AgentGuard FastPath"
#define AGF_VERSION "0.2.0-dev"
#define AGF_MAX_STR 512
#define AGF_BLOOM_BITS (1u << 20)
#define AGF_BLOOM_HASHES 7u
#define AGF_CUCKOO_BUCKETS 4096u
#define AGF_CUCKOO_SLOTS 4u
#define AGF_CUCKOO_MAX_KICKS 64u
#define AGF_CMS_WIDTH 4096u
#define AGF_CMS_DEPTH 5u
#define AGF_HLL_P 14u
#define AGF_HLL_M (1u << AGF_HLL_P)
#define AGF_MAX_CANDIDATES 4096u
#define AGF_GRAPH_PRINT_LIMIT 32u
#define AGF_TIMELINE_PRINT_LIMIT 64u
#define AGF_SPACE_SAVING_K 16u
#define AGF_ODD_BITS 2048u
#define AGF_ODD_BYTES (AGF_ODD_BITS / 8u)
#define AGF_TOP_ALERTS_PRINT 12u
#define AGF_TOP_ITEMS_PRINT 8u

void die(const char *msg);
void die_errno(const char *msg);
char *xstrdup(const char *s);
void copy_trunc(char *dst, size_t dst_size, const char *src);
void trim_newline(char *s);
bool str_ieq(const char *a, const char *b);
bool contains_glob(const char *s);
const char *safe_str(const char *s);
const char *skip_ws(const char *p);
void json_write_string(FILE *out, const char *s);
void html_write_escaped(FILE *out, const char *s);
uint64_t fnv1a64(const char *s);
uint64_t mix64(uint64_t x);

#endif
