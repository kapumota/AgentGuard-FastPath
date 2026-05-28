/**
 * @file utils.h
 * @brief Funciones utilitarias and data structures
 */

#ifndef AG_UTILS_H
#define AG_UTILS_H

#include "agentguard.h"

/* Cadena dinámica simple */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} ag_string_t;

/* Arreglo dinámico simple para enteros */
typedef struct {
    int *data;
    size_t len;
    size_t cap;
} ag_int_array_t;

/* Arreglo dinámico simple para cadenas */
typedef struct {
    char **data;
    size_t len;
    size_t cap;
} ag_str_array_t;

/* Utilidades de marca de tiempo */
char* ag_timestamp_iso8601(char *buf, size_t buflen);
char* ag_timestamp_human(char *buf, size_t buflen);
uint64_t ag_timestamp_ns(void);

/* Utilidades de cadenas */
char* ag_str_trim(char *str);
char* ag_str_dup(const char *src);
size_t ag_strlcpy(char *dst, const char *src, size_t dst_size);
int   ag_str_startswith(const char *str, const char *prefix);
int   ag_str_endswith(const char *str, const char *suffix);
void  ag_str_tolower(char *str);
void  ag_str_replace_char(char *str, char from, char to);

/* Utilidades de archivos */
int   ag_file_exists(const char *path);
int   ag_file_readable(const char *path);
off_t ag_file_size(const char *path);
int   ag_file_copy(const char *src, const char *dst);
int   ag_file_mkdir_p(const char *path);
char* ag_file_read_all(const char *path, size_t *outlen);
int   ag_file_write_all(const char *path, const char *data, size_t len);

/* Utilidades hash (estilo SHA256 simple para fines académicos) */
void  ag_hash_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void  ag_hash_to_hex(const uint8_t hash[32], char hex[AG_HASH_LEN + 1]);
int   ag_hash_file(const char *path, char hex[AG_HASH_LEN + 1]);

/* Utilidades de procesos */
pid_t ag_proc_find_by_name(const char *name);
int   ag_proc_get_comm(pid_t pid, char *buf, size_t buflen);
int   ag_proc_get_exe(pid_t pid, char *buf, size_t buflen);
int   ag_proc_get_cwd(pid_t pid, char *buf, size_t buflen);
int   ag_proc_get_uid_gid(pid_t pid, uid_t *uid, gid_t *gid);
int   ag_proc_list_fds(pid_t pid, ag_int_array_t *fds);
int   ag_proc_get_fd_path(pid_t pid, int fd, char *buf, size_t buflen);

/* Utilidades de memoria */
void* ag_malloc(size_t size);
void* ag_calloc(size_t nmemb, size_t size);
void* ag_realloc(void *ptr, size_t size);
void  ag_free(void *ptr);

/* Utilidades de registro */
void ag_log(ag_log_level_t level, const char *fmt, ...);
void ag_log_raw(const char *fmt, ...);
void ag_set_log_level(ag_log_level_t level);
void ag_set_log_file(const char *path);
void ag_close_log_file(void);

/* Manejo de errores */
void ag_perror(const char *msg);
void ag_die(const char *fmt, ...);

/* Formateador simple estilo JSON */
void ag_json_begin_object(char *buf, size_t buflen, size_t *pos);
void ag_json_end_object(char *buf, size_t buflen, size_t *pos);
void ag_json_add_string(char *buf, size_t buflen, size_t *pos, 
                        const char *key, const char *val);
void ag_json_add_int(char *buf, size_t buflen, size_t *pos, 
                     const char *key, int64_t val);
void ag_json_add_bool(char *buf, size_t buflen, size_t *pos, 
                      const char *key, bool val);

#endif /* AG_UTILS_H */
