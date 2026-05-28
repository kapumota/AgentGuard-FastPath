/**
 * @file integrity.h
 * @brief Monitoreo de integridad de archivos (FIM)
 * 
 * Inspirado en:
 *   - Tsinghua OpenClaw: SBOM y verificación de integridad
 *   - CMU Aegis-4: validación de integridad de sensores
 *   - ETH Zurich: verificación criptográfica
 */

#ifndef AG_INTEGRITY_H
#define AG_INTEGRITY_H

#include "agentguard.h"

/* Resultado de verificación de integridad */
typedef enum {
    AG_INTEGRITY_OK = 0,
    AG_INTEGRITY_MODIFIED = 1,
    AG_INTEGRITY_MISSING = 2,
    AG_INTEGRITY_ADDED = 3,
    AG_INTEGRITY_PERMISSION_CHANGED = 4,
    AG_INTEGRITY_OWNER_CHANGED = 5,
    AG_INTEGRITY_HASH_MISMATCH = 6
} ag_integrity_result_t;

/* Registro de integridad de archivo */
typedef struct {
    char path[AG_MAX_PATH_LEN];
    char hash[AG_HASH_LEN + 1];
    char hash_algo[16];
    mode_t mode;
    uid_t uid;
    gid_t gid;
    off_t size;
    time_t mtime;
    time_t ctime;
    bool is_directory;
    bool is_critical;
} ag_integrity_record_t;

/* Base de datos de integridad */
typedef struct {
    ag_integrity_record_t records[AG_MAX_INTEGRITY_FILES];
    int record_count;
    char db_path[AG_MAX_PATH_LEN];
    time_t last_check;
    time_t check_interval;
    bool auto_repair;
} ag_integrity_db_t;

extern ag_integrity_db_t g_integrity;

/* Ciclo de vida */
int  ag_integrity_init(const char *db_path);
void ag_integrity_free(void);

/* Operaciones de base de datos */
int  ag_integrity_add_file(const char *path);
int  ag_integrity_add_directory(const char *path, bool recursive);
int  ag_integrity_remove_file(const char *path);
int  ag_integrity_update_record(const char *path);

/* Verificación */
int  ag_integrity_check_all(void);
int  ag_integrity_check_file(const char *path, ag_integrity_result_t *result);
int  ag_integrity_check_directory(const char *path);

/* Reportes */
void ag_integrity_print_report(void);
int  ag_integrity_generate_report(const char *path);
void ag_integrity_print_baseline(void);

/* Gestión de línea base */
int  ag_integrity_create_baseline(void);
int  ag_integrity_load_baseline(const char *path);
int  ag_integrity_save_baseline(const char *path);

#endif /* AG_INTEGRITY_H */
