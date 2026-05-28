/**
 * @file integrity.c
 * @brief Monitoreo de integridad de archivos (FIM)
 * 
 * Inspirado en la verificación SBOM de Tsinghua OpenClaw y la integridad de sensores de CMU Aegis-4.
 */

#include "agentguard.h"
#include "utils.h"
#include "integrity.h"

ag_integrity_db_t g_integrity = {0};

int ag_integrity_init(const char *db_path) {
    memset(&g_integrity, 0, sizeof(g_integrity));

    if (db_path) {
        ag_strlcpy(g_integrity.db_path, db_path, sizeof(g_integrity.db_path));
    }

    g_integrity.check_interval = 300; /* 5 minutos */

    ag_log(AG_LOG_INFO, "Monitoreo de integridad initialized");
    return 0;
}

void ag_integrity_free(void) {
    memset(&g_integrity, 0, sizeof(g_integrity));
}

int ag_integrity_add_file(const char *path) {
    if (g_integrity.record_count >= AG_MAX_INTEGRITY_FILES) {
        ag_log(AG_LOG_ERROR, "Base de datos de integridad full");
        return -1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        ag_perror("stat");
        return -1;
    }

    ag_integrity_record_t *rec = &g_integrity.records[g_integrity.record_count];

    ag_strlcpy(rec->path, path, sizeof(rec->path));
    rec->mode = st.st_mode;
    rec->uid = st.st_uid;
    rec->gid = st.st_gid;
    rec->size = st.st_size;
    rec->mtime = st.st_mtime;
    rec->ctime = st.st_ctime;
    rec->is_directory = S_ISDIR(st.st_mode);
    rec->is_critical = false;

    /* Calcula el hash */
    if (!rec->is_directory) {
        if (ag_hash_file(path, rec->hash) != 0) {
            ag_log(AG_LOG_WARN, "No se pudo calcular hash: %s", path);
            ag_strlcpy(rec->hash, "ERROR", sizeof(rec->hash));
        }
    } else {
        ag_strlcpy(rec->hash, "DIRECTORIO", sizeof(rec->hash));
    }

    ag_strlcpy(rec->hash_algo, "SHA256", sizeof(rec->hash_algo));
    g_integrity.record_count++;

    ag_log(AG_LOG_DEBUG, "Agregado a la base de integridad: %s (hash=%s)", path, rec->hash);
    return 0;
}

int ag_integrity_add_directory(const char *path, bool recursive) {
    DIR *dir = opendir(path);
    if (!dir) {
        ag_perror("opendir");
        return -1;
    }

    /* Agrega el propio directorio */
    ag_integrity_add_file(path);

    if (recursive) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            char fullpath[AG_MAX_PATH_LEN];
            snprintf(fullpath, sizeof(fullpath), "%s/%s", path, entry->d_name);

            struct stat st;
            if (stat(fullpath, &st) == 0) {
                if (S_ISDIR(st.st_mode)) {
                    ag_integrity_add_directory(fullpath, true);
                } else {
                    ag_integrity_add_file(fullpath);
                }
            }
        }
    }

    closedir(dir);
    return 0;
}

int ag_integrity_check_file(const char *path, ag_integrity_result_t *result) {
    *result = AG_INTEGRITY_OK;

    /* Buscar el registro */
    ag_integrity_record_t *rec = NULL;
    for (int i = 0; i < g_integrity.record_count; i++) {
        if (strcmp(g_integrity.records[i].path, path) == 0) {
            rec = &g_integrity.records[i];
            break;
        }
    }

    if (!rec) {
        *result = AG_INTEGRITY_MISSING;
        return 0;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        *result = AG_INTEGRITY_MISSING;
        return 0;
    }

    /* Revisar tamaño */
    if (st.st_size != rec->size) {
        *result = AG_INTEGRITY_MODIFIED;
    }

    /* Revisar modo */
    if (st.st_mode != rec->mode) {
        *result = AG_INTEGRITY_PERMISSION_CHANGED;
    }

    /* Revisar propietario */
    if (st.st_uid != rec->uid || st.st_gid != rec->gid) {
        *result = AG_INTEGRITY_OWNER_CHANGED;
    }

    /* Revisar hash de archivos */
    if (!rec->is_directory && strcmp(rec->hash, "DIRECTORIO") != 0) {
        char current_hash[AG_HASH_LEN + 1];
        if (ag_hash_file(path, current_hash) == 0) {
            if (strcmp(current_hash, rec->hash) != 0) {
                *result = AG_INTEGRITY_HASH_MISMATCH;
            }
        }
    }

    return 0;
}

int ag_integrity_check_all(void) {
    int violations = 0;

    ag_log(AG_LOG_INFO, "Ejecutando verificación de integridad en %d archivos...",
           g_integrity.record_count);

    for (int i = 0; i < g_integrity.record_count; i++) {
        ag_integrity_result_t result;
        ag_integrity_check_file(g_integrity.records[i].path, &result);

        if (result != AG_INTEGRITY_OK) {
            violations++;
            const char *status = result == AG_INTEGRITY_MODIFIED ? "MODIFICADO" :
                                 result == AG_INTEGRITY_MISSING ? "FALTANTE" :
                                 result == AG_INTEGRITY_PERMISSION_CHANGED ? "PERMISOS_CAMBIADOS" :
                                 result == AG_INTEGRITY_OWNER_CHANGED ? "PROPIETARIO_CAMBIADO" :
                                 result == AG_INTEGRITY_HASH_MISMATCH ? "HASH_NO_COINCIDE" :
                                 "DESCONOCIDO";

            ag_log(AG_LOG_WARN, "[INTEGRIDAD] %s: %s",
                   status, g_integrity.records[i].path);
        }
    }

    ag_log(AG_LOG_INFO, "Verificación de integridad completa: %d violaciones", violations);
    return violations;
}

void ag_integrity_print_baseline(void) {
    printf("\n-> Línea base de integridad\n");
    printf("%-50s %-12s %-10s %-10s %s\n",
           "RUTA", "TIPO", "TAMAÑO", "PERMISOS", "HASH");
    printf("%s\n", "--------------------------------------------------------------------------------");

    for (int i = 0; i < g_integrity.record_count; i++) {
        ag_integrity_record_t *rec = &g_integrity.records[i];
        printf("%-50s %-12s %-10ld %04o %s\n",
               rec->path,
               rec->is_directory ? "directorio" : "archivo",
               rec->size,
               rec->mode & 07777,
               rec->hash);
    }

    printf("\nTotal: %d elementos\n", g_integrity.record_count);
}

int ag_integrity_create_baseline(void) {
    ag_log(AG_LOG_INFO, "Creando línea base de integridad...");

    /* Agregar archivos críticos comunes */
    ag_integrity_add_file("/etc/passwd");
    ag_integrity_add_file("/etc/shadow");
    ag_integrity_add_file("/etc/sudoers");
    ag_integrity_add_file("/etc/hosts");
    ag_integrity_add_file("/etc/resolv.conf");

    ag_integrity_print_baseline();

    /* Guarda en el archivo */
    char baseline_path[AG_MAX_PATH_LEN];
    snprintf(baseline_path, sizeof(baseline_path),
             "/var/lib/agentguard/baseline-%ld.json", time(NULL));

    ag_file_mkdir_p("/var/lib/agentguard");
    ag_integrity_save_baseline(baseline_path);

    ag_log(AG_LOG_INFO, "Línea base guardada en: %s", baseline_path);
    return 0;
}

int ag_integrity_save_baseline(const char *path) {
    char buf[AG_MAX_REPORT_SIZE];
    size_t pos = 0;

    ag_json_begin_object(buf, sizeof(buf), &pos);
    ag_json_add_string(buf, sizeof(buf), &pos, "type", "linea_base_integridad");
    ag_json_add_string(buf, sizeof(buf), &pos, "created_at",
                       ag_timestamp_iso8601((char[32]){0}, 32));
    ag_json_add_int(buf, sizeof(buf), &pos, "count", g_integrity.record_count);

    /* Agregar arreglo de registros */
    pos += snprintf(buf + pos, sizeof(buf) - pos, "\"records\":[");

    for (int i = 0; i < g_integrity.record_count; i++) {
        ag_integrity_record_t *rec = &g_integrity.records[i];

        pos += snprintf(buf + pos, sizeof(buf) - pos,
                        "{\"path\":\"%s\",\"type\":\"%s\",\"size\":%ld,"
                        "\"mode\":%o,\"uid\":%d,\"gid\":%d,\"hash\":\"%s\"}%s",
                        rec->path,
                        rec->is_directory ? "directorio" : "archivo",
                        rec->size, rec->mode & 07777, rec->uid, rec->gid,
                        rec->hash,
                        i < g_integrity.record_count - 1 ? "," : "");
    }

    pos += snprintf(buf + pos, sizeof(buf) - pos, "]}");

    return ag_file_write_all(path, buf, pos);
}

int ag_integrity_load_baseline(const char *path) {
    (void)path;
    /* TODO: implementar parser JSON */
    ag_log(AG_LOG_WARN, "La carga de línea base aún no está implementada");
    return -1;
}

void ag_integrity_print_report(void) {
    ag_integrity_print_baseline();
}
