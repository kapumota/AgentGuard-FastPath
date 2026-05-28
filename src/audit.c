/**
 * @file audit.c
 * @brief Generación de trazas de auditoría y evidencia de cumplimiento
 * 
 * Inspirado en CMU Aegis-4, gobernanza de IA de Stanford y sistemas confiables de ETH Zurich.
 */

#include "agentguard.h"
#include "utils.h"
#include "audit.h"

ag_audit_log_t g_audit = {0};
static char g_correlation_id[64] = {0};

int ag_audit_init(const char *path) {
    memset(&g_audit, 0, sizeof(g_audit));

    if (path && strlen(path) > 0) {
        ag_strlcpy(g_audit.log_path, path, sizeof(g_audit.log_path));
        g_audit.log_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (g_audit.log_fd < 0) {
            ag_perror("abrir registro de auditoría");
            return -1;
        }
    }

    g_audit.json_format = true;
    g_audit.circular = true;

    ag_log(AG_LOG_INFO, "Sistema de auditoría inicializado: %s", path ? path : "solo memoria");
    return 0;
}

void ag_audit_free(void) {
    if (g_audit.log_fd >= 0) {
        close(g_audit.log_fd);
        g_audit.log_fd = -1;
    }
}

char* ag_audit_generate_correlation_id(char *buf, size_t buflen) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    snprintf(buf, buflen, "AG-%lx-%lx-%d",
             (unsigned long)ts.tv_sec,
             (unsigned long)ts.tv_nsec,
             getpid());

    return buf;
}

void ag_audit_set_correlation(const char *id) {
    if (id) {
        ag_strlcpy(g_correlation_id, id, sizeof(g_correlation_id));
    }
}

int ag_audit_add(ag_audit_type_t type, ag_severity_t severity,
                 const char *source, const char *target,
                 const char *action, const char *result,
                 const char *details) {
    if (g_audit.entry_count >= AG_MAX_LOG_ENTRIES && !g_audit.circular) {
        ag_log(AG_LOG_WARN, "Registro de auditoría lleno");
        return -1;
    }

    int idx = g_audit.head;
    ag_audit_entry_t *entry = &g_audit.entries[idx];

    memset(entry, 0, sizeof(*entry));

    entry->id = g_audit.total_entries++;
    ag_timestamp_iso8601(entry->timestamp, sizeof(entry->timestamp));
    ag_strlcpy(entry->correlation_id, g_correlation_id, sizeof(entry->correlation_id));
    entry->type = type;
    entry->severity = severity;
    ag_strlcpy(entry->source, source ? source : "desconocido", sizeof(entry->source));
    ag_strlcpy(entry->target, target ? target : "desconocido", sizeof(entry->target));
    ag_strlcpy(entry->action, action ? action : "desconocido", sizeof(entry->action));
    ag_strlcpy(entry->result, result ? result : "desconocido", sizeof(entry->result));
    ag_strlcpy(entry->details, details ? details : "", sizeof(entry->details));

    /* Obtiene información del usuario actual */
    entry->pid = getpid();
    entry->uid = getuid();
    entry->gid = getgid();

    struct passwd *pw = getpwuid(entry->uid);
    if (pw) {
        ag_strlcpy(entry->user, pw->pw_name, sizeof(entry->user));
    }

    /* Calcula hash de la entrada para protección contra manipulación */
    char entry_str[AG_MAX_COMM_LEN * 4];
    snprintf(entry_str, sizeof(entry_str), "%lu%s%s%s%s%s",
             entry->id, entry->timestamp, entry->source,
             entry->target, entry->action, entry->result);

    uint8_t hash[32];
    ag_hash_sha256((uint8_t*)entry_str, strlen(entry_str), hash);
    ag_hash_to_hex(hash, entry->hash);

    /* Escribe en el archivo de registro si está disponible */
    if (g_audit.log_fd >= 0) {
        char json[AG_MAX_REPORT_SIZE];
        size_t pos = 0;

        ag_json_begin_object(json, sizeof(json), &pos);
        ag_json_add_int(json, sizeof(json), &pos, "id", entry->id);
        ag_json_add_string(json, sizeof(json), &pos, "timestamp", entry->timestamp);
        ag_json_add_string(json, sizeof(json), &pos, "correlation_id", entry->correlation_id);
        ag_json_add_int(json, sizeof(json), &pos, "type", type);
        ag_json_add_int(json, sizeof(json), &pos, "severity", severity);
        ag_json_add_string(json, sizeof(json), &pos, "source", entry->source);
        ag_json_add_string(json, sizeof(json), &pos, "target", entry->target);
        ag_json_add_string(json, sizeof(json), &pos, "action", entry->action);
        ag_json_add_string(json, sizeof(json), &pos, "result", entry->result);
        ag_json_add_string(json, sizeof(json), &pos, "details", entry->details);
        ag_json_add_string(json, sizeof(json), &pos, "user", entry->user);
        ag_json_add_int(json, sizeof(json), &pos, "pid", entry->pid);
        ag_json_add_string(json, sizeof(json), &pos, "hash", entry->hash);
        ag_json_end_object(json, sizeof(json), &pos);

        dprintf(g_audit.log_fd, "%s\n", json);
    }

    /* Actualiza búfer circular */
    g_audit.head = (g_audit.head + 1) % AG_MAX_LOG_ENTRIES;
    if (g_audit.entry_count < AG_MAX_LOG_ENTRIES) {
        g_audit.entry_count++;
    } else {
        g_audit.tail = (g_audit.tail + 1) % AG_MAX_LOG_ENTRIES;
    }

    /* Incrementa contador de alertas para severidad alta */
    if (severity >= AG_SEV_HIGH) {
        g_ctx.alert_count++;
    }

    return 0;
}

int ag_audit_add_syscall(ag_syscall_info_t *info, ag_action_t action) {
    char details[AG_MAX_COMM_LEN];
    snprintf(details, sizeof(details), "syscall=%s argumentos=[%lu,%lu,%lu]",
             info->syscall_name, info->args[0], info->args[1], info->args[2]);

    return ag_audit_add(AG_AUDIT_SYSCALL,
                        action == AG_ACTION_BLOCK ? AG_SEV_HIGH : AG_SEV_INFO,
                        info->comm, info->syscall_name,
                        action == AG_ACTION_BLOCK ? "BLOQUEAR" : "PERMITIR",
                        action == AG_ACTION_BLOCK ? "bloqueado" : "permitido",
                        details);
}

int ag_audit_add_file_op(const char *path, int flags, ag_action_t action) {
    char details[AG_MAX_COMM_LEN];
    snprintf(details, sizeof(details), "ruta=%s banderas=%d", path, flags);

    return ag_audit_add(AG_AUDIT_FILE,
                        action == AG_ACTION_BLOCK ? AG_SEV_HIGH : AG_SEV_INFO,
                        "acceso_archivo", path,
                        action == AG_ACTION_BLOCK ? "BLOQUEAR" : "PERMITIR",
                        action == AG_ACTION_BLOCK ? "bloqueado" : "permitido",
                        details);
}

int ag_audit_add_net_op(ag_net_op_t *op, ag_action_t action) {
    char details[AG_MAX_COMM_LEN];
    snprintf(details, sizeof(details), "host=%s puerto=%d",
             op->remote_addr, op->remote_port);

    return ag_audit_add(AG_AUDIT_NETWORK,
                        action == AG_ACTION_BLOCK ? AG_SEV_HIGH : AG_SEV_INFO,
                        "conexion_red", op->remote_addr,
                        action == AG_ACTION_BLOCK ? "BLOQUEAR" : "PERMITIR",
                        action == AG_ACTION_BLOCK ? "bloqueado" : "permitido",
                        details);
}

int ag_audit_generate_evidence(const char *framework, const char *output_path) {
    char buf[AG_MAX_REPORT_SIZE];
    size_t pos = 0;

    ag_json_begin_object(buf, sizeof(buf), &pos);
    ag_json_add_string(buf, sizeof(buf), &pos, "framework", framework);
    ag_json_add_string(buf, sizeof(buf), &pos, "generated_at",
                       ag_timestamp_iso8601((char[32]){0}, 32));
    ag_json_add_string(buf, sizeof(buf), &pos, "tool", "AgentGuard-C");
    ag_json_add_string(buf, sizeof(buf), &pos, "version", AG_VERSION_STRING);
    ag_json_add_int(buf, sizeof(buf), &pos, "total_events", g_ctx.event_count);
    ag_json_add_int(buf, sizeof(buf), &pos, "blocked_actions", g_ctx.block_count);
    ag_json_add_int(buf, sizeof(buf), &pos, "alerts", g_ctx.alert_count);
    ag_json_add_int(buf, sizeof(buf), &pos, "audit_entries", g_audit.total_entries);

    /* Agregaa referencias universitarias */
    ag_json_begin_object(buf, sizeof(buf), &pos); /* metodología */
    /* (simplificado; en producción se agregarían referencias completas) */
    ag_json_end_object(buf, sizeof(buf), &pos);

    ag_json_end_object(buf, sizeof(buf), &pos);

    if (output_path) {
        ag_file_write_all(output_path, buf, pos);
    }

    return 0;
}

void ag_audit_print_stats(void) {
    ag_log(AG_LOG_INFO, "-> Estadísticas de auditoría");
    ag_log(AG_LOG_INFO, "Entradas totales: %lu", g_audit.total_entries);
    ag_log(AG_LOG_INFO, "Entradas en memoria: %d", g_audit.entry_count);
    ag_log(AG_LOG_INFO, "Alertas altas/críticas: %lu", g_ctx.alert_count);
}
