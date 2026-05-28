/**
 * @file audit.h
 * @brief Generación de trazas de auditoría y evidencia de cumplimiento
 * 
 * Inspirado en:
 *   - CMU Aegis-4: trazas de auditoría para operaciones defensivas de ciberseguridad
 *   - Stanford: gobernanza de IA y cumplimiento
 *   - ETH Zurich: evidencia estructurada para sistemas confiables
 */

#ifndef AG_AUDIT_H
#define AG_AUDIT_H

#include "agentguard.h"
#include "config.h"
#include "monitor.h"

/* Tipos de entrada de auditoría */
typedef enum {
    AG_AUDIT_SYSCALL = 0,
    AG_AUDIT_FILE    = 1,
    AG_AUDIT_NETWORK = 2,
    AG_AUDIT_PROCESS = 3,
    AG_AUDIT_POLICY  = 4,
    AG_AUDIT_CONFIG  = 5,
    AG_AUDIT_ALERT   = 6,
    AG_AUDIT_HEARTBEAT = 7
} ag_audit_type_t;

/* Severidad de auditoría */
typedef enum {
    AG_SEV_INFO = 0,
    AG_SEV_LOW = 1,
    AG_SEV_MEDIUM = 2,
    AG_SEV_HIGH = 3,
    AG_SEV_CRITICAL = 4
} ag_severity_t;

/* Entrada individual de auditoría */
typedef struct {
    uint64_t id;
    char correlation_id[64];
    ag_audit_type_t type;
    ag_severity_t severity;
    char timestamp[32];
    char source[AG_MAX_COMM_LEN];
    char target[AG_MAX_PATH_LEN];
    char action[32];
    char result[32];
    char details[AG_MAX_COMM_LEN];
    char user[64];
    char process[AG_MAX_COMM_LEN];
    pid_t pid;
    uid_t uid;
    gid_t gid;
    char policy[AG_MAX_COMM_LEN];
    char hash[AG_HASH_LEN + 1];
    bool compliance_relevant;
} ag_audit_entry_t;

/* Contenedor del registro de auditoría */
typedef struct {
    ag_audit_entry_t entries[AG_MAX_LOG_ENTRIES];
    int entry_count;
    int head;
    int tail;
    bool circular;
    char log_path[AG_MAX_PATH_LEN];
    int log_fd;
    bool json_format;
    bool tamper_protected;
    uint64_t total_entries;
} ag_audit_log_t;

extern ag_audit_log_t g_audit;

/* Ciclo de vida */
int  ag_audit_init(const char *path);
void ag_audit_free(void);

/* Gestión de entradas */
int  ag_audit_add(ag_audit_type_t type, ag_severity_t severity,
                  const char *source, const char *target,
                  const char *action, const char *result,
                  const char *details);
int  ag_audit_add_syscall(ag_syscall_info_t *info, ag_action_t action);
int  ag_audit_add_file_op(const char *path, int flags, ag_action_t action);
int  ag_audit_add_net_op(ag_net_op_t *op, ag_action_t action);
int  ag_audit_add_policy_violation(const char *policy, const char *details);

/* Correlación y evidencia */
void ag_audit_set_correlation(const char *id);
char* ag_audit_generate_correlation_id(char *buf, size_t buflen);
int  ag_audit_generate_evidence(const char *framework, const char *output_path);

/* Reportes */
void ag_audit_print_recent(int count);
int  ag_audit_export_json(const char *path);
int  ag_audit_export_csv(const char *path);
int  ag_audit_export_pdf(const char *path);
void ag_audit_print_stats(void);

/* Marcos de cumplimiento */
int  ag_audit_check_soc2_requirements(void);
int  ag_audit_check_iso27001_requirements(void);
int  ag_audit_check_gdpr_requirements(void);
int  ag_audit_check_nist_requirements(void);

#endif /* AG_AUDIT_H */
