/**
 * @file config.h
 * @brief Parser de configuración y motor de políticas
 * 
 * Inspirado en:
 *   - Tsinghua OpenClaw: marco de seguridad de 5 capas
 *   - CMU Aegis-4: configuración y validación de sensores
 *   - ETH Zurich: aplicación de políticas en tiempo de ejecución.
 */

#ifndef AG_CONFIG_H
#define AG_CONFIG_H

#include "agentguard.h"

/* Tipos de acción de política */
typedef enum {
    AG_ACTION_ALLOW = 0,
    AG_ACTION_BLOCK = 1,
    AG_ACTION_ALERT = 2,
    AG_ACTION_LOG   = 3,
    AG_ACTION_KILL  = 4
} ag_action_t;

/* Ámbito de política */
typedef enum {
    AG_SCOPE_GLOBAL = 0,
    AG_SCOPE_PROCESS = 1,
    AG_SCOPE_USER    = 2,
    AG_SCOPE_CGROUP  = 3
} ag_scope_t;

/* Regla individual de política */
typedef struct {
    char name[AG_MAX_COMM_LEN];
    ag_action_t action;
    ag_scope_t scope;

    /* Filtrado de syscalls */
    bool syscall_filter_enabled;
    int allowed_syscalls[AG_MAX_SYSCALLS];
    int allowed_syscall_count;
    int blocked_syscalls[AG_MAX_SYSCALLS];
    int blocked_syscall_count;

    /* Control de acceso a archivos */
    bool file_filter_enabled;
    char allowed_paths[AG_MAX_POLICIES][AG_MAX_PATH_LEN];
    int allowed_path_count;
    char blocked_paths[AG_MAX_POLICIES][AG_MAX_PATH_LEN];
    int blocked_path_count;
    char protected_paths[AG_MAX_POLICIES][AG_MAX_PATH_LEN];
    int protected_path_count;

    /* Control de red */
    bool network_filter_enabled;
    char allowed_hosts[AG_MAX_POLICIES][AG_MAX_COMM_LEN];
    int allowed_host_count;
    int allowed_ports[AG_MAX_POLICIES];
    int allowed_port_count;
    bool block_all_outbound;

    /* Control de ejecución de procesos */
    bool exec_filter_enabled;
    char allowed_executables[AG_MAX_POLICIES][AG_MAX_PATH_LEN];
    int allowed_exec_count;
    char blocked_executables[AG_MAX_POLICIES][AG_MAX_PATH_LEN];
    int blocked_exec_count;
    bool block_shell_execution;
    bool block_script_execution;

    /* Monitoreo de integridad */
    bool integrity_enabled;
    char integrity_files[AG_MAX_INTEGRITY_FILES][AG_MAX_PATH_LEN];
    char integrity_hashes[AG_MAX_INTEGRITY_FILES][AG_HASH_LEN + 1];
    int integrity_file_count;

    /* Límites de recursos */
    bool resource_limits_enabled;
    size_t max_memory_mb;
    size_t max_cpu_percent;
    size_t max_file_size_mb;
    int max_open_fds;
    int max_processes;

    /* Limitación de tasa */
    bool rate_limit_enabled;
    int max_syscalls_per_sec;
    int max_file_ops_per_sec;
    int max_net_conns_per_min;
} ag_policy_t;

/* Contenedor de configuración */
typedef struct {
    char agent_name[AG_MAX_COMM_LEN];
    char agent_version[AG_MAX_COMM_LEN];
    char description[AG_MAX_COMM_LEN];

    /* Ajustes globales */
    ag_log_level_t log_level;
    char log_file[AG_MAX_PATH_LEN];
    char audit_file[AG_MAX_PATH_LEN];
    char report_file[AG_MAX_PATH_LEN];
    bool daemon_mode;
    bool color_output;
    bool json_output;

    /* Ajustes de monitoreo */
    bool monitor_syscalls;
    bool monitor_files;
    bool monitor_network;
    bool monitor_processes;
    bool monitor_integrity;
    int  heartbeat_interval_sec;
    int  snapshot_interval_sec;

    /* Ajustes de seguridad */
    bool enforce_policies;
    bool kill_on_violation;
    bool alert_on_anomaly;
    int  alert_threshold;
    bool auto_block_repeat_offenders;
    int  block_duration_sec;

    /* Políticas */
    ag_policy_t policies[AG_MAX_POLICIES];
    int policy_count;
    ag_policy_t *default_policy;

    /* Lista blanca/lista negra */
    char whitelisted_users[AG_MAX_POLICIES][AG_MAX_COMM_LEN];
    int whitelisted_user_count;
    char blacklisted_users[AG_MAX_POLICIES][AG_MAX_COMM_LEN];
    int blacklisted_user_count;
} ag_config_t;

extern ag_config_t g_config;

/* Utilidades de syscall */
const char* ag_syscall_name(int num);
int ag_syscall_number(const char *name);

/* Ciclo de vida de configuración */
int  ag_config_init(const char *path);
void ag_config_free(void);
int  ag_config_reload(const char *path);
void ag_config_print(void);
int  ag_config_validate(void);

/* Gestión de políticas */
int  ag_config_add_policy(ag_policy_t *policy);
int  ag_config_remove_policy(const char *name);
ag_policy_t* ag_config_find_policy(const char *name);
ag_policy_t* ag_config_get_policy_for_process(const char *comm);

/* Evaluación de políticas */
ag_action_t ag_policy_evaluate_syscall(ag_policy_t *policy, int syscall);
ag_action_t ag_policy_evaluate_file(ag_policy_t *policy, const char *path, int flags);
ag_action_t ag_policy_evaluate_exec(ag_policy_t *policy, const char *path);
ag_action_t ag_policy_evaluate_network(ag_policy_t *policy, const char *host, int port);

/* Configuraciones predeterminadas */
void ag_config_set_defaults(void);
int  ag_config_generate_default(const char *path);

#endif /* AG_CONFIG_H */
