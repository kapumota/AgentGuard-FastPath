/**
 * @file sandbox.h
 * @brief Utilidades de aislamiento (seccomp, namespaces, capacidades)
 * 
 * Inspirado en:
 *   - Tsinghua OpenClaw: aislamiento basado en capacidades
 *   - ETH Zurich: contenedores con superficie mínima de ataque
 *   - Stanford: microsegmentación y aislamiento
 */

#ifndef AG_SANDBOX_H
#define AG_SANDBOX_H

#include "agentguard.h"

/* Tecnologías de aislamiento */
typedef enum {
    AG_SB_SECCOMP = 0,
    AG_SB_NAMESPACE = 1,
    AG_SB_CAPABILITY = 2,
    AG_SB_CGROUP = 3,
    AG_SB_LANDLOCK = 4,
    AG_SB_APPARMOR = 5
} ag_sandbox_tech_t;

/* Perfil de aislamiento */
typedef struct {
    char name[AG_MAX_COMM_LEN];
    bool seccomp_enabled;
    bool namespace_enabled;
    bool capability_drop_all;
    bool read_only_root;
    bool no_new_privs;
    bool network_isolation;
    char allowed_caps[AG_MAX_POLICIES][32];
    int allowed_cap_count;
    char dropped_caps[AG_MAX_POLICIES][32];
    int dropped_cap_count;
    char chroot_dir[AG_MAX_PATH_LEN];
    uid_t map_uid;
    gid_t map_gid;
    size_t max_memory_mb;
    size_t max_cpu_shares;
    size_t max_pids;
} ag_sandbox_profile_t;

/* Constructor de filtros seccomp */
typedef struct {
    struct sock_filter *filter;
    size_t filter_len;
    size_t filter_cap;
    int default_action;
} ag_seccomp_builder_t;

/* Ciclo de vida */
int  ag_sandbox_init(void);
void ag_sandbox_free(void);

/* Gestión de perfiles */
int  ag_sandbox_load_profile(const char *path);
int  ag_sandbox_apply_profile(ag_sandbox_profile_t *profile);
void ag_sandbox_print_profile(ag_sandbox_profile_t *profile);

/* Utilidades seccomp */
int  ag_seccomp_init(ag_seccomp_builder_t *builder);
void ag_seccomp_free(ag_seccomp_builder_t *builder);
int  ag_seccomp_allow_syscall(ag_seccomp_builder_t *builder, int syscall);
int  ag_seccomp_block_syscall(ag_seccomp_builder_t *builder, int syscall);
int  ag_seccomp_errno_syscall(ag_seccomp_builder_t *builder, int syscall, int err);
int  ag_seccomp_trace_syscall(ag_seccomp_builder_t *builder, int syscall);
int  ag_seccomp_load(ag_seccomp_builder_t *builder);

/* Utilidades de capacidades */
int  ag_cap_drop_all(void);
int  ag_cap_drop(const char *cap_name);
int  ag_cap_keep(const char *cap_name);
int  ag_cap_set_ambient(const char *cap_name, bool value);

/* Utilidades de namespaces */
int  ag_ns_unshare_all(void);
int  ag_ns_mount_proc(const char *root);
int  ag_ns_pivot_root(const char *new_root, const char *put_old);
int  ag_ns_setup_user(uid_t uid, gid_t gid);

/* Utilidades Landlock (si están disponibles) */
#ifdef __NR_landlock_create_ruleset
int  ag_landlock_create_ruleset(void);
int  ag_landlock_add_path_beneath(int ruleset, const char *path, int access_rights);
int  ag_landlock_restrict_self(int ruleset);
#endif

#endif /* AG_SANDBOX_H */
