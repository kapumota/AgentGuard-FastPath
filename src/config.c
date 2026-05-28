/**
 * @file config.c
 * @brief Parser de configuración y motor de políticas
 */

#include "agentguard.h"
#include "utils.h"
#include "config.h"

ag_config_t g_config = {0};

/* Tabla de nombres de syscalls (x86_64) */
static struct {
    int num;
    const char *name;
} syscall_table[] = {
    {0, "read"}, {1, "write"}, {2, "open"}, {3, "close"},
    {4, "stat"}, {5, "fstat"}, {6, "lstat"}, {8, "lseek"},
    {9, "mmap"}, {10, "mprotect"}, {11, "munmap"}, {12, "brk"},
    {13, "rt_sigaction"}, {14, "rt_sigprocmask"}, {15, "rt_sigreturn"},
    {16, "ioctl"}, {17, "pread64"}, {18, "pwrite64"}, {19, "readv"},
    {20, "writev"}, {21, "access"}, {22, "pipe"}, {23, "select"},
    {24, "sched_yield"}, {25, "mremap"}, {26, "msync"}, {27, "mincore"},
    {28, "madvise"}, {29, "shmget"}, {30, "shmat"}, {31, "shmctl"},
    {32, "dup"}, {33, "dup2"}, {34, "pause"}, {35, "nanosleep"},
    {36, "getitimer"}, {37, "alarm"}, {38, "setitimer"}, {39, "getpid"},
    {41, "socket"}, {42, "connect"}, {43, "accept"}, {44, "sendto"},
    {45, "recvfrom"}, {46, "sendmsg"}, {47, "recvmsg"}, {48, "shutdown"},
    {49, "bind"}, {50, "listen"}, {51, "getsockname"}, {52, "getpeername"},
    {53, "socketpair"}, {54, "setsockopt"}, {55, "getsockopt"},
    {56, "clone"}, {57, "fork"}, {58, "vfork"}, {59, "execve"},
    {60, "exit"}, {61, "wait4"}, {62, "kill"}, {63, "uname"},
    {72, "fcntl"}, {73, "flock"}, {74, "fsync"}, {75, "fdatasync"},
    {76, "truncate"}, {77, "ftruncate"}, {78, "getdents"}, {79, "getcwd"},
    {80, "chdir"}, {81, "fchdir"}, {82, "rename"}, {83, "mkdir"},
    {84, "rmdir"}, {85, "creat"}, {86, "link"}, {87, "unlink"},
    {88, "symlink"}, {89, "readlink"}, {90, "chmod"}, {91, "fchmod"},
    {92, "chown"}, {93, "fchown"}, {94, "lchown"}, {95, "umask"},
    {96, "gettimeofday"}, {97, "getrlimit"}, {98, "getrusage"},
    {99, "sysinfo"}, {100, "times"}, {101, "ptrace"}, {102, "getuid"},
    {103, "syslog"}, {104, "getgid"}, {105, "setuid"}, {106, "setgid"},
    {107, "geteuid"}, {108, "getegid"}, {109, "setpgid"}, {110, "getppid"},
    {111, "getpgrp"}, {112, "setsid"}, {113, "setreuid"}, {114, "setregid"},
    {115, "getgroups"}, {116, "setgroups"}, {117, "setresuid"},
    {118, "getresuid"}, {119, "setresgid"}, {120, "getresgid"},
    {121, "getpgid"}, {122, "setfsuid"}, {123, "setfsgid"},
    {124, "getsid"}, {125, "capget"}, {126, "capset"}, {127, "rt_sigpending"},
    {128, "rt_sigtimedwait"}, {129, "rt_sigqueueinfo"}, {130, "rt_sigsuspend"},
    {131, "sigaltstack"}, {132, "utime"}, {133, "mknod"}, {134, "uselib"},
    {135, "personality"}, {136, "ustat"}, {137, "statfs"}, {138, "fstatfs"},
    {139, "sysfs"}, {140, "getpriority"}, {141, "setpriority"},
    {142, "sched_setparam"}, {143, "sched_getparam"},
    {144, "sched_setscheduler"}, {145, "sched_getscheduler"},
    {146, "sched_get_priority_max"}, {147, "sched_get_priority_min"},
    {148, "sched_rr_get_interval"}, {149, "mlock"}, {150, "munlock"},
    {151, "mlockall"}, {152, "munlockall"}, {153, "vhangup"},
    {154, "modify_ldt"}, {155, "pivot_root"}, {156, "_sysctl"},
    {157, "prctl"}, {158, "arch_prctl"}, {159, "adjtimex"},
    {160, "setrlimit"}, {161, "chroot"}, {162, "sync"}, {163, "acct"},
    {164, "settimeofday"}, {165, "mount"}, {166, "umount2"},
    {167, "swapon"}, {168, "swapoff"}, {169, "reboot"}, {170, "sethostname"},
    {171, "setdomainname"}, {172, "iopl"}, {173, "ioperm"}, {174, "create_module"},
    {175, "init_module"}, {176, "delete_module"}, {177, "get_kernel_syms"},
    {178, "query_module"}, {179, "quotactl"}, {180, "nfsservctl"},
    {181, "getpmsg"}, {182, "putpmsg"}, {183, "afs_syscall"},
    {184, "tuxcall"}, {185, "security"}, {186, "gettid"},
    {187, "readahead"}, {188, "setxattr"}, {189, "lsetxattr"},
    {190, "fsetxattr"}, {191, "getxattr"}, {192, "lgetxattr"},
    {193, "fgetxattr"}, {194, "listxattr"}, {195, "llistxattr"},
    {196, "flistxattr"}, {197, "removexattr"}, {198, "lremovexattr"},
    {199, "fremovexattr"}, {200, "tkill"}, {201, "time"},
    {202, "futex"}, {203, "sched_setaffinity"}, {204, "sched_getaffinity"},
    {205, "set_hilo_area"}, {206, "io_setup"}, {207, "io_destroy"},
    {208, "io_getevents"}, {209, "io_submit"}, {210, "io_cancel"},
    {211, "get_hilo_area"}, {212, "lookup_dcookie"},
    {213, "epoll_create"}, {214, "epoll_ctl_old"}, {215, "epoll_wait_old"},
    {216, "remap_file_pages"}, {217, "getdents64"}, {218, "set_tid_address"},
    {219, "restart_syscall"}, {220, "semtimedop"}, {221, "fadvise64"},
    {222, "timer_create"}, {223, "timer_settime"}, {224, "timer_gettime"},
    {225, "timer_getoverrun"}, {226, "timer_delete"}, {227, "clock_settime"},
    {228, "clock_gettime"}, {229, "clock_getres"}, {230, "clock_nanosleep"},
    {231, "exit_group"}, {232, "epoll_wait"}, {233, "epoll_ctl"},
    {234, "tgkill"}, {235, "utimes"}, {236, "vserver"},
    {237, "mbind"}, {238, "set_mempolicy"}, {239, "get_mempolicy"},
    {240, "mq_open"}, {241, "mq_unlink"}, {242, "mq_timedsend"},
    {243, "mq_timedreceive"}, {244, "mq_notify"}, {245, "mq_getsetattr"},
    {246, "kexec_load"}, {247, "waitid"}, {248, "add_key"},
    {249, "request_key"}, {250, "keyctl"}, {251, "ioprio_set"},
    {252, "ioprio_get"}, {253, "inotify_init"}, {254, "inotify_add_watch"},
    {255, "inotify_rm_watch"}, {256, "migrate_pages"}, {257, "openat"},
    {258, "mkdirat"}, {259, "mknodat"}, {260, "fchownat"},
    {261, "futimesat"}, {262, "newfstatat"}, {263, "unlinkat"},
    {264, "renameat"}, {265, "linkat"}, {266, "symlinkat"},
    {267, "readlinkat"}, {268, "fchmodat"}, {269, "faccessat"},
    {270, "pselect6"}, {271, "ppoll"}, {272, "unshare"},
    {273, "set_robust_list"}, {274, "get_robust_list"},
    {275, "splice"}, {276, "tee"}, {277, "sync_file_range"},
    {278, "vmsplice"}, {279, "move_pages"}, {280, "utimensat"},
    {281, "epoll_pwait"}, {282, "signalfd"}, {283, "timerfd_create"},
    {284, "eventfd"}, {285, "fallocate"}, {286, "timerfd_settime"},
    {287, "timerfd_gettime"}, {288, "accept4"}, {289, "signalfd4"},
    {290, "eventfd2"}, {291, "epoll_create1"}, {292, "dup3"},
    {293, "pipe2"}, {294, "inotify_init1"}, {295, "preadv"},
    {296, "pwritev"}, {297, "rt_tgsigqueueinfo"}, {298, "perf_event_open"},
    {299, "recvmmsg"}, {300, "fanotify_init"}, {301, "fanotify_mark"},
    {302, "prlimit64"}, {303, "name_to_handle_at"},
    {304, "open_by_handle_at"}, {305, "clock_adjtime"},
    {306, "syncfs"}, {307, "sendmmsg"}, {308, "setns"},
    {309, "getcpu"}, {310, "process_vm_readv"}, {311, "process_vm_writev"},
    {312, "kcmp"}, {313, "finit_module"}, {314, "sched_setattr"},
    {315, "sched_getattr"}, {316, "renameat2"}, {317, "seccomp"},
    {318, "getrandom"}, {319, "memfd_create"}, {320, "kexec_file_load"},
    {321, "bpf"}, {322, "execveat"}, {323, "userfaultfd"},
    {324, "membarrier"}, {325, "mlock2"}, {326, "copy_file_range"},
    {327, "preadv2"}, {328, "pwritev2"}, {329, "pkey_mprotect"},
    {330, "pkey_alloc"}, {331, "pkey_free"}, {332, "statx"},
    {333, "io_pgetevents"}, {334, "rseq"}, {424, "pidfd_send_signal"},
    {425, "io_uring_setup"}, {426, "io_uring_enter"}, {427, "io_uring_register"},
    {428, "open_tree"}, {429, "move_mount"}, {430, "fsopen"},
    {431, "fsconfig"}, {432, "fsmount"}, {433, "fspick"},
    {434, "pidfd_open"}, {435, "clone3"}, {437, "openat2"},
    {438, "pidfd_getfd"}, {439, "faccessat2"}, {440, "process_madvise"},
    {441, "epoll_pwait2"}, {442, "mount_setattr"}, {443, "quotactl_fd"},
    {444, "landlock_create_ruleset"}, {445, "landlock_add_rule"},
    {446, "landlock_restrict_self"}, {447, "memfd_secret"},
    {448, "process_mrelease"}, {449, "futex_waitv"},
    {450, "set_mempolicy_home_node"}, {451, "cachestat"},
    {452, "fchmodat2"}, {453, "map_shadow_stack"}, {454, "futex_wake"},
    {455, "futex_wait"}, {456, "futex_requeue"}, {457, "statmount"},
    {458, "listmount"}, {459, "lsm_get_self_attr"},
    {460, "lsm_set_self_attr"}, {461, "lsm_list_modules"},
    {-1, NULL}
};

const char* ag_syscall_name(int num) {
    for (int i = 0; syscall_table[i].num >= 0; i++) {
        if (syscall_table[i].num == num) {
            return syscall_table[i].name;
        }
    }
    return "desconocido";
}

int ag_syscall_number(const char *name) {
    for (int i = 0; syscall_table[i].num >= 0; i++) {
        if (strcmp(syscall_table[i].name, name) == 0) {
            return syscall_table[i].num;
        }
    }
    return -1;
}

void ag_config_set_defaults(void) {
    memset(&g_config, 0, sizeof(g_config));

    ag_strlcpy(g_config.agent_name, "agentguard-default", sizeof(g_config.agent_name));
    ag_strlcpy(g_config.agent_version, AG_VERSION_STRING, sizeof(g_config.agent_version));
    ag_strlcpy(g_config.description, "Política de seguridad predeterminada para agentes de IA", sizeof(g_config.description));

    g_config.log_level = AG_LOG_INFO;
    ag_strlcpy(g_config.log_file, "/var/log/agentguard.log", sizeof(g_config.log_file));
    ag_strlcpy(g_config.audit_file, "/var/log/agentguard-audit.log", sizeof(g_config.audit_file));
    ag_strlcpy(g_config.report_file, "/var/log/agentguard-report.json", sizeof(g_config.report_file));

    g_config.monitor_syscalls = true;
    g_config.monitor_files = true;
    g_config.monitor_network = true;
    g_config.monitor_processes = true;
    g_config.monitor_integrity = false;
    g_config.heartbeat_interval_sec = 60;
    g_config.snapshot_interval_sec = 300;

    g_config.enforce_policies = true;
    g_config.kill_on_violation = false;
    g_config.alert_on_anomaly = true;
    g_config.alert_threshold = 10;
    g_config.auto_block_repeat_offenders = true;
    g_config.block_duration_sec = 300;

    /* Crea la política predeterminada */
    ag_policy_t *policy = &g_config.policies[0];
    ag_strlcpy(policy->name, "default", sizeof(policy->name));
    policy->action = AG_ACTION_ALLOW;
    policy->scope = AG_SCOPE_GLOBAL;

    policy->syscall_filter_enabled = true;
    policy->file_filter_enabled = true;
    policy->network_filter_enabled = true;
    policy->exec_filter_enabled = true;
    policy->integrity_enabled = false;
    policy->resource_limits_enabled = false;
    policy->rate_limit_enabled = false;

    /* Bloquea syscalls peligrosas por defecto */
    policy->blocked_syscalls[policy->blocked_syscall_count++] = 101;  /* ptrace */
    policy->blocked_syscalls[policy->blocked_syscall_count++] = 135;  /* personality */
    policy->blocked_syscalls[policy->blocked_syscall_count++] = 175;  /* init_module */
    policy->blocked_syscalls[policy->blocked_syscall_count++] = 176;  /* delete_module */
    policy->blocked_syscalls[policy->blocked_syscall_count++] = 246;  /* kexec_load */
    policy->blocked_syscalls[policy->blocked_syscall_count++] = 320;  /* kexec_file_load */
    policy->blocked_syscalls[policy->blocked_syscall_count++] = 321;  /* bpf */
    policy->blocked_syscalls[policy->blocked_syscall_count++] = 298;  /* perf_event_open */

    /* Bloquea ejecución de shell */
    policy->block_shell_execution = true;
    policy->block_script_execution = false;

    g_config.policy_count = 1;
    g_config.default_policy = &g_config.policies[0];
}

int ag_config_init(const char *path) {
    ag_config_set_defaults();

    if (path && strlen(path) > 0) {
        ag_log(AG_LOG_INFO, "Cargando configuración desde: %s", path);
        /* TODO: implementar parser YAML */
        /* Por ahora, usar valores predeterminados */
    }

    return ag_config_validate();
}

void ag_config_free(void) {
    memset(&g_config, 0, sizeof(g_config));
}

int ag_config_validate(void) {
    if (g_config.policy_count == 0) {
        ag_log(AG_LOG_ERROR, "No policies defined");
        return -1;
    }

    if (g_config.default_policy == NULL) {
        g_config.default_policy = &g_config.policies[0];
    }

    return 0;
}

ag_policy_t* ag_config_get_policy_for_process(const char *comm) {
    if (!comm || strlen(comm) == 0) {
        return g_config.default_policy;
    }

    for (int i = 0; i < g_config.policy_count; i++) {
        if (strcmp(g_config.policies[i].name, comm) == 0) {
            return &g_config.policies[i];
        }
    }

    return g_config.default_policy;
}

ag_action_t ag_policy_evaluate_syscall(ag_policy_t *policy, int syscall) {
    if (!policy || !policy->syscall_filter_enabled) {
        return AG_ACTION_ALLOW;
    }

    /* Revisa primero la lista de bloqueo */
    for (int i = 0; i < policy->blocked_syscall_count; i++) {
        if (policy->blocked_syscalls[i] == syscall) {
            return AG_ACTION_BLOCK;
        }
    }

    /* Si se define una lista de permitidos, permitir solo esos elementos */
    if (policy->allowed_syscall_count > 0) {
        for (int i = 0; i < policy->allowed_syscall_count; i++) {
            if (policy->allowed_syscalls[i] == syscall) {
                return AG_ACTION_ALLOW;
            }
        }
        return AG_ACTION_BLOCK;
    }

    return AG_ACTION_ALLOW;
}

ag_action_t ag_policy_evaluate_file(ag_policy_t *policy, const char *path, int flags) {
    if (!policy || !policy->file_filter_enabled || !path) {
        return AG_ACTION_ALLOW;
    }

    /* Revisa rutas protegidas */
    for (int i = 0; i < policy->protected_path_count; i++) {
        if (strncmp(path, policy->protected_paths[i],
                    strlen(policy->protected_paths[i])) == 0) {
            /* El acceso de escritura a rutas protegidas queda bloqueado */
            if ((flags & O_WRONLY) || (flags & O_RDWR)) {
                return AG_ACTION_BLOCK;
            }
        }
    }

    /* Revisa rutas bloqueadas */
    for (int i = 0; i < policy->blocked_path_count; i++) {
        if (strncmp(path, policy->blocked_paths[i],
                    strlen(policy->blocked_paths[i])) == 0) {
            return AG_ACTION_BLOCK;
        }
    }

    return AG_ACTION_ALLOW;
}

ag_action_t ag_policy_evaluate_exec(ag_policy_t *policy, const char *path) {
    if (!policy || !policy->exec_filter_enabled || !path) {
        return AG_ACTION_ALLOW;
    }

    /* Revisa ejecutables bloqueados */
    for (int i = 0; i < policy->blocked_exec_count; i++) {
        if (strcmp(path, policy->blocked_executables[i]) == 0) {
            return AG_ACTION_BLOCK;
        }
    }

    /* Bloquea ejecución de shell */
    if (policy->block_shell_execution) {
        const char *shells[] = {"/bin/sh", "/bin/bash", "/bin/zsh",
                                 "/bin/dash", "/bin/ksh", "/bin/csh",
                                 "/bin/tcsh", "/bin/fish", NULL};
        for (int i = 0; shells[i]; i++) {
            if (strcmp(path, shells[i]) == 0) {
                return AG_ACTION_BLOCK;
            }
        }
    }

    return AG_ACTION_ALLOW;
}

ag_action_t ag_policy_evaluate_network(ag_policy_t *policy, const char *host, int port) {
    (void)host;
    if (!policy || !policy->network_filter_enabled) {
        return AG_ACTION_ALLOW;
    }

    if (policy->block_all_outbound) {
        return AG_ACTION_BLOCK;
    }

    /* Revisa puertos permitidos */
    if (policy->allowed_port_count > 0) {
        bool allowed = false;
        for (int i = 0; i < policy->allowed_port_count; i++) {
            if (policy->allowed_ports[i] == port) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            return AG_ACTION_BLOCK;
        }
    }

    return AG_ACTION_ALLOW;
}

void ag_config_print(void) {
    printf("Configuración:\n");
    printf("  Agente: %s v%s\n", g_config.agent_name, g_config.agent_version);
    printf("  Log level: %d\n", g_config.log_level);
    printf("  Políticas: %d\n", g_config.policy_count);
    printf("  Política predeterminada: %s\n",
           g_config.default_policy ? g_config.default_policy->name : "none");
}

int ag_config_reload(const char *path) {
    ag_log(AG_LOG_INFO, "Recargando configuración desde: %s", path ? path : "configuración por defecto");
    ag_config_free();
    return ag_config_init(path);
}
