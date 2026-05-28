/**
 * @file sandbox.c
 * @brief Utilidades de aislamiento (seccomp, namespaces, capacidades)
 * 
 * Inspirado en el aislamiento basado en capacidades de Tsinghua OpenClaw y contenedores mínimos de ETH Zurich.
 */

#include "agentguard.h"
#include "utils.h"
#include "sandbox.h"
#include <sys/resource.h>
#if defined(__has_include)
#  if __has_include(<sys/capability.h>)
#    include <sys/capability.h>
#    define AG_HAVE_LIBCAP 1
#  else
#    define AG_HAVE_LIBCAP 0
#  endif
#else
#  define AG_HAVE_LIBCAP 0
#endif
#include <sched.h>

int ag_sandbox_init(void) {
    ag_log(AG_LOG_INFO, "Subsistema de aislamiento inicializado");
    return 0;
}

void ag_sandbox_free(void) {
    /* Nada que limpiar */
}

int ag_sandbox_apply_profile(ag_sandbox_profile_t *profile) {
    if (!profile) {
        return -1;
    }

    ag_log(AG_LOG_INFO, "Aplicando perfil de aislamiento: %s", profile->name);

    /* Aplicar reducción de capacidades */
    if (profile->capability_drop_all) {
        ag_cap_drop_all();
    }

    /* Aplicar límites de recursos si están configurados. */
    if (profile->max_memory_mb > 0 || profile->max_pids > 0) {
        struct rlimit rl;

        if (profile->max_memory_mb > 0) {
            rl.rlim_cur = profile->max_memory_mb * 1024 * 1024;
            rl.rlim_max = profile->max_memory_mb * 1024 * 1024;
            setrlimit(RLIMIT_AS, &rl);
        }

        if (profile->max_pids > 0) {
            rl.rlim_cur = profile->max_pids;
            rl.rlim_max = profile->max_pids;
            setrlimit(RLIMIT_NPROC, &rl);
        }
    }

    return 0;
}

int ag_cap_drop_all(void) {
#if AG_HAVE_LIBCAP
    /* Descartar todas las capacidades. */
    cap_t caps = cap_get_proc();
    if (!caps) {
        ag_perror("cap_get_proc");
        return -1;
    }

    cap_clear(caps);

    if (cap_set_proc(caps) != 0) {
        ag_perror("cap_set_proc");
        cap_free(caps);
        return -1;
    }

    cap_free(caps);
    ag_log(AG_LOG_DEBUG, "Se descartaron todas las capacidades");
    return 0;
#else
    ag_log(AG_LOG_WARN, "Soporte libcap no disponible en tiempo de compilación");
    return -1;
#endif
}

int ag_cap_drop(const char *cap_name) {
#if AG_HAVE_LIBCAP
    cap_value_t cap;
    if (cap_from_name(cap_name, &cap) != 0) {
        ag_log(AG_LOG_WARN, "Capacidad desconocida: %s", cap_name);
        return -1;
    }

    cap_t caps = cap_get_proc();
    if (!caps) {
        ag_perror("cap_get_proc");
        return -1;
    }

    cap_set_flag(caps, CAP_EFFECTIVE, 1, &cap, CAP_CLEAR);
    cap_set_flag(caps, CAP_PERMITTED, 1, &cap, CAP_CLEAR);
    cap_set_flag(caps, CAP_INHERITABLE, 1, &cap, CAP_CLEAR);

    if (cap_set_proc(caps) != 0) {
        ag_perror("cap_set_proc");
        cap_free(caps);
        return -1;
    }

    cap_free(caps);
    ag_log(AG_LOG_DEBUG, "Capacidad descartada: %s", cap_name);
    return 0;
#else
    (void)cap_name;
    ag_log(AG_LOG_WARN, "Soporte libcap no disponible en tiempo de compilación");
    return -1;
#endif
}

int ag_ns_unshare_all(void) {
    int flags = CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET |
                CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWUSER;

    if (unshare(flags) != 0) {
        ag_perror("unshare");
        return -1;
    }

    ag_log(AG_LOG_DEBUG, "Se descompartieron todos los namespaces");
    return 0;
}
