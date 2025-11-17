#define _GNU_SOURCE
#include <dlfcn.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

/* Pointer to the original getpwnam() */
typedef struct passwd *(*orig_getpwnam_t)(const char *);
static orig_getpwnam_t real_getpwnam = NULL;

/* Read the env variable only once */
static const char *default_user = NULL;
static int env_checked = 0;

/* once control so init runs exactly once even if constructor + race */
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void init_getpwnam(void) {
    if (!env_checked) {
        if (!real_getpwnam) {
            real_getpwnam = (orig_getpwnam_t)dlsym(RTLD_NEXT, "getpwnam");
        }
        default_user = getenv("NET_SSH_FALLBACK_USER");
        /* Normalize empty string → behave as unset */
        if (default_user && !*default_user) {
            default_user = NULL;
        }
        if (default_user) {
            /* duplicate for safety in case env changes later */
            default_user = strdup(default_user);
        }
        env_checked = 1;
    }
}

/* constructor to run very early when file is loaded */
static void __attribute__((constructor)) init_constructor(void)
{
    /* call pthread_once to be thread-safe even if constructor runs in weird contexts */
    pthread_once(&init_once, init_getpwnam);
}

struct passwd *getpwnam(const char *name) {
    /* Try the real one first */
    struct passwd *pw = real_getpwnam(name);
    if (pw != NULL || !default_user) {
        /* Real user exists → return normally, regardless of failover */
        /* Or if no failover → return the real answer, even if failure */
        return pw;
    }

    /* Failover to default_user */
    pw = real_getpwnam(default_user);
    if (!pw) {
        return NULL; // If even the default_user failed, then there's nothing else I can do to help here.
    }

    // XXX: Does this leak memory by not free'ing the old pw->pw_name string or the pw structure itself?
    // Make a deep copy so we can replace pw_name
    struct passwd *copy = malloc(sizeof(struct passwd));
    memcpy(copy, pw, sizeof(struct passwd));

    // Replace *only* the username
    copy->pw_name = strdup(name);

    return copy;
}
