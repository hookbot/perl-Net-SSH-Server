#define _GNU_SOURCE
#include <dlfcn.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>

/* Pointer to the original getpwnam() */
typedef struct passwd *(*orig_getpwnam_t)(const char *);
static orig_getpwnam_t real_getpwnam = NULL;

/* Read the env variable only once */
static const char *unknown_user_default = NULL;
static int env_checked = 0;

static void init_real(void) {
    if (!real_getpwnam) {
        real_getpwnam = (orig_getpwnam_t)dlsym(RTLD_NEXT, "getpwnam");
    }
}

static void init_env(void) {
    if (!env_checked) {
        unknown_user_default = getenv("NET_SSH_INVALID_USER");
        /* Normalize empty string → behave as unset */
        if (unknown_user_default && unknown_user_default[0] == '\0') {
            unknown_user_default = NULL;
        }
        env_checked = 1;
    }
}

struct passwd *getpwnam(const char *name) {
    init_real();
    init_env();

    /* Call the real one first */
    struct passwd *pw = real_getpwnam(name);
    if (pw != NULL) {
        return pw;  /* Real user exists → return normally */
    }

    /* Real lookup failed; if unknown-user fallback is NOT configured → fail */
    if (!unknown_user_default) {
        return NULL;
    }

    /* Try to map to UNKNOWN_USER_DEFAULT */
    return real_getpwnam(unknown_user_default);
}
