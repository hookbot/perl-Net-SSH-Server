package Net::SSH::Server::FallbackUser;

use strict;
use warnings;

our $codefile = "/var/run/sshd/netssh_getpwnam_override";

sub shared_object {
    my $c = "$codefile.c";
    my $o = "$codefile.so";
    if (!-f $c or -M _ >= -M __FILE__) {
        open my $fh, ">", $c;
        print $fh <DATA>;
        close $fh;
    }
    return undef if !-s $c;
    if (!-f $o or -M _ >= -M $c) {
        `gcc -fPIC -shared -ldl $c -o $o 2>&1`;
    }
    return $o if -s $o;
    return undef;
}

1;

__DATA__
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pwd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>

/* Stolen from /usr/include/bits/local_lim.h */
#define LOGIN_NAME_MAX 256

/* Pointer to the original getpwnam() */
typedef struct passwd *(*orig_getpwnam_t)(const char *);
static orig_getpwnam_t real_getpwnam = NULL;

/* Read the env variable only once */
static const char *default_user = NULL;
static char *default_shell = NULL;
static int initialized = 0;

/* static structure to avoid memory leaks of malloc */
static struct passwd fallback_pw;
static char fallback_name[LOGIN_NAME_MAX + 1]; /* avoid memory leaks from strdup */

/* once control so init runs exactly once even if constructor + race */
static pthread_once_t init_once = PTHREAD_ONCE_INIT;

static void init_getpwnam(void) {
    if (!initialized) {
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
        default_shell = getenv("NET_SSH_FALLBACK_SHELL");
        if (default_shell && !*default_shell) {
            default_shell = NULL;
        }
        if (default_shell) {
            /* duplicate for safety in case env changes later */
            default_shell = strdup(default_shell);
        }
        initialized = 1;
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

    // Copy entire passwd struct (shallow copy)
    fallback_pw = *pw;
    strncpy(fallback_name, name, LOGIN_NAME_MAX);
    fallback_name[LOGIN_NAME_MAX] = '\0';
    fallback_pw.pw_name = fallback_name;
    if (default_shell) fallback_pw.pw_shell = default_shell;

    return &fallback_pw;
}
