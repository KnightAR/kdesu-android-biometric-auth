/* SPDX-License-Identifier: MIT
 * pam_exec entry point for Navi's optional phone approvals, installed as `sudo-approve` and
 * `login-approve` (the name selects the helper). It replaces a /bin/sh wrapper: no shell, and the
 * PAM environment (which a user can partly influence) is reduced to the PAM_* items the helpers
 * read, each checked, before the fixed interpreter command runs. Nothing here grants anything:
 * any failure exits non-zero, so PAM continues to the password.
 */
#define _GNU_SOURCE
#include <stdlib.h>

#include "navi_exec.h"

#ifndef NAVI_SUDO_TERMINALS
#define NAVI_SUDO_TERMINALS "/usr/bin/konsole", "/usr/bin/kitty"
#endif
#ifndef NAVI_SUDO_TIMEOUT
#define NAVI_SUDO_TIMEOUT "60"
#endif

static const char *const kept[] = {"PAM_SERVICE", "PAM_TYPE", "PAM_USER", "PAM_RUSER", "PAM_RHOST", "PAM_TTY", NULL};

/* Printable ASCII only, bounded: these values are service, user, terminal and host names. */
static int plain_value(const char *value)
{
    size_t length = 0;
    for (const char *c = value; *c; ++c, ++length)
        if (*c < 0x20 || *c > 0x7e || length >= 256)
            return 0;
    return 1;
}

int main(int argc, char **argv)
{
    (void)argc;
    const char *name = argv[0] ? strrchr(argv[0], '/') : NULL;
    name = name ? name + 1 : (argv[0] ? argv[0] : "");
    const int sudo = strcmp(name, "sudo-approve") == 0;
    if (!sudo && strcmp(name, "login-approve") != 0)
        return 1;

    /* A fixed base plus the checked PAM items; nothing else from the PAM environment survives. */
    static char storage[6][300];
    char *environment[10] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "HOME=/", NULL};
    int count = 3, used = 0;
    for (const char *const *key = kept; *key; ++key) {
        const char *value = getenv(*key);
        if (!value || !plain_value(value))
            continue;
        snprintf(storage[used], sizeof(storage[used]), "%s=%s", *key, value);
        environment[count++] = storage[used++];
    }
    environment[count] = NULL;

    /* stdin stays open: login-approve reads the typed password field (expose_authtok). */
    if (navi_reset_process(3) || navi_verify_tree(NAVI_LIBEXECDIR))
        return 1;

    char *arguments[16];
    int n = 0;
    arguments[n++] = NAVI_PYTHON;
    arguments[n++] = "-I";
    if (sudo) {
        static const char *const terminals[] = {NAVI_SUDO_TERMINALS, NULL};
        arguments[n++] = NAVI_LIBEXECDIR "/sudo_approve.py";
        arguments[n++] = "--timeout";
        arguments[n++] = NAVI_SUDO_TIMEOUT;
        for (const char *const *terminal = terminals; *terminal && n < 13; ++terminal) {
            arguments[n++] = "--terminal";
            arguments[n++] = (char *)*terminal;
        }
    } else {
        arguments[n++] = NAVI_LIBEXECDIR "/login_approve.py";
    }
    arguments[n] = NULL;
    execve(arguments[0], arguments, environment);
    return 1;
}
