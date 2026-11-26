/* SPDX-License-Identifier: MIT
 * Small setuid entry point. No request content is interpreted by this launcher.
 * The installed verifier owns policy, biometric verification and exact execution.
 */
#define _GNU_SOURCE
#include <grp.h>
#include <stdlib.h>

#include "navi_exec.h"

static int fail(const char *message)
{
    fprintf(stderr, "Navi authorization: %s\n", message);
    return 1;
}

int main(int argc, char **argv)
{
    (void)argv;
    const int error_flags = fcntl(STDERR_FILENO, F_GETFL);
    if (error_flags >= 0)
        fcntl(STDERR_FILENO, F_SETFL, error_flags | O_NONBLOCK);
    const uid_t caller = getuid();
    struct stat input, output;
    if (argc != 1 || caller == 0 || geteuid() != 0)
        return fail("use the installed helper from the desktop account");
    if (fstat(STDIN_FILENO, &input) || fstat(STDOUT_FILENO, &output)
        || !S_ISFIFO(input.st_mode) || !S_ISFIFO(output.st_mode))
        return fail("standard input and output must be private process pipes");

    char uid[32];
    if (snprintf(uid, sizeof(uid), "%lu", (unsigned long)caller) >= (int)sizeof(uid))
        return fail("invalid invoking account");
    if (clearenv() || setgroups(0, NULL) || setresgid(0, 0, 0) || setresuid(0, 0, 0) || chdir("/"))
        return fail("could not establish the protected execution environment");
    if (navi_reset_process(3))
        return fail("could not reset inherited descriptors, signals and limits");
    /* Checked before the interpreter loads any of it (rootauth.py repeats the check). */
    if (navi_verify_tree(NAVI_LIBEXECDIR))
        return fail("the installed implementation is not root-owned and protected");
    alarm(180); /* Absolute process lifetime, including shutdown after a lost GUI. */
    char *const arguments[] = {NAVI_PYTHON, "-I", NAVI_LIBEXECDIR "/rootauth.py", "--stdio", uid, NULL};
    char *const environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LANG=C.UTF-8", NULL};
    execve(arguments[0], arguments, environment);
    return fail("could not start the installed verifier");
}
