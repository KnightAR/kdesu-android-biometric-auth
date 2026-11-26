/* SPDX-License-Identifier: MIT
 * Shared by Navi's native entry points (authorize, sudo-approve, login-approve): a clean process
 * state and a check of the installed implementation before any Python code is loaded.
 */
#ifndef NAVI_EXEC_H
#define NAVI_EXEC_H

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef NAVI_LIBEXECDIR
#define NAVI_LIBEXECDIR "/usr/libexec/navi-auth"
#endif
#ifndef NAVI_PYTHON
#define NAVI_PYTHON "/usr/bin/python3"
#endif

/* Loaded by the root authority (rootauth.py check_implementation() keeps the same lists). */
static const char *const navi_required[] = {
    "rootauth.py", "host.py", "navi_pb2.py", "kdeconnect_transport.py", "ntfy_transport.py", NULL};
static const char *const navi_optional[] = {
    "sudo_approve.py", "login_approve.py", "pam_common.py", "pam_switch.py", NULL};

/* A directory and every parent up to "/" must be root-owned and writable only by root. */
static int navi_trusted_directory(const char *path)
{
    char buffer[PATH_MAX];
    if (strlen(path) >= sizeof(buffer) || path[0] != '/')
        return -1;
    strcpy(buffer, path);
    for (;;) {
        struct stat info;
        if (lstat(buffer, &info) || !S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 022))
            return -1;
        char *slash = strrchr(buffer, '/');
        if (slash == buffer) {
            if (buffer[1] == '\0')
                return 0;
            buffer[1] = '\0';
        } else {
            *slash = '\0';
        }
    }
}

/* A regular, root-owned file not writable by group or others, checked on the opened descriptor. */
static int navi_trusted_file(const char *directory, const char *name, int required)
{
    char path[PATH_MAX];
    if (snprintf(path, sizeof(path), "%s/%s", directory, name) >= (int)sizeof(path))
        return -1;
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return (!required && errno == ENOENT) ? 0 : -1;
    struct stat info;
    const int bad = fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_uid != 0 || (info.st_mode & 022);
    close(fd);
    return bad ? -1 : 0;
}

/* The whole installed implementation, before the interpreter loads any of it. */
static int navi_verify_tree(const char *directory)
{
    if (navi_trusted_directory(directory))
        return -1;
    for (const char *const *name = navi_required; *name; ++name)
        if (navi_trusted_file(directory, *name, 1))
            return -1;
    for (const char *const *name = navi_optional; *name; ++name)
        if (navi_trusted_file(directory, *name, 0))
            return -1;
    return 0;
}

/* Close inherited descriptors from `first`, no core dumps, default signals, private umask. */
static int navi_reset_process(int first)
{
    if (close_range((unsigned int)first, UINT_MAX, 0) != 0)
        return -1;
    const struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &core))
        return -1;
    sigset_t empty;
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL))
        return -1;
    struct sigaction action = {.sa_handler = SIG_DFL};
    sigemptyset(&action.sa_mask);
    for (int sig = 1; sig < NSIG; ++sig)
        if (sig != SIGKILL && sig != SIGSTOP)
            sigaction(sig, &action, NULL);
    umask(0077);
    return 0;
}

#endif
