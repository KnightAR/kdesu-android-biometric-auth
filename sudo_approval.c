/* SPDX-License-Identifier: MIT
 * Navi sudo approval plugin: binds a phone approval to the command sudo finally runs.
 *
 * sudo authenticates first (PAM): there, Navi's sudo-approve asks the phone and, only when the
 * phone approved, leaves a root-only record of exactly what the phone showed (the argv after
 * sudo's options, the run-as user and, for a path, the resolved program). sudo then calls this
 * plugin's check() with the policy-resolved command. This plugin:
 *   - no record:   allows (the password or sudo's timestamp authenticated; normal sudo)
 *   - a record:    consumes it and allows only if the resolved command matches it exactly
 *   - any doubt:   denies (malformed, expired, unreadable or unsafe record)
 * It never allows anything sudo's policy did not already allow; it can only refuse.
 *
 * sudo.conf:  Plugin navi_sudo_approval /usr/libexec/navi-auth/navi_sudo_approval.so
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <sudo_plugin.h>

#ifndef NAVI_SUDO_RECORDS
#define NAVI_SUDO_RECORDS "/run/navi-auth/sudo"
#endif
#ifndef NAVI_RECORD_OWNER
#define NAVI_RECORD_OWNER 0 /* tests build with their own uid */
#endif
#define RECORD_MAGIC "navi-sudo-approval 1\n"
#define RECORD_MAX 131072
#define MAX_GROUPS 256
#define DENIED "Navi: sudo would run something other than the command approved on the phone. Run it again and use your password."

static uid_t user_uid = (uid_t)-1;
static gid_t user_groups[MAX_GROUPS];
static int user_group_count;
static char user_cwd[PATH_MAX];
static sudo_printf_t print;

static const char *find(char *const list[], const char *key)
{
    const size_t length = strlen(key);
    for (int i = 0; list && list[i]; ++i)
        if (strncmp(list[i], key, length) == 0 && list[i][length] == '=')
            return list[i] + length + 1;
    return NULL;
}

static int parse_id(const char *text, unsigned long *value)
{
    if (!text || !*text)
        return -1;
    char *end;
    errno = 0;
    *value = strtoul(text, &end, 10);
    return (errno || *end || *value >= (unsigned long)(uid_t)-1) ? -1 : 0;
}

/* Process start time (clock ticks since boot), field 22 of /proc/PID/stat. */
static int start_time(pid_t pid, unsigned long long *value)
{
    char path[64], data[4096];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    const ssize_t length = read(fd, data, sizeof(data) - 1);
    close(fd);
    if (length <= 0)
        return -1;
    data[length] = '\0';
    char *field = strrchr(data, ')');
    if (!field)
        return -1;
    field += 2; /* field 3 (state) */
    for (int index = 3; index < 22; ++index) {
        field = strchr(field, ' ');
        if (!field)
            return -1;
        ++field;
    }
    return sscanf(field, "%llu", value) == 1 ? 0 : -1;
}

static int in_groups(gid_t gid)
{
    for (int i = 0; i < user_group_count; ++i)
        if (user_groups[i] == gid)
            return 1;
    return 0;
}

static int writable_by_user(const struct stat *info)
{
    if (S_ISLNK(info->st_mode))
        return info->st_uid == user_uid; /* a symlink's mode bits mean nothing */
    return info->st_uid == user_uid || ((info->st_mode & S_IWGRP) && in_groups(info->st_gid))
        || (info->st_mode & S_IWOTH);
}

/* Along one absolute path (not resolved): could the user change any entry, or a directory
 * that holds one? Symlinks are not followed here, so a link the user could repoint counts. */
static int chain_changeable(const char *real)
{
    if (real[0] != '/' || strlen(real) >= PATH_MAX)
        return 1;
    char prefix[PATH_MAX];
    size_t position = 0;
    struct stat parent, info;
    if (lstat("/", &parent))
        return 1;
    if (writable_by_user(&parent) && !(parent.st_mode & S_ISVTX))
        return 1;
    for (;;) {
        const char *next = strchr(real + position + 1, '/');
        const size_t end = next ? (size_t)(next - real) : strlen(real);
        memcpy(prefix, real, end);
        prefix[end] = '\0';
        if (lstat(prefix, &info))
            return 1;
        /* the entry itself: the program, or a directory the user owns */
        if (writable_by_user(&info) && (!next || info.st_uid == user_uid))
            return 1;
        /* a directory writable by the user lets them replace this entry, unless it is sticky */
        if (writable_by_user(&parent) && !((parent.st_mode & S_ISVTX) && info.st_uid != user_uid))
            return 1;
        if (!next)
            return 0;
        parent = info;
        position = end;
    }
}

/* Could the invoking user change what `path` runs: along the path as given and as resolved? */
static int user_can_change(const char *path)
{
    char real[PATH_MAX];
    if (chain_changeable(path) || !realpath(path, real))
        return 1; /* unknown counts as changeable (deny) */
    return chain_changeable(real);
}

static int plugin_open(unsigned int version, sudo_conv_t conversation, sudo_printf_t printf_function,
                       char *const settings[], char *const user_info[], int submit_optind, char *const submit_argv[],
                       char *const submit_envp[], char *const plugin_options[], const char **errstr)
{
    (void)conversation; (void)settings; (void)submit_optind; (void)submit_argv; (void)submit_envp; (void)plugin_options;
    print = printf_function;
    if (SUDO_API_VERSION_GET_MAJOR(version) != SUDO_API_VERSION_MAJOR) {
        *errstr = "Navi: incompatible sudo plugin API";
        return -1;
    }
    unsigned long value;
    if (parse_id(find(user_info, "uid"), &value)) {
        *errstr = "Navi: sudo did not report the invoking user";
        return -1;
    }
    user_uid = (uid_t)value;
    const char *groups = find(user_info, "groups");
    user_group_count = 0;
    for (const char *cursor = groups; cursor && *cursor && user_group_count < MAX_GROUPS;) {
        char *end;
        errno = 0;
        const unsigned long gid = strtoul(cursor, &end, 10);
        if (errno || end == cursor)
            break;
        user_groups[user_group_count++] = (gid_t)gid;
        cursor = *end == ',' ? end + 1 : end;
        if (*end != ',')
            break;
    }
    const char *cwd = find(user_info, "cwd");
    snprintf(user_cwd, sizeof(user_cwd), "%s", cwd ? cwd : "/");
    return 1;
}

static void plugin_close(void)
{
}

/* Remove records of sudo processes that no longer exist (they never reached check()). */
static void remove_stale(void)
{
    DIR *directory = opendir(NAVI_SUDO_RECORDS);
    if (!directory)
        return;
    struct dirent *entry;
    int seen = 0;
    while ((entry = readdir(directory)) && seen++ < 1024) {
        int pid;
        unsigned long long start, current;
        char tail;
        if (sscanf(entry->d_name, "%d.%llu%c", &pid, &start, &tail) != 2)
            continue;
        if (start_time(pid, &current) || current != start)
            unlinkat(dirfd(directory), entry->d_name, 0);
    }
    closedir(directory);
}

static int deny(const char **errstr, const char *why)
{
    if (print)
        print(SUDO_CONV_ERROR_MSG, "%s (%s)\n", DENIED, why);
    *errstr = DENIED;
    return 0;
}

static int plugin_check(char *const command_info[], char *const run_argv[], char *const run_envp[],
                        const char **errstr)
{
    (void)run_envp;
    unsigned long long start;
    if (start_time(getpid(), &start))
        return deny(errstr, "no process start time");
    char path[PATH_MAX];
    snprintf(path, sizeof(path), NAVI_SUDO_RECORDS "/%d.%llu", (int)getpid(), start);
    const int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        remove_stale();
        if (errno == ENOENT)
            return 1; /* authenticated by password or timestamp: nothing to bind */
        return deny(errstr, "unreadable approval record");
    }
    static char record[RECORD_MAX + 1];
    struct stat info;
    ssize_t length = -1;
    if (!fstat(fd, &info) && S_ISREG(info.st_mode) && info.st_uid == NAVI_RECORD_OWNER && !(info.st_mode & 077)
        && info.st_size <= RECORD_MAX)
        length = read(fd, record, RECORD_MAX + 1);
    close(fd);
    unlink(path); /* single use, whatever the outcome */
    remove_stale();
    if (length <= 0 || length > RECORD_MAX)
        return deny(errstr, "invalid approval record");
    record[length] = '\0';

    /* Header lines, a blank line, then argc NUL-terminated arguments. */
    if (strncmp(record, RECORD_MAGIC, strlen(RECORD_MAGIC)) != 0)
        return deny(errstr, "unknown record format");
    char *cursor = record + strlen(RECORD_MAGIC);
    unsigned long uid = 0, runas = 0, argc = 0;
    long long expires = 0;
    char command[PATH_MAX] = "";
    int have = 0;
    while (cursor < record + length && *cursor != '\n') {
        char *end = memchr(cursor, '\n', (size_t)(record + length - cursor));
        if (!end)
            return deny(errstr, "truncated record");
        *end = '\0';
        if (sscanf(cursor, "uid %lu", &uid) == 1)
            have |= 1;
        else if (sscanf(cursor, "runas_uid %lu", &runas) == 1)
            have |= 2;
        else if (sscanf(cursor, "expires %lld", &expires) == 1)
            have |= 4;
        else if (sscanf(cursor, "argc %lu", &argc) == 1)
            have |= 8;
        else if (strncmp(cursor, "command ", 8) == 0 && strlen(cursor + 8) < sizeof(command))
            strcpy(command, cursor + 8), have |= 16;
        else
            return deny(errstr, "unknown record field");
        cursor = end + 1;
    }
    if (have != 31 || cursor >= record + length || argc == 0 || argc > 4096)
        return deny(errstr, "incomplete record");
    ++cursor; /* the blank line */

    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) || (long long)now.tv_sec > expires)
        return deny(errstr, "the phone approval expired");
    if (uid != (unsigned long)user_uid)
        return deny(errstr, "approved for another user");
    unsigned long target;
    if (parse_id(find(command_info, "runas_uid"), &target) || target != runas)
        return deny(errstr, "different run-as user");

    /* The arguments after the program must be byte-identical. */
    unsigned long index = 0;
    const char *approved_program = cursor;
    for (; index < argc; ++index) {
        const char *end = memchr(cursor, '\0', (size_t)(record + length - cursor));
        if (!end || !run_argv[index])
            return deny(errstr, "different arguments");
        if (index > 0 && strcmp(cursor, run_argv[index]) != 0)
            return deny(errstr, "different arguments");
        cursor = (char *)end + 1;
    }
    if (run_argv[index] || cursor != record + length)
        return deny(errstr, "different arguments");

    /* The program: a path must resolve to the same file; a bare name must be that program and not
     * one the user can change (a PATH lookup the phone never showed). */
    const char *resolved = find(command_info, "command");
    if (!resolved || !*resolved)
        return deny(errstr, "no resolved command");
    char absolute[PATH_MAX * 2];
    if (resolved[0] == '/')
        snprintf(absolute, sizeof(absolute), "%s", resolved);
    else
        snprintf(absolute, sizeof(absolute), "%s/%s", find(command_info, "cwd") ? find(command_info, "cwd") : user_cwd,
                 resolved);
    if (command[0]) {
        char real[PATH_MAX];
        if (!realpath(absolute, real) || strcmp(real, command) != 0)
            return deny(errstr, "a different program");
    } else {
        const char *base = strrchr(absolute, '/');
        base = base ? base + 1 : absolute;
        if (strchr(approved_program, '/') || strcmp(base, approved_program) != 0)
            return deny(errstr, "a different program");
        if (user_can_change(absolute))
            return deny(errstr, "the program is one you can change");
    }
    return 1;
}

static int plugin_version(int verbose)
{
    (void)verbose;
    if (print)
        print(SUDO_CONV_INFO_MSG, "Navi sudo approval plugin version 1\n");
    return 1;
}

__attribute__((visibility("default"))) struct approval_plugin navi_sudo_approval = {
    .type = SUDO_APPROVAL_PLUGIN,
    .version = SUDO_API_VERSION,
    .open = plugin_open,
    .close = plugin_close,
    .check = plugin_check,
    .show_version = plugin_version,
};
