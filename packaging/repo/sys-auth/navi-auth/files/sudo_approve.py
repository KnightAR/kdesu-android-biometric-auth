#!/usr/bin/env python3
"""Optional: approve `sudo` from a local Kitty/Konsole terminal on the enrolled phone.

Installed only when built with sudo approval (`make install ENABLE_SUDO=yes`, Gentoo USE=sudo),
and active only after an administrator adds this to /etc/pam.d/sudo, before system-auth:

    auth  sufficient  pam_exec.so quiet stdout seteuid /usr/libexec/navi-auth/sudo-approve

pam_exec runs this inside sudo; `seteuid` makes it run as root (without it, pam_exec uses the
invoking user's real UID and this helper always falls back to the password). Exit 0 approves; any other exit lets PAM continue to the
normal password prompt. Phone approval is offered only when every check below passes; the
terminal check decides *where* the phone is offered, it is not a security boundary against code
already running as the user. The fingerprint approval on the phone is the gate.
"""
import argparse
import asyncio
import fcntl
import importlib.util
import os
import pwd
import re
import shlex
import signal
import sys
import tempfile
import time
import uuid
from pathlib import Path

TERMINAL_NAMES = {"konsole": "Konsole", "kitty": "Kitty"}


def _common():
    spec = importlib.util.spec_from_file_location("navi_pam_common", Path(__file__).resolve().with_name("pam_common.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_pam = _common()
Skip, say, proc_exe, proc_parent_and_uid = _pam.Skip, _pam.say, _pam.proc_exe, _pam.proc_parent_and_uid
desktop_environment, load_rootauth = _pam.desktop_environment, _pam.load_rootauth
SSHD_NAMES, MAX_DEPTH = _pam.SSHD_NAMES, _pam.MAX_DEPTH


def find_terminal(sudo_pid, uid, terminals, root="/proc", program=None):
    """The allowed terminal emulator above sudo, owned by the user; no sshd anywhere in the chain.

    If `program` is a list, the name of the program the terminal is running (for example an
    agent such as claude or codex, two levels below the terminal: terminal → shell → program) is
    appended when it is not sudo itself. It is a label for the phone, not a security check.
    """
    found = None
    pid = sudo_pid
    chain = []  # comm names from sudo's parent upwards
    for _ in range(MAX_DEPTH):
        ppid, _, _ = proc_parent_and_uid(pid, root)
        if ppid <= 1:
            break
        pid = ppid
        _, owner, comm = proc_parent_and_uid(pid, root)
        exe = proc_exe(pid, root)
        if comm in SSHD_NAMES or os.path.basename(exe) in SSHD_NAMES:
            raise Skip("sudo runs inside an SSH session")
        if found is None:
            if exe in terminals and owner == uid:
                found = exe
                if program is not None and len(chain) >= 2:
                    name = chain[-2]  # terminal → shell (chain[-1]) → program (chain[-2])
                    if re.fullmatch(r"[A-Za-z0-9_.+-]{1,32}", name) and name != "sudo":
                        program.append(name)
            else:
                chain.append(comm)
    if found is None:
        raise Skip("sudo is not running in an allowed local terminal")
    return found


SUDO = "/usr/bin/sudo"
RECORDS = Path("/run/navi-auth/sudo")  # read and removed by the Navi sudo approval plugin
RECORD_TTL = 120  # seconds the binding record stays valid (sudo checks it right after PAM)
# sudo's options (sudo 1.9). The phone is offered only for a plain `sudo [options] [VAR=value] command`:
# shells, login shells, sudoedit, listing, validation, background jobs and options that change
# the group, directory, root or host are left to the password (what runs would not be the text shown).
SHORT_FLAGS, SHORT_VALUES, SHORT_REFUSED = set("ABEHkNnPS"), set("CpTu"), set("bDegKhilRrsUtVv")
LONG_FLAGS = {"askpass", "bell", "preserve-env", "set-home", "reset-timestamp", "non-interactive", "preserve-groups",
              "stdin"}
LONG_VALUES = {"close-from", "prompt", "command-timeout", "user"}
LONG_REFUSED = {"background", "chdir", "edit", "group", "help", "host", "login", "remove-timestamp", "list", "chroot",
                "shell", "other-user", "version", "validate", "role", "type"}
ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.S)


def parse_sudo(argv):
    """(index of the command in argv, target user) for a plain `sudo [options] [VAR=value…] command…`."""
    if not argv or os.path.basename(argv[0]) != "sudo":
        raise Skip("not a plain sudo command line (sudoedit or another front end)")
    target, index = "root", 1
    while index < len(argv):
        arg = argv[index]
        if arg == "--":
            index += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        if arg.startswith("--"):
            name, equals, value = arg[2:].partition("=")
            if name in LONG_REFUSED:
                raise Skip(f"sudo --{name} is left to the password")
            if name in LONG_FLAGS and (not equals or name == "preserve-env"):
                index += 1
                continue
            if name not in LONG_VALUES:
                raise Skip(f"unknown sudo option --{name}")
            if not equals:
                index += 1
                if index >= len(argv):
                    raise Skip(f"sudo --{name} without a value")
                value = argv[index]
            if name == "user":
                target = value
            index += 1
            continue
        position = 1
        while position < len(arg):
            letter = arg[position]
            if letter in SHORT_REFUSED:
                raise Skip(f"sudo -{letter} is left to the password")
            if letter in SHORT_FLAGS:
                position += 1
                continue
            if letter not in SHORT_VALUES:
                raise Skip(f"unknown sudo option -{letter}")
            value = arg[position + 1:]
            if not value:
                index += 1
                if index >= len(argv):
                    raise Skip(f"sudo -{letter} without a value")
                value = argv[index]
            if letter == "u":
                target = value
            break
        index += 1
    while index < len(argv) and ASSIGNMENT.fullmatch(argv[index]):
        index += 1  # VAR=value: environment for the command (sudoers decides whether it is allowed)
    if index >= len(argv):
        raise Skip("no command to approve")
    return index, target


def target_uid(target):
    """The run-as user's uid (sudo accepts a name or #uid)."""
    try:
        return int(target[1:]) if re.fullmatch(r"#[0-9]{1,10}", target) else pwd.getpwnam(target).pw_uid
    except (KeyError, ValueError):
        raise Skip("unknown run-as user") from None


def sudo_command(argv, limit=None):
    """Display text and target user from sudo's own argv.

    The whole command is always shown: a command longer than the phone's display limit is not
    offered for phone approval at all (Skip), so nothing can be approved with a hidden tail. What
    runs is then bound to this text by the Navi sudo approval plugin.
    """
    _, target = parse_sudo(argv)
    text = "sudo " + shlex.join(argv[1:])
    # Newlines and tabs are kept (Navi lays them out); other invisible characters become "?".
    text = "".join(c if c.isprintable() or c in "\n\t" else "?" for c in text)
    for low, high in ((0x202a, 0x202e), (0x2066, 0x2069)):
        text = "".join("?" if low <= ord(c) <= high else c for c in text)
    if limit is not None and len(text) > limit:
        raise Skip(f"command too long to show on the phone ({len(text)} characters; limit {limit})")
    if not re.fullmatch(r"#?[A-Za-z0-9_.@-]{1,64}", target):
        raise Skip("unusual run-as user")
    return text, target


def sudo_binary_ok(path):
    """The installed sudo: root-owned, setuid, not writable by others."""
    try:
        info = os.stat(path)
    except OSError:
        return False
    return info.st_uid == 0 and info.st_mode & 0o4000 and not info.st_mode & 0o022


def start_time(pid, root="/proc"):
    """A process's start time in clock ticks since boot (stat field 22): with the pid, a unique key."""
    with open(f"{root}/{pid}/stat", "rb") as stat_file:
        data = stat_file.read(4096).decode(errors="replace")
    return int(data[data.rindex(")") + 2:].split()[19])


def write_record(directory, sudo_pid, uid, runas_uid, argv, program, now=None):
    """The root-only record the Navi sudo approval plugin checks the resolved command against.

    argv: the approved command's exact argument bytes; program: the resolved path when the command
    was given as a path, else "" (the plugin then requires that bare name, from a place the user
    cannot change)."""
    if "\n" in program or any(b"\0" in arg for arg in argv):
        raise ValueError("Unrecordable command")
    now = time.clock_gettime(time.CLOCK_BOOTTIME) if now is None else now
    header = "\n".join(["navi-sudo-approval 1", f"uid {uid}", f"runas_uid {runas_uid}",
                        f"expires {int(now) + RECORD_TTL}", f"argc {len(argv)}", f"command {program}"])
    data = header.encode() + b"\n\n" + b"".join(arg + b"\0" for arg in argv)
    final = Path(directory) / f"{sudo_pid}.{start_time(sudo_pid)}"
    descriptor, temporary = tempfile.mkstemp(prefix=".record-", dir=directory)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, final)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return final


def check_pam(environ):
    if os.geteuid() != 0:
        raise Skip("not running as root (add 'seteuid' to the pam_exec line in /etc/pam.d/sudo)")
    if environ.get("PAM_SERVICE") != "sudo" or environ.get("PAM_TYPE") != "auth":
        raise Skip("only sudo authentication is supported")
    if environ.get("PAM_RHOST"):
        raise Skip("remote host")
    if not re.fullmatch(r"/dev/pts/[0-9]{1,6}", environ.get("PAM_TTY", "")):
        raise Skip("no terminal")
    user = environ.get("PAM_USER", "")
    try:
        return pwd.getpwnam(user)
    except KeyError:
        raise Skip("unknown user") from None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--terminal", action="append", default=[], help="Allowed terminal executable (repeatable)")
    parser.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    terminals = set(args.terminal) or {"/usr/bin/konsole", "/usr/bin/kitty"}
    timeout = max(10, min(args.timeout, 115))  # the phone request lifetime is at most 120 s
    rootauth = None
    try:
        account = check_pam(os.environ)
        sudo_pid = os.getppid()
        if proc_exe(sudo_pid) != SUDO or not sudo_binary_ok(SUDO):
            raise Skip("not started by the installed sudo")
        program = []
        terminal = find_terminal(sudo_pid, account.pw_uid, terminals, program=program)
        with open(f"/proc/{sudo_pid}/cmdline", "rb") as cmdline:
            raw = cmdline.read(65537)
        if len(raw) > 65536 or not raw.endswith(b"\0"):
            raise Skip("sudo command line too long")
        raw_argv = raw.split(b"\0")[:-1]  # every argument, empty ones included, as exact bytes
        sudo_argv = [part.decode(errors="replace") for part in raw_argv]
        rootauth = load_rootauth()
        try:
            index, _ = parse_sudo(sudo_argv)
        except Skip as reason:
            if "left to the password" in str(reason):
                say(f"Phone approval is not offered here ({reason}).")
            raise
        try:
            command, target = sudo_command(sudo_argv, rootauth.crypto.MAX_COMMAND)
        except Skip as reason:
            if "too long" in str(reason):
                say(f"This command is too long to review on the phone (limit {rootauth.crypto.MAX_COMMAND} characters) — use your password, or split it up.")
            raise
        runas_uid = target_uid(target)
        approved = raw_argv[index:]
        sudo_cwd = os.readlink(f"/proc/{sudo_pid}/cwd")
        # A program given as a path is bound to the file it resolves to; a bare name to that name
        # found by sudo somewhere the user cannot change (checked by the plugin).
        resolved = os.path.realpath(os.path.join(sudo_cwd, sudo_argv[index])) if "/" in sudo_argv[index] else ""
        writable = rootauth.writable_inputs(sudo_argv[index:], account.pw_uid,
                                            os.getgrouplist(account.pw_name, account.pw_gid), sudo_cwd)
        rootauth.check_implementation()
        rootauth.private_directory(rootauth.STATE, 0o700)
        rootauth.private_directory(rootauth.RUNTIME, 0o755)
        rootauth.private_directory(RECORDS, 0o700)
        try:
            environment = rootauth.validate_environment(desktop_environment(sudo_pid), account.pw_uid)
        except Exception:
            environment = {}  # KDE Connect needs the session bus; LAN and ntfy routes do not.
        name = TERMINAL_NAMES.get(os.path.basename(terminal), os.path.basename(terminal))
        # Which program asked (e.g. an agent running in the terminal), shown on the phone and logged.
        label = f"{name} · {program[0]}" if program else name
        tty = os.environ["PAM_TTY"]
        request = str(uuid.uuid4())
        with (rootauth.STATE / "authority.lock").open("a") as lock:
            # One phone request at a time: later ones (e.g. other agents) wait their turn.
            waited = False
            give_up = time.monotonic() + timeout
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= give_up:
                        say(f"Not approved on the phone (busy: another Navi request is still waiting) — request {request[:8]}.")
                        raise Skip(f"another Navi request is in progress; gave up after {timeout} s desktop={request}") from None
                    if not waited:
                        say(f"Waiting for another Navi request to finish… (request {request[:8]})")
                        waited = True
                    time.sleep(0.5)
            authority = rootauth.Authority()
            if authority.account.pw_uid != account.pw_uid:
                raise Skip("this account is not enrolled for phone approval")
            context = {"application": f"sudo · {label}"[:80], "action_id": "sudo", "command": command,
                       "command_hidden": False, "requesting_user": account.pw_name, "requesting_uid": account.pw_uid,
                       "target_user": target, "source": "sudo", "mode": "approve", "icon_name": "utilities-terminal",
                       "icon_png_base64": "", "tty": os.environ["PAM_TTY"], "writable_paths": writable}
            rootauth.audit(f"sudo-start desktop={request} user={account.pw_name} terminal={name} "
                           f"program={program[0] if program else '-'} tty={tty}")
            say(f"Approve this sudo in Navi on your phone… (request {request[:8]}; Ctrl-C to cancel; password after {timeout} s)")
            try:
                asyncio.run(_approve(authority, context, environment, timeout, label, request))
            finally:
                authority.db.close()
            # Without this record the approval plugin cannot bind what runs, so no record, no approval.
            write_record(RECORDS, sudo_pid, account.pw_uid, runas_uid, approved, resolved)
            say(f"Approved on the phone — request {request[:8]}.")
        return 0
    except Skip as reason:
        if rootauth is None:
            try:
                rootauth = load_rootauth()
            except Exception:
                pass
        if rootauth is not None:
            rootauth.audit(f"sudo-skipped: {reason}")
        return 1
    except (Exception, KeyboardInterrupt, asyncio.CancelledError) as error:
        if rootauth is not None:
            rootauth.audit(f"sudo-not-approved: {type(error).__name__}: {error}"[:300])
        reason = "failed"
        if rootauth is not None:
            reason = {rootauth.Rejected: "rejected", rootauth.Unanswered: "timed out",
                      rootauth.Undelivered: "phone unreachable"}.get(type(error), reason)
        if isinstance(error, (KeyboardInterrupt, asyncio.CancelledError)):
            reason = "canceled"
        say(f"Not approved on the phone ({reason}) — use your password.")
        return 1


async def _approve(authority, context, environment, timeout, name, request):
    loop = asyncio.get_running_loop()
    task = asyncio.current_task()
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        loop.add_signal_handler(sig, task.cancel)
    await authority.approve_only(context, environment, time.monotonic() + timeout,
                                 f"Approve sudo in {name}"[:160], "sudo", desktop_id=request)


if __name__ == "__main__":
    sys.exit(main())
