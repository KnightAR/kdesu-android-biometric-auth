#!/usr/bin/env python3
"""Turn Navi's optional phone approval on or off in PAM, safely.

    navi-pam status [SERVICE] [--json]   anyone; reports each built-in service's state
    navi-pam enable SERVICE              root (System Settings runs it through pkexec)
    navi-pam disable SERVICE             root

SERVICE is one of the approvals this installation was built with:
    sudo  sudo in local Konsole/Kitty terminals   (USE=sudo / ENABLE_SUDO=yes)
    sddm  the SDDM login screen                   (USE=login / ENABLE_LOGIN=yes)
    kde   the Plasma lock screen                  (USE=login / ENABLE_LOGIN=yes)

`enable` inserts one marked block above the first auth rule of /etc/pam.d/SERVICE: the helper
line, preceded by the stack's own `pam_faillock.so preauth` rule when the stack uses faillock (so a
locked account is not offered the phone). For sudo it also adds the Navi approval plugin to
/etc/sudo.conf, which binds a phone approval to the command sudo finally runs; sudo -V must load it,
otherwise the file is restored. `disable` removes only what this tool recognises. Originals are
backed up, new files are written atomically with the same owner and mode and checked afterwards
(restored on any doubt). Files without auth rules are left alone.
"""
import subprocess
import json
import os
import re
import stat
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PAM_DIR = Path("/etc/pam.d")
SUDO_CONF = Path("/etc/sudo.conf")
SUDO = "/usr/bin/sudo"
PLUGIN = "navi_sudo_approval.so"
PLUGIN_MARKER = "# navi-auth: binds sudo phone approvals to the command sudo runs (navi-pam disable sudo removes it)"
FAILLOCK = re.compile(r"^\s*-?auth\s+(\S+|\[[^\]]*\])\s+pam_faillock\.so\s+(.*\bpreauth\b.*?)\s*$")
INCLUDE = re.compile(r"^\s*-?auth\s+(?:include|substack)\s+(\S+)|^\s*@include\s+(\S+)")
BACKUP_DIR = Path("/var/lib/navi-auth")
MAX_SIZE = 65536
SERVICES = {
    "sudo": dict(helper="sudo-approve", options="quiet stdout seteuid",
                 marker="# navi-auth: phone approval for sudo in local Konsole/Kitty (System Settings or navi-pam disable sudo removes it)"),
    "sddm": dict(helper="login-approve", options="quiet stdout expose_authtok",
                 marker="# navi-auth: phone approval at the SDDM login screen, empty password + Enter (System Settings or navi-pam disable sddm removes it)"),
    "kde": dict(helper="login-approve", options="quiet stdout expose_authtok",
                marker="# navi-auth: phone approval at the Plasma lock screen, empty password + Enter (System Settings or navi-pam disable kde removes it)"),
}


def helper_path(service, directory=HERE):
    return directory / SERVICES[service]["helper"]


def available(directory=HERE):
    """Services whose helper was installed by this build."""
    return [service for service in SERVICES if helper_path(service, directory).exists()]


def expected_line(service, helper):
    return f"auth\tsufficient\tpam_exec.so {SERVICES[service]['options']} {helper}"


def faillock_line(pam_dir, service, depth=0, seen=None):
    """The stack's `auth … pam_faillock.so … preauth …` rule (following include/substack), or None."""
    seen = set() if seen is None else seen
    if depth > 4 or service in seen or "/" in service:
        return None
    seen.add(service)
    try:
        text = (pam_dir / service).read_text()
    except OSError:
        return None
    for line in text.splitlines():
        match = FAILLOCK.match(line)
        if match:
            return f"auth\t{match.group(1)}\tpam_faillock.so {' '.join(match.group(2).split())}"
        include = INCLUDE.match(line)
        if include:
            found = faillock_line(pam_dir, include.group(1) or include.group(2), depth + 1, seen)
            if found:
                return found
    return None


def block_indices(lines, service):
    """Indices of this tool's lines: markers, helper rules, and a faillock rule between the two."""
    mine, marker = ours(service), SERVICES[service]["marker"]
    found = set()
    for i, line in enumerate(lines):
        if line.strip() == marker or mine.match(line):
            found.add(i)
        elif FAILLOCK.match(line) and 0 < i < len(lines) - 1 and lines[i - 1].strip() == marker \
                and mine.match(lines[i + 1]):
            found.add(i)
    return found


def ours(service):
    # Any pam_exec rule running this service's helper, whatever its control or options (also hand-written).
    return re.compile(r"^\s*-?auth\s+(\S+|\[[^\]]*\])\s+pam_exec\.so\b(.*)\b"
                      + re.escape(SERVICES[service]["helper"]) + r"\s*$")


def is_auth_rule(line):
    words = line.split()
    return bool(words) and (words[0] in ("auth", "-auth") or words[0].startswith("@include"))


def inspect(text, service, helper, faillock=None):
    """enabled | disabled | misplaced | outdated | unrecognized for one PAM file's text."""
    mine = ours(service)
    lines = text.splitlines()
    block = block_indices(lines, service)
    found = [i for i, line in enumerate(lines) if mine.match(line)]
    first_other = next((i for i, line in enumerate(lines) if is_auth_rule(line) and i not in block), None)
    if first_other is None and not found:
        return "unrecognized"
    if not found:
        return "disabled"
    if len(found) > 1 or any(lines[i].split() != expected_line(service, helper).split() for i in found):
        return "outdated"  # e.g. hand-written without seteuid, or an old helper path
    before = lines[found[0] - 1] if found[0] > 0 else ""
    if faillock and before.split() != faillock.split():
        return "outdated"  # an older block without the stack's faillock check
    if first_other is not None and found[0] > first_other:
        return "misplaced"  # below the password rule: the password would be asked first
    return "enabled"


def without_ours(lines, service):
    block = block_indices(lines, service)
    return [line for i, line in enumerate(lines) if i not in block]


def enabled_text(text, service, helper, faillock=None):
    lines = without_ours(text.splitlines(), service)
    index = next((i for i, line in enumerate(lines) if is_auth_rule(line)), None)
    if index is None:
        raise ValueError("No auth rule found; refusing to change an unrecognized PAM file")
    lines[index:index] = [SERVICES[service]["marker"]] + ([faillock] if faillock else []) + [expected_line(service, helper)]
    return "\n".join(lines) + "\n"


# --- sudo.conf: the Navi approval plugin (sudo only) ---------------------------------------

def plugin_path(directory=HERE):
    return directory / PLUGIN


def plugin_line(directory=HERE):
    return f"Plugin navi_sudo_approval {plugin_path(directory)}"


def plugin_ours(line):
    words = line.split()
    return len(words) >= 3 and words[0] == "Plugin" and words[1] == "navi_sudo_approval"


def conf_state(text, directory=HERE):
    lines = [line for line in text.splitlines() if plugin_ours(line)]
    if not lines:
        return "disabled"
    return "enabled" if len(lines) == 1 and lines[0].split() == plugin_line(directory).split() else "outdated"


def conf_enabled_text(text, directory=HERE):
    lines = conf_disabled_text(text).splitlines() if text else []
    return "\n".join(lines + [PLUGIN_MARKER, plugin_line(directory)]) + "\n"


def conf_disabled_text(text):
    return "".join(line + "\n" for line in text.splitlines() if not plugin_ours(line) and line.strip() != PLUGIN_MARKER)


def sudo_loads_plugin():
    """sudo itself must load the default policy and the Navi plugin with the new sudo.conf."""
    try:
        result = subprocess.run([SUDO, "-V"], capture_output=True, text=True, timeout=20, env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.SubprocessError):
        return False
    output = result.stdout + result.stderr
    return result.returncode == 0 and "Sudoers policy plugin version" in output \
        and "Navi sudo approval plugin" in output


def disabled_text(text, service):
    return "\n".join(without_ours(text.splitlines(), service)) + "\n"


def status(service, pam_dir=PAM_DIR, directory=HERE, sudo_conf=SUDO_CONF):
    helper = helper_path(service, directory)
    pam_file = pam_dir / service
    faillock = faillock_line(pam_dir, service)
    result = {"service": service, "file": str(pam_file), "line": expected_line(service, helper),
              "helper_installed": helper.exists(), "faillock": faillock}
    try:
        result["state"] = inspect(pam_file.read_text(), service, helper, faillock)
    except FileNotFoundError:
        result["state"] = "unrecognized"  # e.g. SDDM not installed
    except OSError as error:
        result["state"] = "unreadable"
        result["error"] = str(error)
    if service == "sudo" and plugin_path(directory).exists():
        try:
            plugin = conf_state(sudo_conf.read_text(), directory) if sudo_conf.exists() else "disabled"
        except OSError:
            plugin = "unreadable"
        result["plugin"] = plugin
        if result["state"] == "enabled" and plugin != "enabled":
            result["state"] = "outdated"  # phone approval without the command binding: Repair adds it
    return result


def read_protected(pam_file):  # also used for sudo.conf
    info = pam_file.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > MAX_SIZE:
        raise ValueError(f"{pam_file} must be a root-owned regular file that only root can write")
    return pam_file.read_text(), info


def write_atomic(pam_file, text, info):
    descriptor, temporary = tempfile.mkstemp(prefix=".navi-auth-", dir=pam_file.parent)
    try:
        with os.fdopen(descriptor, "w") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, info.st_uid, info.st_gid)
        os.chmod(temporary, stat.S_IMODE(info.st_mode))
        os.replace(temporary, pam_file)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    directory = os.open(pam_file.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def backup(backup_dir, name, text):
    backup_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = backup_dir / name
    path.write_text(text)
    os.chmod(path, 0o600)


def change_sudo_conf(enable, directory, backup_dir, sudo_conf, check):
    """Add or remove the plugin line; on enable, sudo must still load (else the file is restored)."""
    if sudo_conf.exists():
        original, info = read_protected(sudo_conf)
    else:
        original, info = None, None
    current = original or ""
    updated = conf_enabled_text(current, directory) if enable else conf_disabled_text(current)
    if updated == current or (original is None and not enable):
        return
    if original is not None:
        backup(backup_dir, "sudo.conf.backup", original)
        write_atomic(sudo_conf, updated, info)
    else:
        fake = os.stat_result((stat.S_IFREG | 0o644, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        write_atomic(sudo_conf, updated, fake)
    if enable and not check():
        if original is not None:
            write_atomic(sudo_conf, original, info)
        else:
            sudo_conf.unlink()
        raise ValueError(f"sudo could not load the Navi approval plugin; {sudo_conf} was restored")


def change(service, enable, pam_dir=PAM_DIR, directory=HERE, backup_dir=BACKUP_DIR, sudo_conf=SUDO_CONF,
           check=sudo_loads_plugin):
    if service not in SERVICES:
        raise ValueError(f"Unknown service {service!r}")
    if os.geteuid() != 0:
        raise PermissionError("Run as root (System Settings asks for the administrator password)")
    helper = helper_path(service, directory)
    if enable and not helper.exists():
        raise FileNotFoundError(f"{helper} is not installed (this approval was not built in)")
    pam_file = pam_dir / service
    original, info = read_protected(pam_file)
    faillock = faillock_line(pam_dir, service)
    if inspect(original, service, helper, faillock) == "unrecognized":
        raise ValueError(f"{pam_file} has no auth rules; refusing to change it")
    binding = service == "sudo" and plugin_path(directory).exists()
    if binding and enable:
        # The binding first: a phone approval is never accepted without it.
        change_sudo_conf(True, directory, backup_dir, sudo_conf, check)
    updated = enabled_text(original, service, helper, faillock) if enable else disabled_text(original, service)
    if updated != original:
        backup(backup_dir, f"pam-{service}.backup", original)
        write_atomic(pam_file, updated, info)
        result = status(service, pam_dir, directory, sudo_conf)
        if result["state"] != ("enabled" if enable else "disabled"):
            write_atomic(pam_file, original, info)
            raise ValueError(f"Unexpected result ({result['state']}); {pam_file} was restored")
    if service == "sudo" and not enable:
        change_sudo_conf(False, directory, backup_dir, sudo_conf, check)  # also when the plugin was uninstalled
    return status(service, pam_dir, directory, sudo_conf)


def main(argv):
    as_json = "--json" in argv
    args = [arg for arg in argv if arg != "--json"]
    command = args[0] if args else ""
    try:
        if command == "status" and len(args) <= 2:
            services = args[1:] or available()
            unknown = [service for service in services if service not in SERVICES]
            if unknown:
                raise ValueError(f"Unknown service {unknown[0]!r}")
            result = {service: status(service) for service in services}
        elif command in ("enable", "disable") and len(args) == 2:
            result = {args[1]: change(args[1], command == "enable")}
        else:
            print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
            return 2
    except Exception as error:
        if as_json:
            print(json.dumps({"error": str(error)}))
        print(f"navi-pam: {error}", file=sys.stderr)
        return 1
    if as_json:
        print(json.dumps(result))
    else:
        for service, value in result.items():
            print(f"{value['file']}: phone approval is {value['state']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
