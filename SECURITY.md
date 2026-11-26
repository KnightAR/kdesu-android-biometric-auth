# Security model and known limitations

This is experimental software that installs a setuid root helper. The intended
boundary is: an enrolled desktop account can request an exact command, but the
protected authority executes it only after a fresh signature from the approved
phone and an explicit desktop commit. A successful normal flow is not proof that
all malicious flows are excluded.

## What approval establishes

- An approved phone key signed its own `Approval` naming the SHA-256 of the exact
  fresh request bytes (protocol v2, [`proto/navi.proto`](proto/navi.proto)). The
  biometric key signs only messages Navi writes itself; every signed message is
  typed, so one kind cannot be accepted as another. Signatures are checked over
  the exact received bytes, which are never re-serialized. Paired requests carry
  no certificates: Navi uses the ones stored at pairing.
- The installed helper checks the kernel-derived desktop UID, protected trust,
  certificate, nonce, deadline, command context and one-time request consumption.
- Android is configured to require a strong biometric for each signing operation.
- TLS is pinned through the approved phone biometric key. Learning the IP address
  or injecting a generic notification does not authorize a command.

It does not establish that caller-supplied application branding is truthful,
that referenced scripts remain unchanged, that the phone software/update channel
is uncompromised, or that the machine has verified remote hardware attestation.

## Open findings

### Development access and APK signing custody

**High impact, conditional on development access.** The old debuggable APK exposed
its process to an authorized development host. Android 0.8.1 release mode fixes
that flag and denies `run-as`. However, possession of the app signing key plus
usable authorized ADB can allow a modified compatible update. A malicious approval
UI can misdescribe the bytes the user is authorizing. This is not extraction of
the hardware private key or a demonstrated bypass of fresh biometrics.

Keep the APK key away from a potentially compromised development account when
establishing a stronger production boundary. Disable unnecessary ADB access.
The current offline builder retains its historical development signing-key
workflow for update compatibility; non-debuggable does not mean independently
protected update signing. Never distribute a private key or silently rotate it.
See [Android app signing](https://developer.android.com/studio/publish/app-signing),
[debuggable guidance](https://developer.android.com/privacy-and-security/risks/android-debuggable),
and [Keystore limitations](https://developer.android.com/privacy-and-security/keystore).

### Requester branding can be spoofed

**Medium, local request spoofing requiring user approval.** Application name,
executable, PID, source/action strings and icon are supplied by the requester in
[`validate_start`](rootauth.py). The UID/account is kernel-checked; the branding
does not have equivalent provenance. A process under the enrolled UID can call
itself another application. Signing those fields preserves the claim but does
not prove it.

Review the exact command. The intended fix is to label requester branding as
informational and clearly distinguish it from verified machine/account context.
Kernel process metadata can improve diagnostics, but does not create strong
isolation between processes sharing a UID. Agent instructions are not an OS
boundary preventing direct helper invocation.

## Architecture limits

- **Mutable command inputs:** signing `/path/script` does not freeze that script,
  executable, imports or data. Use the same verified byte buffer or a protected
  immutable snapshot. A digest check followed by reopening a writable pathname
  leaves a replacement race. As a warning, not a fix: the root side checks the
  program (resolved through the execution `PATH`) and every argument naming an
  existing file, and signs those the requesting user can change (the file, a
  directory the user owns or can write on the way, or a symlink the user could
  repoint) into the request; Navi shows them prominently ("Runs files you can
  change"). For kdesu the command is split with shell quoting rules as a
  best-effort heuristic (expansions, redirections and files opened indirectly are
  not seen). The approval still covers the text, not those files' contents.
- **Root trusted computing base:** the root side is Python (`rootauth.py`,
  `host.py`, protobuf, `cryptography`), and the direct-network TLS client and
  ntfy decryption run in the root process (KDE Connect D-Bus and ntfy HTTP run in
  workers dropped to the user). The native entry points (`authorize`,
  `sudo-approve`, `login-approve`) verify that every installed implementation
  file and its directories up to `/` are root-owned and not group/other-writable
  before the interpreter starts, and `rootauth.py` repeats the check before it
  loads `host.py`. The planned next step is a small native broker for keys,
  verification, single-use state and execution, with all phone transport in an
  unprivileged process.
- **Development machine key:** configuring root authority copies the machine
  key from user state. A retained user copy means a machine signature alone does
  not prove root-broker origin. Protected execution records are separate evidence.
- **Revocation:** configuration is rechecked at commit. Already committed commands
  are not undone. A stronger guarantee about concurrent revoke return versus
  consume/spawn needs a defined synchronization contract and further validation.
- **Authority status:** the setuid helper answers a read-only `status` request
  from any local account. Only the configured desktop account receives phone key
  IDs, enablement, routes and certificate expiry; other accounts learn only that
  an authority is configured. Logs, executions and certificates are never returned.
  The helper's existing `revoke` request likewise only disables the caller's own
  device. Neither request can enable a phone.
- **Enabling from System Settings:** adding a phone to the root authority always
  needs the administrator password (polkit `auth_admin`, never cached). The polkit
  entry point only runs the installed configurator, which re-validates the machine
  key, phone certificate and route as root. When started by pkexec it also refuses
  any desktop account other than the requesting user (`PKEXEC_UID`) and any source
  state directory that is not that user's own mode-0700 directory.
- **Trusted phone enrollment:** release builds enroll with a one-time
  8-character code shown on the computer and typed into the phone, carried over
  an existing KDE Connect pairing (see [Architecture](docs/ARCHITECTURE.md#code-enrollment-release-builds)).
  Trust therefore rests on the KDE Connect pairing, the user reading the code from
  the intended screen and the biometric signature. Anyone who can see the code
  *and* controls the selected paired KDE Connect device during its ten minutes
  could enroll that device; compare the computer fingerprint shown on the phone.
  The code is 40 bits and is only checked inside KDE Connect's encrypted channel.
  Enrolling only grants account-level approval; administrator prompts still need
  the separate protected configuration. Android 9 cannot receive KDE Connect
  messages, so it keeps the debug-APK and authorized-ADB bootstrap. Release
  builds reject unknown computer keys and every enrollment without a matching
  code pin in the shared validator. This flow has not yet been verified on
  hardware (see [verification record](docs/VERIFICATION.md)).
- **Remote approvals (ntfy):** optional. While KDE Connect sees the phone nothing
  is sent to the relay. Otherwise messages pass through the configured ntfy server,
  end-to-end encrypted with a key derived from a biometric-approved ECDH setup and
  never transmitted; authenticity still rests on the machine and phone signatures.
  The relay learns topic names, IP addresses, timing and sizes, and can delay or
  drop messages (availability, not authorization). The optional ntfy access token
  is sent to Navi inside the signed setup request over KDE Connect. See
  [Remote approvals](docs/REMOTE.md).
- **Optional sudo, login and lock-screen approval:** built only with
  `USE=sudo` / `USE=login` (`ENABLE_SUDO` / `ENABLE_LOGIN`) and active only after
  an administrator switches each on (`navi-pam`, polkit `auth_admin`), which adds
  a marked block to `/etc/pam.d/sudo`, `sddm` or `kde`: the stack's own
  `pam_faillock.so preauth` rule (when the stack uses faillock, so a locked account
  is not offered the phone), then one `pam_exec` line. pam_exec starts a small
  native entry point, not a shell: it keeps only the checked `PAM_SERVICE`,
  `PAM_TYPE`, `PAM_USER`, `PAM_RUSER`, `PAM_RHOST` and `PAM_TTY` values from the
  PAM environment (which a user can partly influence), resets descriptors,
  signals and limits, verifies the installed implementation and runs a fixed
  `python3 -I` command.
  - sudo: the helper runs as root inside sudo and offers the phone only for
    `PAM_SERVICE=sudo`, started by the root-owned setuid `/usr/bin/sudo`, on a
    pseudo-terminal whose process ancestry contains Konsole or Kitty owned by the
    user and no `sshd`, and only for a plain `sudo [options] [VAR=value] command`:
    `-s`, `-i`, `-e`/sudoedit, `-l`, `-v`, `-b`, `-g`, `-D`, `-R` and `-h` are left
    to the password. The phone shows sudo's argument list and the requesting
    terminal (`/dev/pts/N`).
  - sudo binding: PAM authenticates before sudo's policy has resolved the
    command, so the phone approves the command as typed. After a phone approval
    the helper leaves a root-only record (`/run/navi-auth/sudo/PID.START`: the
    exact argument bytes, the run-as uid and, for a program given as a path, the
    file it resolves to; valid 120 s). `navi-pam enable sudo` also adds the Navi
    approval plugin to `/etc/sudo.conf`; sudo calls it with the policy-resolved
    command, and it consumes the record and refuses unless the arguments are
    byte-identical, the run-as user matches and the program is the approved file
    (or, for a bare name, that name found somewhere the user cannot change). When
    sudo was authenticated by the password or its timestamp there is no record and
    the plugin allows, like plain sudo; it never allows what sudo's policy refused.
    The plugin does not compare the environment sudoers builds or the working
    directory. If sudo cannot load it, `navi-pam` restores `sudo.conf`; removing
    the package removes the line.
  - sudo timestamp: a phone approval authenticates like a typed password, so
    sudo's normal credential cache applies (`timestamp_timeout`, per terminal by
    default; 5 minutes unless configured): later sudos in that terminal within
    the timeout run without asking again.
  - SDDM: offered only for `PAM_SERVICE=sddm` from root-owned `sddm-helper`
    started by `sddm`, and only when the password field is empty; a typed password
    goes straight to the normal check.
  - Lock screen: kscreenlocker authenticates without privileges (in Plasma 6.8 in
    `kscreenlocker_worker`, started by `kscreenlocker_greet`), so the helper
    asks the root authority through the setuid helper. The lock screen is
    non-dumpable, so the authority, not the unprivileged helper, verifies as root
    that the request comes from that user's worker/greeter chain; it builds the
    unlock request itself and only answers whether the phone approved. That answer grants
    the caller nothing it could not already do; the event exists only when built in.
  - These checks limit *where* the phone is offered; they are not a boundary
    against code already running as the user. Anyone at the keyboard can trigger a
    request; the fingerprint approval is the gate, and every failure falls back to
    the password. A phone approval returns `sufficient` before the password rules:
    faillock's pre-auth lockout is checked first (see above), but other auth-stage
    modules after the block do not run for it (account checks such as `pam_nologin`
    still do). Approval is recorded without execution.
- **Biometric modality:** Android selects strength, not exclusively fingerprint.
  Locally observed hardware enforcement is not independently verified attestation.
- **Availability:** the LAN service adds network-facing code. Frames, workers and
  transaction times are bounded, but hostile-traffic availability has not been
  established. Reboot/deep-Doze behavior and battery cost require device testing.
- **Scope:** only the configured local UID is supported; kdesu execution targets
  root only. sudo, the SDDM login and the Plasma lock screen are optional and off
  by default (above); there is no automatic system-wide PolicyKit replacement, and
  console logins, SSH, su, pkexec and polkit prompts keep using passwords.
  Password fallback is available before phone commit.

## Failure handling

Never interpret a sent notification, successful biometric animation, helper exit
code or process launch alone as proof of completed privileged work. Verify the
signed response and the operation's actual result. After uncertain commit, do
not retry or switch authentication routes automatically: the command may already
be running. Signed cancellation prevents acceptance of the exact pending request
when processed before commitment; loss of its network delivery does not extend TTL.

Normal expiry can currently surface as `Invalid network frame`; this is a known
error-reporting defect. Do not generalize every malformed-frame error as expiry.

## Reporting

For a non-sensitive bug or documentation issue, use
[GitHub Issues](https://github.com/hparadiz/kdesu-android-biometric-auth/issues).
Do not attach private keys, enrollment databases, signing keystores, authorization
receipts, personal commands or unredacted device logs. For a new exploitable issue,
use GitHub's private vulnerability reporting if offered by the repository; if
unavailable, ask the maintainer for a private channel without posting exploit
details. No response-time or security-support commitment is promised.

See the [bounded audit](docs/SECURITY_AUDIT.md) and
[verification record](docs/VERIFICATION.md) for what was actually checked.
