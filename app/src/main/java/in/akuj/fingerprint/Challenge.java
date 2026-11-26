package in.akuj.fingerprint;

import android.os.SystemClock;
import in.akuj.fingerprint.wire.Execution;
import in.akuj.fingerprint.wire.Kind;
import in.akuj.fingerprint.wire.Mode;
import in.akuj.fingerprint.wire.Payload;
import in.akuj.fingerprint.wire.RemoteSetup;
import in.akuj.fingerprint.wire.Request;
import in.akuj.fingerprint.wire.RequestEnvelope;
import java.security.cert.X509Certificate;

/** A machine-signed, operation-bound challenge; the host owns expiry and consumption. */
final class Challenge {
    static final class Expired extends IllegalArgumentException {
        private static final long serialVersionUID = 1L;
        Expired() { super("The previous computer request expired."); }
    }
    static final String ENROLL = "enroll", AUTHENTICATE = "authenticate", REMOTE_SETUP = "remote-setup";
    final RequestEnvelope envelope;
    /** The signed request, parsed from {@link #bytes} after its signature verified. */
    final Request payload;
    final in.akuj.fingerprint.wire.Context context;
    /** The exact signed bytes. */
    final byte[] bytes;
    final String id, kind, operation, machineName, machineId;
    final long expiresAt;
    final X509Certificate machineCertificate, phoneCertificate;
    final long deadline;

    /** {@code envelope} must already have been verified with {@code machine} (Bridge.validate). */
    Challenge(RequestEnvelope envelope, X509Certificate machine, X509Certificate phone, boolean allowExpired) throws Exception {
        this.envelope = envelope;
        bytes = envelope.getSigned().getPayload().toByteArray();
        payload = Wire.peek(bytes, Payload.BodyCase.REQUEST).getRequest();
        id = Wire.hex(Wire.exact(payload.getRequestId(), 16, "request ID"));
        machineId = Wire.hex(Wire.exact(payload.getMachineId(), 32, "computer key ID"));
        Wire.exact(payload.getNonce(), 32, "request nonce");
        Wire.exact(payload.getCertificateSha256(), 32, "certificate hash");
        kind = kind(payload.getKind());
        operation = payload.getOperation();
        machineName = payload.getMachineName();
        machineCertificate = machine;
        phoneCertificate = phone;
        context = payload.getContext();
        validateText(context.getApplication(), 80, false);
        validateText(context.getActionId(), 160, false);
        validateText(context.getCommand(), Limits.MAX_COMMAND, true, true);
        validateText(context.getRequestingUser(), 64, false);
        validateText(context.getTargetUser(), 64, false);
        validateText(context.getSource(), 64, false);
        validateText(context.getIconName(), 128, true);
        validateText(context.getTty(), 64, true);
        if (context.getWritablePathsCount() > 16)
            throw new IllegalArgumentException("Invalid request display metadata.");
        for (String path : context.getWritablePathsList()) {
            validateText(path, 4096, false);
            if (!path.startsWith("/")) throw new IllegalArgumentException("Invalid request display metadata.");
        }
        if (!context.getIconSha256().isEmpty()) Wire.exact(context.getIconSha256(), 32, "requester icon hash");
        if (!context.hasRequestingUid()) throw new IllegalArgumentException("Invalid requesting account.");
        if (context.getMode() == Mode.UNRECOGNIZED) throw new IllegalArgumentException("Unknown request mode. " + Wire.UPDATE_HINT);
        validateText(operation, 160, false);
        validateText(machineName, 128, false);
        if (execution()) {
            // The signed context.command is the single copy that is shown and run by `/bin/sh -c`.
            Execution execution = payload.getExecution();
            if (!payload.hasExecution() || !"/bin/sh -c".equals(execution.getShell())
                    || execution.getUid() != 0 || execution.getGid() != 0
                    || !"root".equals(context.getTargetUser()) || context.getCommand().isEmpty())
                throw new IllegalArgumentException("Execution does not match the displayed command and account. " + Wire.UPDATE_HINT);
            validateText(execution.getCwd(), 4096, false);
            if (!execution.getCwd().startsWith("/"))
                throw new IllegalArgumentException("Invalid execution directory.");
        } else if (payload.hasExecution()) {
            throw new IllegalArgumentException("Only an execution request may carry an execution.");
        }
        if (approvalOnly() && !AUTHENTICATE.equals(kind))
            throw new IllegalArgumentException("Only an authentication request may be approve-only.");
        long now = System.currentTimeMillis();
        long issued = payload.getIssuedAtMs();
        long expires = payload.getExpiresAtMs();
        if (issued > now + 30_000 || expires <= issued || expires - issued > 120_000) {
            throw new IllegalArgumentException("Invalid or expired computer request. Start a new request on the computer.");
        }
        expiresAt = expires;
        if (remoteSetup()) {
            // Remote approvals: an https ntfy server, an optional access token and the computer's ECDH key.
            RemoteSetup setup = payload.getRemoteSetup();
            RemoteChannel.validateServer(setup.getServer());
            if (!setup.getToken().isEmpty() && !RemoteChannel.TOKEN.matcher(setup.getToken()).matches())
                throw new IllegalArgumentException("Invalid ntfy access token.");
            java.security.PublicKey ecdh = java.security.KeyFactory.getInstance("EC").generatePublic(
                    new java.security.spec.X509EncodedKeySpec(setup.getMachineEcdhSpki().toByteArray()));
            if (!(ecdh instanceof java.security.interfaces.ECPublicKey)
                    || ((java.security.interfaces.ECPublicKey) ecdh).getParams().getCurve().getField().getFieldSize() != 256)
                throw new IllegalArgumentException("Invalid remote setup key.");
            if (execution()) throw new IllegalArgumentException("Remote setup cannot run a command.");
        } else if (payload.hasRemoteSetup()) {
            throw new IllegalArgumentException("Only a remote setup request may carry remote settings.");
        }
        if (expires <= now && !allowExpired) throw new Expired();
        deadline = SystemClock.elapsedRealtime() + Math.min(expires - now, 120_000);
    }

    private static String kind(Kind kind) {
        switch (kind) {
            case KIND_ENROLL: return ENROLL;
            case KIND_AUTHENTICATE: return AUTHENTICATE;
            case KIND_REMOTE_SETUP: return REMOTE_SETUP;
            default: throw new IllegalArgumentException("Unknown request type. " + Wire.UPDATE_HINT);
        }
    }

    boolean expired() { return SystemClock.elapsedRealtime() >= deadline; }
    boolean notificationOnly() { return context.getMode() == Mode.MODE_NOTIFICATION_ONLY; }
    boolean execution() { return context.getMode() == Mode.MODE_EXECUTE; }
    /** sudo, SDDM or the lock screen: the computer runs nothing; the waiting caller continues. */
    boolean approvalOnly() { return context.getMode() == Mode.MODE_APPROVE; }
    /** Files the command uses that the requesting user can change, or "" (signed by the computer). */
    String writableWarning() {
        if (context.getWritablePathsCount() == 0) return "";
        return "Runs files you can change (approving the command does not approve their contents):\n"
                + String.join("\n", context.getWritablePathsList());
    }
    boolean remoteSetup() { return REMOTE_SETUP.equals(kind); }
    /** Hex SHA-256 of the requester icon, or "" when the request carries none. */
    String iconSha256() { return context.getIconSha256().isEmpty() ? "" : Wire.hex(context.getIconSha256()); }

    private static void validateText(String value, int limit, boolean allowEmpty) {
        validateText(value, limit, allowEmpty, false);
    }

    /** Printable text; {@code allowLayout} (commands only) also permits newlines and tabs. */
    static void validateText(String value, int limit, boolean allowEmpty, boolean allowLayout) {
        if ((!allowEmpty && value.isEmpty()) || value.length() > limit) throw new IllegalArgumentException("Invalid request display metadata.");
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (allowLayout && (c == '\n' || c == '\t')) continue;
            if (Character.isISOControl(c) || (c >= '‪' && c <= '‮') || (c >= '⁦' && c <= '⁩')) {
                throw new IllegalArgumentException("Request metadata contains hidden formatting characters.");
            }
        }
    }
}
