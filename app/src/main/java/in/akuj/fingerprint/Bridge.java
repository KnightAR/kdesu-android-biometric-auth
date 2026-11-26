package in.akuj.fingerprint;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.ApplicationInfo;
import android.util.Base64;
import android.util.Log;
import com.google.protobuf.MessageLite;
import in.akuj.fingerprint.wire.Cancel;
import in.akuj.fingerprint.wire.Kind;
import in.akuj.fingerprint.wire.Payload;
import in.akuj.fingerprint.wire.Receipt;
import in.akuj.fingerprint.wire.ReceiptStatus;
import in.akuj.fingerprint.wire.Request;
import in.akuj.fingerprint.wire.RequestEnvelope;
import in.akuj.fingerprint.wire.Response;
import in.akuj.fingerprint.wire.Signed;
import in.akuj.fingerprint.wire.Status;
import org.json.JSONObject;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/** Private mailbox shared by every delivery route (KDE Connect, direct network, ntfy, ADB). */
final class Bridge {
    static final Object MAILBOX = new Object();
    /** The current request and its answers: exact protobuf bytes (proto/navi.proto). */
    static final String REQUEST = "request.pb", RESPONSE = "response.pb", RECEIPT = "receipt.pb", CANCEL = "cancel.pb";
    private static final String[] LEGACY_MAILBOX = {"request.json", "response.json", "receipt.json", "cancel.json", "enroll-hello.json"};
    private final File directory;
    private final boolean developmentEnrollment;

    Bridge(Context context) {
        directory = context.getFilesDir();
        developmentEnrollment = (context.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
    }

    File directory() { return directory; }

    /** Local JSON state (pairings, routes, tombstones); not a wire message. */
    JSONObject read(String name) throws Exception {
        byte[] bytes = readBytes(name);
        return bytes == null ? null : new JSONObject(new String(bytes, StandardCharsets.UTF_8));
    }

    void write(String name, JSONObject value) throws Exception {
        writeBytes(name, value.toString().getBytes(StandardCharsets.UTF_8));
    }

    byte[] readBytes(String name) throws Exception {
        File file = new File(directory, name);
        if (!file.exists()) return null;
        if (file.length() > Wire.MAX_MESSAGE) throw new IllegalArgumentException("Computer message is too large.");
        return Files.readAllBytes(file.toPath());
    }

    void writeBytes(String name, byte[] value) throws Exception {
        File temporary = File.createTempFile(name, ".app-tmp", directory);
        Files.write(temporary.toPath(), value);
        Files.move(temporary.toPath(), new File(directory, name).toPath(),
                StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    void write(String name, MessageLite message) throws Exception { writeBytes(name, message.toByteArray()); }

    RequestEnvelope readRequest() throws Exception {
        byte[] bytes = readBytes(REQUEST);
        return bytes == null ? null : Wire.parse(RequestEnvelope::parseFrom, bytes, Wire.MAX_MESSAGE);
    }

    Response readResponse() throws Exception {
        byte[] bytes = readBytes(RESPONSE);
        return bytes == null ? null : Wire.parse(Response::parseFrom, bytes, Wire.MAX_MESSAGE);
    }

    Signed readSigned(String name) throws Exception {
        byte[] bytes = readBytes(name);
        return bytes == null ? null : Wire.parse(Signed::parseFrom, bytes, Wire.MAX_MESSAGE);
    }

    /** The current response, if it answers {@code request}. */
    Response responseFor(Challenge request) throws Exception {
        Response response = readResponse();
        return response != null && request.id.equals(Wire.hex(response.getRequestId())) ? response : null;
    }

    void identity(SigningKey key) throws Exception {
        write("identity.json", new JSONObject().put("key_id_sha256", key.id)
                .put("public_key_spki_base64", key.publicKeyBase64()));
    }

    /**
     * Once after updating from the JSON protocol: drops its mailbox files, and turns direct network
     * approvals off when their stored binding is in the old format. Navi then asks the user to turn
     * them on again, which signs a new binding with one fingerprint. Pairings are kept.
     */
    static void upgrade(Context context) {
        synchronized (MAILBOX) {
            try {
                File directory = context.getFilesDir();
                for (String name : LEGACY_MAILBOX) Files.deleteIfExists(new File(directory, name).toPath());
                if (Files.deleteIfExists(new File(directory, "network-identity.json").toPath())) {
                    SharedPreferences network = context.getSharedPreferences("network", 0);
                    if (network.getBoolean("enabled", false)) {
                        network.edit().putBoolean("enabled", false).putBoolean(NetworkIdentity.REENABLE, true).apply();
                        NetworkService.showReenableNotification(context);
                    }
                    Log.i("PhoneAuthenticator", "Direct network binding from the previous protocol removed");
                }
            } catch (Exception error) {
                Log.w("PhoneAuthenticator", "Protocol upgrade cleanup failed", error);
            }
        }
    }

    Challenge validate(RequestEnvelope envelope, SigningKey key) throws Exception {
        return validate(envelope, key, false);
    }

    Challenge validate(RequestEnvelope envelope, SigningKey key, boolean allowExpired) throws Exception {
        // Unverified: machine_id only selects the stored pairing whose key must have signed it.
        Request claimed = Wire.peek(envelope.getSigned().getPayload().toByteArray(), Payload.BodyCase.REQUEST).getRequest();
        String machineId = Wire.hex(Wire.exact(claimed.getMachineId(), 32, "computer key ID"));
        boolean enroll = claimed.getKind() == Kind.KIND_ENROLL;
        JSONObject pairing = pairings().optJSONObject(machineId);
        // Release entry points never bootstrap trust from a request's own certificate. The only
        // release bootstrap is a computer key pinned after the user typed its on-screen code.
        JSONObject pinnedPairing = developmentEnrollment ? null : PairingCode.verified(this);
        boolean bootstrap = developmentEnrollment || pinnedPairing != null && machineId.equals(pinnedPairing.getString("machine_id"));
        if (pairing == null && !bootstrap)
            throw new IllegalArgumentException("Unknown computer. Requests require an enrolled computer key.");
        X509Certificate machine, phone;
        if (enroll) {
            // Enrollment carries the certificates (nothing is stored yet); they are checked below.
            if (envelope.getMachineCertificate().isEmpty() || envelope.getPhoneCertificate().isEmpty())
                throw new IllegalArgumentException("Enrollment request is missing its certificates.");
            machine = certificate(envelope.getMachineCertificate().toByteArray());
            phone = certificate(envelope.getPhoneCertificate().toByteArray());
        } else {
            // Paired requests name the certificates by hash; only the ones stored at pairing are used.
            if (!envelope.getMachineCertificate().isEmpty() || !envelope.getPhoneCertificate().isEmpty())
                throw new IllegalArgumentException("A paired request must not carry certificates. " + Wire.UPDATE_HINT);
            if (pairing == null) throw new IllegalArgumentException("This phone must be enrolled by the computer first.");
            machine = certificate(pairing.getString("machine_certificate_b64"));
            phone = certificate(pairing.getString("phone_certificate_b64"));
        }
        validateCertificate(machine, machine, true);
        validateCertificate(phone, machine, false);
        Wire.open(envelope.getSigned(), machine.getPublicKey(), Payload.BodyCase.REQUEST);
        Challenge request = new Challenge(envelope, machine, phone, allowExpired);
        // A completed enrollment stays valid for its receipt/cancel: the stored pairing already
        // holds exactly this certificate, so re-reading it grants nothing new.
        boolean completed = pairing != null && Arrays.equals(decode(pairing.optString("phone_certificate_b64")), phone.getEncoded());
        if (enroll && !bootstrap && !completed)
            throw new IllegalArgumentException("Computer enrollment requires the pairing code shown on the computer.");
        if (enroll && !completed && pinnedPairing != null && !developmentEnrollment
                && !pinnedPairing.getString("desktop_device_id").equals(KdeConnectInbox.desktop(request)))
            throw new IllegalArgumentException("Enrollment must return to the computer that showed the pairing code.");
        // The certificate binds the phone key: it must be this phone's, and the request must name it.
        if (!Arrays.equals(phone.getPublicKey().getEncoded(), key.publicKey.getEncoded())
                || !machineId.equals(hash(machine.getPublicKey().getEncoded()))
                || !Wire.sameHash(phone.getEncoded(), request.payload.getCertificateSha256())) {
            throw new IllegalArgumentException("Computer request does not match this phone’s key and certificate.");
        }
        if (pairing != null) {
            X509Certificate pinned = certificate(pairing.getString("machine_certificate_b64"));
            if (!Arrays.equals(pinned.getPublicKey().getEncoded(), machine.getPublicKey().getEncoded()))
                throw new IllegalArgumentException("Computer identity does not match the stored pairing.");
        }
        return request;
    }

    /** Stores and returns the response carrying the biometric signature over {@code approval}. */
    Response signed(Challenge request, byte[] approval, byte[] signature) throws Exception {
        if (request.kind.equals(Challenge.ENROLL)) {
            JSONObject paired = pairings();
            paired.put(request.machineId, new JSONObject()
                    .put("machine_name", request.machineName)
                    .put("machine_certificate_b64", encode(request.machineCertificate.getEncoded()))
                    .put("phone_certificate_b64", encode(request.phoneCertificate.getEncoded())));
            write("pairings.json", paired);
            PairingCode.clear(this); // The pinned bootstrap is single-use.
        }
        Response response = Response.newBuilder().setRequestId(request.payload.getRequestId())
                .setStatus(Status.STATUS_SIGNED).setApproval(Wire.signed(approval, signature)).build();
        write(RESPONSE, response);
        return response;
    }

    void declined(Challenge request, String message) throws Exception {
        write(RESPONSE, Response.newBuilder().setRequestId(request.payload.getRequestId())
                .setStatus(Status.STATUS_DECLINED).setMessage(message).build());
    }

    /** Whether {@code response} is this phone's verified approval of exactly {@code request}. */
    static boolean approves(Challenge request, Response response, SigningKey key) throws Exception {
        if (response.getStatus() != Status.STATUS_SIGNED || !request.id.equals(Wire.hex(response.getRequestId()))) return false;
        Payload approval = Wire.open(response.getApproval(), key.publicKey, Payload.BodyCase.APPROVAL);
        return Wire.sameHash(request.bytes, approval.getApproval().getRequestSha256());
    }

    boolean canceled(Challenge request) throws Exception {
        return canceled(request, readSigned(CANCEL));
    }

    boolean canceled(Challenge request, Signed signed) throws Exception {
        if (signed == null) return false;
        Cancel claimed = Wire.peek(signed.getPayload().toByteArray(), Payload.BodyCase.CANCEL).getCancel();
        if (!request.id.equals(Wire.hex(claimed.getRequestId()))) return false;
        Cancel value = Wire.open(signed, request.machineCertificate.getPublicKey(), Payload.BodyCase.CANCEL).getCancel();
        if (!Wire.sameHash(request.bytes, value.getRequestSha256()))
            throw new IllegalArgumentException("Computer cancellation does not match this request.");
        return true;
    }

    boolean receipt(Challenge request, Response response) throws Exception {
        return receipt(request, response, readSigned(RECEIPT));
    }

    boolean receipt(Challenge request, Response response, Signed signed) throws Exception {
        if (signed == null || response == null) return false;
        Receipt claimed = Wire.peek(signed.getPayload().toByteArray(), Payload.BodyCase.RECEIPT).getReceipt();
        if (!request.id.equals(Wire.hex(claimed.getRequestId()))) return false;
        Receipt value = Wire.open(signed, request.machineCertificate.getPublicKey(), Payload.BodyCase.RECEIPT).getReceipt();
        // The receipt names this phone's own approval signature, which covers this exact request.
        if (value.getStatus() != ReceiptStatus.RECEIPT_APPROVED || response.getStatus() != Status.STATUS_SIGNED
                || !request.id.equals(Wire.hex(response.getRequestId()))
                || !Wire.sameHash(response.getApproval().getSignature().toByteArray(), value.getResponseSha256())) {
            throw new IllegalArgumentException("Computer confirmation does not match this approval.");
        }
        if (request.execution() && value.getExecutionPid() == 0)
            throw new IllegalArgumentException("The computer did not confirm execution of this command.");
        JSONObject paired = pairings();
        JSONObject computer = paired.optJSONObject(request.machineId);
        if (computer != null) {
            computer.put("machine_name", request.machineName);
            write("pairings.json", paired);
        }
        return true;
    }

    void reset() throws Exception {
        for (String name : new String[]{"pairings.json", "pairing.json", "identity.json", NetworkIdentity.FILE,
                REQUEST, RESPONSE, RECEIPT, CANCEL, "kde-cancellations.json", "remote.json", "request-route.json",
                PairingCode.FILE, PairingCode.HELLO}) {
            Files.deleteIfExists(new File(directory, name).toPath());
        }
        for (String name : LEGACY_MAILBOX) Files.deleteIfExists(new File(directory, name).toPath());
        Files.deleteIfExists(new File(directory, "network-identity.json").toPath());
    }

    JSONObject pairings() throws Exception {
        JSONObject paired = read("pairings.json");
        if (paired != null) return paired;
        paired = new JSONObject();
        JSONObject legacy = read("pairing.json");
        if (legacy != null) {
            String id = hash(certificate(legacy.getString("machine_certificate_b64")).getPublicKey().getEncoded());
            paired.put(id, legacy);
            write("pairings.json", paired);
        }
        return paired;
    }

    static X509Certificate certificate(String base64) throws Exception { return certificate(decode(base64)); }

    static X509Certificate certificate(byte[] der) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
    }

    static void validateCertificate(X509Certificate cert, X509Certificate root, boolean ca) throws Exception {
        cert.checkValidity();
        cert.verify(root.getPublicKey());
        boolean[] usage = cert.getKeyUsage();
        if (!cert.getIssuerX500Principal().equals(root.getSubjectX500Principal())
                || (cert.getBasicConstraints() >= 0) != ca || usage == null || !usage[0] || usage[5] != ca
                || !"1.2.840.10045.4.3.2".equals(cert.getSigAlgOID())) {
            throw new IllegalArgumentException("Invalid computer or phone certificate.");
        }
    }

    static byte[] decode(String value) { return Base64.decode(value, Base64.NO_WRAP); }
    static String encode(byte[] value) { return Base64.encodeToString(value, Base64.NO_WRAP); }
    static String hash(byte[] bytes) throws Exception {
        return Wire.hex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
}
