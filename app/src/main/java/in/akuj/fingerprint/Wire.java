package in.akuj.fingerprint;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import in.akuj.fingerprint.wire.Approval;
import in.akuj.fingerprint.wire.Payload;
import in.akuj.fingerprint.wire.Protocol;
import in.akuj.fingerprint.wire.Signed;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Locale;

/**
 * The protobuf wire format (proto/navi.proto) shared with the computer. Signed messages carry the
 * exact serialized Payload bytes: verify the signature over those bytes first, then parse them, and
 * never re-serialize a received message. Plain Java (no Android APIs).
 */
final class Wire {
    static final String ALGORITHM = "SHA256withECDSA";
    static final int MAX_MESSAGE = 65536, MAX_PAYLOAD = 131072;
    static final String UPDATE_HINT = "Update Navi and the computer's navi-auth together.";

    private Wire() { }

    interface Parser<T> { T parse(byte[] bytes) throws InvalidProtocolBufferException; }

    /** Untrusted bytes as a message, size-capped before parsing. */
    static <T> T parse(Parser<T> parser, byte[] bytes, int limit) {
        if (bytes == null || bytes.length > limit) throw new IllegalArgumentException("Computer message is too large.");
        try {
            return parser.parse(bytes);
        } catch (InvalidProtocolBufferException invalid) {
            throw new IllegalArgumentException("Unreadable computer message. " + UPDATE_HINT);
        }
    }

    /** The Payload of exact signed bytes, checking protocol and type. Unverified unless after {@link #open}. */
    static Payload peek(byte[] raw, Payload.BodyCase expected) {
        Payload payload = parse(Payload::parseFrom, raw, MAX_PAYLOAD);
        if (payload.getProtocol() != Protocol.PROTOCOL_NAVI_V2)
            throw new IllegalArgumentException("Unsupported message version. " + UPDATE_HINT);
        if (payload.getBodyCase() != expected) throw new IllegalArgumentException("Unexpected signed message type.");
        return payload;
    }

    /** Verifies the signature over the exact bytes, then parses them. */
    static Payload open(Signed signed, PublicKey key, Payload.BodyCase expected) throws Exception {
        byte[] raw = signed.getPayload().toByteArray();
        Signature verifier = Signature.getInstance(ALGORITHM);
        verifier.initVerify(key);
        verifier.update(raw);
        if (!verifier.verify(signed.getSignature().toByteArray()))
            throw new IllegalArgumentException("Computer signature is invalid.");
        return peek(raw, expected);
    }

    static byte[] payload(Payload.Builder body) {
        return body.setProtocol(Protocol.PROTOCOL_NAVI_V2).build().toByteArray();
    }

    /** What the biometric key signs for a request: SHA-256 of its exact bytes (and the setup key). */
    static byte[] approval(byte[] requestBytes, byte[] ecdhPublic) throws Exception {
        Approval.Builder approval = Approval.newBuilder().setRequestSha256(ByteString.copyFrom(sha256(requestBytes)));
        if (ecdhPublic != null) approval.setPhoneEcdhSpki(ByteString.copyFrom(ecdhPublic));
        return payload(Payload.newBuilder().setApproval(approval));
    }

    static Signed signed(byte[] payload, byte[] signature) {
        return Signed.newBuilder().setPayload(ByteString.copyFrom(payload)).setSignature(ByteString.copyFrom(signature)).build();
    }

    static byte[] exact(ByteString value, int size, String what) {
        if (value.size() != size) throw new IllegalArgumentException("Invalid " + what + ".");
        return value.toByteArray();
    }

    static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    static boolean sameHash(byte[] data, ByteString expected) throws Exception {
        return expected.size() == 32 && MessageDigest.isEqual(sha256(data), expected.toByteArray());
    }

    static String hex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) result.append(String.format(Locale.ROOT, "%02x", b & 0xff));
        return result.toString();
    }

    static String hex(ByteString bytes) { return hex(bytes.toByteArray()); }

    static ByteString unhex(String hex) {
        if (!hex.matches("([0-9a-f]{2})*")) throw new IllegalArgumentException("Invalid identifier.");
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) result[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        return ByteString.copyFrom(result);
    }
}
