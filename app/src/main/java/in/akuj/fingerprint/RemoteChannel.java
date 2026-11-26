package in.akuj.fingerprint;

import android.content.Context;
import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import com.google.protobuf.ByteString;
import in.akuj.fingerprint.wire.Icon;
import in.akuj.fingerprint.wire.IconRequest;
import in.akuj.fingerprint.wire.Payload;
import in.akuj.fingerprint.wire.RemoteMessage;
import in.akuj.fingerprint.wire.RequestEnvelope;
import in.akuj.fingerprint.wire.Response;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.HttpsURLConnection;

/**
 * Remote approvals over an ntfy server (navi-remote/v2), used by the computer only when KDE Connect
 * cannot see this phone. Navi subscribes to its inbox topic(s) itself and publishes replies to the
 * computer's inbox. Topics and the message key come from the fingerprint-approved ECDH setup and are
 * never transmitted. Every message is a protobuf RemoteMessage, AES-256-GCM encrypted and bound to its
 * direction and topic. Nothing received here is trusted beyond that: requests still go through
 * Bridge.validate (machine signature, pairing, expiry) exactly like the other routes.
 */
final class RemoteChannel {
    /** Message AAD. The key and topic derivation keep their "navi-remote/v1" labels (no new setup needed). */
    static final String PROTOCOL = "navi-remote/v2";
    static final String TO_PHONE = "to-phone", TO_COMPUTER = "to-computer";
    static final int INLINE_LIMIT = 3800, MAX_PLAIN = 65536, MAX_BLOB = 98304, MAX_LINE = 262144;
    static final Pattern TOPIC = Pattern.compile("navi-[a-z2-7]{26}");
    static final Pattern TOKEN = Pattern.compile("[A-Za-z0-9_.-]{1,128}");
    private static final String FILE = "remote.json";
    private static final String WRAP_ALIAS = "navi-remote-wrap.v1";
    private static final String TAG = "PhoneAuthenticator";
    private static final SecureRandom RANDOM = new SecureRandom();

    static final class Config {
        final String machineId, machineName, server, token, phoneTopic, computerTopic;
        final byte[] key;
        Config(String machineId, String machineName, String server, String token, String phoneTopic, String computerTopic, byte[] key) {
            this.machineId = machineId; this.machineName = machineName; this.server = server; this.token = token;
            this.phoneTopic = phoneTopic; this.computerTopic = computerTopic; this.key = key;
        }
        String host() {
            try { return new URL(server).getHost(); } catch (Exception error) { return server; }
        }
    }

    // --- Configuration -----------------------------------------------------------------------
    static boolean configured(Context context) {
        try { return !configs(context).isEmpty(); } catch (Exception error) { return false; }
    }

    static synchronized List<Config> configs(Context context) throws Exception {
        List<Config> result = new ArrayList<>();
        JSONObject stored = new Bridge(context).read(FILE);
        if (stored == null) return result;
        for (Iterator<String> ids = stored.keys(); ids.hasNext(); ) {
            String id = ids.next();
            JSONObject value = stored.getJSONObject(id);
            result.add(new Config(id, value.optString("machine_name", "Computer"), value.getString("server"),
                    value.has("token") ? value.getString("token") : null, value.getString("phone_topic"),
                    value.getString("computer_topic"), unwrap(value.getString("key_wrapped"))));
        }
        return result;
    }

    static Config forMachine(Context context, String machineId) throws Exception {
        for (Config config : configs(context)) if (config.machineId.equals(machineId)) return config;
        return null;
    }

    /** Stores the configuration derived from an approved setup; replaces any earlier one for that computer. */
    static synchronized Config save(Context context, String machineId, String machineName, String server, String token,
                                    byte[] sharedSecret, String setupRequestId) throws Exception {
        validateServer(server);
        if (token != null && !TOKEN.matcher(token).matches()) throw new IllegalArgumentException("Invalid ntfy access token.");
        byte[] salt = setupRequestId.getBytes(StandardCharsets.US_ASCII);
        byte[] key = hkdf(sharedSecret, salt, "navi-remote/v1 key", 32);
        String phoneTopic = topic(hkdf(sharedSecret, salt, "navi-remote/v1 phone-inbox", 16));
        String computerTopic = topic(hkdf(sharedSecret, salt, "navi-remote/v1 computer-inbox", 16));
        Bridge bridge = new Bridge(context);
        JSONObject stored = bridge.read(FILE);
        if (stored == null) stored = new JSONObject();
        JSONObject value = new JSONObject().put("machine_name", machineName).put("server", server)
                .put("phone_topic", phoneTopic).put("computer_topic", computerTopic).put("key_wrapped", wrap(key))
                .put("created_at_ms", System.currentTimeMillis());
        if (token != null) value.put("token", token);
        stored.put(machineId, value);
        bridge.write(FILE, stored);
        return new Config(machineId, machineName, server, token, phoneTopic, computerTopic, key);
    }

    static synchronized void remove(Context context, String machineId) throws Exception {
        Bridge bridge = new Bridge(context);
        JSONObject stored = bridge.read(FILE);
        if (stored == null) return;
        stored.remove(machineId);
        if (stored.length() == 0) java.nio.file.Files.deleteIfExists(new java.io.File(bridge.directory(), FILE).toPath());
        else bridge.write(FILE, stored);
    }

    static void validateServer(String server) throws Exception {
        URL url = new URL(server);
        if (!"https".equals(url.getProtocol()) || url.getHost().isEmpty() || url.getQuery() != null || url.getRef() != null
                || url.getUserInfo() != null || server.length() > 200)
            throw new IllegalArgumentException("The ntfy server must be an https:// address.");
    }

    // The message key is wrapped by a non-exportable, non-biometric Keystore key.
    private static SecretKey wrapKey() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore");
        store.load(null);
        if (!store.containsAlias(WRAP_ALIAS)) {
            KeyGenerator generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(WRAP_ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256).build());
            return generator.generateKey();
        }
        return (SecretKey) store.getKey(WRAP_ALIAS, null);
    }

    private static String wrap(byte[] key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, wrapKey());
        byte[] iv = cipher.getIV();
        byte[] sealed = cipher.doFinal(key);
        byte[] out = new byte[iv.length + sealed.length];
        System.arraycopy(iv, 0, out, 0, iv.length);
        System.arraycopy(sealed, 0, out, iv.length, sealed.length);
        return Bridge.encode(out);
    }

    private static byte[] unwrap(String wrapped) throws Exception {
        byte[] data = Bridge.decode(wrapped);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, wrapKey(), new GCMParameterSpec(128, data, 0, 12));
        return cipher.doFinal(data, 12, data.length - 12);
    }

    // --- Protocol crypto (matches ntfy_transport.py) ---------------------------------------
    static byte[] hkdf(byte[] ikm, byte[] salt, String info, int length) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(salt, "HmacSHA256"));
        byte[] prk = mac.doFinal(ikm);
        mac.init(new SecretKeySpec(prk, "HmacSHA256"));
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] block = new byte[0];
        for (int counter = 1; output.size() < length; counter++) {
            mac.update(block);
            mac.update(info.getBytes(StandardCharsets.US_ASCII));
            mac.update((byte) counter);
            block = mac.doFinal();
            output.write(block, 0, block.length);
        }
        byte[] result = new byte[length];
        System.arraycopy(output.toByteArray(), 0, result, 0, length);
        return result;
    }

    static String topic(byte[] material) {
        final String alphabet = "abcdefghijklmnopqrstuvwxyz234567";
        StringBuilder out = new StringBuilder("navi-");
        int buffer = 0, bits = 0;
        for (byte b : material) {
            buffer = (buffer << 8) | (b & 0xff);
            bits += 8;
            while (bits >= 5) {
                out.append(alphabet.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) out.append(alphabet.charAt((buffer << (5 - bits)) & 31));
        return out.toString();
    }

    private static byte[] aad(String direction, String topic) {
        return (PROTOCOL + "\n" + direction + "\n" + topic).getBytes(StandardCharsets.US_ASCII);
    }

    static byte[] seal(byte[] key, String direction, String topic, RemoteMessage value) throws Exception {
        byte[] plain = value.toByteArray();
        if (plain.length > MAX_PLAIN) throw new IllegalArgumentException("Remote message is too large.");
        byte[] nonce = new byte[12];
        RANDOM.nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad(direction, topic));
        byte[] sealed = cipher.doFinal(plain);
        byte[] out = new byte[12 + sealed.length];
        System.arraycopy(nonce, 0, out, 0, 12);
        System.arraycopy(sealed, 0, out, 12, sealed.length);
        return out;
    }

    static RemoteMessage open(byte[] key, String direction, String topic, byte[] blob) throws Exception {
        if (blob.length < 28 || blob.length > Math.min(MAX_BLOB, MAX_PLAIN + 28)) throw new IllegalArgumentException("Invalid remote message size.");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, blob, 0, 12));
        cipher.updateAAD(aad(direction, topic));
        return Wire.parse(RemoteMessage::parseFrom, cipher.doFinal(blob, 12, blob.length - 12), MAX_PLAIN);
    }

    static String b64url(byte[] data) {
        return Base64.encodeToString(data, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    static byte[] unb64url(String text) {
        if (!text.matches("[A-Za-z0-9_-]*")) throw new IllegalArgumentException("Invalid remote message encoding.");
        return Base64.decode(text, Base64.URL_SAFE | Base64.NO_WRAP | Base64.NO_PADDING);
    }

    // --- HTTP ------------------------------------------------------------------------------
    private static HttpURLConnection connect(Config config, String url, String method) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(url).openConnection();
        if (!(connection instanceof HttpsURLConnection)) throw new IllegalArgumentException("The ntfy server must use https://.");
        connection.setRequestMethod(method);
        connection.setConnectTimeout(15000);
        connection.setReadTimeout(20000);
        connection.setUseCaches(false);
        connection.setRequestProperty("User-Agent", "navi-auth");
        if (config.token != null) connection.setRequestProperty("Authorization", "Bearer " + config.token);
        return connection;
    }

    private static String topicUrl(Config config, String topic) throws Exception {
        if (!TOPIC.matcher(topic).matches()) throw new IllegalArgumentException("Invalid remote topic.");
        return config.server.replaceAll("/+$", "") + "/" + topic;
    }

    /** Publishes to the computer's inbox. Network I/O: call off the main thread. */
    static void publish(Config config, RemoteMessage value) throws Exception {
        byte[] blob = seal(config.key, TO_COMPUTER, config.computerTopic, value);
        String text = b64url(blob);
        boolean inline = text.length() <= INLINE_LIMIT;
        HttpURLConnection connection = connect(config, topicUrl(config, config.computerTopic), inline ? "POST" : "PUT");
        connection.setDoOutput(true);
        byte[] body = inline ? text.getBytes(StandardCharsets.US_ASCII) : blob;
        if (inline) connection.setRequestProperty("Content-Type", "text/plain");
        else connection.setRequestProperty("Filename", "navi.bin");
        connection.setFixedLengthStreamingMode(body.length);
        try (OutputStream output = connection.getOutputStream()) { output.write(body); }
        int code = connection.getResponseCode();
        connection.disconnect();
        if (code / 100 != 2) throw new IllegalStateException("The ntfy server refused the message (HTTP " + code + ").");
    }

    private static byte[] download(Config config, String url) throws Exception {
        URL target = new URL(url), server = new URL(config.server);
        if (!target.getProtocol().equals(server.getProtocol()) || !target.getHost().equals(server.getHost())
                || target.getPort() != server.getPort())
            throw new IllegalArgumentException("Attachment is not on the configured ntfy server.");
        HttpURLConnection connection = connect(config, url, "GET");
        try (InputStream input = connection.getInputStream()) {
            ByteArrayOutputStream data = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) > 0) {
                data.write(buffer, 0, count);
                if (data.size() > MAX_BLOB) throw new IllegalArgumentException("Oversized attachment.");
            }
            return data.toByteArray();
        } finally { connection.disconnect(); }
    }

    private static String readLine(InputStream input) throws Exception {
        ByteArrayOutputStream line = new ByteArrayOutputStream();
        while (true) {
            int next = input.read();
            if (next == -1) return line.size() == 0 ? null : new String(line.toByteArray(), StandardCharsets.UTF_8);
            if (next == '\n') return new String(line.toByteArray(), StandardCharsets.UTF_8);
            line.write(next);
            if (line.size() > MAX_LINE) throw new IllegalArgumentException("Oversized ntfy event.");
        }
    }

    /**
     * Keeps one streaming subscription per ntfy server (all of this phone's inbox topics on it) until
     * {@code stopped} returns true. Reconnects with backoff and resumes from the last message id, so
     * requests sent while the phone was briefly offline still arrive (expired ones are rejected).
     */
    static void listen(Context context, BooleanSupplier stopped, Consumer<String> status,
                       Consumer<HttpURLConnection> current) {
        SharedPreferences progress = context.getSharedPreferences("remote", 0);
        int delay = 1;
        while (!stopped.getAsBoolean()) {
            HttpURLConnection connection = null;
            try {
                Map<String, List<Config>> servers = new LinkedHashMap<>();
                for (Config config : configs(context)) {
                    String group = config.server + "\n" + (config.token == null ? "" : config.token);
                    List<Config> list = servers.get(group);
                    if (list == null) servers.put(group, list = new ArrayList<>());
                    list.add(config);
                }
                if (servers.isEmpty()) return;
                // One stream per call: the first server group. Multiple servers each get their own thread.
                List<Config> group = servers.values().iterator().next();
                Map<String, Config> byTopic = new LinkedHashMap<>();
                StringBuilder topics = new StringBuilder();
                for (Config config : group) {
                    byTopic.put(config.phoneTopic, config);
                    if (topics.length() > 0) topics.append(',');
                    topics.append(config.phoneTopic);
                }
                Config first = group.get(0);
                String sinceKey = "since:" + first.server + ":" + topics;
                String since = progress.getString(sinceKey, String.valueOf(System.currentTimeMillis() / 1000 - 120));
                connection = connect(first, first.server.replaceAll("/+$", "") + "/" + topics + "/json?since="
                        + URLEncoder.encode(since, "UTF-8"), "GET");
                connection.setReadTimeout(90000); // ntfy sends a keepalive every 45 s.
                current.accept(connection);
                try (InputStream input = connection.getInputStream()) {
                    status.accept("Remote: " + first.host() + " · listening");
                    delay = 1;
                    String line;
                    while (!stopped.getAsBoolean() && (line = readLine(input)) != null) {
                        if (line.isEmpty()) continue;
                        JSONObject event = new JSONObject(line);
                        if (!"message".equals(event.optString("event"))) continue;
                        Config config = byTopic.get(event.optString("topic"));
                        if (config == null) continue;
                        progress.edit().putString(sinceKey, event.getString("id")).apply();
                        try {
                            JSONObject attachment = event.optJSONObject("attachment");
                            byte[] blob = attachment != null && attachment.has("url")
                                    ? download(config, attachment.getString("url")) : unb64url(event.getString("message"));
                            handle(context, config, open(config.key, TO_PHONE, config.phoneTopic, blob));
                        } catch (Exception rejected) {
                            Log.w(TAG, "Remote message rejected", rejected);
                        }
                    }
                }
            } catch (Exception error) {
                if (stopped.getAsBoolean()) return;
                Log.w(TAG, "Remote subscription will retry", error);
                status.accept("Remote: reconnecting in " + delay + " s");
            } finally {
                current.accept(null);
                if (connection != null) connection.disconnect();
            }
            try { Thread.sleep(delay * 1000L); } catch (InterruptedException interrupted) { return; }
            delay = Math.min(60, delay * 2);
        }
    }

    // --- Phone-side message handling -------------------------------------------------------
    private static void handle(Context context, Config config, RemoteMessage message) throws Exception {
        switch (message.getBodyCase()) {
            case ICON:
                acceptIcon(context, message.getIcon());
                return;
            case REQUEST:
                // The same RequestEnvelope as on the other routes.
                KdeConnectInbox.deliver(context, message.getRequest(), null, false, KdeConnectInbox.ROUTE_REMOTE, config.machineId);
                return;
            case RECEIPT:
            case CANCEL: {
                // Navi holds the request these end: match it by request ID, then verify as usual.
                boolean cancel = message.getBodyCase() == RemoteMessage.BodyCase.CANCEL;
                in.akuj.fingerprint.wire.Signed terminal = cancel ? message.getCancel() : message.getReceipt();
                byte[] raw = terminal.getPayload().toByteArray();
                ByteString id = cancel ? Wire.peek(raw, Payload.BodyCase.CANCEL).getCancel().getRequestId()
                        : Wire.peek(raw, Payload.BodyCase.RECEIPT).getReceipt().getRequestId();
                RequestEnvelope current = new Bridge(context).readRequest();
                if (current == null || !id.equals(Wire.peek(current.getSigned().getPayload().toByteArray(),
                        Payload.BodyCase.REQUEST).getRequest().getRequestId()))
                    throw new IllegalArgumentException("Remote confirmation does not match the current request.");
                KdeConnectInbox.deliver(context, current, terminal, cancel, KdeConnectInbox.ROUTE_REMOTE, config.machineId);
                return;
            }
            default:
                throw new IllegalArgumentException("Unknown remote message.");
        }
    }

    /** Called after a request arrived over ntfy without its icon: ask the computer for that one icon. */
    static void requestIconIfMissing(Context context, Challenge request) {
        String hash = request.iconSha256();
        if (hash.isEmpty() || IconCache.get(context, hash) != null) return;
        try {
            Config config = forMachine(context, request.machineId);
            if (config != null) publish(config, RemoteMessage.newBuilder().setIconRequest(IconRequest.newBuilder()
                    .setRequestId(request.payload.getRequestId()).setIconSha256(request.context.getIconSha256())).build());
        } catch (Exception error) {
            Log.w(TAG, "Icon request not sent; the default icon stays", error);
        }
    }

    private static void acceptIcon(Context context, Icon icon) throws Exception {
        Bridge bridge = new Bridge(context);
        RequestEnvelope current = bridge.readRequest();
        if (current == null) return;
        Challenge request = bridge.validate(current, SigningKey.prepare(), true);
        String expected = request.iconSha256();
        byte[] png = icon.getPng().toByteArray();
        if (!request.id.equals(Wire.hex(icon.getRequestId())) || expected.isEmpty() || !Bridge.hash(png).equals(expected))
            throw new IllegalArgumentException("Icon does not match the signed request.");
        RequesterIcon.check(png);
        IconCache.put(context, expected, png);
        RequestReceiver.refreshNotification(context, request.id, false);
    }

    /** Sends this phone's signed reply (or decline) for a request that arrived over ntfy. Off the main thread. */
    static void sendResponse(Context context, Challenge request) throws Exception {
        Config config = forMachine(context, request.machineId);
        if (config == null) throw new IllegalStateException("Remote approvals are off for this computer.");
        Response response = new Bridge(context).responseFor(request);
        if (response == null) throw new IllegalStateException("This approval is no longer available.");
        publish(config, RemoteMessage.newBuilder().setResponse(response).build());
    }

    static boolean bound(Challenge request) {
        return request != null && request.payload.hasRemote();
    }

    static String hash(byte[] data) throws Exception {
        StringBuilder result = new StringBuilder();
        for (byte b : MessageDigest.getInstance("SHA-256").digest(data)) result.append(String.format(java.util.Locale.ROOT, "%02x", b & 0xff));
        return result.toString();
    }
}
