package in.akuj.fingerprint;

import android.app.Activity;
import android.content.ClipData;
import android.content.ComponentName;
import android.content.Context;
import android.Manifest;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.DocumentsContract;
import android.util.Log;
import in.akuj.fingerprint.wire.EnrollOffer;
import in.akuj.fingerprint.wire.Mail;
import in.akuj.fingerprint.wire.OfferEnvelope;
import in.akuj.fingerprint.wire.RequestEnvelope;
import in.akuj.fingerprint.wire.Response;
import in.akuj.fingerprint.wire.Signed;
import in.akuj.fingerprint.wire.Status;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.regex.Pattern;
import org.json.JSONObject;

/** Signed mailbox carried by stock KDE Connect file sharing: each file is one protobuf Mail. */
final class KdeConnectInbox {
    static final String AUTHORITY = "in.akuj.fingerprint.documents";
    static final String PACKAGE = "org.kde.kdeconnect_tp";
    static final int MAX_FILE = 65536;
    static final String MIME = "application/octet-stream";
    /** Names of computer messages; KDE Connect may append " (1)" when a name already exists in Downloads. */
    static final String MESSAGE_NAME = "navi-auth-(request|receipt|cancel|enroll-offer)-[a-f0-9]{32}";
    private static final Pattern DOWNLOAD_FILE = Pattern.compile(MESSAGE_NAME + "( \\(\\d{1,3}\\))?\\.pb");

    static String desktop(Challenge request) throws Exception {
        if (!request.payload.hasTransport()) return null;
        String id = request.payload.getTransport().getDesktopDeviceId();
        if (!id.matches("[A-Za-z0-9_-]{1,128}")) throw new IllegalArgumentException("Invalid paired computer route.");
        return id;
    }

    static boolean uses(Challenge request) {
        return request != null && request.payload.hasTransport();
    }

    static void sendResponse(Activity activity, Challenge request) throws Exception {
        String device = desktop(request);
        if (device == null) return;
        if (new Bridge(activity).responseFor(request) == null)
            throw new IllegalStateException("This approval is no longer available.");
        if (request.expired()) throw new IllegalStateException("The request expired before delivery.");
        // Reuse KDE Connect's persisted read/write inbox tree grant. Its upload
        // begins after ShareActivity finishes, outliving that activity's Intent grant.
        Uri uri = DocumentsContract.buildDocumentUriUsingTree(
                DocumentsContract.buildTreeDocumentUri(AUTHORITY, "navi"), "response:" + request.id);
        Intent share = new Intent(Intent.ACTION_SEND)
                .setComponent(new ComponentName(PACKAGE, "org.kde.kdeconnect.plugins.share.ShareActivity"))
                .setType(MIME).putExtra("deviceId", device)
                .putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        share.setClipData(ClipData.newRawUri("Signed authentication response", uri));
        activity.startActivity(share);
    }

    /** Phone key and code tag, returned to the computer that displayed the pairing code. */
    static void sendHello(Activity activity, JSONObject verified) throws Exception {
        String device = verified.getString("desktop_device_id");
        if (!device.matches("[A-Za-z0-9_-]{1,128}")) throw new IllegalArgumentException("Invalid paired computer route.");
        Uri uri = DocumentsContract.buildDocumentUriUsingTree(
                DocumentsContract.buildTreeDocumentUri(AUTHORITY, "navi"), "hello:" + verified.getString("session_id"));
        Intent share = new Intent(Intent.ACTION_SEND)
                .setComponent(new ComponentName(PACKAGE, "org.kde.kdeconnect.plugins.share.ShareActivity"))
                .setType(MIME).putExtra("deviceId", device)
                .putExtra(Intent.EXTRA_STREAM, uri).addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        share.setClipData(ClipData.newRawUri("Pairing confirmation", uri));
        activity.startActivity(share);
    }

    /** Outcome of a pairing offer the user opened themselves (file picker, "Open with", Share). */
    static final class ImportResult {
        enum Kind { ACCEPTED, NEEDS_SETUP, ERROR }
        final Kind kind;
        final String machineName, message;
        private ImportResult(Kind kind, String machineName, String message) {
            this.kind = kind;
            this.machineName = machineName;
            this.message = message;
        }
    }

    /**
     * True when Navi can read later computer messages from Download/ (Android 9-10 with storage
     * access). Otherwise an offer found in Downloads means the rest of the enrollment would be lost.
     */
    static boolean canFollowFromDownloads(Context context) {
        return Build.VERSION.SDK_INT <= 29
                && context.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED;
    }

    /** System file picker for a navi-auth-enroll-offer file, opening in Downloads. */
    static Intent offerPicker() {
        return new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
                .putExtra(Intent.EXTRA_MIME_TYPES, new String[]{MIME, "application/x-protobuf", "application/vnd.google.protobuf"})
                .putExtra(DocumentsContract.EXTRA_INITIAL_URI,
                        Uri.parse("content://com.android.externalstorage.documents/document/primary%3ADownload"));
    }

    /**
     * Imports a pairing offer the user picked or opened. Only offers are accepted on this path and they
     * stay untrusted until the computer's code is typed. The offer is always fully validated; it is stored
     * only when Navi can also follow the rest of the enrollment, otherwise the user must finish the
     * KDE Connect setup and start again. Call on a background thread.
     */
    static ImportResult importOffer(Context context, Uri uri) {
        try {
            byte[] bytes = readDocument(context, uri);
            Mail mail;
            try {
                mail = Wire.parse(Mail::parseFrom, bytes, MAX_FILE);
            } catch (IllegalArgumentException error) {
                throw new IllegalArgumentException("This is not a Navi pairing offer. Choose the navi-auth-enroll-offer file.");
            }
            if (mail.getValueCase() != Mail.ValueCase.OFFER)
                throw new IllegalArgumentException("This is not a Navi pairing offer. Choose the navi-auth-enroll-offer file.");
            OfferEnvelope offer = mail.getOffer();
            EnrollOffer payload = PairingCode.validateOffer(offer);
            String name = payload.getMachineName();
            if (!canFollowFromDownloads(context)) return new ImportResult(ImportResult.Kind.NEEDS_SETUP, name, null);
            PairingCode.receiveOffer(context, offer);
            return new ImportResult(ImportResult.Kind.ACCEPTED, name, null);
        } catch (IllegalArgumentException invalid) {
            return new ImportResult(ImportResult.Kind.ERROR, null, invalid.getMessage());
        } catch (Exception failure) {
            Log.w("PhoneAuthenticator", "Pairing offer import failed", failure);
            return new ImportResult(ImportResult.Kind.ERROR, null,
                    "This pairing offer could not be used. Start pairing again on the computer.");
        }
    }

    /** Reads at most MAX_FILE bytes from a picked or shared document. */
    static byte[] readDocument(Context context, Uri uri) throws Exception {
        try (InputStream input = context.getContentResolver().openInputStream(uri)) {
            if (input == null) throw new IllegalArgumentException("The selected file could not be opened.");
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) > 0) {
                output.write(buffer, 0, count);
                if (output.size() > MAX_FILE) throw new IllegalArgumentException("This file is too large to be a Navi pairing offer.");
            }
            return output.toByteArray();
        }
    }

    /**
     * Android 9 and 10 only: KDE Connect saves into Download/ when Navi is not its destination
     * folder. Each recent navi-auth file is processed exactly like a provider delivery, then removed.
     * Android 11+ cannot read other apps' downloads without all-files access, which Navi does not request.
     */
    @SuppressWarnings("deprecation") // getExternalStoragePublicDirectory is the API 28-29 way to reach Download/.
    static int importDownloads(Context context) {
        if (Build.VERSION.SDK_INT > 29
                || context.checkSelfPermission(Manifest.permission.READ_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED)
            return 0;
        File downloads = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS);
        ArrayList<File> folders = new ArrayList<>();
        folders.add(downloads);
        File[] children = downloads.listFiles(File::isDirectory);
        if (children != null) for (int i = 0; i < children.length && i < 32; i++) folders.add(children[i]);
        SharedPreferences seen = context.getSharedPreferences("download-import", 0);
        long cutoff = System.currentTimeMillis() - 15 * 60_000L;
        ArrayList<File> candidates = new ArrayList<>();
        for (File folder : folders) {
            File[] files = folder.listFiles((dir, name) -> DOWNLOAD_FILE.matcher(name).matches());
            if (files != null) for (File file : files)
                if (file.isFile() && file.length() <= MAX_FILE && file.lastModified() >= cutoff) candidates.add(file);
        }
        // Oldest first, mirroring delivery order (an offer precedes its request; a request its cancel).
        candidates.sort((a, b) -> Long.compare(a.lastModified(), b.lastModified()));
        int imported = 0;
        SharedPreferences.Editor remember = seen.edit();
        for (File file : candidates) {
            String marker = file.getAbsolutePath() + "@" + file.lastModified();
            if (seen.contains(marker)) continue;
            try {
                receive(context, java.nio.file.Files.readAllBytes(file.toPath()));
                imported++;
            } catch (Exception error) {
                Log.w("PhoneAuthenticator", "Ignored " + file.getName() + " from Downloads", error);
            }
            if (!file.delete()) remember.putLong(marker, System.currentTimeMillis());
        }
        for (String marker : seen.getAll().keySet())
            if (seen.getLong(marker, 0) < cutoff) remember.remove(marker);
        remember.apply();
        return imported;
    }

    static void receive(Context context, byte[] bytes) throws Exception {
        Mail mail = Wire.parse(Mail::parseFrom, bytes, MAX_FILE);
        switch (mail.getValueCase()) {
            case OFFER:
                PairingCode.receiveOffer(context, mail.getOffer());
                context.getSharedPreferences("kdeconnect", 0).edit().putBoolean("received", true).apply();
                return;
            case REQUEST:
                deliver(context, mail.getRequest(), null, false, ROUTE_KDECONNECT, null);
                return;
            case RECEIPT:
            case CANCEL:
                // Terminal messages carry the request they end: a cancel may overtake that request.
                if (!mail.hasOriginalRequest()) throw new IllegalArgumentException("Invalid authentication file.");
                boolean cancel = mail.getValueCase() == Mail.ValueCase.CANCEL;
                deliver(context, mail.getOriginalRequest(), cancel ? mail.getCancel() : mail.getReceipt(), cancel,
                        ROUTE_KDECONNECT, null);
                return;
            default:
                throw new IllegalArgumentException("Invalid authentication file.");
        }
    }

    static final String ROUTE_KDECONNECT = "kdeconnect", ROUTE_REMOTE = "remote", ROUTE_LAN = "lan";

    /** The route a request arrived on; Navi answers the same way. */
    static String route(Context context, Challenge request) {
        try {
            JSONObject recorded = new Bridge(context).read("request-route.json");
            if (recorded != null && request.id.equals(recorded.optString("request_id"))) return recorded.getString("route");
        } catch (Exception ignored) { }
        return uses(request) ? ROUTE_KDECONNECT : ROUTE_LAN;
    }

    static void recordRoute(Bridge bridge, String id, String route) throws Exception {
        bridge.write("request-route.json", new JSONObject().put("request_id", id).put("route", route));
    }

    /**
     * A request ({@code terminal} null), or a receipt or cancel ({@code terminal}) together with the request
     * it ends, from KDE Connect or decrypted from ntfy ({@code route} remote, from the configured computer
     * {@code remoteMachine}). The same validation applies to both.
     */
    static void deliver(Context context, RequestEnvelope envelope, Signed terminal, boolean cancel, String route,
                        String remoteMachine) throws Exception {
        boolean remote = ROUTE_REMOTE.equals(route);
        boolean requestMessage = terminal == null;
        Challenge accepted = null;
        synchronized (Bridge.MAILBOX) {
            Bridge bridge = new Bridge(context);
            SigningKey key = SigningKey.prepare();
            Challenge request = bridge.validate(envelope, key, !requestMessage);
            String id = request.id;
            // Enrollment is only reachable here after Bridge.validate accepted a code-pinned computer.
            if (remote ? !RemoteChannel.bound(request) || !Challenge.AUTHENTICATE.equals(request.kind)
                    || !request.machineId.equals(remoteMachine) : desktop(request) == null)
                throw new IllegalArgumentException("Authentication does not match its delivery route.");
            JSONObject tombstones = bridge.read("kde-cancellations.json");
            if (tombstones == null) tombstones = new JSONObject();
            long now = System.currentTimeMillis();
            ArrayList<String> expired = new ArrayList<>();
            Iterator<String> ids = tombstones.keys();
            while (ids.hasNext()) {
                String previous = ids.next();
                if (tombstones.getJSONObject(previous).getLong("until") < now) expired.add(previous);
            }
            for (String previous : expired) tombstones.remove(previous);
            String tombstoneId = request.machineId + ":" + id;
            String requestHash = Bridge.hash(request.bytes);
            RequestEnvelope current = bridge.readRequest();
            boolean isCurrent = current != null && Arrays.equals(current.getSigned().getPayload().toByteArray(), request.bytes);
            if (cancel) {
                if (!bridge.canceled(request, terminal)) throw new IllegalArgumentException("Invalid signed withdrawal.");
                // The transfer may overtake its request. Remember only verified, recent cancellation.
                long until = request.expiresAt + 30000;
                if (until > now) {
                    if (tombstones.length() >= 64 && !tombstones.has(tombstoneId))
                        throw new IllegalStateException("Too many pending computer withdrawals.");
                    tombstones.put(tombstoneId, new JSONObject().put("until", until).put("hash", requestHash));
                }
                bridge.write("kde-cancellations.json", tombstones);
                if (isCurrent) {
                    bridge.write(Bridge.CANCEL, terminal);
                    RequestReceiver.refreshNotification(context, id, true);
                }
                return;
            }
            if (requestMessage) {
                JSONObject withdrawn = tombstones.optJSONObject(tombstoneId);
                if (withdrawn != null && requestHash.equals(withdrawn.getString("hash"))) return;
                if (current != null) {
                    try {
                        Challenge previous = bridge.validate(current, key);
                        if (previous.id.equals(id)) {
                            if (!Arrays.equals(previous.bytes, request.bytes)) throw new IllegalArgumentException("Changed request.");
                            return;
                        }
                        Response response = bridge.responseFor(previous);
                        boolean finished = bridge.canceled(previous) || response != null
                                && (response.getStatus() == Status.STATUS_DECLINED || bridge.receipt(previous, response));
                        if (!finished) throw new IllegalStateException("Another computer request is active.");
                    } catch (Challenge.Expired ignored) { }
                }
                bridge.write(Bridge.REQUEST, envelope);
                recordRoute(bridge, id, route);
                bridge.write("kde-cancellations.json", tombstones);
                if (!remote) context.getSharedPreferences("kdeconnect", 0).edit().putBoolean("received", true).apply();
                // Receiving through KDE Connect must preserve the user's direct-LAN preference.
                RequestReceiver.refreshNotification(context, id, false);
                accepted = request;
            } else {
                Response response = bridge.responseFor(request);
                if (!isCurrent || response == null || !bridge.receipt(request, response, terminal))
                    throw new IllegalArgumentException("Confirmation does not match the current approval.");
                bridge.write(Bridge.RECEIPT, terminal);
            }
        }
        // Over ntfy the request carries only its icon's hash; fetch the PNG if Navi doesn't have it.
        if (remote && accepted != null) RemoteChannel.requestIconIfMissing(context, accepted);
    }
}
