package in.akuj.fingerprint;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import android.util.Log;
import com.google.protobuf.ByteString;
import com.google.protobuf.MessageLite;
import in.akuj.fingerprint.wire.Mail;
import in.akuj.fingerprint.wire.MailName;
import in.akuj.fingerprint.wire.NetworkHello;
import in.akuj.fingerprint.wire.NetworkReply;
import in.akuj.fingerprint.wire.NetworkRpc;
import in.akuj.fingerprint.wire.Op;
import in.akuj.fingerprint.wire.Payload;
import in.akuj.fingerprint.wire.RequestEnvelope;
import in.akuj.fingerprint.wire.Response;
import in.akuj.fingerprint.wire.Signed;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import org.json.JSONObject;

/**
 * Background delivery: the TLS LAN listener (when network authentication is on) and the ntfy
 * subscription for remote approvals (when set up). Every LAN RPC is authenticated with an already
 * pinned computer key; remote messages are validated exactly like KDE Connect deliveries.
 */
public final class NetworkService extends Service {
    static final int PORT = 39841;
    private static final int LIMIT = 131072;
    private static final int NOTIFICATION_ID = 2;
    static final String CHANNEL = "computer_connection";
    private static final int RECOVERY_NOTIFICATION_ID = 3, REENABLE_NOTIFICATION_ID = 4;
    static volatile String status = "Network connection is off";
    static volatile String remoteStatus = "";
    static volatile boolean running;
    private boolean lanStarted;
    private Thread remoteThread;
    private volatile java.net.HttpURLConnection remoteConnection;
    private volatile SSLServerSocket listener;
    private volatile boolean stopping;
    private Thread listenerThread;
    private final ThreadPoolExecutor clients = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(4));
    private Bridge bridge;
    private SigningKey key;
    private Signed identityStatement;
    private final Object mailbox = Bridge.MAILBOX;
    private final java.util.Timer deadlines = new java.util.Timer("navi-lan-deadlines", true);
    private final java.util.Set<SSLSocket> sockets = java.util.concurrent.ConcurrentHashMap.newKeySet();

    @Override public IBinder onBind(Intent intent) { return null; }

    /** Direct network (LAN) authentication is enabled. */
    static boolean enabled(Context context) {
        return context.getSharedPreferences("network", 0).getBoolean("enabled", false);
    }

    /** The service runs for the LAN listener, remote approvals over ntfy, or both. */
    static boolean shouldRun(Context context) {
        return enabled(context) || RemoteChannel.configured(context);
    }

    /** Applies a changed LAN or remote setting: restart with exactly the enabled parts. */
    static void restart(Context context) {
        Intent intent = new Intent(context, NetworkService.class);
        context.stopService(intent);
        if (shouldRun(context)) context.startForegroundService(intent);
    }

    private String combinedStatus() {
        String lan = enabled(this) ? status : "";
        if (remoteStatus.isEmpty()) return lan.isEmpty() ? "Starting…" : lan;
        return lan.isEmpty() ? remoteStatus : lan + "\n" + remoteStatus;
    }

    static void createChannel(Context context) {
        NotificationManager manager = context.getSystemService(NotificationManager.class);
        manager.createNotificationChannel(new NotificationChannel(CHANNEL, "Computer connection", NotificationManager.IMPORTANCE_LOW));
    }

    static void showRecoveryNotification(Context context) {
        createChannel(context);
        PendingIntent open = PendingIntent.getActivity(context, 3, new Intent(context, MainActivity.class),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        context.getSystemService(NotificationManager.class).notify(RECOVERY_NOTIFICATION_ID,
                new Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_notification)
                        .setContentTitle("Navi needs your attention").setContentText(status)
                        .setContentIntent(open).setAutoCancel(true).build());
    }

    /** An update turned direct network approvals off; tapping starts turning them on again. */
    static void showReenableNotification(Context context) {
        createChannel(context);
        PendingIntent open = PendingIntent.getActivity(context, 4, new Intent(context, SettingsActivity.class)
                        .putExtra(SettingsActivity.EXTRA_ENABLE_NETWORK, true),
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);
        context.getSystemService(NotificationManager.class).notify(REENABLE_NOTIFICATION_ID,
                new Notification.Builder(context, CHANNEL).setSmallIcon(R.drawable.ic_notification)
                        .setContentTitle("Direct network approvals are off")
                        .setContentText("Navi was updated. Tap to turn them on again with your fingerprint.")
                        .setContentIntent(open).setAutoCancel(true).build());
    }

    static void cancelReenableNotification(Context context) {
        context.getSystemService(NotificationManager.class).cancel(REENABLE_NOTIFICATION_ID);
    }

    private Notification notification() {
        PendingIntent open = PendingIntent.getActivity(this, 1, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE);
        PendingIntent setup = PendingIntent.getActivity(this, 2, new Intent(this, BackgroundSetupActivity.class), PendingIntent.FLAG_IMMUTABLE);
        Notification.Builder builder = new Notification.Builder(this, CHANNEL).setSmallIcon(R.drawable.ic_notification)
                .setContentTitle("Navi · computer authentication")
                .setContentText(combinedStatus()).setStyle(new Notification.BigTextStyle().bigText(combinedStatus()
                        + "\nListening in the background for your paired computers."))
                .setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true).setShowWhen(false)
                .addAction(new Notification.Action.Builder(null, "Background setup", setup).build())
                .setCategory(Notification.CATEGORY_SERVICE);
        if (Build.VERSION.SDK_INT >= 31) builder.setForegroundServiceBehavior(Notification.FOREGROUND_SERVICE_IMMEDIATE);
        return builder.build();
    }

    private void publishStatus(String message) {
        synchronized (mailbox) {
            if (stopping) return;
            status = message;
            getSystemService(NotificationManager.class).notify(NOTIFICATION_ID, notification());
        }
    }

    private void publishRemoteStatus(String message) {
        synchronized (mailbox) {
            if (stopping) return;
            remoteStatus = message;
            getSystemService(NotificationManager.class).notify(NOTIFICATION_ID, notification());
        }
    }

    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        Bridge.upgrade(this); // An old-protocol network binding turns the LAN listener off until re-enabled.
        if (!shouldRun(this)) {
            stopSelf();
            return START_NOT_STICKY;
        }
        createChannel(this);
        if (!running) status = "Starting network connection…";
        if (Build.VERSION.SDK_INT >= 29)
            startForeground(NOTIFICATION_ID, notification(), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE);
        else
            startForeground(NOTIFICATION_ID, notification());
        getSystemService(NotificationManager.class).cancel(RECOVERY_NOTIFICATION_ID);
        running = true;
        if (enabled(this) && !lanStarted) {
            lanStarted = true;
            listenerThread = new Thread(this::listen, "navi-lan-listener");
            listenerThread.start();
        }
        if (RemoteChannel.configured(this) && remoteThread == null) {
            remoteStatus = "Remote: connecting…";
            remoteThread = new Thread(() -> RemoteChannel.listen(this, () -> stopping, this::publishRemoteStatus,
                    connection -> remoteConnection = connection), "navi-remote-listener");
            remoteThread.start();
        }
        return START_STICKY;
    }

    private void listen() {
        javax.net.ssl.SSLServerSocketFactory socketFactory;
        try {
            bridge = new Bridge(this);
            key = SigningKey.prepare();
            NetworkIdentity identity = new NetworkIdentity();
            identityStatement = identity.approved(bridge, key);
            if (identityStatement == null || bridge.pairings().length() == 0)
                throw new IllegalStateException("Enable the network connection in Navi first.");
            socketFactory = identity.context().getServerSocketFactory();
        } catch (Exception error) {
            if (!stopping) {
                status = "Open Navi and enable network authentication again";
                Log.e("PhoneAuthenticator", "LAN identity unavailable", error);
                showRecoveryNotification(this);
                if (!RemoteChannel.configured(this)) stopSelf(); // Remote approvals keep running.
            }
            return;
        }
        // A lost socket must not permanently disable an opted-in listener.
        // Block in accept while idle; no polling, repeating alarms or permanent wake lock.
        int retrySeconds = 1;
        while (!stopping) {
            try (SSLServerSocket server = (SSLServerSocket) socketFactory.createServerSocket()) {
                listener = server;
                server.setReuseAddress(true);
                server.setEnabledProtocols(new String[]{NetworkIdentity.TLS_PROTOCOL});
                if (Build.VERSION.SDK_INT < 29) server.setEnabledCipherSuites(new String[]{
                        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"});
                server.bind(new InetSocketAddress(PORT), 4);
                publishStatus("Ready on your network · port " + PORT);
                retrySeconds = 1;
                while (!stopping) {
                    SSLSocket socket = (SSLSocket) server.accept();
                    socket.setSoTimeout(5000);
                    sockets.add(socket);
                    try { clients.execute(() -> handle(socket)); }
                    catch (java.util.concurrent.RejectedExecutionException busy) { sockets.remove(socket); socket.close(); }
                }
            } catch (Exception error) {
                if (stopping) break;
                Log.w("PhoneAuthenticator", "LAN listener will retry", error);
                publishStatus("Reconnecting · retrying in " + retrySeconds + " seconds");
                try { Thread.sleep(retrySeconds * 1000L); }
                catch (InterruptedException stopped) { Thread.currentThread().interrupt(); break; }
                retrySeconds = Math.min(30, retrySeconds * 2);
            } finally { listener = null; }
        }
    }

    private void handle(SSLSocket socket) {
        java.util.TimerTask deadline = new java.util.TimerTask() {
            @Override public void run() { try { socket.close(); } catch (Exception ignored) { } }
        };
        try (SSLSocket connection = socket) {
            if (stopping) return;
            deadlines.schedule(deadline, 10000);
            connection.startHandshake();
            byte[] nonce = new byte[32];
            new SecureRandom().nextBytes(nonce);
            InputStream input = connection.getInputStream();
            OutputStream output = connection.getOutputStream();
            send(output, NetworkHello.newBuilder().setIdentity(identityStatement).setNonce(ByteString.copyFrom(nonce)).build());
            Signed envelope = Wire.parse(Signed::parseFrom, receive(input), LIMIT);
            // Unverified until the signature check below: machine_id only selects the pinned computer key.
            NetworkRpc claimed = Wire.peek(envelope.getPayload().toByteArray(), Payload.BodyCase.NETWORK_RPC).getNetworkRpc();
            String machine = Wire.hex(Wire.exact(claimed.getMachineId(), 32, "computer key ID"));
            JSONObject paired = bridge.pairings().optJSONObject(machine);
            if (paired == null) throw new IllegalArgumentException("Computer is not paired");
            NetworkRpc rpc = Wire.open(envelope, Bridge.certificate(paired.getString("machine_certificate_b64")).getPublicKey(),
                    Payload.BodyCase.NETWORK_RPC).getNetworkRpc();
            // Bound to this connection: a recorded call cannot be replayed on another.
            if (!java.security.MessageDigest.isEqual(nonce, rpc.getServerNonce().toByteArray()))
                throw new IllegalArgumentException("Invalid network request");
            // Serialize mailbox changes so paired computers cannot replace each other's active request.
            Mail value;
            synchronized (mailbox) {
                if (stopping) throw new IllegalStateException("Network authentication is off");
                value = exchange(rpc, machine);
            }
            NetworkReply.Builder reply = NetworkReply.newBuilder().setOk(true);
            if (value != null) reply.setValue(value);
            send(output, reply.build());
        } catch (Exception error) {
            // An invalid peer gets no metadata and cannot trigger an Android notification.
            Log.w("PhoneAuthenticator", "LAN request rejected", error);
        } finally {
            deadline.cancel();
            deadlines.purge();
            sockets.remove(socket);
        }
    }

    private Mail exchange(NetworkRpc rpc, String machine) throws Exception {
        Op operation = rpc.getOperation();
        MailName name = rpc.getName();
        String id = Wire.hex(Wire.exact(rpc.getRequestId(), 16, "request ID"));
        if (rpc.getValue().getSerializedSize() > Wire.MAX_MESSAGE) throw new IllegalArgumentException("Message too large");
        if (operation == Op.OP_WRITE && name == MailName.MAIL_REQUEST) {
            if (rpc.getValue().getValueCase() != Mail.ValueCase.REQUEST) throw new IllegalArgumentException("Expected a request");
            RequestEnvelope value = rpc.getValue().getRequest();
            Challenge request = bridge.validate(value, key);
            if (!Challenge.AUTHENTICATE.equals(request.kind) || !id.equals(request.id) || !machine.equals(request.machineId))
                throw new IllegalArgumentException("Request does not match sender");
            RequestEnvelope old = bridge.readRequest();
            if (old != null) {
                try {
                    Challenge previous = bridge.validate(old, key);
                    if (previous.id.equals(id)) {
                        if (!Arrays.equals(previous.bytes, request.bytes)) throw new IllegalArgumentException("Changed request");
                        return null; // Idempotent redelivery cannot repost or clear a completed proof.
                    }
                    Response response = bridge.responseFor(previous);
                    boolean finished = bridge.canceled(previous) || response != null
                            && (response.getStatus() == in.akuj.fingerprint.wire.Status.STATUS_DECLINED || bridge.receipt(previous, response));
                    if (!finished) throw new IllegalStateException("Another computer request is active");
                } catch (Challenge.Expired expired) { /* Old request no longer owns the mailbox. */ }
            }
            bridge.write(Bridge.REQUEST, value);
            KdeConnectInbox.recordRoute(bridge, id, KdeConnectInbox.ROUTE_LAN);
            RequestReceiver.refreshNotification(this, id, false);
            return null;
        }
        RequestEnvelope current = bridge.readRequest();
        if (current == null) throw new IllegalArgumentException("No current request");
        boolean terminal = operation == Op.OP_WRITE && (name == MailName.MAIL_RECEIPT || name == MailName.MAIL_CANCEL);
        Challenge request = bridge.validate(current, key, terminal);
        if (!id.equals(request.id) || !machine.equals(request.machineId))
            throw new IllegalArgumentException("Request is owned by another computer");
        if (operation == Op.OP_READ && name == MailName.MAIL_RESPONSE) {
            Response response = bridge.responseFor(request);
            return response == null ? null : Mail.newBuilder().setResponse(response).build();
        }
        if (operation == Op.OP_WRITE) {
            Mail value = rpc.getValue();
            if (name == MailName.MAIL_CANCEL && value.getValueCase() == Mail.ValueCase.CANCEL) {
                if (!bridge.canceled(request, value.getCancel())) throw new IllegalArgumentException("Wrong cancellation");
                bridge.write(Bridge.CANCEL, value.getCancel());
                RequestReceiver.refreshNotification(this, id, true);
            } else if (name == MailName.MAIL_RECEIPT && value.getValueCase() == Mail.ValueCase.RECEIPT) {
                Response response = bridge.responseFor(request);
                if (response == null || !bridge.receipt(request, response, value.getReceipt()))
                    throw new IllegalArgumentException("Wrong receipt");
                bridge.write(Bridge.RECEIPT, value.getReceipt());
            } else throw new IllegalArgumentException("Unknown mailbox operation");
            return null;
        }
        throw new IllegalArgumentException("Unknown network operation");
    }

    /** One length-prefixed frame (4-byte big-endian length, at most LIMIT bytes). */
    private static byte[] receive(InputStream input) throws Exception {
        DataInputStream data = new DataInputStream(input);
        int size = data.readInt();
        if (size <= 0 || size > LIMIT) throw new IllegalArgumentException("Network message too large");
        byte[] bytes = new byte[size];
        data.readFully(bytes);
        return bytes;
    }

    private static void send(OutputStream output, MessageLite value) throws Exception {
        byte[] bytes = value.toByteArray();
        if (bytes.length == 0 || bytes.length > LIMIT) throw new IllegalArgumentException("Network message too large");
        DataOutputStream data = new DataOutputStream(output);
        data.writeInt(bytes.length);
        data.write(bytes);
        data.flush();
    }

    @Override public void onDestroy() {
        synchronized (mailbox) { stopping = true; }
        try { if (listener != null) listener.close(); } catch (Exception ignored) { }
        if (listenerThread != null) listenerThread.interrupt();
        java.net.HttpURLConnection connection = remoteConnection;
        if (connection != null) connection.disconnect();
        if (remoteThread != null) remoteThread.interrupt();
        remoteStatus = "";
        clients.shutdownNow();
        for (SSLSocket socket : sockets) { try { socket.close(); } catch (Exception ignored) { } }
        deadlines.cancel();
        running = false;
        if (status.startsWith("Ready") || status.startsWith("Starting") || status.startsWith("Reconnecting"))
            status = "Network connection is off";
        stopForeground(STOP_FOREGROUND_REMOVE);
        super.onDestroy();
    }
}
