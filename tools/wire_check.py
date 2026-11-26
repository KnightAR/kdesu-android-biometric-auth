#!/usr/bin/env python3
"""Wire-format self-test (make check): builds and verifies every message type with throwaway keys,
using the real host.py helpers, and checks that tampered or mismatched messages are refused.

Navi's side is played here by a software P-256 key; the Android implementation follows the
same rules (Bridge, Challenge, Wire). Nothing touches the network, KDE Connect or any state.
"""
import importlib.util
import io
import os
from pathlib import Path
import secrets
import sys
import time

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("navi_host", ROOT / "host.py")
host = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(host)
_spec = importlib.util.spec_from_file_location("navi_ntfy", ROOT / "ntfy_transport.py")
ntfy = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ntfy)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

pb = host.pb()
failures = []


def check(name, condition):
    print(("ok   " if condition else "FAIL ") + name)
    if not condition:
        failures.append(name)


def refused(name, action, errors=(ValueError, InvalidSignature)):
    try:
        action()
    except errors:
        check("refuses " + name, True)
    else:
        check("refuses " + name, False)


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


machine_key = ec.generate_private_key(ec.SECP256R1())
root = host.certificate(machine_key.public_key(), None, machine_key, "wire-check", ca=True)
phone_key = ec.generate_private_key(ec.SECP256R1())
leaf = host.certificate(phone_key.public_key(), root, machine_key, "Phone wire-check")
leaf_der = der(leaf)
machine_id = host.digest(host.spki(root.public_key()))
other_key = ec.generate_private_key(ec.SECP256R1())
now = int(time.time() * 1000)

context = {"application": "Konsole", "action_id": "org.kde.kdesu.run", "command": "emerge --ask --update @world",
           "command_hidden": False, "requesting_user": "alice", "requesting_uid": os.getuid(), "target_user": "root",
           "source": "kdesu", "requester_pid": 4242, "requester_executable": "/usr/bin/konsole",
           "icon_name": "utilities-terminal", "icon_png_base64": "", "mode": "execute",
           "desktop_request_id": "0f5ad1f4-6c39-4a5e-9b7c-2f1f5b1e9c3a"}
execution = {"shell": "/bin/sh -c", "uid": 0, "gid": 0, "cwd": "/root", "cwd_device": 2049, "cwd_inode": 131073,
             "environment": {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "HOME": "/root", "LANG": "C.UTF-8"}}


def phone_approve(raw, key=phone_key, request_sha256=None, ecdh=b""):
    """What Navi signs with the biometric key: Payload{approval} over the exact request bytes."""
    approval = pb.Approval(request_sha256=request_sha256 or host.sha256(raw), phone_ecdh_spki=ecdh)
    _, signed = host.sign(key, "approval", approval)
    return signed


def response(request_id, signed=None, status=None):
    return pb.Response(request_id=request_id, status=status or pb.STATUS_SIGNED, approval=signed)


# --- Requests ---------------------------------------------------------------------------
request_id = secrets.token_bytes(16)
message = host.request_message(pb.KIND_AUTHENTICATE, request_id, machine_id, leaf_der, "Run this command as root",
                               now, now + 120000, context, execution=execution, remote=True)
raw, envelope = host.request_envelope(machine_key, message)
check("paired request carries no certificates", not envelope.machine_certificate and not envelope.phone_certificate)
_, opened = host.open_signed(envelope.signed, root.public_key(), "request")
check("request verifies with the machine key and parses back",
      opened.context.command == context["command"] and opened.execution.cwd_inode == 131073
      and opened.HasField("remote") and not opened.HasField("transport"))
check("request binds the phone certificate by hash", bytes(opened.certificate_sha256) == host.sha256(leaf_der))
check("random request ID and nonce precede caller text in the signed bytes",
      raw.index(request_id) < raw.index(context["command"].encode()))
refused("a request signed by another key", lambda: host.open_signed(envelope.signed, other_key.public_key(), "request"))
tampered = bytearray(raw)
tampered[raw.index(b"emerge")] ^= 1
refused("a tampered request byte", lambda: host.open_signed(pb.Signed(payload=bytes(tampered), signature=envelope.signed.signature),
                                                           root.public_key(), "request"))
refused("a request opened as another message type", lambda: host.open_signed(envelope.signed, root.public_key(), "receipt"))
old_protocol = host.wire(pb.Payload(protocol=pb.PROTOCOL_UNSPECIFIED, request=message))
refused("an unknown protocol version", lambda: host.peek(old_protocol, "request"))
refused("malformed bytes", lambda: host.parse("RequestEnvelope", b"\x0a\xff\xff\xff\xff\x0f"))
refused("the old JSON envelope", lambda: host.peek(b'{"payload_b64":"e30=","signature_b64":"AA=="}', "request"))
refused("an oversized message", lambda: host.parse("Mail", b"\x00" * (host.MAX_MESSAGE + 1)))
refused("an unknown context field", lambda: host.context_message(dict(context, argv=["sh"])))
refused("a short request ID", lambda: host.request_message(pb.KIND_AUTHENTICATE, b"short", machine_id, leaf_der, "x",
                                                           now, now + 1, context))

enroll = host.request_message(pb.KIND_ENROLL, secrets.token_bytes(16), machine_id, leaf_der, "Approve this phone",
                              now, now + 120000, dict(context, mode=""))
_, enroll_envelope = host.request_envelope(machine_key, enroll, root, leaf_der)
check("enrollment carries both certificates",
      bytes(enroll_envelope.machine_certificate) == der(root) and bytes(enroll_envelope.phone_certificate) == leaf_der)

# --- Responses (the phone's Approval) ---------------------------------------------------
signature, ecdh = host.verify_response(response(request_id, phone_approve(raw)), raw, leaf)
check("approval of the exact request verifies", len(signature) > 60 and ecdh is None)
refused("an approval of other request bytes",
        lambda: host.verify_response(response(request_id, phone_approve(raw + b"x")), raw, leaf))
refused("an approval with a wrong hash",
        lambda: host.verify_response(response(request_id, phone_approve(raw, request_sha256=b"\0" * 32)), raw, leaf))
refused("an approval by another key", lambda: host.verify_response(response(request_id, phone_approve(raw, other_key)), raw, leaf))
refused("a machine-signed request presented as an approval",
        lambda: host.verify_response(response(request_id, envelope.signed), raw, leaf))
refused("a declined response", lambda: host.verify_response(
    pb.Response(request_id=request_id, status=pb.STATUS_DECLINED, message="Rejected on the phone"), raw, leaf))
refused("a response without status", lambda: host.verify_response(pb.Response(request_id=request_id), raw, leaf))
phone_ecdh = host.spki(ec.generate_private_key(ec.SECP256R1()).public_key())
refused("key agreement in a non-setup approval",
        lambda: host.verify_response(response(request_id, phone_approve(raw, ecdh=phone_ecdh)), raw, leaf))
refused("a remote-setup approval without the phone's key",
        lambda: host.verify_response(response(request_id, phone_approve(raw)), raw, leaf, setup=True))
_, setup_ecdh = host.verify_response(response(request_id, phone_approve(raw, ecdh=phone_ecdh)), raw, leaf, setup=True)
check("remote-setup approval binds the phone's ECDH key", setup_ecdh == phone_ecdh)

# --- Receipt and cancel -----------------------------------------------------------------
receipt = host.receipt_message(machine_key, request_id, signature, 777)
_, opened_receipt = host.open_signed(receipt, root.public_key(), "receipt")
check("receipt names this phone signature and the PID",
      bytes(opened_receipt.response_sha256) == host.sha256(signature) and opened_receipt.execution_pid == 777)
cancel = host.cancel_message(machine_key, request_id, raw)
_, opened_cancel = host.open_signed(cancel, root.public_key(), "cancel")
check("cancel names the exact request", bytes(opened_cancel.request_sha256) == host.sha256(raw))
refused("a cancel accepted as a receipt", lambda: host.open_signed(cancel, root.public_key(), "receipt"))

# --- Code enrollment --------------------------------------------------------------------
code = host.pairing_code()
session = secrets.token_bytes(16)
offer = host.offer_message(machine_key, root, code, session, "desktop_device", now)
offer_raw, opened_offer = host.open_signed(offer.signed, root.public_key(), "enroll_offer")
check("offer verifies and its code tag matches",
      bytes(offer.code_tag) == host.code_tag(code, host.OFFER_LABEL, offer_raw) and bytes(opened_offer.session_id) == session)


def hello(code_used, session_used=session, public=phone_key.public_key()):
    spki = host.spki(public)
    payload = host.signed_payload("enroll_hello", pb.EnrollHello(
        session_id=session_used, machine_id=bytes.fromhex(machine_id), phone_key_id=host.sha256(spki),
        public_key_spki=spki, issued_at_ms=now))
    return pb.HelloEnvelope(payload=payload, code_tag=host.code_tag(code_used, host.HELLO_LABEL, payload))


identity = host.verify_hello(hello(code), code, session, machine_id)
check("hello with the typed code yields the phone key", identity["key_id_sha256"] == host.digest(host.spki(phone_key.public_key())))
refused("a hello tagged with another code", lambda: host.verify_hello(hello("WRONGCOD"), code, session, machine_id))
refused("a hello for another session", lambda: host.verify_hello(hello(code, secrets.token_bytes(16)), code, session, machine_id))
check("no hello yet is not an error", host.verify_hello(None, code, session, machine_id) is None)

# --- Direct network ---------------------------------------------------------------------
statement = pb.NetworkIdentity(phone_key_id=host.sha256(host.spki(phone_key.public_key())), tls_certificate=b"tls")
_, signed_identity = host.sign(phone_key, "network_identity", statement)
_, opened_identity = host.open_signed(signed_identity, leaf.public_key(), "network_identity")
check("network identity verifies with the phone key", bytes(opened_identity.tls_certificate) == b"tls")
refused("an approval presented as a network identity",
        lambda: host.open_signed(phone_approve(raw), leaf.public_key(), "network_identity"))
framed = host.frame(b"hello")
check("frames round-trip", host.read_frame(io.BytesIO(framed)) == b"hello")
refused("an oversized frame", lambda: host.read_frame(io.BytesIO(b"\x00\x02\x00\x01" + b"x" * 8)))
refused("a truncated frame", lambda: host.read_frame(io.BytesIO(b"\x00\x00\x00\x09abc")))

# --- ntfy sealing -----------------------------------------------------------------------
key = os.urandom(32)
remote = pb.RemoteMessage()
remote.request.CopyFrom(envelope)
blob = ntfy.seal(key, ntfy.TO_PHONE, "navi-" + "a" * 26, host.wire(remote))
check("ntfy message decrypts to the same RequestEnvelope",
      host.parse("RemoteMessage", ntfy.open_sealed(key, ntfy.TO_PHONE, "navi-" + "a" * 26, blob)).request == envelope)
refused("an ntfy message for the other direction",
        lambda: ntfy.open_sealed(key, ntfy.TO_COMPUTER, "navi-" + "a" * 26, blob), Exception)

# --- Sizes ------------------------------------------------------------------------------
print("\nSizes (kdesu request, 27-character command):")
kde = host.request_message(pb.KIND_AUTHENTICATE, request_id, machine_id, leaf_der, "Run this command as root", now,
                           now + 120000, context, execution=execution, remote=True,
                           transport={"desktop_device_id": "f3a1c2d4_9b8e_4c7d_a6f5_e4d3c2b1a098"})
kde_mail = pb.Mail(request=host.request_envelope(machine_key, kde)[1])
approval_response = response(request_id, phone_approve(raw))
print(f"  signed request payload   {len(raw):5} B")
print(f"  KDE Connect request file {len(host.wire(kde_mail)):5} B")
print(f"  ntfy request             {len(ntfy.b64url(blob)):5} characters (inline limit {ntfy.INLINE_LIMIT})")
print(f"  response                 {len(host.wire(pb.Mail(response=approval_response))):5} B")
print(f"  receipt                  {len(host.wire(pb.Mail(receipt=receipt))):5} B")

if failures:
    print(f"\n{len(failures)} check(s) failed")
    sys.exit(1)
print("\nAll wire checks passed.")
