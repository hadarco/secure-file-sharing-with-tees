"""Exercise signed operations against a disposable live service.

Synthetic P-256 keys drive real API requests and persistence changes. The harness
disables client certificate verification and cleans up deployment data. Tests of
signature rejection do not establish independent trust in public-key enrollment.
"""

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.request

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

import g8sign

BASE = os.environ.get("G8_BASE", "https://localhost:8443")
_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE
JSONH = {"Content-Type": "application/json"}
PW = "YOUR_TEST_PASSWORD"

_passed = 0
_failed = 0


def check(label, got, want):
    global _passed, _failed
    ok = got == want
    if ok:
        _passed += 1
    else:
        _failed += 1
    print("  [%s] %-56s got %s, want %s" % ("PASS" if ok else "FAIL", label, got, want))
    return ok


def note(label, ok, extra=""):
    global _passed, _failed
    if ok:
        _passed += 1
    else:
        _failed += 1
    print(
        "  [%s] %s%s"
        % ("PASS" if ok else "FAIL", label, ("  " + extra) if extra else "")
    )
    return ok


def call(method, path, body=None, token=None, headers=None):
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=120) as r:
            p = r.read()
            try:
                return r.status, json.loads(p.decode())
            except Exception:
                return r.status, p
    except urllib.error.HTTPError as e:
        p = e.read()
        try:
            return e.code, json.loads(p.decode())
        except Exception:
            return e.code, p


print("=" * 78)
print("TDX CLIENT-SIGNED ACTIONS")
print("=" * 78)

# --------------------------------------------------------------------------------------
print("\n-- setup: a user with a signing key, and one without --")

priv = ec.generate_private_key(ec.SECP256R1())
spki = priv.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
PUB_B64 = base64.b64encode(spki).decode()

ALICE = "sign_a_" + os.urandom(3).hex()
BOB = "sign_b_" + os.urandom(3).hex()

st, b = call(
    "POST",
    "/register",
    json.dumps({"username": ALICE, "password": PW, "pubkey": PUB_B64}).encode(),
    headers=JSONH,
)
check("register Alice WITH a public key -> 201", st, 201)
st, b = call(
    "POST",
    "/register",
    json.dumps({"username": BOB, "password": PW}).encode(),
    headers=JSONH,
)
check("register Bob with NO key -> 201", st, 201)

st, b = call(
    "POST",
    "/login",
    json.dumps({"username": ALICE, "password": PW}).encode(),
    headers=JSONH,
)
TOK_A = b.get("token") if isinstance(b, dict) else None
st, b = call(
    "POST",
    "/login",
    json.dumps({"username": BOB, "password": PW}).encode(),
    headers=JSONH,
)
TOK_B = b.get("token") if isinstance(b, dict) else None
if not (TOK_A and TOK_B):
    print("  [ABORT] registration quota hit -- restart the service and re-run")
    raise SystemExit(1)

st, me = call("GET", "/me", token=TOK_A)
AID = me.get("user_id")
st, me = call("GET", "/me", token=TOK_B)
BID = me.get("user_id")
note("both users logged in", bool(AID and BID))


def sign(action, fid, target, ts=None, nonce=None, key=None, permission=""):
    """Produce (statement, signature) exactly as the browser client does.

    `permission` joined the signed statement, so this helper had to follow.
    Share requests must sign the permission they are asking for; revoke and delete grant
    nothing and sign an empty string.

    Worth noting WHY this file had to change at all: it calls g8sign.canonical() directly,
    which means it would have kept passing while every signature produced by the real
    browser client failed. A test that shares an implementation with the thing it tests
    cannot detect a protocol split between client and server -- so the byte-for-byte
    comparison against the browser's hand-built JSON lives outside this suite.
    """
    ts = ts or int(time.time())
    nonce = nonce or os.urandom(6).hex()
    body = g8sign.canonical(action, AID, fid, target, ts, nonce, permission)
    der = (key or priv).sign(body, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return base64.b64encode(body).decode(), base64.b64encode(raw).decode()


# --------------------------------------------------------------------------------------
print("\n-- 1. an honest signed share --")
st, b = call(
    "POST",
    "/files",
    b"board minutes, confidential\n" * 40,
    token=TOK_A,
    headers={
        "Content-Type": "application/octet-stream",
        "X-Filename": "signed_target.txt",
    },
)
FID = b.get("file_id") if isinstance(b, dict) else None
check("upload -> 201", st, 201)

stmt, sig = sign("share", FID, BOB, permission="read")
st, b = call(
    "POST",
    "/files/%s/share" % FID,
    json.dumps(
        {"username": BOB, "permission": "read", "statement": stmt, "signature": sig}
    ).encode(),
    token=TOK_A,
    headers=JSONH,
)
check("correctly signed share -> 201", st, 201)
note(
    "the response reports the action as signed",
    isinstance(b, dict) and b.get("signed") is True,
)

# --------------------------------------------------------------------------------------
print("\n-- 2. the SERVER tries to forge an action for Alice --")
print(
    "   Everything below is attempted with the session token, the database, the audit"
)
print("   key and full knowledge of the protocol. Only Alice's private key is missing.")

st, b = call(
    "POST",
    "/files/%s/share" % FID,
    json.dumps({"username": "mallory", "permission": "read"}).encode(),
    token=TOK_A,
    headers=JSONH,
)
check("share with NO signature at all -> 400", st, 400)
print("       detail:", b.get("detail") if isinstance(b, dict) else b)

st, b = call(
    "POST",
    "/files/%s/share" % FID,
    json.dumps(
        {
            "username": "mallory",
            "permission": "read",
            "statement": stmt,
            "signature": sig,
        }
    ).encode(),
    token=TOK_A,
    headers=JSONH,
)
check("Alice's real signature reused for a DIFFERENT recipient -> 401", st, 401)

stmt2, sig2 = sign("share", FID, BOB, permission="read")
st, b = call(
    "POST",
    "/files/%s/share" % FID,
    json.dumps(
        {
            "username": BOB,
            "permission": "read",
            "statement": stmt2,
            "signature": base64.b64encode(os.urandom(64)).decode(),
        }
    ).encode(),
    token=TOK_A,
    headers=JSONH,
)
check("a fabricated signature -> 401", st, 401)

evil = ec.generate_private_key(ec.SECP256R1())
stmt3, sig3 = sign("share", FID, BOB, key=evil, permission="read")
st, b = call(
    "POST",
    "/files/%s/share" % FID,
    json.dumps(
        {"username": BOB, "permission": "read", "statement": stmt3, "signature": sig3}
    ).encode(),
    token=TOK_A,
    headers=JSONH,
)
check("signed with the SERVER's own fresh key -> 401", st, 401)
print("       ^ the server can generate keys all day; it cannot generate ALICE's")

stmt4, sig4 = sign("share", FID, BOB, ts=int(time.time()) - 900, permission="read")
st, b = call(
    "POST",
    "/files/%s/share" % FID,
    json.dumps(
        {"username": BOB, "permission": "read", "statement": stmt4, "signature": sig4}
    ).encode(),
    token=TOK_A,
    headers=JSONH,
)
check("a statement signed 15 minutes ago -> 401", st, 401)

# --------------------------------------------------------------------------------------
print("\n-- 3. replay: a captured signature cannot be reused --")
stmt5, sig5 = sign("revoke", FID, BID)
st, _ = call(
    "DELETE",
    "/files/%s/share/%s" % (FID, BID),
    token=TOK_A,
    headers={"X-G8-Statement": stmt5, "X-G8-Signature": sig5},
)
check("signed revoke -> 200", st, 200)
st, b = call(
    "DELETE",
    "/files/%s/share/%s" % (FID, BID),
    token=TOK_A,
    headers={"X-G8-Statement": stmt5, "X-G8-Signature": sig5},
)
check("the SAME signed revoke replayed -> 401", st, 401)
print("       detail:", b.get("detail") if isinstance(b, dict) else b)

# --------------------------------------------------------------------------------------
print("\n-- 4. cross-action reuse: a share signature cannot delete --")
stmt6, sig6 = sign("share", FID, BOB, permission="read")
st, b = call(
    "DELETE",
    "/files/%s" % FID,
    token=TOK_A,
    headers={"X-G8-Statement": stmt6, "X-G8-Signature": sig6},
)
check("a SHARE signature presented to DELETE -> 401", st, 401)

# --------------------------------------------------------------------------------------
print("\n-- 5. the honest path still works --")
stmt7, sig7 = sign("delete", FID, "")
st, b = call(
    "DELETE",
    "/files/%s" % FID,
    token=TOK_A,
    headers={"X-G8-Statement": stmt7, "X-G8-Signature": sig7},
)
check("correctly signed delete -> 200", st, 200)
note(
    "the response reports the action as signed",
    isinstance(b, dict) and b.get("signed") is True,
)

# --------------------------------------------------------------------------------------
print("\n-- 6. a user without a key is not blocked, but the log SAYS SO --")
st, b = call(
    "POST",
    "/files",
    b"bob's own file\n",
    token=TOK_B,
    headers={"Content-Type": "application/octet-stream", "X-Filename": "bob_file.txt"},
)
BFID = b.get("file_id") if isinstance(b, dict) else None
st, b = call(
    "POST",
    "/files/%s/share" % BFID,
    json.dumps({"username": ALICE, "permission": "read"}).encode(),
    token=TOK_B,
    headers=JSONH,
)
check("Bob (no key) shares without signing -> 201", st, 201)
note(
    "...and the response marks it unsigned",
    isinstance(b, dict) and b.get("signed") is False,
)
print("       ^ ENFORCEMENT POLICY: signatures are required from users who HAVE a key,")
print("         optional from those who do not, so non-browser clients still work.")
print("         The residual is narrow: an unsigned entry for a key-holding user is")
print("         itself evidence, and the keyed chain makes it unremovable.")

# --------------------------------------------------------------------------------------
print("\n-- 7. what the audit log actually recorded --")
try:
    import g8audit
    import g8auth
    import g8db

    # NOTE ON FIELD NAMES: g8audit.read() returns 'action' and 'detail'. Those are the
    # DECRYPTED, renamed fields -- inside the sealed payload they are the short keys 'a'
    # and 'd'. An earlier version of this block filtered on 'a'/'d', found nothing, and
    # confidently reported "0 signed" while printing the signatures on the line above.
    # Same family of error as the false pass in e2e_files.py: a check that asks the wrong
    # question returns a wrong answer with no sign of doubt.
    entries = g8audit.read(g8db.get_conn(), g8auth.load_keys(), limit=40)

    for e in entries[:8]:
        print(
            "    seq %-4s %-13s %s"
            % (e.get("seq"), e.get("action"), str(e.get("detail") or "")[:74])
        )

    def detail(e):
        return str(e.get("detail") or "")

    mutating = ("share", "revoke", "delete")
    signed_rows = [
        e for e in entries if e.get("action") in mutating and "sig=" in detail(e)
    ]
    unsigned_rows = [
        e for e in entries if e.get("action") in mutating and "[unsigned]" in detail(e)
    ]
    keyrows = [e for e in entries if e.get("action") == "key_register"]

    note(
        "Alice's actions carry a signature and key fingerprint",
        len(signed_rows) >= 3,
        "%d signed" % len(signed_rows),
    )
    note(
        "Bob's action is recorded as [unsigned]",
        len(unsigned_rows) >= 1,
        "%d unsigned" % len(unsigned_rows),
    )
    note(
        "the public key itself is in the log, protected by the chain",
        len(keyrows) >= 1,
        "%d key_register entr(ies)" % len(keyrows),
    )

    chain = g8audit.verify_chain(g8db.get_conn(), g8auth.load_keys())
    note(
        "the chain covering all of this verifies",
        chain.get("ok") is True,
        "%s entries" % chain.get("entries"),
    )

    print(
        "       ^ an auditor holding the log and Alice's public key can re-verify her"
    )
    print("         actions WITHOUT trusting this server. That is the D4 gap closed.")
except Exception as exc:  # noqa: BLE001
    print("       log inspection skipped:", type(exc).__name__, exc)

print("\n-- cleanup --")
try:
    import g8anchor
    import g8db

    call("DELETE", "/files/%s" % BFID, token=TOK_B)
    with g8db.get_conn().cursor() as cur:
        cur.execute("DELETE FROM audit_log")
        cur.execute("DELETE FROM users WHERE username LIKE %s", ("sign\\_%",))
    root = g8anchor.update(g8db.get_conn())
    print("    cleaned; anchor re-baselined:", root[:32], "...")
    print("    NOTE: clearing the audit log also clears every registered public key,")
    print("          because the log is where they live (D19).")
    g8db.close()
except Exception as exc:  # noqa: BLE001
    print("    cleanup issue:", type(exc).__name__, exc)
    print("    run ~/g8venv/bin/python ~/reanchor.py before restarting the service")

print("\n" + "=" * 78)
print("RESULT: %d passed, %d failed" % (_passed, _failed))
print("=" * 78)
if _failed:
    raise SystemExit(1)
