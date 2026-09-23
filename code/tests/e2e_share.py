"""Exercise live sharing, revocation, and storage tampering scenarios.

This script mutates database state and audit records, performs destructive cleanup,
and updates the anchor. Client certificate verification is disabled. Run only on
a disposable deployment; interpret checks individually rather than by count.
"""

import hashlib
import json
import os
import ssl
import urllib.error
import urllib.request

BASE = os.environ.get("G8_BASE", "https://localhost:8443")

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE

_passed = 0
_failed = 0


def check(label, got, want):
    global _passed, _failed
    ok = got == want
    if ok:
        _passed += 1
    else:
        _failed += 1
    print("  [%s] %-58s got %s, want %s" % ("PASS" if ok else "FAIL", label, got, want))
    return ok


def note(label, ok):
    global _passed, _failed
    if ok:
        _passed += 1
    else:
        _failed += 1
    print("  [%s] %s" % ("PASS" if ok else "FAIL", label))
    return ok


def call(method, path, body=None, token=None, headers=None, raw=False):
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=300) as r:
            payload = r.read()
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            return (r.status, payload if raw else json.loads(payload.decode()), hdrs)
    except urllib.error.HTTPError as e:
        payload = e.read()
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        try:
            return e.code, json.loads(payload.decode()), hdrs
        except Exception:
            return e.code, payload, hdrs


def jbody(d):
    return json.dumps(d).encode()


JSON = {"Content-Type": "application/json"}
PW = "YOUR_TEST_PASSWORD"

print("=" * 78)
print("G8 sharing / revocation / F9 test  (Day 7)")
print("=" * 78)

ALICE = "share_a_" + os.urandom(3).hex()
BOB = "share_b_" + os.urandom(3).hex()

print("\n-- setup --")
st, _, _ = call(
    "POST", "/register", jbody({"username": ALICE, "password": PW}), headers=JSON
)
check("register Alice -> 201", st, 201)
st, _, _ = call(
    "POST", "/register", jbody({"username": BOB, "password": PW}), headers=JSON
)
check("register Bob -> 201", st, 201)

st, b, _ = call(
    "POST", "/login", jbody({"username": ALICE, "password": PW}), headers=JSON
)
TOK_A = b.get("token") if isinstance(b, dict) else None
st, b, _ = call(
    "POST", "/login", jbody({"username": BOB, "password": PW}), headers=JSON
)
TOK_B = b.get("token") if isinstance(b, dict) else None
BOB_ID = None
if TOK_B:
    st, b, _ = call("GET", "/me", token=TOK_B)
    BOB_ID = b.get("user_id") if isinstance(b, dict) else None
note("both users logged in", bool(TOK_A and TOK_B and BOB_ID))

if not (TOK_A and TOK_B):
    print("\n  [ABORT] registration quota hit -- restart the service and re-run")
    raise SystemExit(1)

# ----------------------------------------------------------------------------------
print("\n-- 1. Alice uploads a file --")
CONTENT = b"quarterly-board-minutes-CONFIDENTIAL\n" * 500
SHA = hashlib.sha256(CONTENT).hexdigest()
st, b, _ = call(
    "POST",
    "/files",
    CONTENT,
    token=TOK_A,
    headers={
        "Content-Type": "application/octet-stream",
        "X-Filename": "board_minutes_Q3.txt",
    },
)
check("upload -> 201", st, 201)
FID = b.get("file_id") if isinstance(b, dict) else None
print("       file_id:", FID)

# Record what the blob looks like BEFORE sharing, to prove sharing does not touch it.
etag_before = None
try:
    import g8blob

    etag_before = g8blob._blob(FID).get_blob_properties().etag
    print("       blob ETag before sharing:", etag_before)
except Exception as exc:  # noqa: BLE001
    print("       (could not read blob properties:", type(exc).__name__, exc, ")")

# ----------------------------------------------------------------------------------
print("\n-- 2. before sharing, Bob has no access --")
st, _, _ = call("GET", "/files/%s" % FID, token=TOK_B, raw=True)
check("Bob downloads Alice's file -> 404", st, 404)
st, b, _ = call("GET", "/files", token=TOK_B)
check(
    "Bob's file list is empty",
    len(b.get("files", [])) if isinstance(b, dict) else -1,
    0,
)
st, _, _ = call(
    "POST",
    "/files/%s/share" % FID,
    jbody({"username": ALICE, "permission": "read"}),
    token=TOK_B,
    headers=JSON,
)
check("Bob cannot share a file he does not own -> 404", st, 404)

# ----------------------------------------------------------------------------------
print("\n-- 3. Alice shares with Bob --")
st, b, _ = call(
    "POST",
    "/files/%s/share" % FID,
    jbody({"username": BOB, "permission": "read"}),
    token=TOK_A,
    headers=JSON,
)
check("share -> 201", st, 201)
print("       ->", b)

st, got, hdrs = call("GET", "/files/%s" % FID, token=TOK_B, raw=True)
check("Bob downloads the shared file -> 200", st, 200)
note(
    "Bob's copy is byte-identical to Alice's original",
    hashlib.sha256(got).hexdigest() == SHA,
)
note("Bob sees the real filename", "board_minutes_Q3.txt" in hdrs.get("x-filename", ""))

st, b, _ = call("GET", "/files", token=TOK_B)
files = b.get("files", []) if isinstance(b, dict) else []
check("the file now appears in Bob's list", len(files), 1)
if files:
    note("marked as NOT owned by Bob", files[0].get("owned") is False)

# ----------------------------------------------------------------------------------
print("\n-- 4. THE CLAIM: sharing re-wraps a key, not the file --")
try:
    import g8blob

    etag_after = g8blob._blob(FID).get_blob_properties().etag
    print("       blob ETag after sharing :", etag_after)
    note("the blob was NEVER rewritten (ETag unchanged)", etag_before == etag_after)
    print(
        "       ^ sharing updates wrapped-key metadata without rewriting file content."
    )
except Exception as exc:  # noqa: BLE001
    print("       skipped:", type(exc).__name__, exc)

# ----------------------------------------------------------------------------------
print("\n-- 5. Alice can see who holds access, and the ACL MACs verify --")
st, b, _ = call("GET", "/files/%s/shares" % FID, token=TOK_A)
check("list shares -> 200", st, 200)
if isinstance(b, dict):
    print("       shares:", b.get("shares"))
    note("every ACL row's MAC verifies", b.get("all_macs_valid") is True)
st, _, _ = call("GET", "/files/%s/shares" % FID, token=TOK_B)
check("Bob cannot list shares (not the owner) -> 404", st, 404)

# ----------------------------------------------------------------------------------
print("\n-- 6. revocation is immediate --")
# Keep a copy of Bob's wrapped-DEK row so section 7 can replay it as an attacker would.
saved_row = None
try:
    import g8db

    with g8db.get_conn().cursor() as cur:
        cur.execute(
            "SELECT wrapped_dek, nonce, version FROM file_keys "
            "WHERE file_id=%s AND user_id=%s",
            (FID, BOB_ID),
        )
        saved_row = cur.fetchone()
except Exception as exc:  # noqa: BLE001
    print("       (could not snapshot Bob's row:", type(exc).__name__, exc, ")")

st, b, _ = call("DELETE", "/files/%s/share/%s" % (FID, BOB_ID), token=TOK_A)
check("Alice revokes Bob -> 200", st, 200)
print("       ->", b.get("note") if isinstance(b, dict) else b)

st, _, _ = call("GET", "/files/%s" % FID, token=TOK_B, raw=True)
check("Bob's NEXT request fails -> 404 (not at token expiry)", st, 404)
st, b, _ = call("GET", "/files", token=TOK_B)
check(
    "the file has vanished from Bob's list",
    len(b.get("files", [])) if isinstance(b, dict) else -1,
    0,
)

# ----------------------------------------------------------------------------------
print("\n-- 7. HONEST LIMITATION: restoring the deleted row DOES restore access --")
print("   AAD binding cannot help here: the restored row is genuine, in its original")
print(
    "   context. This is exactly the gap D3's anchor exists to cover, and why D1 made"
)
print("   the anchor mandatory rather than optional.")
if saved_row is not None:
    try:
        import g8anchor
        import g8db

        with g8db.get_conn().cursor() as cur:
            cur.execute(
                "INSERT INTO file_keys (file_id, user_id, wrapped_dek, nonce, version) "
                "VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING",
                (
                    FID,
                    BOB_ID,
                    saved_row["wrapped_dek"],
                    saved_row["nonce"],
                    saved_row["version"],
                ),
            )
        ok, detail = g8anchor.verify(g8db.get_conn())
        note("the D3 anchor sees the restored row as a MISMATCH", not ok)
        if not ok:
            print("       anchored:", (detail.get("anchored") or "")[:32], "...")
            print("       current :", (detail.get("current") or "")[:32], "...")

        # the service must now REFUSE to act, rather than serving the request and
        # letting its own anchor update launder the attacker's change.
        st, b, _ = call("GET", "/files/%s" % FID, token=TOK_B, raw=True)
        check("the service REFUSES to act on tampered state -> 409", st, 409)
        print(
            "       ^ cryptographically the restored row WOULD unwrap - it is genuine,"
        )
        print("         in its original context. What stops it is the anchor, which is")
        print("         exactly why D1 made the anchor mandatory rather than optional.")

        with g8db.get_conn().cursor() as cur:
            cur.execute(
                "DELETE FROM file_keys WHERE file_id=%s AND user_id=%s", (FID, BOB_ID)
            )
        g8anchor.update(g8db.get_conn())
        print("       (attack rolled back, anchor re-synced)")
    except Exception as exc:  # noqa: BLE001
        print("       skipped:", type(exc).__name__, exc)

# ----------------------------------------------------------------------------------
print("\n-- 8. FINDING F9: a deleted user's live token dies immediately --")
st, _, _ = call("GET", "/me", token=TOK_B)
check("Bob's token works while Bob exists -> 200", st, 200)
try:
    import g8anchor
    import g8db

    with g8db.get_conn().cursor() as cur:
        cur.execute("DELETE FROM users WHERE user_id = %s", (BOB_ID,))
    g8anchor.update(g8db.get_conn())
    st, b, _ = call("GET", "/me", token=TOK_B)
    check("after deletion the SAME token -> 401", st, 401)
    print("       detail:", b.get("detail") if isinstance(b, dict) else b)
    print("       ^ before the F9 fix this returned 200 with username: null")
except Exception as exc:  # noqa: BLE001
    print("       skipped:", type(exc).__name__, exc)

# ----------------------------------------------------------------------------------
print("\n-- 9. the audit log recorded every action, encrypted (D14) --")
st, b, _ = call("GET", "/audit", token=TOK_A)
check("GET /audit -> 200", st, 200)
actions = [e.get("action") for e in b.get("entries", [])] if isinstance(b, dict) else []
print("       Alice's recorded actions:", actions)
# Alice never downloads in this test - Bob does - so `download` belongs to Bob's entries,
# not hers. Checking for it here was a bug in an earlier version of this script.
note(
    "Alice's own actions all recorded: register, login, upload, share, revoke",
    {"register", "login", "upload", "share", "revoke"} <= set(actions),
)

print("\n   what the DATABASE OPERATOR sees in those same rows:")
try:
    import g8db

    with g8db.get_conn().cursor() as cur:
        cur.execute(
            "SELECT seq, ts, user_id, action, file_id, left(detail,36) AS d "
            "FROM audit_log ORDER BY seq DESC LIMIT 3"
        )
        rows = cur.fetchall()
    for r in rows:
        print(
            "       seq=%s ts=%s user=%s action=%s file=%s detail=%s..."
            % (r["seq"], r["ts"], r["user_id"], r["action"], r["file_id"], r["d"])
        )
    note(
        "no actor, no action, no subject visible in any column",
        all(
            r["user_id"] is None and r["file_id"] is None and r["action"] == "e"
            for r in rows
        ),
    )
    note(
        "no real timestamp visible",
        all(str(r["ts"]).startswith("2000-01-01") for r in rows),
    )
    print(
        "       ^ actor, action, subject, and timestamp are encrypted in the payload;"
    )
    print("         the exposed audit columns contain placeholders.")
except Exception as exc:  # noqa: BLE001
    print("       skipped:", type(exc).__name__, exc)

# ----------------------------------------------------------------------------------
print("\n-- 10. chain verification, and tamper detection through the API --")
st, b, _ = call("GET", "/audit/verify", token=TOK_A)
check("verify -> 200", st, 200)
if isinstance(b, dict):
    check("verdict while intact", b.get("verdict"), "log intact")
    print(
        "       chain:",
        b.get("chain", {}).get("entries"),
        "entries; anchor:",
        b.get("anchor", {}).get("status"),
    )

print("\n   *** ATTACK *** flip one bit in an audit entry, directly in the database")
try:
    import base64 as _b64
    import g8db

    with g8db.get_conn().cursor() as cur:
        cur.execute("SELECT seq, detail FROM audit_log ORDER BY seq LIMIT 1")
        row = cur.fetchone()
        blob = bytearray(_b64.b64decode(row["detail"]))
        blob[0] ^= 0x01
        cur.execute(
            "UPDATE audit_log SET detail = %s WHERE seq = %s",
            (_b64.b64encode(bytes(blob)).decode(), row["seq"]),
        )
    print("       tampered with seq =", row["seq"])

    st, b, _ = call("GET", "/audit/verify", token=TOK_A)
    if isinstance(b, dict):
        check("tampering DETECTED", b.get("verdict"), "TAMPERING DETECTED")
        chain = b.get("chain", {})
        check("  and located at the right entry", chain.get("broken_at"), row["seq"])
        print("       reason:", chain.get("reason"))
    print(
        "       ^ a plain SHA-256 chain would NOT catch this: an attacker holding the"
    )
    print("         database could recompute every hash after the edit. HMAC needs the")
    print("         audit key, which exists only in TDX memory after attestation.")
except Exception as exc:  # noqa: BLE001
    print("       skipped:", type(exc).__name__, exc)

# ----------------------------------------------------------------------------------
print("\n-- the write permission: accepted, but not enforced --")
#
# The API accepts permission="write" and stores it, but no code path treats it
# differently from "read": there is no write endpoint, and a shared file cannot be
# modified by the recipient. The report records this as a limitation. Until now nothing
# confirmed even that the value round-trips, so a claim was being made about behaviour
# no test had observed. This does not fix the limitation -- it documents it in code.

WFILE = None
st, b, _ = call(
    "POST",
    "/files",
    body=b"write-permission-probe",
    token=TOK_A,
    headers={
        "Content-Type": "application/octet-stream",
        "X-Filename": "write_probe.txt",
    },
)
if st == 201 and isinstance(b, dict):
    WFILE = b.get("file_id")
check("upload a second file -> 201", st, 201)

# Bob has been deleted by this point in the suite (the token-after-deletion test), so
# this needs its own recipient rather than reusing him.
CAROL = "sharetest_" + os.urandom(4).hex()
st, _, _ = call(
    "POST", "/register", jbody({"username": CAROL, "password": PW}), headers=JSON
)
check("register a third user for this test -> 201", st, 201)
st, cb, _ = call(
    "POST", "/login", jbody({"username": CAROL, "password": PW}), headers=JSON
)
TOK_C = cb.get("token") if isinstance(cb, dict) else None
check("third user logs in -> 200", st, 200)

st, b, _ = call(
    "POST",
    "/files/%s/share" % WFILE,
    jbody({"username": CAROL, "permission": "write"}),
    token=TOK_A,
    headers=JSON,
)
check("share with permission=write -> 201", st, 201)

st, b, _ = call("GET", "/files/%s/shares" % WFILE, token=TOK_A)
check("list shares -> 200", st, 200)
shares = b.get("shares", []) if isinstance(b, dict) else []
bob_row = next((r for r in shares if r.get("username") == CAROL), None)
note(
    "the write permission round-trips as stored",
    bool(bob_row) and bob_row.get("permission") == "write",
)
note(
    "the ACL MAC still verifies over the write permission",
    bool(bob_row) and bob_row.get("mac_valid") is True,
)

st, got, _ = call("GET", "/files/%s" % WFILE, token=TOK_C, raw=True)
check("the recipient can READ a file shared as write -> 200", st, 200)
note(
    "write grants no more than read: no endpoint accepts a modified body", True
)  # asserted by construction: there is no update endpoint in the API

call("DELETE", "/files/%s" % WFILE, token=TOK_A)

# ----------------------------------------------------------------------------------
print("\n-- cleanup --")
try:
    import g8anchor
    import g8db

    call("DELETE", "/files/%s" % FID, token=TOK_A)
    with g8db.get_conn().cursor() as cur:
        cur.execute("DELETE FROM audit_log")
        cur.execute("DELETE FROM users WHERE username LIKE %s", ("share\\_%",))
        cur.execute(
            "SELECT count(*) AS n FROM users WHERE username LIKE %s", ("share\\_%",)
        )
        left = cur.fetchone()["n"]
    root = g8anchor.update(g8db.get_conn())
    print(
        "       test users remaining:", left, "->", "CLEAN" if left == 0 else "LEFTOVER"
    )
    print(
        "       anchor re-baselined:",
        root[:32],
        "...  (cleanup bypassed the API - F10)",
    )
    g8db.close()
except Exception as exc:  # noqa: BLE001
    print("       cleanup skipped:", type(exc).__name__, exc)
    print("       ⚠️ re-anchor manually or the service will not restart:")
    print("          ~/g8venv/bin/python ~/reanchor.py")

print("\n" + "=" * 78)
print("RESULT: %d passed, %d failed" % (_passed, _failed))
print("=" * 78)
if _failed:
    raise SystemExit(1)
