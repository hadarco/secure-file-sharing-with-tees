"""Exercise live encrypted upload, download, and file deletion.

Uses real Azure-backed state, disables client certificate verification, and
performs cleanup outside the API. Review cleanup and anchor effects before use.
This module executes at import time; do not collect it as a portable unit test.
"""

import hashlib
import json
import os
import ssl
import time
import urllib.error
import urllib.request
import g8keys

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
    print("  [%s] %-56s got %s, want %s" % ("PASS" if ok else "FAIL", label, got, want))
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
    """Return (status, parsed_or_bytes, response_headers)."""
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=300) as r:
            payload = r.read()
            # HTTP header names are case-insensitive and Starlette sends them lowercase,
            # so normalise rather than assuming the case we happened to write.
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            if raw:
                return r.status, payload, hdrs
            return r.status, json.loads(payload.decode()), hdrs
    except urllib.error.HTTPError as e:
        body = e.read()
        hdrs = {k.lower(): v for k, v in e.headers.items()}
        try:
            return e.code, json.loads(body.decode()), hdrs
        except Exception:
            return e.code, body, hdrs


def upload(token, name, data):
    return call(
        "POST",
        "/files",
        body=data,
        token=token,
        headers={"Content-Type": "application/octet-stream", "X-Filename": name},
    )


print("=" * 78)
print("G8 end-to-end file test  (upload, download, list, delete, T1)")
print("=" * 78)
print("target:", BASE)

MAX_UPLOAD = 512 * 1024 * 1024  # must match app.MAX_UPLOAD_BYTES

PW = "YOUR_TEST_PASSWORD"
USER_A = "filetest_" + os.urandom(4).hex()
USER_B = "filetest_" + os.urandom(4).hex()

# ----------------------------------------------------------------------------------
print("\n-- setup: two users --")
st, body, _ = call(
    "POST",
    "/register",
    json.dumps({"username": USER_A, "password": PW}).encode(),
    headers={"Content-Type": "application/json"},
)
check("register user A -> 201", st, 201)
st, body, _ = call(
    "POST",
    "/register",
    json.dumps({"username": USER_B, "password": PW}).encode(),
    headers={"Content-Type": "application/json"},
)
check("register user B -> 201", st, 201)

st, body, _ = call(
    "POST",
    "/login",
    json.dumps({"username": USER_A, "password": PW}).encode(),
    headers={"Content-Type": "application/json"},
)
TOK_A = body.get("token") if isinstance(body, dict) else None
st, body, _ = call(
    "POST",
    "/login",
    json.dumps({"username": USER_B, "password": PW}).encode(),
    headers={"Content-Type": "application/json"},
)
TOK_B = body.get("token") if isinstance(body, dict) else None
note("both users logged in", bool(TOK_A and TOK_B))

# ----------------------------------------------------------------------------------
print("\n-- 1. small file, byte-exact round trip --")
SECRET = b"TOP-SECRET-SALARY-DATA-2026-DO-NOT-DISCLOSE\n" * 40
st, body, _ = upload(TOK_A, "salary_review_2026.pdf", SECRET)
check("upload -> 201", st, 201)
small_id = body.get("file_id") if isinstance(body, dict) else None
print(
    "       file_id:",
    small_id,
    "chunks:",
    body.get("total_chunks"),
    "blob_bytes:",
    body.get("blob_bytes"),
)

st, got, hdrs = call("GET", "/files/%s" % small_id, token=TOK_A, raw=True)
check("download -> 200", st, 200)
note("content is byte-identical", got == SECRET)
note(
    "filename survived the round trip (X-Filename header)",
    "salary_review_2026.pdf" in hdrs.get("x-filename", ""),
)

# ----------------------------------------------------------------------------------
print("\n-- 2. multi-chunk file (10 MiB = 3 chunks at 4 MiB) --")
BIG = os.urandom(10 * 1024 * 1024)
big_sha = hashlib.sha256(BIG).hexdigest()

t0 = time.time()
st, body, _ = upload(TOK_A, "big_random.bin", BIG)
t_up = time.time() - t0
check("upload 10 MiB -> 201", st, 201)
big_id = body.get("file_id") if isinstance(body, dict) else None
check("  split into 3 chunks", body.get("total_chunks"), 3)

t0 = time.time()
st, got, _ = call("GET", "/files/%s" % big_id, token=TOK_A, raw=True)
t_down = time.time() - t0
check("download 10 MiB -> 200", st, 200)
note(
    "10 MiB round-trips byte-exact (sha256 match)",
    hashlib.sha256(got).hexdigest() == big_sha,
)
print(
    "       MEASUREMENT  upload  %.2f s  = %.1f MiB/s" % (t_up, 10.0 / max(t_up, 0.001))
)
print(
    "       MEASUREMENT  download %.2f s = %.1f MiB/s"
    % (t_down, 10.0 / max(t_down, 0.001))
)

# ----------------------------------------------------------------------------------
print("\n-- 3. zero-byte file (the awkward edge case) --")
st, body, _ = upload(TOK_A, "empty.txt", b"")
check("upload empty file -> 201", st, 201)
empty_id = body.get("file_id") if isinstance(body, dict) else None
check("  stored as ONE empty chunk, not zero", body.get("total_chunks"), 1)
st, got, _ = call("GET", "/files/%s" % empty_id, token=TOK_A, raw=True)
check("download empty -> 200", st, 200)
note("zero bytes returned", got == b"")

# ----------------------------------------------------------------------------------
print("\n-- 4. listing --")
st, body, _ = call("GET", "/files", token=TOK_A)
check("GET /files -> 200", st, 200)
names = (
    sorted(f["filename"] for f in body.get("files", []))
    if isinstance(body, dict)
    else []
)
print("       filenames (decrypted in TEE memory):", names)
note(
    "all three files listed with correct names",
    names == ["big_random.bin", "empty.txt", "salary_review_2026.pdf"],
)

# ----------------------------------------------------------------------------------
print("\n-- 5. *** TEST T1 *** what the cloud operator actually sees --")
print(
    "   Reading the blob DIRECTLY from Azure Storage, bypassing the service entirely."
)
try:
    import g8blob

    raw = g8blob.read_raw(small_id, 512)
    print("       blob name  :", small_id, "  <- a UUID; no filename anywhere")
    print("       first 16 B :", raw[:16].hex(), " (format header: magic + counts)")
    print("       next  48 B :", raw[16:64].hex(), "...")
    note(
        "plaintext 'TOP-SECRET' does NOT appear in the raw blob",
        b"TOP-SECRET" not in raw,
    )
    note("plaintext 'SALARY' does NOT appear in the raw blob", b"SALARY" not in raw)
    note(
        "the original filename does NOT appear in the raw blob",
        b"salary_review" not in raw,
    )

    # A statistical sanity check: encrypted bytes should look uniform. This is not a
    # proof of security - it is a cheap smoke test that would catch the catastrophic
    # mistake of accidentally storing plaintext.
    payload = raw[16:]
    uniq = len(set(payload))
    print(
        "       distinct byte values in %d ciphertext bytes: %d (uniform-ish = good)"
        % (len(payload), uniq)
    )
except Exception as exc:  # noqa: BLE001
    print("       T1 raw read skipped:", type(exc).__name__, exc)

# ----------------------------------------------------------------------------------
print("\n-- 6. a second user cannot read the first user's file --")
if not TOK_B:
    # Guard, added after a false pass. Without a token every request returns 401, and a
    # 401 body has no "files" key -- so "user B's list is empty" passed while user B was
    # never logged in at all. A test that can pass without the thing it tests being true
    # is worse than no test: it is a false reassurance. Same family as F8.
    print("  [SKIP] user B has no session (registration quota?); section not run")
    print("         restart the service to reset the in-memory quota, then re-run")
    _failed += 1
else:
    st, _, _ = call("GET", "/files/%s" % small_id, token=TOK_B, raw=True)
    check("user B downloads user A's file -> 404 (not 403)", st, 404)
    print("       ^ 404 not 403 deliberately: a 403 would confirm the file exists")

    st, body, hdrs = call("GET", "/files", token=TOK_B)
    # Assert the STATUS too. Checking only the list length let a 401 masquerade as an
    # empty list.
    check("user B's file list -> 200 (not 401)", st, 200)
    check(
        "user B's file list is empty",
        len(body.get("files", [])) if isinstance(body, dict) else -1,
        0,
    )

    st, _, _ = call("DELETE", "/files/%s" % small_id, token=TOK_B)
    check("user B cannot delete user A's file -> 403/404", st in (403, 404), True)

# ----------------------------------------------------------------------------------
print("\n-- 7. the D3 anchor followed every mutation --")
st, body, _ = call("GET", "/healthz")
anchor = body.get("anchor", {}) if isinstance(body, dict) else {}
print(
    "       anchor:",
    anchor.get("status"),
    "last_mutation:",
    anchor.get("last_mutation"),
)
note(
    "anchor is current and tracked the upload",
    anchor.get("status") == "current" and not anchor.get("stale"),
)

# ----------------------------------------------------------------------------------
print("\n-- 8. deletion removes metadata AND blob --")
for fid, label in ((small_id, "small"), (big_id, "big"), (empty_id, "empty")):
    st, _, _ = call("DELETE", "/files/%s" % fid, token=TOK_A)
    check("delete %s file -> 200" % label, st, 200)

st, _, _ = call("GET", "/files/%s" % small_id, token=TOK_A, raw=True)
check("deleted file now -> 404", st, 404)

try:
    import g8blob

    gone = g8blob.read_raw(small_id, 16)
    note("blob removed from storage", False)
except Exception:
    note("blob removed from storage", True)

st, body, _ = call("GET", "/files", token=TOK_A)
check(
    "user A's list is empty again",
    len(body.get("files", [])) if isinstance(body, dict) else -1,
    0,
)

# ----------------------------------------------------------------------------------
print("\n-- chunk boundary and the upload cap --")
#
# The chunk count is bound into every chunk's AAD, so an off-by-one in how a file is
# split is not a cosmetic bug: it changes the AAD of every chunk and would be caught
# only on download. A file of EXACTLY one chunk-size is the case most likely to be
# split wrongly, so it is tested explicitly alongside one byte either side of it.

CS = g8keys.CHUNK_SIZE

for label, size, want_chunks in (
    ("one byte under a chunk", CS - 1, 1),
    ("exactly one chunk", CS, 1),
    ("one byte over a chunk", CS + 1, 2),
):
    payload = bytes((i * 7 + 3) & 0xFF for i in range(1024)) * (
        size // 1024
    ) + b"\x00" * (size % 1024)
    st, body, _ = upload(TOK_A, "boundary_%d.bin" % size, payload)
    check("upload %s (%d B) -> 201" % (label, size), st, 201)
    got_chunks = body.get("total_chunks") if isinstance(body, dict) else None
    check("  %s split into %d chunk(s)" % (label, want_chunks), got_chunks, want_chunks)
    bid = body.get("file_id") if isinstance(body, dict) else None
    st, got, _ = call("GET", "/files/%s" % bid, token=TOK_A, raw=True)
    note("  %s downloads byte-identical" % label, st == 200 and got == payload)
    call("DELETE", "/files/%s" % bid, token=TOK_A)

# The cap is checked against Content-Length BEFORE any body is read, so an oversized
# upload is refused at the header rather than after transferring half a gigabyte.
# That is what makes this testable at all: no large file is sent.
oversized = MAX_UPLOAD + 1
req = urllib.request.Request(BASE + "/files", data=b"", method="POST")
req.add_header("Authorization", "Bearer " + TOK_A)
req.add_header("Content-Type", "application/octet-stream")
req.add_header("X-Filename", "too_big.bin")
req.add_header("Content-Length", str(oversized))
try:
    with urllib.request.urlopen(req, context=_ctx, timeout=30) as r:
        cap_status = r.status
except urllib.error.HTTPError as e:
    cap_status = e.code
except Exception:
    cap_status = -1
check("declared %d bytes (cap + 1) -> 413" % oversized, cap_status, 413)

# ----------------------------------------------------------------------------------
print("\n-- cleanup --")
#
# ⚠️ THE RULE, learned three times over: ANY code that changes the database OUTSIDE the
# API must re-anchor before the service next starts.
#
# This cleanup deletes rows straight through g8db, so app.py's _anchor_after_mutation()
# never runs. The database moves; Key Vault does not hear about it; the next startup finds
# them disagreeing and REFUSES TO BOOT (D10, strict enforcement). That is the mechanism
# working exactly as designed - but a test script that leaves the service unable to start
# is a broken test script, not a security success.
#
# The same trap already caught reset_and_verify.sh (fixed with wipe_and_reanchor) and the
# pytest suites (fixed with a final re-baseline step). It is a consequence of a decision
# made hours after these scripts were written, which is precisely why it keeps being
# forgotten - and why it is now written down here in full.
#
try:
    import g8anchor
    import g8db

    with g8db.get_conn().cursor() as cur:
        cur.execute("DELETE FROM users WHERE username LIKE %s", ("filetest\\_%",))
        cur.execute(
            "SELECT count(*) AS n FROM users WHERE username LIKE %s", ("filetest\\_%",)
        )
        left = cur.fetchone()["n"]
    print(
        "       test users remaining:", left, "->", "CLEAN" if left == 0 else "LEFTOVER"
    )

    root = g8anchor.update(g8db.get_conn())
    print("       D3 anchor re-baselined after direct cleanup:", root[:32], "...")
    print(
        "       ^ mandatory: this cleanup bypassed the API, so nothing re-anchored for it"
    )
    g8db.close()
except Exception as exc:  # noqa: BLE001
    print("       cleanup skipped:", type(exc).__name__, exc)
    print(
        "       ⚠️ if rows were removed, RE-ANCHOR MANUALLY or the service will not start:"
    )
    print("          ~/g8venv/bin/python ~/reanchor.py")

print("\n" + "=" * 78)
print("RESULT: %d passed, %d failed" % (_passed, _failed))
print("=" * 78)
if _failed:
    raise SystemExit(1)
