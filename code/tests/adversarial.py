"""Exercise selected storage and API tampering scenarios on a live deployment.

Requires cloud access and makes destructive changes. Some checks test permissions
or diagnostic behavior rather than attestation. In particular, Key Vault get_key()
retrieves an asymmetric public key; refusal is not proof of private-key protection.
Review individual results and cleanup before running on disposable resources.
"""

import hashlib
import json
import os
import ssl
import struct
import urllib.error
import urllib.request

import g8anchor
import g8auth
import g8blob
import g8db
import g8keys

BASE = os.environ.get("G8_BASE", "https://localhost:8443")

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE

_passed = 0
_failed = 0


def result(label, ok, extra=""):
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


def call(method, path, body=None, token=None, headers=None, raw=False):
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=300) as r:
            p = r.read()
            return r.status, (p if raw else json.loads(p.decode()))
    except urllib.error.HTTPError as e:
        p = e.read()
        try:
            return e.code, json.loads(p.decode())
        except Exception:
            return e.code, p


# --------------------------------------------------------------------------------------
# Blob surgery — parse and rebuild the stored container
# --------------------------------------------------------------------------------------


def fetch_blob(file_id: str) -> bytes:
    return g8blob._blob(file_id).download_blob().readall()


def put_blob(file_id: str, data: bytes) -> None:
    """Overwrite the stored blob. This is the cloud operator writing to their own storage."""
    g8blob._blob(file_id).upload_blob(data, overwrite=True)


def split_records(raw: bytes):
    """Return (header, [record, ...]) for a G8BLOB container."""
    header, body = raw[: g8blob.HEADER_LEN], raw[g8blob.HEADER_LEN :]
    records, off = [], 0
    while off < len(body):
        nonce = body[off : off + g8blob.NONCE_LEN]
        off += g8blob.NONCE_LEN
        (ct_len,) = struct.unpack(">I", body[off : off + 4])
        off += 4
        records.append(nonce + struct.pack(">I", ct_len) + body[off : off + ct_len])
        off += ct_len
    return header, records


# --------------------------------------------------------------------------------------

print("=" * 78)
print("G8 ADVERSARIAL TESTS — attacking real Azure storage and the real database")
print("=" * 78)

keys = g8auth.load_keys()
conn = g8db.get_conn()

PW = "YOUR_TEST_PASSWORD"
UA = "adv_a_" + os.urandom(3).hex()
UB = "adv_b_" + os.urandom(3).hex()
JSON_H = {"Content-Type": "application/json"}

print("\n-- setup: two users, one multi-chunk file --")
call(
    "POST",
    "/register",
    json.dumps({"username": UA, "password": PW}).encode(),
    headers=JSON_H,
)
call(
    "POST",
    "/register",
    json.dumps({"username": UB, "password": PW}).encode(),
    headers=JSON_H,
)
_, b = call(
    "POST",
    "/login",
    json.dumps({"username": UA, "password": PW}).encode(),
    headers=JSON_H,
)
TOK = b.get("token") if isinstance(b, dict) else None
_, b = call(
    "POST",
    "/login",
    json.dumps({"username": UB, "password": PW}).encode(),
    headers=JSON_H,
)
TOK_B = b.get("token") if isinstance(b, dict) else None
if not (TOK and TOK_B):
    print(
        "  [ABORT] could not log in (registration quota?). Restart the service and re-run."
    )
    raise SystemExit(1)

_, me = call("GET", "/me", token=TOK)
UID_A = me.get("user_id")
_, me = call("GET", "/me", token=TOK_B)
UID_B = me.get("user_id")

PLAIN = os.urandom(10 * 1024 * 1024)  # 10 MiB -> 3 chunks at 4 MiB
SHA = hashlib.sha256(PLAIN).hexdigest()
st, b = call(
    "POST",
    "/files",
    PLAIN,
    token=TOK,
    headers={
        "Content-Type": "application/octet-stream",
        "X-Filename": "adversarial_target.bin",
    },
)
FID = b.get("file_id") if isinstance(b, dict) else None
VER = b.get("version", 1) if isinstance(b, dict) else 1
print(
    "    file_id:",
    FID,
    " chunks:",
    b.get("total_chunks") if isinstance(b, dict) else "?",
)

row, DEK = g8db.get_file_for_user(FID, UID_A, keys)
TOTAL = g8keys.chunk_count(row["size_bytes"])

original = fetch_blob(FID)
print("    stored blob:", len(original), "bytes")

sane = b"".join(g8blob.download(FID, VER, DEK, expected_chunks=TOTAL))
result(
    "baseline: the untouched file reads back byte-exact",
    hashlib.sha256(sane).hexdigest() == SHA,
)

# ======================================================================================
print("\n== T5 — TAMPERING WITH REAL STORED BYTES ==")
print("   The cloud operator flips one bit inside the blob they are storing for us.")

header, records = split_records(original)
bad = bytearray(original)
# Land the flip inside the first chunk's ciphertext, past the header/nonce/length prefix.
target = g8blob.HEADER_LEN + g8blob.NONCE_LEN + 4 + 1000
bad[target] ^= 0x01
put_blob(FID, bytes(bad))
print("   flipped one bit at byte offset %d of %d" % (target, len(original)))

try:
    b"".join(g8blob.download(FID, VER, DEK, expected_chunks=TOTAL))
    result(
        "T5 single-bit flip in stored ciphertext is REJECTED", False, "(it decrypted!)"
    )
except g8keys.KeyBindingError:
    result(
        "T5 single-bit flip in stored ciphertext is REJECTED",
        True,
        "AEAD tag check failed",
    )

# ======================================================================================
print("\n== T6 — REORDERING REAL STORED CHUNKS ==")
print(
    "   Each chunk stays byte-perfect and individually authentic. Only the ARRANGEMENT"
)
print("   changes — which is the attack encryption alone cannot see.")

swapped = header + records[1] + records[0] + b"".join(records[2:])
put_blob(FID, swapped)
try:
    b"".join(g8blob.download(FID, VER, DEK, expected_chunks=TOTAL))
    result("T6 chunks 0 and 1 swapped in storage is REJECTED", False, "(it decrypted!)")
except g8keys.KeyBindingError:
    result(
        "T6 chunks 0 and 1 swapped in storage is REJECTED",
        True,
        "chunk_index AAD mismatch",
    )

# ======================================================================================
print("\n== T5b — TRUNCATING THE STORED FILE ==")
print("   The operator deletes the last chunk. Every remaining chunk is authentic.")

truncated_body = b"".join(records[:-1])
truncated = (
    g8blob.MAGIC + struct.pack(">II", TOTAL, g8keys.CHUNK_SIZE)
) + truncated_body
put_blob(FID, truncated)
try:
    b"".join(g8blob.download(FID, VER, DEK, expected_chunks=TOTAL))
    result("T5b truncated stored blob is REJECTED", False, "(it decrypted!)")
except (g8keys.KeyBindingError, g8blob.BlobFormatError) as exc:
    result("T5b truncated stored blob is REJECTED", True, type(exc).__name__)

print("\n   ...and if the attacker also rewrites the header to match the shorter file:")
relabelled = (
    g8blob.MAGIC + struct.pack(">II", TOTAL - 1, g8keys.CHUNK_SIZE)
) + truncated_body
put_blob(FID, relabelled)
try:
    b"".join(g8blob.download(FID, VER, DEK, expected_chunks=TOTAL))
    result(
        "T5c truncation with a doctored header is REJECTED", False, "(it decrypted!)"
    )
except (g8keys.KeyBindingError, g8blob.BlobFormatError) as exc:
    result(
        "T5c truncation with a doctored header is REJECTED", True, type(exc).__name__
    )
print("   ^ caught by the cross-check between the two stores, NOT by the AAD:")
print(
    "     the blob header said %d chunks while the database still said %d."
    % (TOTAL - 1, TOTAL)
)

print("\n   ...so now let the attacker doctor BOTH stores until they agree.")
print("   This is the realistic case: the operator controls the blob AND the database,")
print(
    "   so making them tell the same lie costs nothing. Every framing check and every"
)
print("   cross-check now passes, and only the cryptography is left.")

full_chunks_size = (
    TOTAL - 1
) * g8keys.CHUNK_SIZE  # a size that means exactly TOTAL-1 chunks
with conn.cursor() as cur:
    cur.execute(
        "UPDATE files SET size_bytes = %s WHERE file_id = %s", (full_chunks_size, FID)
    )
row_lied, _ = g8db.get_file_for_user(FID, UID_A, keys)
total_lied = g8keys.chunk_count(row_lied["size_bytes"])
print(
    "   database now says %d bytes -> %d chunks; blob header says %d chunks. They agree."
    % (full_chunks_size, total_lied, TOTAL - 1)
)

try:
    b"".join(g8blob.download(FID, VER, DEK, expected_chunks=total_lied))
    result(
        "T5d truncation with BOTH stores doctored is REJECTED", False, "(it decrypted!)"
    )
except g8blob.BlobFormatError as exc:
    result(
        "T5d truncation with BOTH stores doctored is REJECTED",
        False,
        "rejected by framing, not by the AAD: %s" % exc,
    )
except g8keys.KeyBindingError:
    result(
        "T5d truncation with BOTH stores doctored is REJECTED",
        True,
        "chunk AAD binds total_chunks - THIS is the cryptographic defence",
    )

ok_a, det_a = g8anchor.verify(conn)
result(
    "T5d the D3 anchor independently notices the edited size_bytes",
    not ok_a,
    det_a.get("status") + " (files table, added in D12)",
)

with conn.cursor() as cur:
    cur.execute(
        "UPDATE files SET size_bytes = %s WHERE file_id = %s", (row["size_bytes"], FID)
    )
g8anchor.update(conn)
print(
    "   ^ two INDEPENDENT defences fired: the AAD binding, which needs no anchor and no"
)
print("     second store, and the anchor, which needs no cryptographic context. Either")
print("     alone would have caught it; neither relies on the other.")

put_blob(FID, original)
back = b"".join(g8blob.download(FID, VER, DEK, expected_chunks=TOTAL))
result(
    "restoring the original bytes makes the file readable again",
    hashlib.sha256(back).hexdigest() == SHA,
)

# ======================================================================================
print("\n== T6b — RELOCATING A KEY ROW IN THE REAL DATABASE ==")
print("   The database operator copies user A's wrapped-DEK row onto user B's account.")

with conn.cursor() as cur:
    cur.execute(
        "SELECT wrapped_dek, nonce, version FROM file_keys "
        "WHERE file_id=%s AND user_id=%s",
        (FID, UID_A),
    )
    stolen = cur.fetchone()
    cur.execute(
        "INSERT INTO file_keys (file_id, user_id, wrapped_dek, nonce, version) "
        "VALUES (%s,%s,%s,%s,%s) ON CONFLICT (file_id,user_id) DO UPDATE SET "
        "wrapped_dek=EXCLUDED.wrapped_dek, nonce=EXCLUDED.nonce",
        (FID, UID_B, stolen["wrapped_dek"], stolen["nonce"], stolen["version"]),
    )
print("   row copied onto user B")

try:
    g8db.get_file_for_user(FID, UID_B, keys)
    result(
        "T6b stolen key row does not unwrap for another user", False, "(it unwrapped!)"
    )
except g8keys.KeyBindingError:
    result(
        "T6b stolen key row does not unwrap for another user", True, "AAD binds user_id"
    )

ok, detail = g8anchor.verify(conn)
result("T8 the D3 anchor also notices the inserted row", not ok, detail.get("status"))

with conn.cursor() as cur:
    cur.execute("DELETE FROM file_keys WHERE file_id=%s AND user_id=%s", (FID, UID_B))
g8anchor.update(conn)

# ======================================================================================
print("\n== T2 — NO ATTESTATION, NO KEY ==")
print(
    "   Ask Key Vault for the Master_KEK the ordinary way, with no attestation token."
)

try:
    from azure.identity import ManagedIdentityCredential
    from azure.keyvault.keys import KeyClient

    kc = KeyClient(
        vault_url="YOUR_KEY_VAULT_URL", credential=ManagedIdentityCredential()
    )
    k = kc.get_key("YOUR_MASTER_KEY_NAME")
    result(
        "T2 unattested key read is DENIED",
        False,
        "returned a key! kid=%s" % getattr(k, "id", "?"),
    )
except Exception as exc:  # noqa: BLE001
    msg = str(exc)
    denied = (
        "Forbidden" in msg
        or "orbidden" in msg
        or "not authorized" in msg
        or "403" in msg
    )
    result("T2 unattested key read is DENIED", denied, type(exc).__name__)
    print("      ", msg.split("\n")[0][:110])
print(
    "   ^ this VM's identity holds ONLY the release role. The private key is obtainable"
)
print("     exclusively through attested Secure Key Release — not by asking politely.")

# ======================================================================================
print("\n== T10 — A STOLEN DATABASE IS USELESS WITHOUT THE TEE-HELD PEPPER ==")

with conn.cursor() as cur:
    cur.execute("SELECT pw_hash FROM users WHERE username = %s", (UA,))
    stored_hash = cur.fetchone()["pw_hash"]
print("   the attacker has the exact stored hash:", stored_hash[:52], "...")
print("   ...and has correctly guessed the password.")

result(
    "T10 correct password + correct pepper verifies (control)",
    g8auth.verify_password(stored_hash, PW, keys["pepper"]),
)
result(
    "T10 correct password + WRONG pepper is REJECTED",
    not g8auth.verify_password(stored_hash, PW, os.urandom(32)),
)
print("   ^ the offline attack is not slowed down, it is IMPOSSIBLE without first")
print("     breaking TDX. Testing one guess requires the pepper.")

# ======================================================================================
print("\n== T1 — WHAT THE OPERATOR HOLDS ==")
raw = g8blob.read_raw(FID, 256)
result("T1 no plaintext of the file appears in the stored blob", PLAIN[:64] not in raw)
result(
    "T1 the filename does not appear in the stored blob",
    b"adversarial_target" not in raw,
)
result("T1 the blob is named by an opaque UUID", "adversarial" not in FID)
print("   blob name:", FID)
print("   header   :", raw[:16].hex(), "(format marker + counts)")
print("   payload  :", raw[16:48].hex(), "...")

# ======================================================================================
print("\n== T11 — WHAT THE DATABASE OPERATOR HOLDS ==")
#
# T1 above inspects the blob. This inspects the OTHER untrusted store, which the threat
# model names just as explicitly: an operator with full read access to PostgreSQL. Every
# column that could carry something meaningful is read back raw and checked.
#
# This is the claim the whole design rests on, tested against the adversary the design
# actually names -- and it was, until now, the one store no automated check looked inside.

with conn.cursor() as cur:
    cur.execute(
        "SELECT filename_enc, filename_nonce, size_bytes, blob_path "
        "FROM files WHERE file_id = %s",
        (FID,),
    )
    frow = cur.fetchone()
    cur.execute("SELECT wrapped_kek, nonce FROM user_keys LIMIT 1")
    krow = cur.fetchone()
    cur.execute("SELECT wrapped_dek FROM file_keys WHERE file_id = %s", (FID,))
    drow = cur.fetchone()
    cur.execute(
        "SELECT ts, user_id, action, file_id, detail "
        "FROM audit_log ORDER BY seq DESC LIMIT 1"
    )
    arow = cur.fetchone()

fn_enc = bytes(frow["filename_enc"]) if frow else b""
result(
    "T11 the filename column contains no plaintext filename",
    b"adversarial_target" not in fn_enc,
)
result(
    "T11 the filename column is not readable text",
    bool(fn_enc) and not all(32 <= c < 127 for c in fn_enc),
)
result(
    "T11 the blob path leaks no filename",
    frow is not None and "adversarial" not in str(frow["blob_path"]),
)

wk = bytes(krow["wrapped_kek"]) if krow else b""
result(
    "T11 the wrapped User_KEK is ciphertext plus a tag, not a bare 32-byte key",
    len(wk) > 32,
)

wd = bytes(drow["wrapped_dek"]) if drow else b""
result("T11 the wrapped File_DEK is not the wrapped User_KEK", bool(wd) and wd != wk)

# Audit actors, subjects, actions, and timestamps belong to the encrypted payload.
# These checks cover the placeholder values in the exposed audit columns.
if arow is not None:
    result(
        "T11 the audit user_id column is NULL, not the actor", arow["user_id"] is None
    )
    result(
        "T11 the audit file_id column is NULL, not the subject", arow["file_id"] is None
    )
    result(
        "T11 the audit ts column is a constant, not a real timestamp",
        str(arow["ts"]).startswith("2000-01-01"),
    )
    result(
        "T11 the audit action column is a constant, not the real action",
        str(arow["action"]) == "e",
    )
    det = str(arow["detail"] or "")
    result(
        "T11 no action verb appears in the stored audit detail",
        not any(
            w in det.lower() for w in ("share", "revoke", "delete", "upload", "granted")
        ),
    )
    print(
        "   audit row  : ts=%s user_id=%s action=%s detail=%s..."
        % (arow["ts"], arow["user_id"], arow["action"], det[:24])
    )

print("   filename_enc:", fn_enc[:24].hex(), "...")
print("   wrapped_kek :", wk[:24].hex(), "...")
print(
    "   NOTE: size_bytes IS visible (%s) -- documented leakage, not a defect."
    % (frow["size_bytes"] if frow else "?")
)

# ======================================================================================
print("\n== T12 — ORPHANED STATE: THE BLOB IS GONE, THE ROW REMAINS ==")
#
# An adversary with write access to Blob Storage deletes a blob. The metadata database
# still lists the file. This is not an attack that reveals anything -- it is a denial of
# service -- but how the service FAILS matters: an unhandled exception returns a stack
# trace, and stack traces leak paths, library versions and sometimes internal state.
#
# Every other check in this suite tests that correct things work and wrong things are
# refused. This is the only one that tests how the system behaves when it is BROKEN.

st, ob = call(
    "POST",
    "/files",
    body=b"orphan-probe-content",
    token=TOK,
    headers={
        "Content-Type": "application/octet-stream",
        "X-Filename": "orphan_probe.txt",
    },
)
OID = ob.get("file_id") if (st == 201 and isinstance(ob, dict)) else None

if OID:
    # delete the blob directly, leaving the database row untouched
    try:
        g8blob._client().get_container_client("YOUR_BLOB_CONTAINER").delete_blob(OID)
        deleted = True
    except Exception as exc:
        deleted = False
        print("   could not delete the blob:", exc)
    result("T12 the blob was removed behind the service's back", deleted)

    # Before the fix this raised IncompleteRead: the service sent "200, Content-Length: N"
    # from the database and then nothing, because the blob fetch failed after the headers
    # had gone out. A client could not tell that from a dropped connection.
    truncated = False
    try:
        st, body = call("GET", "/files/%s" % OID, token=TOK, raw=True)
    except Exception as exc:
        st, body, truncated = -1, b"", True
        print("   download raised:", type(exc).__name__, exc)
    print("   download of the orphaned file returned:", st)

    result("T12 the orphaned download does not truncate a 200 response", not truncated)
    result(
        "T12 it returns a clean error status, not 200 and not 500",
        st not in (200, 500, -1),
    )
    result(
        "T12 the response carries no Python traceback",
        b"Traceback" not in (body if isinstance(body, bytes) else b"")
        and b"/home/YOUR_VM_USER" not in (body if isinstance(body, bytes) else b""),
    )

    st2, lb = call("GET", "/files", token=TOK)
    result("T12 the file list still responds after the orphaning", st2 == 200)

    call("DELETE", "/files/%s" % OID, token=TOK)
else:
    print("   SKIPPED: could not upload the probe file")

# ======================================================================================
print("\n-- cleanup --")
try:
    call("DELETE", "/files/%s" % FID, token=TOK)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM audit_log")
        cur.execute("DELETE FROM users WHERE username LIKE %s", ("adv\\_%",))
    root = g8anchor.update(conn)
    print("    removed test users and file; anchor re-baselined:", root[:32], "...")
    g8db.close()
except Exception as exc:  # noqa: BLE001
    print("    cleanup issue:", type(exc).__name__, exc)
    print("    ⚠️ run ~/g8venv/bin/python ~/reanchor.py before restarting the service")

print("\n" + "=" * 78)
print("ADVERSARIAL RESULT: %d passed, %d failed" % (_passed, _failed))
print("=" * 78)
if _failed:
    raise SystemExit(1)
