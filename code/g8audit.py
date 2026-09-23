"""Encrypt audit payloads and authenticate their order with a keyed chain.

Each entry uses AES-GCM and an HMAC over its stored payload and previous hash.
Plain columns contain placeholders; row counts and arrival times still leak
activity. The caller manages the separate Key Vault anchor. Full chain checks,
anchor comparisons, and optional user signatures have distinct security roles.
"""

import base64
import hashlib
import hmac
import json
import threading
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

NONCE_LEN = 12
GENESIS = b"\x00" * 32
AAD = b"g8:audit-entry:v1"

# Placeholders written into the columns we deliberately do not use. The real values live
# inside the ciphertext.
CONST_TS = "2000-01-01T00:00:00+00:00"
CONST_ACTION = "e"

# Postgres advisory-lock id, so two concurrent appends cannot both read the same head and
# fork the chain. The in-process lock below is not enough on its own: uvicorn runs sync
# endpoints in a thread pool, and a horizontally scaled deployment would have several
# processes. The advisory lock is held for the transaction and released automatically.
_LOCK_ID = 0x6738_4155_4449_5401
_local_lock = threading.Lock()

# sequence numbers of entries that would not decrypt.
#
# An entry that fails its AEAD check was written under a different key or was altered in
# the untrusted database. Neither is routine, and this is the one place in the running
# system where the FIRST step of the H14 attack chain becomes visible to a human: corrupt
# a key_register entry, and the owner's signing requirement silently disappears. It used
# to be reported as a cosmetic {"error": ...} field inside one API response and nothing
# else. It is now remembered, counted and surfaced in /healthz.
UNDECRYPTABLE_SEQS = set()

# Pages pulled per round trip when filtering by user.
_PAGE = 500


class AuditError(Exception):
    """An audit record cannot be authenticated or a required write fails."""

    pass


# --------------------------------------------------------------------------------------
# Writing
# --------------------------------------------------------------------------------------


def _seal(entry: dict, enc_key: bytes) -> bytes:
    pt = json.dumps(entry, separators=(",", ":"), sort_keys=True).encode()
    nonce = __import__("os").urandom(NONCE_LEN)
    return nonce + AESGCM(enc_key).encrypt(nonce, pt, AAD)


def _open(blob: bytes, enc_key: bytes) -> dict:
    try:
        pt = AESGCM(enc_key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], AAD)
    except InvalidTag:
        raise AuditError("audit entry failed its AEAD check - tampered or wrong key")
    return json.loads(pt)


def _link(prev_hash: bytes, payload: bytes, mac_key: bytes) -> bytes:
    return hmac.new(mac_key, bytes(prev_hash) + payload, hashlib.sha256).digest()


def append(
    conn, keys: dict, action: str, user_id=None, file_id=None, detail=None
) -> int:
    """Encrypt an audit entry and append it under chain-head locks.

    Args:
        conn: PostgreSQL connection.
        keys: Mapping containing audit_enc and audit_hmac.
        action: Event name placed inside the encrypted payload.
        user_id: Optional actor identifier.
        file_id: Optional subject identifier.
        detail: Optional event detail; minimize sensitive content.

    Returns:
        The new sequence number. The caller must manage the separate state anchor.
    """
    entry = {
        "a": action,
        "u": str(user_id) if user_id else None,
        "f": str(file_id) if file_id else None,
        "d": detail,
        "t": time.time(),
    }
    payload = _seal(entry, keys["audit_enc"])
    stored = base64.b64encode(payload).decode("ascii")

    with _local_lock:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (_LOCK_ID,))
                cur.execute(
                    "SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
                )
                row = cur.fetchone()
                prev = bytes(row["entry_hash"]) if row else GENESIS

                entry_hash = _link(prev, payload, keys["audit_hmac"])

                cur.execute(
                    "INSERT INTO audit_log "
                    "(ts, user_id, action, file_id, detail, prev_hash, entry_hash) "
                    "VALUES (%s, NULL, %s, NULL, %s, %s, %s) RETURNING seq",
                    (CONST_TS, CONST_ACTION, stored, prev, entry_hash),
                )
                return cur.fetchone()["seq"]


# actions whose whole point is accountability. A logging failure on one of these is
# not a nuisance to print -- it is the record of a security-relevant act going missing.
MUST_LOG = (
    "share",
    "revoke",
    "delete",
    "key_register",
    "acl_mac_failure",
    "key_binding_failure",
)

# Count of entries that could not be written, for /healthz. A silent counter nobody reads
# is the situation this replaces.
WRITE_FAILURES = []


def safe_append(conn, keys: dict, action: str, **kw) -> None:
    """Append an event and apply the action-specific failure policy.

    Failures are recorded for health diagnostics. The underlying mutation may
    already have committed, so callers must distinguish action and audit outcomes.

    Args:
        conn: PostgreSQL connection used for the audit transaction.
        keys: Mapping containing audit_enc and audit_hmac.
        action: Event name; membership in MUST_LOG controls failure handling.
        **kw: Optional actor, file, and detail arguments forwarded to append().

    Raises:
        AuditError: A write for an action in MUST_LOG failed. Other failures are
            recorded and suppressed.
    """
    try:
        append(conn, keys, action, **kw)
    except Exception as exc:  # noqa: BLE001
        WRITE_FAILURES.append({"action": action, "error": type(exc).__name__})
        del WRITE_FAILURES[:-50]
        print("[audit] WARNING: failed to record %r: %s" % (action, exc))
        if action in MUST_LOG:
            raise AuditError(
                "the audit entry for %r could not be written (%s). The action itself has "
                "already committed; it is the RECORD that is missing."
                % (action, type(exc).__name__)
            )


# --------------------------------------------------------------------------------------
# Verifying
# --------------------------------------------------------------------------------------


def verify_chain(conn, keys: dict) -> dict:
    """Verify stored links and payload HMACs from genesis.

    Args:
        conn: PostgreSQL connection used to read the ordered audit records.
        keys: Mapping containing audit_hmac.

    Returns:
        A result dictionary identifying the first broken link or the final head.
        A valid prefix alone cannot prove that later entries were not removed.
    """
    with conn.cursor() as cur:
        cur.execute(
            "SELECT seq, detail, prev_hash, entry_hash FROM audit_log ORDER BY seq"
        )
        rows = cur.fetchall()

    prev = GENESIS
    for r in rows:
        try:
            payload = base64.b64decode(r["detail"])
        except Exception:  # noqa: BLE001
            return {
                "ok": False,
                "entries": len(rows),
                "broken_at": r["seq"],
                "reason": "payload is not valid base64",
            }

        if bytes(r["prev_hash"]) != prev:
            return {
                "ok": False,
                "entries": len(rows),
                "broken_at": r["seq"],
                "reason": "prev_hash does not match the previous entry's hash "
                "(an entry was inserted, removed, or reordered)",
            }

        expected = _link(prev, payload, keys["audit_hmac"])
        if not hmac.compare_digest(expected, bytes(r["entry_hash"])):
            return {
                "ok": False,
                "entries": len(rows),
                "broken_at": r["seq"],
                "reason": "entry_hash is wrong: this entry's contents were altered, "
                "or it was forged without the TEE-held audit key",
            }

        prev = bytes(r["entry_hash"])

    return {
        "ok": True,
        "entries": len(rows),
        "head": prev.hex() if rows else None,
        "note": "chain intact; the D3 anchor separately covers truncation of the "
        "whole log, which a chain alone cannot detect",
    }


# --------------------------------------------------------------------------------------
# Reading
# --------------------------------------------------------------------------------------


def read(conn, keys: dict, user_id=None, limit: int = 100):
    """Decrypt entries newest first, optionally filtering by actor.

    Reading does not replace full chain verification. Undecryptable rows
    are included as error records and remembered for health diagnostics.

    Args:
        conn: PostgreSQL connection.
        keys: Mapping containing the audit encryption key.
        user_id: Optional actor identifier to select after decryption.
        limit: Requested entry count, clamped to at least one.

    Returns:
        A list of decrypted entries and undecryptable-row error records.
    """
    limit = max(int(limit), 1)
    out = []
    offset = 0
    exhausted = False

    while len(out) < limit and not exhausted:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT seq, detail FROM audit_log ORDER BY seq DESC "
                "LIMIT %s OFFSET %s",
                (_PAGE, offset),
            )
            rows = cur.fetchall()

        if len(rows) < _PAGE:
            exhausted = True
        offset += len(rows)

        for r in rows:
            try:
                e = _open(base64.b64decode(r["detail"]), keys["audit_enc"])
            except Exception:  # noqa: BLE001
                # remember it, so /healthz can report it long after this call.
                UNDECRYPTABLE_SEQS.add(r["seq"])
                out.append({"seq": r["seq"], "error": "undecryptable entry"})
                if len(out) >= limit:
                    break
                continue
            if user_id and e.get("u") != str(user_id):
                continue
            out.append(
                {
                    "seq": r["seq"],
                    "action": e.get("a"),
                    "user_id": e.get("u"),
                    "file_id": e.get("f"),
                    "detail": e.get("d"),
                    "at": e.get("t"),
                }
            )
            if len(out) >= limit:
                break

        if not rows:
            break

    return out


# --------------------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    import g8auth
    import g8db

    print("=" * 78)
    print("g8audit self-test - encrypted, keyed, hash-chained audit log (D14)")
    print("=" * 78)

    conn = g8db.get_conn()
    keys = g8auth.load_keys()

    print("\n[1] append five entries")
    for i in range(5):
        append(conn, keys, "selftest", detail="entry number %d" % i)
    print("    appended")

    print("\n[2] verify the chain")
    print("   ", verify_chain(conn, keys))

    print("\n[3] what the DATABASE OPERATOR sees (raw columns)")
    with conn.cursor() as cur:
        cur.execute(
            "SELECT seq, ts, user_id, action, file_id, left(detail, 44) AS d "
            "FROM audit_log ORDER BY seq DESC LIMIT 3"
        )
        for r in cur.fetchall():
            print(
                "    seq=%s ts=%s user=%s action=%s file=%s detail=%s..."
                % (r["seq"], r["ts"], r["user_id"], r["action"], r["file_id"], r["d"])
            )
    print(
        "    ^ no actor, no action, no subject, no real timestamp. Just opaque blobs."
    )

    print("\n[4] what the TEE sees (decrypted in memory)")
    for e in read(conn, keys, limit=3):
        print("   ", e)

    print("\n[5] *** ATTACK *** edit one entry's payload directly in the database")
    with conn.cursor() as cur:
        cur.execute("SELECT seq, detail FROM audit_log ORDER BY seq LIMIT 1")
        first = cur.fetchone()
        tampered = base64.b64encode(
            bytes([base64.b64decode(first["detail"])[0] ^ 0x01])
            + base64.b64decode(first["detail"])[1:]
        ).decode()
        cur.execute(
            "UPDATE audit_log SET detail = %s WHERE seq = %s", (tampered, first["seq"])
        )
    print("    flipped one bit in entry seq=%s" % first["seq"])

    print("\n[6] verify again - should DETECT and LOCATE the edit")
    result = verify_chain(conn, keys)
    print("   ", result)
    print(
        "    ->",
        (
            "PASS (detected at seq %s)" % result.get("broken_at")
            if not result["ok"]
            else "FAIL (missed it!)"
        ),
    )

    print("\n[7] cleanup")
    with conn.cursor() as cur:
        cur.execute("DELETE FROM audit_log")
    import g8anchor

    g8anchor.update(conn)
    print("    log cleared, anchor re-synced")

    g8db.close()
    print("\nSELF-TEST COMPLETE")
