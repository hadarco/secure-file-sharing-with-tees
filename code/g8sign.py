"""Verify optional browser signatures on share, revoke, and delete requests.

P-256 public keys are enrolled through audit records and cached in process memory.
Statements bind operation context, permission, time, and nonce. The nonce cache
resets on restart. Attribution depends on trusted enrollment and browser code;
these signatures do not independently establish a person's identity.
"""

import base64
import hashlib
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.serialization import load_der_public_key

SKEW_SECONDS = 120  # how stale a signed statement may be
FUTURE_SKEW_SECONDS = 5  # tolerance for client clock drift AHEAD of ours
NONCE_CACHE_MAX = 20000  # bounded, so a flood cannot exhaust memory

SIGNED_ACTIONS = ("share", "revoke", "delete")

# user_id -> public key bytes (SPKI DER). Rebuilt from the audit log at startup.
_pubkeys = {}

# An unavailable key registry is different from an account without an enrolled
# key. The API rejects signable actions while registry state is degraded.
REGISTRY_DEGRADED = False
REGISTRY_ERROR = None

# Remember spent nonces per user until their freshness window expires. At the
# cache limit reject requests rather than discard unexpired replay history.
# The cache is process-local and resets on restart.
_seen_nonces = {}  # (user_id, nonce) -> unix time after which it may be forgotten


class SignatureError(Exception):
    """A signing key, signature, or statement context is unacceptable."""


# --------------------------------------------------------------------------------------
# Canonical statement
# --------------------------------------------------------------------------------------


def canonical(
    action: str,
    user_id: str,
    file_id: str,
    target: str,
    ts: int,
    nonce: str,
    permission: str = "",
) -> bytes:
    """Encode the exact context that a signed action must authenticate.

    Returns:
        Sorted, compact JSON encoded as UTF-8, with Python's default ASCII
        escaping. Browser encoding differs for non-ASCII string values.
    """
    return json.dumps(
        {
            "act": action,
            "by": str(user_id),
            "fid": str(file_id),
            # the permission being granted is part of what the user authorised.
            # Without it, a signed "share file F with Bob" could be applied by the server as a
            # WRITE grant when the user asked for read, and the signature would still verify --
            # so the log would carry cryptographic proof of an action the user did not take.
            # Empty for revoke and delete, which grant nothing.
            "p": str(permission or ""),
            "to": str(target or ""),
            "ts": int(ts),
            "n": str(nonce),
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


# --------------------------------------------------------------------------------------
# Key registry
# --------------------------------------------------------------------------------------


def register_key(user_id: str, spki_b64: str) -> str:
    """Validate a P-256 SPKI public key and activate it in memory.

    Args:
        user_id: Account identifier to bind to the key.
        spki_b64: Base64-encoded DER SubjectPublicKeyInfo.

    Returns:
        The public-key fingerprint. The caller separately persists enrollment.

    Raises:
        SignatureError: The encoding, key type, or curve is unacceptable.
    """
    try:
        raw = base64.b64decode(spki_b64)
        pub = load_der_public_key(raw)
    except Exception as exc:  # noqa: BLE001
        raise SignatureError(
            "public key is not valid SPKI DER: %s" % type(exc).__name__
        )

    if not isinstance(pub, ec.EllipticCurvePublicKey):
        raise SignatureError("public key is not an elliptic-curve key")
    if pub.curve.name != "secp256r1":
        raise SignatureError("expected P-256, got %s" % pub.curve.name)

    _pubkeys[str(user_id)] = raw
    return hashlib.sha256(raw).hexdigest()[:16]


def _expire_nonces() -> int:
    """Forget nonces that are already outside the freshness window. Returns how many.

    Safe by construction: a statement older than SKEW_SECONDS is rejected by the timestamp
    check before its nonce is ever consulted, so remembering it buys nothing. Expiring by
    age keeps the cache bounded WITHOUT the size-triggered `.clear()` that made replay
    possible.
    """
    now = time.time()
    stale = [k for k, exp in _seen_nonces.items() if exp < now]
    for k in stale:
        del _seen_nonces[k]
    return len(stale)


def has_key(user_id: str) -> bool:
    """Check enrollment in the process-local signing-key registry."""
    return str(user_id) in _pubkeys


def fingerprint(user_id: str, short: bool = False):
    """Hash an enrolled SPKI public key for identification.

    Args:
        user_id: Account whose enrolled SPKI key should be hashed.
        short: Use a display-only 16-hex-character prefix when True.

    Returns:
        The full SHA-256 hex digest, a display-only prefix when short is True,
        or None if the account has no enrolled key.
    """
    raw = _pubkeys.get(str(user_id))
    if not raw:
        return None
    digest = hashlib.sha256(raw).hexdigest()
    return digest[:16] if short else digest


def load_registry(conn, keys: dict) -> int:
    """Rebuild the signing-key cache from encrypted audit entries.

    Args:
        conn: PostgreSQL connection.
        keys: Mapping containing the audit encryption key.

    Returns:
        Number of loaded account keys. Undecryptable or malformed entries mark
        the registry degraded, causing the API to reject signable actions.

    Entries are scanned newest first. Deleting the audit log also deletes key
    enrollment history. The caller separately verifies the full audit chain.
    """
    global REGISTRY_DEGRADED, REGISTRY_ERROR
    import g8audit

    _pubkeys.clear()
    REGISTRY_DEGRADED = False
    REGISTRY_ERROR = None

    loaded = 0
    undecryptable = []
    malformed = []

    # this decrypted EVERY audit row at every startup, so boot time grew with the log
    # and never came back down. Two cheap changes: read newest-first so the most recent
    # registration for a user wins naturally, and stop as soon as every account has been
    # accounted for. A deployment where most users hold keys now stops early; one where
    # they do not is no worse than before.
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM users")
        total_users = cur.fetchone()["n"]
        cur.execute("SELECT seq, detail FROM audit_log ORDER BY seq DESC")
        rows = cur.fetchall()

    for r in rows:
        try:
            e = g8audit._open(base64.b64decode(r["detail"]), keys["audit_enc"])
        except Exception:  # noqa: BLE001
            # Cannot tell what this entry was. It may have been a key registration.
            undecryptable.append(r["seq"])
            continue
        if e.get("a") != "key_register":
            continue
        if str(e.get("u")) in _pubkeys:
            continue  # newest-first: a later registration already won
        try:
            register_key(e.get("u"), e.get("d"))
            loaded += 1
            if loaded >= total_users:
                break  # every account has a key; nothing older can matter
        except SignatureError as exc:
            # A key that parsed at registration but not now means the stored bytes changed.
            malformed.append((r["seq"], str(exc)[:60]))

    if undecryptable or malformed:
        REGISTRY_DEGRADED = True
        REGISTRY_ERROR = (
            "%d audit entr(ies) would not decrypt (seq %s); %d registered key(s) no longer "
            "parse (%s). An entry that changed needs investigation. The anchor comparison "
            "alone does not authenticate every payload. "
            "Run /audit/verify to locate the first broken link."
            % (len(undecryptable), undecryptable[:10], len(malformed), malformed[:5])
        )
        print("[sign] *** REGISTRY DEGRADED ***", REGISTRY_ERROR)

    return loaded


# --------------------------------------------------------------------------------------
# Verification
# --------------------------------------------------------------------------------------


def verify(
    action: str,
    user_id: str,
    file_id: str,
    target: str,
    statement_b64: str,
    signature_b64: str,
    permission: str = "",
) -> dict:
    """Authenticate an action statement against the expected request context.

    Successful verification consumes its nonce in the process-local replay
    cache. Attribution assumes a trustworthy enrolled key and browser client.

    Args:
        action: Expected operation name.
        user_id: Authenticated caller whose enrolled key must verify.
        file_id: File identifier named by the actual request.
        target: Expected recipient name/identifier, or an empty string.
        statement_b64: Base64-encoded canonical JSON statement.
        signature_b64: Base64 raw 64-byte P-256 signature in r||s format.
        permission: Expected share permission, or an empty string.

    Returns:
        Verified context, key fingerprint, and the complete encoded
        statement and signature for audit persistence.

    Raises:
        SignatureError: Enrollment, context, freshness, nonce, canonical
            encoding, signature, or replay-cache capacity checks fail.
    """
    if str(user_id) not in _pubkeys:
        raise SignatureError("no public key registered for this user")

    try:
        stmt_bytes = base64.b64decode(statement_b64)
        stmt = json.loads(stmt_bytes)
    except Exception:  # noqa: BLE001
        raise SignatureError("statement is not valid base64 JSON")

    # --- the statement must describe THIS request -------------------------------------
    if stmt.get("act") != action:
        raise SignatureError(
            "statement action %r does not match this endpoint (%r)"
            % (stmt.get("act"), action)
        )
    if str(stmt.get("by")) != str(user_id):
        raise SignatureError("statement was signed by a different user")
    if str(stmt.get("fid")) != str(file_id):
        raise SignatureError("statement names a different file")
    if str(stmt.get("to") or "") != str(target or ""):
        raise SignatureError("statement names a different target")
    if str(stmt.get("p") or "") != str(permission or ""):
        raise SignatureError(
            "statement authorises permission %r, not %r" % (stmt.get("p"), permission)
        )

    # --- freshness and replay ---------------------------------------------------------
    try:
        ts = int(stmt.get("ts", 0))
    except (TypeError, ValueError):
        raise SignatureError("statement timestamp is malformed")
    # abs() accepted statements timestamped up to SKEW_SECONDS in the FUTURE, which
    # let a client pre-sign an action and hold it. Clocks do drift, so a small forward
    # tolerance stays; two minutes of it does not need to.
    drift = time.time() - ts
    if drift > SKEW_SECONDS:
        raise SignatureError(
            "statement is %d s out of date (limit %d s)" % (drift, SKEW_SECONDS)
        )
    if drift < -FUTURE_SKEW_SECONDS:
        raise SignatureError(
            "statement is dated %d s in the future (limit %d s)"
            % (-drift, FUTURE_SKEW_SECONDS)
        )

    nonce = str(stmt.get("n") or "")
    if not nonce:
        raise SignatureError("statement carries no nonce")

    # Drop only nonces that are already too old to be replayed anyway. This is what
    # makes a size-based flush unnecessary: the set can never grow beyond the number of
    # signatures issued within one SKEW_SECONDS window.
    _expire_nonces()
    if (str(user_id), nonce) in _seen_nonces:
        raise SignatureError("statement nonce has already been used (replay)")

    # --- re-derive the canonical bytes rather than trusting what was sent --------------
    # Signing whatever the client transmitted would let a client sign one thing and send
    # another with extra fields appended. Rebuilding from the validated values means the
    # signature is checked over exactly the semantics the server acted on.
    expected = canonical(action, user_id, file_id, target, ts, nonce, permission)
    if expected != stmt_bytes:
        raise SignatureError("statement is not in canonical form")

    # --- the signature itself ---------------------------------------------------------
    # WebCrypto emits ECDSA signatures as raw r||s; `cryptography` expects DER, so the two
    # halves are re-encoded. A mismatch here is the single most common integration bug in
    # browser-to-Python signing, and it fails as an ordinary InvalidSignature, which makes
    # it deceptively hard to diagnose.
    try:
        raw_sig = base64.b64decode(signature_b64)
    except Exception:  # noqa: BLE001
        raise SignatureError("signature is not valid base64")
    if len(raw_sig) != 64:
        raise SignatureError(
            "expected a 64-byte P-256 signature, got %d bytes" % len(raw_sig)
        )

    r = int.from_bytes(raw_sig[:32], "big")
    s = int.from_bytes(raw_sig[32:], "big")
    der = asym_utils.encode_dss_signature(r, s)

    pub = load_der_public_key(_pubkeys[str(user_id)])
    try:
        pub.verify(der, expected, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise SignatureError("signature does not verify against the registered key")

    # Spend the nonce only after everything else has passed, so a failed attempt cannot
    # burn a legitimate one. It is remembered until it falls outside the freshness window,
    # at which point the timestamp check alone is sufficient to reject it.
    if len(_seen_nonces) >= NONCE_CACHE_MAX:
        # A backstop, and note what it does NOT do: it does not clear the cache. Forgetting
        # what we have seen is the one response to overload that enables the attack this
        # bound exists to prevent. Refuse the request instead.
        raise SignatureError(
            "the server is rate limited on signed statements; retry shortly"
        )
    _seen_nonces[(str(user_id), nonce)] = ts + SKEW_SECONDS

    return {
        "verified": True,
        "action": action,
        "user_id": str(user_id),
        "file_id": str(file_id),
        "target": target or None,
        "ts": ts,
        "key_fingerprint": fingerprint(user_id),
        # the STATEMENT is returned, not just the signature.
        # A signature is meaningless without the exact bytes it was computed over, and those
        # bytes carry the timestamp and nonce, which are reconstructable from nothing else.
        # app.py writes both into the audit entry so the action can be re-verified later by
        # anyone holding the user's public key — which is the whole point of D19, and was
        # impossible while only a 24-character fragment was stored.
        "statement": statement_b64,
        "signature": signature_b64,
    }


# --------------------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    print("=" * 78)
    print("g8sign self-test - client-signed actions (D19)")
    print("=" * 78)

    priv = ec.generate_private_key(ec.SECP256R1())
    spki = priv.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )
    uid, fid = "user-aaaa", "file-bbbb"

    print("\n[1] register the public key")
    print("    fingerprint:", register_key(uid, base64.b64encode(spki).decode()))

    def sign(action, user, f, target, ts=None, nonce=None):
        ts = ts or int(time.time())
        nonce = nonce or os.urandom(8).hex()
        body = canonical(action, user, f, target, ts, nonce)
        der = priv.sign(body, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        raw = r.to_bytes(32, "big") + s.to_bytes(32, "big")
        return base64.b64encode(body).decode(), base64.b64encode(raw).decode()

    def check(label, fn, expect_ok=False):
        try:
            fn()
            ok = expect_ok
            out = "accepted"
        except SignatureError as exc:
            ok = not expect_ok
            out = "REJECTED (%s)" % str(exc)[:52]
        print("  [%s] %-46s -> %s" % ("PASS" if ok else "FAIL", label, out))

    print("\n-- happy path --")
    st, sg = sign("share", uid, fid, "bob")
    check(
        "a correctly signed share is accepted",
        lambda: verify("share", uid, fid, "bob", st, sg),
        expect_ok=True,
    )

    print("\n-- the server tries to fabricate or alter an action --")
    check(
        "the same statement replayed", lambda: verify("share", uid, fid, "bob", st, sg)
    )

    st2, sg2 = sign("share", uid, fid, "bob")
    check(
        "action changed to delete", lambda: verify("delete", uid, fid, "bob", st2, sg2)
    )
    check("file changed", lambda: verify("share", uid, "file-cccc", "bob", st2, sg2))
    check("recipient changed", lambda: verify("share", uid, fid, "mallory", st2, sg2))
    check(
        "attributed to another user",
        lambda: verify("share", "user-zzzz", fid, "bob", st2, sg2),
    )

    print("\n-- forgery and staleness --")
    forged = base64.b64encode(os.urandom(64)).decode()
    st3, _ = sign("revoke", uid, fid, "bob")
    check("a made-up signature", lambda: verify("revoke", uid, fid, "bob", st3, forged))

    st4, sg4 = sign("share", uid, fid, "bob", ts=int(time.time()) - 600)
    check(
        "a statement signed ten minutes ago",
        lambda: verify("share", uid, fid, "bob", st4, sg4),
    )

    other = ec.generate_private_key(ec.SECP256R1())
    ts, nonce = int(time.time()), os.urandom(8).hex()
    body = canonical("delete", uid, fid, "", ts, nonce)
    der = other.sign(body, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    check(
        "signed with a different key entirely",
        lambda: verify(
            "delete",
            uid,
            fid,
            "",
            base64.b64encode(body).decode(),
            base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode(),
        ),
    )

    print("\n[2] the point of all this")
    print("    These cases exercise rejection by the implemented signature verifier.")
    print("    Attribution still depends on trusted enrollment and browser code.")
    print("    They do not establish protection against a malicious application.")
    print("\nSELF-TEST COMPLETE")
