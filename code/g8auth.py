"""Derive application subkeys, hash passwords, and authenticate sessions.

Passwords are pre-hashed with HMAC-SHA256 under a service-held pepper before
Argon2id. Session tokens use a fixed HMAC construction. Revocation is process-local
and does not survive restart. Cloud access occurs when load_keys() is called.
"""

import base64
import hashlib
import hmac
import json
import os
import time

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

import boot  # get_service_root() / derive()

# --------------------------------------------------------------------------------------
# Key material — derived at boot, held in memory only
# --------------------------------------------------------------------------------------

INFO_USER_KEK_WRAP = b"g8:userkek-wrap:v1"
INFO_PEPPER = b"g8:pepper:v1"
INFO_SESSION_HMAC = b"g8:session-hmac:v1"
INFO_ACL_MAC = b"g8:acl-mac:v1"  # integrity of permission rows
INFO_AUDIT_HMAC = b"g8:audit-hmac:v1"  # keyed audit chain
INFO_AUDIT_ENC = b"g8:audit-enc:v1"  # audit entries are encrypted

# Adding sub-keys is free and safe because HKDF is domain-separated: each `info` string
# yields an independent key, and learning one reveals nothing about the others. That is
# why the hierarchy can grow without re-keying anything that already exists — the files
# encrypted yesterday are unaffected by the keys added today.


def load_keys():
    """Load the service root through SKR and derive application subkeys.

    Returns:
        A mapping of six purpose names to raw 32-byte keys.

    This calls the external bootstrap path; it is not a pure derivation helper.
    """
    root = boot.get_service_root()
    return {
        "user_kek_wrap": boot.derive(root, INFO_USER_KEK_WRAP),
        "pepper": boot.derive(root, INFO_PEPPER),
        "session_hmac": boot.derive(root, INFO_SESSION_HMAC),
        "acl_mac": boot.derive(root, INFO_ACL_MAC),
        "audit_hmac": boot.derive(root, INFO_AUDIT_HMAC),
        "audit_enc": boot.derive(root, INFO_AUDIT_ENC),
    }


# Argon2id uses 64 MiB, three passes, and two lanes per password operation.
_PH = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def pre_hash(password: str, pepper: bytes) -> str:
    """Combine a password with a secret pepper before Argon2id hashing.

    Args:
        password: User-supplied password, encoded as UTF-8.
        pepper: Secret HMAC key derived from the service root.

    Returns:
        Base64 HMAC-SHA256 output. Offline password checking requires the pepper
        as well as the stored Argon2id hash.
    """
    mac = hmac.new(pepper, password.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(mac).decode("ascii")


def hash_password(password: str, pepper: bytes) -> str:
    """Return the encoded Argon2id hash to store in the (untrusted) database.

    Args:
        password: Plaintext password encoded as UTF-8 before pre-hashing.
        pepper: Service-derived secret HMAC key.
    """
    return _PH.hash(pre_hash(password, pepper))


def verify_password(stored_hash: str, password: str, pepper: bytes) -> bool:
    """Check a peppered password against its stored Argon2id hash.

    Args:
        stored_hash: Encoded Argon2id hash from the account record.
        password: Candidate plaintext password.
        pepper: Service-derived secret used when the hash was created.

    Returns:
        False for a password mismatch or an invalid stored hash.
    """
    try:
        _PH.verify(stored_hash, pre_hash(password, pepper))
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Check whether the stored hash uses different Argon2 parameters.

    Returns:
        Whether the current hasher requests replacement; False on parsing errors.
        This does not mean the previous parameters were necessarily weaker.
    """
    try:
        return _PH.check_needs_rehash(stored_hash)
    except Exception:  # noqa: BLE001
        return False


# --------------------------------------------------------------------------------------
# Session tokens:  payload . HMAC-SHA256(session_hmac, payload)
# --------------------------------------------------------------------------------------

SESSION_TTL_SECONDS = (
    30 * 60
)  # short-lived; mitigates the "stolen session" threat (AS1)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(txt: str) -> bytes:
    return base64.urlsafe_b64decode(txt + "=" * (-len(txt) % 4))


def _new_jti() -> str:
    """A short random identifier for one session token."""
    return base64.urlsafe_b64encode(os.urandom(9)).decode("ascii").rstrip("=")


def issue_session(
    user_id: str, session_key: bytes, ttl: int = SESSION_TTL_SECONDS
) -> str:
    """Issue a fixed-format HMAC-authenticated session token.

    Args:
        user_id: Subject account identifier.
        session_key: Service-derived HMAC key.
        ttl: Token lifetime in seconds.

    Returns:
        A bearer token containing the subject, expiry, and random token ID.
    """
    # a per-token id, so a token can be revoked before it expires. Without it, signing
    # out was purely cosmetic -- the client dropped the token and the server kept honouring
    # it for the rest of its 30 minutes.
    payload = {"uid": user_id, "exp": int(time.time()) + ttl, "jti": _new_jti()}
    body = _b64u(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode())
    sig = hmac.new(session_key, body.encode("ascii"), hashlib.sha256).digest()
    return body + "." + _b64u(sig)


def verify_session(token: str, session_key: bytes):
    """Check a session's HMAC, expiry, and process-local revocation state.

    This does not check whether the account still exists; the API performs
    that database lookup separately.

    Args:
        token: Encoded bearer token supplied by the caller.
        session_key: Service-derived HMAC key.

    Returns:
        The subject identifier on success, or None on a handled rejection.
    """
    try:
        body, sig_b64 = token.split(".", 1)
    except ValueError:
        return None

    expected = hmac.new(session_key, body.encode("ascii"), hashlib.sha256).digest()
    try:
        provided = _b64u_decode(sig_b64)
    except Exception:
        return None
    if not hmac.compare_digest(expected, provided):
        return None

    try:
        payload = json.loads(_b64u_decode(body))
    except Exception:
        return None

    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    if payload.get("jti") and payload["jti"] in _revoked:
        return None
    return payload.get("uid")


# Revocations are process-local. A revoked token can become valid again after
# restart until its original expiry.
_revoked = {}  # jti -> unix time after which it can be forgotten


def revoke_session(token: str, session_key: bytes) -> bool:
    """Remember a valid token's revocation in this process.

    Args:
        token: Bearer token to authenticate and revoke.
        session_key: Service-derived HMAC key used to verify the token.

    Returns:
        True when a token ID was added; False for an invalid or legacy token.

    The revocation set is lost on restart, before the token necessarily expires.
    """
    now = time.time()
    for j in [j for j, exp in _revoked.items() if exp < now]:
        del _revoked[j]

    try:
        body, _sig = token.split(".", 1)
        payload = json.loads(_b64u_decode(body))
    except Exception:  # noqa: BLE001
        return False
    if not verify_session(token, session_key):
        return False
    jti = payload.get("jti")
    if not jti:
        return False  # issued before M11; nothing to revoke by
    _revoked[jti] = int(payload.get("exp", now))
    return True


# --------------------------------------------------------------------------------------
# Self-test — demonstrates the T10 property without touching the database
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    import os

    print("=" * 70)
    print("g8auth self-test  (Argon2id + TEE-held pepper, HMAC session tokens)")
    print("=" * 70)

    keys = load_keys()
    pepper = keys["pepper"]
    skey = keys["session_hmac"]
    print("[keys] derived from attested Service_Root:", ", ".join(sorted(keys)))
    print("[keys] pepper fingerprint:", hashlib.sha256(pepper).hexdigest()[:16], "...")

    pw = "correct horse battery staple"
    stored = hash_password(pw, pepper)
    print("\n[hash] stored form (this is ALL the database holds):")
    print("      ", stored[:78])

    ok = verify_password(stored, pw, pepper)
    print(
        "\n[T1] correct password + correct pepper ->",
        "PASS" if ok else "FAIL",
        "(expect PASS)",
    )

    bad = verify_password(stored, "wrong password", pepper)
    print(
        "[T2] wrong   password + correct pepper ->",
        "PASS" if not bad else "FAIL",
        "(expect reject)",
    )

    # THE KEY DEMONSTRATION (test T10): an attacker who has stolen the whole database has
    # the stored hash and can guess the password perfectly -- but without the TEE-held
    # pepper they still cannot verify it.
    fake_pepper = os.urandom(32)
    stolen = verify_password(stored, pw, fake_pepper)
    print(
        "[T10] CORRECT password + WRONG pepper  ->",
        "PASS" if not stolen else "FAIL",
        "(expect reject)",
    )
    print(
        "      ^ this is the offline-cracking defence: a stolen DB is useless without"
    )
    print("        the pepper, which never leaves TDX memory.")

    print("\n[session] issuing and verifying a token...")
    tok = issue_session("user-123", skey)
    print("      token:", tok[:60], "...")
    print(
        "[T3] valid token verifies       ->",
        "PASS" if verify_session(tok, skey) == "user-123" else "FAIL",
        "(expect PASS)",
    )

    tampered = tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB")
    print(
        "[T4] tampered signature rejected->",
        "PASS" if verify_session(tampered, skey) is None else "FAIL",
        "(expect reject)",
    )

    expired = issue_session("user-123", skey, ttl=-1)
    print(
        "[T5] expired token rejected     ->",
        "PASS" if verify_session(expired, skey) is None else "FAIL",
        "(expect reject)",
    )

    wrong_key = verify_session(tok, os.urandom(32))
    print(
        "[T6] token under wrong key      ->",
        "PASS" if wrong_key is None else "FAIL",
        "(expect reject)",
    )

    print("\nSELF-TEST COMPLETE")
