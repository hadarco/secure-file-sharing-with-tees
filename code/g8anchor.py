"""Compare selected database state with a digest stored in Key Vault.

The v3 digest covers ACLs, key-row identities, file metadata, user credentials,
and ordered stored audit hashes. Wrapped ciphertext is checked by AEAD when used;
audit payload integrity requires a separate chain verification. Updating an anchor
accepts current state as the new baseline. See docs/security-model.md before
using update() or interpreting a matching digest as a complete integrity check.
"""

import hashlib
import json

import os

import psycopg
from azure.core.exceptions import ResourceNotFoundError
from azure.identity import ManagedIdentityCredential
from azure.keyvault.secrets import SecretClient

# Override deployment placeholders through the documented environment settings.
VAULT_URL = os.environ.get("G8_VAULT_URL", "YOUR_KEY_VAULT_URL")
SECRET_NAME = os.environ.get("G8_ANCHOR_SECRET", "YOUR_ANCHOR_SECRET_NAME")

# v1 -> v2: the `files` table joined the covered set.
# v2 -> v3: user credentials, every audit entry_hash and creation timestamps
# joined it. Bumping the tag makes every root change, so a stale value from
#           an earlier version can never be mistaken for a current one.
DOMAIN_TAG = b"g8:state-anchor:v3"

_client = None


class AnchorMismatch(Exception):
    """The database no longer matches the anchored state: rows were deleted, or an older
    snapshot was restored. Treat as an attack indicator."""


def _secret_client() -> SecretClient:
    global _client
    if _client is None:
        _client = SecretClient(
            vault_url=VAULT_URL, credential=ManagedIdentityCredential()
        )
    return _client


# --------------------------------------------------------------------------------------
# Computing the state root
# --------------------------------------------------------------------------------------


def _feed(h, label: str, rows):
    """Absorb a labelled, ordered set of rows into the digest.

    The label and the row count are hashed as well as the contents, so that an empty table
    and a table whose rows were all deleted cannot collide, and so that rows cannot be
    moved between sections.
    """
    h.update(("|%s|%d|" % (label, len(rows))).encode())
    for row in rows:
        h.update(
            json.dumps(row, separators=(",", ":"), sort_keys=True, default=str).encode()
        )
        h.update(b"|")


def compute_state_root(conn) -> str:
    """Hash ordered selected database fields using the v3 format.

    Args:
        conn: PostgreSQL connection. If idle, the function opens a repeatable-read
            transaction; otherwise it uses the caller's current transaction.

    Returns:
        A hexadecimal SHA-256 digest. This does not verify audit payload HMACs
        or make subsequent reads and mutations part of the same snapshot.
    """
    h = hashlib.sha256()
    h.update(DOMAIN_TAG)

    # Are we opening this transaction, or joining one the caller already started?
    try:
        _own_transaction = (
            conn.info.transaction_status == psycopg.pq.TransactionStatus.IDLE
        )
    except Exception:  # noqa: BLE001
        _own_transaction = False  # unsure -> do not risk the SET

    with conn.transaction():
        with conn.cursor() as cur:
            # REPEATABLE READ must be the first statement of a transaction, so it can only
            # be set when we are the ones opening it. If a caller already has a transaction
            # in flight, psycopg's transaction() nests via SAVEPOINT and the SET would
            # error -- which in Postgres poisons the whole transaction. Checking first is
            # cheaper than recovering, and the reads are still consistent under the
            # caller's own snapshot.
            if _own_transaction:
                cur.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ")

            cur.execute(
                "SELECT file_id, user_id, permission, version, encode(mac,'hex') AS mac, "
                "       granted_at "
                "FROM acl ORDER BY file_id, user_id"
            )
            _feed(h, "acl", cur.fetchall())

            cur.execute(
                "SELECT file_id, user_id, version, created_at FROM file_keys "
                "ORDER BY file_id, user_id"
            )
            _feed(h, "file_keys", cur.fetchall())

            # --- files ------------------------------------------------------------
            # Everything that identifies the file and locates its ciphertext. blob_path is
            # included because repointing a file record at a different blob is a real
            # attack: the chunk AAD binds file_id, so it would fail closed at decrypt
            # time — but silently, with no attribution and no way to tell tampering from
            # corruption. The encrypted filename and its nonce are hashed in full rather
            # than digested; filenames are short, and a second hash function here would add
            # a weaker link for no benefit.
            cur.execute(
                "SELECT file_id, owner_id, version, size_bytes, blob_path, created_at, "
                "       encode(filename_enc,'hex')   AS filename_enc, "
                "       encode(filename_nonce,'hex') AS filename_nonce "
                "FROM files ORDER BY file_id"
            )
            _feed(h, "files", cur.fetchall())

            cur.execute("SELECT user_id, version FROM user_keys ORDER BY user_id")
            _feed(h, "user_keys", cur.fetchall())

            # --- users -------------------------------------------------------------
            # The ROWS, not just how many of them there are. `count(*)` alone left an
            # attacker free to swap two accounts' pw_hash values — a complete account
            # takeover that changed no count and therefore no digest.
            #
            # Hashing pw_hash here is safe: an Argon2id digest is not a secret in the way a
            # key is, this value never leaves the TEE, and the anchor stores only the final
            # SHA-256 of everything. The alternative — hashing usernames but not hashes —
            # would leave exactly the swap this exists to catch.
            cur.execute("SELECT user_id, username, pw_hash FROM users ORDER BY user_id")
            _feed(h, "users", cur.fetchall())

            # Hash stored audit sequence numbers and entry hashes. Payload HMACs are checked
            # by verify_chain(); editing a payload without changing entry_hash is not detected
            # by this digest alone.
            cur.execute(
                "SELECT seq, encode(entry_hash,'hex') AS eh FROM audit_log ORDER BY seq"
            )
            _feed(h, "audit_hashes", cur.fetchall())

    return h.hexdigest()


# --------------------------------------------------------------------------------------
# Key Vault I/O
# --------------------------------------------------------------------------------------

# bootstrapping an anchor is now an EXPLICIT act, not a default.
#
# Set G8_BOOTSTRAP_ANCHOR=1 for the one run that initialises a fresh vault secret.
# Leaving it set defeats the point: it would restore the fail-open behaviour below.
BOOTSTRAP_ANCHOR = os.environ.get("G8_BOOTSTRAP_ANCHOR", "0").lower() in (
    "1",
    "true",
    "yes",
)


def read_anchor():
    """Read the trusted digest from the configured Key Vault secret.

    Returns:
        The secret value, or None when the secret does not exist.

    Other Key Vault failures propagate to the caller.
    """
    try:
        return _secret_client().get_secret(SECRET_NAME).value
    except ResourceNotFoundError:
        return None


def write_anchor(state_root: str) -> None:
    """Replace the trusted baseline with the supplied digest.

    Args:
        state_root: Digest to write as a new secret version.

    No comparison is performed before writing. The caller must justify accepting
    the state and control concurrent operations.
    """
    _secret_client().set_secret(SECRET_NAME, state_root)


def update(conn) -> str:
    """Hash current database state and replace the trusted baseline.

    Args:
        conn: PostgreSQL connection used to hash current state.

    Returns:
        The digest written to Key Vault.

    This operation does not authenticate current state before accepting it.
    """
    root = compute_state_root(conn)
    write_anchor(root)
    return root


def verify(conn):
    """Compare selected current database state with the trusted digest.

    Args:
        conn: PostgreSQL connection used to hash current state.

    Returns:
        An (ok, detail) pair. Explicit bootstrap permits an absent anchor;
        otherwise absence or mismatch returns False. Dependency failures propagate.
    """
    current = compute_state_root(conn)
    anchored = read_anchor()

    if anchored is None:
        # this used to return (True, ...). It fails CLOSED now.
        #
        # "I have no baseline to compare against" is not "everything is fine", and
        # conflating the two handed an attacker a complete bypass of D3: delete the Key
        # Vault secret, edit the database freely, restart, and the service adopted the
        # tampered state as its new baseline while /healthz reported `initialised`. Every
        # later check then passed, because it was comparing the tampered state against
        # itself.
        #
        # The vault is the second trust boundary this design already relies on, so its
        # secret going missing is an event worth stopping for. Genuine first-time
        # initialisation still works, but it must be asked for: G8_BOOTSTRAP_ANCHOR=1.
        if BOOTSTRAP_ANCHOR:
            return True, {
                "status": "no_anchor_yet",
                "current": current,
                "note": "bootstrap explicitly permitted by G8_BOOTSTRAP_ANCHOR",
            }
        return False, {
            "status": "NO_ANCHOR",
            "current": current,
            "meaning": "no anchor exists in Key Vault. Either this is a first run, or the "
            "secret was deleted - which is exactly how an attacker would "
            "disable rollback detection. Start once with "
            "G8_BOOTSTRAP_ANCHOR=1 if this is genuinely the first run.",
        }
    if anchored == current:
        return True, {"status": "match", "state_root": current}
    return False, {
        "status": "MISMATCH",
        "anchored": anchored,
        "current": current,
        "meaning": "rows were deleted, or an older snapshot was restored",
    }


def verify_or_raise(conn) -> str:
    """Return the current digest only when anchor verification permits it.

    Args:
        conn: PostgreSQL connection used to compute current state.

    Returns:
        The matching digest, or current digest during explicit bootstrap.

    Raises:
        AnchorMismatch: Selected state differs or the anchor is absent
            without explicit bootstrap. Dependency errors propagate.
    """
    ok, detail = verify(conn)
    if not ok:
        raise AnchorMismatch(json.dumps(detail))
    return detail.get("state_root") or detail.get("current")


# --------------------------------------------------------------------------------------
# Demonstration — this is test T8
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    import os
    import uuid

    import g8auth
    import g8db

    print("=" * 76)
    print("g8anchor demonstration - D3 rollback / deletion detection (test T8)")
    print("=" * 76)

    conn = g8db.get_conn()
    keys = g8auth.load_keys()

    print("\n[1] register two users so there is real state to anchor")
    u1 = "anchor_" + os.urandom(3).hex()
    u2 = "anchor_" + os.urandom(3).hex()
    pw = "YOUR_TEST_PASSWORD"
    id1 = g8db.create_user(u1, pw, keys)
    id2 = g8db.create_user(u2, pw, keys)
    print("    created:", u1, "and", u2)

    print("\n[2] insert an ACL row granting %s read access to a file" % u2)
    fid = str(uuid.uuid4())
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO acl (file_id, user_id, permission, version, mac) "
            "VALUES (%s, %s, %s, %s, %s)",
            (fid, id2, "read", 1, os.urandom(32)),
        )
    print("    acl row inserted for file", fid[:8], "...")

    print("\n[3] anchor the current state into Key Vault")
    root = update(conn)
    print("    state_root:", root)
    print("    written to Key Vault secret:", SECRET_NAME)

    print("\n[4] verify - should MATCH")
    ok, detail = verify(conn)
    print("    ->", "PASS" if ok else "FAIL", detail["status"])

    print("\n[5] *** ATTACK *** delete the ACL row directly in the database")
    print("    (this is a cloud operator or DB-compromise scenario: the row is simply")
    print("     removed. Every remaining row still verifies its own AEAD tag, so AAD")
    print("     binding alone cannot notice.)")
    with conn.cursor() as cur:
        cur.execute("DELETE FROM acl WHERE file_id = %s", (fid,))
    print("    row deleted")

    print("\n[6] verify - should DETECT the deletion")
    ok, detail = verify(conn)
    print(
        "    ->", "PASS (detected)" if not ok else "FAIL (missed it!)", detail["status"]
    )
    if not ok:
        print("       anchored:", detail["anchored"][:32], "...")
        print("       current :", detail["current"][:32], "...")
        print("       meaning :", detail["meaning"])

    print("\n[7] *** ROLLBACK *** restore the row, as if from an old snapshot")
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO acl (file_id, user_id, permission, version, mac) "
            "VALUES (%s, %s, %s, %s, %s)",
            (fid, id2, "read", 1, os.urandom(32)),
        )
    ok, detail = verify(conn)
    print(
        "    restored row has a DIFFERENT mac -> verify:",
        "detected" if not ok else "matched",
    )
    print("    (a genuine snapshot restore would reproduce the original mac and match;")
    print("     the anchor detects the STATE, so rolling back to an anchored state is")
    print("     indistinguishable - which is why the anchor must be updated on EVERY")
    print("     mutation, so the anchored state is always the newest one.)")

    print("\n[8] cleanup")
    with conn.cursor() as cur:
        cur.execute("DELETE FROM acl WHERE file_id = %s", (fid,))
        cur.execute("DELETE FROM users WHERE username LIKE 'anchor\\_%'")
    update(conn)
    print("    test rows removed, anchor re-synced")

    g8db.close()
    print("\nDEMONSTRATION COMPLETE")
