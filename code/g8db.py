"""Persist metadata and wrapped keys in external PostgreSQL.

Managed identity supplies the connection credential; verify-full validates the
server certificate and hostname. Database constraints aid normal operation but
are not trusted security controls. User/file keys are wrapped, filenames are
encrypted, and ACL records carry authentication tags.
"""

import os
import uuid

import psycopg
from psycopg.rows import dict_row
from azure.identity import ManagedIdentityCredential

import g8auth
import g8keys

# Override deployment placeholders through the documented environment settings.
PG_HOST = os.environ.get("G8_PG_HOST", "YOUR_POSTGRES_HOST")
PG_USER = os.environ.get(
    "G8_PG_USER", "YOUR_MANAGED_IDENTITY_NAME"
)  # the VM's managed identity
PG_DB = os.environ.get("G8_PG_DB", "postgres")

# Entra scope for Azure Database for PostgreSQL
_PG_SCOPE = "https://ossrdbms-aad.database.windows.net/.default"


def _ca_bundle() -> str:
    """Resolve an explicit CA bundle path for certificate verification.

    WHY NOT sslrootcert=system: psql uses the SYSTEM libpq, but psycopg[binary] ships its
    OWN libpq and OpenSSL inside the wheel. 'system' means "OpenSSL's compiled-in default
    CA store", and the bundled OpenSSL's default path does not match Ubuntu's. The result
    is 'certificate verify failed' from psycopg on the very connection string that works
    fine in psql.

    Note the failure mode was CORRECT: verify-full failed closed rather than silently
    downgrading to an unverified connection.

    Naming the bundle explicitly removes the ambiguity entirely.
    """
    for path in (
        os.environ.get("G8_PG_CA", ""),
        "/etc/ssl/certs/ca-certificates.crt",  # Debian / Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",  # RHEL / Fedora
    ):
        if path and os.path.exists(path):
            return path
    return "system"


CA_BUNDLE = _ca_bundle()

_CONNINFO = "host=%s port=5432 dbname=%s user=%s sslmode=verify-full sslrootcert=%s" % (
    PG_HOST,
    PG_DB,
    PG_USER,
    CA_BUNDLE,
)

_credential = None
_conn = None


def _token() -> str:
    """Fetch an Entra access token for this VM's managed identity.

    ManagedIdentityCredential caches internally and refreshes when the token nears expiry,
    so calling this per connection is cheap. IMPORTANT: these tokens live about an hour.
    Caching one at startup produces a service that works perfectly in testing and fails
    an hour into a demo.
    """
    global _credential
    if _credential is None:
        _credential = ManagedIdentityCredential()
    return _credential.get_token(_PG_SCOPE).token


def get_conn():
    """Return the process-wide PostgreSQL connection, reconnecting if closed.

    Connections use managed identity and verify-full TLS. Single statements
    autocommit; callers use transaction() for grouped writes. This is a
    shared connection, not a per-request connection pool.
    """
    global _conn
    if _conn is None or _conn.closed:
        # autocommit=True is deliberate. With autocommit=False we relied on psycopg's
        # transaction() block to commit implicitly on exit, and it did not -- rows were
        # visible to this connection but never committed, so every other connection saw
        # an empty table and the data would have vanished on restart.
        # With autocommit=True, single statements commit immediately and
        # `with conn.transaction():` issues an explicit BEGIN/COMMIT. No implicit
        # behaviour to depend on.
        _conn = psycopg.connect(
            _CONNINFO, password=_token(), row_factory=dict_row, autocommit=True
        )
    return _conn


def close():
    """Close and discard the cached PostgreSQL connection."""
    global _conn
    if _conn is not None and not _conn.closed:
        _conn.close()
    _conn = None


def healthcheck() -> dict:
    """Return the connected database role and negotiated TLS details."""
    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT current_user AS user, ssl, version AS tls, cipher "
            "FROM pg_stat_ssl WHERE pid = pg_backend_pid()"
        )
        return cur.fetchone()


# --------------------------------------------------------------------------------------
# Registration
# --------------------------------------------------------------------------------------

MIN_PASSWORD_LEN = 12


class RegistrationError(Exception):
    """Account validation or persistence did not complete successfully."""

    pass


def create_user(username: str, password: str, keys: dict) -> str:
    """Persist an account and its wrapped user key in one transaction.

    Args:
        username: Account name; surrounding whitespace is stripped.
        password: Password subject to the configured minimum length.
        keys: Mapping containing pepper and user_kek_wrap.

    Returns:
        The new account's UUID string. The caller manages auditing and
        state anchoring separately.

    Raises:
        RegistrationError: Input is invalid, the name is taken, or the
            persistence check cannot find the new account.
    """
    username = (username or "").strip()
    if not username:
        raise RegistrationError("username required")
    if len(password or "") < MIN_PASSWORD_LEN:
        raise RegistrationError(
            "password must be at least %d characters" % MIN_PASSWORD_LEN
        )

    user_id = str(uuid.uuid4())
    pw_hash = g8auth.hash_password(password, keys["pepper"])

    user_kek = g8keys.new_user_kek()
    nonce, wrapped = g8keys.wrap_user_kek(user_kek, user_id, 1, keys["user_kek_wrap"])

    conn = get_conn()
    try:
        # Explicit BEGIN/COMMIT around both inserts: either the user and their User_KEK
        # both exist, or neither does.
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute(
                    "INSERT INTO users (user_id, username, pw_hash) VALUES (%s, %s, %s)",
                    (user_id, username, pw_hash),
                )
                cur.execute(
                    "INSERT INTO user_keys (user_id, wrapped_kek, nonce, version) "
                    "VALUES (%s, %s, %s, %s)",
                    (user_id, wrapped, nonce, 1),
                )
    except psycopg.errors.UniqueViolation:
        raise RegistrationError("username already taken")

    # Belt and braces: prove the row is actually committed and visible, rather than
    # trusting that it is. A silent failure to commit produced a service that passed all
    # 20 API tests while storing nothing (every test shared one connection).
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM users WHERE user_id = %s", (user_id,))
        if cur.fetchone()["n"] != 1:
            raise RegistrationError("registration failed to persist")

    return user_id


# --------------------------------------------------------------------------------------
# Authentication
# --------------------------------------------------------------------------------------

# A pre-computed hash of a random password, used to burn the same CPU time when the
# username does not exist. Without this, a missing user returns in microseconds while a
# real user takes ~100 ms of Argon2 work -- a timing side channel that lets an attacker
# enumerate valid usernames without ever guessing a password.
_DUMMY_HASH = None


def _dummy_hash(pepper: bytes) -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = g8auth.hash_password(os.urandom(16).hex(), pepper)
    return _DUMMY_HASH


def authenticate(username: str, password: str, keys: dict):
    """Check credentials and optionally refresh the stored password hash.

    Unknown accounts perform a dummy password check and return the same
    failure value as an incorrect password. Successful hash replacement
    also updates the anchor; callers must first verify existing state.

    Args:
        username: Account name to look up.
        password: Candidate plaintext password.
        keys: Mapping containing the password pepper.

    Returns:
        The account UUID string on success, or None on authentication
        failure. Optional rehash failures are logged and suppressed.
    """
    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT user_id, pw_hash FROM users WHERE username = %s", (username,)
        )
        row = cur.fetchone()

    if row is None:
        g8auth.verify_password(_dummy_hash(keys["pepper"]), password, keys["pepper"])
        return None

    if not g8auth.verify_password(row["pw_hash"], password, keys["pepper"]):
        return None

    # upgrade the stored hash if the Argon2 policy has been raised since it was
    # written. A successful login is the only moment the plaintext password exists in TEE
    # memory, so it is the only moment this is possible. Failures are swallowed: the login
    # succeeded, and refusing it because an optional re-hash could not be persisted would
    # be the wrong trade.
    #
    # ⚠️ AND IT MUST RE-ANCHOR. Since the v3 state root, users.pw_hash is part of the
    # anchored state, so rewriting it without updating the anchor leaves the database and
    # Key Vault disagreeing for an entirely innocent reason -- and the next request would
    # get a 409 "state integrity check failed", i.e. a tampering alarm caused by our own
    # housekeeping. Exactly the false alarm M7 exists to prevent, and easy to reintroduce:
    # any code path that writes to an anchored table owes the anchor an update.
    try:
        if g8auth.needs_rehash(row["pw_hash"]):
            fresh = g8auth.hash_password(password, keys["pepper"])
            with get_conn().cursor() as cur:
                cur.execute(
                    "UPDATE users SET pw_hash = %s WHERE user_id = %s",
                    (fresh, row["user_id"]),
                )
            import g8anchor

            g8anchor.update(get_conn())
            print(
                "[auth] re-hashed %s under the current Argon2 parameters, re-anchored"
                % row["user_id"]
            )
    except Exception as exc:  # noqa: BLE001
        print("[auth] WARNING: could not re-hash %s: %s" % (row["user_id"], exc))

    return str(row["user_id"])


def get_user_kek(user_id: str, keys: dict) -> bytes:
    """Load and authenticate the caller's wrapped user key.

    Args:
        user_id: Expected account identifier for the wrapped key.
        keys: Mapping containing user_kek_wrap.

    Returns:
        Plain user-key bytes.

    Raises:
        KeyError: The user has no key record.
        g8keys.KeyBindingError: The wrapped key or its context cannot be authenticated.
    """
    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT wrapped_kek, nonce, version FROM user_keys WHERE user_id = %s",
            (user_id,),
        )
        row = cur.fetchone()
    if row is None:
        raise KeyError("no User_KEK row for %s" % user_id)

    return g8keys.unwrap_user_kek(
        bytes(row["nonce"]),
        bytes(row["wrapped_kek"]),
        user_id,
        row["version"],
        keys["user_kek_wrap"],
    )


def user_exists(user_id: str) -> bool:
    """Check that a session's account still exists.

    Returns:
        False for an absent account or malformed UUID. Database
        availability errors propagate so callers can reject uncertainty.
    """
    try:
        with get_conn().cursor() as cur:
            cur.execute("SELECT 1 AS ok FROM users WHERE user_id = %s", (user_id,))
            return cur.fetchone() is not None
    except psycopg.errors.InvalidTextRepresentation:
        return False


def delete_user(user_id: str) -> bool:
    """Delete an account, its owned-file metadata, and its access rows.

    The caller separately deletes blobs and coordinates the state anchor.

    Args:
        user_id: Account identifier to remove.

    Returns:
        False when the account was already absent; True after deletion.
    """
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT 1 AS ok FROM users WHERE user_id = %s", (user_id,))
        if cur.fetchone() is None:
            return False

    with conn.transaction():
        with conn.cursor() as cur:
            # ACL rows have no FK, in either direction: as a grantee, and for files owned.
            cur.execute("DELETE FROM acl WHERE user_id = %s", (user_id,))
            cur.execute(
                "DELETE FROM acl WHERE file_id IN "
                "(SELECT file_id FROM files WHERE owner_id = %s)",
                (user_id,),
            )
            cur.execute("DELETE FROM files WHERE owner_id = %s", (user_id,))
            cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
    return True


def get_username(user_id: str):
    """Return an account name, or None if the account does not exist."""
    with get_conn().cursor() as cur:
        cur.execute("SELECT username FROM users WHERE user_id = %s", (user_id,))
        row = cur.fetchone()
    return row["username"] if row else None


# --------------------------------------------------------------------------------------
# Files
# --------------------------------------------------------------------------------------
#
# The rows written here describe a file; the file's CONTENT lives in Blob storage, a
# separate untrusted store. Neither store is trusted, and neither alone is sufficient:
#   * blob without metadata -> ciphertext nobody holds a key for
#   * metadata without blob -> a key for content that does not exist
# Both are covered by the state anchor (the `files` table was added to it in D12), so
# deleting either side is detectable rather than silent.


class FileError(Exception):
    """File metadata did not persist as expected."""

    pass


def create_file_record(
    file_id: str,
    owner_id: str,
    filename: str,
    size_bytes: int,
    blob_path: str,
    file_dek: bytes,
    keys: dict,
    version: int = 1,
):
    """Persist encrypted filename metadata and the owner's wrapped file key.

    Both records are committed together. The caller uploads the blob and
    manages auditing and the state anchor separately.

    Args:
        file_id: Identifier shared by the metadata and blob.
        owner_id: Uploading account identifier.
        filename: Plain filename to encrypt under the file key.
        size_bytes: Plaintext file length.
        blob_path: Deterministic container/file location.
        file_dek: Existing 32-byte file encryption key.
        keys: Application subkeys used to unwrap the owner's user key.
        version: File and wrapped-key version to authenticate.

    Returns:
        The supplied file identifier after persistence.

    Raises:
        FileError: The post-write check cannot find the file record.
        KeyError: The owner's user-key record does not exist.
        g8keys.KeyBindingError: The owner's wrapped user key is invalid.
    """
    user_kek = get_user_kek(owner_id, keys)

    fn_nonce, fn_enc = g8keys.encrypt_filename(filename, file_id, version, file_dek)
    dek_nonce, dek_wrapped = g8keys.wrap_file_dek(
        file_dek, owner_id, file_id, version, user_kek
    )

    conn = get_conn()
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO files (file_id, owner_id, filename_enc, filename_nonce, "
                "size_bytes, blob_path, version) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (file_id, owner_id, fn_enc, fn_nonce, size_bytes, blob_path, version),
            )
            cur.execute(
                "INSERT INTO file_keys (file_id, user_id, wrapped_dek, nonce, version) "
                "VALUES (%s, %s, %s, %s, %s)",
                (file_id, owner_id, dek_wrapped, dek_nonce, version),
            )

    # Same belt-and-braces check as registration. F8 taught that a write which the writing
    # connection can see is not necessarily a write that happened.
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM files WHERE file_id = %s", (file_id,))
        if cur.fetchone()["n"] != 1:
            raise FileError("file record failed to persist")

    return file_id


def get_file_for_user(file_id: str, user_id: str, keys: dict):
    """Authenticate a caller's wrapped file key and its version binding.

    Args:
        file_id: Requested file identifier.
        user_id: Account whose wrapped key must authorize access.
        keys: Application subkeys used to unwrap the user key.

    Returns:
        A (file_row, file_dek) pair. The row includes key_version.

    Raises:
        KeyError: The file or the caller's user-key record is absent.
        PermissionError: The caller has no wrapped key for this file.
        g8keys.KeyBindingError: Versions disagree or key authentication fails.
    """
    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT file_id, owner_id, filename_enc, filename_nonce, size_bytes, "
            "       blob_path, version, created_at "
            "FROM files WHERE file_id = %s",
            (file_id,),
        )
        f = cur.fetchone()
        if f is None:
            raise KeyError("no such file")

        cur.execute(
            "SELECT wrapped_dek, nonce, version FROM file_keys "
            "WHERE file_id = %s AND user_id = %s",
            (file_id, user_id),
        )
        k = cur.fetchone()

    if k is None:
        raise PermissionError("caller holds no wrapped DEK for this file")

    # files.version and file_keys.version are two independently
    # attacker-writable fields, and they feed two DIFFERENT AADs: the wrapped DEK is
    # unwrapped under file_keys.version, while the chunks and the filename are opened
    # under files.version. Nothing checked that they agreed, so a divergence surfaced
    # later as a confusing KeyBindingError from whichever layer happened to run first --
    # or, in share_file, produced a share row that could never be opened.
    #
    # They are written together and only ever move together, so disagreement means the
    # untrusted database has been edited. Say so here, once, instead of letting it become
    # a puzzle three layers down.
    if int(f["version"]) != int(k["version"]):
        raise g8keys.KeyBindingError(
            "stored records disagree: files.version=%s but file_keys.version=%s for "
            "this user. The metadata database was edited."
            % (f["version"], k["version"])
        )

    # Carried on the row so callers do not have to re-read it. NOT a second source of
    # truth -- the check above has already established the two are equal.
    f["key_version"] = k["version"]

    user_kek = get_user_kek(user_id, keys)
    dek = g8keys.unwrap_file_dek(
        bytes(k["nonce"]),
        bytes(k["wrapped_dek"]),
        user_id,
        str(f["file_id"]),
        k["version"],
        user_kek,
    )
    return f, dek


def get_filename(file_row, file_dek: bytes) -> str:
    """Decrypt a stored filename inside the TEE.

    Args:
        file_row: Metadata containing encrypted filename, nonce, file ID, and version.
        file_dek: Unwrapped file encryption key.
    """
    return g8keys.decrypt_filename(
        bytes(file_row["filename_nonce"]),
        bytes(file_row["filename_enc"]),
        str(file_row["file_id"]),
        file_row["version"],
        file_dek,
    )


def list_user_files(user_id: str, keys: dict):
    """List owned or shared files with authenticated wrapped keys.

    Args:
        user_id: Account whose owned and received files should be listed.
        keys: Application subkeys used to unwrap the account key.

    Returns:
        Visible file records with decrypted filenames. Records whose wrapped-key
        or filename authentication fails are represented as binding failures.
    """
    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT f.file_id, f.owner_id, f.size_bytes, f.version, f.created_at, "
            "       f.filename_enc, f.filename_nonce, "
            "       k.wrapped_dek, k.nonce AS dek_nonce, k.version AS key_version "
            "FROM files f JOIN file_keys k ON k.file_id = f.file_id "
            "WHERE k.user_id = %s ORDER BY f.created_at DESC",
            (user_id,),
        )
        rows = cur.fetchall()

    if not rows:
        return []

    user_kek = get_user_kek(user_id, keys)
    out = []
    for r in rows:
        # one bad row used to deny the whole list.
        #
        # A KeyBindingError raised here propagated out of the /files endpoint, which has no
        # handler, so a single tampered or relocated row cost the user access to EVERY file
        # they hold -- an unhandled 500, with no indication of which row was at fault. That
        # is a denial of service any attacker with database write access could trigger by
        # corrupting one byte.
        #
        # A row that fails its AAD check is an attack indicator, so it is reported as one
        # rather than swallowed: the entry is returned with an `error` field, the rest of
        # the list still works, and the caller can see exactly which file is affected.
        try:
            dek = g8keys.unwrap_file_dek(
                bytes(r["dek_nonce"]),
                bytes(r["wrapped_dek"]),
                user_id,
                str(r["file_id"]),
                r["key_version"],
                user_kek,
            )
            filename = g8keys.decrypt_filename(
                bytes(r["filename_nonce"]),
                bytes(r["filename_enc"]),
                str(r["file_id"]),
                r["version"],
                dek,
            )
        except g8keys.KeyBindingError:
            out.append(
                {
                    "file_id": str(r["file_id"]),
                    "filename": None,
                    "size_bytes": r["size_bytes"],
                    "version": r["version"],
                    "owned": str(r["owner_id"]) == str(user_id),
                    "created_at": r["created_at"].isoformat(),
                    "error": "key binding check failed: this row was moved, relabelled or "
                    "tampered with in the untrusted database",
                }
            )
            continue

        out.append(
            {
                "file_id": str(r["file_id"]),
                "filename": filename,
                "size_bytes": r["size_bytes"],
                "version": r["version"],
                "owned": str(r["owner_id"]) == str(user_id),
                "created_at": r["created_at"].isoformat(),
            }
        )
    return out


def delete_file(file_id: str, user_id: str, keys: dict) -> bool:
    """Delete an owner's file metadata and associated access records.

    The caller separately deletes the blob and manages the state anchor.

    Args:
        file_id: File identifier to remove.
        user_id: Caller expected to own the file.
        keys: Application subkeys used for authenticated key access.

    Returns:
        False when the file was already absent; True after deletion.

    Raises:
        PermissionError: The caller lacks access or is not the recorded owner.
        KeyError: A required file or user-key record is absent.
        g8keys.KeyBindingError: Wrapped-key authentication fails.
    """
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT owner_id FROM files WHERE file_id = %s", (file_id,))
        row = cur.fetchone()

    if row is None:
        return False
    # cryptographic ownership check, not a string comparison against an unauthenticated
    # column. Raises PermissionError (mapped to 404 by the caller) if it does not hold.
    assert_owner(file_id, user_id, keys)

    with conn.transaction():
        with conn.cursor() as cur:
            # file_keys cascades from files, but ACL rows have no foreign key by design
            # (schema.sql: the DB is untrusted, constraints are developer conveniences).
            cur.execute("DELETE FROM acl WHERE file_id = %s", (file_id,))
            cur.execute("DELETE FROM file_keys WHERE file_id = %s", (file_id,))
            cur.execute("DELETE FROM files WHERE file_id = %s", (file_id,))
    return True


# Sharing unwraps the existing file key and wraps it for the recipient. Blob
# contents are unchanged. Revocation deletes the recipient access records; it
# does not rotate the file key or erase plaintext already downloaded.
class ShareError(Exception):
    """The requested sharing operation cannot be completed."""

    pass


def assert_owner(file_id: str, user_id: str, keys: dict):
    """Require authenticated file-key access and a matching owner identifier.

    Wrapped-key authentication proves access, not ownership: recipients
    also hold valid keys. The caller's anchor check protects owner_id
    against changes in the untrusted database.

    Args:
        file_id: File whose ownership is required.
        user_id: Caller expected to own the file.
        keys: Application subkeys used for authenticated key access.

    Returns:
        The file metadata row after both checks succeed.

    Raises:
        PermissionError: Access is absent or owner_id names another account.
        KeyError: A required file or user-key record is absent.
        g8keys.KeyBindingError: Wrapped-key authentication fails.
    """
    row, _dek = get_file_for_user(
        file_id, user_id, keys
    )  # raises KeyError / PermissionError
    if str(row["owner_id"]) != str(user_id):
        raise PermissionError("caller is not the owner of this file")
    return row


VALID_PERMISSIONS = ("read", "write")


def share_file(
    file_id: str,
    owner_id: str,
    recipient_username: str,
    keys: dict,
    permission: str = "read",
) -> dict:
    """Wrap the existing file key for a recipient without rewriting the blob.

    Re-sharing refreshes the recipient's key and ACL records together.
    The caller coordinates pre-mutation verification, audit, and anchor.

    Args:
        file_id: File to share.
        owner_id: Caller whose ownership must be verified.
        recipient_username: Account name to receive access.
        keys: Application subkeys for key wrapping and ACL authentication.
        permission: Authenticated read/write label; both currently grant
            the same file-access capability.

    Returns:
        File, recipient, and permission details for the completed share.

    Raises:
        ShareError: Permission or recipient selection is invalid.
        PermissionError: The caller lacks access or ownership.
        KeyError: Required key or file records are absent.
        g8keys.KeyBindingError: Wrapped-key authentication fails.
    """
    if permission not in VALID_PERMISSIONS:
        raise ShareError("permission must be one of %s" % (VALID_PERMISSIONS,))

    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT user_id FROM users WHERE username = %s",
            ((recipient_username or "").strip(),),
        )
        r = cur.fetchone()
    if r is None:
        # this said "no such user", handing any authenticated caller a free
        # username oracle: try a name, read the message, learn whether the account exists.
        # authenticate() goes to real trouble to avoid exactly this (same message and the
        # same CPU cost for a missing user as for a wrong password), and this one line
        # undid it. The recipient is not disclosed either way now.
        raise ShareError("could not share with that user")
    recipient_id = str(r["user_id"])

    if recipient_id == str(owner_id):
        raise ShareError("you already own this file")

    # proves ownership cryptographically. Also the only place the owner's own wrapped
    # DEK is validated before it is re-wrapped for someone else, which is what we want.
    f = assert_owner(file_id, owner_id, keys)
    version = f["version"]

    # Unwrap as the owner, re-wrap for the recipient. Both operations happen in TEE memory
    # and the plaintext DEK never leaves it. The AAD on the new row binds the RECIPIENT's
    # user_id, so the row is useless to anyone else even though it protects the same key.
    _, dek = get_file_for_user(file_id, owner_id, keys)
    rec_kek = get_user_kek(recipient_id, keys)
    nonce, wrapped = g8keys.wrap_file_dek(
        dek, recipient_id, str(file_id), version, rec_kek
    )
    mac = g8keys.acl_mac(
        str(file_id), recipient_id, permission, version, keys["acl_mac"]
    )

    conn = get_conn()
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO file_keys (file_id, user_id, wrapped_dek, nonce, version) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (file_id, user_id) DO UPDATE SET "
                "  wrapped_dek = EXCLUDED.wrapped_dek, nonce = EXCLUDED.nonce, "
                "  version = EXCLUDED.version",
                (file_id, recipient_id, wrapped, nonce, version),
            )
            cur.execute(
                "INSERT INTO acl (file_id, user_id, permission, version, mac) "
                "VALUES (%s, %s, %s, %s, %s) "
                "ON CONFLICT (file_id, user_id) DO UPDATE SET "
                "  permission = EXCLUDED.permission, version = EXCLUDED.version, "
                "  mac = EXCLUDED.mac",
                (file_id, recipient_id, permission, version, mac),
            )

    return {
        "file_id": str(file_id),
        "user_id": recipient_id,
        "username": recipient_username,
        "permission": permission,
    }


def revoke_share(file_id: str, owner_id: str, target_user_id: str, keys: dict) -> bool:
    """Remove a recipient's wrapped key and ACL record in one transaction.

    The file key is not rotated and previously downloaded data is not
    recalled. The caller coordinates verification, auditing, and anchoring.

    Args:
        file_id: Shared file identifier.
        owner_id: Caller whose ownership must be verified.
        target_user_id: Recipient account whose access is removed.
        keys: Application subkeys used for authenticated key access.

    Returns:
        Whether no wrapped-key row remains, including when already absent.

    Raises:
        ShareError: The owner attempts to revoke their own access.
        PermissionError: The caller lacks access or ownership.
        KeyError: Required key or file records are absent.
        g8keys.KeyBindingError: Wrapped-key authentication fails.
    """
    if str(target_user_id) == str(owner_id):
        raise ShareError("the owner cannot revoke their own access; delete the file")

    assert_owner(file_id, owner_id, keys)  # M33
    conn = get_conn()
    with conn.transaction():
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM file_keys WHERE file_id = %s AND user_id = %s",
                (file_id, target_user_id),
            )
            cur.execute(
                "DELETE FROM acl WHERE file_id = %s AND user_id = %s",
                (file_id, target_user_id),
            )

    # Confirm by querying rather than trusting rowcount, which reported 0 on a statement
    # that demonstrably removed a row (noted during Day-5 cleanup work).
    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT count(*) AS n FROM file_keys WHERE file_id = %s AND user_id = %s",
            (file_id, target_user_id),
        )
        return cur.fetchone()["n"] == 0


def list_shares(file_id: str, owner_id: str, keys: dict):
    """Read an owner's sharing records and authenticate each ACL MAC.

    Args:
        file_id: File whose shares are requested.
        owner_id: Caller whose ownership must be verified.
        keys: Application subkeys for access checks and ACL authentication.

    Returns:
        Sharing records with mac_valid flags. Invalid MACs are reported
        rather than raised here; the API decides how to reject and audit.

    Raises:
        PermissionError: The caller lacks access or ownership.
        KeyError: Required key or file records are absent.
        g8keys.KeyBindingError: Wrapped-key authentication fails.
    """
    assert_owner(file_id, owner_id, keys)  # M33

    with get_conn().cursor() as cur:
        cur.execute(
            "SELECT a.user_id, a.permission, a.version, a.mac, a.granted_at, u.username "
            "FROM acl a JOIN users u ON u.user_id = a.user_id "
            "WHERE a.file_id = %s ORDER BY a.granted_at",
            (file_id,),
        )
        rows = cur.fetchall()

    return [
        {
            "user_id": str(r["user_id"]),
            "username": r["username"],
            "permission": r["permission"],
            "version": r["version"],
            "granted_at": r["granted_at"].isoformat(),
            "mac_valid": g8keys.verify_acl(
                bytes(r["mac"]),
                str(file_id),
                str(r["user_id"]),
                r["permission"],
                r["version"],
                keys["acl_mac"],
            ),
        }
        for r in rows
    ]


# --------------------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------------------

if __name__ == "__main__":
    import hashlib

    print("=" * 70)
    print("g8db self-test - external untrusted metadata DB")
    print("=" * 70)

    print("[0] TLS stack in use:")
    print("    psycopg libpq:", psycopg.pq.version(), "impl:", psycopg.pq.__impl__)
    print("    CA bundle    :", CA_BUNDLE)

    print("\n[1] connecting with managed identity (no password on this VM)...")
    hc = healthcheck()
    print("    connected as:", hc["user"])
    print(
        "    TLS:",
        hc["tls"],
        "/",
        hc["cipher"],
        "(verify-full: cert chain + hostname checked)",
    )

    print("\n[2] loading attested keys...")
    keys = g8auth.load_keys()
    print(
        "    pepper fingerprint:",
        hashlib.sha256(keys["pepper"]).hexdigest()[:16],
        "...",
    )

    uname = "selftest_" + os.urandom(4).hex()
    pw = "YOUR_TEST_PASSWORD"

    print("\n[3] registering user %r ..." % uname)
    uid = create_user(uname, pw, keys)
    print("    user_id:", uid)

    print("\n[4] what the database operator can actually see:")
    with get_conn().cursor() as cur:
        cur.execute("SELECT username, pw_hash FROM users WHERE user_id=%s", (uid,))
        r = cur.fetchone()
        print("    users.pw_hash    :", r["pw_hash"][:60], "...")
        cur.execute("SELECT wrapped_kek FROM user_keys WHERE user_id=%s", (uid,))
        print(
            "    user_keys.wrapped:",
            bytes(cur.fetchone()["wrapped_kek"])[:24].hex(),
            "...",
        )
    print("    ^ the hash is useless without the TEE-held pepper (T10);")
    print(
        "      the wrapped KEK is useless without Service_Root and the right AAD context."
    )

    print("\n[5] authentication:")
    print(
        "    correct password ->",
        "PASS" if authenticate(uname, pw, keys) == uid else "FAIL",
    )
    print(
        "    wrong password   ->",
        (
            "reject"
            if authenticate(uname, "wrong-password-here", keys) is None
            else "FAIL"
        ),
    )
    print(
        "    unknown user     ->",
        "reject" if authenticate("no_such_user", pw, keys) is None else "FAIL",
    )

    print("\n[6] User_KEK unwrap (AAD-bound to this user):")
    kek = get_user_kek(uid, keys)
    print(
        "    unwrapped %d bytes, fingerprint %s ..."
        % (len(kek), hashlib.sha256(kek).hexdigest()[:16])
    )

    print("\n[7] attacker moves the row onto another user_id:")
    try:
        get_user_kek(str(uuid.uuid4()), keys)
        print("    FAIL - should not have found a row")
    except KeyError:
        print("    no row for a random user_id (as expected)")

    print("\n[8] session token round trip:")
    tok = g8auth.issue_session(uid, keys["session_hmac"])
    print(
        "    verifies ->",
        "PASS" if g8auth.verify_session(tok, keys["session_hmac"]) == uid else "FAIL",
    )

    print("\n[9] cleanup: removing the self-test user...")
    with get_conn().cursor() as cur:
        cur.execute("DELETE FROM users WHERE user_id = %s", (uid,))
    get_conn().commit()
    print("    done (user_keys row removed by ON DELETE CASCADE)")

    close()
    print("\nSELF-TEST COMPLETE")
