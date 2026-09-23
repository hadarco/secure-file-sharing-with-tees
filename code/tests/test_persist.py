"""Exercise account and key persistence against real deployment resources.

Requires attested keys and PostgreSQL access. Tests mutate database state and
clean up records; use a disposable deployment and review anchor consequences.
See docs/setup.md before collecting or running this file.
"""

import os

import psycopg
import pytest
from psycopg.rows import dict_row

import g8auth
import g8db
import g8keys

# --------------------------------------------------------------------------------------
# Gating — these are integration tests, not unit tests
# --------------------------------------------------------------------------------------


def _on_tdx_vm() -> bool:
    """True only on the attested TDX VM, detected by the wrapped Service_Root blob."""
    return os.path.exists("/home/YOUR_VM_USER/g8state/service_root.wrapped")


pytestmark = pytest.mark.skipif(
    not _on_tdx_vm(),
    reason="requires the attested TDX VM and the external PostgreSQL database",
)

PREFIX = "persist_"
PASSWORD = "YOUR_TEST_PASSWORD"


# --------------------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------------------


@pytest.fixture(scope="module")
def keys():
    """Real attested key material. Module-scoped so the SKR unwrap runs once, not once
    per test — attestation plus an RSA unwrap is not something to repeat needlessly."""
    return g8auth.load_keys()


@pytest.fixture
def reader():
    """A SECOND, genuinely independent connection to the same database.

    This fixture IS the point of the file, so it is worth being exact about what makes it
    independent.

    `g8db` keeps ONE module-level connection and hands the same object to every caller, so
    `g8db.get_conn()` can never yield a second session. We therefore build one directly
    from the same connection parameters — same host, same verify-full TLS, same
    managed-identity token — but as a separate psycopg connection. PostgreSQL gives it its
    own backend process with its own transaction state, which is precisely the isolation
    the F8 bug hid behind.

    Reaching into g8db's private `_CONNINFO` / `_token()` is deliberate: the writer and
    the reader must differ ONLY in being separate sessions. Rebuilding the connection
    string by hand here would risk testing a different security posture (a weaker sslmode,
    say) than the service actually uses.
    """
    conn = psycopg.connect(
        g8db._CONNINFO,
        password=g8db._token(),
        row_factory=dict_row,
        autocommit=True,
    )
    yield conn
    conn.close()


@pytest.fixture
def username():
    """A unique username per test, removed afterwards whatever the test did.

    Cleanup deletes only the `users` row; `user_keys` follows via ON DELETE CASCADE.
    """
    name = PREFIX + os.urandom(4).hex()
    yield name
    with g8db.get_conn().cursor() as cur:
        cur.execute("DELETE FROM users WHERE username = %s", (name,))


# --------------------------------------------------------------------------------------
# The premise itself
# --------------------------------------------------------------------------------------


def test_the_reader_really_is_a_separate_session(reader):
    """Check the assumption before relying on it.

    If the writer and the reader shared one backend, every test below would pass
    vacuously — which is exactly how F8 survived twenty green tests. `pg_backend_pid()`
    returns the server-side process handling each session, so two different numbers prove
    two genuinely independent sessions.
    """
    with g8db.get_conn().cursor() as cur:
        cur.execute("SELECT pg_backend_pid() AS pid")
        writer_pid = cur.fetchone()["pid"]

    with reader.cursor() as cur:
        cur.execute("SELECT pg_backend_pid() AS pid")
        reader_pid = cur.fetchone()["pid"]

    assert (
        writer_pid != reader_pid
    ), "writer and reader share a backend process; this suite would prove nothing"


# --------------------------------------------------------------------------------------
# Durability
# --------------------------------------------------------------------------------------


def test_registered_user_is_visible_to_a_second_connection(keys, reader, username):
    """THE F8 TEST.

    A row written through the service must be readable by a connection that had nothing to
    do with writing it. Only committed data crosses that line.
    """
    user_id = g8db.create_user(username, PASSWORD, keys)

    with reader.cursor() as cur:
        cur.execute("SELECT user_id FROM users WHERE username = %s", (username,))
        row = cur.fetchone()

    assert row is not None, "row not visible to a second connection — F8 has returned"
    assert str(row["user_id"]) == user_id


def test_both_rows_of_the_registration_transaction_persist(keys, reader, username):
    """Registration writes `users` and `user_keys` as ONE transaction.

    A user row without a key row is an account that can never hold a file; a key row
    without a user row is an orphan. Both must survive the commit, not just the first.
    """
    user_id = g8db.create_user(username, PASSWORD, keys)

    with reader.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM users WHERE user_id = %s", (user_id,))
        assert cur.fetchone()["n"] == 1, "users row not committed"

        cur.execute(
            "SELECT count(*) AS n FROM user_keys WHERE user_id = %s", (user_id,)
        )
        assert cur.fetchone()["n"] == 1, "user_keys row not committed"


def test_wrapped_kek_survives_the_database_round_trip(keys, reader, username):
    """Stronger than "the row exists": the BYTES must come back intact.

    The wrapped User_KEK is read through the reader connection and unwrapped inside the
    TEE. Had the untrusted store altered the ciphertext, the nonce, or the version by a
    single bit, the AES-GCM tag check would reject it. Passing proves the
    external database returned exactly what was written — binary data included, which is a
    real risk in its own right, since `bytea` handling is a classic place for silent
    corruption.
    """
    user_id = g8db.create_user(username, PASSWORD, keys)

    with reader.cursor() as cur:
        cur.execute(
            "SELECT wrapped_kek, nonce, version FROM user_keys WHERE user_id = %s",
            (user_id,),
        )
        row = cur.fetchone()

    kek = g8keys.unwrap_user_kek(
        bytes(row["nonce"]),
        bytes(row["wrapped_kek"]),
        user_id,
        row["version"],
        keys["user_kek_wrap"],
    )
    assert len(kek) == g8keys.KEY_LEN


def test_stored_hash_still_authenticates_when_read_independently(
    keys, reader, username
):
    """The real-world consequence of F8, tested directly.

    A password hash that is written but never committed leaves login failing after the
    next restart. Here the hash is fetched by a connection that did not write it and then
    verified with the TEE-held pepper — so a pass means a user could genuinely log in
    after a service restart, which is the property that actually matters.
    """
    user_id = g8db.create_user(username, PASSWORD, keys)

    with reader.cursor() as cur:
        cur.execute("SELECT pw_hash FROM users WHERE user_id = %s", (user_id,))
        stored = cur.fetchone()["pw_hash"]

    assert g8auth.verify_password(stored, PASSWORD, keys["pepper"])
    assert not g8auth.verify_password(stored, "the-wrong-password", keys["pepper"])


def test_failed_registration_leaves_nothing_behind(keys, reader, username):
    """Atomicity, checked from OUTSIDE the writing session.

    A duplicate username must roll BOTH inserts back. A stray `user_keys` row belonging to
    a user that does not exist would be invisible to the service and would quietly corrupt
    the state the anchor hashes.
    """
    g8db.create_user(username, PASSWORD, keys)

    with reader.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM user_keys")
        before = cur.fetchone()["n"]

    with pytest.raises(g8db.RegistrationError):
        g8db.create_user(username, PASSWORD, keys)

    with reader.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM users WHERE username = %s", (username,))
        assert cur.fetchone()["n"] == 1, "the duplicate was somehow inserted"

        cur.execute("SELECT count(*) AS n FROM user_keys")
        assert cur.fetchone()["n"] == before, "rolled-back registration left a key row"


def test_deletion_is_also_committed(keys, reader, username):
    """Revocation depends on DELETES being durable too.

    A delete that never commits would silently restore access on the next restart — the
    same bug wearing different clothes, and a far more dangerous one, since it would undo
    a security decision rather than lose a convenience.
    """
    user_id = g8db.create_user(username, PASSWORD, keys)

    with g8db.get_conn().cursor() as cur:
        cur.execute("DELETE FROM users WHERE user_id = %s", (user_id,))

    with reader.cursor() as cur:
        cur.execute("SELECT count(*) AS n FROM users WHERE user_id = %s", (user_id,))
        assert cur.fetchone()["n"] == 0, "delete was not committed"

        cur.execute(
            "SELECT count(*) AS n FROM user_keys WHERE user_id = %s", (user_id,)
        )
        assert cur.fetchone()["n"] == 0, "ON DELETE CASCADE did not commit"
