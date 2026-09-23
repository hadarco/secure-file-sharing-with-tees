"""Test cryptographic bindings with synthetic keys.

Use the explicit portable command in docs/setup.md. The final integration case
loads real attested keys; exclude it for local checks. These tests verify selected
cryptographic constructions, not hardware attestation or cloud release policies.
"""

import os
import time

import pytest

import g8auth
import g8keys
from g8keys import KeyBindingError

ALICE, BOB = "alice-0001", "bob-0002"
F1, F2 = "file-aaaa", "file-bbbb"


# ======================================================================================
# Fixtures
# ======================================================================================


@pytest.fixture
def wrap_key():
    return os.urandom(32)


@pytest.fixture
def alice_kek():
    return g8keys.new_user_kek()


@pytest.fixture
def bob_kek():
    return g8keys.new_user_kek()


@pytest.fixture
def dek():
    return g8keys.new_file_dek()


@pytest.fixture
def pepper():
    return os.urandom(32)


@pytest.fixture
def session_key():
    return os.urandom(32)


# ======================================================================================
# Key generation
# ======================================================================================


def test_generated_keys_are_256_bit():
    assert len(g8keys.new_user_kek()) == 32
    assert len(g8keys.new_file_dek()) == 32


def test_generated_keys_are_unique():
    """A repeated key would be catastrophic; 200 samples must all differ."""
    keys = {g8keys.new_file_dek() for _ in range(200)}
    assert len(keys) == 200


def test_nonces_are_unique_across_wraps(alice_kek, dek):
    """GCM nonce reuse under the same key breaks confidentiality AND authenticity."""
    nonces = set()
    for _ in range(200):
        n, _ = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
        nonces.add(n)
    assert len(nonces) == 200
    assert all(len(n) == g8keys.NONCE_LEN for n in nonces)


# ======================================================================================
# User_KEK layer — round trip and AAD rejections
# ======================================================================================


def test_user_kek_roundtrip(wrap_key, alice_kek):
    n, ct = g8keys.wrap_user_kek(alice_kek, ALICE, 1, wrap_key)
    assert g8keys.unwrap_user_kek(n, ct, ALICE, 1, wrap_key) == alice_kek


def test_user_kek_wrapped_form_is_not_the_key(wrap_key, alice_kek):
    _, ct = g8keys.wrap_user_kek(alice_kek, ALICE, 1, wrap_key)
    assert alice_kek not in ct


def test_user_kek_rejects_wrong_user(wrap_key, alice_kek):
    """T6d: Alice's User_KEK row copied onto Bob's account."""
    n, ct = g8keys.wrap_user_kek(alice_kek, ALICE, 1, wrap_key)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_user_kek(n, ct, BOB, 1, wrap_key)


def test_user_kek_rejects_stale_version(wrap_key, alice_kek):
    n, ct = g8keys.wrap_user_kek(alice_kek, ALICE, 1, wrap_key)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_user_kek(n, ct, ALICE, 2, wrap_key)


def test_user_kek_rejects_wrong_wrap_key(alice_kek):
    n, ct = g8keys.wrap_user_kek(alice_kek, ALICE, 1, os.urandom(32))
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_user_kek(n, ct, ALICE, 1, os.urandom(32))


# ======================================================================================
# File_DEK layer — round trip and AAD rejections
# ======================================================================================


def test_file_dek_roundtrip(alice_kek, dek):
    n, ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    assert g8keys.unwrap_file_dek(n, ct, ALICE, F1, 1, alice_kek) == dek


def test_file_dek_rejects_wrong_user(alice_kek, bob_kek, dek):
    """T6a: Bob replays Alice's wrapped-DEK row onto his own account."""
    n, ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(n, ct, BOB, F1, 1, bob_kek)


def test_file_dek_rejects_wrong_file(alice_kek, dek):
    """T6b: a row relabelled to point at a different file."""
    n, ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(n, ct, ALICE, F2, 1, alice_kek)


def test_file_dek_rejects_stale_version(alice_kek, dek):
    """T6c: an old row replayed after key rotation."""
    n, ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(n, ct, ALICE, F1, 2, alice_kek)


def test_file_dek_rejects_wrong_kek(alice_kek, bob_kek, dek):
    n, ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(n, ct, ALICE, F1, 1, bob_kek)


@pytest.mark.parametrize("byte_index", [0, 5, -1])
def test_file_dek_rejects_tampered_ciphertext(alice_kek, dek, byte_index):
    """T5: flipping ANY single bit must be detected by the GCM tag."""
    n, ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    bad = bytearray(ct)
    bad[byte_index] ^= 0x01
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(n, bytes(bad), ALICE, F1, 1, alice_kek)


def test_file_dek_rejects_tampered_nonce(alice_kek, dek):
    n, ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    bad = bytearray(n)
    bad[0] ^= 0x01
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(bytes(bad), ct, ALICE, F1, 1, alice_kek)


def test_file_dek_rejects_truncated_ciphertext(alice_kek, dek):
    n, ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(n, ct[:-1], ALICE, F1, 1, alice_kek)


# ======================================================================================
# Sharing and revocation semantics
# ======================================================================================


def test_sharing_yields_same_dek_without_reencrypting(alice_kek, bob_kek, dek):
    """Sharing re-wraps a key, not the file. Both users recover identical DEK bytes."""
    a_n, a_ct = g8keys.wrap_file_dek(dek, ALICE, F1, 1, alice_kek)
    b_n, b_ct = g8keys.wrap_file_dek(dek, BOB, F1, 1, bob_kek)

    assert g8keys.unwrap_file_dek(a_n, a_ct, ALICE, F1, 1, alice_kek) == dek
    assert g8keys.unwrap_file_dek(b_n, b_ct, BOB, F1, 1, bob_kek) == dek
    assert a_ct != b_ct  # same key, different wrapped forms


def test_revoked_user_cannot_reuse_their_old_row(alice_kek, bob_kek, dek):
    """After revocation the row is deleted; if an attacker restores it under a rotated
    version, the AAD version mismatch rejects it."""
    b_n, b_ct = g8keys.wrap_file_dek(dek, BOB, F1, 1, bob_kek)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(b_n, b_ct, BOB, F1, 2, bob_kek)


# ======================================================================================
# AAD canonical encoding — the ambiguity bug this design avoids
# ======================================================================================


def test_aad_is_unambiguous_across_field_boundaries():
    """Naive concatenation makes ('ab','c') and ('a','bc') identical, which would allow a
    wrapped key to be replayed across a different (user, file) pair. Canonical JSON keeps
    field boundaries explicit."""
    a = g8keys._aad(t="file_dek", uid="ab", fid="c", v=1)
    b = g8keys._aad(t="file_dek", uid="a", fid="bc", v=1)
    assert a != b


def test_aad_is_deterministic():
    assert g8keys._aad(uid="x", fid="y", v=1) == g8keys._aad(v=1, fid="y", uid="x")


def test_cross_context_replay_blocked_by_canonical_aad(alice_kek, dek):
    """The concrete attack the previous test describes, executed end to end."""
    n, ct = g8keys.wrap_file_dek(dek, "ab", "c", 1, alice_kek)
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_file_dek(n, ct, "a", "bc", 1, alice_kek)


# ======================================================================================
# Filename encryption
# ======================================================================================


def test_filename_roundtrip(dek):
    n, ct = g8keys.encrypt_filename("salary_review_2026.pdf", F1, 1, dek)
    assert g8keys.decrypt_filename(n, ct, F1, 1, dek) == "salary_review_2026.pdf"


def test_filename_ciphertext_leaks_nothing(dek):
    n, ct = g8keys.encrypt_filename("salary_review_2026.pdf", F1, 1, dek)
    assert b"salary" not in ct
    assert b"pdf" not in ct


def test_filename_rejects_wrong_file_id(dek):
    n, ct = g8keys.encrypt_filename("secret.pdf", F1, 1, dek)
    with pytest.raises(KeyBindingError):
        g8keys.decrypt_filename(n, ct, F2, 1, dek)


def test_filename_handles_unicode(dek):
    name = "\u05d3\u05d5\u05d7 \u05e1\u05d5\u05d3\u05d9.pdf"  # Hebrew filename
    n, ct = g8keys.encrypt_filename(name, F1, 1, dek)
    assert g8keys.decrypt_filename(n, ct, F1, 1, dek) == name


# ======================================================================================
# Password hashing with the TEE-held pepper
# ======================================================================================


def test_password_roundtrip(pepper):
    h = g8auth.hash_password("correct horse battery staple", pepper)
    assert g8auth.verify_password(h, "correct horse battery staple", pepper)


def test_wrong_password_rejected(pepper):
    h = g8auth.hash_password("correct horse", pepper)
    assert not g8auth.verify_password(h, "wrong horse", pepper)


def test_T10_correct_password_with_wrong_pepper_is_rejected(pepper):
    """TEST T10 — the offline-cracking defence.

    An attacker has dumped the entire untrusted database and has even guessed the password
    correctly. Without the pepper (which exists only in TDX memory after attestation) they
    still cannot verify the guess.
    """
    h = g8auth.hash_password("correct horse battery staple", pepper)
    assert not g8auth.verify_password(h, "correct horse battery staple", os.urandom(32))


def test_same_password_hashes_differently_each_time(pepper):
    """Argon2 salts per hash, so identical passwords must not produce identical rows."""
    a = g8auth.hash_password("same", pepper)
    b = g8auth.hash_password("same", pepper)
    assert a != b
    assert g8auth.verify_password(a, "same", pepper)
    assert g8auth.verify_password(b, "same", pepper)


def test_hash_records_current_parameters(pepper):
    h = g8auth.hash_password("x", pepper)
    assert h.startswith("$argon2id$")
    assert "m=65536" in h and "t=3" in h and "p=2" in h


def test_malformed_hash_does_not_raise(pepper):
    assert not g8auth.verify_password("not-a-hash", "x", pepper)


# ======================================================================================
# Session tokens
# ======================================================================================


def test_session_roundtrip(session_key):
    tok = g8auth.issue_session("user-123", session_key)
    assert g8auth.verify_session(tok, session_key) == "user-123"


def test_session_rejects_tampered_signature(session_key):
    tok = g8auth.issue_session("user-123", session_key)
    bad = tok[:-4] + ("AAAA" if not tok.endswith("AAAA") else "BBBB")
    assert g8auth.verify_session(bad, session_key) is None


def test_session_rejects_tampered_payload(session_key):
    """Swapping the user id in the payload must invalidate the signature."""
    tok = g8auth.issue_session("user-123", session_key)
    body, sig = tok.split(".", 1)
    forged = g8auth._b64u(b'{"exp":9999999999,"uid":"admin"}') + "." + sig
    assert g8auth.verify_session(forged, session_key) is None


def test_session_rejects_expired(session_key):
    tok = g8auth.issue_session("user-123", session_key, ttl=-1)
    assert g8auth.verify_session(tok, session_key) is None


def test_session_rejects_wrong_key(session_key):
    tok = g8auth.issue_session("user-123", session_key)
    assert g8auth.verify_session(tok, os.urandom(32)) is None


@pytest.mark.parametrize("junk", ["", ".", "no-dot", "a.b.c", "!!!.???"])
def test_session_rejects_malformed(session_key, junk):
    assert g8auth.verify_session(junk, session_key) is None


def test_session_not_yet_expired_is_accepted(session_key):
    tok = g8auth.issue_session("user-123", session_key, ttl=60)
    assert g8auth.verify_session(tok, session_key) == "user-123"


# ======================================================================================
# ACL row MACs
# ======================================================================================


@pytest.fixture
def mac_key():
    return os.urandom(32)


def test_acl_mac_verifies(mac_key):
    m = g8keys.acl_mac(F1, ALICE, "read", 1, mac_key)
    assert g8keys.verify_acl(m, F1, ALICE, "read", 1, mac_key)


@pytest.mark.parametrize(
    "field,value",
    [
        ("fid", F2),
        ("uid", BOB),
        ("perm", "write"),
        ("ver", 2),
    ],
)
def test_acl_mac_rejects_any_altered_field(mac_key, field, value):
    """An attacker with database write access edits one column of an ACL row. Escalating
    'read' to 'write' is the obvious one, but moving a row to another file or user must
    fail identically."""
    m = g8keys.acl_mac(F1, ALICE, "read", 1, mac_key)
    args = {"fid": F1, "uid": ALICE, "perm": "read", "ver": 1}
    args[field] = value
    assert not g8keys.verify_acl(
        m, args["fid"], args["uid"], args["perm"], args["ver"], mac_key
    )


def test_acl_mac_rejects_wrong_key(mac_key):
    """The MAC key is derived from the attested Service_Root, so an attacker holding the
    whole database still cannot forge a row."""
    m = g8keys.acl_mac(F1, ALICE, "read", 1, mac_key)
    assert not g8keys.verify_acl(m, F1, ALICE, "read", 1, os.urandom(32))


def test_acl_mac_is_unambiguous_across_field_boundaries(mac_key):
    """Same concatenation-ambiguity trap as the AAD: canonical JSON keeps boundaries."""
    a = g8keys.acl_mac("ab", "c", "read", 1, mac_key)
    b = g8keys.acl_mac("a", "bc", "read", 1, mac_key)
    assert a != b


# ======================================================================================
# Integration — real attested key material (skipped off the TDX VM)
# ======================================================================================


def _on_tdx_vm():
    return os.path.exists("/home/YOUR_VM_USER/g8state/service_root.wrapped")


@pytest.mark.skipif(not _on_tdx_vm(), reason="requires the attested TDX VM")
def test_attested_keys_integration():
    """End to end with REAL key material released by attested SKR.

    Proves the hierarchy works with keys that exist only after Intel TDX attestation,
    not merely with synthetic test keys.
    """
    keys = g8auth.load_keys()
    assert set(keys) == {
        "user_kek_wrap",
        "pepper",
        "session_hmac",
        "acl_mac",
        "audit_hmac",
        "audit_enc",
    }
    assert all(len(v) == 32 for v in keys.values())
    # all six sub-keys must be distinct - HKDF domain separation working
    assert len(set(keys.values())) == 6

    kek = g8keys.new_user_kek()
    n, ct = g8keys.wrap_user_kek(kek, ALICE, 1, keys["user_kek_wrap"])
    assert g8keys.unwrap_user_kek(n, ct, ALICE, 1, keys["user_kek_wrap"]) == kek
    with pytest.raises(KeyBindingError):
        g8keys.unwrap_user_kek(n, ct, BOB, 1, keys["user_kek_wrap"])
