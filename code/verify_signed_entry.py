#!/usr/bin/env python3
"""Check stored action signatures against enrolled public keys.

verify_entry() uses only its inputs. The --user CLI path reads the database and
loads attested keys to decrypt audit entries; it is not an offline export reader.
The --self-test path uses synthetic keys and needs no cloud deployment. Signature
validity does not independently authenticate the account-to-public-key binding.
"""

import argparse
import base64
import json
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils
from cryptography.hazmat.primitives.serialization import load_der_public_key


def parse_detail(detail: str) -> dict:
    """Pull stmt= / sig= / key= out of an audit entry's detail field."""
    out = {}
    for part in (detail or "").split("|"):
        part = part.strip()
        for field in ("stmt=", "sig=", "key="):
            if part.startswith(field):
                out[field.rstrip("=")] = part[len(field) :].strip()
        for token in part.split():
            for field in ("stmt=", "sig=", "key="):
                if token.startswith(field):
                    out[field.rstrip("=")] = token[len(field) :].strip()
    return out


def verify_entry(statement_b64: str, signature_b64: str, spki_der: bytes):
    """Verify an action signature using only the supplied public key and bytes.

    Args:
        statement_b64: Base64 JSON statement.
        signature_b64: Base64 raw r||s P-256 signature.
        spki_der: DER public key trusted independently by the caller.

    Returns:
        An (ok, parsed_statement_or_error) pair. No account enrollment, freshness,
        or replay checks are performed by this primitive.
    """
    try:
        body = base64.b64decode(statement_b64)
        stmt = json.loads(body)
    except Exception as exc:  # noqa: BLE001
        return False, "statement is not valid base64 JSON: %s" % type(exc).__name__

    try:
        raw = base64.b64decode(signature_b64)
    except Exception:  # noqa: BLE001
        return False, "signature is not valid base64"
    if len(raw) != 64:
        return False, "expected a 64-byte P-256 signature, got %d bytes" % len(raw)

    der = asym_utils.encode_dss_signature(
        int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")
    )
    try:
        pub = load_der_public_key(spki_der)
    except Exception as exc:  # noqa: BLE001
        return False, "public key will not parse: %s" % type(exc).__name__
    if not isinstance(pub, ec.EllipticCurvePublicKey):
        return False, "public key is not an elliptic-curve key"

    try:
        pub.verify(der, body, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "SIGNATURE DOES NOT VERIFY"
    return True, stmt


def self_test() -> int:
    """Check signature acceptance and rejection with synthetic key material."""
    import os
    import time

    sys.path.insert(0, os.path.expanduser("~"))
    import g8sign

    print("=" * 72)
    print("verify_signed_entry self-test - no VM, no database, no service required")
    print("=" * 72)

    priv = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    spki = priv.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo
    )

    ts, nonce = int(time.time()), os.urandom(8).hex()
    body = g8sign.canonical("share", "user-alice", "file-1", "bob", ts, nonce)
    der = priv.sign(body, ec.ECDSA(hashes.SHA256()))
    r, s = asym_utils.decode_dss_signature(der)
    stmt_b64 = base64.b64encode(body).decode()
    sig_b64 = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()

    # Exactly the string app.py now writes into the audit entry.
    detail = "granted read to bob | stmt=%s sig=%s key=%s" % (
        stmt_b64,
        sig_b64,
        "deadbeef",
    )
    print("\n[1] audit detail as stored (%d chars):" % len(detail))
    print("    %s..." % detail[:96])

    fields = parse_detail(detail)
    print("\n[2] parsed out of the entry: %s" % sorted(fields))
    ok, out = verify_entry(fields["stmt"], fields["sig"], spki)
    print(
        "    genuine entry           -> %s  %s"
        % ("VALID" if ok else "INVALID", out if ok else out)
    )

    passed = ok
    print("\n[3] forgeries the server might attempt:")

    tampered = bytearray(base64.b64decode(stmt_b64))
    tampered[20] ^= 0x01
    ok2, _ = verify_entry(base64.b64encode(bytes(tampered)).decode(), sig_b64, spki)
    print("    statement edited        -> %s" % ("VALID (FAIL)" if ok2 else "REJECTED"))
    passed &= not ok2

    ok3, _ = verify_entry(stmt_b64, base64.b64encode(os.urandom(64)).decode(), spki)
    print("    signature invented      -> %s" % ("VALID (FAIL)" if ok3 else "REJECTED"))
    passed &= not ok3

    other = ec.generate_private_key(ec.SECP256R1())
    d2 = other.sign(body, ec.ECDSA(hashes.SHA256()))
    r2, s2 = asym_utils.decode_dss_signature(d2)
    ok4, _ = verify_entry(
        stmt_b64,
        base64.b64encode(r2.to_bytes(32, "big") + s2.to_bytes(32, "big")).decode(),
        spki,
    )
    print("    signed with another key -> %s" % ("VALID (FAIL)" if ok4 else "REJECTED"))
    passed &= not ok4

    ok5, _ = verify_entry(stmt_b64, sig_b64[:24] + "...", spki)
    print("    TRUNCATED to 24 chars   -> %s" % ("VALID (FAIL)" if ok5 else "REJECTED"))
    print("      ^ complete statement and signature bytes are needed for verification:")
    print("        a truncated signature cannot establish validity.")
    passed &= not ok5

    print(
        "\n%s"
        % (
            "SELF-TEST PASSED - genuine accepted, every forgery rejected"
            if passed
            else "SELF-TEST FAILED"
        )
    )
    return 0 if passed else 1


def main() -> int:
    """Run offline self-tests or verify stored entries for the requested account.

    Returns:
        The command's exit status. Live verification loads keys and reads
        PostgreSQL; the self-test uses only synthetic local keys.
    """
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--user", help="user_id whose entries to check")
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument(
        "--self-test",
        action="store_true",
        help="prove the verifier works, with no VM or database",
    )
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if not args.user:
        ap.error("--user is required (or use --self-test)")

    import os

    sys.path.insert(0, os.path.expanduser("~"))
    import g8audit
    import g8auth
    import g8db

    keys = g8auth.load_keys()
    conn = g8db.get_conn()

    # The public keys live in the log too, so the whole check is self-contained.
    pubkeys = {}
    for e in g8audit.read(conn, keys, limit=10000):
        if e.get("action") == "key_register" and e.get("detail"):
            try:
                pubkeys[str(e["user_id"])] = base64.b64decode(e["detail"])
            except Exception:  # noqa: BLE001
                pass

    spki = pubkeys.get(str(args.user))
    if not spki:
        print("no registered public key found for %s" % args.user)
        return 1
    print("public key for %s: %d bytes (from the audit log)\n" % (args.user, len(spki)))

    checked = verified = unsigned = 0
    for e in g8audit.read(conn, keys, user_id=args.user, limit=args.limit):
        if e.get("action") not in ("share", "revoke", "delete"):
            continue
        checked += 1
        fields = parse_detail(e.get("detail") or "")
        if "stmt" not in fields or "sig" not in fields:
            unsigned += 1
            print(
                "  seq %-6s %-8s UNSIGNED (or written before the H11 fix)"
                % (e["seq"], e["action"])
            )
            continue
        ok, out = verify_entry(fields["stmt"], fields["sig"], spki)
        verified += bool(ok)
        print(
            "  seq %-6s %-8s %s"
            % (e["seq"], e["action"], "VERIFIED" if ok else "*** %s ***" % out)
        )
        if ok:
            print("            signed statement: %s" % json.dumps(out, sort_keys=True))

    print(
        "\n%d signable action(s): %d verified, %d unsigned, %d failed"
        % (checked, verified, unsigned, checked - verified - unsigned)
    )
    print("Verification used only the audit log and the registered public key.")
    g8db.close()
    return 0 if checked == verified + unsigned else 1


if __name__ == "__main__":
    raise SystemExit(main())
