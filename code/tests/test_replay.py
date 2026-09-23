"""Inspect a saved attestation token and attempt release against two key versions.

Configure the token path, vault, key name, and versions for a disposable deployment.
The broad exception handling cannot distinguish policy refusal from all setup or
network errors. Read the underlying failure before interpreting a PASS result.
This is a diagnostic script, not a conclusive replay-resistance acceptance test.
"""

import base64
import json
import os
import time

TOKEN_PATH = os.path.expanduser("~/docs/maa_token.jwt")
VAULT = "YOUR_KEY_VAULT_URL"

KEY_VERSIONS = [
    (
        "YOUR_COMPARISON_KEY_VERSION",
        "comparison version: configure its matching release policy",
    ),
    (
        "YOUR_CURRENT_KEY_VERSION",
        "current version: configure its matching release policy",
    ),
]

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


def b64url(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


print("=" * 78)
print("ANTI-REPLAY TEST — redeeming a captured attestation token (AS2)")
print("=" * 78)

if not os.path.exists(TOKEN_PATH):
    print("  [ABORT] no saved token at", TOKEN_PATH)
    raise SystemExit(1)

token = open(TOKEN_PATH).read().strip()
print("\n-- the intercepted credential --")
print("    file :", TOKEN_PATH)
print("    size :", len(token), "chars")

header, payload, _sig = token.split(".")
claims = json.loads(b64url(payload))
hdr = json.loads(b64url(header))

iat, exp, nbf = claims.get("iat"), claims.get("exp"), claims.get("nbf")
now = int(time.time())
print("    issuer            :", claims.get("iss"))
print("    attestation type  :", claims.get("x-ms-attestation-type"))
print("    compliance        :", claims.get("x-ms-compliance-status"))
print(
    "    issued at (iat)   :",
    iat,
    time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(iat)) if iat else "",
)
print(
    "    expires   (exp)   :",
    exp,
    time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(exp)) if exp else "",
)
print(
    "    now               :",
    now,
    time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(now)),
)

if exp:
    age_h = (now - exp) / 3600.0
    print("    -> the token expired %.1f hours ago" % age_h)
    result(
        "the captured token carries a bounded lifetime (freshness)",
        exp > (iat or 0),
        "valid for %.1f hours from issue" % (((exp - iat) / 3600.0) if iat else 0),
    )

# The ephemeral per-boot keys the deck's anti-replay claim rests on.
runtime = claims.get("x-ms-runtime", {})
rkeys = runtime.get("keys", [])
kids = [k.get("kid") for k in rkeys]
print("\n-- the per-boot ephemeral keys this token is bound to --")
for k in rkeys:
    n = k.get("n", "")
    print(
        "    kid=%-10s kty=%s  modulus starts %s..."
        % (k.get("kid"), k.get("kty"), n[:28])
    )
result(
    "the token embeds per-boot vTPM keys (HCLAkPub / HCLEkPub)",
    any("HCLAkPub" == kid for kid in kids) or any("HCLEkPub" == kid for kid in kids),
    "kids: %s" % kids,
)
print("    Inspect the deployed transport-key lifecycle separately.")
print("      This script does not establish whether matching private keys persist")
print("      or whether a fresh replay could release usable key material.")

print("\n-- replaying it against Key Vault --")
try:
    from azure.identity import ManagedIdentityCredential
    from azure.keyvault.keys import KeyClient

    cred = ManagedIdentityCredential()
    for version, note in KEY_VERSIONS:
        kc = KeyClient(vault_url=VAULT, credential=cred)
        print("\n    key version %s" % version)
        print("      (%s)" % note)
        try:
            kc.release_key(
                name="YOUR_MASTER_KEY_NAME",
                version=version,
                target_attestation_token=token,
            )
            result(
                "replayed token is REFUSED",
                False,
                "*** KEY VAULT RELEASED THE KEY TO A REPLAYED TOKEN ***",
            )
        except Exception as exc:  # noqa: BLE001
            msg = str(exc).replace("\n", " ")
            result("replayed token is REFUSED", True, type(exc).__name__)
            print("      ", msg[:150])
except ImportError as exc:  # noqa: BLE001
    print("    [SKIP] azure-keyvault-keys not available:", exc)

print("\n" + "=" * 78)
print("WHAT THIS SHOWS")
print("=" * 78)
print(
    "Interpret release failures individually: expiration, policy, authorization, network, or configuration errors can all affect the result. A matching fresh-token baseline is needed to isolate freshness. This script does not establish immediate-replay resistance or destruction of transport keys."
)

print("\n" + "=" * 78)
print("RESULT: %d passed, %d failed" % (_passed, _failed))
print("=" * 78)
