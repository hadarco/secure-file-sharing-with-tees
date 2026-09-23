"""Bootstrap the service root through an external Secure Key Release client.

Configure the deployment constants before running this module. The wrapped root
must survive restarts; losing it while retaining encrypted data prevents recovery.
The client contract and deployment prerequisites are documented in docs/setup.md.
"""

import os
import subprocess
import base64
import hashlib

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

SKR = "/home/YOUR_VM_USER/confidential-computing-cvm-guest-attestation/cvm-securekey-release-app/build/AzureAttestSKR"
ATTEST_URL = "YOUR_ATTESTATION_URL"
KEK = "YOUR_KEY_VAULT_KEY_ID"
STATE_DIR = "/home/YOUR_VM_USER/g8state"
WRAPPED_FILE = os.path.join(STATE_DIR, "service_root.wrapped")


def _skr(secret_b64_or_plain, op):
    """Invoke the configured SKR client and extract its base64 result.

    Args:
        secret_b64_or_plain: Value passed to the client's -s option.
        op: -w for wrapping or -u for unwrapping.

    Returns:
        The last output line accepted by the existing base64 heuristic.

    Raises:
        RuntimeError: No candidate result line was found.
        subprocess.TimeoutExpired: The client exceeded 180 seconds.

    The heuristic does not establish a successful exit or validate key length.
    """
    r = subprocess.run(
        ["sudo", SKR, "-a", ATTEST_URL, "-k", KEK, "-s", secret_b64_or_plain, op],
        capture_output=True,
        text=True,
        timeout=180,
    )
    lines = [l.strip() for l in (r.stdout + "\n" + r.stderr).splitlines() if l.strip()]
    # the final bare base64 line is the result
    for l in reversed(lines):
        if all(c.isalnum() or c in "+/=" for c in l) and len(l) > 12:
            return l
    raise RuntimeError("SKR failed (" + op + "):\n" + "\n".join(lines[-6:]))


def get_service_root():
    """Load the root, creating and persisting a wrapped root on first use.

    Returns:
        Plain service-root bytes for in-process key derivation.

    Raises:
        OSError: Persistent state cannot be read or written.
        RuntimeError: The SKR wrapper cannot extract a result.

    A missing wrapped file triggers creation; callers must distinguish fresh
    deployment from loss of state before invoking this function.
    """
    os.makedirs(STATE_DIR, exist_ok=True)
    if not os.path.exists(WRAPPED_FILE):
        # FIRST BOOT: make a random 32-byte root, wrap with the real Master_KEK
        root = os.urandom(32)
        root_b64 = base64.b64encode(root).decode()
        wrapped = _skr(root_b64, "-w")
        with open(WRAPPED_FILE, "w") as f:
            f.write(wrapped)
        print(
            "[boot] FIRST BOOT: generated Service_Root, wrapped with genuine Master_KEK"
        )
        return root
    else:
        wrapped = open(WRAPPED_FILE).read().strip()
        root_b64 = _skr(wrapped, "-u")  # unwrap with the real private key
        print("[boot] unwrapped Service_Root with genuine Master_KEK")
        return base64.b64decode(root_b64)


def derive(root, info, length=32):
    """Derive a purpose-specific key from the service root with HKDF-SHA256.

    Args:
        root: Plain service-root bytes.
        info: Stable domain label; changing it changes the derived key.
        length: Output length in bytes.

    Returns:
        Derived key bytes. Do not write these bytes or their prefixes to logs.
    """
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(
        root
    )


if __name__ == "__main__":
    root = get_service_root()
    print("[boot] Service_Root ready:", len(root), "bytes (memory only)")
    print("[boot] root fingerprint:", hashlib.sha256(root).hexdigest()[:16], "...")
    print("[boot] BOOT SEQUENCE COMPLETE (service root available)")
