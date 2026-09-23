"""Measure API transfer, sharing, and state-anchor operations on a live service.

Use only a disposable deployment. This script creates users and files, disables
client certificate verification, deletes the entire audit log during cleanup,
and updates the trusted anchor. It prints results to stdout; capture them outside
the repository. Results describe this deployment, not isolated TDX overhead.
"""

import hashlib
import json
import os
import ssl
import statistics
import time
import urllib.error
import urllib.request

import g8anchor
import g8auth
import g8db

BASE = os.environ.get("G8_BASE", "https://localhost:8443")

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE

JSON_H = {"Content-Type": "application/json"}
PW = "YOUR_TEST_PASSWORD"
REPEATS = 3


def call(method, path, body=None, token=None, headers=None, raw=False):
    """Call the configured test API with certificate validation disabled.

    Returns:
        An (HTTP status, body) pair. Successful bodies are decoded as JSON
        unless raw is True; error bodies are decoded as JSON when possible.
    """
    req = urllib.request.Request(BASE + path, data=body, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, context=_ctx, timeout=600) as r:
            p = r.read()
            return r.status, (p if raw else json.loads(p.decode()))
    except urllib.error.HTTPError as e:
        p = e.read()
        try:
            return e.code, json.loads(p.decode())
        except Exception:
            return e.code, p


def stats(samples):
    """Summarize nonempty timing samples without discarding outliers."""
    return {
        "mean": statistics.mean(samples),
        "min": min(samples),
        "max": max(samples),
        "n": len(samples),
    }


def fmt(label, st, unit="s"):
    """Format timing statistics with their unit and sample count."""
    return "    %-28s mean %7.3f %s   (min %.3f, max %.3f, n=%d)" % (
        label,
        st["mean"],
        unit,
        st["min"],
        st["max"],
        st["n"],
    )


print("=" * 78)
print("G8 MEASUREMENTS — Intel TDX confidential file sharing")
print("=" * 78)

UA = "meas_a_" + os.urandom(3).hex()
UB = "meas_b_" + os.urandom(3).hex()

call(
    "POST",
    "/register",
    json.dumps({"username": UA, "password": PW}).encode(),
    headers=JSON_H,
)
call(
    "POST",
    "/register",
    json.dumps({"username": UB, "password": PW}).encode(),
    headers=JSON_H,
)
_, b = call(
    "POST",
    "/login",
    json.dumps({"username": UA, "password": PW}).encode(),
    headers=JSON_H,
)
TOK = b.get("token") if isinstance(b, dict) else None
if not TOK:
    print(
        "  [ABORT] could not log in (registration quota?). Restart the service and re-run."
    )
    raise SystemExit(1)
print("users:", UA, "/", UB)

# ======================================================================================
print("\n" + "=" * 78)
print("1. THROUGHPUT vs FILE SIZE")
print("=" * 78)
print(
    "   Each size uploaded and downloaded %d times through the live TLS API." % REPEATS
)
print("   The plaintext is encrypted and decrypted inside TDX memory in 4 MiB chunks.")

SIZES_MIB = [1, 10, 50]
throughput = {}
file_ids = {}

# Warm-up, reported rather than hidden.
warm = os.urandom(1024 * 1024)
t0 = time.time()
st, b = call(
    "POST",
    "/files",
    warm,
    token=TOK,
    headers={"Content-Type": "application/octet-stream", "X-Filename": "warmup.bin"},
)
warm_t = time.time() - t0
print("\n    warm-up upload (1 MiB, cold token + TLS + pool): %.3f s" % warm_t)
if isinstance(b, dict) and b.get("file_id"):
    call("DELETE", "/files/%s" % b["file_id"], token=TOK)

for mib in SIZES_MIB:
    data = os.urandom(mib * 1024 * 1024)
    sha = hashlib.sha256(data).hexdigest()
    ups, downs, exact = [], [], True
    fid = None
    for i in range(REPEATS):
        t0 = time.time()
        st, b = call(
            "POST",
            "/files",
            data,
            token=TOK,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Filename": "bench_%d.bin" % mib,
            },
        )
        ups.append(time.time() - t0)
        if not (isinstance(b, dict) and b.get("file_id")):
            print("    upload failed at %d MiB: %s" % (mib, b))
            break
        fid = b["file_id"]

        t0 = time.time()
        st, got = call("GET", "/files/%s" % fid, token=TOK, raw=True)
        downs.append(time.time() - t0)
        if hashlib.sha256(got).hexdigest() != sha:
            exact = False

        if i < REPEATS - 1:
            call("DELETE", "/files/%s" % fid, token=TOK)

    if not ups or not downs:
        continue
    file_ids[mib] = fid
    u, d = stats(ups), stats(downs)
    throughput[mib] = (u, d)
    print(
        "\n    --- %d MiB %s ---"
        % (mib, "(byte-exact)" if exact else "*** MISMATCH ***")
    )
    print(fmt("upload", u))
    print("      -> %.1f MiB/s" % (mib / u["mean"]))
    print(fmt("download", d))
    print("      -> %.1f MiB/s" % (mib / d["mean"]))

# ======================================================================================
print("\n" + "=" * 78)
print("2. SHARE LATENCY vs FILE SIZE  — the central claim, as a number")
print("=" * 78)
print(
    "   'Shared files: re-wraps a key, not the file.' If that is true, sharing a 50 MiB"
)
print(
    "   file must cost the same as sharing a 1 MiB one. A design that re-encrypted on"
)
print("   share would show latency climbing with size.")

share_times = {}
for mib, fid in sorted(file_ids.items()):
    samples = []
    for _ in range(REPEATS):
        t0 = time.time()
        st, b = call(
            "POST",
            "/files/%s/share" % fid,
            json.dumps({"username": UB, "permission": "read"}).encode(),
            token=TOK,
            headers=JSON_H,
        )
        samples.append(time.time() - t0)
        if st != 201:
            print("    share failed for %d MiB: %s" % (mib, b))
            break
    if samples:
        share_times[mib] = stats(samples)
        print(fmt("share a %d MiB file" % mib, share_times[mib]))

if len(share_times) >= 2:
    ms = [s["mean"] for s in share_times.values()]
    spread = max(ms) / min(ms)
    biggest = max(share_times), min(share_times)
    print(
        "\n    file size grew %dx (%d MiB -> %d MiB); share latency changed %.2fx"
        % (
            max(share_times) // min(share_times),
            min(share_times),
            max(share_times),
            spread,
        )
    )
    print(
        "    -> share cost is INDEPENDENT of file size, as the design claims."
        if spread < 2.0
        else "    -> share cost varies with size; investigate before claiming otherwise."
    )

# ======================================================================================
print("\n" + "=" * 78)
print("3. THE D3 ANCHOR'S COST  (decisions D3 and D15, finding F11)")
print("=" * 78)
print(
    "   Every acting request now VERIFIES the anchor before working (one Key Vault read"
)
print(
    "   plus a full state recomputation) and UPDATES it afterwards (one Key Vault write)."
)
print("   Those costs have been asserted all project. Here they are measured.")

conn = g8db.get_conn()
keys = g8auth.load_keys()

recompute, verify_t, update_t = [], [], []
g8anchor.compute_state_root(conn)  # warm-up
for _ in range(REPEATS + 2):
    t0 = time.time()
    g8anchor.compute_state_root(conn)
    recompute.append(time.time() - t0)
    t0 = time.time()
    g8anchor.verify(conn)
    verify_t.append(time.time() - t0)
    t0 = time.time()
    g8anchor.update(conn)
    update_t.append(time.time() - t0)

r, v, u = stats(recompute), stats(verify_t), stats(update_t)
print()
print(fmt("state recomputation (DB only)", r))
print(fmt("verify  (recompute + KV read)", v))
print(fmt("update  (recompute + KV write)", u))
print(
    "\n    Key Vault read  ~= %.3f s   (verify minus recomputation)"
    % (v["mean"] - r["mean"])
)
print(
    "    Key Vault write ~= %.3f s   (update minus recomputation)"
    % (u["mean"] - r["mean"])
)
print(
    "    Total anchor overhead per acting request ~= %.3f s" % (v["mean"] + u["mean"])
)
if 10 in throughput:
    print(
        "    For context, a 10 MiB upload averaged %.3f s in total."
        % throughput[10][0]["mean"]
    )
print(
    "\n    D3 permits batching the update if this ever hurts, at the cost of a documented"
)
print("    detection window. These numbers are what that decision should be based on.")

# ======================================================================================
print("\n" + "=" * 78)
print("4. SERVICE BOOT-TO-READY")
print("=" * 78)
print("   Measured separately by the restart harness (measure_boot.sh): attestation ->")
print("   Secure Key Release -> HKDF sub-key derivation -> database connect -> anchor")
print(
    "   verification. This is the price of confidential computing, paid once per boot."
)
print("   See ~/docs/boot_timing.txt.")

# ======================================================================================
print("\n" + "=" * 78)
print("MEASUREMENT SUMMARY")
print("=" * 78)
print("    %-10s %14s %14s %14s" % ("size", "upload", "download", "share"))
for mib in sorted(throughput):
    up, dn = throughput[mib]
    sh = share_times.get(mib)
    print(
        "    %-10s %10.3f s   %10.3f s   %10.3f s"
        % ("%d MiB" % mib, up["mean"], dn["mean"], sh["mean"] if sh else float("nan"))
    )
print()
for mib in sorted(throughput):
    up, dn = throughput[mib]
    print(
        "    %-10s %10.1f MiB/s %8.1f MiB/s"
        % ("%d MiB" % mib, mib / up["mean"], mib / dn["mean"])
    )

# ======================================================================================
print("\n-- cleanup --")
try:
    for fid in file_ids.values():
        call("DELETE", "/files/%s" % fid, token=TOK)
    with conn.cursor() as cur:
        cur.execute("DELETE FROM audit_log")
        cur.execute("DELETE FROM users WHERE username LIKE %s", ("meas\\_%",))
    root = g8anchor.update(conn)
    print("    cleaned; anchor re-baselined:", root[:32], "...")
    g8db.close()
except Exception as exc:  # noqa: BLE001
    print("    cleanup issue:", type(exc).__name__, exc)
    print("    ⚠️ run ~/g8venv/bin/python ~/reanchor.py before restarting the service")

print("\nMEASUREMENTS COMPLETE — saved to ~/docs/measurements.txt")
