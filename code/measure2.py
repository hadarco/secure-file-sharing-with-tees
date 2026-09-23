"""Measure in-memory file encryption, key wrapping, and password hashing.

The baseline copies bytes in memory; it does not compare TLS transfers or TDX
against a non-TDX machine. Workloads use different sample counts, shown in output.
No live API requests are made by the current measurements.
"""

import os
import ssl
import statistics
import time
import urllib.error
import urllib.request

import g8auth
import g8blob
import g8keys

BASE = os.environ.get("G8_BASE", "https://localhost:8443")
N = 10

_ctx = ssl.create_default_context()
_ctx.check_hostname = False
_ctx.verify_mode = ssl.CERT_NONE


def stats(samples):
    """Median plus the spread, so a reader can judge whether the median means anything."""
    s = sorted(samples)
    return {
        "median": statistics.median(s),
        "mean": statistics.fmean(s),
        "min": s[0],
        "max": s[-1],
        "n": len(s),
    }


def show(label, st, unit="s"):
    """Print benchmark statistics with their unit and sample count."""
    print(
        "    %-38s median %7.4f %s   (mean %.4f, min %.4f, max %.4f, n=%d)"
        % (label, st["median"], unit, st["mean"], st["min"], st["max"], st["n"])
    )


def timed(fn, n=N, warmup=1):
    """Measure repeated calls after recording separate warmup samples.

    Returns:
        A (statistics, warmup_samples) pair. Timings include the work
        performed by fn and do not isolate TDX overhead.
    """
    cold = []
    for _ in range(warmup):
        t = time.perf_counter()
        fn()
        cold.append(time.perf_counter() - t)
    warm = []
    for _ in range(n):
        t = time.perf_counter()
        fn()
        warm.append(time.perf_counter() - t)
    return stats(warm), cold


hr = "=" * 96
print(hr)
print("G8 MEASUREMENTS — PART 2: what the security costs, not just what it costs")
print(time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
print(hr)

# ======================================================================================
print("\n" + hr)
print(
    "1. THE BASELINE — chunked AES-256-GCM with AAD binding vs. no cryptography at all"
)
print(hr)
print(
    """   The same bytes, in memory, on this VM. One path runs the real encryption: a 4 MiB
   chunked container, AES-256-GCM per chunk, each chunk's AAD binding file id, version,
   chunk index and total chunk count. The other path does nothing at all to the bytes.
   The difference is the cost of the confidentiality and integrity properties, isolated
   from the network, the database and Azure."""
)

FID = "00000000-0000-0000-0000-000000000001"
DEK = os.urandom(32)

for label, size in (("1 MiB", 1 << 20), ("10 MiB", 10 << 20), ("50 MiB", 50 << 20)):
    payload = os.urandom(size)
    print("\n    --- %s ---" % label)

    def _manual_encrypt(buf=None):
        buf = payload if buf is None else buf
        cs = g8keys.CHUNK_SIZE
        total = max(1, (len(buf) + cs - 1) // cs)
        out = []
        for i in range(total):
            out.append(
                g8keys.encrypt_chunk(buf[i * cs : (i + 1) * cs], FID, 1, i, total, DEK)
            )
        return out

    def do_nothing():
        # The honest baseline: touch every byte once, so the comparison is not against
        # a no-op the optimiser could elide, but do nothing cryptographic.
        return bytes(memoryview(payload)[:])

    enc, enc_cold = timed(_manual_encrypt, n=max(3, N // 2), warmup=1)
    plain, _ = timed(do_nothing, n=max(3, N // 2), warmup=1)

    show("chunked AES-256-GCM + AAD", enc)
    show("no cryptography (copy only)", plain)
    ratio = enc["median"] / plain["median"] if plain["median"] > 0 else float("inf")
    mbps = (size / (1 << 20)) / enc["median"]
    print("    -> encryption costs %.1fx a plain copy of the same bytes" % ratio)
    print("    -> %.0f MiB/s of pure AES-256-GCM throughput inside the TEE" % mbps)

print(
    "Compare absolute encryption throughput with separately measured end-to-end transfer throughput. The in-memory copy ratio does not measure TDX overhead or isolate every component of request latency."
)

# ======================================================================================
print("\n" + hr)
print("2. WHERE A REQUEST'S TIME ACTUALLY GOES")
print(hr)
print(
    """   An upload is not one operation. It unwraps a User_KEK, generates a File_DEK, wraps it,
   encrypts the filename, seals every chunk, writes to Azure Blob, writes metadata rows,
   appends an audit entry and updates the anchor. Reporting only the total attributes the
   whole cost to "encryption" by implication."""
)

payload = os.urandom(10 << 20)
kek = os.urandom(32)

st, _ = timed(lambda: g8keys.wrap_file_dek(DEK, "u1", FID, 1, kek), n=N)
show("wrap a File_DEK (one AES-GCM op)", st)

st, _ = timed(
    lambda: g8keys.encrypt_filename("quarterly_report_2026.pdf", FID, 1, DEK), n=N
)
show("encrypt a filename", st)


def _seal_all(buf):
    cs = g8keys.CHUNK_SIZE
    total = max(1, (len(buf) + cs - 1) // cs)
    return [
        g8keys.encrypt_chunk(buf[i * cs : (i + 1) * cs], FID, 1, i, total, DEK)
        for i in range(total)
    ]


st, _ = timed(lambda: _seal_all(payload), n=3, warmup=1)
show("seal a 10 MiB file (3 chunks)", st)


print(
    "Compare sealing time with measurements collected on the same deployment. This isolated operation does not include storage, metadata, or anchoring."
)

# ======================================================================================
print("\n" + hr)
print("3. ARGON2id — the cost of the password parameters, measured")
print(hr)
print(
    "   64 MiB, t=3, p=2 was chosen deliberately and exceeds the comparison profile of 19 MiB,\n   t=2, p=1. Stronger parameters cost the user time on every login, and that cost has\n   never been stated. Both are measured here so the choice can be defended with a number."
)

PW = "YOUR_TEST_PASSWORD"
pepper = os.urandom(32)

st, cold = timed(lambda: g8auth.hash_password(PW, pepper), n=max(5, N // 2), warmup=1)
show("hash_password (64 MiB, t=3, p=2)", st)
print("    first (cold) sample: %.4f s" % cold[0])

stored = g8auth.hash_password(PW, pepper)
st, _ = timed(
    lambda: g8auth.verify_password(stored, PW, pepper), n=max(5, N // 2), warmup=1
)
show("verify_password (the login path)", st)

try:
    from argon2 import PasswordHasher

    weak = PasswordHasher(time_cost=2, memory_cost=19 * 1024, parallelism=1)
    st, _ = timed(lambda: weak.hash(PW), n=max(5, N // 2), warmup=1)
    show("comparison profile (19 MiB, t=2, p=1)", st)
except Exception as exc:
    print("    could not measure the comparison profile:", exc)

print(
    "Record parameters and latency together when comparing password-hashing profiles."
)

print("\n" + hr)
print("DONE — saved to ~/docs/measurements2.txt")
print(hr)
