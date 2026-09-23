#!/usr/bin/env python3
"""Run legacy cloud validation suites with destructive resets between suites.

This runner expects scripts in the deployment user's home directory, with only
test_crypto.py and test_persist.py under ~/tests. Adapt its placeholder paths to
that layout before use. It deletes deployment data and parses textual counts;
its aggregate result is not a portable or complete security acceptance signal.
"""

import os
import re
import subprocess
import sys
import time

PY = "/home/YOUR_VM_USER/g8venv/bin/python"
HOME = "/home/YOUR_VM_USER"
RESET = "bash %s/demo_reset.sh" % HOME

WITH_ANCHOR = "--with-anchor" in sys.argv
QUICK = "--quick" in sys.argv

# (label, command, needs_reset_first, expected_checks)
SUITES = [
    (
        "test_crypto + test_persist",
        "cd %s && PYTHONPATH=%s %s -m pytest %s/tests/ -q" % (HOME, HOME, PY, HOME),
        True,
        59,
    ),
    ("test_replay", "%s %s/test_replay.py" % (PY, HOME), False, 4),
    ("test_api", "%s %s/test_api.py" % (PY, HOME), True, 20),
    ("e2e_files", "%s %s/e2e_files.py" % (PY, HOME), True, 41),
    ("e2e_share", "%s %s/e2e_share.py" % (PY, HOME), True, 41),
    ("e2e_sign", "%s %s/e2e_sign.py" % (PY, HOME), True, 22),
    ("adversarial", "%s %s/adversarial.py" % (PY, HOME), True, 31),
]

ANCHOR_SUITE = (
    "test_anchor_startup (standalone)",
    "%s %s/test_anchor_startup.py" % (PY, HOME),
    True,
    5,
)


def parse(output):
    """Return (passed, failed). Handles both output styles used across the suites."""
    m = re.search(r"RESULT:\s*(\d+)\s*passed,\s*(\d+)\s*failed", output)
    if m:
        return int(m.group(1)), int(m.group(2))
    # pytest: "59 passed in 5.12s" / "57 passed, 2 failed in 5.12s"
    p = re.search(r"(\d+)\s+passed", output)
    f = re.search(r"(\d+)\s+failed", output)
    if p or f:
        return (int(p.group(1)) if p else 0), (int(f.group(1)) if f else 0)
    return 0, 0


def run(cmd, timeout=900):
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return "TIMEOUT after %ds" % timeout


def reset():
    out = run(RESET, timeout=180)
    return "READY." in out, out


bar = "=" * 78
print(bar)
print("G8 FULL REGRESSION")
print(time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()))
print(bar)
if QUICK:
    print(
        "\n⚠️  --quick: resets are SKIPPED. Expect 429s if more than one suite registers.\n"
    )

rows = []
suites = SUITES + ([ANCHOR_SUITE] if WITH_ANCHOR else [])

for label, cmd, needs_reset, expected in suites:
    print("\n" + "-" * 78)
    print("%-40s" % label, end="", flush=True)

    if needs_reset and not QUICK:
        ok, rout = reset()
        if not ok:
            print(" RESET FAILED")
            print(rout[-1500:])
            rows.append((label, 0, 0, expected, "reset failed"))
            continue
        print(" [reset ok]", end="", flush=True)

    t0 = time.time()
    out = run(cmd)
    secs = time.time() - t0
    passed, failed = parse(out)

    if "TIMEOUT" in out and passed == 0:
        status = "TIMEOUT"
    elif "Traceback" in out and failed == 0 and passed < expected:
        status = "CRASHED"
    elif failed:
        status = "FAILURES"
    elif passed == expected:
        status = "ok"
    else:
        status = "count differs"

    print("  %3d passed, %2d failed  (%.0fs)  %s" % (passed, failed, secs, status))
    rows.append((label, passed, failed, expected, status))

    # Show enough to diagnose without drowning the summary.
    if failed or status in ("CRASHED", "TIMEOUT", "count differs"):
        print("\n    ---- output tail ----")
        for line in out.strip().splitlines()[-25:]:
            print("    " + line[:118])
        print("    ---------------------")

print("\n" + bar)
print("SUMMARY")
print(bar)
print("%-40s %8s %8s %10s  %s" % ("suite", "passed", "failed", "expected", "status"))
print("-" * 78)
tp = tf = te = 0
for label, p, f, e, status in rows:
    print("%-40s %8d %8d %10d  %s" % (label, p, f, e, status))
    tp += p
    tf += f
    te += e
print("-" * 78)
print("%-40s %8d %8d %10d" % ("TOTAL", tp, tf, te))
print(bar)

if tf == 0 and tp == te:
    print("\nAll suites passed at the expected counts.")
else:
    if tf:
        print("\n%d check(s) FAILED." % tf)
    if tp != te:
        print("Total is %d, expected %d — a suite may have aborted early." % (tp, te))
    print("If the service is down, recover with:")
    print("  %s %s/reanchor.py && bash %s/demo_reset.sh" % (PY, HOME, HOME))

sys.exit(1 if (tf or tp != te) else 0)
