#!/usr/bin/env python3
"""Exercise service restart and anchor handling on a disposable deployment.

This script stops the service, changes database state, and rewrites the anchor.
The insert-then-delete stimulus restores the selected state and does not reliably
produce the mismatch the assertions expect. Retained for review; do not use its
summary as release evidence without correcting the scenario.
"""

import os
import subprocess
import sys
import time

sys.path.insert(0, "/home/YOUR_VM_USER")
import g8anchor
import g8db

PY = "/home/YOUR_VM_USER/g8venv/bin/python"
LOG = "/home/YOUR_VM_USER/docs/app.log"
HEALTH = "https://localhost:8443/healthz"

_passed = 0
_failed = 0


def result(label, ok):
    global _passed, _failed
    if ok:
        _passed += 1
    else:
        _failed += 1
    print("  [%s] %s" % ("PASS" if ok else "FAIL", label))
    return ok


def stop_service():
    subprocess.run(["fuser", "-k", "-n", "tcp", "8443"], capture_output=True)
    time.sleep(3)


def try_start(seconds=40):
    """Start the service and report whether it became healthy. Returns (ok, log_tail)."""
    subprocess.Popen(
        "cd /home/YOUR_VM_USER && setsid nohup %s /home/YOUR_VM_USER/run.py "
        "< /dev/null > %s 2>&1 &" % (PY, LOG),
        shell=True,
    )
    for _ in range(seconds * 2):
        out = subprocess.run(
            ["curl", "-sk", "--max-time", "2", HEALTH], capture_output=True, text=True
        ).stdout
        if '"status":"ok"' in out:
            return True, ""
        time.sleep(0.5)
    tail = subprocess.run(["tail", "-25", LOG], capture_output=True, text=True).stdout
    return False, tail


print("=" * 78)
print("D3 anchor: does a mismatch actually REFUSE to start the service?")
print("=" * 78)

print("\n-- 1. stopping the service --")
stop_service()
print("     stopped")

conn = g8db.get_conn()
before = g8anchor.compute_state_root(conn)
print("\n-- 2. anchor before --")
print("     ", before[:32], "...")

print("\n-- 3. changing the database OUTSIDE the API --")
marker = "anchortest_" + os.urandom(4).hex()
with conn.cursor() as cur:
    cur.execute(
        "INSERT INTO users (user_id, username, pw_hash) "
        "VALUES (gen_random_uuid(), %s, %s)",
        (marker, "not-a-real-hash"),
    )
    cur.execute("DELETE FROM users WHERE username = %s", (marker,))
after = g8anchor.compute_state_root(conn)
print("      inserted and deleted a throwaway user; nothing re-anchored for it")
print("     ", after[:32], "...")
result("the database state root changed", before != after)

print("\n-- 4. attempting to start on unanchored state (EXPECT FAILURE) --")
ok, tail = try_start(seconds=40)
result("the service REFUSED to start", not ok)
result(
    "the log names a D3 anchor mismatch",
    "anchor MISMATCH" in tail or "MISMATCH" in tail,
)
if not ok:
    for line in tail.splitlines():
        if "MISMATCH" in line or "RuntimeError" in line:
            print("      >", line.strip()[:110])

print("\n-- 5. re-anchoring --")
root = g8anchor.update(conn)
print("      re-baselined:", root[:32], "...")

print("\n-- 6. attempting to start again (EXPECT SUCCESS) --")
ok2, tail2 = try_start(seconds=45)
result("the service started once the anchor matched", ok2)
if not ok2:
    print(tail2[-800:])

g8db.close()

print("\n" + "=" * 78)
print("RESULT: %d passed, %d failed" % (_passed, _failed))
print("=" * 78)
if _failed:
    print("\nThe service may be stopped. Recover with:")
    print("  %s ~/reanchor.py && bash ~/demo_reset.sh" % PY)
sys.exit(1 if _failed else 0)
