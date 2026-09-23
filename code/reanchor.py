"""Replace the trusted state digest after an independently verified change.

This administrative utility can overwrite evidence of database tampering. It
prints a warning but does not prompt before writing. Stop service activity and
establish why the state changed before invoking it. See docs/setup.md.
"""

import sys

import g8anchor
import g8db

if __name__ == "__main__":
    conn = g8db.get_conn()

    ok, detail = g8anchor.verify(conn)
    print("current status :", detail.get("status"))
    if not ok:
        print("  anchored     :", (detail.get("anchored") or "")[:48], "...")
        print("  current      :", (detail.get("current") or "")[:48], "...")
        print("  meaning      :", detail.get("meaning"))
        print()
        print("  ⚠️  Re-baseline ONLY if you know this change was deliberate.")
        print("      If you did not expect it, that is an attack indicator - stop and")
        print("      investigate before overwriting the evidence.")
    elif detail.get("status") == "match":
        print("nothing to do  : the anchor already matches the database")
        g8db.close()
        sys.exit(0)

    root = g8anchor.update(conn)
    print()
    print("re-baselined   :", root)
    print("domain tag     :", g8anchor.DOMAIN_TAG.decode())
    print("the service will now start cleanly.")
    g8db.close()
