#!/bin/bash
# Delete all configured blobs and database rows, then reanchor and restart.
# Disposable deployments only: this removes user accounts and signing-key records.
# The original harness uses ~/g8venv, home-installed modules, and ~/docs.
# Adapt placeholders and review docs/setup.md before running.

set -u
cd ~ || exit 1
PY=~/g8venv/bin/python
# The service is started via run.py, NOT bare uvicorn: run.py pins the TLS listener to
# 1.3 only (D20). Starting uvicorn directly would silently fall back to accepting TLS 1.2.

hr() { echo "=================================================================="; }

hr; echo " DEMO RESET"; date -u "+ %Y-%m-%d %H:%M:%S UTC"; hr

echo
echo "[1/4] stopping the service"
fuser -k -n tcp 8443 2>/dev/null
sleep 2
if ss -ltn 2>/dev/null | grep -q ':8443'; then
    echo "      WARNING: something is still listening on 8443"
else
    echo "      port 8443 is free"
fi

echo
echo "[2/4] deleting blobs and database rows, then re-anchoring"
$PY -c "
import g8anchor, g8blob, g8db

c = g8blob._client().get_container_client('YOUR_BLOB_CONTAINER')
names = [b.name for b in c.list_blobs()]
for n in names:
    c.delete_blob(n)
print('      blobs deleted : %d' % len(names))

with g8db.get_conn().cursor() as cur:
    # children before parents; DELETE not TRUNCATE (B9 revoked that privilege)
    for t in ('acl', 'file_keys', 'files', 'user_keys', 'users', 'audit_log'):
        cur.execute('DELETE FROM ' + t)
    print('      rows remaining:')
    for t in ('users', 'user_keys', 'files', 'file_keys', 'acl', 'audit_log'):
        cur.execute('SELECT count(*) AS n FROM ' + t)
        print('        %-12s %d' % (t, cur.fetchone()['n']))

root = g8anchor.update(g8db.get_conn())
print('      anchor re-baselined: %s ...' % root[:32])
print('      (mandatory: this script bypasses the API, so nothing re-anchored for it)')
g8db.close()
" || { echo "      *** FAILED — do not start the service until this succeeds ***"; exit 1; }

echo
echo "[3/4] starting the service"
echo "      (attestation -> Secure Key Release -> 6 sub-keys -> DB TLS -> anchor verify)"
setsid nohup $PY ~/run.py < /dev/null > ~/docs/app.log 2>&1 &

READY=""
for i in $(seq 1 100); do
    if curl -sk --max-time 2 https://localhost:8443/healthz 2>/dev/null | grep -q '"status":"ok"'; then
        READY="yes"; break
    fi
    sleep 0.3
done

echo
echo "[4/4] verification"
if [ -z "$READY" ]; then
    echo "      *** the service did not come up. Check ~/docs/app.log ***"
    tail -20 ~/docs/app.log
    exit 1
fi
curl -sk https://localhost:8443/healthz; echo
echo
echo "      expect: status ok · 6 derived keys · TLSv1.3 verify-full · anchor verified"
echo
echo "      TLS policy on the listener:"
grep '\[tls\]' ~/docs/app.log | head -3 | sed 's/^/      /'

# One warm request so the first Key Vault call of the demonstration is not the slow one.
# The anchor's first operation after a restart pays for a fresh TLS handshake, which showed
# up as roughly 1259 ms against ~1180 ms warm during testing (finding F12).
curl -sk https://localhost:8443/ >/dev/null 2>&1

hr
echo " READY."
echo
echo " Open:  https://YOUR_SERVICE_HOST:8443/ui"
echo
echo " Signing-key enrollment was cleared with the audit log."
echo " Use a trusted certificate matching the service hostname."
echo " Registration is capped at 3 accounts per IP per hour."
hr
