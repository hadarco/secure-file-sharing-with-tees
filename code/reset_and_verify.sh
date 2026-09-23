#!/bin/bash
# Reset database state, reanchor, and restart the service.
# Destructive maintenance for disposable deployments only.
# Unlike demo_reset.sh, this does not delete all Blob objects.
# Review deployment paths and docs/setup.md before running.

set -u
cd ~ || exit 1
PY=~/g8venv/bin/python

hr() { echo "=============================================================="; }

# --------------------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------------------

wipe_and_reanchor() {
    # DELETE, not TRUNCATE: after B9 the VM's role holds only SELECT/INSERT/UPDATE/DELETE.
    # TRUNCATE is a destructive DDL-adjacent privilege we deliberately did not grant.
    # Order matters — children before parents, to respect the foreign keys.
    #
    # Note: no explicit .commit() is needed. g8db opens the connection with autocommit=True
    # (the F8 fix), so each DELETE commits as it runs.
    $PY -c "
import g8db, g8anchor
with g8db.get_conn().cursor() as cur:
    for t in ('acl', 'file_keys', 'files', 'user_keys', 'users', 'audit_log'):
        cur.execute('DELETE FROM ' + t)
print('  all tables emptied (DELETE, not TRUNCATE — B9 removed that privilege)')
root = g8anchor.update(g8db.get_conn())
print('  D3 anchor re-baselined to this state: ' + root[:32] + ' ...')
g8db.close()
"
}

start_service() {
    # M17 — MUST be run.py, never bare uvicorn.
    #
    # uvicorn started from the command line leaves the TLS policy at library defaults,
    # which accept TLS 1.2. run.py pins the SSLContext to 1.3 only (decision D20). The
    # listener is configured to require TLS 1.3 as part of its security
    # objective, so "1.3 is what the browser happened to negotiate" does not do -- and
    # whether it was true depended on which script had last started the service.
    setsid nohup $PY ~/run.py < /dev/null > ~/docs/app.log 2>&1 &
    sleep 18
}

hr; echo "STEP 1  stop any running service"; hr
fuser -k -n tcp 8443 2>/dev/null
sleep 2
if ss -ltn 2>/dev/null | grep -q ':8443'; then echo "  WARNING: something still on 8443"; else echo "  port 8443 is free"; fi

hr; echo "STEP 2  wipe every table, then re-baseline the D3 anchor"; hr
wipe_and_reanchor

hr; echo "STEP 3  confirm empty, from a BRAND NEW connection"; hr
$PY -c "
import g8db
with g8db.get_conn().cursor() as cur:
    for t in ('users','user_keys','files','file_keys','acl','audit_log'):
        cur.execute('SELECT count(*) AS n FROM ' + t)
        print('  %-12s %d rows' % (t, cur.fetchone()['n']))
g8db.close()
"

hr; echo "STEP 4  start the service"; hr
echo "  (startup performs the attested Service_Root unwrap AND verifies the D3 anchor;"
echo "   a mismatch here would abort the boot — see app.py, G8_ANCHOR_ENFORCE)"
start_service
echo "  /healthz:"
curl -sk https://localhost:8443/healthz; echo
echo "  ^ expect \"status\":\"ok\" and anchor \"status\":\"verified\""

hr; echo "STEP 5  register ONE user through the API"; hr
curl -sk -X POST https://localhost:8443/register \
     -H 'Content-Type: application/json' \
     -d '{"username":"persisttest1","password":"YOUR_TEST_PASSWORD"}'
echo

hr; echo "STEP 6  *** THE KEY CHECK *** does that row persist?"; hr
echo "  A separate process = a separate DB connection. It can only see COMMITTED data."
$PY -c "
import g8db
with g8db.get_conn().cursor() as cur:
    cur.execute('SELECT user_id, username, created_at FROM users')
    rows = cur.fetchall()
    cur.execute('SELECT count(*) AS n FROM user_keys')
    keks = cur.fetchone()['n']
g8db.close()
print('  users rows visible to a fresh connection: %d' % len(rows))
for r in rows:
    print('    -', r['username'], r['user_id'], r['created_at'])
print('  user_keys rows: %d' % keks)
print()
if len(rows) == 1 and keks == 1:
    print('  VERDICT: PERSISTS CORRECTLY - registration commits properly.')
elif len(rows) == 0:
    print('  VERDICT: *** NOT COMMITTED *** create_user is not persisting. REAL BUG.')
else:
    print('  VERDICT: unexpected state - investigate.')
"

hr; echo "STEP 6b  did /register re-anchor automatically?"; hr
echo "  The anchor must track EVERY mutation, or a rollback to a previously-anchored"
echo "  state becomes indistinguishable from the truth (Evidence 15 limitation)."
curl -sk https://localhost:8443/healthz; echo
echo "  ^ expect anchor \"status\":\"current\" and \"last_mutation\":\"register\""

hr; echo "STEP 7  restart (clears in-memory rate limits) + wipe + full API test"; hr
fuser -k -n tcp 8443 2>/dev/null
sleep 2
wipe_and_reanchor
start_service
echo "  running test_api.py ..."
$PY ~/test_api.py > ~/docs/api_test_results.txt 2>&1
tail -30 ~/docs/api_test_results.txt

hr; echo "STEP 8  final database state"; hr
$PY -c "
import g8db
with g8db.get_conn().cursor() as cur:
    cur.execute('SELECT count(*) AS n FROM users')
    print('  users rows remaining: %d  (0 = test cleaned up after itself)' % cur.fetchone()['n'])
g8db.close()
"

hr; echo "STEP 9  full pytest suite (crypto + persistence)"; hr
$PY -m pytest tests/ -q 2>&1 | tail -12

hr; echo "STEP 10  final re-baseline"; hr
echo "  The test suites write and delete rows DIRECTLY through g8db, bypassing the API,"
echo "  so nothing re-anchored on their behalf. Re-baseline once at the end, deliberately,"
echo "  so the service starts cleanly next time."
wipe_and_reanchor
echo "  anchor check via the API is unavailable here (needs a session token);"
echo "  restart the service and read /healthz to confirm \"status\":\"verified\"."

hr
echo "DONE.  Service is running on https://localhost:8443"
echo "Evidence saved to ~/docs/api_test_results.txt"
hr
