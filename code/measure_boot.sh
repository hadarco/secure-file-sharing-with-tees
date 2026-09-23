#!/bin/bash
# Restart the live service and measure time until readiness.
# This interrupts the listener; use only a disposable deployment.
# Review home-directory paths and docs/setup.md before running.

PY=~/g8venv/bin/python
cd ~ || exit 1

echo "=================================================================="
echo "BOOT-TO-READY MEASUREMENT"
echo "=================================================================="
date -u "+started: %Y-%m-%d %H:%M:%S UTC"

echo
echo "-- 1. attested key release alone (attestation + SKR + unwrap) --"
echo "   3 runs; this is the confidential-computing-specific part."
for i in 1 2 3; do
    S=$(date +%s.%N)
    $PY -c "import boot, hashlib; r = boot.get_service_root(); print('   fingerprint:', hashlib.sha256(r).hexdigest()[:16])" 2>/dev/null | tail -1
    E=$(date +%s.%N)
    echo "   run $i: $(echo "$E - $S" | bc) s"
done

echo
echo "-- 2. full service start to /healthz returning ok --"
fuser -k -n tcp 8443 2>/dev/null
sleep 3
S=$(date +%s.%N)
# M17: run.py, not bare uvicorn -- otherwise this measures the boot time of a service
# with a DIFFERENT TLS policy from the one that is actually deployed (D20).
setsid nohup $PY ~/run.py < /dev/null > ~/docs/app.log 2>&1 &

READY=""
for i in $(seq 1 120); do
    if curl -sk --max-time 2 https://localhost:8443/healthz 2>/dev/null | grep -q '"status":"ok"'; then
        E=$(date +%s.%N)
        READY=$(echo "$E - $S" | bc)
        break
    fi
    sleep 0.25
done

if [ -n "$READY" ]; then
    echo "   service ready after: $READY s"
    echo "   (uvicorn start + attestation + SKR + 6 HKDF sub-keys + DB TLS connect + anchor verify)"
else
    echo "   *** service did not become ready within 30 s - check ~/docs/app.log ***"
fi

echo
echo "-- 3. what /healthz reports --"
curl -sk https://localhost:8443/healthz; echo

echo
echo "-- 4. system uptime (how long since the VM itself booted) --"
uptime -p
echo "=================================================================="
