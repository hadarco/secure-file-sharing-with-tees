"""Serve the confidential file-sharing API and coordinate its security checks.

Startup loads the service root, derives subkeys, and checks stored integrity state.
Request handlers combine authentication, key access, storage, auditing, and signing.
See docs/security-model.md for enforcement gaps and trust assumptions. Clearing
Python references on shutdown does not guarantee zeroization of key bytes.
"""

import itertools
import os
import time
import uuid
from collections import defaultdict, deque
from contextlib import asynccontextmanager
from urllib.parse import quote, unquote

from fastapi import FastAPI, HTTPException, Header, Request, status
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

import g8anchor
import g8audit
import g8auth
import g8blob
import g8db
import g8keys
import g8sign
from boot import get_service_root, derive

# in-memory key material (never written to disk)
KEYS = {}

# Anchor enforcement is coordinated here. Strict mode rejects detected mismatch;
# startup dependency failures can instead leave state unverified. See the security
# model for request coverage and concurrency limits.
ANCHOR_ENFORCE = os.environ.get("G8_ANCHOR_ENFORCE", "strict").lower()

ANCHOR = {
    "status": "not_checked",
    "enforce": ANCHOR_ENFORCE,
    "stale": False,
    "state_root": None,
}

# Audit-chain state, reported by /healthz alongside the anchor. The two are
# separate mechanisms answering separate questions -- "is this the state we anchored?" and
# "is this log internally consistent and keyed by us?" -- so they are reported separately
# rather than collapsed into one flag.
CHAIN = {
    "status": "not_checked",
    "entries": None,
}


def _anchor_startup_check():
    """Check the selected database state against the trusted anchor.

    Strict enforcement aborts on detected mismatch or unauthorized absence.
    Dependency exceptions record an unverified state and allow startup to continue.
    """
    try:
        conn = g8db.get_conn()
        ok, detail = g8anchor.verify(conn)
    except Exception as exc:  # noqa: BLE001
        ANCHOR.update(
            {
                "status": "unverified",
                "reason": "could not reach the database or Key Vault: %s"
                % type(exc).__name__,
            }
        )
        print("[anchor] WARNING: startup verification could not run:", exc)
        return

    if detail.get("status") == "NO_ANCHOR":
        # the secret is absent and bootstrapping was NOT explicitly requested. Under
        # strict enforcement this stops the service, because a vanished anchor is
        # indistinguishable from an attacker removing it to disable rollback detection.
        ANCHOR.update(
            {"status": "NO_ANCHOR", "stale": True, "meaning": detail.get("meaning")}
        )
        print("[anchor] *** NO ANCHOR IN KEY VAULT ***")
        print("[anchor]", detail.get("meaning"))
        if ANCHOR_ENFORCE == "strict":
            raise RuntimeError(
                "no D3 anchor exists in Key Vault. If this is a genuine first run, start "
                "once with G8_BOOTSTRAP_ANCHOR=1. If it is not, the secret was deleted - "
                "investigate before re-creating it, because re-creating it destroys the "
                "only evidence of what the state used to be."
            )
        print("[anchor] G8_ANCHOR_ENFORCE=warn - continuing with no anchor")
        return

    if detail.get("status") == "no_anchor_yet":
        # First ever run against this vault secret. Anchoring the current state is the
        # only sensible bootstrap: there is nothing to compare against yet.
        root = g8anchor.update(conn)
        ANCHOR.update({"status": "initialised", "state_root": root, "stale": False})
        print("[anchor] no anchor existed; initialised to", root[:32], "...")
        return

    if ok:
        ANCHOR.update(
            {
                "status": "verified",
                "state_root": detail.get("state_root"),
                "stale": False,
            }
        )
        print(
            "[anchor] verified against Key Vault:",
            (detail.get("state_root") or "")[:32],
            "...",
        )
        return

    # MISMATCH: rows were deleted, or an older snapshot was restored.
    ANCHOR.update(
        {
            "status": "MISMATCH",
            "anchored": detail.get("anchored"),
            "current": detail.get("current"),
            "meaning": detail.get("meaning"),
            "stale": True,
        }
    )
    print("[anchor] *** MISMATCH *** anchored:", (detail.get("anchored") or "")[:32])
    print("[anchor] *** MISMATCH *** current :", (detail.get("current") or "")[:32])
    print("[anchor] meaning:", detail.get("meaning"))

    if ANCHOR_ENFORCE == "strict":
        raise RuntimeError(
            "D3 anchor MISMATCH at startup: the external database no longer matches the "
            "state anchored in Key Vault (rows deleted, or an older snapshot restored). "
            "Refusing to start. If this change was deliberate (an administrative reset), "
            "re-anchor explicitly, or start once with G8_ANCHOR_ENFORCE=warn."
        )
    print("[anchor] G8_ANCHOR_ENFORCE=warn - continuing despite the mismatch")


def _audit_chain_startup_check():
    """Verify audit payload HMACs independently of stored anchor hashes.

    Strict mode aborts on a broken chain. Database/verification exceptions record
    an unverified state and allow startup to continue.
    """
    try:
        chain = g8audit.verify_chain(g8db.get_conn(), KEYS)
    except Exception as exc:  # noqa: BLE001
        CHAIN.update({"status": "unverified", "reason": type(exc).__name__})
        print("[chain] WARNING: startup verification could not run:", exc)
        return

    if chain.get("ok"):
        CHAIN.update(
            {
                "status": "verified",
                "entries": chain.get("entries"),
                "head": (chain.get("head") or "")[:32],
            }
        )
        print("[chain] audit chain verified: %d entries" % chain.get("entries", 0))
        return

    CHAIN.update(
        {
            "status": "BROKEN",
            "entries": chain.get("entries"),
            "broken_at": chain.get("broken_at"),
            "reason": chain.get("reason"),
        }
    )
    print("[chain] *** BROKEN *** first bad link at seq", chain.get("broken_at"))
    print("[chain] reason:", chain.get("reason"))

    if ANCHOR_ENFORCE == "strict":
        raise RuntimeError(
            "audit chain BROKEN at seq %s: %s. An entry was edited, forged, removed or "
            "reordered in the untrusted database. Refusing to start. If this was a "
            "deliberate administrative reset, clear the log and re-anchor, or start once "
            "with G8_ANCHOR_ENFORCE=warn."
            % (chain.get("broken_at"), chain.get("reason"))
        )
    print("[chain] G8_ANCHOR_ENFORCE=warn - continuing despite the broken chain")


def _anchor_after_mutation(what: str):
    """Accept current state as the baseline after an application mutation.

    Retries Key Vault writes three times. Failure marks the process's anchor state
    stale rather than undoing an already committed mutation. Callers must establish
    that the state being accepted is authorized.
    """
    last_exc = None
    for attempt in range(3):
        try:
            root = g8anchor.update(g8db.get_conn())
            ANCHOR.update(
                {
                    "status": "current",
                    "state_root": root,
                    "stale": False,
                    "last_mutation": what,
                }
            )
            ANCHOR.pop("write_failed", None)
            return
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            if attempt < 2:
                time.sleep(0.25 * (attempt + 1))

    # a Key Vault write failure is NOT tampering, and must not be reported
    # as tampering. The database has moved and the anchor has not, so every later call to
    # _verify_state_before_acting would find a genuine mismatch and return 409 "state
    # integrity check failed" - sending an operator hunting an attacker who does not
    # exist, while the service refuses all work until someone runs reanchor.py by hand.
    #
    # The flag below makes the two distinguishable: 503 "we could not write the anchor"
    # instead of 409 "the state does not match". Same refusal to act, honest reason.
    ANCHOR.update(
        {
            "status": "STALE",
            "stale": True,
            "write_failed": True,
            "error": type(last_exc).__name__,
            "last_mutation": what,
        }
    )
    print(
        "[anchor] WARNING: failed to re-anchor after %r after 3 attempts: %s"
        % (what, last_exc)
    )


def _verify_state_before_acting():
    """Reject protected operations when the stored state cannot be trusted.

    This is a point-in-time comparison, not a lock across the subsequent operation.
    Request-time mismatches are rejected regardless of the startup enforcement mode.

    Raises:
        HTTPException: State cannot be verified, a previous anchor write failed,
            or the current state does not match the trusted baseline.
    """
    # if our OWN last anchor write failed, the mismatch below is ours, not an
    # attacker's. Say so, and use a status code that means "our problem".
    if ANCHOR.get("write_failed"):
        raise HTTPException(
            status_code=503,
            detail="the state anchor could not be written after the last mutation (%s), "
            "so the database and the anchor are known to disagree for an innocent "
            "reason. This is NOT a tampering indicator. Retrying automatically; "
            "run reanchor.py if it persists." % ANCHOR.get("error"),
        )

    try:
        ok, detail = g8anchor.verify(g8db.get_conn())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail="cannot verify state integrity (%s); refusing to act"
            % type(exc).__name__,
        )

    if not ok and detail.get("status") == "NO_ANCHOR":
        ANCHOR.update({"status": "NO_ANCHOR", "stale": True})
        raise HTTPException(
            status_code=409,
            detail="no state anchor exists in Key Vault, so this database cannot be "
            "checked against anything. Refusing to act. A missing anchor is how "
            "rollback detection would be disabled - investigate before re-creating "
            "it.",
        )

    if not ok:
        ANCHOR.update(
            {
                "status": "MISMATCH",
                "stale": True,
                "anchored": detail.get("anchored"),
                "current": detail.get("current"),
            }
        )
        raise HTTPException(
            status_code=409,
            detail="state integrity check failed: the metadata database no longer "
            "matches the Key Vault anchor (rows deleted, or an older snapshot "
            "restored). Refusing to act. Investigate before re-baselining — "
            "re-anchoring an unexplained mismatch destroys the evidence.",
        )


def _signed_detail(base, signed):
    """Attach complete signed bytes to encrypted audit detail.

    Returns:
        Detail containing the original statement, signature, and key fingerprint,
        so later verification does not depend on reconstructing signed bytes.
    """
    if not signed:
        return (base + " [unsigned]") if base else "[unsigned]"
    part = "stmt=%s sig=%s key=%s" % (
        signed["statement"],
        signed["signature"],
        signed["key_fingerprint"],
    )
    return (base + " | " + part) if base else part


def _require_signature(
    action: str,
    user_id: str,
    file_id: str,
    target: str,
    statement: str,
    signature: str,
    permission: str = "",
):
    """Enforce signing for accounts with an enrolled public key.

    Accounts without a key may use unsigned requests. An unavailable
    registry is not treated as an account without a key. Attribution
    assumes trusted enrollment and browser code.

    Args:
        action: Expected operation name.
        user_id: Authenticated caller identifier.
        file_id: File named by the request.
        target: Recipient name or identifier expected for this operation.
        statement: Base64 canonical statement supplied by the client.
        signature: Base64 raw P-256 signature over that statement.
        permission: Expected share permission, or an empty string.

    Returns:
        Verified statement evidence, or None for an unenrolled account.

    Raises:
        HTTPException: The registry is unavailable, a required signature
            is absent, or signature/context verification fails.
    """
    if g8sign.REGISTRY_DEGRADED:
        raise HTTPException(
            status_code=503,
            detail="the client-key registry did not load cleanly, so %s cannot be "
            "authorised right now. This is an attack indicator: check /audit/verify "
            "and the service log." % action,
        )
    if not g8sign.has_key(user_id):
        return None
    if not statement or not signature:
        raise HTTPException(
            status_code=400,
            detail="this account has a registered signing key, so %s must be signed"
            % action,
        )
    try:
        return g8sign.verify(
            action, user_id, file_id, target, statement, signature, permission
        )
    except g8sign.SignatureError as exc:
        raise HTTPException(status_code=401, detail="signature rejected: %s" % exc)


def _audit(action: str, **kw):
    """Record an event, then update the trusted state digest.

    Callers must verify the existing anchor before their first mutation,
    including an audit-only mutation. Checking here would be too late for
    operations that have already changed the database.

    Args:
        action: Audit event name.
        **kw: Actor, file, and detail fields forwarded to safe_append().

    Raises:
        HTTPException: A required audit write failed after the action
            committed; the error does not mean the action was rolled back.
    """
    # safe_append RAISES for the actions in g8audit.MUST_LOG. The mutation has already
    # committed at this point, so this cannot be undone -- but reporting success over a
    # missing accountability record would be the worse of the two lies. 500 with an honest
    # message, and the anchor still updated so the state stays consistent.
    try:
        g8audit.safe_append(g8db.get_conn(), KEYS, action, **kw)
    except g8audit.AuditError as exc:
        _anchor_after_mutation(action)
        raise HTTPException(
            status_code=500,
            detail="the action completed but could not be recorded in the audit log (%s). "
            "Treat the action as done and the record as missing." % exc,
        )
    _anchor_after_mutation(action)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup: the confidential-computing boot sequence ---
    """Bootstrap keys and integrity state, then release resources on shutdown.

    Startup invokes the external SKR client. Clearing key references on
    shutdown does not guarantee memory zeroization.

    Args:
        app: FastAPI application supplied by the lifespan protocol.

    Yields:
        Control to the application after initialization.
    """
    root = get_service_root()  # attested unwrap of Service_Root
    KEYS["service_root"] = root
    KEYS["user_kek_wrap"] = derive(root, b"g8:userkek-wrap:v1")
    KEYS["pepper"] = derive(root, b"g8:pepper:v1")
    KEYS["session_hmac"] = derive(root, b"g8:session-hmac:v1")
    KEYS["acl_mac"] = derive(root, b"g8:acl-mac:v1")
    KEYS["audit_hmac"] = derive(root, b"g8:audit-hmac:v1")
    KEYS["audit_enc"] = derive(root, b"g8:audit-enc:v1")
    print("[app] startup complete - Service_Root unwrapped, keys derived in memory")
    # G8_ANCHOR_ENFORCE is a plain environment variable with no integrity protection,
    # so the least this can do is refuse to be quiet about it. 'warn' means a rolled-back
    # database will NOT stop the service, which is a demonstration setting, not a
    # deployment one.
    if ANCHOR_ENFORCE != "strict":
        print("[app] " + "!" * 68)
        print(
            "[app] !! G8_ANCHOR_ENFORCE=%s - a D3 anchor MISMATCH will NOT stop this"
            % ANCHOR_ENFORCE
        )
        print(
            "[app] !! service. Rollback and deletion of database rows are DETECTED but"
        )
        print(
            "[app] !! NOT ENFORCED. This is a demonstration mode. Unset it to restore"
        )
        print("[app] !! fail-closed behaviour (decision D10).")
        print("[app] " + "!" * 68)

    # Only now, with key material in hand, is the state anchor meaningful.
    _anchor_startup_check()

    # The anchor proves the audit hashes are the ones we anchored; the chain proves those
    # hashes are internally consistent and were produced with the TEE-held audit key.
    # Neither subsumes the other, so both run.
    _audit_chain_startup_check()

    # Rebuild the client-key registry from the audit log. The log is the store of
    # record; this in-memory map is a cache derived from it, and therefore inherits the
    # keyed chain and the state anchor rather than needing protection of its own.
    # A failure here does NOT silently disable signature enforcement. The
    # registry marks itself degraded, _require_signature refuses signable actions with 503,
    # and /healthz reports it. The service still starts, so an operator can diagnose the
    # problem rather than facing a machine that will not boot.
    try:
        n = g8sign.load_registry(g8db.get_conn(), KEYS)
        print("[sign] loaded %d client public key(s) from the audit log" % n)
        if g8sign.REGISTRY_DEGRADED:
            print(
                "[sign] *** signable actions will be REFUSED until this is resolved ***"
            )
    except Exception as exc:  # noqa: BLE001
        g8sign.REGISTRY_DEGRADED = True
        g8sign.REGISTRY_ERROR = "load_registry raised %s: %s" % (
            type(exc).__name__,
            exc,
        )
        print("[sign] *** REGISTRY DEGRADED ***", g8sign.REGISTRY_ERROR)
        print("[sign] *** share, revoke and delete will be REFUSED with 503 ***")

    yield
    # --- shutdown: drop key material (see the module docstring, M30) ---
    KEYS.clear()
    g8db.close()
    print("[app] shutdown - key material cleared")


# /docs, /redoc and /openapi.json are mounted by default and served with no
# authentication. They publish the whole API surface -- including the demonstration
# endpoints -- to anyone who finds the host. Nothing in this project consumes them.
app = FastAPI(
    title="TDX Confidential File Sharing",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


# ======================================================================================
# Response headers and error handling
# ======================================================================================


@app.middleware("http")
async def _security_headers(request: Request, call_next):
    """Attach browser security headers to responses.

    The UI currently uses inline script and style, so its CSP permits unsafe-inline.
    These headers do not replace output handling or a trusted browser origin.
    """
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline'; "  # see the limitation above
        "style-src 'self' 'unsafe-inline'; "
        "connect-src 'self'; "
        "img-src 'self' data:; "
        "base-uri 'none'; "
        "form-action 'none'; "
        "frame-ancestors 'none'; "
        "object-src 'none'"
    )
    # The service is TLS 1.3 only, so instructing browsers never to try plaintext
    # costs nothing and closes the first-request downgrade window.
    response.headers["Strict-Transport-Security"] = (
        "max-age=63072000; includeSubDomains"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.exception_handler(Exception)
async def _unhandled(request: Request, exc: Exception):
    """Return an opaque 500 rather than a stack trace.

    A traceback discloses file paths, library versions and sometimes internal state. The
    detail goes to the service log, where the operator can read it and the network cannot.
    Found worth doing by adversarial test T12, which is the only test that asks how the
    system behaves when it is BROKEN rather than when it is attacked.
    """
    print(
        "[error] unhandled %s on %s %s: %s"
        % (type(exc).__name__, request.method, request.url.path, exc)
    )
    return JSONResponse(status_code=500, content={"detail": "internal error"})


# ======================================================================================
# Rate limiting / lockout  (mitigates login brute force on attack surface AS1)
# ======================================================================================
#
# Deliberately in-memory, not in the database:
#   * The DB is untrusted - an attacker with write access could simply clear their own
#     failure counters, which would make the control worthless.
#   * Counters in TEE memory cannot be tampered with from outside.
#
# Documented limitation: state resets when the service restarts, and it does not span
# multiple instances. For a single-VM deployment that is acceptable; a horizontally scaled
# deployment would need a shared, integrity-protected counter store.

MAX_FAILURES = 5  # failures allowed within the window
WINDOW_SECONDS = 300  # 5 minutes
LOCKOUT_SECONDS = 900  # 15 minutes after tripping the limit

REGISTER_MAX = 3  # registrations per IP per window
REGISTER_WINDOW = 3600

# bounding /audit/verify without ever refusing or faking an answer.
#
# Two wrong designs preceded this one, and both are worth recording because they failed in
# the same way. A per-user COOLDOWN returning 429 refused the check exactly when a caller
# had most reason to run it: e2e_share verifies, tampers, and verifies again, which is
# correct behaviour that the throttle broke. Caching the whole RESULT was worse -- it
# answered the second call with a stale "log intact" over a log that had just been
# tampered with. A security check that can return a comforting cached answer is not a
# check.
#
# The mistake in both was treating this endpoint as one cost. It is two:
#
#   the chain walk    local CPU, O(entries), no external call      -> ALWAYS run it
#   the anchor read   a Key Vault request, rate limited and billed -> cache briefly
#
# The scarce resource is the second one, and it is the only one cached. Tampering with the
# log is always detected on the spot, and a flood costs one Key Vault read every few
# seconds rather than one per request.
ANCHOR_READ_CACHE_SECONDS = 5
_anchor_read_cache = {"at": 0.0, "ok": None, "status": None}

_failures = defaultdict(deque)  # key -> timestamps of recent failures
_locked_until = {}  # key -> unix time
_registrations = defaultdict(deque)


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


# these three tables gained a permanent entry for every distinct username|IP and every
# distinct IP, and nothing ever removed one. Old timestamps inside a deque were trimmed, but
# the KEY stayed forever -- so an attacker looping /login with random usernames added one
# permanent dict entry per attempt, against the same process that holds every key in the
# system. Swept periodically rather than on every call: the work is proportional to the
# table, and doing it 500 times less often makes it free without changing the bound.
_SWEEP_EVERY = 500
_sweep_counter = 0


def _sweep_rate_limit_tables(force: bool = False) -> None:
    global _sweep_counter
    _sweep_counter += 1
    if not force and _sweep_counter % _SWEEP_EVERY:
        return
    now = time.time()
    for key in [
        k for k, q in _failures.items() if not q or q[-1] < now - WINDOW_SECONDS
    ]:
        # Never drop a key that is still serving a lockout, or the lockout is forgotten.
        if _locked_until.get(key, 0) < now:
            _failures.pop(key, None)
    for key in [k for k, until in _locked_until.items() if until < now]:
        _locked_until.pop(key, None)
    for ip in [
        k for k, q in _registrations.items() if not q or q[-1] < now - REGISTER_WINDOW
    ]:
        _registrations.pop(ip, None)


def _check_locked(key: str):
    until = _locked_until.get(key)
    if until and time.time() < until:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="too many failed attempts; try again in %d seconds"
            % int(until - time.time()),
        )


def _record_failure(key: str):
    _sweep_rate_limit_tables()
    now = time.time()
    q = _failures[key]
    q.append(now)
    while q and q[0] < now - WINDOW_SECONDS:
        q.popleft()
    if len(q) >= MAX_FAILURES:
        _locked_until[key] = now + LOCKOUT_SECONDS
        q.clear()


def _record_success(key: str):
    _failures.pop(key, None)
    _locked_until.pop(key, None)


def _check_register_quota(ip: str):
    _sweep_rate_limit_tables()
    now = time.time()
    q = _registrations[ip]
    while q and q[0] < now - REGISTER_WINDOW:
        q.popleft()
    if len(q) >= REGISTER_MAX:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="registration limit reached; try again later",
        )
    q.append(now)


# ======================================================================================
# Request / response models
# ======================================================================================


class Credentials(BaseModel):
    """Carry account credentials and an optional enrollment key.

    Attributes:
        username: Account name used for registration or login.
        password: Plaintext password received over the TLS connection.
        pubkey: Optional base64 DER SPKI key used during registration.
    """

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    # Optional SPKI DER public key, base64. Supplied by the browser client; omitted
    # by curl, the test suites, and any other non-signing client.
    pubkey: str = Field(default="", max_length=2048)


class RegisterResponse(BaseModel):
    """Identify the newly registered account."""

    user_id: str
    username: str


class LoginResponse(BaseModel):
    """Return a bearer token and its lifetime.

    Attributes:
        token: HMAC-authenticated bearer token.
        expires_in: Token lifetime in seconds.
    """

    token: str
    expires_in: int


# ======================================================================================
# Session helper
# ======================================================================================


def _require_session(authorization: str) -> str:
    """Authenticate a token and require its account to still exist.

    Returns:
        The subject user identifier.

    Raises:
        HTTPException: The token/account is invalid or the account store cannot
            be reached. This helper does not verify the database state anchor.
    """
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="missing bearer token")

    token = authorization.split(" ", 1)[1].strip()
    user_id = g8auth.verify_session(token, KEYS["session_hmac"])
    if not user_id:
        raise HTTPException(status_code=401, detail="invalid or expired session")

    try:
        still_there = g8db.user_exists(user_id)
    except Exception:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail="cannot validate session: the account store is unreachable",
        )

    if not still_there:
        raise HTTPException(
            status_code=401,
            detail="session subject no longer exists",
        )

    return user_id


# ======================================================================================
# Endpoints
# ======================================================================================


@app.get("/")
def root():
    """Return service identification without checking dependencies."""
    return {
        "service": "G8 Secure File Sharing",
        "tee": "Intel TDX",
        "status": "running",
    }


@app.get("/healthz")
def healthz():
    """Report dependency reachability and cached security state.

    Database and Blob reachability are checked live. Key availability
    reflects completed startup; this response is not attestation evidence
    independently verified by the browser.

    Returns:
        Aggregate status plus key names, connection diagnostics, and
        cached anchor/chain state. An unverified chain can currently
        count as healthy in the aggregate calculation.
    """
    db_ok, db_detail = False, None
    try:
        hc = g8db.healthcheck()
        # `ssl` was selected from pg_stat_ssl and then ignored, while "verify-full"
        # was printed as a hardcoded string. A dashboard that reports a constant is not a
        # check -- it would have said verify-full on an unverified connection. The measured
        # value is now what decides db_ok, and the one value that genuinely cannot be
        # measured from inside the session is labelled as coming from the config.
        db_ok = bool(hc.get("ssl"))
        db_detail = {
            # the database username used to be published here to unauthenticated
            # callers. It is the VM's managed identity, which is not a secret, but naming
            # the exact principal to anyone who asks is free reconnaissance for no benefit.
            # Authenticated callers still get it from /healthz/detail.
            "ssl": hc.get("ssl"),
            "tls": hc["tls"],
            "cipher": hc["cipher"],
            "sslmode": "verify-full (from the connection string, not measured here)",
        }
        if not db_ok:
            db_detail["error"] = "database connection is NOT using TLS"
    except Exception as exc:  # noqa: BLE001
        db_detail = {"error": type(exc).__name__}

    blob_ok, blob_detail = False, None
    try:
        blob_detail = g8blob.healthcheck()
        blob_ok = True
    except Exception as exc:  # noqa: BLE001
        blob_detail = {"error": type(exc).__name__}

    anchor_ok = ANCHOR.get("status") in ("verified", "current", "initialised")
    chain_ok = (
        CHAIN.get("status") in ("verified", "unverified")
        and not g8audit.UNDECRYPTABLE_SEQS
        and not g8audit.WRITE_FAILURES
    )
    registry_ok = not g8sign.REGISTRY_DEGRADED

    return {
        "status": (
            "ok"
            if (KEYS and db_ok and blob_ok and anchor_ok and chain_ok and registry_ok)
            else "degraded"
        ),
        # Reported because a silently degraded registry is exactly the state finding H14's
        # attack chain tries to reach, and an alarm nobody can see is not an alarm.
        # entries that would not decrypt, remembered across requests. This is where
        # the first step of the H14 chain becomes visible while the service is running.
        "audit_undecryptable": sorted(g8audit.UNDECRYPTABLE_SEQS) or None,
        # audit writes that failed. Previously these existed only as a line on stdout.
        "audit_write_failures": len(g8audit.WRITE_FAILURES) or None,
        "client_key_registry": {
            "ok": registry_ok,
            "keys_loaded": len(g8sign._pubkeys),
            "error": g8sign.REGISTRY_ERROR,
        },
        "service_root_loaded": "service_root" in KEYS,
        "derived_keys": [k for k in KEYS if k != "service_root"],
        "external_db": db_detail,
        "blob_store": blob_detail,
        # a broken chain is now visible without anyone calling /audit/verify.
        "audit_chain": {
            "status": CHAIN.get("status"),
            "entries": CHAIN.get("entries"),
            "broken_at": CHAIN.get("broken_at"),
        },
        "anchor": {
            "status": ANCHOR.get("status"),
            "enforce": ANCHOR.get("enforce"),
            "stale": ANCHOR.get("stale"),
            # truncated: enough to compare by eye during a demo, short enough to read
            "state_root": (ANCHOR.get("state_root") or "")[:32] or None,
            # Keep recent action details behind the authenticated /healthz/detail route.
        },
    }


@app.get("/healthz/detail")
def healthz_detail(authorization: str = Header(default="")):
    """Return operational diagnostics to an authenticated caller."""
    _require_session(authorization)
    try:
        hc = g8db.healthcheck()
        db = {
            "connected_as": hc["user"],
            "ssl": hc.get("ssl"),
            "tls": hc["tls"],
            "cipher": hc["cipher"],
        }
    except Exception as exc:  # noqa: BLE001
        db = {"error": type(exc).__name__}
    return {
        "external_db": db,
        "anchor": {
            "status": ANCHOR.get("status"),
            "state_root": ANCHOR.get("state_root"),
            "last_mutation": ANCHOR.get("last_mutation"),
            "enforce": ANCHOR.get("enforce"),
        },
        "audit_chain": CHAIN,
        "client_key_registry": {
            "keys_loaded": len(g8sign._pubkeys),
            "degraded": g8sign.REGISTRY_DEGRADED,
            "error": g8sign.REGISTRY_ERROR,
        },
        "audit_undecryptable": sorted(g8audit.UNDECRYPTABLE_SEQS) or None,
    }


@app.get("/anchor/verify")
def anchor_verify(authorization: str = Header(default="")):
    """Compare live database state with Key Vault on demand.

    Returns:
        A verdict and comparison details. A detected mismatch remains an
        HTTP 200 response with an explicit negative verdict in its body.
    """
    _require_session(authorization)

    try:
        ok, detail = g8anchor.verify(g8db.get_conn())
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=503,
            detail="anchor verification unavailable: %s" % type(exc).__name__,
        )

    ANCHOR.update(
        {
            "status": "verified" if ok else "MISMATCH",
            "stale": not ok,
            "state_root": detail.get("state_root") or detail.get("current"),
        }
    )

    return {
        "ok": ok,
        "verdict": (
            "state matches the Key Vault anchor"
            if ok
            else "STATE DIVERGED - rows deleted, or an older snapshot restored"
        ),
        "detail": detail,
    }


@app.post("/register", response_model=RegisterResponse, status_code=201)
def register(creds: Credentials, request: Request):
    """Create an account and optionally enroll its browser signing key.

    Account creation precedes public-key validation/persistence. A later error can
    leave an account created without completing the intended key enrollment.
    """
    _check_register_quota(_client_ip(request))
    _verify_state_before_acting()
    try:
        user_id = g8db.create_user(creds.username, creds.password, KEYS)
    except g8db.RegistrationError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # MUTATION: a users row and a user_keys row now exist. Re-anchor so the Key Vault
    # state root describes this database, not the one that existed a moment ago.
    _audit("register", user_id=user_id)

    # D19: record the client's signing key AS AN AUDIT ENTRY rather than in a new column.
    # Two reasons, in ascending order of importance. The VM's database role holds no DDL
    # privilege after B9, so a schema change would need the bootstrap credential. And the
    # log is the better home anyway: key registration is a security-relevant event an
    # auditor wants to see, and storing it here means the key inherits the keyed chain
    # (it cannot be edited or forged) and the state anchor (it cannot be silently removed).
    if creds.pubkey:
        # validate, PERSIST, then activate, in that order.
        #
        # This used to call register_key() first, which put the key straight into the
        # in-memory registry, and only then write the audit entry that persists it via
        # _audit -> safe_append, which swallows failures. So a failed write left the key
        # live for this process and gone after the next restart, flipping the account
        # between the signed and unsigned paths with nothing recorded either way.
        #
        # g8audit.append is used directly here rather than safe_append, because for THIS
        # entry a write failure must fail the request: the audit log is the store of
        # record for public keys, so an unwritten entry means an unregistered key.
        try:
            g8sign.register_key(user_id, creds.pubkey)  # validate only
        except g8sign.SignatureError as exc:
            raise HTTPException(status_code=400, detail="public key rejected: %s" % exc)

        try:
            g8audit.append(
                g8db.get_conn(),
                KEYS,
                "key_register",
                user_id=user_id,
                detail=creds.pubkey,
            )
            _anchor_after_mutation("key_register")
        except Exception as exc:  # noqa: BLE001
            g8sign._pubkeys.pop(str(user_id), None)  # do not leave it half-live
            raise HTTPException(
                status_code=503,
                detail="the account was created, but its signing key could not be "
                "recorded (%s). Register a key again before signing actions."
                % type(exc).__name__,
            )
        print(
            "[sign] registered client key %s for %s"
            % (g8sign.fingerprint(user_id, short=True), user_id)
        )

    return RegisterResponse(user_id=user_id, username=creds.username.strip())


@app.post("/login", response_model=LoginResponse)
def login(creds: Credentials, request: Request):
    # Lock on username AND source IP: locking on username alone would let an attacker
    # lock a victim out of their own account by failing on purpose.
    """Verify state and credentials, then issue and audit a session.

    Failed authentication contributes to the process-local lockout state.
    """
    key = "%s|%s" % (creds.username, _client_ip(request))
    _check_locked(key)
    _verify_state_before_acting()

    user_id = g8db.authenticate(creds.username, creds.password, KEYS)
    if not user_id:
        _record_failure(key)
        # Same message for unknown user and wrong password - see g8db.authenticate.
        raise HTTPException(status_code=401, detail="invalid credentials")

    _record_success(key)
    _audit("login", user_id=user_id)
    token = g8auth.issue_session(user_id, KEYS["session_hmac"])
    # an earlier comment here claimed login "is deliberately NOT a mutation for
    # anchoring purposes". The code says otherwise and the code is right -- _audit()
    # above writes an audit row, that row is part of the state the anchor covers, and
    # skipping the re-anchor would leave the anchor describing a log that is already out
    # of date. It does put a Key Vault write on the hottest path; the answer to that is
    # caching the anchor read, not pretending the write is unnecessary.
    return LoginResponse(token=token, expires_in=g8auth.SESSION_TTL_SECONDS)


@app.post("/logout")
def logout(authorization: str = Header(default="")):
    """Verify state, revoke the caller's session, and audit the logout.

    A failed integrity check leaves the token and trusted baseline
    unchanged. Successful revocation is process-local and expires with
    the token; restarting the service clears it.

    Raises:
        HTTPException: Authentication or state verification fails, or a
            required audit write fails after revocation.
    """
    user_id = _require_session(authorization)
    _verify_state_before_acting()
    token = authorization.split(" ", 1)[1].strip()
    g8auth.revoke_session(token, KEYS["session_hmac"])
    _audit("logout", user_id=user_id)
    return {
        "logged_out": True,
        "note": "this token is now rejected; other sessions are unaffected",
    }


@app.get("/me")
def me(authorization: str = Header(default="")):
    """Return the account associated with a currently accepted session."""
    user_id = _require_session(authorization)
    return {"user_id": user_id, "username": g8db.get_username(user_id)}


# ======================================================================================
# Files — upload, download, list, delete
# ======================================================================================
#
# The service processes file plaintext in memory inside the TDX VM and streams
# authenticated chunks over TLS. These handlers do not write plaintext files to disk.

MAX_UPLOAD_BYTES = 512 * 1024 * 1024  # a bound, not a memory requirement


@app.post("/files", status_code=201)
async def upload_file(
    request: Request,
    authorization: str = Header(default=""),
    x_filename: str = Header(default=""),
):
    """Encrypt a raw request body and persist its file/key records.

    Content-Length is required before chunk encryption because total chunk count
    is authenticated. Blocking storage operations run in a worker thread. The
    endpoint stages chunks rather than retaining the entire file in memory.

    Returns:
        File identity, sizes, chunk count, and version.

    Raises:
        HTTPException: Authentication, integrity, length, or persistence checks fail.
    """
    user_id = _require_session(authorization)
    _verify_state_before_acting()

    filename = (unquote(x_filename).strip() or "unnamed")[:255]

    declared = request.headers.get("content-length")
    if declared is None:
        raise HTTPException(
            status_code=411,
            detail="Content-Length is required: the chunk count is bound into every "
            "chunk's AAD and must be known before encryption begins",
        )
    try:
        size = int(declared)
    except ValueError:
        raise HTTPException(status_code=400, detail="malformed Content-Length")
    if size < 0 or size > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="file too large")

    file_id = str(uuid.uuid4())
    version = 1
    dek = g8keys.new_file_dek()
    total = g8keys.chunk_count(size)
    chunk_size = g8keys.CHUNK_SIZE

    up = await run_in_threadpool(g8blob.Uploader, file_id, version, total, dek)

    try:
        buf = bytearray()
        received = 0
        async for piece in request.stream():
            received += len(piece)
            if received > size:
                raise HTTPException(
                    status_code=400,
                    detail="body longer than the declared Content-Length",
                )
            buf += piece
            while len(buf) >= chunk_size:
                await run_in_threadpool(up.stage, bytes(buf[:chunk_size]))
                del buf[:chunk_size]

        # The remainder. A file whose length is an exact multiple of the chunk size has
        # nothing left over, so guard on the staged count rather than on the buffer being
        # empty -- a zero-byte file legitimately stages ONE empty chunk (g8keys.chunk_count).
        if up.staged < total:
            await run_in_threadpool(up.stage, bytes(buf))

        if received != size:
            raise HTTPException(
                status_code=400,
                detail="body shorter than the declared Content-Length",
            )

        info = await run_in_threadpool(up.commit)
    except HTTPException:
        up.abandon()
        raise
    except Exception:
        up.abandon()
        raise

    # Blob first, metadata second. A committed blob with no metadata row is unreadable
    # ciphertext nobody holds a key for; the reverse would be a key row pointing at
    # content that does not exist. If the metadata write fails, remove the blob so no
    # orphan is left behind.
    try:
        await run_in_threadpool(
            g8db.create_file_record,
            file_id,
            user_id,
            filename,
            size,
            info["blob_path"],
            dek,
            KEYS,
            version,
        )
    except Exception:
        await run_in_threadpool(g8blob.delete, file_id)
        raise

    _audit(
        "upload",
        user_id=user_id,
        file_id=file_id,
        detail="%d bytes in %d chunks" % (size, info["total_chunks"]),
    )

    return {
        "file_id": file_id,
        "filename": filename,
        "size_bytes": size,
        "total_chunks": info["total_chunks"],
        "blob_bytes": info["blob_bytes"],
        "version": version,
    }


@app.get("/files")
def list_files(authorization: str = Header(default="")):
    """List files for which the caller holds an authenticated wrapped key.

    Ordinary listings are read-only. Before auditing a key-binding
    failure, verify the anchor so the diagnostic cannot accept an
    unverified database state as the new baseline.

    Returns:
        Owned and received file records, with a degraded count for
        binding failures when the diagnostic audit can proceed.

    Raises:
        HTTPException: Authentication fails or the diagnostic write is
            blocked by a failed state-integrity check.
    """
    user_id = _require_session(authorization)
    files = g8db.list_user_files(user_id, KEYS)

    # a row that failed its AAD check is an attack indicator. The listing still
    # succeeds -- one bad row must not deny the other files -- but it is recorded, so the
    # evidence does not depend on the user noticing a null filename.
    bad = [f for f in files if f.get("error")]
    if bad:
        # Recording the diagnostic also replaces the trusted state baseline.
        _verify_state_before_acting()
        _audit(
            "key_binding_failure",
            user_id=user_id,
            detail="%d file row(s) failed the AAD check: %s"
            % (len(bad), ",".join(f["file_id"] for f in bad)),
        )

    return {"files": files, "degraded": len(bad) or None}


@app.get("/files/{file_id}")
def download_file(file_id: uuid.UUID, authorization: str = Header(default="")):
    """Stream authenticated plaintext for a caller holding a wrapped file key.

    A later chunk failure can occur after HTTP headers and earlier chunks have
    been sent. Clients must treat a truncated/failed transfer as incomplete; the
    service cannot replace an already-started response with a normal JSON error.
    """
    user_id = _require_session(authorization)
    # typed as UUID so a malformed id is a clean 422 from the framework and the
    # query never runs. Passed on as str, which is what g8db expects.
    file_id = str(file_id)
    _verify_state_before_acting()

    try:
        row, dek = g8db.get_file_for_user(file_id, user_id, KEYS)
    except (KeyError, PermissionError):
        raise HTTPException(status_code=404, detail="file not found")
    except g8keys.KeyBindingError:
        # The stored key row did not unwrap in this user's context: the untrusted database
        # returned a row that was moved, relabelled, or replayed. An attack indicator.
        raise HTTPException(status_code=409, detail="key binding check failed")

    name = g8db.get_filename(row, dek)
    total = g8keys.chunk_count(row["size_bytes"])

    # O4 requires a record of every ACCESS, not just of changes. Recorded before the
    # stream starts: a download that fails midway still happened, and pretending
    # otherwise would leave the more interesting case unlogged.
    _audit(
        "download",
        user_id=user_id,
        file_id=str(row["file_id"]),
        detail="%d bytes" % row["size_bytes"],
    )

    stream = g8blob.download(
        str(row["file_id"]), row["version"], dek, expected_chunks=total
    )

    # Advance the generator once so failures become status codes rather than a truncated
    # 200. Nothing has been sent to the client at this point.
    try:
        first_chunk = next(stream)
        body = itertools.chain([first_chunk], stream)
    except StopIteration:
        body = iter(())
    except g8blob.BlobFormatError as exc:
        # The two untrusted stores disagree, or the container is not what it claims.
        raise HTTPException(
            status_code=409, detail="stored object failed its format check"
        )
    except g8keys.KeyBindingError:
        raise HTTPException(status_code=409, detail="key binding check failed")
    except Exception:
        # Most likely the blob is gone while its metadata row survives. 404 rather than
        # 500: the caller cannot act on the distinction, and it matches this endpoint's
        # existing policy of not confirming what does or does not exist.
        raise HTTPException(status_code=404, detail="file content is unavailable")

    # the chunk AAD binds total_chunks, not the byte length, so an edit to
    # files.size_bytes that stays within the same chunk count is authenticated by nothing.
    # The value is used directly as Content-Length, so the client would receive a truncated
    # or over-declared body under a clean HTTP 200.
    #
    # Binding the size into the final chunk's AAD would be the cleaner fix and is what a
    # v2 blob format should do; it cannot be applied retroactively, because every blob
    # already stored was sealed without it. So the length is checked as it is emitted, and
    # a mismatch terminates the stream rather than completing a response that lies.
    declared = int(row["size_bytes"])

    def _length_checked(source):
        sent = 0
        for piece in source:
            sent += len(piece)
            if sent > declared:
                raise g8blob.BlobFormatError(
                    "decrypted content exceeds the declared size (%d > %d); the metadata "
                    "database and the stored object disagree" % (sent, declared)
                )
            yield piece
        if sent != declared:
            raise g8blob.BlobFormatError(
                "decrypted content is %d bytes but the metadata database declares %d"
                % (sent, declared)
            )

    return StreamingResponse(
        _length_checked(body),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(row["size_bytes"]),
            # safe="" so a '/' inside a filename is percent-encoded like everything
            # else. quote()'s default keeps '/' unescaped, which is right for URL paths and
            # wrong for a filename being handed to a browser's save dialogue.
            "X-Filename": quote(name, safe=""),
            "Content-Disposition": "attachment; filename*=UTF-8''%s"
            % quote(name, safe=""),
        },
    )


@app.delete("/files/{file_id}")
def delete_file(
    file_id: uuid.UUID,
    authorization: str = Header(default=""),
    x_g8_statement: str = Header(default=""),
    x_g8_signature: str = Header(default=""),
):
    """Delete a file. Owner only."""
    user_id = _require_session(authorization)
    # typed as UUID so a malformed id is a clean 422 from the framework and the
    # query never runs. Passed on as str, which is what g8db expects.
    file_id = str(file_id)
    _verify_state_before_acting()
    signed = _require_signature(
        "delete", user_id, file_id, "", x_g8_statement, x_g8_signature
    )

    try:
        removed = g8db.delete_file(file_id, user_id, KEYS)
    except KeyError:
        raise HTTPException(status_code=404, detail="file not found")
    except g8keys.KeyBindingError:
        raise HTTPException(status_code=409, detail="key binding check failed")
    except PermissionError:
        # 404, not 403. Every other endpoint here returns 404 for both "no such file"
        # and "not yours", with comments explaining that a 403 confirms a file exists to
        # someone not entitled to know. Delete was the one that broke that policy.
        raise HTTPException(status_code=404, detail="file not found")

    if not removed:
        raise HTTPException(status_code=404, detail="file not found")

    # Metadata is gone; the blob is now unreadable ciphertext regardless. Removing it is
    # housekeeping, so a failure here is logged rather than raised.
    try:
        g8blob.delete(file_id)
    except Exception as exc:  # noqa: BLE001
        print("[files] WARNING: blob %s left behind: %s" % (file_id, exc))

    _audit(
        "delete", user_id=user_id, file_id=file_id, detail=_signed_detail(None, signed)
    )
    return {"deleted": file_id, "signed": bool(signed)}


# ======================================================================================
# Sharing and revocation
# ======================================================================================


class ShareRequest(BaseModel):
    """Describe a share and optional client signature.

    Attributes:
        username: Recipient account name.
        permission: Authenticated intent metadata; read and write currently grant
            the same access because the API has no file-edit operation.
        statement: Base64 canonical operation statement, when signing is required.
        signature: Base64 raw P-256 signature over the statement.
    """

    username: str = Field(min_length=1, max_length=64)
    permission: str = Field(default="read", max_length=16)
    statement: str = Field(default="", max_length=1024)  # D19, base64 canonical JSON
    signature: str = Field(default="", max_length=256)  # D19, base64 raw r||s


@app.post("/files/{file_id}/share", status_code=201)
def share_file(
    file_id: uuid.UUID, req: ShareRequest, authorization: str = Header(default="")
):
    """Share a file. The blob is never opened, never re-encrypted, never even read.

    404 rather than 403 when the caller is not the owner: a 403 would confirm that the
    file exists, which is the same reasoning as the download endpoint.
    """
    user_id = _require_session(authorization)
    # typed as UUID so a malformed id is a clean 422 from the framework and the
    # query never runs. Passed on as str, which is what g8db expects.
    file_id = str(file_id)
    _verify_state_before_acting()
    # the permission is bound into the signature, so the server cannot upgrade a
    # signed "share as read" into a write grant.
    signed = _require_signature(
        "share",
        user_id,
        file_id,
        req.username,
        req.statement,
        req.signature,
        req.permission,
    )
    try:
        result = g8db.share_file(file_id, user_id, req.username, KEYS, req.permission)
    except KeyError:
        raise HTTPException(status_code=404, detail="file not found")
    except PermissionError:
        raise HTTPException(status_code=404, detail="file not found")
    except g8db.ShareError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _audit(
        "share",
        user_id=user_id,
        file_id=file_id,
        detail=_signed_detail(
            "granted %s to %s" % (result["permission"], result["user_id"]), signed
        ),
    )
    result["signed"] = bool(signed)
    return result


@app.delete("/files/{file_id}/share/{target_user_id}")
def revoke_share(
    file_id: uuid.UUID,
    target_user_id: uuid.UUID,
    authorization: str = Header(default=""),
    x_g8_statement: str = Header(default=""),
    x_g8_signature: str = Header(default=""),
):
    """Remove a recipient's wrapped key and ACL record.

    Subsequent requests rely on the updated state. Already downloaded plaintext
    cannot be recalled, and the file key is not rotated by this operation.
    """
    user_id = _require_session(authorization)
    # typed as UUID so a malformed id is a clean 422 from the framework and the
    # query never runs. Passed on as str, which is what g8db expects.
    file_id = str(file_id)
    target_user_id = str(target_user_id)
    _verify_state_before_acting()
    signed = _require_signature(
        "revoke", user_id, file_id, target_user_id, x_g8_statement, x_g8_signature
    )
    try:
        removed = g8db.revoke_share(file_id, user_id, target_user_id, KEYS)
    except KeyError:
        raise HTTPException(status_code=404, detail="file not found")
    except PermissionError:
        raise HTTPException(status_code=404, detail="file not found")
    except g8db.ShareError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # this used to return 200 with removed=false and still write a `revoke` audit
    # entry, so the log recorded an access as revoked when nothing had been. An audit
    # trail that says something happened when it did not is worse than no entry at all.
    if not removed:
        raise HTTPException(
            status_code=404,
            detail="that user holds no access to this file",
        )

    _audit(
        "revoke",
        user_id=user_id,
        file_id=file_id,
        detail=_signed_detail("revoked %s" % target_user_id, signed),
    )
    return {
        "file_id": file_id,
        "revoked": target_user_id,
        "removed": removed,
        "note": "future access is prevented; data already downloaded cannot be recalled",
    }


@app.get("/files/{file_id}/shares")
def list_shares(file_id: uuid.UUID, authorization: str = Header(default="")):
    """List an owner's shares and reject invalid ACL MACs.

    Ordinary listings are read-only. An invalid MAC is audited only
    after the current state passes the anchor check.

    Returns:
        The file identifier and shares with verified ACL MACs.

    Raises:
        HTTPException: Authentication, ownership, state verification,
            or ACL authentication fails.
    """
    user_id = _require_session(authorization)
    # typed as UUID so a malformed id is a clean 422 from the framework and the
    # query never runs. Passed on as str, which is what g8db expects.
    file_id = str(file_id)
    try:
        shares = g8db.list_shares(file_id, user_id, KEYS)
    except KeyError:
        raise HTTPException(status_code=404, detail="file not found")
    except PermissionError:
        raise HTTPException(status_code=404, detail="file not found")

    # the MAC was computed, returned as `mac_valid`, and then ignored.
    #
    # g8keys.py states the principle: "a decision read from an untrusted store must be
    # authenticated or it is a suggestion". Computing the MAC and reporting it in a JSON
    # field satisfies the letter of that and none of the intent -- a forged permission row
    # went unnoticed unless the owner happened to open this page and read a boolean.
    bad = [s for s in shares if not s["mac_valid"]]
    if bad:
        # Reject an untrusted baseline before recording and re-anchoring it.
        _verify_state_before_acting()
        _audit(
            "acl_mac_failure",
            user_id=user_id,
            file_id=file_id,
            detail="%d access-control row(s) failed MAC verification: %s"
            % (len(bad), ",".join(s["user_id"] for s in bad)),
        )
        raise HTTPException(
            status_code=409,
            detail="%d access-control row(s) for this file were not written by this "
            "service and failed their integrity check. Refusing to report them as "
            "if they were genuine." % len(bad),
        )

    return {
        "file_id": file_id,
        "shares": shares,
        "all_macs_valid": True,
    }


# ======================================================================================
# Audit log
# ======================================================================================


@app.get("/audit")
def audit_read(limit: int = 50, authorization: str = Header(default="")):
    """Return decrypted audit events belonging to the caller.

    Actor filtering happens after payload decryption. Undecryptable rows
    are returned as errors without event contents. This read does not
    perform full chain verification.
    """
    user_id = _require_session(authorization)
    return {
        "user_id": user_id,
        "entries": g8audit.read(
            g8db.get_conn(), KEYS, user_id=user_id, limit=min(max(limit, 1), 200)
        ),
    }


@app.get("/audit/verify")
def audit_verify(authorization: str = Header(default="")):
    """Verify the audit chain and separately compare the state anchor.

    Returns:
        Chain and anchor verdicts with counts and the first broken link,
        when present. No decrypted event contents are returned.
    """
    _require_session(authorization)

    # The chain walk is never skipped: it is what detects an edited entry, and it needs no
    # external call.
    chain = g8audit.verify_chain(g8db.get_conn(), KEYS)

    # The anchor read is a Key Vault request. Reuse a very recent one.
    now = time.time()
    if (
        _anchor_read_cache["ok"] is not None
        and now - _anchor_read_cache["at"] < ANCHOR_READ_CACHE_SECONDS
    ):
        anchor_ok = _anchor_read_cache["ok"]
        anchor_status = _anchor_read_cache["status"]
        anchor_age = round(now - _anchor_read_cache["at"], 1)
    else:
        anchor_ok, anchor_detail = g8anchor.verify(g8db.get_conn())
        anchor_status = anchor_detail.get("status")
        _anchor_read_cache.update({"at": now, "ok": anchor_ok, "status": anchor_status})
        anchor_age = 0.0

    return {
        "chain": chain,
        "anchor": {
            "ok": anchor_ok,
            "status": anchor_status,
            "read_seconds_ago": anchor_age,
        },
        "verdict": (
            "log intact" if (chain["ok"] and anchor_ok) else "TAMPERING DETECTED"
        ),
    }


# ======================================================================================
# Demonstration UI
# ======================================================================================
#
# ⚠️ THIS SECTION IS FOR THE DEMONSTRATION AND WOULD NOT SHIP.
#
# `/demo/operator-view` returns exactly what an adversary with full read access to the
# untrusted stores would see: the first bytes of the stored blob, the encrypted filename,
# the wrapped DEKs, and the audit rows as they sit in PostgreSQL. Every byte of it is
# already available to the cloud operator by definition, so the endpoint discloses nothing
# to them that they do not hold.
#
# It exists because a screenshot of a hex dump is a much weaker argument than the audience
# watching the ciphertext appear beside the plaintext, in the same second, for a file they
# just chose.
#
# ⚠️ It previously disclosed all of that to ANY authenticated user, for ANY file — finding
# H1. Marking a hole in a comment does not close it. The endpoint is now gated three ways:
#   * G8_DEMO=0 removes it entirely, for any deployment that is not a demonstration;
#   * the caller must hold a key for the file (see operator_view's docstring);
#   * a malformed file_id is a 422 from the framework, not an unhandled 500.
#
# RESIDUAL, stated rather than quietly left: `audit_rows` below is still the last four rows
# of the WHOLE log, not the caller's. Those rows carry a NULL actor, a NULL subject, a
# constant action and an encrypted detail, so what leaks is row count and timing, not
# content — and showing them is the point of the demonstration. Narrow it or drop it if this
# ever becomes more than a demonstration.

# Kill switch for the demonstration-only endpoints. Defaults to enabled so the demo and
# g8ui.html behave exactly as before; set G8_DEMO=0 to remove them.
DEMO_ENDPOINTS = os.environ.get("G8_DEMO", "1").lower() not in ("0", "false", "no")

UI_PATH = os.path.expanduser("~/g8ui.html")


@app.get("/ui", include_in_schema=False)
def ui():
    """Serve the single-page demonstration client."""
    if not os.path.exists(UI_PATH):
        raise HTTPException(status_code=404, detail="UI not installed at %s" % UI_PATH)
    return FileResponse(UI_PATH, media_type="text/html")


@app.get("/demo/operator-view/{file_id}")
def operator_view(file_id: uuid.UUID, authorization: str = Header(default="")):
    """Return selected storage diagnostics to an authorized file holder.

    The service retrieves these values from storage; the browser does not connect
    directly to Azure. The endpoint exposes key-holder identifiers and encrypted
    audit samples and is disabled when G8_DEMO is false.
    """
    user_id = _require_session(authorization)

    if not DEMO_ENDPOINTS:
        raise HTTPException(status_code=404, detail="Not Found")

    file_id = str(file_id)

    # The access check. Its return value is deliberately discarded — we want the operator's
    # view of the stored bytes, not the decrypted content — but it must run, and it must run
    # BEFORE anything is read back.
    try:
        g8db.get_file_for_user(file_id, user_id, KEYS)
    except (KeyError, PermissionError):
        raise HTTPException(status_code=404, detail="file not found")
    except g8keys.KeyBindingError:
        raise HTTPException(status_code=409, detail="key binding check failed")

    out = {"file_id": file_id}

    try:
        out["blob_head"] = g8blob.read_raw(file_id, 96).hex()
    except Exception as exc:  # noqa: BLE001
        out["blob_head"] = None
        out["blob_error"] = type(exc).__name__

    with g8db.get_conn().cursor() as cur:
        cur.execute(
            "SELECT owner_id, size_bytes, blob_path, version, "
            "       encode(filename_enc,'hex')   AS filename_enc, "
            "       encode(filename_nonce,'hex') AS filename_nonce "
            "FROM files WHERE file_id = %s",
            (file_id,),
        )
        row = cur.fetchone()
        out["files_row"] = dict(row) if row else None

        cur.execute(
            "SELECT user_id, version, encode(wrapped_dek,'hex') AS wrapped_dek "
            "FROM file_keys WHERE file_id = %s ORDER BY user_id",
            (file_id,),
        )
        out["file_keys_rows"] = [dict(r) for r in cur.fetchall()]

        cur.execute(
            "SELECT seq, ts, user_id, action, file_id, left(detail, 56) AS detail "
            "FROM audit_log ORDER BY seq DESC LIMIT 4"
        )
        out["audit_rows"] = [dict(r) for r in cur.fetchall()]

    return out
