"""Check request rejection before audit writes and trusted-anchor replacement.

These local regression tests call the real API handlers, session implementation,
integrity guard, and audit coordinator. Database and Key Vault I/O are replaced
with controlled outcomes. They do not exercise TDX, Azure, or cloud persistence.
Run this file explicitly; neighboring legacy scripts can perform live operations.
"""

import uuid

import pytest
from fastapi import HTTPException

import app as service


@pytest.fixture
def request_state(monkeypatch):
    """Provide a real signed session and isolate external I/O and mutable state."""
    events = []
    user_id = str(uuid.uuid4())
    file_id = uuid.uuid4()
    session_key = b"local regression test session key"
    monkeypatch.setattr(service, "KEYS", {"session_hmac": session_key})
    monkeypatch.setattr(service, "ANCHOR", {"stale": False})
    monkeypatch.setattr(service.g8auth, "_revoked", {})
    monkeypatch.setattr(service.g8db, "get_conn", lambda: object())
    monkeypatch.setattr(service.g8db, "user_exists", lambda uid: uid == user_id)
    monkeypatch.setattr(
        service.g8db,
        "list_user_files",
        lambda *args: [{"file_id": str(file_id), "error": "key binding failed"}],
    )
    monkeypatch.setattr(
        service.g8db,
        "list_shares",
        lambda *args: [{"user_id": user_id, "mac_valid": False}],
    )
    monkeypatch.setattr(
        service.g8audit,
        "safe_append",
        lambda conn, keys, action, **kw: events.append(("audit", action)),
    )

    def update(conn):
        events.append(("anchor", "write"))
        return "local-test-digest"

    monkeypatch.setattr(service.g8anchor, "update", update)
    token = service.g8auth.issue_session(user_id, session_key)
    return {
        "events": events,
        "user_id": user_id,
        "file_id": file_id,
        "session_key": session_key,
        "token": token,
        "authorization": "Bearer " + token,
    }


def invoke(operation, state):
    """Call a handler without running application startup or cloud bootstrap."""
    if operation == "logout":
        return service.logout(state["authorization"])
    if operation == "list_files":
        return service.list_files(state["authorization"])
    return service.list_shares(state["file_id"], state["authorization"])


@pytest.mark.parametrize("operation", ["logout", "list_files", "list_shares"])
@pytest.mark.parametrize(
    "failure, expected_status",
    [("MISMATCH", 409), ("NO_ANCHOR", 409), ("unavailable", 503), ("stale", 503)],
)
def test_unverified_state_cannot_be_reanchored(
    monkeypatch, request_state, operation, failure, expected_status
):
    """Failed integrity checks must leave audit, anchor, and session unchanged."""

    def verify(conn):
        if failure == "unavailable":
            raise ConnectionError("local simulated dependency failure")
        return False, {"status": failure}

    monkeypatch.setattr(service.g8anchor, "verify", verify)
    if failure == "stale":
        service.ANCHOR["write_failed"] = True

    with pytest.raises(HTTPException) as exc:
        invoke(operation, request_state)

    assert exc.value.status_code == expected_status
    assert request_state["events"] == []
    assert (
        service.g8auth.verify_session(
            request_state["token"], request_state["session_key"]
        )
        == request_state["user_id"]
    )


@pytest.mark.parametrize(
    "operation, action",
    [
        ("logout", "logout"),
        ("list_files", "key_binding_failure"),
        ("list_shares", "acl_mac_failure"),
    ],
)
def test_verified_state_preserves_existing_action_results(
    monkeypatch, request_state, operation, action
):
    """A matching baseline permits the existing logout and diagnostic behavior."""

    def verify(conn):
        request_state["events"].append(("anchor", "check"))
        return True, {"status": "match"}

    monkeypatch.setattr(service.g8anchor, "verify", verify)
    if operation == "list_shares":
        with pytest.raises(HTTPException) as exc:
            invoke(operation, request_state)
        assert exc.value.status_code == 409
        assert "failed their integrity check" in exc.value.detail
    else:
        result = invoke(operation, request_state)
        if operation == "logout":
            assert result["logged_out"] is True
            assert (
                service.g8auth.verify_session(
                    request_state["token"], request_state["session_key"]
                )
                is None
            )
        else:
            assert result["degraded"] == 1

    assert request_state["events"] == [
        ("anchor", "check"),
        ("audit", action),
        ("anchor", "write"),
    ]


@pytest.mark.parametrize("operation", ["list_files", "list_shares"])
def test_normal_listings_remain_read_only(monkeypatch, request_state, operation):
    """Listings with no diagnostic audit event do not read or replace the anchor."""
    monkeypatch.setattr(service.g8db, "list_user_files", lambda *args: [])
    monkeypatch.setattr(service.g8db, "list_shares", lambda *args: [])

    def unexpected_verify(conn):
        pytest.fail("ordinary read-only listing unexpectedly requested an anchor check")

    monkeypatch.setattr(service.g8anchor, "verify", unexpected_verify)
    result = invoke(operation, request_state)
    assert result["files" if operation == "list_files" else "shares"] == []
    assert request_state["events"] == []
