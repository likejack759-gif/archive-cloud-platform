import asyncio

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import Response

from app import main


def make_request(*, method="POST", path="/", headers=None):
    encoded_headers = [
        (key.lower().encode("latin-1"), value.encode("latin-1"))
        for key, value in (headers or {}).items()
    ]
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": encoded_headers,
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 80),
        "session": {},
    }
    return Request(scope)


def test_csrf_token_is_created_and_reused():
    request = make_request()
    first = main.get_csrf_token(request)
    second = main.get_csrf_token(request)

    assert first
    assert first == second
    assert request.session["csrf_token"] == first


def test_csrf_validation_accepts_matching_token():
    request = make_request()
    request.session["csrf_token"] = "expected-token"

    main.validate_csrf(request, "expected-token")


@pytest.mark.parametrize("submitted", ["", "wrong-token"])
def test_csrf_validation_rejects_missing_or_wrong_token(submitted):
    request = make_request()
    request.session["csrf_token"] = "expected-token"

    with pytest.raises(HTTPException) as exc:
        main.validate_csrf(request, submitted)

    assert exc.value.status_code == 403


def test_csrf_validation_rejects_token_without_session_value():
    with pytest.raises(HTTPException) as exc:
        main.validate_csrf(make_request(), "anything")

    assert exc.value.status_code == 403


def test_login_throttle_blocks_after_five_failures_and_can_be_cleared():
    key = "test-client:test-user"
    main.clear_login_failures(key)

    for _ in range(main.LOGIN_FAILURE_LIMIT - 1):
        assert main.record_login_failure(key) == 0

    retry_after = main.record_login_failure(key)
    assert retry_after > 0
    blocked, remaining = main.login_is_blocked(key)
    assert blocked is True
    assert remaining > 0

    main.clear_login_failures(key)
    assert main.login_is_blocked(key) == (False, 0)


def test_request_guard_rejects_oversized_non_upload_request():
    request = make_request(
        path="/login",
        headers={"content-length": str(2 * 1024 * 1024 + 1)},
    )
    called = False

    async def call_next(_request):
        nonlocal called
        called = True
        return Response("ok")

    response = asyncio.run(main.request_size_guard(request, call_next))

    assert response.status_code == 413
    assert called is False


def test_request_guard_rejects_invalid_content_length():
    request = make_request(headers={"content-length": "not-a-number"})

    async def call_next(_request):
        return Response("ok")

    response = asyncio.run(main.request_size_guard(request, call_next))

    assert response.status_code == 400


def test_request_guard_allows_small_request():
    request = make_request(path="/login", headers={"content-length": "128"})

    async def call_next(_request):
        return Response("ok", status_code=200)

    response = asyncio.run(main.request_size_guard(request, call_next))

    assert response.status_code == 200

def test_login_throttle_prunes_expired_entries(monkeypatch):
    main._login_attempts.clear()
    main._login_attempts["expired-key"] = (1, 0.0, 0.0)
    monkeypatch.setattr(main.time, "monotonic", lambda: float(main.LOGIN_WINDOW_SECONDS + 100))
    monkeypatch.setattr(main, "_last_login_cleanup", 0.0)

    assert main.login_is_blocked("new-key") == (False, 0)
    assert "expired-key" not in main._login_attempts


def test_login_throttle_fails_closed_when_key_capacity_is_full(monkeypatch):
    main._login_attempts.clear()
    monkeypatch.setattr(main, "LOGIN_MAX_TRACKED_KEYS", 2)
    monkeypatch.setattr(main.time, "monotonic", lambda: 100.0)
    monkeypatch.setattr(main, "_last_login_cleanup", 100.0)
    main._login_attempts["active-1"] = (1, 99.0, 0.0)
    main._login_attempts["active-2"] = (1, 99.0, 0.0)

    blocked, retry_after = main.login_is_blocked("new-key")

    assert blocked is True
    assert retry_after == main.LOGIN_CAPACITY_RETRY_SECONDS
    assert len(main._login_attempts) == 2
    assert "new-key" not in main._login_attempts




def test_login_rate_key_is_shared_across_usernames_from_same_ip():
    request = make_request()
    first_username_key = main.login_rate_key(request)
    second_username_key = main.login_rate_key(request)

    assert first_username_key == second_username_key == "127.0.0.1"


def test_login_failures_accumulate_across_username_changes_from_same_ip():
    request = make_request()
    ip_key = main.login_rate_key(request)
    main.clear_login_failures(ip_key)

    # Simulate four failures against one username, then a fifth against another.
    for _ in range(main.LOGIN_FAILURE_LIMIT - 1):
        assert main.record_login_failure(ip_key) == 0

    changed_username_key = main.login_rate_key(request)
    assert changed_username_key == ip_key
    retry_after = main.record_login_failure(changed_username_key)

    assert retry_after > 0
    assert main.login_is_blocked(ip_key)[0] is True
    main.clear_login_failures(ip_key)
