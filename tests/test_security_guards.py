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
