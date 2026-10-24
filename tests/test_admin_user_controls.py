import ast
from pathlib import Path

from app.main import app, hash_password, verify_password


def test_password_hash_is_salted_and_verifiable():
    first = hash_password("Test-Password-123")
    second = hash_password("Test-Password-123")
    assert first.startswith("scrypt$")
    assert first != second
    assert verify_password("Test-Password-123", first)
    assert not verify_password("Wrong-Password-123", first)


def test_admin_routes_are_registered():
    routes = {(method, route.path) for route in app.routes for method in (getattr(route, "methods", None) or set())}
    assert ("POST", "/admin/users/{user_id}/ban") in routes
    assert ("POST", "/admin/users/{user_id}/reset-password") in routes
    assert ("POST", "/admin/users/{user_id}/role") in routes


def test_main_python_syntax():
    source = Path("app/main.py").read_text(encoding="utf-8")
    ast.parse(source)


def test_admin_template_contains_controls():
    template = Path("app/templates/admin.html").read_text(encoding="utf-8")
    assert 'action="/admin/users/{{ u.id }}/ban"' in template
    assert 'action="/admin/users/{{ u.id }}/reset-password"' in template
    assert 'name="csrf_token"' in template

def test_admin_cannot_ban_own_account(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    request = SimpleNamespace(session={"csrf_token": "test"})
    with pytest.raises(HTTPException) as exc:
        main.set_user_ban(request, 7, action="ban", csrf_token="test")
    assert exc.value.status_code == 400


def test_admin_cannot_reset_own_password(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    request = SimpleNamespace(session={"csrf_token": "test"})
    with pytest.raises(HTTPException) as exc:
        main.reset_user_password(request, 7, new_password="New-Secure-Password-123", csrf_token="test")
    assert exc.value.status_code == 400


def test_password_reset_rejects_short_password(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    request = SimpleNamespace(session={"csrf_token": "test"})
    with pytest.raises(HTTPException) as exc:
        main.reset_user_password(request, 8, new_password="short", csrf_token="test")
    assert exc.value.status_code == 400


def test_current_user_invalidates_banned_or_stale_session(monkeypatch):
    from types import SimpleNamespace
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params):
            return self

        def fetchone(self):
            return self.user_row

    for user_row in (
        {"id": 8, "username": "blocked", "role": "user", "created_at": None, "is_banned": True, "session_version": 2},
        {"id": 8, "username": "stale", "role": "user", "created_at": None, "is_banned": False, "session_version": 3},
    ):
        conn = FakeConnection()
        conn.user_row = user_row
        monkeypatch.setattr(main, "db_connect", lambda conn=conn: conn)
        session = {"user_id": 8, "session_version": 2, "csrf_token": "old"}
        request = SimpleNamespace(session=session)

        assert main.current_user(request) is None
        assert session == {}
