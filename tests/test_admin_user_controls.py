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


def test_admin_cannot_demote_another_admin(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params):
            return self

        def fetchone(self):
            return {"username": "other-admin", "role": "admin"}

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    request = SimpleNamespace(session={"csrf_token": "test"})

    with pytest.raises(HTTPException) as exc:
        main.change_user_role(request, 8, role="user", csrf_token="test")
    assert exc.value.status_code == 403


def test_only_superadmin_can_demote_another_admin(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params):
            return self

        def fetchone(self):
            return {"username": "other-admin", "role": "admin"}

        def commit(self):
            return None

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    request = SimpleNamespace(session={"csrf_token": "test"})

    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin", "is_superadmin": False})
    with pytest.raises(HTTPException) as exc:
        main.change_user_role(request, 8, role="user", csrf_token="test")
    assert exc.value.status_code == 403

    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin", "is_superadmin": True})
    response = main.change_user_role(request, 8, role="user", csrf_token="test")
    assert response.status_code == 303


def test_superadmin_cannot_be_demoted(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params):
            return self

        def fetchone(self):
            return {"username": "chief", "role": "admin", "is_superadmin": True}

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin", "is_superadmin": True})
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    request = SimpleNamespace(session={"csrf_token": "test"})

    with pytest.raises(HTTPException) as exc:
        main.change_user_role(request, 8, role="user", csrf_token="test")
    assert exc.value.status_code == 409


def test_superadmin_cannot_be_banned(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def execute(self, query, params):
            return self

        def fetchone(self):
            return {"id": 8, "username": "chief", "role": "admin", "is_banned": False, "is_superadmin": True}

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin", "is_superadmin": True})
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    request = SimpleNamespace(session={"csrf_token": "test"})

    with pytest.raises(HTTPException) as exc:
        main.set_user_ban(request, 8, action="ban", csrf_token="test")
    assert exc.value.status_code == 409


def test_password_reset_updates_hash_and_invalidates_sessions(monkeypatch):
    from types import SimpleNamespace
    import app.main as main

    class FakeConnection:
        def __init__(self):
            self.queries = []
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            self.queries.append((query, params))
            return self
        def fetchone(self):
            return {"id": 8, "username": "member"}
        def commit(self):
            return None

    conn = FakeConnection()
    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    monkeypatch.setattr(main, "db_connect", lambda: conn)
    monkeypatch.setattr(main, "write_admin_audit", lambda *args, **kwargs: None)
    request = SimpleNamespace(session={"csrf_token": "test"})

    response = main.reset_user_password(request, 8, new_password="New-Secure-Password-123", csrf_token="test")
    assert response.status_code == 303
    update = next((q, p) for q, p in conn.queries if "UPDATE users SET password_hash" in q)
    assert "session_version=session_version+1" in update[0]
    assert main.verify_password("New-Secure-Password-123", update[1][0])


def test_resource_cannot_be_approved_without_clean_scan(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            return self
        def fetchone(self):
            return {"scan_status": "pending"}

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    request = SimpleNamespace(session={"csrf_token": "test"})

    with pytest.raises(HTTPException) as exc:
        main.review_resource(request, 12, action="approve", review_note="", csrf_token="test")
    assert exc.value.status_code == 409


def test_resource_approval_allowed_after_clean_scan(monkeypatch):
    from types import SimpleNamespace
    import app.main as main

    class FakeConnection:
        def __init__(self):
            self.queries = []
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            self.queries.append((query, params))
            return self
        def fetchone(self):
            return {"scan_status": "clean"}
        def commit(self):
            return None

    conn = FakeConnection()
    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    monkeypatch.setattr(main, "db_connect", lambda: conn)
    monkeypatch.setattr(main, "write_admin_audit", lambda *args, **kwargs: None)
    request = SimpleNamespace(session={"csrf_token": "test"})

    response = main.review_resource(request, 12, action="approve", review_note="checked", csrf_token="test")
    assert response.status_code == 303
    assert any("UPDATE resources SET status=%s" in q for q, _ in conn.queries)


def test_regular_admin_cannot_promote_user_to_admin(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            return self
        def fetchone(self):
            return {"username": "member", "role": "user", "is_superadmin": False}

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin", "is_superadmin": False})
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    request = SimpleNamespace(session={"csrf_token": "test"})

    with pytest.raises(HTTPException) as exc:
        main.change_user_role(request, 8, role="admin", csrf_token="test")
    assert exc.value.status_code == 403


def test_regular_admin_cannot_reset_superadmin_password(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            return self
        def fetchone(self):
            return {"id": 8, "username": "chief", "is_superadmin": True}

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin", "is_superadmin": False})
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    request = SimpleNamespace(session={"csrf_token": "test"})

    with pytest.raises(HTTPException) as exc:
        main.reset_user_password(request, 8, new_password="New-Secure-Password-123", csrf_token="test")
    assert exc.value.status_code == 403


def test_unban_restores_account_and_invalidates_old_sessions(monkeypatch):
    from types import SimpleNamespace
    import app.main as main

    class FakeConnection:
        def __init__(self):
            self.queries = []
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            self.queries.append((query, params))
            return self
        def fetchone(self):
            return {"id": 8, "username": "member", "role": "user", "is_banned": True, "is_superadmin": False}
        def commit(self):
            return None

    conn = FakeConnection()
    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin", "is_superadmin": True})
    monkeypatch.setattr(main, "db_connect", lambda: conn)
    monkeypatch.setattr(main, "write_admin_audit", lambda *args, **kwargs: None)
    request = SimpleNamespace(session={"csrf_token": "test"})

    response = main.set_user_ban(request, 8, action="unban", csrf_token="test")
    assert response.status_code == 303
    update = next((q, p) for q, p in conn.queries if "UPDATE users SET is_banned=%s" in q)
    assert update[1] == (False, 8)
    assert "session_version=session_version+1" in update[0]


def test_banning_user_invalidates_existing_sessions(monkeypatch):
    from types import SimpleNamespace
    import app.main as main

    class FakeConnection:
        def __init__(self):
            self.queries = []
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            self.queries.append((query, params))
            return self
        def fetchone(self):
            return {"id": 8, "username": "member", "role": "user", "is_banned": False, "is_superadmin": False}
        def commit(self):
            return None

    conn = FakeConnection()
    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin", "is_superadmin": True})
    monkeypatch.setattr(main, "db_connect", lambda: conn)
    monkeypatch.setattr(main, "write_admin_audit", lambda *args, **kwargs: None)
    request = SimpleNamespace(session={"csrf_token": "test"})

    response = main.set_user_ban(request, 8, action="ban", csrf_token="test")
    assert response.status_code == 303
    update = next((q, p) for q, p in conn.queries if "UPDATE users SET is_banned=%s" in q)
    assert update[1] == (True, 8)
    assert "session_version=session_version+1" in update[0]


def test_resource_rejection_updates_status_audits_and_commits(monkeypatch):
    from types import SimpleNamespace
    import app.main as main

    class FakeConnection:
        def __init__(self):
            self.queries = []
            self.committed = False
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            self.queries.append((query, params))
            return self
        def fetchone(self):
            return {"scan_status": "clean"}
        def commit(self):
            self.committed = True

    conn = FakeConnection()
    audits = []
    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    monkeypatch.setattr(main, "db_connect", lambda: conn)
    monkeypatch.setattr(main, "write_admin_audit", lambda *args, **kwargs: audits.append((args, kwargs)))
    request = SimpleNamespace(session={"csrf_token": "test"})

    response = main.review_resource(request, 12, action="reject", review_note="unsafe file", csrf_token="test")

    assert response.status_code == 303
    update = next((query, params) for query, params in conn.queries if "UPDATE resources SET status=%s" in query)
    assert update[1] == ("rejected", "unsafe file", 7, 12)
    assert conn.committed
    assert audits and audits[0][0][2] == "resource.rejected"


def test_resource_review_returns_404_when_resource_is_not_pending(monkeypatch):
    from types import SimpleNamespace
    from fastapi import HTTPException
    import pytest
    import app.main as main

    class FakeConnection:
        def __enter__(self):
            return self
        def __exit__(self, exc_type, exc, tb):
            return False
        def execute(self, query, params):
            return self
        def fetchone(self):
            return None

    monkeypatch.setattr(main, "validate_csrf", lambda request, token: None)
    monkeypatch.setattr(main, "require_admin", lambda request: {"id": 7, "role": "admin"})
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    request = SimpleNamespace(session={"csrf_token": "test"})

    with pytest.raises(HTTPException) as exc:
        main.review_resource(request, 999, action="reject", review_note="", csrf_token="test")
    assert exc.value.status_code == 404

