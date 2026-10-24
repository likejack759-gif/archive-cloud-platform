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
