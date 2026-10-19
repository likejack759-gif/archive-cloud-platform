from starlette.requests import Request

from app import main


class FakeResult:
    def __init__(self, rows=None, row=None):
        self._rows = rows or []
        self._row = row

    def fetchall(self):
        return self._rows

    def fetchone(self):
        return self._row


class FakeConnection:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def execute(self, sql, params=()):
        self.calls.append((sql, params))
        if "COUNT(*) AS resources" in sql:
            return FakeResult(row={"resources": 12, "downloads": 85, "apps": 4, "archives": 8})
        return FakeResult(rows=[])


def make_request():
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "https",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 443),
        "session": {"user_id": 1},
    })


def run_index(monkeypatch, *, q="", resource_type="", sort="latest"):
    connection = FakeConnection()
    monkeypatch.setattr(main, "db_connect", lambda: connection)
    monkeypatch.setattr(main, "current_user", lambda _request: {"id": 1, "username": "tester", "role": "user"})
    monkeypatch.setattr(main, "page", lambda _request, _template, **context: context)

    context = main.index(make_request(), q=q, resource_type=resource_type, sort=sort)
    return connection, context


def test_index_filters_by_query_and_resource_type(monkeypatch):
    connection, context = run_index(
        monkeypatch, q="  pack  ", resource_type="apk", sort="latest"
    )

    sql, params = connection.calls[0]
    assert "r.name ILIKE %s OR r.description ILIKE %s OR r.original_filename ILIKE %s" in sql
    assert "r.resource_type=%s" in sql
    assert params == ("%pack%", "%pack%", "%pack%", "apk")
    assert context["q"] == "pack"
    assert context["resource_type"] == "apk"


def test_index_popular_sort_is_supported(monkeypatch):
    connection, context = run_index(monkeypatch, sort="popular")

    sql, _params = connection.calls[0]
    assert "ORDER BY r.downloads DESC, r.created_at DESC" in sql
    assert context["sort"] == "popular"
    assert context["stats"]["downloads"] == 85


def test_index_rejects_unrecognized_sort_value(monkeypatch):
    connection, context = run_index(monkeypatch, sort="downloads DESC; DROP TABLE users")

    sql, _params = connection.calls[0]
    assert "ORDER BY r.created_at DESC, r.id DESC" in sql
    assert "DROP TABLE" not in sql
    assert context["sort"] == "latest"
