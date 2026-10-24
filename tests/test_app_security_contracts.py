import hashlib
import json

import pytest
from fastapi import HTTPException
from fastapi.responses import FileResponse

from app import main


class FakeBody:
    def __init__(self, payload):
        self.payload = payload

    def iter_chunks(self, chunk_size=1024 * 1024):
        yield self.payload

    def close(self):
        pass


class FakeS3:
    def __init__(self, payload):
        self.payload = payload

    def get_object(self, **kwargs):
        return {"Body": FakeBody(self.payload)}


class FakeConnection:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def execute(self, *args):
        return self

    def commit(self):
        pass


def test_health_reports_dependency_status(monkeypatch):
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    monkeypatch.setattr(main, "s3_client", lambda: type("S3", (), {"head_bucket": lambda self, **kwargs: None})())
    monkeypatch.setattr(main, "clamav_ping", lambda: True)
    response = main.health()
    assert response.status_code == 200
    assert json.loads(response.body) == {
        "status": "ok", "database": "ok", "storage": "ok", "scanner": "ok"
    }


def test_download_verifies_sha256_before_serving(monkeypatch):
    payload = b"known-good-archive-bytes"
    monkeypatch.setattr(main, "s3_client", lambda: FakeS3(payload))
    resource = {"id": 12, "sha256": hashlib.sha256(payload).hexdigest()}
    response = main.verified_download_response(resource, "files/sample.zip", "sample.zip")
    assert isinstance(response, FileResponse)
    with open(response.path, "rb") as source:
        assert source.read() == payload
    main._remove_temp_file(response.path)


def test_download_rejects_sha256_mismatch(monkeypatch):
    monkeypatch.setattr(main, "s3_client", lambda: FakeS3(b"tampered"))
    monkeypatch.setattr(main, "db_connect", lambda: FakeConnection())
    with pytest.raises(HTTPException) as exc:
        main.verified_download_response(
            {"id": 13, "sha256": hashlib.sha256(b"original").hexdigest()},
            "files/sample.zip",
            "sample.zip",
        )
    assert exc.value.status_code == 502



def test_admin_audit_records_action_without_secret_material():
    calls = []

    class AuditConnection:
        def execute(self, sql, params):
            calls.append((sql, params))

    main.write_admin_audit(
        AuditConnection(), 7, "resource.approved", "resource", 42, "reviewed"
    )
    assert len(calls) == 1
    assert "INSERT INTO admin_audit_log" in calls[0][0]
    assert calls[0][1] == (7, "resource.approved", "resource", "42", "reviewed")
