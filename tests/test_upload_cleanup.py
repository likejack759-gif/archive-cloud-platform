import asyncio
import tempfile

import pytest
from fastapi import HTTPException
from starlette.datastructures import UploadFile
from starlette.requests import Request

from app import main


def make_request():
    return Request({
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "path": "/submit",
        "raw_path": b"/submit",
        "query_string": b"",
        "headers": [],
        "client": ("127.0.0.1", 12345),
        "server": ("testserver", 443),
        "session": {"csrf_token": "test-token"},
    })


def upload(filename, data):
    f = tempfile.SpooledTemporaryFile()
    f.write(data)
    f.seek(0)
    return UploadFile(filename=filename, file=f)


def test_cover_size_http_exception_cleans_uploaded_archive(monkeypatch):
    uploaded_keys = []
    deleted_keys = []
    monkeypatch.setattr(main, "current_user", lambda _request: {"id": 7, "role": "user"})
    monkeypatch.setattr(main, "s3_put", lambda _path, key, _content_type: uploaded_keys.append(key))
    monkeypatch.setattr(main, "s3_delete", lambda key: deleted_keys.append(key))
    monkeypatch.setattr(main, "MAX_UPLOAD_MB", 50)

    archive = upload("test.zip", b"PK\\x03\\x04" + b"x" * 20)
    cover = upload("cover.png", b"\\x89PNG\\r\\n\\x1a\\n" + b"x" * (8 * 1024 * 1024))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(main.submit_resource(
            make_request(),
            resource_type="archive",
            name="test resource",
            description="",
            archive=archive,
            cover=cover,
            csrf_token="test-token",
        ))

    assert exc.value.status_code == 413
    assert len(uploaded_keys) == 1
    assert deleted_keys == uploaded_keys


def test_s3_delete_logs_failure(monkeypatch, caplog):
    class BrokenStorage:
        def delete_object(self, **_kwargs):
            raise RuntimeError("storage unavailable")

    monkeypatch.setattr(main, "s3_client", lambda: BrokenStorage())

    with caplog.at_level("ERROR"):
        main.s3_delete("files/orphan.zip")

    assert "Failed to delete object from storage" in caplog.text
    assert "files/orphan.zip" in caplog.text
