import asyncio
import tempfile

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


def test_cover_size_error_is_rendered_before_any_upload(monkeypatch):
    uploaded_keys = []
    deleted_keys = []
    monkeypatch.setattr(main, "current_user", lambda _request: {"id": 7, "role": "user"})
    monkeypatch.setattr(main, "s3_put", lambda _path, key, _content_type: uploaded_keys.append(key))
    monkeypatch.setattr(main, "s3_delete", lambda key: deleted_keys.append(key))
    monkeypatch.setattr(main, "MAX_UPLOAD_MB", 50)

    archive = upload("test.zip", b"PK\x03\x04" + b"x" * 20)
    cover = upload("cover.png", b"\x89PNG\r\n\x1a\n" + b"x" * (8 * 1024 * 1024))

    response = asyncio.run(main.submit_resource(
        make_request(),
        resource_type="archive",
        name="test resource",
        description="",
        archive=archive,
        cover=cover,
        csrf_token="test-token",
    ))

    # The HTML form route converts upload-limit exceptions into a useful
    # page-level validation message rather than returning a raw API error.
    assert response.status_code == 200
    assert "Cover image exceeds 8 MiB limit" in response.body.decode("utf-8")
    # All files are staged and validated before storage writes begin.
    assert uploaded_keys == []
    assert deleted_keys == []


def test_s3_delete_logs_failure(monkeypatch, caplog):
    class BrokenStorage:
        def delete_object(self, **_kwargs):
            raise RuntimeError("storage unavailable")

    monkeypatch.setattr(main, "s3_client", lambda: BrokenStorage())

    with caplog.at_level("ERROR"):
        main.s3_delete("files/orphan.zip")

    assert "Failed to delete object from storage" in caplog.text
    assert "files/orphan.zip" in caplog.text

def test_cover_at_size_limit_is_accepted_and_preserves_size():
    limit = 8 * 1024 * 1024
    cover = upload("cover.png", b"\x89PNG\r\n\x1a\n" + b"x" * (limit - 8))
    path = None
    try:
        path, size = asyncio.run(main.save_upload_to_temp(
            cover, limit, file_label="Cover image"
        ))
        assert size == limit
        with open(path, "rb") as saved:
            assert len(saved.read()) == limit
    finally:
        if path:
            from pathlib import Path
            Path(path).unlink(missing_ok=True)
