import zipfile
from app import upload_security

def test_scanner_fails_closed_when_unconfigured(monkeypatch, tmp_path):
    path = tmp_path / "sample.zip"
    path.write_bytes(b"sample")
    monkeypatch.setattr(upload_security, "CLAMAV_HOST", "")
    assert upload_security.clamav_scan(str(path))[0] == "unavailable"

def test_zip_path_traversal_is_rejected(tmp_path):
    path = tmp_path / "bad.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("../outside.txt", "bad")
    assert upload_security.inspect_zip_archive(str(path))[0] is False

def test_valid_zip_is_accepted_by_structure_check(tmp_path):
    path = tmp_path / "ok.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("docs/readme.txt", "hello")
    assert upload_security.inspect_zip_archive(str(path))[0] is True

def test_object_key_validation():
    assert upload_security.safe_object_key("files/sample.zip")
    assert not upload_security.safe_object_key("files/../secret")
    assert not upload_security.safe_object_key("covers/sample.png")
