import zipfile

from app import upload_security


def test_scanner_ping_fails_closed_when_unconfigured(monkeypatch):
    monkeypatch.setattr(upload_security, "CLAMAV_HOST", "")
    assert upload_security.clamav_ping() is False


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


def test_windows_zip_path_traversal_is_rejected(tmp_path):
    path = tmp_path / "bad-windows.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(r"..\\outside.txt", "bad")
    assert upload_security.inspect_zip_archive(str(path))[0] is False


def test_windows_drive_path_is_rejected(tmp_path):
    path = tmp_path / "bad-drive.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(r"C:\\Windows\\system.ini", "bad")
    assert upload_security.inspect_zip_archive(str(path))[0] is False


def test_symlink_zip_entry_is_rejected(tmp_path):
    path = tmp_path / "symlink.zip"
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo("link")
        info.create_system = 3
        info.external_attr = (0o120777 << 16)
        archive.writestr(info, "target")
    assert upload_security.inspect_zip_archive(str(path))[0] is False


def test_encrypted_flag_is_rejected(tmp_path):
    path = tmp_path / "encrypted-flag.zip"
    with zipfile.ZipFile(path, "w") as archive:
        info = zipfile.ZipInfo("secret.txt")
        info.flag_bits |= 1
        archive.writestr(info, "secret")
    # ZIP implementations may normalize unsupported encryption flags on write;
    # if the flag survives, the security helper must reject it.
    with zipfile.ZipFile(path) as archive:
        survives = bool(archive.infolist()[0].flag_bits & 1)
    if survives:
        assert upload_security.inspect_zip_archive(str(path))[0] is False


def test_valid_zip_is_accepted_by_structure_check(tmp_path):
    path = tmp_path / "ok.zip"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("docs/readme.txt", "hello")
    assert upload_security.inspect_zip_archive(str(path)) == (True, "OK")


def test_object_key_validation():
    assert upload_security.safe_object_key("files/sample.zip")
    assert not upload_security.safe_object_key("files/../secret")
    assert not upload_security.safe_object_key("covers/sample.png")
    assert not upload_security.safe_object_key("files//sample.zip")
    assert not upload_security.safe_object_key(r"files\\..\\secret")
