import zipfile

from app import main


def test_clamav_missing_configuration_is_not_clean(monkeypatch, tmp_path):
    monkeypatch.setattr(main, "CLAMAV_HOST", "")
    sample = tmp_path / "sample.zip"
    sample.write_bytes(b"not really a zip")
    status, detail = main.clamav_scan(str(sample))
    assert status == "unavailable"
    assert "未配置" in detail


def test_zip_inspection_lists_suspicious_files_without_extracting(tmp_path):
    sample = tmp_path / "sample.zip"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("readme.txt", "hello reviewer")
        archive.writestr("payload.exe", b"not executed")
        archive.writestr("../outside.txt", "path traversal")
    result = main.inspect_zip_archive(str(sample))
    assert result["supported"] is True
    assert result["entry_count"] == 3
    items = {item["name"]: item for item in result["items"]}
    assert items["payload.exe"]["suspicious"] is True
    assert items["../outside.txt"]["unsafe"] is True
    assert items["readme.txt"]["previewable"] is True


def test_zip_inspection_previews_only_small_text_files(tmp_path):
    sample = tmp_path / "sample.zip"
    with zipfile.ZipFile(sample, "w") as archive:
        archive.writestr("readme.txt", "hello reviewer")
        archive.writestr("run.exe", "must not preview")
        archive.writestr("large.txt", "x" * (main.MAX_TEXT_PREVIEW_BYTES + 1))
    result = main.inspect_zip_archive(str(sample), "readme.txt")
    assert result["preview"] == "hello reviewer"
    blocked = main.inspect_zip_archive(str(sample), "run.exe")
    assert blocked["preview"] is None
    assert "仅允许预览" in blocked["preview_error"]
    too_large = main.inspect_zip_archive(str(sample), "large.txt")
    assert too_large["preview"] is None
    assert "64 KiB" in too_large["preview_error"]


def test_zip_inspection_rejects_invalid_zip(tmp_path):
    sample = tmp_path / "broken.zip"
    sample.write_bytes(b"not a zip")
    result = main.inspect_zip_archive(str(sample))
    assert result["supported"] is False
