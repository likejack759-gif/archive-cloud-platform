import os
import zstandard as zstd
from starlette.requests import Request

from app import main


def test_secondary_compression_is_lossless_for_compressible_data(tmp_path):
    source = tmp_path / "source.zip"
    payload = (b"resource-index\n" * 200_000)
    source.write_bytes(payload)

    stored_path, encoding, stored_size = main.compress_if_smaller(str(source))
    try:
        assert encoding == "zstd"
        assert stored_size < len(payload)
        with open(stored_path, "rb") as compressed:
            restored = zstd.ZstdDecompressor().decompress(compressed.read())
        assert restored == payload
    finally:
        if stored_path != str(source):
            os.unlink(stored_path)


def test_secondary_compression_keeps_original_when_not_smaller(tmp_path):
    source = tmp_path / "random.zip"
    payload = os.urandom(128 * 1024)
    source.write_bytes(payload)

    stored_path, encoding, stored_size = main.compress_if_smaller(str(source))
    try:
        assert encoding == "raw"
        assert stored_path == str(source)
        assert stored_size == len(payload)
        assert source.read_bytes() == payload
    finally:
        if stored_path != str(source):
            os.unlink(stored_path)


def test_download_stream_restores_zstandard_wrapped_original():
    payload = b"original archive bytes" * 50_000
    compressed = zstd.ZstdCompressor(level=3).compress(payload)
    restored = b"".join(main.decompressed_s3_chunks(__import__("io").BytesIO(compressed)))
    assert restored == payload


def test_request_rate_limit_is_per_ip_and_bounded(monkeypatch):
    with main._request_windows_lock:
        main._request_windows.clear()
        main._last_request_cleanup = 0.0
    monkeypatch.setattr(main, "REQUEST_RATE_LIMIT", 2)
    monkeypatch.setattr(main, "REQUEST_RATE_WINDOW_SECONDS", 60)
    assert main.request_rate_limited("198.51.100.7") == (False, 0)
    assert main.request_rate_limited("198.51.100.7") == (False, 0)
    limited, retry_after = main.request_rate_limited("198.51.100.7")
    assert limited is True
    assert retry_after > 0
    assert main.request_rate_limited("198.51.100.8") == (False, 0)


def test_client_ip_uses_real_ip_only_for_trusted_proxy():
    headers = [(b"x-real-ip", b"198.51.100.44")]
    trusted_scope = {
        "type": "http", "http_version": "1.1", "method": "GET", "scheme": "http",
        "path": "/", "raw_path": b"/", "query_string": b"", "headers": headers,
        "client": ("127.0.0.1", 12345), "server": ("testserver", 80), "session": {},
    }
    assert main.get_client_ip(Request(trusted_scope)) == "198.51.100.44"

    untrusted_scope = dict(trusted_scope)
    untrusted_scope["client"] = ("198.51.100.9", 12345)
    assert main.get_client_ip(Request(untrusted_scope)) == "198.51.100.9"
