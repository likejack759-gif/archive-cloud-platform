import os
import zstandard as zstd

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
