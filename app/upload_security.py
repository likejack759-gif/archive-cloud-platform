"""Fail-closed upload safety helpers."""
import os
import socket
import struct
import zipfile
from pathlib import PurePosixPath

CLAMAV_HOST = os.getenv("CLAMAV_HOST", "").strip()
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT_SECONDS = float(os.getenv("CLAMAV_TIMEOUT_SECONDS", "60"))
MAX_ARCHIVE_MEMBERS = int(os.getenv("MAX_ARCHIVE_MEMBERS", "20000"))
MAX_ARCHIVE_MEMBER_BYTES = int(os.getenv("MAX_ARCHIVE_MEMBER_BYTES", str(2 * 1024**3)))

def clamav_ping():
    if not CLAMAV_HOST:
        return False
    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=min(CLAMAV_TIMEOUT_SECONDS, 3)) as sock:
            sock.settimeout(min(CLAMAV_TIMEOUT_SECONDS, 3))
            sock.sendall(b"zPING" + bytes([0]))
            response = bytearray()
            while len(response) < 64:
                chunk = sock.recv(64)
                if not chunk:
                    break
                response.extend(chunk)
                if bytes([0]) in chunk or bytes([10]) in chunk:
                    break
        return bytes(response).decode("utf-8", "replace").strip().strip(chr(0)) == "PONG"
    except (OSError, TimeoutError, ValueError):
        return False


def clamav_scan(path):
    if not CLAMAV_HOST:
        return "unavailable", "ClamAV is not configured"
    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=CLAMAV_TIMEOUT_SECONDS) as sock:
            sock.settimeout(CLAMAV_TIMEOUT_SECONDS)
            sock.sendall(b"zINSTREAM" + bytes([0]))
            with open(path, "rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    sock.sendall(struct.pack("!I", len(chunk)) + chunk)
            sock.sendall(struct.pack("!I", 0))
            response = bytearray()
            while len(response) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                response.extend(chunk)
                if bytes([0]) in chunk or bytes([10]) in chunk:
                    break
        result = bytes(response).decode("utf-8", "replace").strip().strip(chr(0))
        if result.endswith("OK"):
            return "clean", result
        if "FOUND" in result:
            return "infected", result
        return "unavailable", result or "Empty scanner response"
    except (OSError, TimeoutError, ValueError) as exc:
        return "unavailable", type(exc).__name__

def inspect_zip_archive(path):
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if len(infos) > MAX_ARCHIVE_MEMBERS:
                return False, "Too many entries"
            total = 0
            for info in infos:
                parts = PurePosixPath(info.filename.replace(chr(92), "/"))
                mode = (info.external_attr >> 16) & 0o170000
                has_windows_drive = bool(parts.parts and len(parts.parts[0]) >= 2 and parts.parts[0][1] == ":")
                if parts.is_absolute() or has_windows_drive or ".." in parts.parts or mode == 0o120000 or info.flag_bits & 1:
                    return False, "Unsafe archive entry"
                if info.file_size < 0 or info.file_size > MAX_ARCHIVE_MEMBER_BYTES:
                    return False, "Entry too large"
                total += info.file_size
                if total > MAX_ARCHIVE_MEMBER_BYTES:
                    return False, "Expanded archive too large"
        return True, "OK"
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
        return False, "Invalid ZIP/APK"

def safe_object_key(key, prefix="files/"):
    return bool(key and key.startswith(prefix) and chr(92) not in key and all(p not in {"", ".", ".."} for p in key.split("/")))
