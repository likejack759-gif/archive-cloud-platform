import os
import re
import secrets
import hashlib
import tempfile
import zipfile
import logging
import time
import threading
import socket
import struct
import ipaddress
import shutil
from pathlib import Path
import zstandard as zstd
from posixpath import normpath
from urllib.parse import quote

import boto3
import psycopg
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates
from psycopg.rows import dict_row
from psycopg.errors import IntegrityError
from app.storage_quota import MAX_STORAGE_BYTES, would_exceed_quota

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "500"))
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "true").lower() in {"1", "true", "yes", "on"}
LOGIN_FAILURE_LIMIT = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60
LOGIN_MAX_TRACKED_KEYS = 10_000
LOGIN_CLEANUP_INTERVAL_SECONDS = 60
LOGIN_CAPACITY_RETRY_SECONDS = 60
REQUEST_RATE_LIMIT = max(30, int(os.getenv("REQUEST_RATE_LIMIT", "120")))
REQUEST_RATE_WINDOW_SECONDS = max(10, int(os.getenv("REQUEST_RATE_WINDOW_SECONDS", "60")))
REQUEST_RATE_MAX_TRACKED_IPS = 10_000
_request_windows: dict[str, tuple[int, float]] = {}
_request_windows_lock = threading.Lock()
_last_request_cleanup = 0.0
_login_attempts: dict[str, tuple[int, float, float]] = {}
_login_attempts_lock = threading.Lock()
_last_login_cleanup = 0.0
S3_ENDPOINT = os.getenv("AWS_ENDPOINT_URL_S3", "").strip()
AWS_REGION = os.getenv("AWS_REGION", "us-east-2").strip()
S3_BUCKET = os.getenv("S3_BUCKET", "archive-files").strip()

app = FastAPI(title="Archive Cloud Platform")
if SECRET_KEY:
    app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY, same_site="lax", https_only=SESSION_HTTPS_ONLY)
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def db_connect():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL environment variable is not configured")
    return psycopg.connect(DATABASE_URL, row_factory=dict_row, connect_timeout=10, autocommit=False)


def s3_client():
    key = os.getenv("AWS_ACCESS_KEY_ID", "").strip()
    secret = os.getenv("AWS_SECRET_ACCESS_KEY", "").strip()
    if not all([S3_ENDPOINT, AWS_REGION, S3_BUCKET, key, secret]):
        raise RuntimeError("Object storage environment variables are incomplete")
    return boto3.client(
        "s3", endpoint_url=S3_ENDPOINT, region_name=AWS_REGION,
        aws_access_key_id=key, aws_secret_access_key=secret,
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return "scrypt$" + salt.hex() + "$" + digest.hex()


def verify_password(password: str, encoded: str) -> bool:
    try:
        method, salt_hex, digest_hex = encoded.split("$", 2)
        if method != "scrypt":
            return False
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return secrets.compare_digest(actual.hex(), digest_hex)
    except (ValueError, TypeError):
        return False


def init_db():
    with db_connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id BIGSERIAL PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS invites (
                id BIGSERIAL PRIMARY KEY,
                code TEXT NOT NULL UNIQUE,
                created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
                used_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                used_at TIMESTAMPTZ,
                label TEXT NOT NULL DEFAULT '',
                max_uses INTEGER NOT NULL DEFAULT 1,
                uses INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS resources (
                id BIGSERIAL PRIMARY KEY,
                user_id BIGINT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                resource_type TEXT NOT NULL DEFAULT 'archive',
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                filename TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                cover_filename TEXT,
                status TEXT NOT NULL DEFAULT 'pending',
                downloads BIGINT NOT NULL DEFAULT 0,
                size_bytes BIGINT NOT NULL DEFAULT 0,
                storage_size_bytes BIGINT NOT NULL DEFAULT 0,
                storage_encoding TEXT NOT NULL DEFAULT 'raw',
                sha256 TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                reviewed_at TIMESTAMPTZ,
                reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
                review_note TEXT NOT NULL DEFAULT ''
            )
        """)
        # Add missing fields safely for databases created by earlier revisions.
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT 'archive'")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS cover_filename TEXT")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS downloads BIGINT NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS size_bytes BIGINT NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS cover_size_bytes BIGINT NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS storage_size_bytes BIGINT NOT NULL DEFAULT 0")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS storage_encoding TEXT NOT NULL DEFAULT 'raw'")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS sha256 TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS scan_status TEXT NOT NULL DEFAULT 'not_scanned'")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS scan_result TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS review_note TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE invites ADD COLUMN IF NOT EXISTS label TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE invites ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 1")
        conn.execute("ALTER TABLE invites ADD COLUMN IF NOT EXISTS uses INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE invites SET uses=1 WHERE used_by IS NOT NULL AND uses=0")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ip_bans (
                id BIGSERIAL PRIMARY KEY,
                ip_address TEXT NOT NULL,
                reason TEXT NOT NULL DEFAULT '',
                created_by BIGINT REFERENCES users(id) ON DELETE SET NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ,
                revoked_at TIMESTAMPTZ,
                revoked_by BIGINT REFERENCES users(id) ON DELETE SET NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_audit_log (
                id BIGSERIAL PRIMARY KEY,
                actor_user_id BIGINT REFERENCES users(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                details TEXT NOT NULL DEFAULT '',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
        """)
        
        if ADMIN_USERNAME and ADMIN_PASSWORD:
            row = conn.execute(
                "SELECT id FROM users WHERE username=%s",
                (ADMIN_USERNAME,)
            ).fetchone()

            new_password_hash = hash_password(ADMIN_PASSWORD)

            if row is None:
                conn.execute(
                    "INSERT INTO users (username,password_hash,role) "
                    "VALUES (%s,%s,'admin')",
                    (ADMIN_USERNAME, new_password_hash)
                )
            else:
                conn.execute(
                    "UPDATE users SET password_hash=%s, role='admin' WHERE id=%s",
                    (new_password_hash, row["id"])
                )
        conn.commit()



@app.on_event("startup")
def startup():
    if not SECRET_KEY:
        raise RuntimeError("Set SECRET_KEY in your deployment environment")
    if not DATABASE_URL:
        raise RuntimeError("Set DATABASE_URL in your deployment environment")
    init_db()


def current_user(request: Request):
    uid = request.session.get("user_id")
    if not uid:
        return None
    with db_connect() as conn:
        return conn.execute("SELECT id, username, role, created_at FROM users WHERE id=%s", (uid,)).fetchone()


def require_user(request: Request):
    user = current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please log in")
    return user


def require_admin(request: Request):
    user = require_user(request)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    return user


def get_csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


def validate_csrf(request: Request, submitted_token: str) -> None:
    expected = request.session.get("csrf_token", "")
    if not expected or not secrets.compare_digest(str(expected), str(submitted_token or "")):
        raise HTTPException(status_code=403, detail="Security token invalid or expired. Refresh the page and try again.")


def login_rate_key(request: Request, username: str = "") -> str:
    # IP-wide throttling prevents bypass by rotating usernames.
    return get_client_ip(request)


def _cleanup_login_attempts(now: float, *, force: bool = False) -> None:
    """Remove expired throttle entries; caller must hold _login_attempts_lock."""
    global _last_login_cleanup
    if not force and now - _last_login_cleanup < LOGIN_CLEANUP_INTERVAL_SECONDS:
        return
    expired = [
        key for key, (_, window_start, blocked_until) in _login_attempts.items()
        if blocked_until <= now and now - window_start >= LOGIN_WINDOW_SECONDS
    ]
    for key in expired:
        _login_attempts.pop(key, None)
    _last_login_cleanup = now


def login_is_blocked(key: str) -> tuple[bool, int]:
    now = time.monotonic()
    with _login_attempts_lock:
        _cleanup_login_attempts(now)
        entry = _login_attempts.get(key)
        if entry is None and len(_login_attempts) >= LOGIN_MAX_TRACKED_KEYS:
            # Fail closed instead of allowing unlimited unique keys to grow memory.
            _cleanup_login_attempts(now, force=True)
            if len(_login_attempts) >= LOGIN_MAX_TRACKED_KEYS:
                return True, LOGIN_CAPACITY_RETRY_SECONDS
            entry = None
        if entry is None:
            return False, 0
        _, window_start, blocked_until = entry
        if blocked_until > now:
            return True, max(1, int(blocked_until - now))
        if now - window_start >= LOGIN_WINDOW_SECONDS or blocked_until:
            _login_attempts[key] = (0, now, 0.0)
    return False, 0


def record_login_failure(key: str) -> int:
    now = time.monotonic()
    with _login_attempts_lock:
        _cleanup_login_attempts(now)
        entry = _login_attempts.get(key)
        if entry is None and len(_login_attempts) >= LOGIN_MAX_TRACKED_KEYS:
            _cleanup_login_attempts(now, force=True)
            if len(_login_attempts) >= LOGIN_MAX_TRACKED_KEYS:
                return LOGIN_CAPACITY_RETRY_SECONDS
            entry = None
        attempts, window_start, blocked_until = entry or (0, now, 0.0)
        if now - window_start >= LOGIN_WINDOW_SECONDS or blocked_until:
            attempts, window_start, blocked_until = 0, now, 0.0
        attempts += 1
        if attempts >= LOGIN_FAILURE_LIMIT:
            blocked_until = now + LOGIN_LOCKOUT_SECONDS
        _login_attempts[key] = (attempts, window_start, blocked_until)
        return max(1, int(blocked_until - now)) if blocked_until > now else 0


def clear_login_failures(key: str) -> None:
    with _login_attempts_lock:
        _login_attempts.pop(key, None)


@app.middleware("http")
async def request_size_guard(request: Request, call_next):
    # Reject oversized requests early when Content-Length is supplied.
    # The upload handler still enforces actual bytes read.
    raw_length = request.headers.get("content-length")
    if raw_length:
        try:
            content_length = int(raw_length)
        except ValueError:
            return PlainTextResponse("Invalid Content-Length", status_code=400)
        limit = (MAX_UPLOAD_MB + 12) * 1024 * 1024 if request.url.path == "/submit" and request.method == "POST" else 2 * 1024 * 1024
        if content_length < 0 or content_length > limit:
            return PlainTextResponse("Request body too large", status_code=413)
    if request.url.path != "/health":
        client_ip = get_client_ip(request)
        limited, retry_after = request_rate_limited(client_ip)
        if limited:
            return PlainTextResponse(
                "Too many requests; please slow down",
                status_code=429,
                headers={"Retry-After": str(retry_after), "Cache-Control": "no-store"},
            )
        try:
            with db_connect() as conn:
                ban = conn.execute(
                    "SELECT reason FROM ip_bans WHERE ip_address=%s AND revoked_at IS NULL "
                    "AND (expires_at IS NULL OR expires_at > NOW()) ORDER BY created_at DESC LIMIT 1",
                    (client_ip,),
                ).fetchone()
            if ban:
                return PlainTextResponse("Access temporarily restricted", status_code=403, headers={"Cache-Control": "no-store"})
        except Exception:
            logging.exception("IP ban check failed")
            return PlainTextResponse("Access control temporarily unavailable", status_code=503)
    return await call_next(request)


TRUSTED_PROXY_IPS = {
    value.strip() for value in os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1").split(",") if value.strip()
}


def get_client_ip(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    # Trust X-Real-IP only from an explicitly trusted reverse proxy.
    if peer in TRUSTED_PROXY_IPS:
        forwarded = request.headers.get("x-real-ip", "").strip()
        try:
            return str(ipaddress.ip_address(forwarded))
        except ValueError:
            pass
    try:
        return str(ipaddress.ip_address(peer))
    except ValueError:
        return "unknown"


def request_rate_limited(client_ip: str) -> tuple[bool, int]:
    """Bound per-IP request volume while keeping memory use capped."""
    global _last_request_cleanup
    now = time.monotonic()
    with _request_windows_lock:
        if now - _last_request_cleanup >= 60:
            for key, (_, started) in list(_request_windows.items()):
                if now - started >= REQUEST_RATE_WINDOW_SECONDS:
                    _request_windows.pop(key, None)
            _last_request_cleanup = now
        entry = _request_windows.get(client_ip)
        if entry is None:
            if len(_request_windows) >= REQUEST_RATE_MAX_TRACKED_IPS:
                return True, REQUEST_RATE_WINDOW_SECONDS
            _request_windows[client_ip] = (1, now)
            return False, 0
        count, started = entry
        if now - started >= REQUEST_RATE_WINDOW_SECONDS:
            _request_windows[client_ip] = (1, now)
            return False, 0
        if count >= REQUEST_RATE_LIMIT:
            return True, max(1, int(REQUEST_RATE_WINDOW_SECONDS - (now - started)))
        _request_windows[client_ip] = (count + 1, started)
        return False, 0


def audit_security_event(actor_user_id: int | None, action: str, target: str = "", details: str = "") -> None:
    try:
        with db_connect() as conn:
            conn.execute(
                "INSERT INTO security_audit_log (actor_user_id,action,target,details) VALUES (%s,%s,%s,%s)",
                (actor_user_id, action[:80], target[:200], details[:1000]),
            )
            conn.commit()
    except Exception:
        logging.exception("Failed to write security audit event: %s", action)


def page(request: Request, template: str, **context):
    if not context.get("user"):
        context["user"] = current_user(request)
    context.setdefault("csrf_token", get_csrf_token(request))
    return templates.TemplateResponse(request=request, name=template, context=context)


def safe_name(name: str) -> str:
    name = Path(name or "upload.bin").name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (name or "upload.bin")[:180]



CLAMAV_HOST = os.getenv("CLAMAV_HOST", "").strip()
CLAMAV_PORT = int(os.getenv("CLAMAV_PORT", "3310"))
CLAMAV_TIMEOUT_SECONDS = float(os.getenv("CLAMAV_TIMEOUT_SECONDS", "30"))
MAX_ARCHIVE_INSPECT_ENTRIES = 2000
MAX_TEXT_PREVIEW_BYTES = 64 * 1024
TEXT_PREVIEW_SUFFIXES = {
    ".txt", ".md", ".json", ".xml", ".html", ".htm", ".js", ".mjs",
    ".css", ".py", ".sh", ".bat", ".ps1", ".yml", ".yaml", ".ini",
    ".cfg", ".conf", ".properties", ".csv", ".log", ".sql", ".toml",
}
SUSPICIOUS_SUFFIXES = {
    ".exe", ".dll", ".scr", ".com", ".bat", ".cmd", ".ps1", ".vbs",
    ".vbe", ".js", ".jse", ".wsf", ".hta", ".msi", ".apk", ".jar",
    ".so", ".dex", ".sh", ".lnk",
}


def clamav_scan(path: str) -> tuple[str, str]:
    """Scan a staged file using a configured ClamAV clamd INSTREAM endpoint.

    Return ('clean'|'infected'|'unavailable', short detail). Missing scanner
    configuration is deliberately not treated as a clean result.
    """
    if not CLAMAV_HOST:
        return "unavailable", "未配置 ClamAV 扫描服务"
    try:
        with socket.create_connection((CLAMAV_HOST, CLAMAV_PORT), timeout=CLAMAV_TIMEOUT_SECONDS) as sock:
            sock.settimeout(CLAMAV_TIMEOUT_SECONDS)
            sock.sendall(b"zINSTREAM\0")
            with open(path, "rb") as source:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    sock.sendall(struct.pack("!I", len(chunk)))
                    sock.sendall(chunk)
            sock.sendall(struct.pack("!I", 0))
            response = bytearray()
            while len(response) < 4096:
                part = sock.recv(1024)
                if not part:
                    break
                response.extend(part)
                if b"\0" in part:
                    break
        result = bytes(response).decode("utf-8", "replace").strip("\0\r\n ")
        if result.endswith("OK"):
            return "clean", result[:200]
        if "FOUND" in result:
            return "infected", result[:200]
        return "unavailable", (result or "ClamAV 返回无法识别的结果")[:200]
    except (OSError, TimeoutError, ValueError) as exc:
        logging.warning("ClamAV scanner unavailable: %s", type(exc).__name__)
        return "unavailable", "扫描服务不可用或超时"


def _safe_archive_member(info: zipfile.ZipInfo) -> tuple[bool, str]:
    name = info.filename.replace("\\", "/")
    normalized = normpath(name)
    parts = name.split("/")
    if name.startswith("/") or (parts and ":" in parts[0]) or any(part == ".." for part in parts) or normalized == ".." or normalized.startswith("../"):
        return False, "路径穿越风险"
    mode = (info.external_attr >> 16) & 0xFFFF
    if (mode & 0o170000) == 0o120000:
        return False, "符号链接"
    return True, ""


def inspect_zip_archive(path: str, member_name: str = "") -> dict:
    """List ZIP/APK contents without extracting files; optionally preview small text."""
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            total_uncompressed = sum(max(0, i.file_size) for i in infos)
            items = []
            for info in infos[:MAX_ARCHIVE_INSPECT_ENTRIES]:
                safe, reason = _safe_archive_member(info)
                suffix = Path(info.filename).suffix.lower()
                items.append({
                    "name": info.filename[:300],
                    "size": max(0, info.file_size),
                    "compressed_size": max(0, info.compress_size),
                    "suspicious": suffix in SUSPICIOUS_SUFFIXES,
                    "unsafe": not safe,
                    "reason": reason,
                    "previewable": safe and not info.is_dir() and suffix in TEXT_PREVIEW_SUFFIXES and 0 < info.file_size <= MAX_TEXT_PREVIEW_BYTES,
                })
            preview = None
            preview_error = ""
            if member_name:
                found = next((i for i in infos if i.filename == member_name), None)
                if found is None:
                    preview_error = "未找到指定文件"
                else:
                    safe, reason = _safe_archive_member(found)
                    suffix = Path(found.filename).suffix.lower()
                    if not safe:
                        preview_error = "该条目存在路径或链接风险，禁止预览"
                    elif found.is_dir() or suffix not in TEXT_PREVIEW_SUFFIXES:
                        preview_error = "仅允许预览常见文本文件；不会执行或渲染其内容"
                    elif found.file_size > MAX_TEXT_PREVIEW_BYTES:
                        preview_error = "文件超过 64 KiB 预览上限"
                    else:
                        raw = zf.read(found)
                        preview = raw.decode("utf-8", "replace")
            return {
                "supported": True, "items": items, "entry_count": len(infos),
                "truncated": len(infos) > MAX_ARCHIVE_INSPECT_ENTRIES,
                "total_uncompressed": total_uncompressed, "preview": preview,
                "preview_error": preview_error,
            }
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError):
        return {"supported": False, "items": [], "entry_count": 0, "truncated": False,
                "total_uncompressed": 0, "preview": None,
                "preview_error": "无法安全读取该 ZIP/APK 文件；7Z/RAR 内容浏览尚未接入"}


def _download_resource_to_temp(key: str) -> str:
    fd, path = tempfile.mkstemp(prefix="admin-inspect-", suffix=Path(key).suffix.lower())
    try:
        with os.fdopen(fd, "wb") as target:
            obj = s3_client().get_object(Bucket=S3_BUCKET, Key=key)
            body = obj["Body"]
            total = 0
            try:
                for chunk in body.iter_chunks(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    total += len(chunk)
                    if total > MAX_UPLOAD_MB * 1024 * 1024:
                        raise HTTPException(status_code=413, detail="文件超过平台检查上限")
                    target.write(chunk)
            finally:
                body.close()
        return path
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def archive_is_valid(path: str, filename: str) -> bool:
    ext = Path(filename).suffix.lower()
    with open(path, "rb") as f:
        head = f.read(16)
    if ext == ".zip":
        return head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06") or head.startswith(b"PK\x07\x08")
    if ext == ".apk":
        if not (head.startswith(b"PK\x03\x04") or head.startswith(b"PK\x05\x06")):
            return False
        try:
            with zipfile.ZipFile(path) as zf:
                return "AndroidManifest.xml" in zf.namelist()
        except (zipfile.BadZipFile, OSError):
            return False
    if ext == ".7z":
        return head.startswith(b"7z\xbc\xaf\x27\x1c")
    if ext == ".rar":
        return head.startswith(b"Rar!\x1a\x07")
    return False


async def save_upload_to_temp(upload: UploadFile, max_bytes: int, *, file_label: str = "File") -> tuple[str, int]:
    suffix = Path(upload.filename or "upload.bin").suffix[:12]
    fd, path = tempfile.mkstemp(prefix="archive-upload-", suffix=suffix)
    total = 0
    try:
        with os.fdopen(fd, "wb") as out:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    limit_mib = max_bytes / (1024 * 1024)
                    raise HTTPException(status_code=413, detail=f"{file_label} exceeds {limit_mib:g} MiB limit")
                out.write(chunk)
        if total == 0:
            raise HTTPException(status_code=400, detail="Uploaded file is empty")
        return path, total
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    finally:
        await upload.close()


def s3_put(local_path: str, key: str, content_type: str):
    client = s3_client()
    client.upload_file(local_path, S3_BUCKET, key, ExtraArgs={"ContentType": content_type})


def s3_total_bytes() -> int:
    """Return actual object bytes in the bucket, including covers and orphaned uploads."""
    client = s3_client()
    total = 0
    request = {"Bucket": S3_BUCKET}
    while True:
        response = client.list_objects_v2(**request)
        total += sum(int(item.get("Size", 0)) for item in response.get("Contents", []))
        if not response.get("IsTruncated"):
            return total
        token = response.get("NextContinuationToken")
        if not token:
            raise RuntimeError("Object storage returned a truncated listing without a continuation token")
        request["ContinuationToken"] = token


def s3_delete(key: str):
    """Delete an uploaded object; log failures so orphaned objects can be investigated."""
    try:
        s3_client().delete_object(Bucket=S3_BUCKET, Key=key)
    except Exception:
        logging.exception("Failed to delete object from storage: key=%s", key)

def s3_delete_strict(key: str):
    """Deletion used by explicit user/admin actions; propagate errors for retry."""
    s3_client().delete_object(Bucket=S3_BUCKET, Key=key)


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        while True:
            chunk = source.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def compress_if_smaller(path: str) -> tuple[str, str, int]:
    """Losslessly wrap the file in Zstandard only if at least 1% smaller."""
    compressed_path = None
    try:
        original_size = os.path.getsize(path)
        # Keep a safety margin so temporary compression cannot exhaust the disk.
        if shutil.disk_usage(os.path.dirname(path) or ".").free < original_size + 256 * 1024 * 1024:
            return path, "raw", original_size
        fd, compressed_path = tempfile.mkstemp(prefix="archive-store-", suffix=".zst")
        os.close(fd)
        with open(path, "rb") as source, open(compressed_path, "wb") as target:
            zstd.ZstdCompressor(level=3, threads=0).copy_stream(source, target)
        original_size = os.path.getsize(path)
        compressed_size = os.path.getsize(compressed_path)
        if compressed_size <= int(original_size * 0.99):
            return compressed_path, "zstd", compressed_size
        os.unlink(compressed_path)
        return path, "raw", original_size
    except Exception:
        logging.exception("Secondary compression failed; preserving original upload")
        if compressed_path:
            try:
                os.unlink(compressed_path)
            except OSError:
                pass
        return path, "raw", os.path.getsize(path)


def decompressed_s3_chunks(body, chunk_size: int = 1024 * 1024):
    reader = zstd.ZstdDecompressor().stream_reader(body)
    try:
        while True:
            chunk = reader.read(chunk_size)
            if not chunk:
                break
            yield chunk
    finally:
        reader.close()
        try:
            body.close()
        except Exception:
            pass


def stream_s3_object(key: str, filename: str, content_type: str):
    try:
        obj = s3_client().get_object(Bucket=S3_BUCKET, Key=key)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchKey", "404", "NotFound"}:
            raise HTTPException(status_code=404, detail="File not found")
        raise HTTPException(status_code=502, detail="Object storage read failed")
    body = obj["Body"]
    headers = {"Content-Disposition": f"inline; filename*=UTF-8''{quote(filename)}", "Cache-Control": "private, no-store"}
    return StreamingResponse(body.iter_chunks(chunk_size=1024 * 1024), media_type=content_type, headers=headers)


@app.get("/", response_class=HTMLResponse)
def index(request: Request, q: str = "", resource_type: str = "", sort: str = "latest"):
    user = current_user(request)
    where = ["r.status='approved'"]
    params = []
    query_text = q.strip()[:100]
    if query_text:
        where.append("(r.name ILIKE %s OR r.description ILIKE %s OR r.original_filename ILIKE %s)")
        pattern = f"%{query_text}%"
        params.extend([pattern, pattern, pattern])
    if resource_type in {"archive", "apk"}:
        where.append("r.resource_type=%s")
        params.append(resource_type)
    sort = sort if sort in {"latest", "popular", "name"} else "latest"
    order_by = {
        "latest": "r.created_at DESC, r.id DESC",
        "popular": "r.downloads DESC, r.created_at DESC",
        "name": "LOWER(r.name) ASC, r.created_at DESC",
    }.get(sort, "r.created_at DESC, r.id DESC")
    where_sql = " AND ".join(where)
    with db_connect() as conn:
        resources = conn.execute(
            "SELECT r.*, u.username AS owner_name FROM resources r JOIN users u ON u.id=r.user_id WHERE "
            + where_sql + " ORDER BY " + order_by + " LIMIT 100",
            tuple(params),
        ).fetchall()
        popular = conn.execute(
            "SELECT r.id, r.name, r.resource_type, r.downloads FROM resources r "
            "WHERE r.status='approved' ORDER BY r.downloads DESC, r.created_at DESC LIMIT 5"
        ).fetchall()
        stats = conn.execute(
            "SELECT COUNT(*) AS resources, COALESCE(SUM(downloads),0) AS downloads, "
            "COUNT(*) FILTER (WHERE resource_type='apk') AS apps, "
            "COUNT(*) FILTER (WHERE resource_type <> 'apk') AS archives "
            "FROM resources WHERE status='approved'"
        ).fetchone()
    return page(
        request, "index.html", user=user, items=resources, resources=resources,
        q=query_text, resource_type=resource_type, sort=sort, popular=popular, stats=stats,
    )


@app.get("/resource/{resource_id}", response_class=HTMLResponse)
def resource_detail(request: Request, resource_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db_connect() as conn:
        resource = conn.execute(
            "SELECT r.*, u.username AS owner_name FROM resources r JOIN users u ON u.id=r.user_id WHERE r.id=%s AND r.status='approved'",
            (resource_id,),
        ).fetchone()
    if not resource:
        raise HTTPException(status_code=404, detail="Resource not found")
    return page(request, "resource_detail.html", user=user, r=resource)


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    return page(request, "register.html", error=None)


@app.post("/register")
def register(request: Request, username: str = Form(...), password: str = Form(...), invite: str = Form(...), csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    username = username.strip()
    invite_code = invite.strip()
    invite_digest = hashlib.sha256(invite_code.encode("utf-8")).hexdigest()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return page(request, "register.html", error="用户名需为 3–32 位字母、数字、点、下划线或连字符。")
    if len(password) < 10:
        return page(request, "register.html", error="密码至少需要 10 个字符。")
    try:
        with db_connect() as conn:
            invite_row = conn.execute(
                "SELECT id, is_active, used_by, max_uses, uses FROM invites WHERE code=%s FOR UPDATE",
                (invite_digest,),
            ).fetchone()
            # Accept legacy plaintext invite codes created by an earlier version.
            if invite_row is None:
                invite_row = conn.execute(
                    "SELECT id, is_active, used_by, max_uses, uses FROM invites WHERE code=%s FOR UPDATE",
                    (invite_code,),
                ).fetchone()
            if not invite_row or not invite_row["is_active"] or invite_row["uses"] >= invite_row["max_uses"]:
                return page(request, "register.html", error="邀请码无效、次数已用完或已停用。")
            user = conn.execute("INSERT INTO users (username,password_hash,role) VALUES (%s,%s,'user') RETURNING id", (username, hash_password(password))).fetchone()
            next_uses = invite_row["uses"] + 1
            conn.execute(
                "UPDATE invites SET uses=%s, used_by=CASE WHEN %s >= max_uses THEN %s ELSE used_by END, used_at=NOW(), is_active=CASE WHEN %s >= max_uses THEN FALSE ELSE is_active END WHERE id=%s",
                (next_uses, next_uses, user["id"], next_uses, invite_row["id"]),
            )
            conn.commit()
    except IntegrityError:
        return page(request, "register.html", error="用户名已存在，请更换用户名。")
    request.session.clear()
    request.session["user_id"] = user["id"]
    return RedirectResponse("/", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return page(request, "login.html", error=None)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...), csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    key = login_rate_key(request, username)
    blocked, retry_after = login_is_blocked(key)
    if blocked:
        return page(request, "login.html", error=f"登录尝试过多，请在 {retry_after} 秒后重试。")
    with db_connect() as conn:
        user = conn.execute("SELECT id, password_hash FROM users WHERE username=%s", (username.strip(),)).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        retry_after = record_login_failure(key)
        if retry_after:
            return page(request, "login.html", error=f"登录失败次数过多，账号和当前网络组合已暂时限制登录，请在 {retry_after} 秒后重试。")
        return page(request, "login.html", error="用户名或密码不正确。")
    clear_login_failures(key)
    request.session.clear()
    request.session["user_id"] = user["id"]
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request, csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    request.session.clear()
    return RedirectResponse("/", status_code=303)


@app.get("/submit", response_class=HTMLResponse)
def submit_page(request: Request):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error=None)


@app.post("/submit")
async def submit_resource(
    request: Request,
    resource_type: str = Form(...),
    name: str = Form(...),
    description: str = Form(""),
    archive: UploadFile = File(...),
    cover: UploadFile | None = File(None),
    csrf_token: str = Form(...),
):
    validate_csrf(request, csrf_token)
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    name = name.strip()
    if not name or len(name) > 100:
        return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="资源名称不能为空且不能超过 100 个字符。")
    if resource_type not in {"archive", "apk"}:
        return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="请选择有效的资源类型。")
    archive_filename = safe_name(archive.filename or "")
    if Path(archive_filename).suffix.lower() not in {".zip", ".7z", ".rar", ".apk"}:
        return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="只允许 ZIP、7Z、RAR 或 APK 文件。")
    archive_path = None
    cover_path = None
    archive_key = None
    cover_key = None
    archive_size = 0
    cover_size = 0
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    try:
        # Stage and validate all files before reserving quota or uploading anything.
        archive_path, archive_size = await save_upload_to_temp(archive, max_bytes, file_label="Archive")
        original_sha256 = sha256_file(archive_path)
        if not archive_is_valid(archive_path, archive_filename):
            return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="文件内容与扩展名不匹配，或文件格式无效。")
        scan_status, scan_result = clamav_scan(archive_path)
        if scan_status == "infected":
            return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="安全扫描检测到疑似恶意文件，已拒绝上传。")

        cover_filename = None
        cover_ext = None
        cover_mime = None
        if cover and cover.filename:
            cover_filename = safe_name(cover.filename)
            cover_ext = Path(cover_filename).suffix.lower()
            if cover_ext not in {".jpg", ".jpeg", ".png", ".webp", ".gif"}:
                return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="封面只允许 JPG、PNG、WEBP 或 GIF 图片。")
            cover_path, cover_size = await save_upload_to_temp(cover, 8 * 1024 * 1024, file_label="Cover image")
            with open(cover_path, "rb") as f:
                signature = f.read(12)
            valid = (cover_ext in {".jpg", ".jpeg"} and signature.startswith(b"\xff\xd8\xff")) or (cover_ext == ".png" and signature.startswith(b"\x89PNG\r\n\x1a\n")) or (cover_ext == ".gif" and signature.startswith((b"GIF87a", b"GIF89a"))) or (cover_ext == ".webp" and signature.startswith(b"RIFF") and signature[8:12] == b"WEBP")
            if not valid:
                return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="封面文件内容不是有效的支持格式图片。")
            cover_mime = {".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".gif": "image/gif"}[cover_ext]

        stored_path, storage_encoding, stored_size = compress_if_smaller(archive_path)
        archive_key = f"files/{secrets.token_hex(16)}_{archive_filename}" + (".zst" if storage_encoding == "zstd" else "")
        cover_key = f"covers/{secrets.token_hex(16)}{cover_ext}" if cover_ext else None
        content_type = "application/octet-stream"
        incoming_bytes = stored_size + cover_size

        # Serialize quota check + object writes + DB insert across app workers.
        # The transaction-level advisory lock remains held until commit/rollback.
        with db_connect() as conn:
            conn.execute("SELECT pg_advisory_xact_lock(%s)", (730214051,))
            current_bytes = s3_total_bytes()
            if would_exceed_quota(current_bytes, incoming_bytes):
                raise HTTPException(
                    status_code=413,
                    detail="平台存储空间已满（总容量上限为 5 GiB），请联系管理员清理资源后再上传。",
                )
            s3_put(stored_path, archive_key, content_type)
            if cover_path and cover_key and cover_mime:
                s3_put(cover_path, cover_key, cover_mime)
            conn.execute(
                "INSERT INTO resources (user_id,resource_type,name,description,filename,original_filename,cover_filename,status,size_bytes,cover_size_bytes,storage_size_bytes,storage_encoding,sha256,scan_status,scan_result) VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s,%s,%s,%s,%s,%s,%s)",
                (user["id"], resource_type[:40], name, description.strip()[:2000], archive_key, archive_filename, cover_key, archive_size, cover_size, stored_size, storage_encoding, original_sha256, scan_status, scan_result),
            )
            conn.commit()
        return RedirectResponse("/my-resources?notice=submitted", status_code=303)
    except HTTPException:
        if archive_key:
            s3_delete(archive_key)
        if cover_key:
            s3_delete(cover_key)
        raise
    except (BotoCoreError, ClientError, RuntimeError) as exc:
        if archive_key:
            s3_delete(archive_key)
        if cover_key:
            s3_delete(cover_key)
        return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="上传失败：请检查对象存储配置或稍后重试。")
    except Exception:
        logging.exception("Unexpected error in submit_resource")
        if archive_key:
            s3_delete(archive_key)
        if cover_key:
            s3_delete(cover_key)
        return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="提交失败，请稍后重试。")
    finally:
        for p in (archive_path, cover_path, locals().get("stored_path")):
            if p:
                try:
                    os.unlink(p)
                except OSError:
                    pass


@app.get("/my-resources", response_class=HTMLResponse)
def my_resources(request: Request, notice: str = ""):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db_connect() as conn:
        resources = conn.execute("SELECT * FROM resources WHERE user_id=%s ORDER BY created_at DESC", (user["id"],)).fetchall()
    return page(request, "my_resources.html", user=user, items=resources, resources=resources, notice=notice, submitted=(notice == "submitted"))


@app.get("/covers/{filename:path}")
def cover_file(request: Request, filename: str):
    if not current_user(request):
        raise HTTPException(status_code=401, detail="Please log in")
    if not filename.startswith("covers/") or ".." in filename:
        raise HTTPException(status_code=404, detail="File not found")
    with db_connect() as conn:
        exists = conn.execute("SELECT 1 FROM resources WHERE cover_filename=%s LIMIT 1", (filename,)).fetchone()
    if not exists:
        raise HTTPException(status_code=404, detail="File not found")
    ext = Path(filename).suffix.lower()
    mime = {".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png", ".webp":"image/webp", ".gif":"image/gif"}.get(ext, "application/octet-stream")
    return stream_s3_object(filename, Path(filename).name, mime)


@app.get("/download/{resource_id}")
def download_resource(request: Request, resource_id: int):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    with db_connect() as conn:
        resource = conn.execute("SELECT * FROM resources WHERE id=%s", (resource_id,)).fetchone()
        if not resource or resource["status"] != "approved":
            raise HTTPException(status_code=404, detail="Resource not found")
        # Fail closed: only resources with a confirmed clean scan may be downloaded.
        # This also protects legacy resources that were approved before scanning existed.
        if resource.get("scan_status") != "clean":
            raise HTTPException(status_code=404, detail="Resource not found")
        conn.execute("UPDATE resources SET downloads=downloads+1 WHERE id=%s", (resource_id,))
        conn.commit()
    key = resource["filename"]
    if not key.startswith("files/") or ".." in key:
        raise HTTPException(status_code=404, detail="File not found")
    try:
        obj = s3_client().get_object(Bucket=S3_BUCKET, Key=key)
    except ClientError:
        raise HTTPException(status_code=502, detail="Unable to retrieve file")
    body = obj["Body"]
    filename = safe_name(resource["original_filename"] or Path(key).name)
    headers = {
        "Content-Disposition": f"attachment; filename*=UTF-8''{quote(filename)}",
        "Cache-Control": "private, no-store",
        "X-Content-Type-Options": "nosniff",
        "X-Content-SHA256": resource.get("sha256", ""),
    }
    if resource.get("storage_encoding", "raw") == "zstd":
        return StreamingResponse(decompressed_s3_chunks(body), media_type="application/octet-stream", headers=headers)
    return StreamingResponse(body.iter_chunks(chunk_size=1024 * 1024), media_type="application/octet-stream", headers=headers)


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, notice: str = ""):
    user = current_user(request)
    if not user:
        return RedirectResponse("/login", status_code=303)
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access required")
    with db_connect() as conn:
        stats_row = conn.execute("SELECT (SELECT COUNT(*) FROM users) AS users, (SELECT COUNT(*) FROM resources) AS resources, (SELECT COUNT(*) FROM resources WHERE status='pending') AS pending, (SELECT COUNT(*) FROM resources WHERE status='approved') AS approved").fetchone()
        pending = conn.execute("SELECT r.*, u.username AS owner_name FROM resources r JOIN users u ON u.id=r.user_id WHERE r.status='pending' ORDER BY r.created_at ASC").fetchall()
        invites = conn.execute("SELECT i.*, i.is_active AS active FROM invites i ORDER BY i.created_at DESC LIMIT 100").fetchall()
        users = conn.execute("SELECT id,username,role,created_at FROM users ORDER BY created_at DESC LIMIT 200").fetchall()
        all_resources = conn.execute("SELECT r.id,r.name,r.original_filename,r.status,r.size_bytes,r.created_at,u.username AS owner_name FROM resources r JOIN users u ON u.id=r.user_id ORDER BY r.created_at DESC LIMIT 100").fetchall()
        bans = conn.execute("SELECT b.*,u.username AS creator_name FROM ip_bans b LEFT JOIN users u ON u.id=b.created_by WHERE b.revoked_at IS NULL AND (b.expires_at IS NULL OR b.expires_at > NOW()) ORDER BY b.created_at DESC LIMIT 200").fetchall()
        audit_events = conn.execute("SELECT a.*,u.username AS actor_name FROM security_audit_log a LEFT JOIN users u ON u.id=a.actor_user_id ORDER BY a.created_at DESC LIMIT 50").fetchall()
    stats = dict(stats_row)
    return page(request, "admin.html", user=user, stats=stats, pending=pending, invites=invites, users=users, all_resources=all_resources, bans=bans, audit_events=audit_events, notice=notice)


@app.post("/admin/invites")
def create_invite(request: Request, label: str = Form(""), max_uses: int = Form(1), csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    admin = require_admin(request)
    max_uses = max(1, min(int(max_uses), 1000))
    label = label.strip()[:100]
    code = secrets.token_urlsafe(12).replace("-", "A").replace("_", "B")[:16]
    code_digest = hashlib.sha256(code.encode("utf-8")).hexdigest()
    with db_connect() as conn:
        conn.execute(
            "INSERT INTO invites (code,created_by,is_active,label,max_uses,uses) VALUES (%s,%s,TRUE,%s,%s,0)",
            (code_digest, admin["id"], label, max_uses),
        )
        conn.commit()
    request.session["new_invite"] = code
    return RedirectResponse("/admin?notice=invite_created", status_code=303)


@app.post("/admin/invites/{invite_id}/toggle")
def toggle_invite(request: Request, invite_id: int, csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    require_admin(request)
    with db_connect() as conn:
        conn.execute("UPDATE invites SET is_active=NOT is_active WHERE id=%s AND uses < max_uses", (invite_id,))
        conn.commit()
    return RedirectResponse("/admin?notice=invite_updated", status_code=303)


@app.post("/admin/resources/{resource_id}/review")
def review_resource(request: Request, resource_id: int, action: str = Form(...), review_note: str = Form(""), csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    admin = require_admin(request)
    if action not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="Invalid review action")
    status = "approved" if action == "approve" else "rejected"
    with db_connect() as conn:
        resource = conn.execute("SELECT scan_status FROM resources WHERE id=%s AND status='pending' FOR UPDATE", (resource_id,)).fetchone()
        if not resource:
            return RedirectResponse("/admin?notice=resource_reviewed", status_code=303)
        if action == "approve" and resource["scan_status"] != "clean":
            return RedirectResponse("/admin?notice=scan_required", status_code=303)
        conn.execute("UPDATE resources SET status=%s,review_note=%s,reviewed_at=NOW(),reviewed_by=%s WHERE id=%s AND status='pending'", (status, review_note.strip()[:500], admin["id"], resource_id))
        conn.commit()
    return RedirectResponse("/admin?notice=resource_reviewed", status_code=303)



@app.get("/admin/resources/{resource_id}/contents", response_class=HTMLResponse)
def admin_resource_contents(request: Request, resource_id: int, member: str = ""):
    admin = require_admin(request)
    with db_connect() as conn:
        resource = conn.execute(
            "SELECT r.*, u.username AS owner_name FROM resources r JOIN users u ON u.id=r.user_id WHERE r.id=%s",
            (resource_id,),
        ).fetchone()
    if not resource or resource["status"] != "pending":
        raise HTTPException(status_code=404, detail="Pending resource not found")
    key = resource["filename"]
    if not key or not key.startswith("files/") or ".." in key:
        raise HTTPException(status_code=404, detail="File not found")
    temp_path = None
    restored_path = None
    try:
        temp_path = _download_resource_to_temp(key)
        inspect_path = temp_path
        if resource.get("storage_encoding", "raw") == "zstd":
            needed = int(resource.get("size_bytes") or 0) + 256 * 1024 * 1024
            if shutil.disk_usage(tempfile.gettempdir()).free < needed:
                inspection = {
                    "supported": False, "items": [], "entry_count": 0,
                    "truncated": False, "total_uncompressed": 0, "preview": None,
                    "preview_error": "磁盘余量保护：可用空间不足，暂不生成内容预览。",
                }
                return page(request, "admin_resource_contents.html", user=admin, r=resource, inspection=inspection)
            fd, restored_path = tempfile.mkstemp(prefix="admin-restored-", suffix=Path(resource["original_filename"] or key).suffix.lower())
            os.close(fd)
            with open(temp_path, "rb") as compressed, open(restored_path, "wb") as restored:
                zstd.ZstdDecompressor().copy_stream(compressed, restored)
            if os.path.getsize(restored_path) != int(resource.get("size_bytes") or 0):
                raise HTTPException(status_code=422, detail="存储文件恢复后的大小与原文件记录不一致")
            inspect_path = restored_path
        ext = Path(resource["original_filename"] or key).suffix.lower()
        if ext in {".zip", ".apk"}:
            inspection = inspect_zip_archive(inspect_path, member)
        else:
            inspection = {
                "supported": False, "items": [], "entry_count": 0,
                "truncated": False, "total_uncompressed": 0, "preview": None,
                "preview_error": "目前仅支持 ZIP/APK 内部目录和小型文本预览；7Z/RAR 仅能进行基本安全扫描，暂不展开浏览。",
            }
        return page(request, "admin_resource_contents.html", user=admin, r=resource, inspection=inspection)
    finally:
        for temporary_path in (temp_path, restored_path):
            if temporary_path:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass


@app.post("/admin/users/{user_id}/role")
def change_user_role(request: Request, user_id: int, role: str = Form(...), csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    admin = require_admin(request)
    if role not in {"user", "admin"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    if user_id == admin["id"] and role != "admin":
        raise HTTPException(status_code=400, detail="You cannot remove your own administrator role")
    with db_connect() as conn:
        conn.execute("UPDATE users SET role=%s WHERE id=%s", (role, user_id))
        conn.commit()
    return RedirectResponse("/admin?notice=user_role_updated", status_code=303)


@app.post("/resources/{resource_id}/delete")
def delete_resource(request: Request, resource_id: int, csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    user = require_user(request)
    with db_connect() as conn:
        resource = conn.execute("SELECT * FROM resources WHERE id=%s FOR UPDATE", (resource_id,)).fetchone()
        if not resource:
            raise HTTPException(status_code=404, detail="Resource not found")
        if user["role"] != "admin" and int(resource["user_id"]) != int(user["id"]):
            raise HTTPException(status_code=403, detail="You may only delete your own resources")
        conn.execute("UPDATE resources SET status='deleting', review_note='Deletion in progress' WHERE id=%s", (resource_id,))
        conn.commit()
    try:
        for key in (resource.get("filename"), resource.get("cover_filename")):
            if key:
                s3_delete_strict(key)
    except Exception:
        logging.exception("Resource deletion incomplete; row retained for retry id=%s", resource_id)
        audit_security_event(user["id"], "resource_delete_failed", str(resource_id), "Object storage deletion failed; row retained")
        target = "/admin?notice=delete_failed" if user["role"] == "admin" else "/my-resources?notice=delete_failed"
        return RedirectResponse(target, status_code=303)
    with db_connect() as conn:
        conn.execute("DELETE FROM resources WHERE id=%s", (resource_id,))
        conn.commit()
    audit_security_event(user["id"], "resource_deleted", str(resource_id), "Resource and linked objects deleted")
    target = "/admin?notice=resource_deleted" if user["role"] == "admin" else "/my-resources?notice=resource_deleted"
    return RedirectResponse(target, status_code=303)


@app.post("/admin/ip-bans")
def create_ip_ban(request: Request, ip_address: str = Form(...), reason: str = Form(""), duration: str = Form("24h"), csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    admin = require_admin(request)
    try:
        normalized_ip = str(ipaddress.ip_address(ip_address.strip()))
    except ValueError:
        raise HTTPException(status_code=400, detail="Enter a valid IPv4 or IPv6 address")
    if normalized_ip == get_client_ip(request):
        raise HTTPException(status_code=400, detail="You cannot ban the IP currently used for this admin session")
    if duration not in {"10m", "1h", "24h", "permanent"}:
        raise HTTPException(status_code=400, detail="Invalid ban duration")
    expires_sql = {"10m": "NOW() + INTERVAL '10 minutes'", "1h": "NOW() + INTERVAL '1 hour'", "24h": "NOW() + INTERVAL '24 hours'", "permanent": "NULL"}[duration]
    with db_connect() as conn:
        conn.execute("UPDATE ip_bans SET revoked_at=NOW(),revoked_by=%s WHERE ip_address=%s AND revoked_at IS NULL", (admin["id"], normalized_ip))
        conn.execute(
            f"INSERT INTO ip_bans (ip_address,reason,created_by,expires_at) VALUES (%s,%s,%s,{expires_sql})",
            (normalized_ip, reason.strip()[:500], admin["id"]),
        )
        conn.commit()
    audit_security_event(admin["id"], "ip_banned", normalized_ip, f"duration={duration}; reason={reason.strip()[:300]}")
    return RedirectResponse("/admin?notice=ip_banned", status_code=303)


@app.post("/admin/ip-bans/{ban_id}/revoke")
def revoke_ip_ban(request: Request, ban_id: int, csrf_token: str = Form(...)):
    validate_csrf(request, csrf_token)
    admin = require_admin(request)
    with db_connect() as conn:
        row = conn.execute("SELECT ip_address FROM ip_bans WHERE id=%s AND revoked_at IS NULL", (ban_id,)).fetchone()
        if row:
            conn.execute("UPDATE ip_bans SET revoked_at=NOW(),revoked_by=%s WHERE id=%s", (admin["id"], ban_id))
            conn.commit()
    if row:
        audit_security_event(admin["id"], "ip_unbanned", row["ip_address"], "Manual unban")
    return RedirectResponse("/admin?notice=ip_unbanned", status_code=303)


@app.get("/health")
def health():
    result = {"status": "ok", "database": "unknown", "storage": "configured" if all([S3_ENDPOINT, os.getenv("AWS_ACCESS_KEY_ID"), os.getenv("AWS_SECRET_ACCESS_KEY"), S3_BUCKET]) else "missing_config"}
    try:
        with db_connect() as conn:
            conn.execute("SELECT 1")
        result["database"] = "ok"
    except Exception:
        result["status"] = "degraded"
        result["database"] = "error"
    return JSONResponse(result, status_code=200 if result["status"] == "ok" else 503)


@app.get("/robots.txt")
def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /admin\nDisallow: /my-resources\n")
