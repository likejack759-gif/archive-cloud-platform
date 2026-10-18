import os
import re
import secrets
import hashlib
import tempfile
import zipfile
import logging
from pathlib import Path
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

BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
DATABASE_URL = os.getenv("DATABASE_URL", "").strip()
SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "").strip()
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "500"))
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "true").lower() in {"1", "true", "yes", "on"}
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
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS reviewed_by BIGINT REFERENCES users(id) ON DELETE SET NULL")
        conn.execute("ALTER TABLE resources ADD COLUMN IF NOT EXISTS review_note TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE invites ADD COLUMN IF NOT EXISTS label TEXT NOT NULL DEFAULT ''")
        conn.execute("ALTER TABLE invites ADD COLUMN IF NOT EXISTS max_uses INTEGER NOT NULL DEFAULT 1")
        conn.execute("ALTER TABLE invites ADD COLUMN IF NOT EXISTS uses INTEGER NOT NULL DEFAULT 0")
        conn.execute("UPDATE invites SET uses=1 WHERE used_by IS NOT NULL AND uses=0")
        
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


def page(request: Request, template: str, **context):
    if not context.get("user"):
        context["user"] = current_user(request)
    return templates.TemplateResponse(request=request, name=template, context=context)


def safe_name(name: str) -> str:
    name = Path(name or "upload.bin").name
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (name or "upload.bin")[:180]


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


async def save_upload_to_temp(upload: UploadFile, max_bytes: int) -> tuple[str, int]:
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
                    raise HTTPException(status_code=413, detail=f"File exceeds {MAX_UPLOAD_MB} MB limit")
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


def s3_delete(key: str):
    try:
        s3_client().delete_object(Bucket=S3_BUCKET, Key=key)
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
def index(request: Request, q: str = "", resource_type: str = ""):
    user = current_user(request)
    where = ["r.status='approved'"]
    params = []
    if q.strip():
        where.append("(r.name ILIKE %s OR r.description ILIKE %s)")
        params.extend([f"%{q.strip()}%", f"%{q.strip()}%"])
    if resource_type.strip():
        where.append("r.resource_type=%s")
        params.append(resource_type.strip())
    with db_connect() as conn:
        resources = conn.execute(
            "SELECT r.*, u.username AS owner_name FROM resources r JOIN users u ON u.id=r.user_id WHERE " + " AND ".join(where) + " ORDER BY r.created_at DESC LIMIT 100",
            tuple(params),
        ).fetchall()
    return page(request, "index.html", user=user, items=resources, resources=resources, q=q, resource_type=resource_type)


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
def register(request: Request, username: str = Form(...), password: str = Form(...), invite: str = Form(...)):
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
    request.session["user_id"] = user["id"]
    return RedirectResponse("/", status_code=303)


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return page(request, "login.html", error=None)


@app.post("/login")
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with db_connect() as conn:
        user = conn.execute("SELECT id, password_hash FROM users WHERE username=%s", (username.strip(),)).fetchone()
    if not user or not verify_password(password, user["password_hash"]):
        return page(request, "login.html", error="用户名或密码不正确。")
    request.session.clear()
    request.session["user_id"] = user["id"]
    return RedirectResponse("/", status_code=303)


@app.post("/logout")
def logout(request: Request):
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
):
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
    max_bytes = MAX_UPLOAD_MB * 1024 * 1024
    try:
        archive_path, archive_size = await save_upload_to_temp(archive, max_bytes)
        if not archive_is_valid(archive_path, archive_filename):
            return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="文件内容与扩展名不匹配，或文件格式无效。")
        archive_key = f"files/{secrets.token_hex(16)}_{archive_filename}"
        content_type = "application/vnd.android.package-archive" if archive_filename.lower().endswith(".apk") else "application/octet-stream"
        s3_put(archive_path, archive_key, content_type)
        if cover and cover.filename:
            cover_filename = safe_name(cover.filename)
            ext = Path(cover_filename).suffix.lower()
            if ext not in {".jpg", ".jpeg", ".png", ".webp", ".gif"}:
                s3_delete(archive_key)
                return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="封面只允许 JPG、PNG、WEBP 或 GIF 图片。")
            cover_path, _ = await save_upload_to_temp(cover, 8 * 1024 * 1024)
            with open(cover_path, "rb") as f:
                signature = f.read(12)
            valid = (ext in {".jpg", ".jpeg"} and signature.startswith(b"\xff\xd8\xff")) or (ext == ".png" and signature.startswith(b"\x89PNG\r\n\x1a\n")) or (ext == ".gif" and signature.startswith((b"GIF87a", b"GIF89a"))) or (ext == ".webp" and signature.startswith(b"RIFF") and signature[8:12] == b"WEBP")
            if not valid:
                s3_delete(archive_key)
                return page(request, "submit.html", user=user, max_upload_mb=MAX_UPLOAD_MB, error="封面文件内容不是有效的支持格式图片。")
            cover_key = f"covers/{secrets.token_hex(16)}{ext}"
            mime = {".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png", ".webp":"image/webp", ".gif":"image/gif"}[ext]
            s3_put(cover_path, cover_key, mime)
        with db_connect() as conn:
            conn.execute(
                "INSERT INTO resources (user_id,resource_type,name,description,filename,original_filename,cover_filename,status,size_bytes) VALUES (%s,%s,%s,%s,%s,%s,%s,'pending',%s)",
                (user["id"], resource_type[:40], name, description.strip()[:2000], archive_key, archive_filename, cover_key, archive_size),
            )
            conn.commit()
        return RedirectResponse("/my-resources?notice=submitted", status_code=303)
    except HTTPException as exc:
        raise exc
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
        for p in (archive_path, cover_path):
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
    }
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
    stats = dict(stats_row)
    return page(request, "admin.html", user=user, stats=stats, pending=pending, invites=invites, users=users, notice=notice)


@app.post("/admin/invites")
def create_invite(request: Request, label: str = Form(""), max_uses: int = Form(1)):
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
def toggle_invite(request: Request, invite_id: int):
    require_admin(request)
    with db_connect() as conn:
        conn.execute("UPDATE invites SET is_active=NOT is_active WHERE id=%s AND uses < max_uses", (invite_id,))
        conn.commit()
    return RedirectResponse("/admin?notice=invite_updated", status_code=303)


@app.post("/admin/resources/{resource_id}/review")
def review_resource(request: Request, resource_id: int, action: str = Form(...), review_note: str = Form("")):
    admin = require_admin(request)
    if action not in {"approve", "reject"}:
        raise HTTPException(status_code=400, detail="Invalid review action")
    status = "approved" if action == "approve" else "rejected"
    with db_connect() as conn:
        conn.execute("UPDATE resources SET status=%s,review_note=%s,reviewed_at=NOW(),reviewed_by=%s WHERE id=%s AND status='pending'", (status, review_note.strip()[:500], admin["id"], resource_id))
        conn.commit()
    return RedirectResponse("/admin?notice=resource_reviewed", status_code=303)


@app.post("/admin/users/{user_id}/role")
def change_user_role(request: Request, user_id: int, role: str = Form(...)):
    admin = require_admin(request)
    if role not in {"user", "admin"}:
        raise HTTPException(status_code=400, detail="Invalid role")
    if user_id == admin["id"] and role != "admin":
        raise HTTPException(status_code=400, detail="You cannot remove your own administrator role")
    with db_connect() as conn:
        conn.execute("UPDATE users SET role=%s WHERE id=%s", (role, user_id))
        conn.commit()
    return RedirectResponse("/admin?notice=user_role_updated", status_code=303)


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
