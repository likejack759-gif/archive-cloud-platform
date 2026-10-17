import os, re, hmac, hashlib, secrets, sqlite3, uuid, mimetypes
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.templating import Jinja2Templates

DATA_DIR = Path(os.getenv("DATA_DIR", "data")).resolve()
FILES_DIR = DATA_DIR / "files"
COVERS_DIR = DATA_DIR / "covers"
DB_PATH = DATA_DIR / "app.db"
for p in (FILES_DIR, COVERS_DIR):
    p.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv("SECRET_KEY", "")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
MAX_UPLOAD_MB = max(1, int(os.getenv("MAX_UPLOAD_MB", "2048")))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
SESSION_HTTPS_ONLY = os.getenv("SESSION_HTTPS_ONLY", "false").lower() == "true"
ALLOWED_ARCHIVES = {".zip", ".7z", ".rar"}
ALLOWED_APK = {".apk"}
ALLOWED_IMAGES = {".jpg", ".jpeg", ".png", ".webp", ".gif"}

app = FastAPI(title="Cloud Resource Platform")
app.add_middleware(
    SessionMiddleware, secret_key=SECRET_KEY or "UNSAFE-DEV-KEY-CHANGE-ME",
    session_cookie="resource_session", same_site="lax", https_only=SESSION_HTTPS_ONLY,
    max_age=60 * 60 * 24 * 7
)
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def connect():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return salt.hex() + "$" + digest.hex()

def verify_password(password: str, encoded: str) -> bool:
    try:
        salt_hex, digest_hex = encoded.split("$", 1)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=bytes.fromhex(salt_hex), n=2**14, r=8, p=1)
        return hmac.compare_digest(actual.hex(), digest_hex)
    except Exception:
        return False

def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code_hash TEXT UNIQUE NOT NULL,
            label TEXT NOT NULL DEFAULT '',
            max_uses INTEGER NOT NULL DEFAULT 1,
            uses INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            active INTEGER NOT NULL DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL,
            cover_filename TEXT,
            size_bytes INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewer_id INTEGER REFERENCES users(id),
            review_note TEXT NOT NULL DEFAULT '',
            downloads INTEGER NOT NULL DEFAULT 0
        );
        """)
        row = c.execute("SELECT id FROM users WHERE username=?", (ADMIN_USERNAME,)).fetchone()
        if not row:
            if not ADMIN_PASSWORD or ADMIN_PASSWORD.startswith("REPLACE_"):
                raise RuntimeError("Set a strong ADMIN_PASSWORD in .env before first startup.")
            c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                      (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD), "admin", now()))

@app.on_event("startup")
def startup():
    if not SECRET_KEY or SECRET_KEY.startswith("REPLACE_"):
        raise RuntimeError("Set a unique random SECRET_KEY in .env before startup.")
    init_db()

def current_user(request: Request):
    uid = request.session.get("uid")
    if not uid:
        return None
    with connect() as c:
        return c.execute("SELECT id,username,role FROM users WHERE id=?", (uid,)).fetchone()

def require_user(request: Request):
    u = current_user(request)
    if not u:
        raise HTTPException(401, "请先登录")
    return u

def require_admin(request: Request):
    u = require_user(request)
    if u["role"] != "admin":
        raise HTTPException(403, "需要管理员权限")
    return u

def page(request: Request, name: str, context=None, status_code=200):
    data = {"request": request, "user": current_user(request)}
    if context:
        data.update(context)
    return templates.TemplateResponse(name, data, status_code=status_code)

def safe_name(value: str, maxlen=80):
    value = re.sub(r"[\x00-\x1f<>:\"/\\|?*]", "_", value or "").strip(" .")
    return value[:maxlen] or "未命名资源"

async def save_upload(upload: UploadFile, target: Path, max_bytes: int):
    total = 0
    try:
        with target.open("wb") as out:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise HTTPException(413, f"文件超过限制（{MAX_UPLOAD_MB} MB）")
                out.write(chunk)
        if total == 0:
            raise HTTPException(400, "不能上传空文件")
        return total
    except Exception:
        target.unlink(missing_ok=True)
        raise
    finally:
        await upload.close()

@app.get("/", response_class=HTMLResponse)
def home(request: Request, q: str = ""):
    u = current_user(request)
    items = []
    if u:
        with connect() as c:
            items = c.execute("""
                SELECT r.*, users.username AS owner_name
                FROM resources r JOIN users ON users.id=r.owner_id
                WHERE r.status='approved' AND (r.name LIKE ? OR r.description LIKE ?)
                ORDER BY r.reviewed_at DESC, r.id DESC LIMIT 300
            """, (f"%{q[:100]}%", f"%{q[:100]}%")).fetchall()
    return page(request, "index.html", {"items": items, "q": q, "max_upload_mb": MAX_UPLOAD_MB})

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    if current_user(request):
        return RedirectResponse("/", 303)
    return page(request, "register.html", {"error": None})

@app.post("/register", response_class=HTMLResponse)
def register(request: Request, username: str = Form(...), password: str = Form(...), invite: str = Form(...)):
    username = username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
        return page(request, "register.html", {"error": "用户名需为 3–32 位字母、数字、点、下划线或连字符。"}, 400)
    if len(password) < 10 or len(password) > 128:
        return page(request, "register.html", {"error": "密码长度必须为 10–128 个字符。"}, 400)
    code_hash = hashlib.sha256(invite.strip().encode()).hexdigest()
    with connect() as c:
        inv = c.execute("SELECT * FROM invites WHERE code_hash=? AND active=1", (code_hash,)).fetchone()
        if not inv or inv["uses"] >= inv["max_uses"]:
            return page(request, "register.html", {"error": "邀请码无效、已停用或已用完。"}, 400)
        try:
            c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                      (username, hash_password(password), "user", now()))
        except sqlite3.IntegrityError:
            return page(request, "register.html", {"error": "用户名已存在。"}, 400)
        c.execute("UPDATE invites SET uses=uses+1 WHERE id=?", (inv["id"],))
    return RedirectResponse("/login?registered=1", 303)

@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request, registered: int = 0):
    if current_user(request):
        return RedirectResponse("/", 303)
    return page(request, "login.html", {"error": None, "registered": bool(registered)})

@app.post("/login", response_class=HTMLResponse)
def login(request: Request, username: str = Form(...), password: str = Form(...)):
    with connect() as c:
        u = c.execute("SELECT * FROM users WHERE username=?", (username.strip(),)).fetchone()
    if not u or not verify_password(password, u["password_hash"]):
        return page(request, "login.html", {"error": "用户名或密码错误。", "registered": False}, 401)
    request.session.clear()
    request.session["uid"] = u["id"]
    request.session["username"] = u["username"]
    request.session["role"] = u["role"]
    return RedirectResponse("/", 303)

@app.post("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", 303)

@app.get("/submit", response_class=HTMLResponse)
def submit_page(request: Request):
    require_user(request)
    return page(request, "submit.html", {"error": None, "max_upload_mb": MAX_UPLOAD_MB})

@app.post("/submit", response_class=HTMLResponse)
async def submit_resource(request: Request, name: str = Form(...), description: str = Form(""),
                          archive: UploadFile = File(...), cover: UploadFile = File(...)):
    u = require_user(request)
    clean_name = safe_name(name, 100)
    ext = Path(archive.filename or "").suffix.lower()
    cover_ext = Path(cover.filename or "").suffix.lower()
    if ext not in ALLOWED_ARCHIVES:
        return page(request, "submit.html", {"error": "仅支持 ZIP、7Z、RAR 文件。", "max_upload_mb": MAX_UPLOAD_MB}, 400)
    if cover_ext not in ALLOWED_IMAGES:
        return page(request, "submit.html", {"error": "封面仅支持 JPG、PNG、WEBP、GIF。", "max_upload_mb": MAX_UPLOAD_MB}, 400)
    stored = f"{uuid.uuid4().hex}{ext}"
    cover_stored = f"{uuid.uuid4().hex}{cover_ext}"
    archive_path = FILES_DIR / stored
    cover_path = COVERS_DIR / cover_stored
    try:
        size = await save_upload(archive, archive_path, MAX_UPLOAD_BYTES)
        cover_size = await save_upload(cover, cover_path, 8 * 1024 * 1024)
        # Basic file-signature checks reduce accidental mismatches; this is not malware scanning.
        with archive_path.open("rb") as f:
            sig = f.read(8)
        valid = (ext == ".zip" and sig.startswith(b"PK")) or (ext == ".7z" and sig.startswith(b"7z\xbc\xaf\x27\x1c")) or (ext == ".rar" and sig.startswith(b"Rar!\x1a\x07"))
        if not valid:
            raise HTTPException(400, "压缩包扩展名与文件内容不匹配，或格式不受支持。")
        with cover_path.open("rb") as f:
            image_sig = f.read(12)
        image_valid = image_sig.startswith(b"\xff\xd8\xff") or image_sig.startswith(b"\x89PNG\r\n\x1a\n") or image_sig.startswith(b"RIFF") or image_sig.startswith(b"GIF87a") or image_sig.startswith(b"GIF89a")
        if not image_valid:
            raise HTTPException(400, "封面图片内容无效。")
        with connect() as c:
            c.execute("""INSERT INTO resources(owner_id,name,description,original_filename,stored_filename,cover_filename,size_bytes,status,created_at)
                         VALUES(?,?,?,?,?,?,?,?,?)""",
                      (u["id"], clean_name, description[:2000], safe_name(archive.filename, 180), stored, cover_stored, size, "pending", now()))
    except Exception:
        archive_path.unlink(missing_ok=True)
        cover_path.unlink(missing_ok=True)
        raise
    return RedirectResponse("/my-resources?submitted=1", 303)

@app.get("/my-resources", response_class=HTMLResponse)
def my_resources(request: Request, submitted: int = 0):
    u = require_user(request)
    with connect() as c:
        items = c.execute("SELECT * FROM resources WHERE owner_id=? ORDER BY id DESC", (u["id"],)).fetchall()
    return page(request, "my_resources.html", {"items": items, "submitted": bool(submitted)})

@app.get("/covers/{filename}")
def cover(filename: str):
    if not re.fullmatch(r"[a-f0-9]{32}\.(jpg|jpeg|png|webp|gif)", filename):
        raise HTTPException(404)
    path = COVERS_DIR / filename
    if not path.is_file():
        raise HTTPException(404)
    media = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
    return FileResponse(path, media_type=media, headers={"Cache-Control": "public, max-age=3600"})

@app.get("/download/{resource_id}")
def download(request: Request, resource_id: int):
    require_user(request)
    with connect() as c:
        r = c.execute("SELECT * FROM resources WHERE id=? AND status='approved'", (resource_id,)).fetchone()
        if not r:
            raise HTTPException(404, "资源不存在或尚未审核通过")
        path = FILES_DIR / r["stored_filename"]
        if not path.is_file():
            raise HTTPException(404, "文件暂时不可用")
        c.execute("UPDATE resources SET downloads=downloads+1 WHERE id=?", (resource_id,))
    return FileResponse(path, filename=r["original_filename"], media_type="application/octet-stream")

@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request):
    require_admin(request)
    with connect() as c:
        pending = c.execute("""SELECT r.*,u.username AS owner_name FROM resources r JOIN users u ON u.id=r.owner_id
                               WHERE r.status='pending' ORDER BY r.id ASC""").fetchall()
        invites = c.execute("SELECT * FROM invites ORDER BY id DESC LIMIT 50").fetchall()
        users = c.execute("SELECT id,username,role,created_at FROM users ORDER BY id DESC LIMIT 100").fetchall()
        stats = {
            "users": c.execute("SELECT COUNT(*) FROM users").fetchone()[0],
            "resources": c.execute("SELECT COUNT(*) FROM resources").fetchone()[0],
            "pending": c.execute("SELECT COUNT(*) FROM resources WHERE status='pending'").fetchone()[0],
            "approved": c.execute("SELECT COUNT(*) FROM resources WHERE status='approved'").fetchone()[0],
        }
    return page(request, "admin.html", {"pending": pending, "invites": invites, "users": users, "stats": stats, "notice": request.query_params.get("notice")})

@app.post("/admin/invites")
def create_invite(request: Request, label: str = Form(""), max_uses: int = Form(1)):
    require_admin(request)
    max_uses = min(1000, max(1, max_uses))
    code = secrets.token_urlsafe(9)
    digest = hashlib.sha256(code.encode()).hexdigest()
    with connect() as c:
        c.execute("INSERT INTO invites(code_hash,label,max_uses,uses,created_at,active) VALUES(?,?,?,?,?,1)",
                  (digest, safe_name(label, 100) if label.strip() else "", max_uses, 0, now()))
    # One-time display of plaintext invite code; only hash is stored.
    request.session["new_invite"] = code
    return RedirectResponse("/admin?notice=invite_created", 303)

@app.post("/admin/invites/{invite_id}/toggle")
def toggle_invite(request: Request, invite_id: int):
    require_admin(request)
    with connect() as c:
        row = c.execute("SELECT active FROM invites WHERE id=?", (invite_id,)).fetchone()
        if row:
            c.execute("UPDATE invites SET active=? WHERE id=?", (0 if row["active"] else 1, invite_id))
    return RedirectResponse("/admin", 303)

@app.post("/admin/resources/{resource_id}/review")
def review_resource(request: Request, resource_id: int, action: str = Form(...), review_note: str = Form("")):
    admin = require_admin(request)
    if action not in {"approve", "reject"}:
        raise HTTPException(400, "无效操作")
    status = "approved" if action == "approve" else "rejected"
    with connect() as c:
        r = c.execute("SELECT id FROM resources WHERE id=?", (resource_id,)).fetchone()
        if not r:
            raise HTTPException(404)
        c.execute("UPDATE resources SET status=?,reviewed_at=?,reviewer_id=?,review_note=? WHERE id=?",
                  (status, now(), admin["id"], review_note[:500], resource_id))
    return RedirectResponse("/admin", 303)

@app.post("/admin/users/{user_id}/role")
def change_role(request: Request, user_id: int, role: str = Form(...)):
    admin = require_admin(request)
    if role not in {"user", "admin"}:
        raise HTTPException(400)
    if user_id == admin["id"] and role != "admin":
        raise HTTPException(400, "不能降级当前管理员")
    with connect() as c:
        c.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    return RedirectResponse("/admin", 303)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/robots.txt")
def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /\n")
