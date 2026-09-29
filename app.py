
""""
QR Mesaj Uygulaması — v2 Güvenli Sürüm
Yenilikler:
  - Profil resmi değiştirme (sahip)
  - PIN brute-force koruması (günde 3 hak, başarılı girişte sıfırlanır)
  - Kullanıcı adı (display_name) — 30 günde bir değiştirme hakkı
  - Geliştirilmiş güvenlik (rate limit, input validation, vb.)
"""

import base64
from flask import redirect, url_for, Response, session
from flask import Flask, render_template, request, jsonify, abort, g
import sqlite3
import uuid
import os
import re
import html
import hashlib
import secrets
import json as _json
from datetime import datetime, date, timedelta
from functools import wraps
from collections import defaultdict
import threading
import time

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH  = os.path.join(BASE_DIR, "qr_data.db")

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "templates"))

# SECRET_KEY: her başlatmada sabit kalması için dosyaya yaz
_SECRET_KEY_FILE = os.path.join(BASE_DIR, ".flask_secret")
def _load_or_create_secret_key():
    env_key = os.environ.get("SECRET_KEY", "").strip()
    if env_key:
        return env_key.encode()
    if os.path.exists(_SECRET_KEY_FILE):
        with open(_SECRET_KEY_FILE, "rb") as f:
            k = f.read().strip()
            if k:
                return k
    k = secrets.token_bytes(32)
    with open(_SECRET_KEY_FILE, "wb") as f:
        f.write(k)
    os.chmod(_SECRET_KEY_FILE, 0o600)
    return k

app.secret_key = _load_or_create_secret_key()

app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024   # 4MB → 2MB (resim için yeterli)
app.config["JSON_ENSURE_ASCII"]  = False
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=365)   # çıkış yapana kadar (1 yıl)
app.config["SESSION_COOKIE_HTTPONLY"]  = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"]   = os.environ.get("HTTPS", "0") == "1"

# ──────────────────────────────────────
#  BASİT IN-MEMORY RATE LIMITER
#  (flask-limiter gerektirmez)
# ──────────────────────────────────────
_rl_lock   = threading.Lock()
_rl_store  = defaultdict(list)   # key → [timestamp, ...]

def _rl_check(key: str, limit: int, window_sec: int) -> bool:
    """True = istek geçer, False = engelle."""
    now = time.time()
    cutoff = now - window_sec
    with _rl_lock:
        _rl_store[key] = [t for t in _rl_store[key] if t > cutoff]
        if len(_rl_store[key]) >= limit:
            return False
        _rl_store[key].append(now)
        return True

def rate_limit(key_prefix: str, limit: int, window_sec: int):
    """Decorator: IP başına rate-limit uygular."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
            key = f"{key_prefix}:{ip}"
            if not _rl_check(key, limit, window_sec):
                return jsonify({"error": "Çok fazla istek. Lütfen bekleyin."}), 429
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ──────────────────────────────────────
#  GÜVENLİK BAŞLIKLARI
# ──────────────────────────────────────
@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"]  = "nosniff"
    resp.headers["X-Frame-Options"]         = "DENY"
    resp.headers["X-XSS-Protection"]        = "1; mode=block"
    resp.headers["Referrer-Policy"]         = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"]      = "geolocation=(), microphone=(), camera=(), payment=()"
    # HSTS: HTTPS ortamında aktif et
    if os.environ.get("HTTPS") == "1":
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "font-src https://fonts.gstatic.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    # Önbelleği hassas API yanıtları için kapat
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        resp.headers["Pragma"]        = "no-cache"
    return resp

# ──────────────────────────────────────
#  VERİTABANI
# ──────────────────────────────────────
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
            CREATE TABLE IF NOT EXISTS entries (
                id                  TEXT PRIMARY KEY,
                text                TEXT NOT NULL,
                created_at          TEXT NOT NULL,
                owner_token         TEXT NOT NULL,
                owner_pin           TEXT NOT NULL,
                view_count          INTEGER DEFAULT 0,
                profile_image       TEXT DEFAULT '',
                socials             TEXT DEFAULT '{}',
                comments_enabled    INTEGER DEFAULT 1,
                display_name        TEXT DEFAULT '',
                display_name_changed_at TEXT DEFAULT NULL
            );

            CREATE TABLE IF NOT EXISTS views (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                entry_id   TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                viewed_at  TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS replies (
                id             TEXT PRIMARY KEY,
                entry_id       TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                text           TEXT NOT NULL,
                created_at     TEXT NOT NULL,
                ip_hash        TEXT NOT NULL,
                owner_reply    TEXT DEFAULT NULL,
                owner_reply_at TEXT DEFAULT NULL
            );

            CREATE TABLE IF NOT EXISTS reply_limits (
                ip_hash    TEXT NOT NULL,
                entry_id   TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                reply_date TEXT NOT NULL,
                PRIMARY KEY (ip_hash, entry_id, reply_date)
            );

            -- PIN brute-force takibi
            -- fail_count: o gün toplam yanlış deneme
            -- reset edilir: başarılı girişte veya yeni gün başında
            CREATE TABLE IF NOT EXISTS pin_attempts (
                ip_hash    TEXT NOT NULL,
                attempt_date TEXT NOT NULL,
                fail_count INTEGER DEFAULT 0,
                PRIMARY KEY (ip_hash, attempt_date)
            );

            CREATE INDEX IF NOT EXISTS idx_views_entry   ON views(entry_id);
            CREATE INDEX IF NOT EXISTS idx_replies_entry ON replies(entry_id);
            CREATE INDEX IF NOT EXISTS idx_limits        ON reply_limits(ip_hash, entry_id, reply_date);
            CREATE INDEX IF NOT EXISTS idx_pin_attempts  ON pin_attempts(ip_hash, attempt_date);
            CREATE INDEX IF NOT EXISTS idx_entries_pin   ON entries(owner_pin);

            -- Bildirim tablosu
            CREATE TABLE IF NOT EXISTS notifications (
                id          TEXT PRIMARY KEY,
                entry_id    TEXT NOT NULL REFERENCES entries(id) ON DELETE CASCADE,
                reply_id    TEXT NOT NULL REFERENCES replies(id) ON DELETE CASCADE,
                is_read     INTEGER DEFAULT 0,
                created_at  TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_notifs_entry ON notifications(entry_id, is_read);

            -- OTP doğrulama tablosu
            CREATE TABLE IF NOT EXISTS otp_codes (
                id          TEXT PRIMARY KEY,
                phone       TEXT NOT NULL,
                code        TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                expires_at  TEXT NOT NULL,
                verified    INTEGER DEFAULT 0,
                attempts    INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_otp_phone ON otp_codes(phone);

            -- Ödeme erişim kodları (tek kullanımlık)
            CREATE TABLE IF NOT EXISTS access_codes (
                code        TEXT PRIMARY KEY,
                created_at  TEXT NOT NULL,
                used        INTEGER DEFAULT 0,
                used_at     TEXT,
                used_by_ip  TEXT,
                note        TEXT
            );

            -- Günlük QR oluşturma limiti (IP başına günde 1)
            CREATE TABLE IF NOT EXISTS create_limits (
                ip_hash     TEXT NOT NULL,
                create_date TEXT NOT NULL,
                PRIMARY KEY (ip_hash, create_date)
            );
            CREATE INDEX IF NOT EXISTS idx_create_limits ON create_limits(ip_hash, create_date);

            -- Direkt mesajlaşma
            -- sender_entry_id: gönderen QR'ın entry id'si (PIN ile doğrulandı)
            -- receiver_entry_id: alıcı QR'ın entry id'si
            -- thread_id: iki kişi arasındaki sabit konuşma id'si
            CREATE TABLE IF NOT EXISTS direct_messages (
                id                TEXT PRIMARY KEY,
                thread_id         TEXT NOT NULL,
                sender_pin        TEXT NOT NULL,
                sender_entry_id   TEXT NOT NULL,
                receiver_entry_id TEXT NOT NULL,
                text              TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                is_read           INTEGER DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_dm_thread   ON direct_messages(thread_id, created_at);
            CREATE INDEX IF NOT EXISTS idx_dm_receiver ON direct_messages(receiver_entry_id, is_read);
            CREATE INDEX IF NOT EXISTS idx_dm_sender   ON direct_messages(sender_entry_id);
        """)
        db.commit()

        # Migration: eski DB için sütun ekle
        migrations = [
            'ALTER TABLE entries ADD COLUMN comments_enabled INTEGER DEFAULT 1',
            'ALTER TABLE entries ADD COLUMN display_name TEXT DEFAULT ""',
            'ALTER TABLE entries ADD COLUMN display_name_changed_at TEXT DEFAULT NULL',
            'ALTER TABLE entries ADD COLUMN last_owner_visit TEXT DEFAULT NULL',
            'ALTER TABLE entries ADD COLUMN background_image TEXT DEFAULT ""',
            'ALTER TABLE entries ADD COLUMN discoverable INTEGER DEFAULT 0',
            'ALTER TABLE entries ADD COLUMN is_activated INTEGER DEFAULT 0',
            'ALTER TABLE entries ADD COLUMN activated_at TEXT DEFAULT NULL',
            # direct_messages tablosu CREATE TABLE IF NOT EXISTS ile oluşturuluyor
            '''CREATE TABLE IF NOT EXISTS direct_messages (
                id                TEXT PRIMARY KEY,
                thread_id         TEXT NOT NULL,
                sender_pin        TEXT NOT NULL,
                sender_entry_id   TEXT NOT NULL,
                receiver_entry_id TEXT NOT NULL,
                text              TEXT NOT NULL,
                created_at        TEXT NOT NULL,
                is_read           INTEGER DEFAULT 0
            )''',
            'CREATE INDEX IF NOT EXISTS idx_dm_thread   ON direct_messages(thread_id, created_at)',
            'CREATE INDEX IF NOT EXISTS idx_dm_receiver ON direct_messages(receiver_entry_id, is_read)',
            'CREATE INDEX IF NOT EXISTS idx_dm_sender   ON direct_messages(sender_entry_id)',
        ]
        for sql in migrations:
            try:
                db.execute(sql)
                db.commit()
            except Exception:
                pass

# ──────────────────────────────────────
#  YARDIMCI FONKSİYONLAR
# ──────────────────────────────────────
ALLOWED_SOCIALS  = ["instagram", "twitter", "tiktok", "whatsapp"]
SOCIAL_PATTERN   = re.compile(r'^[\w.@+ -]{1,100}$')
PHONE_IQ_PATTERN = re.compile(r'^07\d{9}$')   # 07 ile başlayan 11 haneli Irak formatı
DISPLAY_NAME_MAX = 8

PIN_DAILY_LIMIT  = 3   # günde max yanlış deneme
FREE_TRIAL_HOURS = 1/60   # ödeme öncesi ücretsiz kullanım süresi (1 dakika — test modu)

ADMIN_PIN   = os.environ.get("ADMIN_PIN", "").strip()   # ortam değişkeninden al
if not ADMIN_PIN:
    raise RuntimeError("ADMIN_PIN ortam değişkeni ayarlanmamış! Örnek: export ADMIN_PIN=GÜÇLÜPIN")

# ADMIN_TOKEN: yeniden başlatmalarda kaybolmamak için dosyaya sakla
_TOKEN_FILE = os.path.join(BASE_DIR, ".admin_token")

def _load_or_create_admin_token():
    if os.path.exists(_TOKEN_FILE):
        with open(_TOKEN_FILE, "r") as f:
            t = f.read().strip()
            if t:
                return t
    t = secrets.token_urlsafe(32)
    with open(_TOKEN_FILE, "w") as f:
        f.write(t)
    os.chmod(_TOKEN_FILE, 0o600)
    return t

ADMIN_TOKEN = _load_or_create_admin_token()

def get_ip():
    raw_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
    raw_ip = raw_ip.split(",")[0].strip()
    salt   = os.environ.get("IP_SALT", app.config.get("IP_SALT", ""))
    if not salt:
        # Uygulama başlatılırken .admin_token ile aynı konuma bir salt üret
        _salt_file = os.path.join(BASE_DIR, ".ip_salt")
        if os.path.exists(_salt_file):
            with open(_salt_file) as f:
                salt = f.read().strip()
        if not salt:
            salt = secrets.token_hex(32)
            with open(_salt_file, "w") as f:
                f.write(salt)
            os.chmod(_salt_file, 0o600)
        app.config["IP_SALT"] = salt
    return hashlib.sha256(f"{salt}{raw_ip}".encode()).hexdigest()[:32]

def sanitize_text(text, max_len=1000):
    if not isinstance(text, str):
        return None
    text = text.strip()
    text = html.escape(text, quote=True)
    if not text or len(text) > max_len:
        return None
    return text

def sanitize_display_name(name):
    """Kullanıcı adını temizle ve doğrula (max 8 karakter, her zaman BÜYÜK harf)."""
    if not isinstance(name, str):
        return ""
    name = name.strip().upper()
    # Sadece büyük harf, rakam, nokta, alt çizgi, tire
    name = re.sub(r'[^A-Z0-9_.-]', '', name)
    name = name.strip()
    if len(name) > DISPLAY_NAME_MAX:
        name = name[:DISPLAY_NAME_MAX]
    return name

def sanitize_social(value, platform):
    if not isinstance(value, str):
        return ""
    value = value.strip().lstrip("@")
    if not value:
        return ""
    if platform == "whatsapp":
        digits = re.sub(r'[\s()-]', '', value)
        if not PHONE_IQ_PATTERN.match(digits):
            return ""
        return digits
    if not SOCIAL_PATTERN.match(value):
        return ""
    return html.escape(value)

def validate_image(image_data):
    if not isinstance(image_data, str):
        return ""
    image_data = image_data.strip()
    if not image_data:
        return ""
    if image_data.startswith("data:image"):
        allowed_types = ["data:image/jpeg", "data:image/jpg", "data:image/png",
                         "data:image/gif", "data:image/webp"]
        if not any(image_data.startswith(t) for t in allowed_types):
            return ""
        b64_part = image_data.split(",", 1)[-1] if "," in image_data else ""
        if len(b64_part) > 4_000_000:
            return ""
        if not re.match(r'^[A-Za-z0-9+/=]+$', b64_part[:100]):
            return ""
        return image_data
    if image_data.startswith(("https://", "http://")):
        if len(image_data) > 2000:
            return ""
        if not re.match(r'^https?://[^\s<>"]+$', image_data):
            return ""
        return image_data
    return ""

def require_json(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not request.is_json:
            return jsonify({"error": "Content-Type application/json olmalı"}), 415
        return f(*args, **kwargs)
    return decorated

def check_entry_id(entry_id):
    if not entry_id or not re.match(r'^[a-f0-9]{8}$', entry_id):
        abort(404)

# ──────────────────────────────────────
#  PIN BRUTE-FORCE KORUMASI
# ──────────────────────────────────────
def get_pin_fail_count(db, ip_hash):
    """Bugünkü yanlış PIN deneme sayısını döndür."""
    today = date.today().isoformat()
    row = db.execute(
        "SELECT fail_count FROM pin_attempts WHERE ip_hash=? AND attempt_date=?",
        (ip_hash, today)
    ).fetchone()
    return row["fail_count"] if row else 0

def record_pin_fail(db, ip_hash):
    """Yanlış PIN denemesini kaydet, sayacı artır."""
    today = date.today().isoformat()
    db.execute("""
        INSERT INTO pin_attempts (ip_hash, attempt_date, fail_count)
        VALUES (?, ?, 1)
        ON CONFLICT(ip_hash, attempt_date)
        DO UPDATE SET fail_count = fail_count + 1
    """, (ip_hash, today))
    db.commit()

def reset_pin_fails(db, ip_hash):
    """Başarılı girişten sonra günlük sayacı sıfırla."""
    today = date.today().isoformat()
    db.execute(
        "UPDATE pin_attempts SET fail_count=0 WHERE ip_hash=? AND attempt_date=?",
        (ip_hash, today)
    )
    db.commit()

def check_owner_auth(db, entry, data, ip_hash=None):
    """
    Sahip kimliğini doğrula.
    - Token ile giriş: brute-force limiti yok (token zaten gizli ve uzun)
    - PIN ile giriş: brute-force limiti UYGULANIR (günde 3 hak)
    Dönüş: (is_valid: bool, error_msg: str | None, remaining: int)
    """
    token = data.get("token", "").strip()
    pin   = data.get("pin", "").strip().upper()

    # Token doğrulama (brute-force limiti yok)
    if token and secrets.compare_digest(token, entry["owner_token"]):
        return True, None, PIN_DAILY_LIMIT

    # PIN doğrulama (brute-force limiti VAR)
    if pin:
        if ip_hash is None:
            ip_hash = hashlib.sha256(
                (request.headers.get("X-Forwarded-For", "") or request.remote_addr or "").encode()
            ).hexdigest()[:32]

        fail_count = get_pin_fail_count(db, ip_hash)
        if fail_count >= PIN_DAILY_LIMIT:
            return False, "BLOCKED", 0

        if secrets.compare_digest(pin, entry["owner_pin"]):
            reset_pin_fails(db, ip_hash)
            return True, None, PIN_DAILY_LIMIT
        else:
            record_pin_fail(db, ip_hash)
            remaining = PIN_DAILY_LIMIT - fail_count - 1
            if remaining <= 0:
                return False, "BLOCKED", 0
            return False, "WRONG_PIN", remaining

    return False, "UNAUTHORIZED", PIN_DAILY_LIMIT

# ──────────────────────────────────────
#  ROTALAR
# ──────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

# ── QR Oluştur ──
@app.route("/api/create", methods=["POST"])
@require_json
@rate_limit("create", limit=10, window_sec=60)   # Dakikada max 10 istek (genel koruma)
def create():
    try:
        data = request.get_json(silent=True) or {}

        # ── Günde 1 QR oluşturma limiti (IP başına) ──
        ip_hash   = get_ip()
        today_str = date.today().isoformat()
        db_check  = get_db()
        existing_today = db_check.execute(
            "SELECT 1 FROM create_limits WHERE ip_hash=? AND create_date=?",
            (ip_hash, today_str)
        ).fetchone()
        if existing_today:
            return jsonify({
                "error": "DAILY_LIMIT",
                "message": "Bugün zaten bir QR oluşturdunuz! Yarın tekrar deneyebilirsiniz."
            }), 429

        text = sanitize_text(data.get("text", ""), max_len=1000)
        if not text:
            return jsonify({"error": "Metin boş veya çok uzun (max 1000)"}), 400

        # display_name: zorunlu
        raw_name = data.get("display_name", "") or ""
        display_name = re.sub(r"[^A-Z0-9_.-]", "", str(raw_name).strip().upper())[:DISPLAY_NAME_MAX]
        if not display_name:
            return jsonify({"error": "Kullanıcı adı zorunludur!"}), 400

        img_b64   = validate_image(data.get("profile_image", ""))
        img_url   = validate_image(data.get("profile_image_url", ""))
        final_image = img_b64 or img_url

        socials_raw = data.get("socials", {})
        if not isinstance(socials_raw, dict):
            socials_raw = {}
        socials = {}
        for p in ALLOWED_SOCIALS:
            v = sanitize_social(socials_raw.get(p, ""), p)
            if v:
                socials[p] = v

        # WhatsApp zorunlu
        if not socials.get("whatsapp"):
            return jsonify({"error": "WhatsApp numarası zorunludur (07 ile başlayan 11 hane)!"}), 400

        socials_json = _json.dumps(socials, ensure_ascii=False)

        db = get_db()

        # Kullanıcı adı benzersizlik kontrolü
        if display_name:
            existing = db.execute(
                "SELECT 1 FROM entries WHERE LOWER(display_name)=LOWER(?)", (display_name,)
            ).fetchone()
            if existing:
                return jsonify({"error": "USERNAME_TAKEN", "message": "Bu kullanıcı adı zaten kullanımda!"}), 409

        PIN_CHARS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        owner_pin = None
        for _ in range(30):
            candidate = "".join(secrets.choice(PIN_CHARS) for __ in range(8))
            row = db.execute("SELECT 1 FROM entries WHERE owner_pin=?", (candidate,)).fetchone()
            if not row:
                owner_pin = candidate
                break
        if not owner_pin:
            owner_pin = "".join(secrets.choice(PIN_CHARS) for __ in range(8))

        entry_id    = secrets.token_hex(4)
        owner_token = secrets.token_urlsafe(32)

        db.execute(
            """INSERT INTO entries
               (id, text, created_at, owner_token, owner_pin,
                view_count, profile_image, socials, display_name, display_name_changed_at)
               VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, NULL)""",
            (entry_id, text, datetime.now().isoformat(), owner_token, owner_pin,
             final_image, socials_json, display_name)
        )
        # Günlük limit kaydı
        db.execute(
            "INSERT OR IGNORE INTO create_limits (ip_hash, create_date) VALUES (?, ?)",
            (ip_hash, today_str)
        )
        db.commit()

        base      = request.host_url.rstrip("/")
        view_url  = f"{base}/view/{entry_id}"
        owner_url = f"{base}/view/{entry_id}?token={owner_token}"

        return jsonify({
            "id": entry_id,
            "url": view_url,
            "owner_url": owner_url,
            "owner_token": owner_token,
            "owner_pin": owner_pin
        })

    except Exception as exc:
        app.logger.error("CREATE ERROR: %s", exc, exc_info=True)
        return jsonify({"error": "Beklenmedik bir hata oluştu. Lütfen tekrar deneyin."}), 500

# ── QR Görüntüle ──
@app.route("/view/<entry_id>")
def view_entry(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        abort(404)

    ip_hash = get_ip()
    token   = request.args.get("token", "")
    # PIN artık URL'de kabul edilmez (loglarda görünür); sadece token ile URL girişi
    pin     = ""   # URL'den PIN alımı güvenlik nedeniyle devre dışı

    is_owner = bool(token and secrets.compare_digest(token, entry["owner_token"]))
    if is_owner:
        login_session(entry_id)               # sahip linkiyle gelen de giriş yapmış sayılır
    me = current_login(db)
    if me and me["id"] == entry_id:
        is_owner = True                       # oturum açık → token/PIN sormadan sahip modu
    viewer = None
    if me:
        _img = me["profile_image"] or ""
        viewer = {"id": me["id"], "display_name": me["display_name"] or "",
                  "profile_image": _img if len(_img) < 300000 else ""}

    # ── Aktivasyon / Deneme Süresi Kontrolü ──
    is_activated = bool(entry["is_activated"] if "is_activated" in entry.keys() else 0)

    if not is_activated:
        # Deneme süresi dolmuş mu?
        trial_expired = False
        try:
            created   = datetime.fromisoformat(entry["created_at"])
            trial_end = created + timedelta(hours=FREE_TRIAL_HOURS)
            trial_expired = datetime.now() > trial_end
        except Exception:
            trial_expired = False

        if trial_expired:
            if is_owner:
                # QR sahibi → erişim kodu giriş sayfası göster
                return render_template(
                    "locked.html",
                    entry_id=entry_id,
                    owner_token=entry["owner_token"],
                    display_name=entry["display_name"] or "",
                    profile_image=entry["profile_image"] or "",
                )
            else:
                # Ziyaretçi → 404 (hesap aktif edilene kadar erişim yok)
                abort(404)
        # Süre henüz dolmadıysa hem sahip hem ziyaretçi normal sayfayı görür

    if not is_owner:
        db.execute("INSERT INTO views (entry_id, viewed_at) VALUES (?, ?)",
                   (entry_id, datetime.now().isoformat()))
        db.execute("UPDATE entries SET view_count = view_count + 1 WHERE id=?", (entry_id,))
        db.commit()
    else:
        # Sahip ziyaretini kaydet
        db.execute("UPDATE entries SET last_owner_visit=? WHERE id=?",
                   (datetime.now().isoformat(), entry_id))
        db.commit()

    last_views = []
    if is_owner:
        rows = db.execute(
            "SELECT viewed_at FROM views WHERE entry_id=? ORDER BY id DESC LIMIT 5",
            (entry_id,)
        ).fetchall()
        last_views = [r["viewed_at"] for r in rows]

    replies_rows = db.execute(
        "SELECT * FROM replies WHERE entry_id=? ORDER BY created_at DESC",
        (entry_id,)
    ).fetchall()
    replies = [{
        "id": r["id"], "text": r["text"], "created_at": r["created_at"],
        "owner_reply": r["owner_reply"], "owner_reply_at": r["owner_reply_at"]
    } for r in replies_rows]

    today = date.today().isoformat()
    already_replied = False
    if not is_owner:
        row = db.execute(
            "SELECT 1 FROM reply_limits WHERE ip_hash=? AND entry_id=? AND reply_date=?",
            (ip_hash, entry_id, today)
        ).fetchone()
        already_replied = row is not None

    # Display name değiştirme hakkı kontrolü (30 gün)
    can_change_name = True
    name_change_wait_days = 0
    if is_owner and entry["display_name_changed_at"]:
        try:
            last_change = datetime.fromisoformat(entry["display_name_changed_at"]).date()
            days_passed = (date.today() - last_change).days
            if days_passed < 30:
                can_change_name = False
                name_change_wait_days = 30 - days_passed
        except Exception:
            pass

    socials    = _json.loads(entry["socials"] or "{}")
    view_count = db.execute(
        "SELECT view_count FROM entries WHERE id=?", (entry_id,)
    ).fetchone()["view_count"]

    return render_template(
        "view.html",
        text=entry["text"],
        created_at=entry["created_at"],
        entry_id=entry_id,
        view_count=view_count,
        last_views=last_views,
        replies=replies,
        already_replied=already_replied,
        is_owner=is_owner,
        owner_token=entry["owner_token"] if is_owner else "",
        owner_pin=entry["owner_pin"] if is_owner else "",
        profile_image=entry["profile_image"] or "",
        socials=socials,
        viewer=viewer,
        discoverable=bool(entry["discoverable"] if "discoverable" in entry.keys() else 0),
        background_image=(entry["background_image"] if "background_image" in entry.keys() else "") or "",
        comments_enabled=bool(entry["comments_enabled"] if entry["comments_enabled"] is not None else 1),
        display_name=entry["display_name"] or "",
        can_change_name=can_change_name,
        name_change_wait_days=name_change_wait_days,
    )

# ── Yorum Bırak ──
@app.route("/api/reply/<entry_id>", methods=["POST"])
@require_json
@rate_limit("reply", limit=10, window_sec=60)   # dakikada max 10 istek
def reply(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT id, comments_enabled FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404
    if not entry["comments_enabled"]:
        return jsonify({"error": "Yorumlar kapalı"}), 403

    ip_hash = get_ip()
    today   = date.today().isoformat()
    row = db.execute(
        "SELECT 1 FROM reply_limits WHERE ip_hash=? AND entry_id=? AND reply_date=?",
        (ip_hash, entry_id, today)
    ).fetchone()
    if row:
        return jsonify({"error": "Bugün zaten mesaj bıraktın! Yarın tekrar deneyebilirsin."}), 429

    data = request.get_json(silent=True) or {}
    text = sanitize_text(data.get("text", ""), max_len=500)
    if not text:
        return jsonify({"error": "Mesaj boş veya çok uzun (max 500)"}), 400

    reply_id = secrets.token_hex(4)
    now      = datetime.now().isoformat()
    db.execute(
        "INSERT INTO replies (id, entry_id, text, created_at, ip_hash) VALUES (?,?,?,?,?)",
        (reply_id, entry_id, text, now, ip_hash)
    )
    db.execute(
        "INSERT INTO reply_limits (ip_hash, entry_id, reply_date) VALUES (?,?,?)",
        (ip_hash, entry_id, today)
    )
    # Bildirim oluştur (sahip için)
    notif_id = secrets.token_hex(4)
    db.execute(
        "INSERT INTO notifications (id, entry_id, reply_id, is_read, created_at) VALUES (?,?,?,0,?)",
        (notif_id, entry_id, reply_id, now)
    )
    db.commit()
    return jsonify({"ok": True, "reply_id": reply_id})

# ── Sahip Yanıtı ──
@app.route("/api/owner-reply/<entry_id>/<reply_id>", methods=["POST"])
@require_json
def owner_reply(entry_id, reply_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    text = sanitize_text(data.get("text", ""), max_len=500)
    if not text:
        return jsonify({"error": "Cevap boş veya çok uzun"}), 400

    reply_row = db.execute(
        "SELECT id FROM replies WHERE id=? AND entry_id=?", (reply_id, entry_id)
    ).fetchone()
    if not reply_row:
        return jsonify({"error": "Mesaj bulunamadı"}), 404

    db.execute(
        "UPDATE replies SET owner_reply=?, owner_reply_at=? WHERE id=?",
        (text, datetime.now().isoformat(), reply_id)
    )
    db.commit()
    return jsonify({"ok": True})

# ── Metni Düzenle ──
@app.route("/api/edit-text/<entry_id>", methods=["POST"])
@require_json
def edit_text(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    text = sanitize_text(data.get("text", ""), max_len=1000)
    if not text:
        return jsonify({"error": "Metin boş veya çok uzun"}), 400

    db.execute("UPDATE entries SET text=? WHERE id=?", (text, entry_id))
    db.commit()
    return jsonify({"ok": True, "text": text})

# ── Profil Resmi Güncelle (Sahip) ──
@app.route("/api/update-image/<entry_id>", methods=["POST"])
@require_json
def update_image(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    img_b64 = validate_image(data.get("profile_image", ""))
    img_url = validate_image(data.get("profile_image_url", ""))
    final_image = img_b64 or img_url  # boş string = resim kaldır

    db.execute("UPDATE entries SET profile_image=? WHERE id=?", (final_image, entry_id))
    db.commit()
    return jsonify({"ok": True, "profile_image": final_image})

# ── Arka Plan Resmi Güncelle (Sahip) ──
@app.route("/api/update-background/<entry_id>", methods=["POST"])
@require_json
def update_background(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    img = validate_image(data.get("background_image", ""))
    if img and not img.startswith("data:image"):   # sadece yüklenen resim, uzak URL yok
        img = ""
    db.execute("UPDATE entries SET background_image=? WHERE id=?", (img, entry_id))
    db.commit()
    return jsonify({"ok": True})

# ── Display Name Güncelle (Sahip, 30 günde bir) ──
@app.route("/api/update-display-name/<entry_id>", methods=["POST"])
@require_json
def update_display_name(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    # 30 gün kontrolü
    if entry["display_name_changed_at"]:
        try:
            last_change = datetime.fromisoformat(entry["display_name_changed_at"]).date()
            days_passed = (date.today() - last_change).days
            if days_passed < 30:
                wait = 30 - days_passed
                return jsonify({
                    "error": "NAME_COOLDOWN",
                    "wait_days": wait
                }), 429
        except Exception:
            pass

    new_name = sanitize_display_name(data.get("display_name", ""))
    # Boş string geçerliliği: isim kaldırılabilir (cooldown uygulanmaz)
    now_iso  = datetime.now().isoformat() if new_name else None

    db.execute(
        "UPDATE entries SET display_name=?, display_name_changed_at=? WHERE id=?",
        (new_name, now_iso, entry_id)
    )
    db.commit()
    return jsonify({"ok": True, "display_name": new_name})

# ── Yorum Sil ──
@app.route("/api/delete-reply/<entry_id>/<reply_id>", methods=["POST"])
@require_json
def delete_reply(entry_id, reply_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    db.execute("DELETE FROM replies WHERE id=? AND entry_id=?", (reply_id, entry_id))
    db.commit()
    return jsonify({"ok": True})

# ── Yorumları Aç/Kapat ──
@app.route("/api/toggle-comments/<entry_id>", methods=["POST"])
@require_json
def toggle_comments(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    current = entry["comments_enabled"] if entry["comments_enabled"] is not None else 1
    new_val = 0 if current else 1
    db.execute("UPDATE entries SET comments_enabled=? WHERE id=?", (new_val, entry_id))
    db.commit()
    return jsonify({"ok": True, "comments_enabled": bool(new_val)})

# ── Oturum (Giriş) Sistemi ──
def login_session(entry_id):
    """Bu tarayıcıyı bu hesapla giriş yapmış say (çıkış yapana kadar)."""
    session.permanent = True
    session["eid"] = entry_id

def current_login(db):
    """Oturumdaki hesap (yoksa None). Hesap silinmişse oturumu temizler."""
    eid = session.get("eid")
    if not eid:
        return None
    row = db.execute(
        "SELECT id, display_name, profile_image FROM entries WHERE id=?", (str(eid),)
    ).fetchone()
    if not row:
        session.pop("eid", None)
        return None
    return row

@app.route("/api/me")
def api_me():
    me = current_login(get_db())
    if not me:
        return jsonify({"logged_in": False})
    return jsonify({"logged_in": True, "entry_id": me["id"], "display_name": me["display_name"] or ""})

@app.route("/api/logout", methods=["POST"])
@require_json
def api_logout():
    session.clear()
    return jsonify({"ok": True})

# ── Kullanıcı Arama / Keşfet ──
_NAME_RE = re.compile(r'^[A-Z0-9_.-]{1,8}$')

def _is_public(entry):
    """Profil ziyaretçiye açık mı? (aktif ya da deneme süresi dolmamış)"""
    keys = entry.keys()
    if "is_activated" in keys and entry["is_activated"]:
        return True
    try:
        created = datetime.fromisoformat(entry["created_at"])
        return datetime.now() <= created + timedelta(hours=FREE_TRIAL_HOURS)
    except Exception:
        return True

@app.route("/api/search")
@rate_limit("search", limit=30, window_sec=60)
def search_users():
    """İsim başlangıcına göre arama. Sadece 'aramada görünsün' diyenler, en az 2 harf, en fazla 8 sonuç."""
    q = re.sub(r'[^A-Z0-9_.-]', '', (request.args.get("q") or "").upper())[:8]
    if len(q) < 2:
        return jsonify({"results": []})
    like = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    db   = get_db()
    rows = db.execute(
        "SELECT id, display_name, created_at, is_activated, "
        "(profile_image IS NOT NULL AND profile_image != '') AS has_img "
        "FROM entries WHERE discoverable=1 AND display_name != '' "
        "AND UPPER(display_name) LIKE ? ESCAPE '\\' "
        "ORDER BY (UPPER(display_name)=?) DESC, display_name LIMIT 30",
        (like, q)
    ).fetchall()
    out = []
    for r in rows:
        if not _is_public(r):
            continue
        name = r["display_name"].upper()
        out.append({
            "name":   name,
            "url":    "/u/" + name,
            "avatar": ("/avatar/" + r["id"]) if r["has_img"] else "",
        })
        if len(out) >= 8:
            break
    return jsonify({"results": out})

@app.route("/u/<name>")
@rate_limit("user_lookup", limit=60, window_sec=60)
def user_by_name(name):
    """/u/ISIM → profil sayfası (sadece aramada görünür olanlar)."""
    name = name.upper()
    if not _NAME_RE.match(name):
        abort(404)
    db = get_db()
    e  = db.execute(
        "SELECT id, created_at, is_activated FROM entries "
        "WHERE discoverable=1 AND UPPER(display_name)=?", (name,)
    ).fetchone()
    if not e or not _is_public(e):
        abort(404)
    return redirect(url_for("view_entry", entry_id=e["id"]))

@app.route("/avatar/<entry_id>")
def avatar_image(entry_id):
    """Arama listesi için küçük profil resmi (sadece aramada görünür profiller)."""
    check_entry_id(entry_id)
    db = get_db()
    e  = db.execute(
        "SELECT profile_image, discoverable, is_activated, created_at FROM entries WHERE id=?",
        (entry_id,)
    ).fetchone()
    if not e or not e["discoverable"] or not _is_public(e):
        abort(404)
    m = re.match(r'^data:(image/(?:png|jpe?g|gif|webp));base64,(.+)$', e["profile_image"] or "", re.S)
    if not m:
        abort(404)
    try:
        raw = base64.b64decode(m.group(2))
    except Exception:
        abort(404)
    resp = Response(raw, mimetype=m.group(1))
    resp.headers["Cache-Control"] = "public, max-age=300"
    return resp

@app.route("/api/toggle-discoverable/<entry_id>", methods=["POST"])
@require_json
def toggle_discoverable(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    current = bool(entry["discoverable"])
    if not current and not (entry["display_name"] or "").strip():
        return jsonify({"error": "NO_NAME"}), 400   # isimsiz profil aranamaz
    new_val = 0 if current else 1
    db.execute("UPDATE entries SET discoverable=? WHERE id=?", (new_val, entry_id))
    db.commit()
    return jsonify({"ok": True, "discoverable": bool(new_val)})

# ── Sosyal Medya Güncelle ──
@app.route("/api/update-socials/<entry_id>", methods=["POST"])
@require_json
def update_socials(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    socials_raw = data.get("socials", {})
    if not isinstance(socials_raw, dict):
        return jsonify({"error": "Geçersiz veri"}), 400

    socials = {}
    for p in ALLOWED_SOCIALS:
        v = sanitize_social(socials_raw.get(p, ""), p)
        if v:
            socials[p] = v

    # hidden listesini sakla (sadece izin verilen platformlar)
    hidden_raw = socials_raw.get("hidden", [])
    if isinstance(hidden_raw, list):
        hidden = [h for h in hidden_raw if h in ALLOWED_SOCIALS]
        if hidden:
            socials["hidden"] = hidden

    db.execute("UPDATE entries SET socials=? WHERE id=?",
               (_json.dumps(socials, ensure_ascii=False), entry_id))
    db.commit()
    return jsonify({"ok": True, "socials": socials})

# ── Kullanıcı Adı Kontrol ──
@app.route("/api/check-username", methods=["GET"])
@rate_limit("check_username", limit=30, window_sec=60)   # dakikada max 30
def check_username():
    try:
        name = request.args.get("name", "").strip()
        if not name:
            return jsonify({"available": True})
        # Direkt küçük harf alfanümerik kontrol
        import re as _re
        clean = re.sub(r'[^A-Z0-9_.-]', '', name.upper())[:8]
        if not clean:
            return jsonify({"available": False, "reason": "invalid"})
        db = get_db()
        existing = db.execute(
            "SELECT 1 FROM entries WHERE UPPER(display_name)=UPPER(?)", (clean,)
        ).fetchone()
        return jsonify({"available": existing is None, "sanitized": clean})
    except Exception as e:
        app.logger.error("check_username error: %s", e)
        return jsonify({"available": False}), 500

# ── Global PIN Arama ──
@app.route("/api/find-by-pin", methods=["POST"])
@require_json
def find_by_pin():
    data    = request.get_json(silent=True) or {}
    pin     = data.get("pin", "").strip().upper()
    ip_hash = get_ip()

    if not pin or not re.match(r'^[A-Z0-9]{8}$', pin):
        return jsonify({"error": "Geçersiz PIN formatı (8 haneli olmalı)"}), 400

    db = get_db()

    # Brute-force kontrolü
    fail_count = get_pin_fail_count(db, ip_hash)
    if fail_count >= PIN_DAILY_LIMIT:
        return jsonify({"error": "BLOCKED", "remaining": 0}), 429

    # Timing-safe karşılaştırma — PIN index'li arama (büyük DB'lerde performans)
    row = db.execute("SELECT id, owner_pin, owner_token FROM entries WHERE owner_pin=?", (pin,)).fetchone()
    found = row if row and secrets.compare_digest(pin, row["owner_pin"]) else None

    if not found:
        record_pin_fail(db, ip_hash)
        fail_count += 1
        remaining   = PIN_DAILY_LIMIT - fail_count
        if remaining <= 0:
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 404

    reset_pin_fails(db, ip_hash)
    login_session(found["id"])
    return jsonify({
        "ok": True,
        "entry_id": found["id"],
        "owner_token": found["owner_token"]
    })

# ── Verify PIN (geriye dönük uyumluluk) ──
@app.route("/api/verify-pin/<entry_id>", methods=["POST"])
@require_json
def verify_pin(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data    = request.get_json(silent=True) or {}
    ip_hash = get_ip()
    pin     = data.get("pin", "").strip().upper()

    fail_count = get_pin_fail_count(db, ip_hash)
    if fail_count >= PIN_DAILY_LIMIT:
        return jsonify({"error": "BLOCKED", "remaining": 0}), 429

    if not pin or not secrets.compare_digest(pin, entry["owner_pin"]):
        record_pin_fail(db, ip_hash)
        fail_count += 1
        remaining   = PIN_DAILY_LIMIT - fail_count
        return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403

    reset_pin_fails(db, ip_hash)
    login_session(entry_id)
    return jsonify({"ok": True, "owner_token": entry["owner_token"]})

# ── Liste ──
# ── Liste (Sadece Admin) ──
@app.route("/api/list")
def list_qr():
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        return jsonify({"error": "Yetkisiz"}), 403
    db   = get_db()
    rows = db.execute(
        "SELECT id, text, created_at, view_count, display_name FROM entries ORDER BY created_at DESC"
    ).fetchall()
    items = []
    for r in rows:
        rc = db.execute(
            "SELECT COUNT(*) as c FROM replies WHERE entry_id=?", (r["id"],)
        ).fetchone()["c"]
        items.append({
            "id": r["id"],
            "text_preview": r["text"][:60] + ("\u2026" if len(r["text"]) > 60 else ""),
            "created_at": r["created_at"],
            "view_count": r["view_count"],
            "reply_count": rc,
            "display_name": r["display_name"] or ""
        })
    return jsonify(items)

# ──────────────────────────────────────
#  OTP — SMS DOĞRULAMA
# ──────────────────────────────────────
# ──────────────────────────────────────
#  OTP — WHATSAPP CLOUD API
# ──────────────────────────────────────
OTP_EXPIRE_MINUTES = 10
OTP_MAX_ATTEMPTS   = 5

# .env veya ortam değişkenlerinden oku:
#   WA_PHONE_NUMBER_ID  — Meta Business > WhatsApp > Phone Number ID
#   WA_ACCESS_TOKEN     — Permanent / Temporary Access Token
WA_PHONE_NUMBER_ID = os.environ.get("WA_PHONE_NUMBER_ID", "")
WA_ACCESS_TOKEN    = os.environ.get("WA_ACCESS_TOKEN", "")

def send_whatsapp_otp(to_number, code):
    """
    Meta WhatsApp Cloud API ile OTP mesajı gönder.
    to_number: 07XXXXXXXXX  →  +447XXXXXXXXX
    Dönüş: (success: bool, error_msg: str | None)
    """
    if not WA_PHONE_NUMBER_ID or not WA_ACCESS_TOKEN:
        # Credentials yoksa dev modunda terminale yaz, kodu yine de döndür
        app.logger.info(f"[DEV WhatsApp OTP] {to_number} → {code}")
        return True, None

    # Irak formatına çevir: 07... → +9647...
    if to_number.startswith("07"):
        intl = "+964" + to_number[1:]
    else:
        intl = to_number

    url = f"https://graph.facebook.com/v20.0/{WA_PHONE_NUMBER_ID}/messages"
    headers = {
        "Authorization": f"Bearer {WA_ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "messaging_product": "whatsapp",
        "to": intl,
        "type": "text",
        "text": {
            "body": (
                f"🔐 *QR Mesaj Doğrulama*\n\n"
                f"Kodunuz: *{code}*\n\n"
                f"Bu kod {OTP_EXPIRE_MINUTES} dakika geçerlidir.\n"
                f"Kodu kimseyle paylaşmayın."
            )
        }
    }

    try:
        import urllib.request, json as _json_mod
        req = urllib.request.Request(
            url,
            data=_json_mod.dumps(payload).encode(),
            headers=headers,
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = _json_mod.loads(resp.read())
            if result.get("messages"):
                return True, None
            return False, "WhatsApp API beklenmedik yanıt döndürdü"
    except Exception as e:
        app.logger.error(f"WhatsApp OTP error: {e}")
        return False, str(e)


@app.route("/api/send-otp", methods=["POST"])
@require_json
@rate_limit("send_otp", limit=3, window_sec=600)   # 10 dakikada max 3 OTP
def send_otp():
    data  = request.get_json(silent=True) or {}
    phone = data.get("phone", "").strip().replace(" ", "")

    if not re.match(r'^07\d{9}$', phone):
        return jsonify({"error": "Geçersiz telefon numarası (07 ile başlayan 11 hane)"}), 400

    db  = get_db()
    now = datetime.now()
    expires = (now + timedelta(minutes=OTP_EXPIRE_MINUTES)).isoformat()

    # Eski kodları sil
    db.execute("DELETE FROM otp_codes WHERE phone=?", (phone,))

    # 6 haneli kod üret
    code   = "".join([str(secrets.randbelow(10)) for _ in range(6)])
    otp_id = secrets.token_hex(8)

    db.execute(
        "INSERT INTO otp_codes (id, phone, code, created_at, expires_at) VALUES (?,?,?,?,?)",
        (otp_id, phone, code, now.isoformat(), expires)
    )
    db.commit()

    success, err = send_whatsapp_otp(phone, code)

    if not success:
        app.logger.error("WhatsApp OTP gönderilemedi: %s", err)
        return jsonify({"error": "Mesaj gönderilemedi. Lütfen tekrar deneyin."}), 500

    # Credentials yoksa (dev mod) kodu frontend'e de dön
    dev_code = code if not WA_PHONE_NUMBER_ID else None
    return jsonify({"ok": True, "dev_code": dev_code})


@app.route("/api/verify-otp", methods=["POST"])
@require_json
@rate_limit("verify_otp", limit=10, window_sec=300)   # 5 dakikada max 10 deneme
def verify_otp():
    data  = request.get_json(silent=True) or {}
    phone = data.get("phone", "").strip().replace(" ", "")
    code  = data.get("code", "").strip()

    if not re.match(r'^07\d{9}$', phone):
        return jsonify({"error": "Geçersiz telefon"}), 400
    if not re.match(r'^\d{6}$', code):
        return jsonify({"error": "Geçersiz kod formatı"}), 400

    db  = get_db()
    now = datetime.now()

    row = db.execute(
        "SELECT * FROM otp_codes WHERE phone=? ORDER BY created_at DESC LIMIT 1",
        (phone,)
    ).fetchone()

    if not row:
        return jsonify({"error": "Kod bulunamadı. Tekrar gönder."}), 404

    # Süre kontrolü
    if datetime.fromisoformat(row["expires_at"]) < now:
        db.execute("DELETE FROM otp_codes WHERE id=?", (row["id"],))
        db.commit()
        return jsonify({"error": "EXPIRED"}), 410

    # Deneme limiti
    if row["attempts"] >= OTP_MAX_ATTEMPTS:
        db.execute("DELETE FROM otp_codes WHERE id=?", (row["id"],))
        db.commit()
        return jsonify({"error": "Çok fazla hatalı deneme. Tekrar gönder."}), 429

    # Kod kontrolü
    if not secrets.compare_digest(row["code"], code):
        db.execute("UPDATE otp_codes SET attempts=attempts+1 WHERE id=?", (row["id"],))
        db.commit()
        remaining = OTP_MAX_ATTEMPTS - row["attempts"] - 1
        return jsonify({"error": "WRONG_CODE", "remaining": remaining}), 400

    # Başarılı — doğrulandı olarak işaretle
    db.execute("UPDATE otp_codes SET verified=1 WHERE id=?", (row["id"],))
    db.commit()

    return jsonify({"ok": True})


# ── Bildirimleri Listele (Sahip) ──
@app.route("/api/notifications/<entry_id>", methods=["POST"])
@require_json
def get_notifications(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    rows = db.execute("""
        SELECT n.id, n.reply_id, n.is_read, n.created_at,
               r.text as reply_text
        FROM notifications n
        JOIN replies r ON r.id = n.reply_id
        WHERE n.entry_id=?
        ORDER BY n.created_at DESC
        LIMIT 50
    """, (entry_id,)).fetchall()

    unread_count = db.execute(
        "SELECT COUNT(*) as c FROM notifications WHERE entry_id=? AND is_read=0", (entry_id,)
    ).fetchone()["c"]

    notifs = [{
        "id": r["id"],
        "reply_id": r["reply_id"],
        "is_read": bool(r["is_read"]),
        "created_at": r["created_at"],
        "reply_text": r["reply_text"]
    } for r in rows]

    return jsonify({"notifications": notifs, "unread_count": unread_count})


# ── Bildirimi Okundu İşaretle ──
@app.route("/api/notifications/<entry_id>/read/<notif_id>", methods=["POST"])
@require_json
def mark_notification_read(entry_id, notif_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    db.execute(
        "UPDATE notifications SET is_read=1 WHERE id=? AND entry_id=?",
        (notif_id, entry_id)
    )
    db.commit()

    unread_count = db.execute(
        "SELECT COUNT(*) as c FROM notifications WHERE entry_id=? AND is_read=0", (entry_id,)
    ).fetchone()["c"]

    return jsonify({"ok": True, "unread_count": unread_count})


# ── Tümünü Okundu İşaretle ──
@app.route("/api/notifications/<entry_id>/read-all", methods=["POST"])
@require_json
def mark_all_notifications_read(entry_id):
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        if err == "WRONG_PIN":
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403
        return jsonify({"error": "Yetkisiz erişim!"}), 403

    db.execute(
        "UPDATE notifications SET is_read=1 WHERE entry_id=?", (entry_id,)
    )
    db.commit()
    return jsonify({"ok": True, "unread_count": 0})


# ──────────────────────────────────────
#  ADMİN PANELI
# ──────────────────────────────────────
@app.route("/admin")
def admin_page():
    from flask import send_from_directory
    for folder in [os.path.join(BASE_DIR, "templates"), BASE_DIR]:
        p = os.path.join(folder, "admin.html")
        if os.path.exists(p):
            return send_from_directory(folder, "admin.html")
    return "admin.html bulunamadi", 404

@app.route("/api/admin/verify", methods=["POST"])
@require_json
@rate_limit("admin_verify", limit=5, window_sec=300)   # 5 dakikada max 5 deneme
def admin_verify():
    data    = request.get_json(silent=True) or {}
    pin     = data.get("pin", "").strip().upper()
    if not pin or not secrets.compare_digest(pin, ADMIN_PIN):
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()
        app.logger.warning("Admin giriş başarısız — IP: %s", ip)
        return jsonify({"error": "WRONG_PIN"}), 403
    return jsonify({"ok": True, "token": ADMIN_TOKEN})

@app.route("/api/admin/data")
def admin_data():
    from datetime import timedelta
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        return jsonify({"error": "Yetkisiz"}), 403

    db      = get_db()
    entries = db.execute("SELECT * FROM entries ORDER BY created_at DESC").fetchall()
    cutoff_24h = (datetime.now() - timedelta(hours=24)).isoformat()
    cutoff_7d  = (datetime.now() - timedelta(days=7)).isoformat()

    result = []
    for e in entries:
        reply_count = db.execute(
            "SELECT COUNT(*) as c FROM replies WHERE entry_id=?", (e["id"],)
        ).fetchone()["c"]

        views_24h = db.execute(
            "SELECT COUNT(*) as c FROM views WHERE entry_id=? AND viewed_at>?",
            (e["id"], cutoff_24h)
        ).fetchone()["c"]

        views_7d = db.execute(
            "SELECT COUNT(*) as c FROM views WHERE entry_id=? AND viewed_at>?",
            (e["id"], cutoff_7d)
        ).fetchone()["c"]

        socials = _json.loads(e["socials"] or "{}")

        # Sahip son aktif ne zaman
        low = e["last_owner_visit"] if "last_owner_visit" in e.keys() else None

        result.append({
            "id":                   e["id"],
            "display_name":         e["display_name"] or "",
            "text":                 e["text"],
            "text_preview":         e["text"][:120] + ("…" if len(e["text"]) > 120 else ""),
            "created_at":           e["created_at"],
            "view_count":           e["view_count"],
            "reply_count":          reply_count,
            "views_24h":            views_24h,
            "views_7d":             views_7d,
            "owner_pin":            e["owner_pin"],
            "comments_enabled":     bool(e["comments_enabled"] if e["comments_enabled"] is not None else 1),
            "socials":              socials,
            "has_profile_image":    bool(e["profile_image"] and e["profile_image"].strip()),
            "last_owner_visit":     low,
            "is_activated":         bool(e["is_activated"] if "is_activated" in e.keys() else 0),
            "activated_at":         e["activated_at"] if "activated_at" in e.keys() else None,
        })

    total_views   = db.execute("SELECT COALESCE(SUM(view_count),0) as s FROM entries").fetchone()["s"]
    total_replies = db.execute("SELECT COUNT(*) as c FROM replies").fetchone()["c"]
    active_24h    = db.execute(
        "SELECT COUNT(DISTINCT entry_id) as c FROM views WHERE viewed_at>?", (cutoff_24h,)
    ).fetchone()["c"]
    owner_active_24h = sum(
        1 for r in result
        if r["last_owner_visit"] and r["last_owner_visit"] > cutoff_24h
    )

    return jsonify({
        "entries": result,
        "stats": {
            "total_entries":      len(result),
            "total_views":        total_views,
            "total_replies":      total_replies,
            "active_24h":         active_24h,
            "owner_active_24h":   owner_active_24h,
        }
    })

@app.route("/api/admin/delete/<entry_id>", methods=["POST"])
@require_json
def admin_delete(entry_id):
    check_entry_id(entry_id)
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        return jsonify({"error": "Yetkisiz"}), 403
    db = get_db()
    db.execute("DELETE FROM entries WHERE id=?", (entry_id,))
    db.commit()
    return jsonify({"ok": True})


# ──────────────────────────────────────
#  ÖDEME ERİŞİM KODLARI
# ──────────────────────────────────────

@app.route("/api/admin/gen-code", methods=["POST"])
def admin_gen_code():
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        return jsonify({"error": "Yetkisiz"}), 403
    data  = request.get_json(silent=True) or {}
    note  = html.escape((data.get("note") or "").strip()[:80])
    count = max(1, min(int(data.get("count", 1) or 1), 20))

    db  = get_db()
    now = datetime.now().isoformat()
    codes = []
    for _ in range(count):
        # 7 haneli büyük harf + rakam kodu (örn: A3F9K2M)
        alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'  # karışıklık yaratan 0/O/1/I çıkarıldı
        code = ''.join(secrets.choice(alphabet) for _ in range(7))
        try:
            db.execute(
                "INSERT INTO access_codes (code, created_at, note) VALUES (?,?,?)",
                (code, now, note)
            )
            codes.append(code)
        except Exception:
            pass
    db.commit()
    return jsonify({"ok": True, "codes": codes})


@app.route("/api/admin/codes")
def admin_list_codes():
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        return jsonify({"error": "Yetkisiz"}), 403
    rows = get_db().execute(
        "SELECT code, created_at, used, used_at, note FROM access_codes ORDER BY created_at DESC LIMIT 300"
    ).fetchall()
    return jsonify({"codes": [dict(r) for r in rows]})


@app.route("/api/admin/delete-code/<path:code>", methods=["POST"])
def admin_delete_code(code):
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        return jsonify({"error": "Yetkisiz"}), 403
    get_db().execute("DELETE FROM access_codes WHERE code=?", (code.upper(),))
    get_db().commit()
    return jsonify({"ok": True})


@app.route("/api/admin/delete-used-codes", methods=["POST"])
def admin_delete_used_codes():
    """Kullanılmış tüm erişim kodlarını sil."""
    token = request.headers.get("X-Admin-Token", "").strip()
    if not token or not secrets.compare_digest(token, ADMIN_TOKEN):
        return jsonify({"error": "Yetkisiz"}), 403
    db = get_db()
    result = db.execute("DELETE FROM access_codes WHERE used=1")
    db.commit()
    return jsonify({"ok": True, "deleted": result.rowcount})


@app.route("/api/verify-access-code", methods=["POST"])
@require_json
@rate_limit("verify_access_code", limit=5, window_sec=300)   # 5 dakikada max 5 deneme
def verify_access_code():
    data = request.get_json(silent=True) or {}
    raw  = (data.get("code") or "").strip().upper()

    if not re.match(r'^[A-Z0-9]{7}$', raw):
        return jsonify({"error": "Geçersiz kod formatı"}), 400

    db  = get_db()
    row = db.execute("SELECT * FROM access_codes WHERE code=?", (raw,)).fetchone()

    if not row:
        return jsonify({"error": "Kod bulunamadı"}), 404
    if row["used"]:
        return jsonify({"error": "Bu kod daha önce kullanılmış"}), 409

    ip_hash = get_ip()

    db.execute(
        "UPDATE access_codes SET used=1, used_at=?, used_by_ip=? WHERE code=?",
        (datetime.now().isoformat(), ip_hash, raw)
    )
    db.commit()
    return jsonify({"ok": True})

# ── Hesap Aktivasyonu (Erişim Kodu ile) ──
@app.route("/api/activate/<entry_id>", methods=["POST"])
@require_json
@rate_limit("activate", limit=5, window_sec=300)   # 5 dakikada max 5 deneme
def activate_entry(entry_id):
    check_entry_id(entry_id)
    data = request.get_json(silent=True) or {}
    raw  = (data.get("code") or "").strip().upper()

    if not re.match(r'^[A-Z0-9]{7}$', raw):
        return jsonify({"error": "Geçersiz kod formatı (7 karakter olmalı)"}), 400

    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    # Sadece QR sahibi aktive edebilir (token doğrulama)
    owner_token = data.get("owner_token", "").strip()
    if not owner_token or not secrets.compare_digest(owner_token, entry["owner_token"]):
        return jsonify({"error": "Yetkisiz erişim"}), 403

    # Zaten aktif mi?
    if entry["is_activated"]:
        return jsonify({"ok": True, "already_active": True})

    # Kodu kontrol et
    code_row = db.execute("SELECT * FROM access_codes WHERE code=?", (raw,)).fetchone()
    if not code_row:
        return jsonify({"error": "WRONG_CODE", "message": "Kod bulunamadı"}), 404
    if code_row["used"]:
        return jsonify({"error": "USED_CODE", "message": "Bu kod daha önce kullanılmış"}), 409

    ip_hash = get_ip()
    now     = datetime.now().isoformat()

    # Kodu kullanıldı olarak işaretle
    db.execute(
        "UPDATE access_codes SET used=1, used_at=?, used_by_ip=? WHERE code=?",
        (now, ip_hash, raw)
    )
    # Hesabı süresiz aktif et
    db.execute(
        "UPDATE entries SET is_activated=1, activated_at=? WHERE id=?",
        (now, entry_id)
    )
    db.commit()
    return jsonify({"ok": True, "activated": True})




# ──────────────────────────────────────
#  DİREKT MESAJLAŞMA
# ──────────────────────────────────────

def _dm_thread_id(a, b):
    """İki entry_id arasında deterministik thread_id üret."""
    return hashlib.sha256(("::".join(sorted([a, b]))).encode()).hexdigest()[:16]


@app.route("/api/dm/check-pin", methods=["POST"])
@require_json
@rate_limit("dm_check", limit=15, window_sec=60)
def dm_check_pin():
    """
    Mesaj göndermeden önce gönderenin PIN'ini doğrula.
    Başarılıysa display_name ve entry_id döner.
    """
    data    = request.get_json(silent=True) or {}
    pin     = (data.get("pin") or "").strip().upper()
    ip_hash = get_ip()

    if not pin or not re.match(r'^[A-Z0-9]{8}$', pin):
        return jsonify({"valid": False, "error": "invalid_format"}), 400

    db = get_db()
    fail_count = get_pin_fail_count(db, ip_hash)
    if fail_count >= PIN_DAILY_LIMIT:
        return jsonify({"valid": False, "error": "BLOCKED", "remaining": 0}), 429

    row = db.execute(
        "SELECT id, owner_pin, display_name, profile_image FROM entries WHERE owner_pin=?",
        (pin,)
    ).fetchone()

    if not row or not secrets.compare_digest(pin, row["owner_pin"]):
        record_pin_fail(db, ip_hash)
        remaining = max(0, PIN_DAILY_LIMIT - fail_count - 1)
        if remaining == 0:
            return jsonify({"valid": False, "error": "BLOCKED", "remaining": 0}), 429
        return jsonify({"valid": False, "error": "WRONG_PIN", "remaining": remaining}), 200

    reset_pin_fails(db, ip_hash)
    return jsonify({
        "valid":         True,
        "entry_id":      row["id"],
        "display_name":  row["display_name"] or "",
        "profile_image": row["profile_image"] or "",
    })


@app.route("/api/dm/send/<receiver_entry_id>", methods=["POST"])
@require_json
@rate_limit("dm_send", limit=20, window_sec=60)
def dm_send(receiver_entry_id):
    """PIN doğrulandıktan sonra mesaj gönder."""
    check_entry_id(receiver_entry_id)
    data       = request.get_json(silent=True) or {}
    sender_pin = (data.get("sender_pin") or "").strip().upper()
    text       = sanitize_text(data.get("text", ""), max_len=500)
    ip_hash    = get_ip()

    if not text:
        return jsonify({"error": "Mesaj boş veya çok uzun (max 500)"}), 400

    db = get_db()
    me = current_login(db)

    if not sender_pin and me:
        # Oturum açık → PIN istenmez
        sender_row = me
        stored_pin = ""
    else:
        if not sender_pin or not re.match(r'^[A-Z0-9]{8}$', sender_pin):
            return jsonify({"error": "Geçersiz PIN" if sender_pin else "LOGIN_REQUIRED"}), 400

        # Göndereni tekrar doğrula
        fail_count = get_pin_fail_count(db, ip_hash)
        if fail_count >= PIN_DAILY_LIMIT:
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429

        sender_row = db.execute(
            "SELECT id, owner_pin, display_name FROM entries WHERE owner_pin=?",
            (sender_pin,)
        ).fetchone()

        if not sender_row or not secrets.compare_digest(sender_pin, sender_row["owner_pin"]):
            record_pin_fail(db, ip_hash)
            remaining = max(0, PIN_DAILY_LIMIT - fail_count - 1)
            return jsonify({"error": "WRONG_PIN", "remaining": remaining}), 403

        reset_pin_fails(db, ip_hash)
        stored_pin = sender_pin

    sender_entry_id = sender_row["id"]

    if sender_entry_id == receiver_entry_id:
        return jsonify({"error": "Kendinize mesaj gönderemezsiniz"}), 400

    receiver_row = db.execute(
        "SELECT id, display_name FROM entries WHERE id=?", (receiver_entry_id,)
    ).fetchone()
    if not receiver_row:
        return jsonify({"error": "Alıcı bulunamadı"}), 404

    thread_id = _dm_thread_id(sender_entry_id, receiver_entry_id)
    msg_id    = secrets.token_hex(4)
    now       = datetime.now().isoformat()

    db.execute("""
        INSERT INTO direct_messages
          (id, thread_id, sender_pin, sender_entry_id, receiver_entry_id, text, created_at, is_read)
        VALUES (?,?,?,?,?,?,?,0)
    """, (msg_id, thread_id, stored_pin, sender_entry_id, receiver_entry_id, text, now))
    db.commit()

    return jsonify({
        "ok":                   True,
        "msg_id":               msg_id,
        "thread_id":            thread_id,
        "sender_display_name":  sender_row["display_name"] or "",
        "receiver_display_name": receiver_row["display_name"] or "",
    })


@app.route("/api/dm/inbox/<entry_id>", methods=["POST"])
@require_json
@rate_limit("dm_inbox", limit=60, window_sec=60)
def dm_inbox(entry_id):
    """Sahibin tüm konuşmalarını listele (son mesaja göre sıralı)."""
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        return jsonify({"error": "Yetkisiz"}), 403

    threads_raw = db.execute("""
        SELECT
          thread_id,
          CASE WHEN sender_entry_id=? THEN receiver_entry_id ELSE sender_entry_id END AS other_id,
          MAX(created_at) AS last_at
        FROM direct_messages
        WHERE sender_entry_id=? OR receiver_entry_id=?
        GROUP BY thread_id
        ORDER BY last_at DESC
    """, (entry_id, entry_id, entry_id)).fetchall()

    threads = []
    for tr in threads_raw:
        other = db.execute(
            "SELECT id, display_name, profile_image FROM entries WHERE id=?",
            (tr["other_id"],)
        ).fetchone()

        last_msg = db.execute("""
            SELECT text, sender_entry_id, created_at FROM direct_messages
            WHERE thread_id=? ORDER BY created_at DESC LIMIT 1
        """, (tr["thread_id"],)).fetchone()

        unread = db.execute("""
            SELECT COUNT(*) AS c FROM direct_messages
            WHERE thread_id=? AND receiver_entry_id=? AND is_read=0
        """, (tr["thread_id"], entry_id)).fetchone()["c"]

        threads.append({
            "thread_id":          tr["thread_id"],
            "other_entry_id":     tr["other_id"],
            "other_display_name": other["display_name"] if other else "?",
            "other_profile_image": other["profile_image"] if other else "",
            "last_message":       last_msg["text"] if last_msg else "",
            "last_at":            last_msg["created_at"] if last_msg else "",
            "last_is_mine":       (last_msg["sender_entry_id"] == entry_id) if last_msg else False,
            "unread_count":       unread,
        })

    total_unread = sum(t["unread_count"] for t in threads)
    return jsonify({"threads": threads, "total_unread": total_unread})


@app.route("/api/dm/thread/<entry_id>/<thread_id>", methods=["POST"])
@require_json
@rate_limit("dm_thread", limit=60, window_sec=60)
def dm_thread_msgs(entry_id, thread_id):
    """Bir thread'in tüm mesajlarını döndür, okundu işaretle."""
    check_entry_id(entry_id)
    if not re.match(r'^[a-f0-9]{16}$', thread_id):
        abort(404)

    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"error": "Bulunamadı"}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        if err == "BLOCKED":
            return jsonify({"error": "BLOCKED", "remaining": 0}), 429
        return jsonify({"error": "Yetkisiz"}), 403

    # Thread'e erişim hakkı var mı?
    member = db.execute("""
        SELECT 1 FROM direct_messages
        WHERE thread_id=? AND (sender_entry_id=? OR receiver_entry_id=?)
        LIMIT 1
    """, (thread_id, entry_id, entry_id)).fetchone()
    if not member:
        return jsonify({"error": "Thread bulunamadı"}), 404

    # Gelen mesajları okundu yap
    db.execute("""
        UPDATE direct_messages SET is_read=1
        WHERE thread_id=? AND receiver_entry_id=? AND is_read=0
    """, (thread_id, entry_id))
    db.commit()

    msgs = db.execute("""
        SELECT m.id, m.text, m.created_at, m.sender_entry_id,
               e.display_name AS sender_name
        FROM direct_messages m
        LEFT JOIN entries e ON e.id = m.sender_entry_id
        WHERE m.thread_id=?
        ORDER BY m.created_at ASC
    """, (thread_id,)).fetchall()

    return jsonify({"messages": [{
        "id":          m["id"],
        "text":        m["text"],
        "created_at":  m["created_at"],
        "is_mine":     m["sender_entry_id"] == entry_id,
        "sender_name": m["sender_name"] or "?",
    } for m in msgs]})


@app.route("/api/dm/unread/<entry_id>", methods=["POST"])
@require_json
@rate_limit("dm_unread", limit=120, window_sec=60)
def dm_unread(entry_id):
    """Polling: sadece toplam okunmamış DM sayısını döndür."""
    check_entry_id(entry_id)
    db    = get_db()
    entry = db.execute("SELECT * FROM entries WHERE id=?", (entry_id,)).fetchone()
    if not entry:
        return jsonify({"unread": 0}), 404

    data  = request.get_json(silent=True) or {}
    valid, err, remaining = check_owner_auth(db, entry, data, ip_hash=get_ip())
    if not valid:
        return jsonify({"unread": 0}), 403

    count = db.execute("""
        SELECT COUNT(*) AS c FROM direct_messages
        WHERE receiver_entry_id=? AND is_read=0
    """, (entry_id,)).fetchone()["c"]
    return jsonify({"unread": count})


# ── Hata Sayfaları ──
@app.errorhandler(404)
def not_found(e):
    return render_template("404.html"), 404

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": "İstek çok büyük (max 4MB)"}), 413

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Çok fazla istek"}), 429

@app.errorhandler(500)
def server_error(e):
    app.logger.error("500: %s", e)
    return jsonify({"error": "Sunucu hatası oluştu. Lütfen tekrar deneyin."}), 500

# ──────────────────────────────────────
#  BAŞLATMA
# ──────────────────────────────────────
init_db()

if __name__ == "__main__":
    import socket
    local_ip = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    print(f"\n🚀 QR Mesaj v2 — Güvenli Sürüm")
    print(f"   Local:   http://127.0.0.1:5000")
    print(f"   Network: http://{local_ip}:5000")
    print(f"   DB:      {DB_PATH}\n")

    app.run(debug=False, host="0.0.0.0", port=5000)