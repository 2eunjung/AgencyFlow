import base64
import hashlib
import hmac
import secrets
import time
import json
import os
import re
import sqlite3
from datetime import date, datetime, timedelta
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "projects.sqlite3"
SECRET_PATH = BASE_DIR / "projects.secret"
DEFAULT_ADMIN_ID = "admin"
DEFAULT_ADMIN_PASSWORD = os.environ.get("AGENCY_FLOW_ADMIN_PASSWORD", "").strip()
PASSWORD_ITERATIONS = 260000
PASSWORD_HASH_PREFIX = f"pbkdf2:{PASSWORD_ITERATIONS}:"
VALID_MODES = {"public", "private"}
MAX_JSON_BODY_BYTES = 25 * 1024 * 1024
MAX_PDF_BYTES = 10 * 1024 * 1024
MAX_LIBRARY_FILE_BYTES = 5 * 1024 * 1024
MAX_LIBRARY_FILES = 3
LIBRARY_ALLOWED_EXTENSIONS = {
    ".pdf": {"application/pdf"},
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
    ".gif": {"image/gif"},
    ".webp": {"image/webp"},
    ".txt": {"text/plain"},
    ".csv": {"text/csv", "application/vnd.ms-excel"},
    ".doc": {"application/msword", "application/octet-stream"},
    ".docx": {"application/vnd.openxmlformats-officedocument.wordprocessingml.document", "application/zip", "application/octet-stream"},
    ".xls": {"application/vnd.ms-excel", "application/octet-stream"},
    ".xlsx": {"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "application/zip", "application/octet-stream"},
    ".ppt": {"application/vnd.ms-powerpoint", "application/octet-stream"},
    ".pptx": {"application/vnd.openxmlformats-officedocument.presentationml.presentation", "application/zip", "application/octet-stream"},
}
LIBRARY_BLOCKED_EXTENSIONS = {
    ".html", ".htm", ".svg", ".js", ".mjs", ".cmd", ".bat", ".ps1", ".exe", ".dll", ".msi", ".scr", ".vbs",
    ".php", ".py", ".rb", ".jar", ".sh", ".com", ".lnk", ".zip", ".7z", ".rar",
}
SESSION_TTL_SECONDS = 60 * 60
SESSION_TOKEN_BYTES = 32
LOGIN_FAILURE_LIMIT = 5
ALLOW_WEAK_ADMIN_PASSWORD = os.environ.get("AGENCY_FLOW_ALLOW_WEAK_ADMIN", "").strip().lower() in {"1", "true", "yes"}
SECURITY_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'",
}
SESSIONS = {}
LOGIN_FAILURE_COUNT = 0
LOGIN_LOCKED = False
DEFAULT_DEPARTMENTS = ("경영관리", "영업", "pm", "디자인", "퍼블리싱", "프로그램", "유지보수")
USER_ROLES = ("admin", "team_lead", "user")
DEFAULT_DEPARTMENT_COLORS = {
    "경영관리": "#d9eadf",
    "영업": "#fdecc8",
    "pm": "#dbeafe",
    "디자인": "#f3d9fa",
    "퍼블리싱": "#d9f99d",
    "프로그램": "#cffafe",
    "유지보수": "#fee2e2",
}
PROJECT_STAFF_ASSIGNMENTS = (
    ("pm", "pmId", ("pm",)),
    ("designer", "designerId", ("디자인", "디자이너")),
    ("publisher", "publisherId", ("퍼블리싱", "퍼블리셔")),
    ("programmer", "programmerId", ("프로그램", "프로그래머")),
)
PROJECT_COMPLETION_STAGES = (
    {"key": "design_worker", "label": "담당자 디자인 완료", "actor": "worker", "departments": ("디자인", "디자이너"), "name_key": "designer", "id_key": "designerId"},
    {"key": "design_lead", "label": "팀장 디자인 완료", "actor": "lead", "departments": ("디자인", "디자이너")},
    {"key": "design_pm", "label": "PM 디자인 완료", "actor": "pm", "departments": ("pm",), "name_key": "pm", "id_key": "pmId"},
    {"key": "publishing_worker", "label": "담당자 퍼블리싱 완료", "actor": "worker", "departments": ("퍼블리싱", "퍼블리셔"), "name_key": "publisher", "id_key": "publisherId"},
    {"key": "publishing_lead", "label": "팀장 퍼블리싱 완료", "actor": "lead", "departments": ("퍼블리싱", "퍼블리셔")},
    {"key": "publishing_pm", "label": "PM 퍼블리싱 완료", "actor": "pm", "departments": ("pm",), "name_key": "pm", "id_key": "pmId"},
    {"key": "program_worker", "label": "담당자 프로그램 완료", "actor": "worker", "departments": ("프로그램", "프로그래머"), "name_key": "programmer", "id_key": "programmerId"},
    {"key": "program_lead", "label": "팀장 프로그램 완료", "actor": "lead", "departments": ("프로그램", "프로그래머")},
    {"key": "program_pm", "label": "PM 프로그램 완료", "actor": "pm", "departments": ("pm",), "name_key": "pm", "id_key": "pmId"},
)
PDF_DANGEROUS_MARKERS = (
    b"/JavaScript",
    b"/JS",
    b"/OpenAction",
    b"/AA",
    b"/Launch",
    b"/EmbeddedFile",
    b"/RichMedia",
    b"/XFA",
)

SAMPLE_PROJECTS = []


def load_secret():
    if SECRET_PATH.exists():
        return base64.b64decode(SECRET_PATH.read_text(encoding="ascii"))
    secret = os.urandom(32)
    SECRET_PATH.write_text(base64.b64encode(secret).decode("ascii"), encoding="ascii")
    return secret


APP_SECRET = load_secret()


def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def normalize_mode(value):
    return "private" if value == "private" else "public"


def read_json_file(name, fallback):
    path = BASE_DIR / name
    if not path.exists():
        return fallback
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(text):
    return base64.b64decode(str(text).encode("ascii"))


def crypto_key(label):
    return hmac.new(APP_SECRET, label.encode("utf-8"), hashlib.sha256).digest()


def keystream(key, nonce, length):
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def encrypt_text(value):
    plain = str(value or "").encode("utf-8")
    nonce = os.urandom(16)
    key = crypto_key("identity-encryption")
    stream = keystream(key, nonce, len(plain))
    cipher = bytes(a ^ b for a, b in zip(plain, stream))
    tag = hmac.new(crypto_key("identity-auth"), nonce + cipher, hashlib.sha256).digest()
    return "enc:v1:" + b64(nonce + cipher + tag)


def decrypt_text(value):
    text = str(value or "")
    if not text.startswith("enc:v1:"):
        return text
    raw = unb64(text[len("enc:v1:"):])
    if len(raw) < 48:
        return ""
    nonce = raw[:16]
    tag = raw[-32:]
    cipher = raw[16:-32]
    expected = hmac.new(crypto_key("identity-auth"), nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("Encrypted data validation failed.")
    stream = keystream(crypto_key("identity-encryption"), nonce, len(cipher))
    plain = bytes(a ^ b for a, b in zip(cipher, stream))
    return plain.decode("utf-8")


def id_lookup(user_id):
    normalized = str(user_id or "").strip().lower()
    return hmac.new(crypto_key("identity-lookup"), normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def hash_password(password, salt=None):
    salt_bytes = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt_bytes, PASSWORD_ITERATIONS)
    return f"{PASSWORD_HASH_PREFIX}{b64(salt_bytes)}:{b64(digest)}"


def verify_password(password, stored):
    value = str(stored or "")
    if not value.startswith("pbkdf2:"):
        return False
    try:
        prefix, rounds_text, body = value.split(":", 2)
        rounds = int(rounds_text)
        salt_part, hash_part = body.rsplit(":", 1)
        salt = unb64(salt_part)
        expected = unb64(hash_part)
        actual = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt, rounds)
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def password_needs_rehash(stored):
    return not str(stored or "").startswith(PASSWORD_HASH_PREFIX)


def normalize_approval_status(status, role="user"):
    if status in ("활성화", "승인", "active", "approved"):
        return "활성화"
    if status in ("비활성화", "대기", "거부", "inactive", "pending", "rejected"):
        return "비활성화"
    return "활성화" if role == "admin" else "비활성화"


def normalize_user_role(role):
    value = str(role or "").strip()
    return value if value in USER_ROLES else "user"


def is_strong_password(password):
    value = str(password or "")
    return len(value) >= 8 and re.search(r"[A-Za-z]", value) and re.search(r"[0-9]", value) and re.search(r"[^A-Za-z0-9]", value)


def is_default_admin_password(user_id, password):
    return str(user_id or "").strip().lower() == DEFAULT_ADMIN_ID and str(password or "") == "admin"


def request_origin_allowed(handler):
    origin = handler.headers.get("Origin") or handler.headers.get("Referer") or ""
    if not origin:
        return True
    parsed = urlparse(origin)
    host = handler.headers.get("Host") or ""
    return not parsed.netloc or parsed.netloc == host



def public_user(row):
    return {
        "id": decrypt_text(row["id_enc"]),
        "name": decrypt_text(row["name_enc"]),
        "role": row["role"],
        "approvalStatus": row["approval_status"],
        "department": row["department"] if "department" in row.keys() else "",
        "position": row["position"] if "position" in row.keys() else "",
        "hireDate": row["hire_date"] if "hire_date" in row.keys() else "",
        "resignDate": row["resign_date"] if "resign_date" in row.keys() else "",
    }


def normalize_department(value):
    department = str(value or "").strip()
    return department if department else DEFAULT_DEPARTMENTS[0]


def project_sort_key(project):
    value = project.get("projectNo") or project.get("no") or project.get("id") or ""
    text = str(value)
    return (0, int(text)) if text.isdigit() else (1, text)


def project_columns(project):
    return (
        str(project.get("id") or project.get("projectNo") or os.urandom(8).hex()),
        str(project.get("projectNo") or project.get("no") or ""),
        str(project.get("name") or ""),
        str(project.get("status") or project.get("progressStatus") or ""),
        str(project.get("milestone") or project.get("adminMilestone") or ""),
        str(project.get("pm") or ""),
        json.dumps(project, ensure_ascii=False),
    )


def admin_project_columns(project):
    return (
        str(project.get("projectNo") or project.get("id") or os.urandom(8).hex()),
        str(project.get("projectNo") or ""),
        str(project.get("name") or ""),
        str(project.get("progressStatus") or project.get("status") or ""),
        str(project.get("milestone") or ""),
        str(project.get("pm") or ""),
        json.dumps(project, ensure_ascii=False),
    )


def insert_projects(conn, mode, projects):
    conn.executemany(
        """
        INSERT INTO project_records
          (mode, id, project_no, name, status, milestone, pm, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mode, id) DO UPDATE SET
          project_no = excluded.project_no,
          name = excluded.name,
          status = excluded.status,
          milestone = excluded.milestone,
          pm = excluded.pm,
          data_json = excluded.data_json,
          updated_at = CURRENT_TIMESTAMP
        """,
        [(mode, *project_columns(project)) for project in projects],
    )


def insert_admin_projects(conn, mode, admin_projects):
    conn.executemany(
        """
        INSERT INTO admin_project_records
          (mode, id, project_no, name, progress_status, milestone, pm, data_json)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(mode, id) DO UPDATE SET
          project_no = excluded.project_no,
          name = excluded.name,
          progress_status = excluded.progress_status,
          milestone = excluded.milestone,
          pm = excluded.pm,
          data_json = excluded.data_json,
          updated_at = CURRENT_TIMESTAMP
        """,
        [(mode, *admin_project_columns(project)) for project in admin_projects],
    )


def load_legacy_dataset(conn, mode):
    row = conn.execute(
        "SELECT projects_json, admin_projects_json FROM datasets WHERE mode = ?",
        (mode,),
    ).fetchone()
    if row:
        return {
            "projects": json.loads(row["projects_json"] or "[]"),
            "adminProjects": json.loads(row["admin_projects_json"] or "[]"),
        }
    filename = "projects-data.private.json" if mode == "private" else "projects-data.json"
    return read_json_file(filename, {"projects": [], "adminProjects": []})


def legacy_users(conn):
    table = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
    if not table:
        return []
    return conn.execute("SELECT id, password, name, role, approval_status FROM users").fetchall()


def upsert_secure_user(conn, user_id, password_hash, name, role, approval_status, department="", position="", hire_date="", resign_date=""):
    role = normalize_user_role(role)
    approval = normalize_approval_status(approval_status, role)
    department = normalize_department(department)
    position = str(position or "").strip()[:40]
    hire_date = str(hire_date or "").strip()[:10]
    resign_date = str(resign_date or "").strip()[:10]
    conn.execute(
        """
        INSERT INTO users_secure
          (id_lookup, id_enc, password, name_enc, role, approval_status, department, position, hire_date, resign_date)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id_lookup) DO UPDATE SET
          id_enc = excluded.id_enc,
          password = excluded.password,
          name_enc = excluded.name_enc,
          role = excluded.role,
          approval_status = excluded.approval_status,
          department = excluded.department,
          position = excluded.position,
          hire_date = excluded.hire_date,
          resign_date = excluded.resign_date,
          updated_at = CURRENT_TIMESTAMP
        """,
        (id_lookup(user_id), encrypt_text(user_id), password_hash, encrypt_text(name), role, approval, department, position, hire_date, resign_date),
    )


def create_users_secure_table(conn):
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users_secure (
          id_lookup TEXT PRIMARY KEY,
          id_enc TEXT NOT NULL,
          password TEXT NOT NULL,
          name_enc TEXT NOT NULL,
          role TEXT NOT NULL CHECK(role IN ('admin', 'team_lead', 'user')),
          approval_status TEXT NOT NULL,
          department TEXT NOT NULL DEFAULT '',
          position TEXT NOT NULL DEFAULT '',
          hire_date TEXT NOT NULL DEFAULT '',
          resign_date TEXT NOT NULL DEFAULT '',
          created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def migrate_users_secure_role_check(conn):
    row = conn.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='users_secure'").fetchone()
    sql = row["sql"] if row else ""
    if "team_lead" in str(sql):
        return
    legacy_columns = [row["name"] for row in conn.execute("PRAGMA table_info(users_secure)").fetchall()]
    if not legacy_columns:
        return
    conn.execute("ALTER TABLE users_secure RENAME TO users_secure_legacy_role")
    create_users_secure_table(conn)
    target_columns = [
        "id_lookup",
        "id_enc",
        "password",
        "name_enc",
        "role",
        "approval_status",
        "department",
        "position",
        "hire_date",
        "resign_date",
        "created_at",
        "updated_at",
    ]
    defaults = {
        "department": "''",
        "position": "''",
        "hire_date": "''",
        "resign_date": "''",
        "created_at": "CURRENT_TIMESTAMP",
        "updated_at": "CURRENT_TIMESTAMP",
    }
    select_exprs = [column if column in legacy_columns else defaults.get(column, "''") for column in target_columns]
    conn.execute(
        f"""
        INSERT INTO users_secure ({", ".join(target_columns)})
        SELECT {", ".join(select_exprs)}
        FROM users_secure_legacy_role
        """
    )
    conn.execute("DROP TABLE users_secure_legacy_role")


def ensure_db():
    with connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS datasets (
              mode TEXT PRIMARY KEY CHECK(mode IN ('public', 'private')),
              projects_json TEXT NOT NULL,
              admin_projects_json TEXT NOT NULL,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS project_records (
              mode TEXT NOT NULL CHECK(mode IN ('public', 'private')),
              id TEXT NOT NULL,
              project_no TEXT,
              name TEXT,
              status TEXT,
              milestone TEXT,
              pm TEXT,
              data_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (mode, id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_records_mode_project_no ON project_records(mode, project_no)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_records_mode_status ON project_records(mode, status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_records_mode_milestone ON project_records(mode, milestone)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS admin_project_records (
              mode TEXT NOT NULL CHECK(mode IN ('public', 'private')),
              id TEXT NOT NULL,
              project_no TEXT,
              name TEXT,
              progress_status TEXT,
              milestone TEXT,
              pm TEXT,
              data_json TEXT NOT NULL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              PRIMARY KEY (mode, id)
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_admin_project_records_mode_project_no ON admin_project_records(mode, project_no)")
        create_users_secure_table(conn)
        migrate_users_secure_role_check(conn)
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(users_secure)").fetchall()]
        if "department" not in columns:
            conn.execute("ALTER TABLE users_secure ADD COLUMN department TEXT NOT NULL DEFAULT ''")
        if "position" not in columns:
            conn.execute("ALTER TABLE users_secure ADD COLUMN position TEXT NOT NULL DEFAULT ''")
        if "hire_date" not in columns:
            conn.execute("ALTER TABLE users_secure ADD COLUMN hire_date TEXT NOT NULL DEFAULT ''")
        if "resign_date" not in columns:
            conn.execute("ALTER TABLE users_secure ADD COLUMN resign_date TEXT NOT NULL DEFAULT ''")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS departments (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL UNIQUE,
              color TEXT NOT NULL DEFAULT '#d9eadf',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        department_columns = [row["name"] for row in conn.execute("PRAGMA table_info(departments)").fetchall()]
        if "color" not in department_columns:
            conn.execute("ALTER TABLE departments ADD COLUMN color TEXT NOT NULL DEFAULT '#d9eadf'")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS company_holidays (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              date TEXT NOT NULL,
              title TEXT NOT NULL,
              kind TEXT NOT NULL DEFAULT '회사휴일',
              created_by_enc TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(date, title)
            )
            """
        )
        holiday_columns = [row["name"] for row in conn.execute("PRAGMA table_info(company_holidays)").fetchall()]
        if "kind" not in holiday_columns:
            conn.execute("ALTER TABLE company_holidays ADD COLUMN kind TEXT NOT NULL DEFAULT '회사휴일'")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS app_state (
              key TEXT PRIMARY KEY,
              value TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS login_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id_enc TEXT NOT NULL,
              name_enc TEXT NOT NULL,
              role TEXT NOT NULL,
              result TEXT NOT NULL CHECK(result IN ('success', 'failure')),
              failure_reason TEXT NOT NULL,
              ip TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_logs_created_at ON login_logs(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_login_logs_result ON login_logs(result)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS project_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id_enc TEXT NOT NULL,
              name_enc TEXT NOT NULL,
              role TEXT NOT NULL,
              action TEXT NOT NULL,
              category TEXT NOT NULL,
              project_no TEXT NOT NULL,
              project_name_enc TEXT NOT NULL,
              target TEXT NOT NULL,
              summary_enc TEXT NOT NULL,
              created_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_logs_created_at ON project_logs(created_at DESC)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_project_logs_project_no ON project_logs(project_no)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leave_balances (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id_lookup TEXT NOT NULL,
              user_id_enc TEXT NOT NULL,
              user_name_enc TEXT NOT NULL,
              year INTEGER NOT NULL,
              total_days REAL NOT NULL DEFAULT 15,
              remaining_days REAL,
              created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
              UNIQUE(user_id_lookup, year)
            )
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(leave_balances)").fetchall()}
        if "remaining_days" not in columns:
            conn.execute("ALTER TABLE leave_balances ADD COLUMN remaining_days REAL")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leave_balances_user_year ON leave_balances(user_id_lookup, year)")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS leave_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              user_id_lookup TEXT NOT NULL,
              user_id_enc TEXT NOT NULL,
              user_name_enc TEXT NOT NULL,
              year INTEGER NOT NULL,
              start_date TEXT NOT NULL,
              end_date TEXT NOT NULL,
              days REAL NOT NULL,
              leave_type TEXT NOT NULL,
              reason_enc TEXT NOT NULL,
              status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected')),
              approved_by_enc TEXT NOT NULL DEFAULT '',
              approved_at TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leave_requests_user_year ON leave_requests(user_id_lookup, year)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leave_requests_status ON leave_requests(status)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_leave_requests_start_date ON leave_requests(start_date DESC)")
        for department in DEFAULT_DEPARTMENTS:
            conn.execute(
                "INSERT OR IGNORE INTO departments (name, color) VALUES (?, ?)",
                (department, DEFAULT_DEPARTMENT_COLORS.get(department, "#d9eadf")),
            )
            conn.execute(
                "UPDATE departments SET color = ? WHERE name = ? AND (color = '' OR color IS NULL OR color = '#d9eadf')",
                (DEFAULT_DEPARTMENT_COLORS.get(department, "#d9eadf"), department),
            )

        for mode in ("private",):
            count = conn.execute("SELECT COUNT(*) AS count FROM project_records WHERE mode = ?", (mode,)).fetchone()["count"]
            if count == 0:
                seed = load_legacy_dataset(conn, mode)
                insert_projects(conn, mode, seed.get("projects") or [])
                insert_admin_projects(conn, mode, seed.get("adminProjects") or [])

        secure_count = conn.execute("SELECT COUNT(*) AS count FROM users_secure").fetchone()["count"]
        if secure_count == 0:
            for row in legacy_users(conn):
                password = row["password"] if str(row["password"] or "").startswith("pbkdf2:") else hash_password(row["password"])
                upsert_secure_user(conn, row["id"], password, row["name"], row["role"], row["approval_status"])

        weak_rows = conn.execute("SELECT * FROM users_secure WHERE password NOT LIKE 'pbkdf2:%'").fetchall()
        for row in weak_rows:
            user = public_user(row)
            upsert_secure_user(conn, user["id"], hash_password(row["password"]), user.get("name", ""), user.get("role", "user"), user.get("approvalStatus", ""), user.get("department", ""), user.get("position", ""), user.get("hireDate", ""), user.get("resignDate", ""))

        admin_row = conn.execute("SELECT 1 FROM users_secure WHERE id_lookup = ?", (id_lookup(DEFAULT_ADMIN_ID),)).fetchone()
        if not admin_row and DEFAULT_ADMIN_PASSWORD:
            upsert_secure_user(conn, DEFAULT_ADMIN_ID, hash_password(DEFAULT_ADMIN_PASSWORD), "관리자", "admin", "활성화", DEFAULT_DEPARTMENTS[0])

        legacy = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").fetchone()
        if legacy:
            conn.execute("DROP TABLE users")
        conn.commit()


def get_users(conn):
    rows = conn.execute("SELECT id_enc, name_enc, role, approval_status, department, position, hire_date, resign_date FROM users_secure ORDER BY role, id_lookup").fetchall()
    users = []
    year = date.today().year
    for row in rows:
        user = public_user(row)
        try:
            summary = leave_summary(conn, user, year)
        except Exception:
            summary = {"totalDays": 0, "remainingDays": 0}
        user["leaveTotalDays"] = summary.get("totalDays", 0)
        user["leaveRemainingDays"] = summary.get("remainingDays", 0)
        users.append(user)
    return users


def get_user_directory(conn):
    rows = conn.execute("SELECT id_enc, name_enc, role, approval_status, department, position, hire_date, resign_date FROM users_secure ORDER BY role, id_lookup").fetchall()
    return [public_user(row) for row in rows]


def get_departments(conn):
    rows = conn.execute(
        """
        SELECT d.id, d.name, d.color, d.created_at, COUNT(u.id_lookup) AS user_count
        FROM departments d
        LEFT JOIN users_secure u ON u.department = d.name
        GROUP BY d.id, d.name, d.color, d.created_at
        ORDER BY d.id
        """
    ).fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "color": row["color"] or "#d9eadf",
            "createdAt": row["created_at"],
            "userCount": row["user_count"],
        }
        for row in rows
    ]


def normalize_department_color(value):
    color = str(value or "").strip()
    if not color:
        return "#d9eadf"
    if not re.match(r"^#[0-9a-fA-F]{6}$", color):
        raise ValueError("Invalid department color.")
    return color.lower()


def create_department(conn, name, color="#d9eadf"):
    department = str(name or "").strip()[:40]
    department_color = normalize_department_color(color)
    if not department:
        raise ValueError("Department name is required.")
    conn.execute("INSERT OR IGNORE INTO departments (name, color) VALUES (?, ?)", (department, department_color))


def update_department(conn, department_id, name, color="#d9eadf"):
    department = str(name or "").strip()[:40]
    department_color = normalize_department_color(color)
    if not department:
        raise ValueError("Department name is required.")
    row = conn.execute("SELECT id, name FROM departments WHERE id = ?", (int(department_id),)).fetchone()
    if not row:
        raise ValueError("Department not found.")
    if conn.execute("SELECT 1 FROM departments WHERE name = ? AND id != ?", (department, int(department_id))).fetchone():
        raise ValueError("Department name already exists.")
    old_name = row["name"]
    conn.execute("UPDATE departments SET name = ?, color = ? WHERE id = ?", (department, department_color, int(department_id)))
    conn.execute("UPDATE users_secure SET department = ? WHERE department = ?", (department, old_name))


def delete_department(conn, department_id):
    row = conn.execute(
        """
        SELECT d.id, d.name, COUNT(u.id_lookup) AS user_count
        FROM departments d
        LEFT JOIN users_secure u ON u.department = d.name
        WHERE d.id = ?
        GROUP BY d.id, d.name
        """,
        (int(department_id),),
    ).fetchone()
    if not row:
        raise ValueError("Department not found.")
    if int(row["user_count"] or 0) > 0:
        raise ValueError("Department has assigned members.")
    conn.execute("DELETE FROM departments WHERE id = ?", (int(department_id),))


def company_holidays(conn, year=None):
    params = []
    where = ""
    if year:
        where = "WHERE substr(date, 1, 4) = ?"
        params.append(str(year))
    rows = conn.execute(
        f"SELECT id, date, title, kind, created_at FROM company_holidays {where} ORDER BY date DESC, id DESC",
        params,
    ).fetchall()
    return [dict(row) for row in rows]


def normalize_holiday_kind(value):
    kind = str(value or "회사휴일").strip()
    allowed = {"회사휴일", "대체공휴일", "국가공휴일"}
    if kind not in allowed:
        raise ValueError("Invalid holiday kind.")
    return kind


def create_company_holiday(conn, payload, user):
    holiday_date = str(payload.get("date") or "").strip()
    title = str(payload.get("title") or "").strip()[:80]
    kind = normalize_holiday_kind(payload.get("kind"))
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", holiday_date):
        raise ValueError("Invalid holiday date.")
    if not title:
        raise ValueError("Holiday title is required.")
    conn.execute(
        "INSERT OR IGNORE INTO company_holidays (date, title, kind, created_by_enc) VALUES (?, ?, ?, ?)",
        (holiday_date, title, kind, encrypt_text(user.get("id", ""))),
    )


def update_company_holiday(conn, holiday_id, payload):
    holiday_date = str(payload.get("date") or "").strip()
    title = str(payload.get("title") or "").strip()[:80]
    kind = normalize_holiday_kind(payload.get("kind"))
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", holiday_date):
        raise ValueError("Invalid holiday date.")
    if not title:
        raise ValueError("Holiday title is required.")
    try:
        target_id = int(holiday_id)
    except (TypeError, ValueError):
        raise ValueError("Invalid holiday id.")
    duplicate = conn.execute(
        "SELECT id FROM company_holidays WHERE date = ? AND title = ? AND id != ?",
        (holiday_date, title, target_id),
    ).fetchone()
    if duplicate:
        raise ValueError("Holiday already exists.")
    cursor = conn.execute(
        "UPDATE company_holidays SET date = ?, title = ?, kind = ? WHERE id = ?",
        (holiday_date, title, kind, target_id),
    )
    if cursor.rowcount == 0:
        raise ValueError("Holiday not found.")


def delete_company_holiday(conn, holiday_id):
    try:
        target_id = int(holiday_id)
    except (TypeError, ValueError):
        raise ValueError("Invalid holiday id.")
    cursor = conn.execute("DELETE FROM company_holidays WHERE id = ?", (target_id,))
    if cursor.rowcount == 0:
        raise ValueError("Holiday not found.")


def log_login_attempt(conn, user_id, name, role, result, failure_reason, ip):
    conn.execute(
        """
        INSERT INTO login_logs (user_id_enc, name_enc, role, result, failure_reason, ip, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            encrypt_text(str(user_id or "")),
            encrypt_text(str(name or "")),
            normalize_user_role(role),
            "success" if result == "success" else "failure",
            str(failure_reason or ""),
            str(ip or ""),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()


def login_logs(conn):
    rows = conn.execute(
        """
        SELECT id, user_id_enc, name_enc, role, result, failure_reason, ip, created_at
        FROM login_logs
        ORDER BY created_at DESC, id DESC
        LIMIT 1000
        """
    ).fetchall()
    return [
        {
            "id": row["id"],
            "userId": decrypt_text(row["user_id_enc"]) if row["user_id_enc"] else "",
            "name": decrypt_text(row["name_enc"]) if row["name_enc"] else "",
            "role": row["role"],
            "result": row["result"],
            "failureReason": row["failure_reason"],
            "ip": row["ip"],
            "createdAt": row["created_at"],
        }
        for row in rows
    ]


def leave_year(value=None):
    if value:
        text = str(value)
        if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
            return int(text[:4])
    return date.today().year


def parse_iso_date(value):
    text = str(value or "").strip()[:10]
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", text):
        return None
    try:
        return date.fromisoformat(text)
    except ValueError:
        return None


def full_months_between(start, end):
    months = (end.year - start.year) * 12 + (end.month - start.month)
    if end.day < start.day:
        months -= 1
    return max(0, months)


def calculate_annual_leave_days(user, year=None):
    year = int(year or date.today().year)
    approval = normalize_approval_status(user.get("approvalStatus"), user.get("role", "user"))
    hire_date = parse_iso_date(user.get("hireDate"))
    resign_date = parse_iso_date(user.get("resignDate"))
    if approval != "활성화":
        return 0.0
    if resign_date and resign_date < date(year, 1, 1):
        return 0.0
    target = date(year, 12, 31)
    today_value = date.today()
    if year == today_value.year:
        target = today_value
    if resign_date and resign_date < target:
        target = resign_date
    if not hire_date or hire_date > target:
        return 0.0
    months = full_months_between(hire_date, target)
    if months < 12:
        return float(min(11, months))
    years = target.year - hire_date.year
    if (target.month, target.day) < (hire_date.month, hire_date.day):
        years -= 1
    years = max(1, years)
    extra = (years - 1) // 2 if years >= 3 else 0
    return float(min(25, 15 + extra))


def parse_leave_days(value):
    if value is None or value == "":
        return None
    try:
        days = float(value)
    except (TypeError, ValueError):
        return None
    return max(0.0, round(days * 2) / 2)


def approved_leave_used_days(conn, user, year=None):
    year = int(year or date.today().year)
    row = conn.execute(
        """
        SELECT COALESCE(SUM(days), 0) AS used_days
        FROM leave_requests
        WHERE user_id_lookup = ? AND year = ? AND status = 'approved'
        """,
        (id_lookup(user.get("id", "")), year),
    ).fetchone()
    return float(row["used_days"] or 0)


def approved_leave_used_days_by_lookup(conn, lookup, year=None):
    year = int(year or date.today().year)
    row = conn.execute(
        """
        SELECT COALESCE(SUM(days), 0) AS used_days
        FROM leave_requests
        WHERE user_id_lookup = ? AND year = ? AND status = 'approved'
        """,
        (lookup, year),
    ).fetchone()
    return float(row["used_days"] or 0)


def sync_leave_remaining_days(conn, lookup, year=None):
    year = int(year or date.today().year)
    balance = conn.execute(
        "SELECT total_days FROM leave_balances WHERE user_id_lookup = ? AND year = ?",
        (lookup, year),
    ).fetchone()
    if not balance:
        return
    total = float(balance["total_days"] or 0)
    used = approved_leave_used_days_by_lookup(conn, lookup, year)
    conn.execute(
        """
        UPDATE leave_balances
        SET remaining_days = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE user_id_lookup = ? AND year = ?
        """,
        (max(0, total - used), lookup, year),
    )


def set_leave_balance(conn, user, year=None, total_days=None, remaining_days=None):
    year = int(year or date.today().year)
    total = parse_leave_days(total_days)
    remaining = parse_leave_days(remaining_days)
    if total is None:
        total = calculate_annual_leave_days(user, year)
    lookup = id_lookup(user.get("id", ""))
    conn.execute(
        """
        INSERT INTO leave_balances (user_id_lookup, user_id_enc, user_name_enc, year, total_days, remaining_days)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(user_id_lookup, year) DO UPDATE SET
          user_id_enc = excluded.user_id_enc,
          user_name_enc = excluded.user_name_enc,
          total_days = excluded.total_days,
          remaining_days = excluded.remaining_days,
          updated_at = CURRENT_TIMESTAMP
        """,
        (lookup, encrypt_text(user.get("id", "")), encrypt_text(user.get("name", "")), year, float(total), remaining),
    )

def leave_status_label(status):
    if status in ("approved", "승인"):
        return "승인"
    if status in ("rejected", "반려"):
        return "반려"
    return "대기"


def leave_status_code(status):
    if status in ("approved", "승인"):
        return "approved"
    if status in ("rejected", "반려"):
        return "rejected"
    return "pending"


def ensure_leave_balance(conn, user, year=None):
    year = int(year or date.today().year)
    lookup = id_lookup(user.get("id", ""))
    existing = conn.execute(
        "SELECT * FROM leave_balances WHERE user_id_lookup = ? AND year = ?",
        (lookup, year),
    ).fetchone()
    if existing:
        return existing
    conn.execute(
        """
        INSERT INTO leave_balances (user_id_lookup, user_id_enc, user_name_enc, year, total_days, remaining_days)
        VALUES (?, ?, ?, ?, ?, NULL)
        """,
        (lookup, encrypt_text(user.get("id", "")), encrypt_text(user.get("name", "")), year, calculate_annual_leave_days(user, year)),
    )
    return conn.execute(
        "SELECT * FROM leave_balances WHERE user_id_lookup = ? AND year = ?",
        (lookup, year),
    ).fetchone()


def leave_summary(conn, user, year=None):
    year = int(year or date.today().year)
    balance = ensure_leave_balance(conn, user, year)
    total = float(balance["total_days"] or 0)
    used = approved_leave_used_days(conn, user, year)
    remaining = balance["remaining_days"] if "remaining_days" in balance.keys() else None
    remaining = float(remaining) if remaining is not None else max(0, total - used)
    return {
        "year": year,
        "totalDays": total,
        "usedDays": used,
        "remainingDays": max(0, remaining),
    }


def leave_request_payload(row):
    return {
        "id": row["id"],
        "userId": decrypt_text(row["user_id_enc"]) if row["user_id_enc"] else "",
        "userName": decrypt_text(row["user_name_enc"]) if row["user_name_enc"] else "",
        "department": row["department"] if "department" in row.keys() else "",
        "year": row["year"],
        "startDate": row["start_date"],
        "endDate": row["end_date"],
        "days": float(row["days"] or 0),
        "type": row["leave_type"],
        "reason": decrypt_text(row["reason_enc"]) if row["reason_enc"] else "",
        "status": leave_status_label(row["status"]),
        "statusCode": row["status"],
        "approvedBy": decrypt_text(row["approved_by_enc"]) if row["approved_by_enc"] else "",
        "approvedAt": row["approved_at"] if "approved_at" in row.keys() else "",
        "createdAt": row["created_at"],
        "updatedAt": row["updated_at"],
    }


def user_leave_requests(conn, user, year=None):
    year = int(year or date.today().year)
    ensure_leave_balance(conn, user, year)
    rows = conn.execute(
        """
        SELECT l.*, COALESCE(u.department, '') AS department
        FROM leave_requests l
        LEFT JOIN users_secure u ON u.id_lookup = l.user_id_lookup
        WHERE l.user_id_lookup = ? AND l.year = ?
        ORDER BY start_date DESC, id DESC
        """,
        (id_lookup(user.get("id", "")), year),
    ).fetchall()
    return [leave_request_payload(row) for row in rows]


def leave_approvals(conn, year=None):
    params = []
    where = ""
    if year:
        where = "WHERE l.year = ?"
        params.append(int(year))
    rows = conn.execute(
        f"""
        SELECT l.*, COALESCE(u.department, '') AS department
        FROM leave_requests l
        LEFT JOIN users_secure u ON u.id_lookup = l.user_id_lookup
        {where}
        ORDER BY
          CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
          start_date DESC,
          id DESC
        """,
        params,
    ).fetchall()
    return [leave_request_payload(row) for row in rows]


def approved_leave_calendar(conn, year=None):
    params = []
    where = "WHERE l.status = 'approved'"
    if year:
        where += " AND l.year = ?"
        params.append(int(year))
    rows = conn.execute(
        f"""
        SELECT l.*, COALESCE(u.department, '') AS department
        FROM leave_requests l
        LEFT JOIN users_secure u ON u.id_lookup = l.user_id_lookup
        {where}
        ORDER BY start_date DESC, id DESC
        """,
        params,
    ).fetchall()
    return [leave_request_payload(row) for row in rows]


def target_leave_user(conn, user, payload):
    if is_admin(user):
        target_id = str(payload.get("userId") or payload.get("targetUserId") or "").strip()
        if target_id:
            row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(target_id),)).fetchone()
            if not row:
                raise ValueError("Leave target user not found.")
            return public_user(row)
    return user


def create_leave_request(conn, user, payload):
    target_user = target_leave_user(conn, user, payload)
    start_date, end_date, leave_type, reason, days = validate_leave_payload(payload)
    year = leave_year(start_date)
    ensure_leave_balance(conn, target_user, year)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    auto_approve = bool(payload.get("autoApprove")) and is_admin(user)
    status = "approved" if auto_approve else "pending"
    approved_by = encrypt_text(user.get("id", "")) if auto_approve else ""
    approved_at = now if auto_approve else ""
    conn.execute(
        """
        INSERT INTO leave_requests
          (user_id_lookup, user_id_enc, user_name_enc, year, start_date, end_date, days, leave_type, reason_enc, status, approved_by_enc, approved_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            id_lookup(target_user.get("id", "")),
            encrypt_text(target_user.get("id", "")),
            encrypt_text(target_user.get("name", "")),
            year,
            start_date,
            end_date,
            days,
            leave_type,
            encrypt_text(reason),
            status,
            approved_by,
            approved_at,
            now,
            now,
        ),
    )
    if status == "approved":
        sync_leave_remaining_days(conn, id_lookup(target_user.get("id", "")), year)


def validate_leave_payload(payload):
    start_date = str(payload.get("startDate") or "").strip()
    end_date = str(payload.get("endDate") or start_date).strip()
    leave_type = str(payload.get("type") or "연차").strip()[:40]
    reason = str(payload.get("reason") or "").strip()[:120]
    try:
        days = float(payload.get("days") or 0)
    except (TypeError, ValueError):
        raise ValueError("Invalid leave days.")
    if not re.match(r"^\d{4}-\d{2}-\d{2}$", start_date) or not re.match(r"^\d{4}-\d{2}-\d{2}$", end_date):
        raise ValueError("Invalid leave date.")
    if days <= 0 or days > 30:
        raise ValueError("Invalid leave days.")
    cursor = date.fromisoformat(start_date)
    last = date.fromisoformat(end_date)
    while cursor <= last:
        if cursor.weekday() >= 5:
            raise ValueError("Weekend leave dates are not allowed.")
        cursor += timedelta(days=1)
    return start_date, end_date, leave_type, reason, days


def update_leave_request(conn, request_id, user, payload):
    if not is_admin(user):
        raise PermissionError("Admin login required.")
    row = conn.execute("SELECT * FROM leave_requests WHERE id = ?", (int(request_id),)).fetchone()
    if not row:
        raise ValueError("Leave request not found.")
    previous_lookup = row["user_id_lookup"]
    previous_year = int(row["year"])
    target_user = target_leave_user(conn, user, payload)
    start_date, end_date, leave_type, reason, days = validate_leave_payload(payload)
    year = leave_year(start_date)
    ensure_leave_balance(conn, target_user, year)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute(
        """
        UPDATE leave_requests
        SET user_id_lookup = ?,
            user_id_enc = ?,
            user_name_enc = ?,
            year = ?,
            start_date = ?,
            end_date = ?,
            days = ?,
            leave_type = ?,
            reason_enc = ?,
            status = ?,
            approved_by_enc = ?,
            approved_at = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            id_lookup(target_user.get("id", "")),
            encrypt_text(target_user.get("id", "")),
            encrypt_text(target_user.get("name", "")),
            year,
            start_date,
            end_date,
            days,
            leave_type,
            encrypt_text(reason),
            "approved",
            encrypt_text(user.get("id", "")),
            now,
            now,
            int(request_id),
        ),
    )
    sync_leave_remaining_days(conn, previous_lookup, previous_year)
    sync_leave_remaining_days(conn, id_lookup(target_user.get("id", "")), year)


def delete_leave_request(conn, request_id):
    row = conn.execute("SELECT id, user_id_lookup, year FROM leave_requests WHERE id = ?", (int(request_id),)).fetchone()
    if not row:
        raise ValueError("Leave request not found.")
    conn.execute("DELETE FROM leave_requests WHERE id = ?", (int(request_id),))
    sync_leave_remaining_days(conn, row["user_id_lookup"], int(row["year"]))


def update_leave_status(conn, request_id, status, approver):
    status_code = leave_status_code(status)
    if status_code == "pending":
        raise ValueError("Invalid leave approval status.")
    row = conn.execute("SELECT * FROM leave_requests WHERE id = ?", (int(request_id),)).fetchone()
    if not row:
        raise ValueError("Leave request not found.")
    conn.execute(
        """
        UPDATE leave_requests
        SET status = ?,
            approved_by_enc = ?,
            approved_at = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            status_code,
            encrypt_text(approver.get("id", "")),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            int(request_id),
        ),
    )
    sync_leave_remaining_days(conn, row["user_id_lookup"], int(row["year"]))


def project_logs(conn, page=1, page_size=10):
    page = max(1, int(page or 1))
    page_size = max(1, min(100, int(page_size or 10)))
    offset = (page - 1) * page_size
    total = conn.execute("SELECT COUNT(*) AS count FROM project_logs").fetchone()["count"]
    rows = conn.execute(
        """
        SELECT id, user_id_enc, name_enc, role, action, category, project_no,
               project_name_enc, target, summary_enc, created_at
        FROM project_logs
        ORDER BY created_at DESC, id DESC
        LIMIT ? OFFSET ?
        """,
        (page_size, offset),
    ).fetchall()
    logs = [
        {
            "id": row["id"],
            "userId": decrypt_text(row["user_id_enc"]) if row["user_id_enc"] else "",
            "name": decrypt_text(row["name_enc"]) if row["name_enc"] else "",
            "role": row["role"],
            "action": row["action"],
            "category": row["category"],
            "projectNo": row["project_no"],
            "projectName": decrypt_text(row["project_name_enc"]) if row["project_name_enc"] else "",
            "target": row["target"],
            "summary": decrypt_text(row["summary_enc"]) if row["summary_enc"] else "",
            "createdAt": row["created_at"],
        }
        for row in rows
    ]
    total_pages = max(1, (total + page_size - 1) // page_size) if total else 1
    return {
        "logs": logs,
        "total": total,
        "page": page,
        "pageSize": page_size,
        "totalPages": total_pages,
    }


def clear_project_logs(conn):
    conn.execute("DELETE FROM project_logs")
    conn.commit()


def log_project_actions(conn, user, entries):
    if not user or not entries:
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_id = str(user.get("id") or "")
    name = str(user.get("name") or "")
    role = normalize_user_role(user.get("role"))
    for entry in entries:
        action = str(entry.get("action") or "?섏젙").strip() or "?섏젙"
        category = str(entry.get("category") or "?꾨줈?앺듃").strip() or "?꾨줈?앺듃"
        project_no = str(entry.get("projectNo") or "").strip()
        project_name = str(entry.get("projectName") or "").strip()
        target = str(entry.get("target") or "").strip()
        summary = str(entry.get("summary") or "").strip()
        conn.execute(
            """
            INSERT INTO project_logs
              (user_id_enc, name_enc, role, action, category, project_no, project_name_enc, target, summary_enc, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                encrypt_text(user_id),
                encrypt_text(name),
                role,
                action,
                category,
                project_no,
                encrypt_text(project_name),
                target,
                encrypt_text(summary),
                now,
            ),
        )
    conn.commit()



def project_identity(project):
    return str(project.get("id") or project.get("projectNo") or project.get("no") or "").strip()


def next_project_no(projects):
    used = {str(project.get("projectNo") or "").strip() for project in projects if isinstance(project, dict)}
    number = 0
    while f"{number:05d}" in used:
        number += 1
    return f"{number:05d}"


def ensure_project_no(project, existing_projects):
    if isinstance(project, dict) and not str(project.get("projectNo") or "").strip():
        project["projectNo"] = next_project_no(existing_projects)
    return project


def project_log_entry(action, category, project, target="", summary=""):
    return {
        "action": action,
        "category": category,
        "projectNo": str(project.get("projectNo") or project.get("no") or "")[:80],
        "projectName": str(project.get("name") or "")[:200],
        "target": str(target or "")[:120],
        "summary": str(summary or "")[:500],
    }


def scalar_change_summary(field, before, after):
    before_text = str(before or "").strip()
    after_text = str(after or "").strip()
    if field == "depositDate":
        if before_text and not after_text:
            return "\uc644\ub8cc\uc77c\uc790 \uc0ad\uc81c"
        if not before_text and after_text:
            return "\uc644\ub8cc\uc77c\uc790 \ub4f1\ub85d"
        return "\uc644\ub8cc\uc77c\uc790 \uc218\uc815"
    if field in ("milestone", "adminMilestone"):
        return f"\ub9c8\uc77c\uc2a4\ud1a4 \ubcc0\uacbd: {before_text or '-'} -> {after_text or '-'}"
    if field in ("status", "progressStatus"):
        return f"\uc791\uc5c5\uc0c1\ud0dc \ubcc0\uacbd: {before_text or '-'} -> {after_text or '-'}"
    if field == "hasIssue":
        return "\uc774\uc288 \ub4f1\ub85d" if bool(after) else "\uc774\uc288 \ud574\uc81c"
    return f"{field} \ubcc0\uacbd"


def issue_signature(issue):
    return json.dumps({
        "memo": issue.get("memo") or issue.get("text") or "",
        "status": issue.get("status") or "",
        "type": issue.get("type") or "",
        "resolved": bool(issue.get("resolved") or issue.get("completed")),
        "visibility": normalize_issue_visibility(issue.get("visibility")),
    }, ensure_ascii=False, sort_keys=True)


def issue_log_summary(previous, current, action):
    before_memo = str((previous or {}).get("memo") or (previous or {}).get("text") or "").strip()
    after_memo = str((current or {}).get("memo") or (current or {}).get("text") or "").strip()
    if action == "등록":
        return "이슈 내용 등록" if after_memo else "이슈 등록"
    if action == "삭제":
        return "이슈 내용 삭제" if before_memo else "이슈 삭제"
    before_status = str((previous or {}).get("status") or "").strip()
    after_status = str((current or {}).get("status") or "").strip()
    if before_status != after_status:
        return "이슈 상태 변경"
    before_type = str((previous or {}).get("type") or "").strip()
    after_type = str((current or {}).get("type") or "").strip()
    if before_type != after_type:
        return "이슈 유형 변경"
    if normalize_issue_visibility((previous or {}).get("visibility")) != normalize_issue_visibility((current or {}).get("visibility")):
        return "이슈 노출 여부 변경"
    before_resolved = bool((previous or {}).get("resolved") or (previous or {}).get("completed"))
    after_resolved = bool((current or {}).get("resolved") or (current or {}).get("completed"))
    if before_resolved != after_resolved:
        return "이슈 상태 변경"
    if before_memo and not after_memo:
        return "이슈 내용 삭제"
    if not before_memo and after_memo:
        return "이슈 내용 등록"
    if before_memo != after_memo:
        return "이슈 내용 수정"
    return "이슈 수정"


def schedule_signature(entry):
    return json.dumps({
        "date": entry.get("date") or "",
        "milestone": entry.get("milestone") or "",
        "detail": entry.get("detail") or "",
        "staffRole": entry.get("staffRole") or "",
        "staffName": entry.get("staffName") or "",
        "completed": bool(entry.get("completed")),
    }, ensure_ascii=False, sort_keys=True)


def schedule_target(entry):
    parts = [str(entry.get(key) or "") for key in ("date", "milestone", "detail") if entry.get(key)]
    return " \u00b7 ".join(parts) or "\uc77c\uc815"


def build_project_logs_from_diff(before_projects, after_projects):
    logs = []
    before_map = {project_identity(project): project for project in before_projects if isinstance(project, dict) and project_identity(project)}
    after_map = {project_identity(project): project for project in after_projects if isinstance(project, dict) and project_identity(project)}
    for key, project in before_map.items():
        if key not in after_map:
            logs.append(project_log_entry("\uc0ad\uc81c", "\ud504\ub85c\uc81d\ud2b8", project, summary="\ud504\ub85c\uc81d\ud2b8 \uc0ad\uc81c"))
    for key, project in after_map.items():
        previous = before_map.get(key)
        if not previous:
            logs.append(project_log_entry("\ub4f1\ub85d", "\ud504\ub85c\uc81d\ud2b8", project, summary="\ud504\ub85c\uc81d\ud2b8 \ub4f1\ub85d"))
            continue
        for field in ("depositDate", "milestone", "adminMilestone", "status", "progressStatus", "hasIssue"):
            if previous.get(field) != project.get(field):
                logs.append(project_log_entry("\uc218\uc815", "\ud504\ub85c\uc81d\ud2b8", project, target=field, summary=scalar_change_summary(field, previous.get(field), project.get(field))))
        before_issues = {str(issue.get("id") or index): issue for index, issue in enumerate(previous.get("issues") or []) if isinstance(issue, dict)}
        after_issues = {str(issue.get("id") or index): issue for index, issue in enumerate(project.get("issues") or []) if isinstance(issue, dict)}
        for issue_id, issue in before_issues.items():
            if issue_id not in after_issues:
                logs.append(project_log_entry("\uc0ad\uc81c", "\uc774\uc288", project, target="\uc774\uc288", summary=issue_log_summary(issue, None, "삭제")))
        for issue_id, issue in after_issues.items():
            old = before_issues.get(issue_id)
            if not old:
                logs.append(project_log_entry("\ub4f1\ub85d", "\uc774\uc288", project, target="\uc774\uc288", summary=issue_log_summary(None, issue, "등록")))
            elif issue_signature(old) != issue_signature(issue):
                logs.append(project_log_entry("\uc218\uc815", "\uc774\uc288", project, target="\uc774\uc288", summary=issue_log_summary(old, issue, "수정")))
        before_schedules = {str(entry.get("id") or index): entry for index, entry in enumerate(previous.get("schedules") or []) if isinstance(entry, dict)}
        after_schedules = {str(entry.get("id") or index): entry for index, entry in enumerate(project.get("schedules") or []) if isinstance(entry, dict)}
        for entry_id, entry in before_schedules.items():
            if entry_id not in after_schedules:
                logs.append(project_log_entry("\uc0ad\uc81c", "\uc77c\uc815", project, target=schedule_target(entry), summary="\uc77c\uc815 \uc0ad\uc81c"))
        for entry_id, entry in after_schedules.items():
            old = before_schedules.get(entry_id)
            if not old:
                logs.append(project_log_entry("\ub4f1\ub85d", "\uc77c\uc815", project, target=schedule_target(entry), summary="\uc77c\uc815 \ub4f1\ub85d"))
            elif schedule_signature(old) != schedule_signature(entry):
                summary = "\uc77c\uc815 \uc644\ub8cc" if bool(entry.get("completed")) and not bool(old.get("completed")) else "\uc77c\uc815 \uc218\uc815"
                logs.append(project_log_entry("\uc218\uc815", "\uc77c\uc815", project, target=schedule_target(entry), summary=summary))
    return logs[:200]


def user_can_complete_project_schedule(user):
    return is_admin(user) or user_in_department(user, "pm")


def user_can_edit_schedule_note(user):
    return is_admin(user) or user_in_department(user, "pm")


def sanitize_schedule_entry_for_user(existing_entry, incoming_entry, user):
    item = dict(incoming_entry)
    existing = existing_entry if isinstance(existing_entry, dict) else {}
    was_completed = bool(existing.get("completed"))
    if user_can_complete_project_schedule(user):
        completed = bool(item.get("completed"))
    else:
        completed = bool(existing.get("completed"))
    if was_completed:
        locked = dict(existing)
        locked["completed"] = completed
        history = item.get("history") if isinstance(item.get("history"), list) else existing.get("history")
        locked["history"] = history if isinstance(history, list) else []
        return locked
    item["completed"] = completed
    if user_can_edit_schedule_note(user):
        item["note"] = str(item.get("note") or "")
    else:
        item["note"] = str(existing.get("note") or "")
    history = item.get("history") if isinstance(item.get("history"), list) else existing.get("history")
    item["history"] = history if isinstance(history, list) else []
    return item


def schedule_owned_by_user(entry, user):
    if not isinstance(entry, dict) or not user:
        return False
    values = user_match_values(user)
    owner_id = str(entry.get("createdById") or "").strip().lower()
    owner_name = str(entry.get("createdByName") or "").strip().lower()
    staff_name = str(entry.get("staffName") or entry.get("staff") or "").strip().lower()
    return bool((owner_id and owner_id in values) or (owner_name and owner_name in values) or (not owner_id and staff_name in values))


def merge_schedule_entries_for_user(existing_project, incoming_project, user):
    if is_admin(user):
        existing_by_id = {str(entry.get("id") or "").strip(): entry for entry in existing_project.get("schedules") or [] if isinstance(entry, dict)}
        return [sanitize_schedule_entry_for_user(existing_by_id.get(str(entry.get("id") or "").strip()), entry, user) for entry in incoming_project.get("schedules") or [] if isinstance(entry, dict)]
    if not (user_in_department(user, "pm") or user_assigned_to_project(user, existing_project)):
        return existing_project.get("schedules") or []

    existing_entries = existing_project.get("schedules") or []
    incoming_entries = incoming_project.get("schedules") or []
    incoming_by_id = {
        str(entry.get("id")): entry
        for entry in incoming_entries
        if isinstance(entry, dict) and str(entry.get("id") or "").strip()
    }
    merged = []
    used = set()
    for entry in existing_entries:
        entry_id = str(entry.get("id") or "").strip() if isinstance(entry, dict) else ""
        if entry_id and entry_id in incoming_by_id:
            candidate = incoming_by_id[entry_id]
            can_update = user_in_department(user, "pm") or schedule_owned_by_user(candidate, user)
            merged.append(sanitize_schedule_entry_for_user(entry, candidate, user) if can_update else entry)
            used.add(entry_id)
        else:
            merged.append(entry)
    for entry in incoming_entries:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id") or "").strip()
        if entry_id and entry_id in used:
            continue
        if user_in_department(user, "pm") or schedule_owned_by_user(entry, user):
            merged.append(sanitize_schedule_entry_for_user({}, entry, user))
    return merged

def user_can_edit_project_activity(user):
    return user_can_edit_projects(user) or user_in_department(user, "영업")


def user_can_edit_project_issues(user):
    return is_admin(user) or user_in_department(user, "영업", "pm", "디자인", "디자이너", "퍼블리싱", "퍼블리셔", "프로그램", "프로그래머")


def user_can_edit_project_communications(user):
    return is_admin(user) or user_in_department(user, "영업", "pm")


def user_can_manage_project_quote(user):
    return is_admin(user) or user_in_department(user, "영업", "경영관리")


def normalize_issue_visibility(value):
    return "private" if str(value or "").strip() == "private" else "visible"


def user_can_view_private_issues(user):
    return is_admin(user) or is_team_lead(user) or user_in_department(user, "영업", "pm")


def entry_owned_by_user(entry, user):
    if not isinstance(entry, dict) or not user:
        return False
    values = user_match_values(user)
    owner_id = str(entry.get("createdById") or "").strip().lower()
    owner_name = str(entry.get("createdByName") or "").strip().lower()
    return bool((owner_id and owner_id in values) or (not owner_id and owner_name and owner_name in values))


def merge_entries_without_delete(existing_entries, incoming_entries, user=None, owner_only=False):
    incoming_by_id = {
        str(entry.get("id")): entry
        for entry in (incoming_entries or [])
        if isinstance(entry, dict) and str(entry.get("id") or "").strip()
    }
    merged = []
    used = set()
    for entry in existing_entries or []:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id") or "").strip()
        if entry_id and entry_id in incoming_by_id:
            candidate = incoming_by_id[entry_id]
            merged.append(candidate if not owner_only or entry_owned_by_user(entry, user) else entry)
            used.add(entry_id)
        else:
            merged.append(entry)
    for entry in incoming_entries or []:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id") or "").strip()
        if entry_id and entry_id in used:
            continue
        if owner_only and not entry_owned_by_user(entry, user):
            continue
        merged.append(entry)
    return merged


def merge_issue_entries_without_delete(existing_entries, incoming_entries, user=None):
    merged = merge_entries_without_delete(existing_entries, incoming_entries, user, True)
    existing_by_id = {
        str(entry.get("id") or "").strip(): entry
        for entry in existing_entries or []
        if isinstance(entry, dict) and str(entry.get("id") or "").strip()
    }
    can_manage_visibility = user_can_view_private_issues(user)
    sanitized = []
    for entry in merged:
        item = dict(entry)
        entry_id = str(item.get("id") or "").strip()
        if can_manage_visibility:
            item["visibility"] = normalize_issue_visibility(item.get("visibility"))
        elif entry_id and entry_id in existing_by_id:
            item["visibility"] = normalize_issue_visibility(existing_by_id[entry_id].get("visibility"))
        else:
            item["visibility"] = "visible"
        sanitized.append(item)
    return sanitized


def protect_admin_only_activity_fields(existing_project, incoming_project, user):
    item = dict(incoming_project)
    if not is_admin(user):
        item["issues"] = merge_issue_entries_without_delete(existing_project.get("issues") or [], incoming_project.get("issues") or [], user) if user_can_edit_project_issues(user) else existing_project.get("issues") or []
        item["communications"] = merge_entries_without_delete(existing_project.get("communications") or [], incoming_project.get("communications") or [], user, True) if user_can_edit_project_communications(user) else existing_project.get("communications") or []
        item["schedules"] = merge_schedule_entries_for_user(existing_project, incoming_project, user)
    return item


def merge_project_activity_fields(existing_project, incoming_project, user):
    item = dict(existing_project)
    if user_can_edit_project_activity(user):
        item["clientContacts"] = incoming_project.get("clientContacts") or []
    if user_can_edit_project_issues(user):
        item["issues"] = (incoming_project.get("issues") or []) if is_admin(user) else merge_issue_entries_without_delete(existing_project.get("issues") or [], incoming_project.get("issues") or [], user)
    if user_can_edit_project_communications(user):
        item["communications"] = (incoming_project.get("communications") or []) if is_admin(user) else merge_entries_without_delete(existing_project.get("communications") or [], incoming_project.get("communications") or [], user, True)
    if user_can_manage_project_quote(user):
        item["quoteFileName"] = incoming_project.get("quoteFileName") or ""
        item["quoteFileData"] = incoming_project.get("quoteFileData") or ""
    return item


def merge_projects_for_user(existing_projects, incoming_projects, user):
    normalized_incoming = []
    number_source = list(existing_projects)
    for project in incoming_projects:
        if isinstance(project, dict):
            project = dict(project)
            project = ensure_project_no(project, number_source)
            number_source.append(project)
        normalized_incoming.append(project)
    incoming_projects = normalized_incoming
    if is_admin(user):
        return incoming_projects
    incoming_by_id = {project_identity(project): project for project in incoming_projects if isinstance(project, dict) and project_identity(project)}
    merged = []
    used = set()
    for project in existing_projects:
        key = project_identity(project)
        can_edit_project = user_in_department(user, "pm") or user_can_access_project(user, project) or user_can_edit_project_activity(user) or user_can_edit_project_issues(user) or user_can_edit_project_communications(user) or user_can_manage_project_quote(user)
        if key in incoming_by_id and can_edit_project:
            candidate = incoming_by_id[key]
            if user_can_edit_projects(user):
                merged.append(protect_admin_only_activity_fields(project, candidate, user) if (user_in_department(user, "pm") or user_can_access_project(user, candidate)) else project)
            else:
                item = merge_project_activity_fields(project, candidate, user)
                item["schedules"] = merge_schedule_entries_for_user(project, candidate, user)
                merged.append(item)
            used.add(key)
        else:
            merged.append(project)
    for key, project in incoming_by_id.items():
        if key not in used and user_can_create_projects(user):
            merged.append(project)
    return merged


def assignment_fields_for_user(user):
    if is_admin(user):
        return {
            ("pm", "pmId"),
            ("designer", "designerId"),
            ("publisher", "publisherId"),
            ("programmer", "programmerId"),
        }
    if not is_team_lead(user):
        return set()
    if user_in_department(user, "pm"):
        return {("pm", "pmId")}
    if user_in_department(user, "디자인", "디자이너"):
        return {("designer", "designerId")}
    if user_in_department(user, "퍼블리싱", "퍼블리셔"):
        return {("publisher", "publisherId")}
    if user_in_department(user, "프로그램", "프로그래머"):
        return {("programmer", "programmerId")}
    return set()


def project_completion_done(project, *stage_keys):
    completed = set(normalize_completion_flow((project or {}).get("completionFlow")).get("completed", []))
    return all(key in completed for key in stage_keys)


def project_assignment_missing(project, name_key, id_key):
    return not str((project or {}).get(id_key) or (project or {}).get(name_key) or "").strip()


def project_ready_for_assignment_departments(project, departments):
    normalized = {normalize_department_key(department) for department in departments}
    if "pm" in normalized:
        return True
    if "디자인" in normalized:
        return not project_assignment_missing(project, "pm", "pmId")
    if "퍼블리싱" in normalized:
        return project_completion_done(project, "design_worker", "design_lead", "design_pm")
    if "프로그램" in normalized:
        return project_completion_done(project, "publishing_worker", "publishing_lead", "publishing_pm")
    return False


def project_ready_for_assignment_field(project, name_key, id_key):
    if (name_key, id_key) == ("pm", "pmId"):
        return project_ready_for_assignment_departments(project, ("pm",))
    if (name_key, id_key) == ("designer", "designerId"):
        return project_ready_for_assignment_departments(project, ("디자인", "디자이너"))
    if (name_key, id_key) == ("publisher", "publisherId"):
        return project_ready_for_assignment_departments(project, ("퍼블리싱", "퍼블리셔"))
    if (name_key, id_key) == ("programmer", "programmerId"):
        return project_ready_for_assignment_departments(project, ("프로그램", "프로그래머"))
    return False


def merge_project_assignments_for_user(existing_projects, incoming_projects, user):
    allowed_fields = assignment_fields_for_user(user)
    if not allowed_fields:
        return existing_projects
    incoming_by_id = {project_identity(project): project for project in incoming_projects if isinstance(project, dict) and project_identity(project)}
    merged = []
    for project in existing_projects:
        key = project_identity(project)
        candidate = incoming_by_id.get(key)
        if not candidate:
            merged.append(project)
            continue
        item = dict(project)
        for name_key, id_key in allowed_fields:
            if not is_admin(user) and not project_ready_for_assignment_field(project, name_key, id_key):
                continue
            item[name_key] = str(candidate.get(name_key) or "").strip()
            item[id_key] = str(candidate.get(id_key) or "").strip()
            assigned_at_key = f"{name_key}AssignedAt"
            item[assigned_at_key] = str(candidate.get(assigned_at_key) or "").strip()
        merged.append(item)
    return merged


def normalize_completion_flow(flow):
    allowed = {stage["key"] for stage in PROJECT_COMPLETION_STAGES}
    if not isinstance(flow, dict):
        flow = {}
    completed = []
    for key in flow.get("completed") or []:
        if key in allowed and key not in completed:
            completed.append(key)
    history = flow.get("history") if isinstance(flow.get("history"), list) else []
    return {"completed": completed, "history": history, "pendingType": str(flow.get("pendingType") or ""), "hideApproval": bool(flow.get("hideApproval"))}


def project_completion_stage(project):
    flow = normalize_completion_flow((project or {}).get("completionFlow"))
    completed = set(flow["completed"])
    for stage in PROJECT_COMPLETION_STAGES:
        if stage["key"] not in completed:
            return stage
    return None


def last_project_completion_entry(project):
    history = normalize_completion_flow((project or {}).get("completionFlow")).get("history", [])
    return history[-1] if history else None


def user_already_handled_latest_completion(user, project):
    latest = last_project_completion_entry(project)
    return bool(user and latest and str(latest.get("userId") or "") == str(user.get("id") or ""))


def user_can_advance_project_completion(user, project, stage=None):
    if not user or not project:
        return False
    stage = stage or project_completion_stage(project)
    if not stage:
        return False
    if is_admin(user):
        return True
    actor = stage.get("actor")
    if actor == "lead":
        return is_team_lead(user) and user_in_department(user, *stage.get("departments", ()))
    if actor == "pm":
        return user_in_department(user, "pm") and (is_team_lead(user) or project_staff_matches(user, project, stage.get("name_key", "pm"), stage.get("id_key", "pmId")))
    if actor == "worker":
        return project_staff_matches(user, project, stage.get("name_key", ""), stage.get("id_key", ""))
    return False


def normalize_completion_type(value):
    value = str(value or "").strip().lower()
    return value if value in {"design", "publishing", "program"} else ""


def normalize_completion_type_from_stage_key(key):
    key = str(key or "")
    if key.startswith("design_"):
        return "design"
    if key.startswith("publishing_"):
        return "publishing"
    if key.startswith("program_"):
        return "program"
    return ""


def advance_project_completion(project, user, completion_type="", memo=""):
    stage = project_completion_stage(project)
    if not stage:
        raise ValueError('이미 모든 완료 단계가 처리되었습니다.')
    if not user_can_advance_project_completion(user, project, stage):
        raise PermissionError('현재 계정은 이 완료 단계를 처리할 권한이 없습니다.')
    item = dict(project)
    flow = normalize_completion_flow(item.get("completionFlow"))
    completion_type = normalize_completion_type(completion_type)
    memo = str(memo or "").strip()[:200]
    if completion_type:
        flow["pendingType"] = completion_type
    flow["hideApproval"] = bool(is_admin(user) and stage.get("actor") == "worker")
    flow["completed"].append(stage["key"])
    history_stage = stage
    if stage.get("actor") == "worker" and is_team_lead(user):
        completed = set(flow["completed"])
        next_stage = next((candidate for candidate in PROJECT_COMPLETION_STAGES if candidate["key"] not in completed), None)
        current_type = completion_type or normalize_completion_type_from_stage_key(stage.get("key", ""))
        next_type = normalize_completion_type_from_stage_key(next_stage.get("key", "") if next_stage else "")
        if next_stage and next_stage.get("actor") == "lead" and current_type and current_type == next_type:
            flow["completed"].append(next_stage["key"])
            history_stage = next_stage
    flow["history"].append({
        "id": secrets.token_urlsafe(12),
        "stage": history_stage["key"],
        "label": history_stage["label"],
        "userId": str(user.get("id") or ""),
        "userName": str(user.get("name") or ""),
        "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "memo": memo,
        "action": "approve",
        "reason": "",
        "completionType": completion_type,
    })
    item["completionFlow"] = flow
    return item, history_stage


def reject_project_completion(project, user, reason=""):
    stage = project_completion_stage(project)
    if not stage:
        raise ValueError('이미 모든 완료 단계가 처리되었습니다.')
    if stage.get("actor") == "worker":
        raise ValueError('반려할 완료 요청이 없습니다.')
    if not user_can_advance_project_completion(user, project, stage):
        raise PermissionError('현재 계정은 이 완료 단계를 처리할 권한이 없습니다.')
    reason = str(reason or "").strip()
    if not reason:
        raise ValueError('반려 사유를 입력해 주세요.')
    item = dict(project)
    flow = normalize_completion_flow(item.get("completionFlow"))
    if not flow["completed"]:
        raise ValueError('반려할 완료 요청이 없습니다.')
    rejected_type = normalize_completion_type_from_stage_key(stage.get("key", ""))
    rejected_key = flow["completed"][-1]
    while flow["completed"]:
        latest_key = flow["completed"][-1]
        if rejected_type and normalize_completion_type_from_stage_key(latest_key) != rejected_type:
            break
        rejected_key = flow["completed"].pop()
    rejected_stage = next((item for item in PROJECT_COMPLETION_STAGES if item["key"] == rejected_key), stage)
    flow["history"].append({
        "id": secrets.token_urlsafe(12),
        "stage": stage["key"],
        "label": f"{stage.get('label', '완료')} 반려",
        "userId": str(user.get("id") or ""),
        "userName": str(user.get("name") or ""),
        "at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "memo": "",
        "action": "reject",
        "reason": reason,
        "rejectedStage": rejected_key,
    })
    flow["history"] = flow.get("history", [])
    item["completionFlow"] = flow
    return item, rejected_stage


def cleanup_sessions():
    now = time.time()
    expired_tokens = [token for token, session in SESSIONS.items() if session.get("expires_at", 0) <= now]
    for token in expired_tokens:
        SESSIONS.pop(token, None)


def create_session(user):
    cleanup_sessions()
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    SESSIONS[token] = {
        "user": user,
        "expires_at": time.time() + SESSION_TTL_SECONDS,
    }
    return token


def session_from_token(token):
    cleanup_sessions()
    token = str(token or "")
    session = SESSIONS.get(token)
    if not session:
        return None
    if session.get("expires_at", 0) <= time.time():
        SESSIONS.pop(token, None)
        return None
    session["expires_at"] = time.time() + SESSION_TTL_SECONDS
    return session


def auth_token_from_handler(handler):
    auth = handler.headers.get("Authorization") or ""
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return handler.headers.get("X-Session-Token") or ""


def current_session(handler):
    return session_from_token(auth_token_from_handler(handler))


def current_user(handler):
    session = current_session(handler)
    if not session:
        return None
    return session.get("user")

def is_admin(user):
    return bool(user and user.get("role") == "admin")


def is_team_lead(user):
    return bool(user and user.get("role") == "team_lead")


def user_department(user):
    return str((user or {}).get("department") or "").strip().lower()


def normalize_department_key(value):
    department = str(value or "").strip().lower()
    aliases = {
        "디자이너": "디자인",
        "퍼블리셔": "퍼블리싱",
        "프로그래머": "프로그램",
        "개발": "프로그램",
        "개발자": "프로그램",
    }
    return aliases.get(department, department)


def user_in_department(user, *names):
    department = normalize_department_key(user_department(user))
    return department in {normalize_department_key(name) for name in names}


def user_can_view_all_projects(user):
    return is_admin(user) or is_team_lead(user) or user_in_department(user, "경영관리", "영업", "pm")


def user_can_edit_projects(user):
    return is_admin(user) or is_team_lead(user) or user_in_department(user, "pm")


def user_can_create_projects(user):
    return is_admin(user) or user_in_department(user, "영업")


def user_assigned_to_project(user, project):
    if not user or not isinstance(project, dict):
        return False
    if not user_match_values(user):
        return False
    if user_in_department(user, "디자인", "디자이너"):
        return project_staff_matches(user, project, "designer", "designerId")
    if user_in_department(user, "퍼블리싱", "퍼블리셔"):
        return project_staff_matches(user, project, "publisher", "publisherId")
    if user_in_department(user, "프로그램", "프로그래머"):
        return project_staff_matches(user, project, "programmer", "programmerId")
    if user_in_department(user, "pm"):
        return project_staff_matches(user, project, "pm", "pmId")
    return False


def user_match_values(user):
    if not user:
        return set()
    return {str(user.get("id") or "").strip().lower(), str(user.get("name") or "").strip().lower()} - {""}


def project_staff_matches(user, project, name_key, id_key):
    user_id = str(user.get("id") or "").strip().lower()
    user_name = str(user.get("name") or "").strip().lower()
    assigned_id = str(project.get(id_key) or "").strip().lower()
    assigned_name = str(project.get(name_key) or "").strip().lower()
    return bool((user_id and assigned_id == user_id) or (user_name and assigned_name == user_name))


def user_matches_departments(user, departments):
    department = normalize_department_key(user.get("department") if user else "")
    return department in {normalize_department_key(name) for name in departments}


def find_staff_user(users, name, departments):
    value = str(name or "").strip().lower()
    if not value:
        return None
    for user in users:
        if str(user.get("name") or "").strip().lower() == value and user_matches_departments(user, departments):
            return user
    return None


def enrich_project_staff_ids(projects, users):
    enriched = []
    for project in projects:
        if not isinstance(project, dict):
            continue
        item = dict(project)
        for name_key, id_key, departments in PROJECT_STAFF_ASSIGNMENTS:
            assigned_id = str(item.get(id_key) or "").strip()
            staff_name = str(item.get(name_key) or "").strip()
            if assigned_id:
                continue
            staff = find_staff_user(users, staff_name, departments)
            if staff and staff.get("id"):
                item[id_key] = staff["id"]
        enriched.append(item)
    return enriched


def user_can_access_project(user, project):
    if user_can_view_all_projects(user):
        return True
    return user_assigned_to_project(user, project)


def filter_project_issues_for_user(project, user):
    if not isinstance(project, dict) or user_can_view_private_issues(user):
        return project
    item = dict(project)
    item["issues"] = [
        issue
        for issue in (project.get("issues") or [])
        if not isinstance(issue, dict) or normalize_issue_visibility(issue.get("visibility")) != "private"
    ]
    return item


def filter_projects_for_user(projects, user):
    visible_projects = projects if user_can_view_all_projects(user) else [project for project in projects if user_can_access_project(user, project)]
    return [filter_project_issues_for_user(project, user) for project in visible_projects]


def schedule_project_payload(project):
    return {
        "id": project.get("id", ""),
        "projectNo": project.get("projectNo", ""),
        "name": project.get("name", ""),
        "milestone": project.get("milestone", ""),
        "adminMilestone": project.get("adminMilestone", ""),
        "pm": project.get("pm", ""),
        "designer": project.get("designer", ""),
        "publisher": project.get("publisher", ""),
        "programmer": project.get("programmer", ""),
        "schedules": project.get("schedules") or [],
    }


def assignment_project_payload(project):
    return {
        "id": project.get("id", ""),
        "projectNo": project.get("projectNo", ""),
        "name": project.get("name", ""),
        "pm": project.get("pm", ""),
        "pmId": project.get("pmId", ""),
        "pmAssignedAt": project.get("pmAssignedAt", ""),
        "designer": project.get("designer", ""),
        "designerId": project.get("designerId", ""),
        "designerAssignedAt": project.get("designerAssignedAt", ""),
        "publisher": project.get("publisher", ""),
        "publisherId": project.get("publisherId", ""),
        "publisherAssignedAt": project.get("publisherAssignedAt", ""),
        "programmer": project.get("programmer", ""),
        "programmerId": project.get("programmerId", ""),
        "programmerAssignedAt": project.get("programmerAssignedAt", ""),
        "completionFlow": project.get("completionFlow") or {},
    }


def filter_schedule_projects_for_user(projects, user):
    if is_admin(user) or is_team_lead(user):
        return [schedule_project_payload(project) for project in projects]
    return [schedule_project_payload(project) for project in projects if user_can_access_project(user, project)]


def filter_assignment_projects_for_user(projects, user):
    if is_admin(user) or is_team_lead(user):
        return [assignment_project_payload(project) for project in projects]
    return []


def users_for_snapshot(conn, user):
    users = get_users(conn)
    if is_admin(user):
        return users
    if is_team_lead(user):
        department = normalize_department_key(user_department(user))
        return [item for item in users if normalize_department_key(item.get("department", "")) == department]
    return []


def user_payload(user):
    if not user:
        return None
    return {
        "id": user.get("id", ""),
        "name": user.get("name", ""),
        "role": user.get("role", "user"),
        "approvalStatus": user.get("approvalStatus", ""),
        "department": user.get("department", ""),
        "position": user.get("position", ""),
        "hireDate": user.get("hireDate", ""),
        "resignDate": user.get("resignDate", ""),
    }

def is_active_account(row):
    if row["role"] == "admin":
        return True
    approval = str(row["approval_status"] or "")
    normalized = normalize_approval_status(approval, row["role"])
    return approval in ("활성화", "승인") or normalized in ("활성화", "승인")


def clear_session_token(token):
    if token:
        SESSIONS.pop(str(token), None)

def login_access_locked():
    return LOGIN_LOCKED or LOGIN_FAILURE_COUNT >= LOGIN_FAILURE_LIMIT


def record_login_failure():
    global LOGIN_FAILURE_COUNT, LOGIN_LOCKED
    LOGIN_FAILURE_COUNT += 1
    if LOGIN_FAILURE_COUNT >= LOGIN_FAILURE_LIMIT:
        LOGIN_LOCKED = True
        SESSIONS.clear()


def reset_login_failures():
    global LOGIN_FAILURE_COUNT, LOGIN_LOCKED
    LOGIN_FAILURE_COUNT = 0
    LOGIN_LOCKED = False


def records_as_json(conn, table, mode):
    if table == "project_records":
        rows = conn.execute("SELECT data_json FROM project_records WHERE mode = ? ORDER BY project_no, id", (mode,)).fetchall()
    elif table == "admin_project_records":
        rows = conn.execute("SELECT data_json FROM admin_project_records WHERE mode = ? ORDER BY project_no, id", (mode,)).fetchall()
    else:
        raise ValueError("Invalid table.")
    return sorted((json.loads(row["data_json"]) for row in rows), key=project_sort_key)


def app_state_json(conn, key, fallback):
    row = conn.execute("SELECT value FROM app_state WHERE key = ?", (key,)).fetchone()
    if not row:
        return fallback
    try:
        value = json.loads(row["value"] or "")
    except json.JSONDecodeError:
        return fallback
    return value if isinstance(value, type(fallback)) else fallback


def save_app_state_json(conn, key, value):
    conn.execute(
        """
        INSERT INTO app_state (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value = excluded.value
        """,
        (key, json.dumps(value, ensure_ascii=False)),
    )


def project_library_posts(conn):
    posts = app_state_json(conn, "project_library_posts", [])
    return sorted((normalize_project_library_post(post) for post in posts), key=lambda post: post.get("createdAt", ""), reverse=True)


def save_project_library_posts(conn, posts):
    save_app_state_json(conn, "project_library_posts", [normalize_project_library_post(post) for post in posts])


def normalize_project_library_post(post):
    comments = post.get("comments") if isinstance(post, dict) else []
    if not isinstance(comments, list):
        comments = []
    return {
        "id": str((post or {}).get("id") or secrets.token_hex(8)),
        "projectId": str((post or {}).get("projectId") or "").strip(),
        "projectNo": str((post or {}).get("projectNo") or "").strip(),
        "projectName": str((post or {}).get("projectName") or "").strip(),
        "important": bool((post or {}).get("important")),
        "title": str((post or {}).get("title") or "").strip(),
        "url": str((post or {}).get("url") or "").strip(),
        "content": str((post or {}).get("content") or "").strip(),
        "attachments": normalize_project_library_attachments((post or {}).get("attachments")),
        "createdById": str((post or {}).get("createdById") or "").strip(),
        "createdByName": str((post or {}).get("createdByName") or "").strip(),
        "createdAt": str((post or {}).get("createdAt") or "").strip(),
        "updatedAt": str((post or {}).get("updatedAt") or "").strip(),
        "comments": [normalize_project_library_comment(comment) for comment in comments],
    }


def normalize_project_library_comment(comment):
    return {
        "id": str((comment or {}).get("id") or secrets.token_hex(8)),
        "content": str((comment or {}).get("content") or "").strip(),
        "createdById": str((comment or {}).get("createdById") or "").strip(),
        "createdByName": str((comment or {}).get("createdByName") or "").strip(),
        "createdAt": str((comment or {}).get("createdAt") or "").strip(),
    }


def normalize_project_library_attachments(attachments):
    if not isinstance(attachments, list):
        return []
    normalized = []
    for file in attachments[:MAX_LIBRARY_FILES]:
        if not isinstance(file, dict):
            continue
        name = safe_library_file_name(file.get("name"))
        normalized.append({
            "id": str(file.get("id") or secrets.token_hex(8)),
            "name": name,
            "type": str(file.get("type") or "application/octet-stream").strip()[:120],
            "size": int(file.get("size") or 0),
            "dataUrl": str(file.get("dataUrl") or ""),
        })
    return normalized


def safe_library_file_name(name):
    value = str(name or "첨부파일").strip().replace("\\", "_").replace("/", "_")
    value = re.sub(r"[\x00-\x1f\x7f]+", "", value)
    value = re.sub(r"\s+", " ", value).strip(" .")
    return (value or "첨부파일")[:160]


def decode_library_data_url(data_url):
    value = str(data_url or "")
    match = re.match(r"^data:([^;,]+);base64,([A-Za-z0-9+/=\s]+)$", value, re.I)
    if not match:
        raise ValueError("첨부파일 형식이 올바르지 않습니다.")
    mime_type = match.group(1).lower()
    try:
        data = base64.b64decode(re.sub(r"\s+", "", match.group(2)), validate=True)
    except Exception:
        raise ValueError("첨부파일 데이터가 올바르지 않습니다.")
    return mime_type, data


def library_file_extension(file_name):
    return Path(str(file_name or "")).suffix.lower()


def validate_library_file_signature(ext, data):
    if ext == ".pdf":
        if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
            raise ValueError("정상 PDF 파일이 아닙니다.")
        scan = data[: min(len(data), 2 * 1024 * 1024)]
        lowered = scan.lower()
        for marker in PDF_DANGEROUS_MARKERS:
            if marker.lower() in lowered:
                raise ValueError("보안상 위험한 PDF 기능이 포함되어 업로드할 수 없습니다.")
    elif ext in {".jpg", ".jpeg"} and not data.startswith(b"\xff\xd8\xff"):
        raise ValueError("정상 JPG 파일이 아닙니다.")
    elif ext == ".png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("정상 PNG 파일이 아닙니다.")
    elif ext == ".gif" and not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
        raise ValueError("정상 GIF 파일이 아닙니다.")
    elif ext == ".webp" and not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
        raise ValueError("정상 WEBP 파일이 아닙니다.")
    elif ext in {".docx", ".xlsx", ".pptx"} and not data.startswith(b"PK\x03\x04"):
        raise ValueError("정상 Office 문서 파일이 아닙니다.")


def validate_project_library_attachments(attachments):
    if isinstance(attachments, list) and len(attachments) > MAX_LIBRARY_FILES:
        raise ValueError("첨부파일은 최대 3개까지 등록할 수 있습니다.")
    files = normalize_project_library_attachments(attachments)
    for file in files:
        ext = library_file_extension(file["name"])
        if ext in LIBRARY_BLOCKED_EXTENSIONS or ext not in LIBRARY_ALLOWED_EXTENSIONS:
            raise ValueError("허용되지 않는 첨부파일 형식입니다.")
        if file["size"] > MAX_LIBRARY_FILE_BYTES:
            raise ValueError("첨부파일은 1개당 최대 5MB까지 등록할 수 있습니다.")
        if file["size"] <= 0:
            raise ValueError("빈 첨부파일은 등록할 수 없습니다.")
        mime_type, data = decode_library_data_url(file["dataUrl"])
        allowed_mimes = LIBRARY_ALLOWED_EXTENSIONS[ext]
        if mime_type not in allowed_mimes:
            raise ValueError("첨부파일 확장자와 파일 형식이 일치하지 않습니다.")
        if len(data) != file["size"] or len(data) > MAX_LIBRARY_FILE_BYTES:
            raise ValueError("첨부파일 크기가 올바르지 않습니다.")
        validate_library_file_signature(ext, data)
        file["type"] = mime_type
        file["size"] = len(data)
    return files


def validate_project_library_url(url):
    value = str(url or "").strip()
    if not value:
        return ""
    if not re.match(r"^https?://", value, re.I):
        value = f"https://{value}"
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("자료 URL은 http 또는 https 주소만 등록할 수 있습니다.")
    return value[:500]


def project_library_project(conn, mode, payload):
    project_id = str(payload.get("projectId") or "").strip()
    project_no = str(payload.get("projectNo") or "").strip()
    projects = records_as_json(conn, "project_records", mode)
    for project in projects:
        if (project_id and str(project.get("id") or "") == project_id) or (project_no and str(project.get("projectNo") or "") == project_no):
            return project
    raise ValueError("프로젝트를 선택해 주세요.")


def create_project_library_post(conn, mode, user, payload):
    project = project_library_project(conn, mode, payload)
    title = str(payload.get("title") or "").strip()
    content = str(payload.get("content") or "").strip()
    if not title or not content:
        raise ValueError("제목과 내용을 입력해 주세요.")
    attachments = validate_project_library_attachments(payload.get("attachments"))
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    posts = project_library_posts(conn)
    posts.insert(0, {
        "id": secrets.token_hex(12),
        "projectId": str(project.get("id") or ""),
        "projectNo": str(project.get("projectNo") or ""),
        "projectName": str(project.get("name") or ""),
        "important": bool(payload.get("important")),
        "title": title[:120],
        "url": validate_project_library_url(payload.get("url")),
        "content": content[:3000],
        "attachments": attachments,
        "createdById": user.get("id", ""),
        "createdByName": user.get("name", ""),
        "createdAt": now,
        "updatedAt": now,
        "comments": [],
    })
    save_project_library_posts(conn, posts)


def update_project_library_post(conn, mode, post_id, payload):
    project = project_library_project(conn, mode, payload)
    title = str(payload.get("title") or "").strip()
    content = str(payload.get("content") or "").strip()
    if not title or not content:
        raise ValueError("제목과 내용을 입력해 주세요.")
    attachments = validate_project_library_attachments(payload.get("attachments"))
    posts = project_library_posts(conn)
    changed = False
    for post in posts:
        if str(post.get("id") or "") != str(post_id):
            continue
        post.update({
            "projectId": str(project.get("id") or ""),
            "projectNo": str(project.get("projectNo") or ""),
            "projectName": str(project.get("name") or ""),
            "important": bool(payload.get("important")),
            "title": title[:120],
            "url": validate_project_library_url(payload.get("url")),
            "content": content[:3000],
            "attachments": attachments,
            "updatedAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        changed = True
        break
    if not changed:
        raise ValueError("자료를 찾을 수 없습니다.")
    save_project_library_posts(conn, posts)


def delete_project_library_post(conn, post_id):
    posts = project_library_posts(conn)
    next_posts = [post for post in posts if str(post.get("id") or "") != str(post_id)]
    if len(next_posts) == len(posts):
        raise ValueError("자료를 찾을 수 없습니다.")
    save_project_library_posts(conn, next_posts)


def add_project_library_comment(conn, post_id, user, payload):
    content = str(payload.get("content") or "").strip()
    if not content:
        raise ValueError("댓글 내용을 입력해 주세요.")
    posts = project_library_posts(conn)
    changed = False
    for post in posts:
        if str(post.get("id") or "") != str(post_id):
            continue
        comments = post.get("comments")
        if not isinstance(comments, list):
            comments = []
        comments.append({
            "id": secrets.token_hex(12),
            "content": content[:500],
            "createdById": user.get("id", ""),
            "createdByName": user.get("name", ""),
            "createdAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })
        post["comments"] = comments
        post["updatedAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        changed = True
        break
    if not changed:
        raise ValueError("자료를 찾을 수 없습니다.")
    save_project_library_posts(conn, posts)


def update_project_library_comment(conn, post_id, comment_id, payload):
    content = str(payload.get("content") or "").strip()
    if not content:
        raise ValueError("댓글 내용을 입력해 주세요.")
    posts = project_library_posts(conn)
    changed = False
    for post in posts:
        if str(post.get("id") or "") != str(post_id):
            continue
        comments = post.get("comments") if isinstance(post.get("comments"), list) else []
        for comment in comments:
            if str(comment.get("id") or "") != str(comment_id):
                continue
            comment["content"] = content[:500]
            changed = True
            break
        if changed:
            post["comments"] = comments
            post["updatedAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            break
    if not changed:
        raise ValueError("댓글을 찾을 수 없습니다.")
    save_project_library_posts(conn, posts)


def delete_project_library_comment(conn, post_id, comment_id):
    posts = project_library_posts(conn)
    changed = False
    for post in posts:
        if str(post.get("id") or "") != str(post_id):
            continue
        comments = post.get("comments") if isinstance(post.get("comments"), list) else []
        next_comments = [comment for comment in comments if str(comment.get("id") or "") != str(comment_id)]
        if len(next_comments) == len(comments):
            break
        post["comments"] = next_comments
        post["updatedAt"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        changed = True
        break
    if not changed:
        raise ValueError("댓글을 찾을 수 없습니다.")
    save_project_library_posts(conn, posts)


def dataset_snapshot(conn, mode, user=None):
    normalized_mode = normalize_mode(mode)
    if normalized_mode == "public" or not user:
        return {
            "mode": "public",
            "projects": public_sample_projects(),
            "scheduleProjects": [],
            "assignmentProjects": [],
            "adminProjects": [],
            "users": [],
            "projectLibraryPosts": [],
            "loginUser": "",
            "currentUser": None,
        }
    projects = records_as_json(conn, "project_records", normalized_mode)
    return {
        "mode": normalized_mode,
        "projects": filter_projects_for_user(projects, user),
        "scheduleProjects": filter_schedule_projects_for_user(projects, user),
        "assignmentProjects": filter_assignment_projects_for_user(projects, user),
        "adminProjects": records_as_json(conn, "admin_project_records", normalized_mode) if is_admin(user) else [],
        "users": users_for_snapshot(conn, user),
        "projectLibraryPosts": project_library_posts(conn),
        "loginUser": user.get("id", ""),
        "currentUser": user_payload(user),
    }


def public_sample_projects():
    return []

def read_request_json(handler):
    length = int(handler.headers.get("Content-Length") or 0)
    if length > MAX_JSON_BODY_BYTES:
        raise ValueError("요청 데이터가 너무 큽니다.")
    if length <= 0:
        return {}
    raw = handler.rfile.read(length).decode("utf-8")
    try:
        return json.loads(raw or "{}")
    except json.JSONDecodeError:
        raise ValueError("요청 JSON 형식이 올바르지 않습니다.")

def decode_data_url(data_url):
    value = str(data_url or "")
    if not value:
        return b""
    match = re.match(r"^data:([^;,]+);base64,(.*)$", value, re.I | re.S)
    if not match:
        raise ValueError("첨부 파일 형식이 올바르지 않습니다.")
    mime_type = match.group(1).lower()
    if mime_type != "application/pdf":
        raise ValueError("PDF 파일만 업로드할 수 있습니다.")
    return base64.b64decode(match.group(2), validate=True)

def validate_pdf_payload(file_name, data_url):
    if not data_url:
        return
    if file_name and not str(file_name).lower().endswith(".pdf"):
        raise ValueError("PDF 확장자 파일만 업로드할 수 있습니다.")
    data = decode_data_url(data_url)
    if len(data) > MAX_PDF_BYTES:
        raise ValueError("PDF 파일은 10MB 이하만 업로드할 수 있습니다.")
    if not data.startswith(b"%PDF-") or b"%%EOF" not in data[-2048:]:
        raise ValueError("정상 PDF 파일이 아닙니다.")
    scan = data[: min(len(data), 2 * 1024 * 1024)]
    lowered = scan.lower()
    for marker in PDF_DANGEROUS_MARKERS:
        if marker.lower() in lowered:
            raise ValueError("보안상 위험한 PDF 기능이 포함되어 업로드할 수 없습니다.")

def validate_project_files(projects):
    for project in projects:
        validate_pdf_payload(project.get("quoteFileName"), project.get("quoteFileData"))

def read_text_asset(relative_path):
    path = BASE_DIR / relative_path
    return path.read_text(encoding="utf-8")


VIEW_PAGE_FILES = (
    "dashboard.html",
    "projects.html",
    "schedule.html",
    "vacation_schedule.html",
    "monthly.html",
    "issues.html",
    "project_completion_approval.html",
    "project_assignment.html",
    "project_library.html",
    "departments.html",
    "members.html",
    "leave_management.html",
    "leave_approvals.html",
    "login_logs.html",
    "project_logs.html",
)


def render_project_page():
    template = read_text_asset("templates/base.html")
    pages_html = "".join(read_text_asset(f"pages/{filename}") for filename in VIEW_PAGE_FILES)
    replacements = {
        "{{HEADER}}": read_text_asset("templates/header.html"),
        "{{SIDEBAR}}": read_text_asset("templates/sidebar.html"),
        "{{PAGES}}": pages_html,
        "{{DETAIL}}": read_text_asset("pages/detail.html"),
        "{{DIALOGS}}": read_text_asset("pages/dialogs.html"),
        "{{FOOTER}}": read_text_asset("templates/footer.html"),
    }
    for token, value in replacements.items():
        template = template.replace(token, value)
    return template


class SQLiteDashboardHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(BASE_DIR), **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)
        super().end_headers()

    def write_json(self, payload, status=HTTPStatus.OK):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def write_error_json(self, message, status=HTTPStatus.BAD_REQUEST):
        safe_message = str(message or "요청을 처리하지 못했습니다.")
        if "Encrypted data validation failed" in safe_message or "Encrypted user data" in safe_message:
            safe_message = "데이터를 불러오지 못했습니다. 관리자에게 문의하세요."
        self.write_json({"ok": False, "message": safe_message}, status)

    def write_html(self, html, status=HTTPStatus.OK):
        body = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/agencyflow.html", "/project.html"):
            try:
                return self.write_html(render_project_page())
            except Exception:
                return self.write_error_json("Project page render failed.", HTTPStatus.INTERNAL_SERVER_ERROR)
        if not parsed.path.startswith("/api/"):
            return super().do_GET()
        try:
            with connect() as conn:
                if parsed.path == "/api/initialize":
                    user = current_user(self)
                    mode = "private" if user else "public"
                    return self.write_json(dataset_snapshot(conn, mode, user))
                if parsed.path == "/api/dataset":
                    mode = parse_qs(parsed.query).get("mode", ["public"])[0]
                    user = current_user(self)
                    if normalize_mode(mode) == "private" and not user:
                        return self.write_json(dataset_snapshot(conn, "public", None))
                    return self.write_json(dataset_snapshot(conn, mode, user))
                if parsed.path == "/api/login-user":
                    user = current_user(self)
                    return self.write_json({"loginUser": user.get("id", "") if user else "", "currentUser": user})
                if parsed.path == "/api/users":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_json({"users": get_users(conn)})
                if parsed.path == "/api/departments":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_json({"departments": get_departments(conn)})
                if parsed.path == "/api/company-holidays":
                    user = current_user(self)
                    if not user:
                        return self.write_json({"holidays": []})
                    query = parse_qs(parsed.query)
                    year = query.get("year", [""])[0] or None
                    return self.write_json({"holidays": company_holidays(conn, year)})
                if parsed.path == "/api/leaves":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    query = parse_qs(parsed.query)
                    year = int(query.get("year", [date.today().year])[0])
                    return self.write_json({"summary": leave_summary(conn, user, year), "requests": user_leave_requests(conn, user, year)})
                if parsed.path == "/api/leave-approvals":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    query = parse_qs(parsed.query)
                    year = query.get("year", [""])[0] or None
                    return self.write_json({"requests": leave_approvals(conn, year)})
                if parsed.path == "/api/leave-calendar":
                    user = current_user(self)
                    query = parse_qs(parsed.query)
                    year = query.get("year", [""])[0] or None
                    return self.write_json({
                        "requests": approved_leave_calendar(conn, year) if user else [],
                        "holidays": company_holidays(conn, year) if user else [],
                        "departments": get_departments(conn) if user else [],
                    })
                if parsed.path == "/api/login-logs":
                    user = current_user(self)
                    if not user or user.get("role") != "admin":
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_json({"logs": login_logs(conn)})
                if parsed.path == "/api/project-logs":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    query = parse_qs(parsed.query)
                    page = query.get("page", ["1"])[0]
                    page_size = query.get("pageSize", ["10"])[0]
                    return self.write_json(project_logs(conn, page, page_size))
                if parsed.path == "/api/project-library":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_json({"posts": project_library_posts(conn)})
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        except PermissionError as error:
            return self.write_error_json(str(error), HTTPStatus.FORBIDDEN)
        except ValueError as error:
            return self.write_error_json(str(error), HTTPStatus.BAD_REQUEST)
        except Exception:
            return self.write_error_json("Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_PUT(self):
        if not request_origin_allowed(self):
            return self.write_error_json("허용되지 않은 요청 출처입니다.", HTTPStatus.FORBIDDEN)
        parsed = urlparse(self.path)
        if not parsed.path.startswith("/api/"):
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        try:
            payload = read_request_json(self)
            with connect() as conn:
                if parsed.path == "/api/projects":
                    mode = normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return self.write_json({"ok": True, "sampleOnly": True})
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    incoming_projects = payload.get("projects") or []
                    if not isinstance(incoming_projects, list):
                        return self.write_error_json("Invalid project payload.", HTTPStatus.BAD_REQUEST)
                    incoming_projects = enrich_project_staff_ids(incoming_projects, get_user_directory(conn))
                    validate_project_files(incoming_projects)
                    before_projects = records_as_json(conn, "project_records", mode)
                    projects = merge_projects_for_user(before_projects, incoming_projects, user)
                    conn.execute("DELETE FROM project_records WHERE mode = ?", (mode,))
                    insert_projects(conn, mode, projects)
                    logs = build_project_logs_from_diff(before_projects, projects)
                    if logs:
                        log_project_actions(conn, user, logs)
                    conn.commit()
                    snapshot = dataset_snapshot(conn, mode, user)
                    snapshot["ok"] = True
                    snapshot["logged"] = len(logs)
                    return self.write_json(snapshot)
                if parsed.path == "/api/project-assignments":
                    mode = normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return self.write_json({"ok": True, "sampleOnly": True})
                    user = current_user(self)
                    if not (is_admin(user) or is_team_lead(user)):
                        return self.write_error_json("Admin or team lead login required.", HTTPStatus.UNAUTHORIZED)
                    incoming_projects = payload.get("projects") or []
                    if not isinstance(incoming_projects, list):
                        return self.write_error_json("Invalid project assignment payload.", HTTPStatus.BAD_REQUEST)
                    incoming_projects = enrich_project_staff_ids(incoming_projects, get_user_directory(conn))
                    before_projects = records_as_json(conn, "project_records", mode)
                    projects = merge_project_assignments_for_user(before_projects, incoming_projects, user)
                    conn.execute("DELETE FROM project_records WHERE mode = ?", (mode,))
                    insert_projects(conn, mode, projects)
                    logs = build_project_logs_from_diff(before_projects, projects)
                    if logs:
                        log_project_actions(conn, user, logs)
                    conn.commit()
                    return self.write_json({
                        "ok": True,
                        "logged": len(logs),
                        "projects": filter_projects_for_user(projects, user),
                        "scheduleProjects": filter_schedule_projects_for_user(projects, user),
                        "assignmentProjects": filter_assignment_projects_for_user(projects, user),
                    })
                if parsed.path == "/api/admin-projects":
                    mode = normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return self.write_json({"ok": True, "sampleOnly": True})
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    admin_projects = payload.get("adminProjects") or []
                    if not isinstance(admin_projects, list):
                        return self.write_error_json("Invalid admin project payload.", HTTPStatus.BAD_REQUEST)
                    conn.execute("DELETE FROM admin_project_records WHERE mode = ?", (mode,))
                    insert_admin_projects(conn, mode, admin_projects)
                    conn.commit()
                    return self.write_json({"ok": True})
                if parsed.path == "/api/login-user":
                    return self.write_json({"ok": True})
                if parsed.path.startswith("/api/company-holidays/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    holiday_id = unquote(parsed.path.split("/api/company-holidays/", 1)[1])
                    update_company_holiday(conn, holiday_id, payload)
                    conn.commit()
                    return self.write_json({"ok": True, "holidays": company_holidays(conn)})
                if parsed.path.startswith("/api/leaves/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    suffix = parsed.path.split("/api/leaves/", 1)[1]
                    parts = suffix.split("/")
                    if len(parts) == 2 and parts[1] == "approval":
                        update_leave_status(conn, parts[0], payload.get("status") or "approved", user)
                        conn.commit()
                        return self.write_json({"ok": True, "requests": leave_approvals(conn)})
                    if len(parts) == 1 and parts[0]:
                        update_leave_request(conn, parts[0], user, payload)
                        conn.commit()
                        return self.write_json({"ok": True, "requests": approved_leave_calendar(conn), "users": get_users(conn)})
                if parsed.path.startswith("/api/users/"):
                    user = current_user(self)
                    if not user or user.get("role") != "admin":
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    user_id = unquote(parsed.path.split("/api/users/", 1)[1])
                    return self.update_user(conn, user_id, payload)
                if parsed.path.startswith("/api/departments/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    department_id = unquote(parsed.path.split("/api/departments/", 1)[1])
                    update_department(conn, department_id, payload.get("name"), payload.get("color"))
                    conn.commit()
                    return self.write_json({"ok": True, "departments": get_departments(conn), "users": get_users(conn)})
                if parsed.path.startswith("/api/project-library/") and "/comments/" in parsed.path:
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    rest = parsed.path.split("/api/project-library/", 1)[1]
                    post_id, comment_id = rest.split("/comments/", 1)
                    update_project_library_comment(conn, unquote(post_id), unquote(comment_id), payload)
                    conn.commit()
                    return self.write_json({"ok": True, "posts": project_library_posts(conn)})
                if parsed.path.startswith("/api/project-library/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    mode = normalize_mode(payload.get("mode"))
                    post_id = unquote(parsed.path.split("/api/project-library/", 1)[1])
                    update_project_library_post(conn, mode, post_id, payload)
                    conn.commit()
                    return self.write_json({"ok": True, "posts": project_library_posts(conn)})
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        except PermissionError as error:
            return self.write_error_json(str(error), HTTPStatus.FORBIDDEN)
        except ValueError as error:
            return self.write_error_json(str(error), HTTPStatus.BAD_REQUEST)
        except Exception:
            return self.write_error_json("Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self):
        if not request_origin_allowed(self):
            return self.write_error_json("허용되지 않은 요청 출처입니다.", HTTPStatus.FORBIDDEN)
        parsed = urlparse(self.path)
        try:
            payload = read_request_json(self)
            with connect() as conn:
                if parsed.path == "/api/authenticate":
                    return self.authenticate(conn, payload)
                if parsed.path == "/api/users":
                    user = current_user(self)
                    if not user or user.get("role") != "admin":
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return self.create_user(conn, payload)
                if parsed.path == "/api/departments":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    create_department(conn, payload.get("name"), payload.get("color"))
                    conn.commit()
                    return self.write_json({"ok": True, "departments": get_departments(conn)})
                if parsed.path == "/api/company-holidays":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    create_company_holiday(conn, payload, user)
                    conn.commit()
                    return self.write_json({"ok": True, "holidays": company_holidays(conn)})
                if parsed.path == "/api/leaves":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    target_user = target_leave_user(conn, user, payload)
                    create_leave_request(conn, user, payload)
                    conn.commit()
                    year = leave_year(payload.get("startDate"))
                    return self.write_json({"ok": True, "summary": leave_summary(conn, target_user, year), "requests": user_leave_requests(conn, target_user, year)})
                if parsed.path == "/api/project-completion":
                    mode = normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return self.write_json({"ok": True, "sampleOnly": True})
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    project_id = str(payload.get("projectId") or "").strip()
                    action = str(payload.get("action") or "approve").strip().lower()
                    before_projects = records_as_json(conn, "project_records", mode)
                    updated_projects = []
                    changed_project = None
                    changed_stage = None
                    for project in before_projects:
                        if str(project.get("id") or "") == project_id or str(project.get("projectNo") or "") == project_id:
                            if action == "reject":
                                changed_project, changed_stage = reject_project_completion(project, user, payload.get("reason") or "")
                            else:
                                changed_project, changed_stage = advance_project_completion(project, user, payload.get("completionType") or "", payload.get("memo") or "")
                            updated_projects.append(changed_project)
                        else:
                            updated_projects.append(project)
                    if not changed_project:
                        return self.write_error_json("Project not found.", HTTPStatus.NOT_FOUND)
                    conn.execute("DELETE FROM project_records WHERE mode = ?", (mode,))
                    insert_projects(conn, mode, updated_projects)
                    log_action = "반려" if action == "reject" else "완료"
                    log_project_actions(conn, user, [project_log_entry("수정", log_action, changed_project, target="프로젝트 완료", summary=changed_stage.get("label", log_action))])
                    conn.commit()
                    return self.write_json(dataset_snapshot(conn, mode, user))
                if parsed.path == "/api/project-library":
                    mode = normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return self.write_json({"ok": True, "sampleOnly": True, "posts": []})
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    create_project_library_post(conn, mode, user, payload)
                    conn.commit()
                    return self.write_json({"ok": True, "posts": project_library_posts(conn)})
                if parsed.path.startswith("/api/project-library/") and parsed.path.endswith("/comments"):
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    post_id = unquote(parsed.path.split("/api/project-library/", 1)[1].rsplit("/comments", 1)[0])
                    add_project_library_comment(conn, post_id, user, payload)
                    conn.commit()
                    return self.write_json({"ok": True, "posts": project_library_posts(conn)})
                if parsed.path == "/api/project-logs":
                    user = current_user(self)
                    if not user:
                        return self.write_error_json("Login required.", HTTPStatus.UNAUTHORIZED)
                    return self.write_error_json("Project logs are recorded by the server.", HTTPStatus.METHOD_NOT_ALLOWED)
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        except PermissionError as error:
            return self.write_error_json(str(error), HTTPStatus.FORBIDDEN)
        except ValueError as error:
            return self.write_error_json(str(error), HTTPStatus.BAD_REQUEST)
        except Exception:
            return self.write_error_json("Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_DELETE(self):
        if not request_origin_allowed(self):
            return self.write_error_json("허용되지 않은 요청 출처입니다.", HTTPStatus.FORBIDDEN)
        parsed = urlparse(self.path)
        try:
            with connect() as conn:
                if parsed.path == "/api/project-logs":
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    clear_project_logs(conn)
                    return self.write_json({"ok": True})
                if parsed.path == "/api/login-user":
                    clear_session_token(auth_token_from_handler(self))
                    return self.write_json({"ok": True})
                if parsed.path.startswith("/api/company-holidays/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    holiday_id = unquote(parsed.path.split("/api/company-holidays/", 1)[1])
                    delete_company_holiday(conn, holiday_id)
                    conn.commit()
                    return self.write_json({"ok": True, "holidays": company_holidays(conn)})
                if parsed.path.startswith("/api/leaves/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    leave_id = unquote(parsed.path.split("/api/leaves/", 1)[1])
                    delete_leave_request(conn, leave_id)
                    conn.commit()
                    return self.write_json({"ok": True, "requests": approved_leave_calendar(conn), "users": get_users(conn)})
                if parsed.path.startswith("/api/departments/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    department_id = unquote(parsed.path.split("/api/departments/", 1)[1])
                    delete_department(conn, department_id)
                    conn.commit()
                    return self.write_json({"ok": True, "departments": get_departments(conn)})
                if parsed.path.startswith("/api/project-library/") and "/comments/" in parsed.path:
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    rest = parsed.path.split("/api/project-library/", 1)[1]
                    post_id, comment_id = rest.split("/comments/", 1)
                    delete_project_library_comment(conn, unquote(post_id), unquote(comment_id))
                    conn.commit()
                    return self.write_json({"ok": True, "posts": project_library_posts(conn)})
                if parsed.path.startswith("/api/project-library/"):
                    user = current_user(self)
                    if not is_admin(user):
                        return self.write_error_json("Admin login required.", HTTPStatus.UNAUTHORIZED)
                    post_id = unquote(parsed.path.split("/api/project-library/", 1)[1])
                    delete_project_library_post(conn, post_id)
                    conn.commit()
                    return self.write_json({"ok": True, "posts": project_library_posts(conn)})
            return self.write_error_json("Unknown API endpoint.", HTTPStatus.NOT_FOUND)
        except PermissionError as error:
            return self.write_error_json(str(error), HTTPStatus.FORBIDDEN)
        except ValueError as error:
            return self.write_error_json(str(error), HTTPStatus.BAD_REQUEST)
        except Exception:
            return self.write_error_json("Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)

    def authenticate(self, conn, payload):
        user_id = str(payload.get("id") or "").strip()
        password = str(payload.get("password") or "").strip()
        ip = self.client_address[0] if self.client_address else ""
        if login_access_locked():
            log_login_attempt(conn, user_id, "", "user", "failure", "로그인 실패 횟수 초과", ip)
            return self.write_json({"ok": False, "message": "로그인 시도가 5회 이상 실패하여 잠시 동안 잠겼습니다. 서버를 다시 시작해야 잠금이 해제됩니다."}, HTTPStatus.TOO_MANY_REQUESTS)
        row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(user_id),)).fetchone()
        if not row:
            log_login_attempt(conn, user_id, "", "user", "failure", "아이디 또는 비밀번호 불일치", ip)
            record_login_failure()
            return self.write_json({"ok": False, "message": "아이디 또는 비밀번호가 올바르지 않습니다."})
        user = public_user(row)
        if not verify_password(password, row["password"]):
            log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "failure", "아이디 또는 비밀번호 불일치", ip)
            record_login_failure()
            return self.write_json({"ok": False, "message": "아이디 또는 비밀번호가 올바르지 않습니다."})
        if is_default_admin_password(user_id, password) and not ALLOW_WEAK_ADMIN_PASSWORD:
            log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "failure", "?? ??? ???? ??", ip)
            return self.write_json({"ok": False, "message": "기본 관리자 비밀번호는 사용할 수 없습니다. 관리자 비밀번호를 변경해 주세요."}, HTTPStatus.FORBIDDEN)
        approval = normalize_approval_status(row["approval_status"], row["role"])
        if not is_active_account(row):
            log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "failure", "비활성화 계정", ip)
            record_login_failure()
            return self.write_json({"ok": False, "message": "계정이 비활성화되었습니다. 관리자에게 문의하세요."})
        reset_login_failures()
        if password_needs_rehash(row["password"]):
            upsert_secure_user(conn, user["id"], hash_password(password), user.get("name", ""), user.get("role", "user"), approval, user.get("department", ""), user.get("position", ""), user.get("hireDate", ""), user.get("resignDate", ""))
        log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "success", "", ip)
        token = create_session(user)
        return self.write_json({"ok": True, "user": user_payload(user), "token": token, "expiresIn": SESSION_TTL_SECONDS, "users": get_users(conn) if is_admin(user) else []})

    def create_user(self, conn, payload):
        user_id = str(payload.get("id") or "").strip()
        password = str(payload.get("password") or "").strip()
        name = str(payload.get("name") or "").strip()
        role = normalize_user_role(payload.get("role"))
        approval = normalize_approval_status(payload.get("approvalStatus"), role)
        department = normalize_department(payload.get("department"))
        position = str(payload.get("position") or "").strip()[:40]
        hire_date = str(payload.get("hireDate") or "").strip()[:10]
        resign_date = str(payload.get("resignDate") or "").strip()[:10]
        if not re.match(r"^[A-Za-z0-9_.@-]{1,80}$", user_id):
            return self.write_json({"ok": False, "message": "아이디 형식이 올바르지 않습니다.", "users": get_users(conn)})
        if not password or not name:
            return self.write_json({"ok": False, "message": "아이디, 비밀번호, 이름을 모두 입력하세요.", "users": get_users(conn)})
        if not is_strong_password(password):
            return self.write_json({"ok": False, "message": "비밀번호는 알파벳, 숫자, 특수문자를 포함해 8자 이상이어야 합니다.", "users": get_users(conn)})
        if is_default_admin_password(user_id, password):
            return self.write_json({"ok": False, "message": "기본 관리자 비밀번호는 사용할 수 없습니다.", "users": get_users(conn)})
        if conn.execute("SELECT 1 FROM users_secure WHERE id_lookup = ?", (id_lookup(user_id),)).fetchone():
            return self.write_json({"ok": False, "message": "이미 사용 중인 아이디입니다.", "users": get_users(conn)})
        upsert_secure_user(conn, user_id, hash_password(password), name[:80], role, approval, department, position, hire_date, resign_date)
        row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(user_id),)).fetchone()
        created_user = public_user(row)
        set_leave_balance(conn, created_user, date.today().year, payload.get("leaveTotalDays"), payload.get("leaveRemainingDays"))
        conn.commit()
        return self.write_json({"ok": True, "user": public_user(row), "users": get_users(conn), "message": "회원이 등록되었습니다."})

    def update_user(self, conn, user_id, payload):
        row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(user_id),)).fetchone()
        if not row:
            return self.write_json({"ok": False, "message": "회원을 찾을 수 없습니다.", "users": get_users(conn)})
        current = public_user(row)
        name = str(payload.get("name") if payload.get("name") is not None else current["name"]).strip()[:80]
        role = normalize_user_role(payload.get("role"))
        approval = normalize_approval_status(payload.get("approvalStatus"), role)
        department = normalize_department(payload.get("department") if payload.get("department") is not None else current.get("department", ""))
        position = str(payload.get("position") if payload.get("position") is not None else current.get("position", "")).strip()[:40]
        hire_date = str(payload.get("hireDate") if payload.get("hireDate") is not None else current.get("hireDate", "")).strip()[:10]
        resign_date = str(payload.get("resignDate") if payload.get("resignDate") is not None else current.get("resignDate", "")).strip()[:10]
        password = row["password"]
        if current["id"].lower() == DEFAULT_ADMIN_ID:
            role = "admin"
            approval = "활성화"
        new_password = str(payload.get("password") or "").strip()
        if new_password:
            if not is_strong_password(new_password):
                return self.write_json({"ok": False, "message": "비밀번호는 알파벳, 숫자, 특수문자를 포함해 8자 이상이어야 합니다.", "users": get_users(conn)})
            if is_default_admin_password(current["id"], new_password):
                return self.write_json({"ok": False, "message": "기본 관리자 비밀번호는 사용할 수 없습니다.", "users": get_users(conn)})
            password = hash_password(new_password)
        upsert_secure_user(conn, current["id"], password, name, role, approval, department, position, hire_date, resign_date)
        next_row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (id_lookup(current["id"]),)).fetchone()
        updated_user = public_user(next_row)
        if "leaveTotalDays" in payload or "leaveRemainingDays" in payload:
            set_leave_balance(conn, updated_user, date.today().year, payload.get("leaveTotalDays"), payload.get("leaveRemainingDays"))
        else:
            ensure_leave_balance(conn, updated_user, date.today().year)
        conn.commit()
        return self.write_json({"ok": True, "user": public_user(next_row), "users": get_users(conn)})


def run(port=8766):
    ensure_db()
    server = ThreadingHTTPServer(("127.0.0.1", port), SQLiteDashboardHandler)
    print(f"SQLite dashboard server: http://127.0.0.1:{port}/agencyflow.html")
    print(f"SQLite database: {DB_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    run(int(os.environ.get("PORT", "8766")))



