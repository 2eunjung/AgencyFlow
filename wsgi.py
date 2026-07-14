"""PythonAnywhere WSGI entrypoint for Agency Flow.

Set PythonAnywhere's WSGI file to import this module and expose `application`.
This file intentionally uses only the Python standard library so the app can run
on low-cost hosting without extra package installation.
"""

from http import HTTPStatus
import json
import mimetypes
from pathlib import Path
import sys
from urllib.parse import parse_qs, unquote

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import sqlite_server as core

STATIC_DIR = BASE_DIR / "static"

core.ensure_db()


def status_line(status):
    status = HTTPStatus(status)
    return f"{status.value} {status.phrase}"


def response(start_response, body=b"", status=HTTPStatus.OK, content_type="text/plain; charset=utf-8", headers=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    response_headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
    ]
    if headers:
        response_headers.extend(headers)
    start_response(status_line(status), response_headers)
    return [body]


def json_response(start_response, payload, status=HTTPStatus.OK):
    return response(
        start_response,
        json.dumps(payload, ensure_ascii=False),
        status,
        "application/json; charset=utf-8",
    )


def html_response(start_response, html, status=HTTPStatus.OK):
    return response(start_response, html, status, "text/html; charset=utf-8")


def error_json(start_response, message, status=HTTPStatus.BAD_REQUEST):
    return json_response(start_response, {"ok": False, "message": message}, status)


def read_json(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length > core.MAX_JSON_BODY_BYTES:
        raise ValueError("Request body is too large.")
    if length <= 0:
        return {}
    raw = environ["wsgi.input"].read(length).decode("utf-8")
    return json.loads(raw or "{}")


def auth_token(environ):
    auth = environ.get("HTTP_AUTHORIZATION") or ""
    if auth.startswith("Bearer "):
        return auth.split(" ", 1)[1].strip()
    return environ.get("HTTP_X_SESSION_TOKEN") or ""


def current_user(environ):
    session = core.session_from_token(auth_token(environ))
    return session.get("user") if session else None


def client_ip(environ):
    forwarded = environ.get("HTTP_X_FORWARDED_FOR") or ""
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    return environ.get("REMOTE_ADDR") or ""


def serve_static(environ, start_response):
    raw_path = unquote(environ.get("PATH_INFO") or "")
    relative = raw_path[len("/static/"):]
    if not relative or ".." in Path(relative).parts:
        return error_json(start_response, "Static file not found.", HTTPStatus.NOT_FOUND)
    path = (STATIC_DIR / relative).resolve()
    try:
        path.relative_to(STATIC_DIR.resolve())
    except ValueError:
        return error_json(start_response, "Static file not found.", HTTPStatus.NOT_FOUND)
    if not path.is_file():
        return error_json(start_response, "Static file not found.", HTTPStatus.NOT_FOUND)
    content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    return response(start_response, path.read_bytes(), HTTPStatus.OK, content_type)


def authenticate(conn, payload, environ, start_response):
    user_id = str(payload.get("id") or "").strip()
    password = str(payload.get("password") or "").strip()
    ip = client_ip(environ)
    if core.login_access_locked():
        core.log_login_attempt(conn, user_id, "", "user", "failure", "로그인 실패 한도 초과", ip)
        return json_response(
            start_response,
            {"ok": False, "message": "로그인 시도가 5회 이상 실패하여 잠시 동안 잠겼습니다. 서버를 다시 시작해야 잠금이 해제됩니다."},
            HTTPStatus.TOO_MANY_REQUESTS,
        )
    row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (core.id_lookup(user_id),)).fetchone()
    if not row:
        core.log_login_attempt(conn, user_id, "", "user", "failure", "아이디 또는 비밀번호 불일치", ip)
        core.record_login_failure()
        return json_response(start_response, {"ok": False, "message": "아이디 또는 비밀번호가 올바르지 않습니다."})
    user = core.public_user(row)
    if not core.verify_password(password, row["password"]):
        core.log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "failure", "아이디 또는 비밀번호 불일치", ip)
        core.record_login_failure()
        return json_response(start_response, {"ok": False, "message": "아이디 또는 비밀번호가 올바르지 않습니다."})
    approval = core.normalize_approval_status(row["approval_status"], row["role"])
    if not core.is_active_account(row):
        core.log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "failure", "비활성화 계정", ip)
        core.record_login_failure()
        return json_response(start_response, {"ok": False, "message": "계정이 비활성화되었습니다. 관리자에게 문의하세요."})
    core.reset_login_failures()
    if core.password_needs_rehash(row["password"]):
        core.upsert_secure_user(conn, user["id"], core.hash_password(password), user.get("name", ""), user.get("role", "user"), approval, user.get("department", ""))
    core.log_login_attempt(conn, user["id"], user.get("name", ""), user.get("role", "user"), "success", "", ip)
    token = core.create_session(user)
    return json_response(start_response, {
        "ok": True,
        "user": core.user_payload(user),
        "token": token,
        "expiresIn": core.SESSION_TTL_SECONDS,
        "users": core.get_users(conn) if core.is_admin(user) else [],
    })


def create_user(conn, payload, start_response):
    user_id = str(payload.get("id") or "").strip()
    password = str(payload.get("password") or "").strip()
    name = str(payload.get("name") or "").strip()
    role = "admin" if payload.get("role") == "admin" else "user"
    approval = core.normalize_approval_status(payload.get("approvalStatus"), role)
    department = core.normalize_department(payload.get("department"))
    if not core.re.match(r"^[A-Za-z0-9_.@-]{1,80}$", user_id):
        return json_response(start_response, {"ok": False, "message": "Invalid ID format.", "users": core.get_users(conn)})
    if not password or not name:
        return json_response(start_response, {"ok": False, "message": "ID, password, and name are required.", "users": core.get_users(conn)})
    if conn.execute("SELECT 1 FROM users_secure WHERE id_lookup = ?", (core.id_lookup(user_id),)).fetchone():
        return json_response(start_response, {"ok": False, "message": "This ID is already in use.", "users": core.get_users(conn)})
    core.upsert_secure_user(conn, user_id, core.hash_password(password), name[:80], role, approval, department)
    conn.commit()
    row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (core.id_lookup(user_id),)).fetchone()
    return json_response(start_response, {"ok": True, "user": core.public_user(row), "users": core.get_users(conn), "message": "Member created."})


def update_user(conn, user_id, payload, start_response):
    row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (core.id_lookup(user_id),)).fetchone()
    if not row:
        return json_response(start_response, {"ok": False, "message": "Member not found.", "users": core.get_users(conn)})
    current = core.public_user(row)
    name = str(payload.get("name") if payload.get("name") is not None else current["name"]).strip()[:80]
    role = "admin" if payload.get("role") == "admin" else "user"
    approval = core.normalize_approval_status(payload.get("approvalStatus"), role)
    department = core.normalize_department(payload.get("department") if payload.get("department") is not None else current.get("department", ""))
    password = row["password"]
    if current["id"].lower() == core.DEFAULT_ADMIN_ID:
        role = "admin"
        approval = "활성화"
    if str(payload.get("password") or "").strip():
        password = core.hash_password(str(payload.get("password")).strip())
    core.upsert_secure_user(conn, current["id"], password, name, role, approval, department)
    conn.commit()
    next_row = conn.execute("SELECT * FROM users_secure WHERE id_lookup = ?", (core.id_lookup(current["id"]),)).fetchone()
    return json_response(start_response, {"ok": True, "user": core.public_user(next_row), "users": core.get_users(conn)})


def api_request(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = environ.get("PATH_INFO") or ""
    query = parse_qs(environ.get("QUERY_STRING") or "")
    try:
        with core.connect() as conn:
            if method == "GET":
                if path == "/api/initialize":
                    user = current_user(environ)
                    mode = "private" if user else "public"
                    return json_response(start_response, core.dataset_snapshot(conn, mode, user))
                if path == "/api/dataset":
                    mode = query.get("mode", ["public"])[0]
                    user = current_user(environ)
                    if core.normalize_mode(mode) == "private" and not user:
                        return json_response(start_response, core.dataset_snapshot(conn, "public", None))
                    return json_response(start_response, core.dataset_snapshot(conn, mode, user))
                if path == "/api/login-user":
                    user = current_user(environ)
                    return json_response(start_response, {"loginUser": user.get("id", "") if user else "", "currentUser": user})
                if path == "/api/users":
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return json_response(start_response, {"users": core.get_users(conn)})
                if path == "/api/departments":
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return json_response(start_response, {"departments": core.get_departments(conn)})
                if path == "/api/company-holidays":
                    user = current_user(environ)
                    if not user:
                        return json_response(start_response, {"holidays": []})
                    year = query.get("year", [""])[0] or None
                    return json_response(start_response, {"holidays": core.company_holidays(conn, year)})
                if path == "/api/leaves":
                    user = current_user(environ)
                    if not user:
                        return error_json(start_response, "Login required.", HTTPStatus.UNAUTHORIZED)
                    year = int(query.get("year", [core.date.today().year])[0])
                    return json_response(start_response, {"summary": core.leave_summary(conn, user, year), "requests": core.user_leave_requests(conn, user, year)})
                if path == "/api/leave-approvals":
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    year = query.get("year", [""])[0] or None
                    return json_response(start_response, {"requests": core.leave_approvals(conn, year)})
                if path == "/api/leave-calendar":
                    user = current_user(environ)
                    year = query.get("year", [""])[0] or None
                    return json_response(start_response, {"requests": core.leave_approvals(conn, year) if user else [], "holidays": core.company_holidays(conn, year) if user else []})
                if path == "/api/login-logs":
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return json_response(start_response, {"logs": core.login_logs(conn)})
                if path == "/api/project-logs":
                    user = current_user(environ)
                    if not user:
                        return error_json(start_response, "Login required.", HTTPStatus.UNAUTHORIZED)
                    return json_response(start_response, core.project_logs(conn, query.get("page", ["1"])[0], query.get("pageSize", ["10"])[0]))
            if method in ("POST", "PUT"):
                payload = read_json(environ)
                if method == "POST" and path == "/api/authenticate":
                    return authenticate(conn, payload, environ, start_response)
                if method == "POST" and path == "/api/users":
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return create_user(conn, payload, start_response)
                if method == "POST" and path == "/api/departments":
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    core.create_department(conn, payload.get("name"))
                    conn.commit()
                    return json_response(start_response, {"ok": True, "departments": core.get_departments(conn)})
                if method == "POST" and path == "/api/company-holidays":
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    core.create_company_holiday(conn, payload, user)
                    conn.commit()
                    return json_response(start_response, {"ok": True, "holidays": core.company_holidays(conn)})
                if method == "POST" and path == "/api/leaves":
                    user = current_user(environ)
                    if not user:
                        return error_json(start_response, "Login required.", HTTPStatus.UNAUTHORIZED)
                    target_user = core.target_leave_user(conn, user, payload)
                    core.create_leave_request(conn, user, payload)
                    conn.commit()
                    year = core.leave_year(payload.get("startDate"))
                    return json_response(start_response, {"ok": True, "summary": core.leave_summary(conn, target_user, year), "requests": core.user_leave_requests(conn, target_user, year)})
                if method == "POST" and path == "/api/project-logs":
                    user = current_user(environ)
                    if not user:
                        return error_json(start_response, "Login required.", HTTPStatus.UNAUTHORIZED)
                    return error_json(start_response, "Project logs are recorded by the server.", HTTPStatus.METHOD_NOT_ALLOWED)
                if method == "PUT" and path == "/api/projects":
                    mode = core.normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return json_response(start_response, {"ok": True, "sampleOnly": True})
                    user = current_user(environ)
                    if not user:
                        return error_json(start_response, "Login required.", HTTPStatus.UNAUTHORIZED)
                    incoming_projects = payload.get("projects") or []
                    if not isinstance(incoming_projects, list):
                        return error_json(start_response, "Invalid project payload.", HTTPStatus.BAD_REQUEST)
                    core.validate_project_files(incoming_projects)
                    before_projects = core.records_as_json(conn, "project_records", mode)
                    projects = core.merge_projects_for_user(before_projects, incoming_projects, user)
                    conn.execute("DELETE FROM project_records WHERE mode = ?", (mode,))
                    core.insert_projects(conn, mode, projects)
                    logs = core.build_project_logs_from_diff(before_projects, projects)
                    if logs:
                        core.log_project_actions(conn, user, logs)
                    conn.commit()
                    return json_response(start_response, {"ok": True, "logged": len(logs)})
                if method == "PUT" and path == "/api/admin-projects":
                    mode = core.normalize_mode(payload.get("mode"))
                    if mode == "public":
                        return json_response(start_response, {"ok": True, "sampleOnly": True})
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    admin_projects = payload.get("adminProjects") or []
                    if not isinstance(admin_projects, list):
                        return error_json(start_response, "Invalid admin project payload.", HTTPStatus.BAD_REQUEST)
                    conn.execute("DELETE FROM admin_project_records WHERE mode = ?", (mode,))
                    core.insert_admin_projects(conn, mode, admin_projects)
                    conn.commit()
                    return json_response(start_response, {"ok": True})
                if method == "PUT" and path == "/api/login-user":
                    return json_response(start_response, {"ok": True})
                if method == "PUT" and path.startswith("/api/leaves/"):
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    suffix = path.split("/api/leaves/", 1)[1]
                    parts = suffix.split("/")
                    if len(parts) == 2 and parts[1] == "approval":
                        core.update_leave_status(conn, parts[0], payload.get("status") or "approved", user)
                        conn.commit()
                        return json_response(start_response, {"ok": True, "requests": core.leave_approvals(conn)})
                if method == "PUT" and path.startswith("/api/users/"):
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    return update_user(conn, unquote(path.split("/api/users/", 1)[1]), payload, start_response)
                if method == "PUT" and path.startswith("/api/departments/"):
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    core.update_department(conn, unquote(path.split("/api/departments/", 1)[1]), payload.get("name"))
                    conn.commit()
                    return json_response(start_response, {"ok": True, "departments": core.get_departments(conn), "users": core.get_users(conn)})
            if method == "DELETE":
                if path == "/api/project-logs":
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    core.clear_project_logs(conn)
                    return json_response(start_response, {"ok": True})
                if path == "/api/login-user":
                    core.clear_session_token(auth_token(environ))
                    return json_response(start_response, {"ok": True})
                if path.startswith("/api/departments/"):
                    user = current_user(environ)
                    if not core.is_admin(user):
                        return error_json(start_response, "Admin login required.", HTTPStatus.UNAUTHORIZED)
                    core.delete_department(conn, unquote(path.split("/api/departments/", 1)[1]))
                    conn.commit()
                    return json_response(start_response, {"ok": True, "departments": core.get_departments(conn)})
            return error_json(start_response, "Unknown API endpoint.", HTTPStatus.NOT_FOUND)
    except ValueError as error:
        return error_json(start_response, str(error), HTTPStatus.BAD_REQUEST)
    except Exception:
        return error_json(start_response, "Internal server error.", HTTPStatus.INTERNAL_SERVER_ERROR)


def application(environ, start_response):
    path = environ.get("PATH_INFO") or "/"
    if path in ("/", "/agencyflow.html", "/project.html"):
        try:
            return html_response(start_response, core.render_project_page())
        except Exception:
            return error_json(start_response, "Project page render failed.", HTTPStatus.INTERNAL_SERVER_ERROR)
    if path.startswith("/api/"):
        return api_request(environ, start_response)
    if path.startswith("/static/"):
        return serve_static(environ, start_response)
    return error_json(start_response, "Not found.", HTTPStatus.NOT_FOUND)
