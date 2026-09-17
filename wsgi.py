"""PythonAnywhere entrypoint sharing the local server's API implementation.

Only HTTP/WSGI transport is adapted here. Authentication, permissions, database
updates and API routes remain in sqlite_server.SQLiteDashboardHandler so the
local and deployed versions cannot silently acquire different business rules.
"""

from email.message import Message
from http import HTTPStatus
from io import BytesIO
import json
import mimetypes
from pathlib import Path
import sys
from urllib.parse import quote

BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import sqlite_server as core

STATIC_DIR = BASE_DIR / "static"
core.ensure_db()


def response(start_response, body=b"", status=HTTPStatus.OK,
             content_type="text/plain; charset=utf-8", headers=None, head=False):
    if isinstance(body, str):
        body = body.encode("utf-8")
    status = HTTPStatus(status)
    response_headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
        *core.SECURITY_HEADERS.items(),
        *(headers or []),
    ]
    start_response(f"{status.value} {status.phrase}", response_headers)
    return [b"" if head else body]


def error_json(start_response, message, status, headers=None, head=False):
    return response(
        start_response, json.dumps({"ok": False, "message": message}, ensure_ascii=False),
        status, "application/json; charset=utf-8", headers=headers, head=head,
    )


class WSGIAPIHandler(core.SQLiteDashboardHandler):
    """Provide the request/response interface used by the shared API methods.

    The socket handler constructor is intentionally not called: WSGI has already
    parsed the HTTP request. No socket, HTTP server or network loop is started.
    Only /api/ requests may be dispatched to this adapter.
    """

    def __init__(self, environ):
        # WSGI PATH_INFO is decoded; restore URI escaping for the shared routes,
        # which explicitly unquote path parameters (IDs can contain @ or %).
        path = environ.get("PATH_INFO") or "/"
        self.path = quote(path, safe="/", encoding="utf-8")
        query = environ.get("QUERY_STRING") or ""
        if query:
            self.path += "?" + query
        self.command = environ.get("REQUEST_METHOD", "GET").upper()
        self.headers = Message()
        for name, value in environ.items():
            if name.startswith("HTTP_"):
                self.headers[name[5:].replace("_", "-")] = str(value)
        for name in ("CONTENT_TYPE", "CONTENT_LENGTH"):
            if environ.get(name):
                self.headers[name.replace("_", "-")] = str(environ[name])
        if not self.headers.get("Host"):
            host = environ.get("SERVER_NAME", "localhost")
            port = environ.get("SERVER_PORT", "")
            default_port = "443" if environ.get("wsgi.url_scheme") == "https" else "80"
            self.headers["Host"] = host + (f":{port}" if port and port != default_port else "")
        forwarded = environ.get("HTTP_X_FORWARDED_FOR") or ""
        ip = forwarded.split(",", 1)[0].strip() if forwarded else environ.get("REMOTE_ADDR", "")
        self.client_address = (ip, 0)
        self.rfile = environ["wsgi.input"]
        self.wfile = BytesIO()
        self.response_status = HTTPStatus.OK
        self.response_headers = []

    def send_response(self, code, message=None):
        self.response_status = HTTPStatus(code)

    def send_header(self, keyword, value):
        self.response_headers.append((str(keyword), str(value)))

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        for name, value in core.SECURITY_HEADERS.items():
            self.send_header(name, value)

    def dispatch(self, start_response):
        method = "GET" if self.command == "HEAD" else self.command
        if method not in {"GET", "POST", "PUT", "DELETE"}:
            return error_json(
                start_response, "Method not allowed.", HTTPStatus.METHOD_NOT_ALLOWED,
                headers=[("Allow", "GET, HEAD, POST, PUT, DELETE")],
            )
        getattr(self, "do_" + method)()
        status = self.response_status
        start_response(f"{status.value} {status.phrase}", self.response_headers)
        return [b"" if self.command == "HEAD" else self.wfile.getvalue()]


def serve_static(environ, start_response):
    # PATH_INFO has already been URL-decoded by the WSGI server.
    relative = (environ.get("PATH_INFO") or "")[len("/static/"):]
    head = environ.get("REQUEST_METHOD", "GET").upper() == "HEAD"
    try:
        if not relative or ".." in Path(relative).parts:
            raise ValueError("Invalid static path")
        path = (STATIC_DIR / relative).resolve()
        path.relative_to(STATIC_DIR.resolve())
        if not path.is_file():
            raise FileNotFoundError(path)
        body = path.read_bytes()
    except (OSError, ValueError):
        return error_json(start_response, "Static file not found.", HTTPStatus.NOT_FOUND, head=head)
    content_type = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    return response(start_response, body, content_type=content_type, head=head)


def application(environ, start_response):
    path = environ.get("PATH_INFO") or "/"
    method = environ.get("REQUEST_METHOD", "GET").upper()
    head = method == "HEAD"
    if path.startswith("/api/"):
        return WSGIAPIHandler(environ).dispatch(start_response)
    if path in ("/", "/agencyflow.html", "/project.html") or path.startswith("/static/"):
        if method not in {"GET", "HEAD"}:
            return error_json(
                start_response, "Method not allowed.", HTTPStatus.METHOD_NOT_ALLOWED,
                headers=[("Allow", "GET, HEAD")],
            )
        if path.startswith("/static/"):
            return serve_static(environ, start_response)
        try:
            html = core.render_project_page()
        except Exception:
            return error_json(
                start_response, "Project page render failed.",
                HTTPStatus.INTERNAL_SERVER_ERROR, head=head,
            )
        return response(start_response, html, content_type="text/html; charset=utf-8", head=head)
    return error_json(start_response, "Not found.", HTTPStatus.NOT_FOUND, head=head)
