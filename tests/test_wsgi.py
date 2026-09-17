"""WSGI integration checks; only a temporary database/secret is ever used.

Run from the app directory: python -B -m unittest discover -s tests -v
AGENCY_FLOW_TEST_SOURCE optionally selects an app directory to copy for testing.
AGENCY_FLOW_TEST_WSGI optionally overrides just the WSGI file under test.
"""

from contextlib import closing
import gc
import importlib
from io import BytesIO
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from urllib.parse import unquote, urlsplit
from wsgiref.util import setup_testing_defaults
from wsgiref.validate import validator


class WSGIIntegrationTests(unittest.TestCase):
    password = "Test-only-2026!"

    @classmethod
    def setUpClass(cls):
        source = Path(os.environ.get("AGENCY_FLOW_TEST_SOURCE", Path(__file__).resolve().parents[1]))
        cls.temp = tempfile.TemporaryDirectory(prefix="agencyflow-wsgi-")
        cls.root = Path(cls.temp.name).resolve()
        # Never copy projects.sqlite3 or projects.secret from the user's app.
        for name in ("sqlite_server.py", "wsgi.py"):
            source_file = Path(os.environ.get("AGENCY_FLOW_TEST_WSGI", source / name)) if name == "wsgi.py" else source / name
            shutil.copy2(source_file, cls.root / name)
        for name in ("templates", "pages", "static"):
            shutil.copytree(source / name, cls.root / name)
        cls.old_modules = {name: sys.modules.pop(name, None) for name in ("sqlite_server", "wsgi")}
        cls.old_path = sys.path[:]
        sys.path.insert(0, str(cls.root))
        # Prevent local deployment settings from seeding an unrelated account.
        cls.old_admin_password = os.environ.pop("AGENCY_FLOW_ADMIN_PASSWORD", None)
        cls.app_module = importlib.import_module("wsgi")
        cls.core = cls.app_module.core
        assert cls.core.DB_PATH.resolve().parent == cls.root
        assert cls.core.SECRET_PATH.resolve().parent == cls.root
        cls.app = staticmethod(validator(cls.app_module.application))
        cls.password_hash = cls.core.hash_password(cls.password)

    @classmethod
    def tearDownClass(cls):
        cls.core.SESSIONS.clear()
        for name, previous in cls.old_modules.items():
            sys.modules.pop(name, None)
            if previous is not None:
                sys.modules[name] = previous
        sys.path[:] = cls.old_path
        if cls.old_admin_password is not None:
            os.environ["AGENCY_FLOW_ADMIN_PASSWORD"] = cls.old_admin_password
        gc.collect()
        cls.temp.cleanup()

    def setUp(self):
        self.core.SESSIONS.clear()
        self.core.DB_PATH = self.root / (self._testMethodName + ".sqlite3")
        self.core.ensure_db()
        users = [
            ("admin", "관리자", "admin", "경영관리", "관리자"),
            ("pm.test", "테스트 PM", "user", "pm", "매니저"),
            ("lead.test", "디자인 팀장", "team_lead", "디자인", "팀장"),
            ("worker.test", "디자인 담당", "user", "디자인", "사원"),
            ("other.test", "다른 담당", "user", "디자인", "사원"),
        ]
        with closing(self.core.connect()) as conn, conn:
            for user_id, name, role, department, position in users:
                self.core.upsert_secure_user(
                    conn, user_id, self.password_hash, name, role, "활성화",
                    department, position, "2025-01-01", "",
                )
            self.core.insert_projects(conn, "private", [self.project()])

    def tearDown(self):
        gc.collect()

    def project(self):
        return {
            "id": "test-project", "projectNo": "00001", "name": "배포 검증 프로젝트",
            "status": "작업중", "milestone": "메인시안중", "pm": "테스트 PM", "pmId": "pm.test",
            "designer": "디자인 담당", "designerId": "worker.test",
            "publisher": "", "programmer": "", "completionFlow": {"completed": [], "history": []},
            "schedules": [], "issues": [], "communications": [],
        }

    def request(self, path, method="GET", payload=None, token=None, headers=None,
                raw=None, length=None):
        parts = urlsplit(path)
        env = {}
        setup_testing_defaults(env)
        body = raw if raw is not None else json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else b""
        env.update({
            "REQUEST_METHOD": method, "PATH_INFO": unquote(parts.path),
            "QUERY_STRING": parts.query, "HTTP_HOST": "portfolio.example.test",
            "SERVER_NAME": "portfolio.example.test", "SERVER_PORT": "443",
            "SERVER_PROTOCOL": "HTTP/1.1", "wsgi.url_scheme": "https",
            "REMOTE_ADDR": "127.0.0.1", "wsgi.input": BytesIO(body),
            "CONTENT_TYPE": "application/json", "CONTENT_LENGTH": str(len(body) if length is None else length),
        })
        if method in {"POST", "PUT", "DELETE"}:
            env["HTTP_ORIGIN"] = "https://portfolio.example.test"
        if token:
            env["HTTP_AUTHORIZATION"] = "Bearer " + token
        env.update(headers or {})
        captured = {}

        def start_response(status, response_headers, exc_info=None):
            captured["status"] = int(status.split()[0])
            captured["headers"] = dict(response_headers)

        result = self.app(env, start_response)
        try:
            data = b"".join(result)
        finally:
            result.close()
        if method != "HEAD":
            self.assertEqual(int(captured["headers"]["Content-Length"]), len(data))
        for name, value in self.core.SECURITY_HEADERS.items():
            self.assertEqual(captured["headers"][name], value)
        content_type = captured["headers"].get("Content-Type", "")
        parsed = json.loads(data) if data and content_type.startswith("application/json") else data
        return captured["status"], parsed, captured["headers"]

    def login(self, user="pm.test", password=None):
        status, data, _ = self.request("/api/authenticate", "POST", {"id": user, "password": password or self.password})
        self.assertEqual(status, 200, data)
        self.assertTrue(data["ok"], data)
        return data["token"]

    def test_pages_static_head_and_private_files(self):
        for path in ("/", "/agencyflow.html", "/project.html"):
            status, page, _ = self.request(path)
            self.assertEqual(status, 200)
            self.assertIn(b"dashboardView", page)
            self.assertNotIn(b"{{PAGES}}", page)
        for path in ("/static/project.css", "/static/project.js"):
            status, body, headers = self.request(path)
            self.assertEqual(status, 200)
            self.assertGreater(len(body), 100)
            head_status, head_body, head_headers = self.request(path, "HEAD")
            self.assertEqual(head_status, 200)
            self.assertEqual(head_body, b"")
            self.assertEqual(headers["Content-Length"], head_headers["Content-Length"])
        for path in ("/projects.sqlite3", "/projects.secret", "/sqlite_server.py",
                     "/static/../projects.secret", "/static/%2e%2e/projects.secret"):
            self.assertEqual(self.request(path)[0], 404)

    def test_public_and_role_filtered_snapshots(self):
        self.assertEqual(self.request("/api/initialize")[1]["projects"], [])
        self.assertEqual(self.request("/api/dataset?mode=private")[1]["mode"], "public")
        for user, count in (("pm.test", 1), ("lead.test", 1), ("worker.test", 1), ("other.test", 0)):
            token = self.login(user)
            status, data, _ = self.request("/api/initialize", token=token)
            self.assertEqual(status, 200)
            self.assertEqual(len(data["projects"]), count)
            self.assertEqual(data["currentUser"]["id"], user)
            for key in ("scheduleProjects", "assignmentProjects", "projectLibraryPosts"):
                self.assertIn(key, data)
        self.assertEqual(self.request("/api/users", token=token)[0], 401)

    def test_account_lockout_is_persistent_and_reset_by_admin(self):
        old_token = self.login("worker.test")
        for attempt in range(5):
            status, data, _ = self.request("/api/authenticate", "POST", {"id": "worker.test", "password": "wrong"})
            self.assertEqual(status, 200)
            self.assertFalse(data["ok"])
        self.assertNotIn(old_token, self.core.SESSIONS)
        self.core.SESSIONS.clear()
        self.core.ensure_db()
        self.assertEqual(self.request("/api/authenticate", "POST", {"id": "worker.test", "password": self.password})[0], 429)
        self.login("other.test")
        admin = self.login("admin")
        status, data, _ = self.request("/api/users/worker.test", "PUT", {
            "role": "user", "approvalStatus": "활성화", "password": "New-test-2026!",
        }, admin)
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.login("worker.test", "New-test-2026!")

    def test_partial_login_failures_reset_on_success(self):
        for _ in range(4):
            self.request("/api/authenticate", "POST", {"id": "pm.test", "password": "wrong"})
        self.login()
        self.request("/api/authenticate", "POST", {"id": "pm.test", "password": "wrong"})
        self.login()

    def test_session_header_logout_and_expiry(self):
        token = self.login()
        status, data, _ = self.request("/api/login-user", headers={"HTTP_X_SESSION_TOKEN": token})
        self.assertEqual(status, 200)
        self.assertEqual(data["loginUser"], "pm.test")
        self.assertEqual(self.request("/api/login-user", "DELETE", token=token)[0], 200)
        self.assertEqual(self.request("/api/initialize", token=token)[1]["mode"], "public")
        token = self.login()
        self.core.SESSIONS[token]["expires_at"] = 0
        self.assertEqual(self.request("/api/initialize", token=token)[1]["mode"], "public")

    def test_project_save_returns_full_snapshot_and_persists(self):
        token = self.login()
        project = self.project()
        project.update({"name": "수정한 프로젝트", "isUrgent": True})
        project["schedules"] = [{"id": "schedule-1", "date": "2026-09-17", "content": "검수", "staffName": "테스트 PM", "createdById": "pm.test", "completed": True}]
        status, data, _ = self.request("/api/projects", "PUT", {"mode": "private", "projects": [project]}, token)
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["projects"][0]["name"], "수정한 프로젝트")
        self.assertIn("currentUser", data)
        reloaded = self.request("/api/dataset?mode=private", token=token)[1]["projects"][0]
        self.assertTrue(reloaded["isUrgent"])
        self.assertTrue(reloaded["schedules"][0]["completed"])

    def test_assignments_enforce_role_and_department(self):
        project = self.project()
        project.update({"designer": "다른 담당", "designerId": "other.test", "designerAssignedAt": "2026-09-17T10:00:00", "pm": "바꾸면 안 됨", "name": "바꾸면 안 됨"})
        payload = {"mode": "private", "projects": [project]}
        self.assertEqual(self.request("/api/project-assignments", "PUT", payload, self.login("worker.test"))[0], 401)
        status, data, _ = self.request("/api/project-assignments", "PUT", payload, self.login("lead.test"))
        self.assertEqual(status, 200)
        self.assertEqual(data["projects"][0]["designerId"], "other.test")
        self.assertEqual(data["projects"][0]["pm"], "테스트 PM")
        self.assertEqual(data["projects"][0]["name"], "배포 검증 프로젝트")
        self.assertIn("assignmentProjects", data)

    def test_completion_approval_and_rejection(self):
        worker, lead, pm = self.login("worker.test"), self.login("lead.test"), self.login()
        payload = {"mode": "private", "projectId": "test-project", "action": "approve"}
        self.assertEqual(self.request("/api/project-completion", "POST", payload, pm)[0], 403)
        self.assertEqual(self.request("/api/project-completion", "POST", payload, worker)[0], 200)
        rejected = {**payload, "action": "reject", "reason": "검수 수정 필요"}
        status, data, _ = self.request("/api/project-completion", "POST", rejected, lead)
        self.assertEqual(status, 200)
        flow = data["projects"][0]["completionFlow"]
        self.assertEqual(flow["completed"], [])
        self.assertEqual(flow["history"][-1]["reason"], "검수 수정 필요")
        for token in (worker, lead, pm):
            status, data, _ = self.request("/api/project-completion", "POST", payload, token)
            self.assertEqual(status, 200, data)
        self.assertEqual(data["projects"][0]["completionFlow"]["completed"], ["design_worker", "design_lead", "design_pm"])

    def test_library_post_attachment_comment_and_admin_edits(self):
        pm, worker, admin = self.login(), self.login("worker.test"), self.login("admin")
        payload = {
            "mode": "private", "projectId": "test-project", "title": "시안 공유", "content": "검토 부탁드립니다.",
            "messengerUrl": "https://example.test/thread/1", "attachments": [
                {"id": "file-1", "name": "notes.txt", "size": 3, "type": "text/plain", "dataUrl": "data:text/plain;base64,YWJj"},
            ],
        }
        status, data, _ = self.request("/api/project-library", "POST", payload, pm)
        self.assertEqual(status, 200, data)
        post = data["posts"][0]
        post_path = "/api/project-library/" + post["id"]
        self.assertEqual(post["attachments"][0]["size"], 3)
        self.assertEqual(self.request("/api/project-library", token=worker)[1]["posts"][0]["messengerUrl"], payload["messengerUrl"])
        status, data, _ = self.request(post_path + "/comments", "POST", {"content": "확인했습니다."}, worker)
        self.assertEqual(status, 200)
        comment_path = post_path + "/comments/" + data["posts"][0]["comments"][0]["id"]
        self.assertEqual(self.request(post_path, "PUT", payload, worker)[0], 401)
        self.assertEqual(self.request(comment_path, "DELETE", token=worker)[0], 401)
        status, data, _ = self.request(post_path, "PUT", {**payload, "title": "시안 확정"}, admin)
        self.assertEqual(status, 200)
        self.assertEqual(data["posts"][0]["title"], "시안 확정")
        self.assertEqual(self.request(comment_path, "PUT", {"content": "승인 완료"}, admin)[0], 200)
        self.assertEqual(self.request(comment_path, "DELETE", token=admin)[1]["posts"][0]["comments"], [])
        self.assertEqual(self.request(post_path, "DELETE", token=admin)[1]["posts"], [])

    def test_library_rejects_unsafe_attachments(self):
        payload = {"mode": "private", "projectId": "test-project", "title": "첨부 검사", "content": "검증",
                   "attachments": [{"name": "script.html", "size": 3, "type": "text/html", "dataUrl": "data:text/html;base64,YWJj"}]}
        self.assertEqual(self.request("/api/project-library", "POST", payload, self.login())[0], 400)

    def test_member_creation_preserves_role_position_and_dates(self):
        admin = self.login("admin")
        payload = {"id": "new.lead@test", "name": "새 팀장", "password": self.password, "role": "team_lead",
                   "approvalStatus": "활성화", "department": "프로그램", "position": "팀장", "hireDate": "2024-02-01"}
        status, data, _ = self.request("/api/users", "POST", payload, admin)
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])
        self.assertEqual(data["user"]["role"], "team_lead")
        self.assertEqual(data["user"]["hireDate"], "2024-02-01")
        status, data, _ = self.request("/api/users/new.lead%40test", "PUT", {"role": "team_lead", "approvalStatus": "활성화", "position": "개발팀장"}, admin)
        self.assertEqual(status, 200)
        self.assertEqual(data["user"]["position"], "개발팀장")
        self.login("new.lead@test")

    def test_member_weak_password_rejected(self):
        status, data, _ = self.request("/api/users", "POST", {"id": "weak", "name": "검증", "password": "123"}, self.login("admin"))
        self.assertEqual(status, 200)
        self.assertFalse(data["ok"])

    def test_leave_calendar_department_metadata_and_admin_endpoints(self):
        admin = self.login("admin")
        status, data, _ = self.request("/api/leave-calendar?year=2026", token=admin)
        self.assertEqual(status, 200)
        self.assertIn("departments", data)
        for path in ("/api/users", "/api/departments", "/api/company-holidays", "/api/leaves?year=2026", "/api/leave-approvals?year=2026", "/api/login-logs", "/api/project-logs?page=1&pageSize=10"):
            self.assertEqual(self.request(path, token=admin)[0], 200, path)

    def test_invalid_requests_origins_and_methods(self):
        token = self.login()
        self.assertEqual(self.request("/api/projects", "PUT", {"mode": "private", "projects": []})[0], 401)
        self.assertEqual(self.request("/api/project-library")[0], 401)
        self.assertEqual(self.request("/api/authenticate", "POST", {}, headers={"HTTP_ORIGIN": "https://elsewhere.example.test"})[0], 403)
        self.assertEqual(self.request("/api/authenticate", "POST", raw=b"{")[0], 400)
        self.assertEqual(self.request("/api/authenticate", "POST", length=self.core.MAX_JSON_BODY_BYTES + 1)[0], 400)
        self.assertEqual(self.request("/api/unknown", token=token)[0], 404)
        self.assertEqual(self.request("/api/projects", "PATCH", {}, token)[0], 405)
        self.assertEqual(self.request("/", "POST", {})[0], 405)


if __name__ == "__main__":
    unittest.main(verbosity=2)
