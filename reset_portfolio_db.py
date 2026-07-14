from __future__ import annotations

import shutil
from datetime import datetime
from pathlib import Path

import sqlite_server as app


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "projects.sqlite3"
BACKUP_DIR = BASE_DIR / "db_backups"


def count_rows(conn, table: str) -> int:
    row = conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
    return int(row["count"])


def main() -> None:
    if not DB_PATH.exists():
        raise SystemExit(f"DB file not found: {DB_PATH}")

    BACKUP_DIR.mkdir(exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = BACKUP_DIR / f"projects.real.backup.{stamp}.sqlite3"
    shutil.copy2(DB_PATH, backup_path)

    app.ensure_db()
    with app.connect() as conn:
        admin_row = conn.execute(
            "SELECT * FROM users_secure WHERE id_lookup = ?",
            (app.id_lookup(app.DEFAULT_ADMIN_ID),),
        ).fetchone()
        preserved_admin = app.public_user(admin_row) if admin_row else None
        preserved_admin_password = admin_row["password"] if admin_row else None

        before = {
            "project_records": count_rows(conn, "project_records"),
            "admin_project_records": count_rows(conn, "admin_project_records"),
            "login_logs": count_rows(conn, "login_logs"),
            "project_logs": count_rows(conn, "project_logs"),
            "leave_requests": count_rows(conn, "leave_requests"),
            "users_secure": count_rows(conn, "users_secure"),
        }

        conn.execute("DELETE FROM leave_requests")
        conn.execute("DELETE FROM leave_balances")
        conn.execute("DELETE FROM company_holidays")
        conn.execute("DELETE FROM project_logs")
        conn.execute("DELETE FROM login_logs")
        conn.execute("DELETE FROM admin_project_records")
        conn.execute("DELETE FROM project_records")
        conn.execute("DELETE FROM datasets")
        conn.execute("DELETE FROM app_state")
        conn.execute("DELETE FROM users_secure")
        conn.execute("DELETE FROM departments")

        for department in app.DEFAULT_DEPARTMENTS:
            conn.execute("INSERT OR IGNORE INTO departments (name) VALUES (?)", (department,))

        if preserved_admin and preserved_admin_password:
            app.upsert_secure_user(
                conn,
                preserved_admin["id"],
                preserved_admin_password,
                preserved_admin.get("name", "관리자"),
                "admin",
                "활성화",
                preserved_admin.get("department") or app.DEFAULT_DEPARTMENTS[0],
            )

        demo_user = {
            "id": "demo",
            "name": "데모 관리자",
            "role": "admin",
            "approvalStatus": "활성화",
            "department": app.DEFAULT_DEPARTMENTS[0],
        }
        app.upsert_secure_user(
            conn,
            "demo",
            app.hash_password("demo"),
            demo_user["name"],
            "admin",
            "활성화",
            demo_user["department"],
        )
        app.insert_projects(conn, "private", app.SAMPLE_PROJECTS)
        app.insert_admin_projects(conn, "private", [])
        app.create_leave_request(
            conn,
            demo_user,
            {
                "userId": "demo",
                "startDate": "2026-07-15",
                "endDate": "2026-07-15",
                "type": "연차",
                "days": 1,
                "reason": "포트폴리오 샘플 연차",
            },
        )
        request_id = conn.execute("SELECT MAX(id) AS id FROM leave_requests").fetchone()["id"]
        app.update_leave_status(conn, request_id, "approved", demo_user)
        conn.execute(
            "INSERT OR IGNORE INTO company_holidays (date, title, created_by_enc) VALUES (?, ?, ?)",
            ("2026-07-31", "회사 자체 휴일 샘플", app.encrypt_text("demo")),
        )

        conn.commit()

        after = {
            "project_records": count_rows(conn, "project_records"),
            "admin_project_records": count_rows(conn, "admin_project_records"),
            "login_logs": count_rows(conn, "login_logs"),
            "project_logs": count_rows(conn, "project_logs"),
            "leave_requests": count_rows(conn, "leave_requests"),
            "users_secure": count_rows(conn, "users_secure"),
        }

    print(f"Backup saved: {backup_path}")
    print(f"Before: {before}")
    print(f"After: {after}")
    print("Portfolio DB reset complete. Only demo/sample data remains.")


if __name__ == "__main__":
    main()
