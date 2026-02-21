import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional

_UNSET = object()

class JobStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    created_at TEXT,
                    status TEXT,
                    package_name TEXT,
                    apk_path TEXT,
                    aurora_mode TEXT,
                    auth_enabled INTEGER,
                    write_enabled INTEGER,
                    scan_rate REAL,
                    output_root TEXT,
                    error TEXT,
                    summary_json TEXT,
                    files_json TEXT,
                    auth_email TEXT,
                    dispenser_url TEXT,
                    device_props TEXT,
                    locale TEXT,
                    keep_apk INTEGER,
                    scan_source TEXT
                )
                """
            )
            self._ensure_column(conn, "dispenser_url", "TEXT")
            self._ensure_column(conn, "device_props", "TEXT")
            self._ensure_column(conn, "locale", "TEXT")
            self._ensure_column(conn, "keep_apk", "INTEGER DEFAULT 0")
            self._ensure_column(conn, "scan_source", "TEXT")
            conn.commit()

    @staticmethod
    def _ensure_column(conn: sqlite3.Connection, name: str, definition: str) -> None:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(jobs)")}
        if name not in columns:
            conn.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")

    def create_job(self, job: Dict[str, Any]) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT INTO jobs (
                    id, created_at, status, package_name, apk_path, aurora_mode,
                    auth_enabled, write_enabled, scan_rate, output_root, error,
                    summary_json, files_json, auth_email, dispenser_url, device_props, locale, keep_apk, scan_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job["id"],
                    job["created_at"],
                    job["status"],
                    job.get("package_name"),
                    job.get("apk_path"),
                    job.get("aurora_mode"),
                    1 if job.get("auth_enabled") else 0,
                    1 if job.get("write_enabled") else 0,
                    job.get("scan_rate"),
                    job.get("output_root"),
                    job.get("error"),
                    json.dumps(job.get("summary") or {}),
                    json.dumps(job.get("files") or []),
                    job.get("auth_email"),
                    job.get("dispenser_url"),
                    job.get("device_props"),
                    job.get("locale"),
                    1 if job.get("keep_apk") else 0,
                    job.get("scan_source"),
                ),
            )
            conn.commit()

    def update_job(
        self,
        job_id: str,
        status: Optional[str] = None,
        error: Optional[str] = None,
        summary: Optional[Dict[str, Any]] = None,
        files: Optional[List[Dict[str, Any]]] = None,
        output_root: Optional[str] = None,
        apk_path: object = _UNSET,
        keep_apk: object = _UNSET,
    ) -> None:
        fields = []
        values: List[Any] = []
        if status is not None:
            fields.append("status = ?")
            values.append(status)
        if error is not None:
            fields.append("error = ?")
            values.append(error)
        if summary is not None:
            fields.append("summary_json = ?")
            values.append(json.dumps(summary))
        if files is not None:
            fields.append("files_json = ?")
            values.append(json.dumps(files))
        if output_root is not None:
            fields.append("output_root = ?")
            values.append(output_root)
        if apk_path is not _UNSET:
            fields.append("apk_path = ?")
            values.append(apk_path)
        if keep_apk is not _UNSET:
            fields.append("keep_apk = ?")
            values.append(1 if keep_apk else 0)

        if not fields:
            return

        values.append(job_id)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(f"UPDATE jobs SET {', '.join(fields)} WHERE id = ?", values)
            conn.commit()

    def list_jobs(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                """
                SELECT id, created_at, status, package_name, apk_path, aurora_mode,
                       auth_enabled, write_enabled, scan_rate, output_root, error,
                       summary_json, files_json, auth_email, dispenser_url, device_props, locale, keep_apk,
                       scan_source
                FROM jobs
                ORDER BY created_at DESC
                """
            ).fetchall()

        return [self._row_to_job(row) for row in rows]

    def delete_job(self, job_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM jobs WHERE id = ?", (job_id,))
            conn.commit()

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                """
                SELECT id, created_at, status, package_name, apk_path, aurora_mode,
                       auth_enabled, write_enabled, scan_rate, output_root, error,
                       summary_json, files_json, auth_email, dispenser_url, device_props, locale, keep_apk,
                       scan_source
                FROM jobs
                WHERE id = ?
                """,
                (job_id,),
            ).fetchone()

        if not row:
            return None
        return self._row_to_job(row)

    @staticmethod
    def _row_to_job(row: Any) -> Dict[str, Any]:
        return {
            "id": row[0],
            "created_at": row[1],
            "status": row[2],
            "package_name": row[3],
            "apk_path": row[4],
            "aurora_mode": row[5],
            "auth_enabled": bool(row[6]),
            "write_enabled": bool(row[7]),
            "scan_rate": row[8],
            "output_root": row[9],
            "error": row[10],
            "summary": json.loads(row[11] or "{}"),
            "files": json.loads(row[12] or "[]"),
            "auth_email": row[13],
            "dispenser_url": row[14],
            "device_props": row[15],
            "locale": row[16],
            "keep_apk": bool(row[17]) if row[17] is not None else False,
            "scan_source": row[18],
        }
