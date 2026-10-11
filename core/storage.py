import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, List
from core.base_module import ModuleResult, Finding

FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL REFERENCES execution_results(id),
    module_name   TEXT NOT NULL,
    target        TEXT NOT NULL,
    claim         TEXT NOT NULL,
    tag           TEXT NOT NULL,          -- OBSERVED | INFERRED | ASSUMED
    method        TEXT NOT NULL,          -- how it was observed
    evidence_json TEXT NOT NULL,          -- raw evidence pointer
    observed_date TEXT NOT NULL,          -- intelligence rots: everything dated
    confidence    TEXT NOT NULL,          -- VERIFIED..LEAD
    quarantined   INTEGER NOT NULL DEFAULT 0,
    burned        INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS findings_run    ON findings(run_id);
CREATE INDEX IF NOT EXISTS findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS findings_conf   ON findings(confidence);
"""

class StorageEngine:
    def __init__(self, db_path: str = "results.db"):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS execution_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    module_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    status TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    errors_json TEXT NOT NULL
                )
            """)
            cursor.executescript(FINDINGS_SCHEMA)
            conn.commit()

    def save_result(self, result: ModuleResult) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO execution_results
                (module_name, target, timestamp, status, data_json, errors_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    result.module_name,
                    result.target,
                    result.timestamp,
                    result.status,
                    json.dumps(result.data),
                    json.dumps(result.errors)
                )
            )
            conn.commit()
            return cursor.lastrowid

    def save_findings(self, result: ModuleResult, run_id: int) -> int:
        """Persist evidence-chained findings alongside the run record.
        Findings live next to data, never replace it."""
        count = 0
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for f in result.findings:
                fd = f.to_dict() if isinstance(f, Finding) else dict(f)
                cursor.execute(
                    """
                    INSERT INTO findings
                    (run_id, module_name, target, claim, tag, method,
                     evidence_json, observed_date, confidence,
                     quarantined, burned, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        fd.get("module_name", result.module_name),
                        fd.get("target", result.target),
                        fd.get("claim", ""),
                        fd.get("tag", "OBSERVED"),
                        fd.get("method", ""),
                        json.dumps(fd.get("evidence", {})),
                        fd.get("observed_date", ""),
                        fd.get("confidence", "LEAD"),
                        1 if fd.get("quarantined") else 0,
                        1 if fd.get("burned") else 0,
                        datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    ),
                )
                count += 1
            conn.commit()
        return count

    def fetch_findings(self, run_id: int = None, target: str = None) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            q = "SELECT * FROM findings"
            clauses, params = [], []
            if run_id is not None:
                clauses.append("run_id = ?"); params.append(run_id)
            if target is not None:
                clauses.append("target = ?"); params.append(target)
            if clauses:
                q += " WHERE " + " AND ".join(clauses)
            q += " ORDER BY id"
            cursor.execute(q, params)
            rows = cursor.fetchall()
            out = []
            for row in rows:
                item = dict(row)
                item["evidence"] = json.loads(item.pop("evidence_json"))
                item["quarantined"] = bool(item["quarantined"])
                item["burned"] = bool(item["burned"])
                out.append(item)
            return out

    def fetch_all(self) -> List[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM execution_results ORDER BY id DESC")
            rows = cursor.fetchall()
            results = []
            for row in rows:
                item = dict(row)
                item["data"] = json.loads(item["data_json"])
                item["errors"] = json.loads(item["errors_json"])
                del item["data_json"]
                del item["errors_json"]
                results.append(item)
            return results

    def export_json(self, output_file: str = "export.json") -> None:
        data = self.fetch_all()
        for item in data:
            # Evidence chains travel with the run record.
            item["findings"] = self.fetch_findings(run_id=item["id"])
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
