import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, List
from core.base_module import ModuleResult

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
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
