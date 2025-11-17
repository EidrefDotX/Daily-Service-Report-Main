from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path


def ensure_database_initialized(database_path: Path) -> None:

	connection = sqlite3.connect(database_path)
	try:
		cursor = connection.cursor()

		cursor.execute(
			"""
			CREATE TABLE IF NOT EXISTS entries (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				message TEXT NOT NULL,
				created_at TEXT NOT NULL
			)
			"""
		)

		cursor.execute(
			"INSERT INTO entries (message, created_at) VALUES (?, ?)",
			("Sample row inserted by init_db.py", datetime.now(timezone.utc).isoformat(timespec="seconds") + "Z"),
		)
		connection.commit()

		cursor.execute("SELECT COUNT(*) FROM entries")
		total_rows = cursor.fetchone()[0]
		print(f"OK: Inserted 1 row into 'entries'. Total rows now: {total_rows}")
	finally:
		connection.close()


if __name__ == "__main__":
	# Use the backend-level database path to match the running app
	db_path = Path(__file__).parent.parent / "dsr.sqlite3"
	print(f"Using database: {db_path}")
	ensure_database_initialized(db_path)


