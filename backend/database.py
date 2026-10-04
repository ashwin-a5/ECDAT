import sqlite3
from pathlib import Path


DATABASE_PATH = Path("ecdat.db")


def get_connection():
    """Create a connection to the SQLite database."""
    connection = sqlite3.connect(DATABASE_PATH)

    connection.row_factory = sqlite3.Row

    return connection


def initialize_database():
    """Create all required database tables."""
    connection = get_connection()

    # Store one record for every scan.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            directory TEXT NOT NULL,
            files_scanned INTEGER NOT NULL,
            total_findings INTEGER NOT NULL,
            critical INTEGER NOT NULL,
            high INTEGER NOT NULL,
            medium INTEGER NOT NULL,
            low INTEGER NOT NULL,
            info INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    # Store individual findings belonging to scans.
    connection.execute(
        """
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            file TEXT NOT NULL,
            line INTEGER NOT NULL,
            matched_text TEXT NOT NULL,
            rule_id TEXT NOT NULL,
            category TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            confidence TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """
    )

    connection.commit()
    connection.close()


def create_scan(directory: str, summary: dict) -> int:
    """Create a scan history record and return its ID."""
    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO scans (
            directory,
            files_scanned,
            total_findings,
            critical,
            high,
            medium,
            low,
            info,
            risk_score
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            directory,
            summary.get("files_scanned", 0),
            summary.get("total_findings", 0),
            summary.get("critical", 0),
            summary.get("high", 0),
            summary.get("medium", 0),
            summary.get("low", 0),
            summary.get("info", 0),
            summary.get("total_risk_score", 0),
        ),
    )

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    return scan_id


def save_findings(findings: list[dict], scan_id: int):
    """Save findings and associate them with a scan."""
    connection = get_connection()

    for finding in findings:
        connection.execute(
            """
            INSERT INTO findings (
                scan_id,
                file,
                line,
                matched_text,
                rule_id,
                category,
                severity,
                title,
                description,
                recommendation,
                confidence,
                risk_score
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                finding["file"],
                finding["line"],
                finding["matched_text"],
                finding["rule_id"],
                finding["category"],
                finding["severity"],
                finding["title"],
                finding["description"],
                finding["recommendation"],
                finding["confidence"],
                finding["risk_score"],
            ),
        )

    connection.commit()
    connection.close()


def get_scan_history(limit: int = 20) -> list[dict]:
    """Return recent scan history."""
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            directory,
            files_scanned,
            total_findings,
            critical,
            high,
            medium,
            low,
            info,
            risk_score,
            scan_time
        FROM scans
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


def get_scan(scan_id: int):
    """Return one scan record."""
    connection = get_connection()

    row = connection.execute(
        """
        SELECT
            id,
            directory,
            files_scanned,
            total_findings,
            critical,
            high,
            medium,
            low,
            info,
            risk_score,
            scan_time
        FROM scans
        WHERE id = ?
        """,
        (scan_id,),
    ).fetchone()

    connection.close()

    return dict(row) if row else None


def get_findings_for_scan(scan_id: int) -> list[dict]:
    """Return all findings belonging to a scan."""
    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            scan_id,
            file,
            line,
            matched_text,
            rule_id,
            category,
            severity,
            title,
            description,
            recommendation,
            confidence,
            risk_score,
            created_at
        FROM findings
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]
