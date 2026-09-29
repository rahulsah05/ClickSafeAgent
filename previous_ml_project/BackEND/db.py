import sqlite3
import datetime

DB_PATH = "reports.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT,
            reporter TEXT,
            notes TEXT,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def add_report(url: str, reporter: str, notes: str | None):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    cur.execute("""
        INSERT INTO reports (url, reporter, notes, created_at)
        VALUES (?, ?, ?, ?)
    """, (url, reporter, notes, datetime.datetime.now().isoformat()))
    
    conn.commit()
    report_id = cur.lastrowid
    conn.close()
    
    return report_id

