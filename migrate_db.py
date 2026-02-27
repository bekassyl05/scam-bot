# migrate_db.py
import sqlite3
DB = "scam.db"

required_columns = {
    "url": "TEXT",
    "domain": "TEXT",
    "reported_by": "TEXT",
    "source": "TEXT",
    "file_type": "TEXT",
    "file_name": "TEXT",
    "ocr_text": "TEXT",
    "analysis_details": "TEXT",
    "confidence": "REAL",
    "created_at": "DATETIME"
}

conn = sqlite3.connect(DB)
cur = conn.cursor()

cur.execute("PRAGMA table_info(reports);")
rows = cur.fetchall()
existing = [r[1] for r in rows]

added = []
for col, coltype in required_columns.items():
    if col not in existing:
        sql = f"ALTER TABLE reports ADD COLUMN {col} {coltype};"
        print("Executing:", sql)
        try:
            cur.execute(sql)
            added.append(col)
        except Exception as e:
            print("Failed to add column", col, ":", e)

conn.commit()
conn.close()
print("Migration done. Added columns:", added)
