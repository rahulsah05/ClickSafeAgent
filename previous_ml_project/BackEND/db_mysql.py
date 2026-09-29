import mysql.connector
from datetime import datetime

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="clicksafe"
    )

def add_report(url, reporter, notes):
    conn = get_connection()
    cursor = conn.cursor()

    query = """
        INSERT INTO reports (url, reporter, notes, created_at)
        VALUES (%s, %s, %s, %s)
    """
    timestamp = datetime.now()

    cursor.execute(query, (url, reporter, notes, timestamp))
    conn.commit()

    insert_id = cursor.lastrowid

    cursor.close()
    conn.close()

    return insert_id
