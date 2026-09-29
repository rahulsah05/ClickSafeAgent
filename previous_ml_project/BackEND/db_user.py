import mysql.connector

def get_connection():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="clicksafe"
    )

def create_user(name, mobile):
    conn = get_connection()
    cursor = conn.cursor()

    query = "INSERT INTO users (name, mobile) VALUES (%s, %s)"
    cursor.execute(query, (name, mobile))
    conn.commit()

    user_id = cursor.lastrowid

    cursor.close()
    conn.close()
    return user_id

def get_user(mobile):
    conn = get_connection()
    cursor = conn.cursor()

    query = "SELECT id, name, mobile FROM users WHERE mobile=%s"
    cursor.execute(query, (mobile,))
    user = cursor.fetchone()

    cursor.close()
    conn.close()
    return user
