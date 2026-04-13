import sqlite3


def get_db_connection() -> sqlite3.Connection:
    return sqlite3.connect("users.db")
