from database import get_db_connection


def init_db() -> None:
    connection = get_db_connection()
    try:
        cursor = connection.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
            """
        )
        connection.commit()
    finally:
        connection.close()


if __name__ == "__main__":
    init_db()
