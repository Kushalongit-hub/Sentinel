def insert_user(value):
    cursor.execute("SELECT * FROM users WHERE name = '" + value + "'")
