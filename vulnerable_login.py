import sqlite3

conn = sqlite3.connect("users.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    username TEXT,
    password TEXT
)
""")

cursor.execute("INSERT INTO users VALUES ('admin', '1234')")
conn.commit()

print("=== Vulnerable Login System ===")

username = input("Enter username: ")
password = input("Enter password: ")

query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"

print(query)

cursor.execute(query)

result = cursor.fetchone()

if result:
    print("Login Successful")
else:
    print("Invalid Credentials")

conn.close()