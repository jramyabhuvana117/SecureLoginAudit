# =============================================================================
# SECURE LOGIN SYSTEM - CodeAlpha Cybersecurity Internship Project
# Author: Ramya
# Description: A secure Python login system that fixes common vulnerabilities
#              found in vulnerable_login.py
# =============================================================================

import sqlite3      # For database operations
import bcrypt       # For secure password hashing
import re           # For input validation using regex
import time         # For login attempt delay (brute-force protection)

# =============================================================================
# DATABASE SETUP
# =============================================================================

def init_database():
    """
    Creates the users table if it doesn't exist.
    Passwords are stored as HASHED values — never plain text!
    """
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    print("[✔] Database initialized successfully.")


# =============================================================================
# INPUT VALIDATION
# =============================================================================

def is_valid_username(username):
    """
    FIX: Input Validation
    - Username must be 3–20 characters
    - Only allows letters, numbers, and underscores
    - Prevents special characters that could be used in attacks
    """
    if not username or len(username) < 3 or len(username) > 20:
        return False
    # Only allow alphanumeric characters and underscores
    return bool(re.match(r"^[a-zA-Z0-9_]+$", username))


def is_valid_password(password):
    """
    FIX: Input Validation
    - Password must be at least 8 characters
    - Must include uppercase, lowercase, digit, and special character
    """
    if not password or len(password) < 8:
        return False
    has_upper   = bool(re.search(r"[A-Z]", password))
    has_lower   = bool(re.search(r"[a-z]", password))
    has_digit   = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password))
    return has_upper and has_lower and has_digit and has_special


# =============================================================================
# PASSWORD HASHING
# =============================================================================

def hash_password(plain_password):
    """
    FIX: Secure Password Hashing using bcrypt
    - bcrypt automatically adds a 'salt' (random data) to each hash
    - Even if two users have the same password, their hashes will be different
    - Never store plain text passwords!
    """
    # Encode the password to bytes, then hash it
    hashed = bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")  # Store as string in database


def verify_password(plain_password, stored_hash):
    """
    Verifies entered password against the stored bcrypt hash.
    bcrypt.checkpw() safely compares without exposing the hash.
    """
    return bcrypt.checkpw(
        plain_password.encode("utf-8"),
        stored_hash.encode("utf-8")
    )


# =============================================================================
# USER REGISTRATION
# =============================================================================

def register_user(username, password):
    """
    Registers a new user with:
    - Input validation
    - Secure password hashing
    - Parameterized SQL queries (prevents SQL Injection)
    """

    # Step 1: Validate inputs
    if not is_valid_username(username):
        print("[✘] Invalid username! Use 3–20 characters (letters, numbers, underscores only).")
        return False

    if not is_valid_password(password):
        print("[✘] Weak password! Must be 8+ chars with uppercase, lowercase, digit & special character.")
        return False

    # Step 2: Hash the password before storing
    password_hash = hash_password(password)

    # Step 3: FIX - Use parameterized query (prevents SQL Injection)
    # BAD  (vulnerable): f"INSERT INTO users VALUES ('{username}', '{password}')"
    # GOOD (secure):     Use ? placeholders — database handles escaping
    try:
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            (username, password_hash)   # ← Values passed separately, not in the query string
        )

        conn.commit()
        conn.close()
        print(f"[✔] User '{username}' registered successfully!")
        return True

    except sqlite3.IntegrityError:
        print(f"[✘] Username '{username}' already exists. Choose a different one.")
        return False


# =============================================================================
# USER LOGIN
# =============================================================================

# Track failed login attempts per username {username: [attempt_count, last_attempt_time]}
failed_attempts = {}
MAX_ATTEMPTS    = 5     # Max allowed failed attempts
LOCKOUT_TIME    = 30    # Lockout duration in seconds

def login_user(username, password):
    """
    Authenticates a user with:
    - Input validation
    - Parameterized SQL queries (prevents SQL Injection)
    - Secure password comparison using bcrypt
    - Brute-force protection (account lockout after 5 failed attempts)
    """

    # Step 1: Validate inputs
    if not is_valid_username(username):
        print("[✘] Invalid username format.")
        return False

    if not password:
        print("[✘] Password cannot be empty.")
        return False

    # Step 2: Brute-force protection — check if account is locked
    if username in failed_attempts:
        attempts, last_time = failed_attempts[username]
        if attempts >= MAX_ATTEMPTS:
            elapsed = time.time() - last_time
            if elapsed < LOCKOUT_TIME:
                wait = int(LOCKOUT_TIME - elapsed)
                print(f"[✘] Account locked! Too many failed attempts. Try again in {wait} seconds.")
                return False
            else:
                # Reset after lockout period
                failed_attempts[username] = [0, time.time()]

    # Step 3: FIX - Use parameterized query (prevents SQL Injection)
    # BAD  (vulnerable): f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    # GOOD (secure):     Use ? placeholder — user input never touches the query string
    conn   = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT password_hash FROM users WHERE username = ?",
        (username,)   # ← Tuple with username, passed separately
    )

    row = cursor.fetchone()
    conn.close()

    # Step 4: Verify password using bcrypt
    if row and verify_password(password, row[0]):
        # Login successful — reset failed attempts
        failed_attempts[username] = [0, time.time()]
        print(f"[✔] Welcome, {username}! Login successful.")
        return True
    else:
        # Login failed — increment attempt counter
        if username not in failed_attempts:
            failed_attempts[username] = [0, time.time()]
        failed_attempts[username][0] += 1
        failed_attempts[username][1]  = time.time()

        remaining = MAX_ATTEMPTS - failed_attempts[username][0]
        print(f"[✘] Invalid username or password. {remaining} attempts remaining.")
        return False


# =============================================================================
# MAIN MENU
# =============================================================================

def main():
    """
    Simple command-line interface to test the secure login system.
    """
    init_database()

    print("\n" + "="*50)
    print("   SECURE LOGIN SYSTEM — CodeAlpha Internship")
    print("="*50)

    while True:
        print("\nOptions:")
        print("  1. Register")
        print("  2. Login")
        print("  3. Exit")

        choice = input("\nEnter choice (1/2/3): ").strip()

        if choice == "1":
            print("\n--- REGISTER ---")
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            register_user(username, password)

        elif choice == "2":
            print("\n--- LOGIN ---")
            username = input("Enter username: ").strip()
            password = input("Enter password: ").strip()
            login_user(username, password)

        elif choice == "3":
            print("\n[✔] Exiting. Stay secure! 🔐")
            break

        else:
            print("[✘] Invalid choice. Enter 1, 2, or 3.")


# Run the program
if __name__ == "__main__":
    main()