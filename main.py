import json
import os
from datetime import datetime, timedelta

from colorama import Fore, Style, init
import bcrypt 

init(autoreset=True)

USERS_FILE = "users.json"
ATTEMPTS_FILE = "attempts.json"
LOG_FILE = "auth.log"

LOCK_THRESHOLD = 5
LOCK_DURATION_MINUTES = 10

# Banner

BANNER = f"""
{Fore.CYAN}==============================
{Fore.CYAN}     Secure Login CLI
{Fore.YELLOW}   Author: Petar Miketa
{Fore.CYAN}=============================={Style.RESET_ALL}
"""

# JSON storage

def load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}

    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read().strip()
            if not content:
                return {}
            return json.loads(content)
    except (json.JSONDecodeError, OSError):
        return {}


def save_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

# Audit logging

def log_event(event: str, username: str, status: str, reason: str = "") -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"{ts} | event={event} | user={username} | status={status}"
    if reason:
        line += f" | reason={reason}"
    line += "\n"

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)

# Password hashing

def hash_password(password: str) -> str:
    pw_bytes = password.encode("utf-8")
    hashed = bcrypt.hashpw(pw_bytes, bcrypt.gensalt())
    return hashed.decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    pw_bytes = password.encode("utf-8")
    hash_bytes = stored_hash.encode("utf-8")
    return bcrypt.checkpw(pw_bytes, hash_bytes)

# Security layer

def get_attempt_record(attempts: dict, username: str) -> dict:
    if username not in attempts:
        attempts[username] = {"fails": 0, "lock_until": None}
    return attempts[username]


def is_locked(record: dict) -> bool:
    lock_until = record.get("lock_until")
    if not lock_until:
        return False

    try:
        lock_time = datetime.fromisoformat(lock_until)
    except ValueError:
        record["lock_until"] = None
        return False

    return datetime.now() < lock_time


def lock_account(record: dict) -> None:
    until = datetime.now() + timedelta(minutes=LOCK_DURATION_MINUTES)
    record["lock_until"] = until.isoformat()

# Authentication logic

def password_policy_ok(password: str) -> tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if not any(ch.isdigit() for ch in password):
        return False, "Password must contain at least one digit."
    return True, ""


def register(users: dict, attempts: dict) -> None:
    username = input("Choose username: ").strip()

    if not username:
        print(Fore.RED + "Username cannot be empty.")
        return

    if username in users:
        print(Fore.RED + "Username already exists.")
        log_event("REGISTER", username, "FAIL", "username_exists")
        return

    password = input("Choose password: ").strip()
    ok, msg = password_policy_ok(password)
    if not ok:
        print(Fore.RED + msg)
        log_event("REGISTER", username, "FAIL", "password_policy_failed")
        return

    users[username] = {"password_hash": hash_password(password)}
    get_attempt_record(attempts, username)

    save_json(USERS_FILE, users)
    save_json(ATTEMPTS_FILE, attempts)

    print(Fore.GREEN + "Account created successfully.")
    log_event("REGISTER", username, "SUCCESS")


def login(users: dict, attempts: dict) -> None:
    username = input("Username: ").strip()
    password = input("Password: ").strip()

    if username not in users:
        print(Fore.RED + "Invalid username or password.")
        log_event("LOGIN", username, "FAIL", "user_not_found")
        return

    record = get_attempt_record(attempts, username)

    if is_locked(record):
        print(Fore.RED + "Account locked. Try again later.")
        log_event("LOGIN", username, "LOCKED", "account_locked")
        return

    stored_hash = users[username]["password_hash"]
    if verify_password(password, stored_hash):
        record["fails"] = 0
        record["lock_until"] = None
        save_json(ATTEMPTS_FILE, attempts)

        print(Fore.GREEN + "Login successful.")
        log_event("LOGIN", username, "SUCCESS")
        return

    record["fails"] += 1

    if record["fails"] >= LOCK_THRESHOLD:
        lock_account(record)
        save_json(ATTEMPTS_FILE, attempts)

        print(
            Fore.RED
            + f"Too many failed attempts. Account locked for {LOCK_DURATION_MINUTES} minutes."
        )
        log_event("LOGIN", username, "FAIL", "lock_set")
        return

    save_json(ATTEMPTS_FILE, attempts)
    remaining = LOCK_THRESHOLD - record["fails"]

    print(
        Fore.YELLOW
        + f"Invalid username or password. Attempts left before lock: {remaining}"
    )
    log_event("LOGIN", username, "FAIL", "wrong_password")

# Main loop

def main():
    print(BANNER)

    users = load_json(USERS_FILE)
    attempts = load_json(ATTEMPTS_FILE)

    while True:
        print(Fore.CYAN + "Menu: ")
        print("1) Register")
        print("2) Login")
        print("3) Exit")

        choice = input("Choose option: ").strip()

        if choice == "1":
            register(users, attempts)
            users = load_json(USERS_FILE)
            attempts = load_json(ATTEMPTS_FILE)
        elif choice == "2":
            login(users, attempts)
            attempts = load_json(ATTEMPTS_FILE)
        elif choice == "3":
            print("Bye.")
            break
        else:
            print(Fore.RED + "Invalid option.")


if __name__ == "__main__":
    main()
