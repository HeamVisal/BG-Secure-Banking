import os
import random
import sqlite3
import uuid
from datetime import datetime, timedelta


DATA_DIR = os.environ.get("DATA_DIR", ".")
DB_NAME = os.path.join(DATA_DIR, "banking.db")


def now_text():
    return datetime.utcnow().isoformat()


def get_connection():
    os.makedirs(DATA_DIR, exist_ok=True)
    connection = sqlite3.connect(DB_NAME, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    return connection


def _columns(cursor, table_name):
    cursor.execute(f"PRAGMA table_info({table_name})")
    return {row["name"] for row in cursor.fetchall()}


def _add_column(cursor, table_name, column_name, column_definition):
    if column_name not in _columns(cursor, table_name):
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}")


def generate_account_number():
    return f"AC{datetime.utcnow().year}{random.randint(100000, 999999)}"


def generate_transaction_id():
    return f"TX{datetime.utcnow().strftime('%Y%m%d')}{uuid.uuid4().hex[:10].upper()}"


def init_db():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            action_password_hash TEXT,
            role TEXT DEFAULT 'customer',
            status TEXT DEFAULT 'active',
            created_at TEXT,
            last_login TEXT
        )
        """
    )
    _add_column(cursor, "users", "action_password_hash", "TEXT")
    _add_column(cursor, "users", "role", "TEXT DEFAULT 'customer'")
    _add_column(cursor, "users", "status", "TEXT DEFAULT 'active'")
    _add_column(cursor, "users", "last_login", "TEXT")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS customer_profiles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            full_name TEXT,
            gender TEXT,
            date_of_birth TEXT,
            phone_number TEXT,
            email TEXT,
            profile_picture TEXT,
            national_id TEXT,
            address TEXT,
            city TEXT,
            country TEXT,
            occupation TEXT,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    _add_column(cursor, "customer_profiles", "profile_picture", "TEXT")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_number TEXT UNIQUE,
            username TEXT UNIQUE,
            account_type TEXT DEFAULT 'Savings',
            balance REAL DEFAULT 0,
            currency TEXT DEFAULT 'USD',
            status TEXT DEFAULT 'active',
            daily_transfer_limit REAL DEFAULT 1000,
            created_at TEXT,
            updated_at TEXT
        )
        """
    )
    _add_column(cursor, "accounts", "account_number", "TEXT")
    _add_column(cursor, "accounts", "account_type", "TEXT DEFAULT 'Savings'")
    _add_column(cursor, "accounts", "currency", "TEXT DEFAULT 'USD'")
    _add_column(cursor, "accounts", "status", "TEXT DEFAULT 'active'")
    _add_column(cursor, "accounts", "daily_transfer_limit", "REAL DEFAULT 1000")
    _add_column(cursor, "accounts", "updated_at", "TEXT")

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            transaction_id TEXT UNIQUE,
            username TEXT,
            account_number TEXT,
            transaction_type TEXT,
            amount REAL,
            currency TEXT,
            receiver_username TEXT,
            receiver_account_number TEXT,
            balance_before REAL,
            balance_after REAL,
            status TEXT,
            fraud_flag INTEGER,
            risk_score INTEGER,
            reason TEXT,
            created_at TEXT
        )
        """
    )
    for name, definition in {
        "transaction_id": "TEXT",
        "account_number": "TEXT",
        "currency": "TEXT DEFAULT 'USD'",
        "receiver_account_number": "TEXT",
        "balance_before": "REAL DEFAULT 0",
        "balance_after": "REAL DEFAULT 0",
        "risk_score": "INTEGER DEFAULT 0",
    }.items():
        _add_column(cursor, "transactions", name, definition)

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            action TEXT,
            details TEXT,
            ip_address TEXT,
            created_at TEXT
        )
        """
    )

    cursor.execute("UPDATE users SET role = 'customer' WHERE role IS NULL")
    cursor.execute("UPDATE users SET status = 'active' WHERE status IS NULL")
    cursor.execute("UPDATE accounts SET account_type = 'Savings' WHERE account_type IS NULL")
    cursor.execute("UPDATE accounts SET currency = 'USD' WHERE currency IS NULL")
    cursor.execute("UPDATE accounts SET status = 'active' WHERE status IS NULL")
    cursor.execute("UPDATE accounts SET daily_transfer_limit = 1000 WHERE daily_transfer_limit IS NULL")
    cursor.execute("SELECT id FROM accounts WHERE account_number IS NULL OR account_number = ''")
    for row in cursor.fetchall():
        cursor.execute("UPDATE accounts SET account_number = ?, updated_at = ? WHERE id = ?", (generate_account_number(), now_text(), row["id"]))
    cursor.execute(
        """
        SELECT users.username
        FROM users
        LEFT JOIN accounts ON users.username = accounts.username
        WHERE accounts.username IS NULL
        """
    )
    for row in cursor.fetchall():
        created_at = now_text()
        cursor.execute(
            """
            INSERT INTO accounts
            (account_number, username, account_type, balance, currency, status,
             daily_transfer_limit, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (generate_account_number(), row["username"], "Savings", 0.0, "USD", "active", 1000.0, created_at, created_at),
        )
    cursor.execute(
        """
        INSERT OR IGNORE INTO customer_profiles
        (username, full_name, gender, date_of_birth, phone_number, email, profile_picture, national_id,
         address, city, country, occupation, created_at, updated_at)
        SELECT username, username, '', '', '', '', '', '', '', '', '', '', ?, ?
        FROM users
        """,
        (now_text(), now_text()),
    )

    connection.commit()
    connection.close()


def create_user(username, password_hash, action_password_hash, role="customer", status="active"):
    try:
        connection = get_connection()
        cursor = connection.cursor()
        cursor.execute(
            """
            INSERT INTO users (username, password_hash, action_password_hash, role, status, created_at, last_login)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (username, password_hash, action_password_hash, role, status, now_text(), None),
        )
        connection.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        connection.close()


def get_user(username):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    connection.close()
    return dict(user) if user else None


def update_last_login(username):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", (now_text(), username))
    connection.commit()
    connection.close()


def create_customer_profile(username, profile_data):
    connection = get_connection()
    cursor = connection.cursor()
    created_at = now_text()
    cursor.execute(
        """
        INSERT INTO customer_profiles
        (username, full_name, gender, date_of_birth, phone_number, email, profile_picture, national_id,
         address, city, country, occupation, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username,
            profile_data.get("full_name", ""),
            profile_data.get("gender", ""),
            profile_data.get("date_of_birth", ""),
            profile_data.get("phone_number", ""),
            profile_data.get("email", ""),
            profile_data.get("profile_picture", ""),
            profile_data.get("national_id", ""),
            profile_data.get("address", ""),
            profile_data.get("city", ""),
            profile_data.get("country", ""),
            profile_data.get("occupation", ""),
            created_at,
            created_at,
        ),
    )
    connection.commit()
    connection.close()


def get_customer_profile(username):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM customer_profiles WHERE username = ?", (username,))
    profile = cursor.fetchone()
    connection.close()
    return dict(profile) if profile else None


def update_customer_profile(username, profile_data):
    allowed = ["full_name", "phone_number", "email", "address", "city", "country", "occupation", "profile_picture"]
    values = [profile_data.get(field, "") for field in allowed]
    connection = get_connection()
    cursor = connection.cursor()
    if not get_customer_profile(username):
        created_at = now_text()
        cursor.execute(
            """
            INSERT OR IGNORE INTO customer_profiles
            (username, full_name, gender, date_of_birth, phone_number, email, profile_picture,
             national_id, address, city, country, occupation, created_at, updated_at)
            VALUES (?, ?, '', '', ?, ?, ?, '', ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                profile_data.get("full_name", username),
                profile_data.get("phone_number", ""),
                profile_data.get("email", ""),
                profile_data.get("profile_picture", ""),
                profile_data.get("address", ""),
                profile_data.get("city", ""),
                profile_data.get("country", ""),
                profile_data.get("occupation", ""),
                created_at,
                created_at,
            ),
        )
    cursor.execute(
        """
        UPDATE customer_profiles
        SET full_name = ?, phone_number = ?, email = ?, address = ?, city = ?,
            country = ?, occupation = ?,
            profile_picture = COALESCE(NULLIF(?, ''), profile_picture),
            updated_at = ?
        WHERE username = ?
        """,
        (*values, now_text(), username),
    )
    connection.commit()
    changed = cursor.rowcount > 0
    connection.close()
    return changed


def create_account(username, account_type="Savings"):
    try:
        connection = get_connection()
        cursor = connection.cursor()
        created_at = now_text()
        cursor.execute(
            """
            INSERT INTO accounts
            (account_number, username, account_type, balance, currency, status,
             daily_transfer_limit, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (generate_account_number(), username, account_type, 0.0, "USD", "active", 1000.0, created_at, created_at),
        )
        connection.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        connection.close()


def get_account(username):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
    account = cursor.fetchone()
    connection.close()
    return dict(account) if account else None


def get_balance(username):
    account = get_account(username)
    return float(account["balance"]) if account else None


def update_balance(username, new_balance):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE accounts SET balance = ?, updated_at = ? WHERE username = ?",
        (new_balance, now_text(), username),
    )
    connection.commit()
    changed = cursor.rowcount > 0
    connection.close()
    return changed


def add_transaction(
    username,
    transaction_type,
    amount,
    receiver_username,
    status,
    fraud_flag,
    reason,
    account_number=None,
    currency="USD",
    receiver_account_number=None,
    balance_before=0,
    balance_after=0,
    risk_score=0,
):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO transactions
        (transaction_id, username, account_number, transaction_type, amount, currency,
         receiver_username, receiver_account_number, balance_before, balance_after,
         status, fraud_flag, risk_score, reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            generate_transaction_id(),
            username,
            account_number,
            transaction_type,
            float(amount),
            currency,
            receiver_username,
            receiver_account_number,
            float(balance_before),
            float(balance_after),
            status,
            int(fraud_flag),
            int(risk_score),
            reason,
            now_text(),
        ),
    )
    connection.commit()
    transaction_row_id = cursor.lastrowid
    connection.close()
    return transaction_row_id


def get_transactions(username, limit=None):
    connection = get_connection()
    cursor = connection.cursor()
    sql = "SELECT * FROM transactions WHERE username = ? ORDER BY created_at DESC"
    params = [username]
    if limit:
        sql += " LIMIT ?"
        params.append(limit)
    cursor.execute(sql, params)
    rows = cursor.fetchall()
    connection.close()
    return [dict(row) for row in rows]


def get_recent_transactions(username, minutes=1):
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT * FROM transactions
        WHERE username = ? AND created_at >= ?
        ORDER BY created_at DESC
        """,
        (username, since),
    )
    rows = cursor.fetchall()
    connection.close()
    return [dict(row) for row in rows]


def get_average_transaction_amount(username):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT AVG(amount) AS average_amount
        FROM transactions
        WHERE username = ? AND status = 'success' AND amount > 0
        """,
        (username,),
    )
    row = cursor.fetchone()
    connection.close()
    return float(row["average_amount"]) if row and row["average_amount"] is not None else 0.0


def count_recent_receivers(username, minutes=5):
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT COUNT(DISTINCT receiver_username) AS receiver_count
        FROM transactions
        WHERE username = ?
          AND transaction_type = 'TRANSFER_OUT'
          AND receiver_username IS NOT NULL
          AND created_at >= ?
        """,
        (username, since),
    )
    row = cursor.fetchone()
    connection.close()
    return int(row["receiver_count"]) if row else 0


def get_daily_transfer_total(username):
    since = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT COALESCE(SUM(amount), 0) AS total
        FROM transactions
        WHERE username = ?
          AND transaction_type = 'TRANSFER_OUT'
          AND status = 'success'
          AND created_at >= ?
        """,
        (username, since),
    )
    row = cursor.fetchone()
    connection.close()
    return float(row["total"]) if row else 0.0


def trust_suspicious_transactions(username):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        UPDATE transactions
        SET fraud_flag = 0,
            risk_score = 0,
            reason = CASE
                WHEN reason IS NULL OR reason = '' THEN 'Trusted by customer review'
                ELSE reason || '; Trusted by customer review'
            END
        WHERE username = ? AND (fraud_flag = 1 OR risk_score > 0)
        """,
        (username,),
    )
    changed = cursor.rowcount
    connection.commit()
    connection.close()
    return changed


def count_transactions(username):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM transactions WHERE username = ?", (username,))
    row = cursor.fetchone()
    connection.close()
    return int(row["total"]) if row else 0


def add_audit_log(username, action, details="", ip_address="RPC"):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        INSERT INTO audit_logs (username, action, details, ip_address, created_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (username, action, details, ip_address, now_text()),
    )
    connection.commit()
    connection.close()


def get_audit_logs(username, limit=50):
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        """
        SELECT * FROM audit_logs
        WHERE username = ?
        ORDER BY created_at DESC
        LIMIT ?
        """,
        (username, limit),
    )
    rows = cursor.fetchall()
    connection.close()
    return [dict(row) for row in rows]
