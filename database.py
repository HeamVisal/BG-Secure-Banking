import os
import random
import sqlite3
import uuid
from datetime import datetime, timedelta

from app_logging import get_logger, log_event, log_full_details


logger = get_logger("DB")


DATA_DIR = os.environ.get("DATA_DIR", ".")
DB_NAME = os.path.join(DATA_DIR, "banking.db")


def now_text():
    return datetime.utcnow().isoformat()


def get_connection():
    os.makedirs(DATA_DIR, exist_ok=True)
    if log_full_details():
        log_event(logger, "db_connection_open", path=DB_NAME)
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


def _transaction_log_fields(transactions):
    if log_full_details():
        return {"transactions": transactions}

    latest = transactions[0] if transactions else None
    return {
        "latest_transaction": _transaction_summary(latest) if latest else {},
    }


def _transaction_summary(transaction):
    return {
        "transaction_id": transaction.get("transaction_id"),
        "type": transaction.get("transaction_type"),
        "amount": transaction.get("amount"),
        "status": transaction.get("status"),
        "risk_score": transaction.get("risk_score"),
        "fraud_flag": transaction.get("fraud_flag"),
    }


def _profile_summary(profile):
    return {
        "full_name": profile.get("full_name"),
        "email": profile.get("email"),
        "city": profile.get("city"),
        "country": profile.get("country"),
    }


def _account_summary(account):
    return {
        "account_number": account.get("account_number"),
        "type": account.get("account_type"),
        "balance": account.get("balance"),
        "currency": account.get("currency"),
        "status": account.get("status"),
    }


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
        account_number = generate_account_number()
        log_event(logger, "account_number_generated", user=row["username"], account_number=account_number, source="init_db_missing_account_backfill")
        cursor.execute(
            """
            INSERT INTO accounts
            (account_number, username, account_type, balance, currency, status,
             daily_transfer_limit, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (account_number, row["username"], "Savings", 0.0, "USD", "active", 1000.0, created_at, created_at),
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
    log_event(logger, "database_initialized", path=DB_NAME)


def create_user(username, password_hash, action_password_hash, role="customer", status="active"):
    try:
        log_event(logger, "db_write_start", table="users", operation="INSERT", user=username, role=role, status=status)
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
        log_event(logger, "db_write_commit", table="users", operation="INSERT", user=username, row_id=cursor.lastrowid)
        log_event(logger, "user_created", user=username, role=role, status=status)
        return True
    except sqlite3.IntegrityError:
        log_event(logger, "user_create_failed", user=username, reason="duplicate")
        return False
    finally:
        connection.close()


def get_user(username):
    if log_full_details():
        log_event(logger, "db_read_start", table="users", operation="SELECT_BY_USERNAME", user=username)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    connection.close()
    result = dict(user) if user else None
    log_event(logger, "user_loaded", user=username, found=bool(result), role=result.get("role") if result else None, status=result.get("status") if result else None)
    return result


def update_last_login(username):
    timestamp = now_text()
    log_event(logger, "db_write_start", table="users", operation="UPDATE_LAST_LOGIN", user=username, last_login=timestamp)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("UPDATE users SET last_login = ? WHERE username = ?", (timestamp, username))
    changed = cursor.rowcount
    connection.commit()
    connection.close()
    log_event(logger, "db_write_commit", table="users", operation="UPDATE_LAST_LOGIN", user=username, changed=changed)


def create_customer_profile(username, profile_data):
    log_event(logger, "db_write_start", table="customer_profiles", operation="INSERT", user=username, profile_data=profile_data)
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
    row_id = cursor.lastrowid
    connection.close()
    log_event(logger, "db_write_commit", table="customer_profiles", operation="INSERT", user=username, row_id=row_id)
    log_event(logger, "profile_created", user=username)


def get_customer_profile(username):
    if log_full_details():
        log_event(logger, "db_read_start", table="customer_profiles", operation="SELECT_BY_USERNAME", user=username)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM customer_profiles WHERE username = ?", (username,))
    profile = cursor.fetchone()
    connection.close()
    result = dict(profile) if profile else None
    log_event(logger, "profile_loaded", user=username, found=bool(result), **(_profile_summary(result) if result else {}))
    return result


def update_customer_profile(username, profile_data):
    log_event(logger, "db_write_start", table="customer_profiles", operation="UPDATE", user=username, profile_data=profile_data)
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
    log_event(logger, "db_write_commit", table="customer_profiles", operation="UPDATE", user=username, changed=changed)
    log_event(logger, "profile_updated", user=username, changed=changed)
    return changed


def create_account(username, account_type="Savings"):
    try:
        log_event(logger, "db_write_start", table="accounts", operation="INSERT", user=username, account_type=account_type, starting_balance="0.00", currency="USD")
        connection = get_connection()
        cursor = connection.cursor()
        created_at = now_text()
        account_number = generate_account_number()
        log_event(logger, "account_number_generated", user=username, account_number=account_number)
        cursor.execute(
            """
            INSERT INTO accounts
            (account_number, username, account_type, balance, currency, status,
             daily_transfer_limit, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (account_number, username, account_type, 0.0, "USD", "active", 1000.0, created_at, created_at),
        )
        connection.commit()
        log_event(logger, "db_write_commit", table="accounts", operation="INSERT", user=username, account_number=account_number, row_id=cursor.lastrowid)
        log_event(logger, "account_created", user=username, account_type=account_type)
        return True
    except sqlite3.IntegrityError:
        log_event(logger, "account_create_failed", user=username, reason="duplicate")
        return False
    finally:
        connection.close()


def get_account(username):
    if log_full_details():
        log_event(logger, "db_read_start", table="accounts", operation="SELECT_BY_USERNAME", user=username)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM accounts WHERE username = ?", (username,))
    account = cursor.fetchone()
    connection.close()
    result = dict(account) if account else None
    log_event(logger, "account_loaded", user=username, found=bool(result), **(_account_summary(result) if result else {}))
    return result


def get_balance(username):
    account = get_account(username)
    return float(account["balance"]) if account else None


def update_balance(username, new_balance):
    log_event(logger, "db_write_start", table="accounts", operation="UPDATE_BALANCE", user=username, new_balance=float(new_balance))
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute(
        "UPDATE accounts SET balance = ?, updated_at = ? WHERE username = ?",
        (new_balance, now_text(), username),
    )
    connection.commit()
    changed = cursor.rowcount > 0
    connection.close()
    log_event(logger, "db_write_commit", table="accounts", operation="UPDATE_BALANCE", user=username, new_balance=float(new_balance), changed=changed)
    log_event(logger, "balance_saved", user=username, balance=f"{float(new_balance):.2f}", changed=changed)
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
    transaction_id = generate_transaction_id()
    log_event(logger, "db_write_start", table="transactions", operation="INSERT", transaction_id=transaction_id, user=username, type=transaction_type, amount=float(amount), receiver=receiver_username, status=status, fraud_flag=fraud_flag, risk_score=risk_score, balance_before=float(balance_before), balance_after=float(balance_after), reason=reason)
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
            transaction_id,
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
    log_event(logger, "db_write_commit", table="transactions", operation="INSERT", transaction_id=transaction_id, row_id=transaction_row_id, user=username)
    log_event(logger, "transaction_saved", row_id=transaction_row_id, transaction_id=transaction_id, user=username, type=transaction_type, status=status, amount=f"{float(amount):.2f}", fraud_flag=fraud_flag, risk_score=risk_score)
    return transaction_row_id


def get_transactions(username, limit=None):
    if log_full_details():
        log_event(logger, "db_read_start", table="transactions", operation="SELECT_HISTORY", user=username, limit=limit)
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
    result = [dict(row) for row in rows]
    log_event(
        logger,
        "transactions_loaded",
        user=username,
        count=len(result),
        limit=limit,
        detail_mode="full" if log_full_details() else "summary",
        **_transaction_log_fields(result),
    )
    return result


def get_recent_transactions(username, minutes=1):
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    if log_full_details():
        log_event(logger, "db_read_start", table="transactions", operation="SELECT_RECENT", user=username, minutes=minutes, since=since)
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
    result = [dict(row) for row in rows]
    log_event(
        logger,
        "recent_transactions_loaded",
        user=username,
        count=len(result),
        window_minutes=minutes,
        detail_mode="full" if log_full_details() else "summary",
        **_transaction_log_fields(result),
    )
    return result


def get_average_transaction_amount(username):
    if log_full_details():
        log_event(logger, "db_read_start", table="transactions", operation="AVG_AMOUNT", user=username)
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
    average = float(row["average_amount"]) if row and row["average_amount"] is not None else 0.0
    log_event(logger, "average_transaction_amount_loaded", user=username, average_amount=average)
    return average


def count_recent_receivers(username, minutes=5):
    since = (datetime.utcnow() - timedelta(minutes=minutes)).isoformat()
    if log_full_details():
        log_event(logger, "db_read_start", table="transactions", operation="COUNT_RECENT_RECEIVERS", user=username, minutes=minutes, since=since)
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
    count = int(row["receiver_count"]) if row else 0
    log_event(logger, "recent_receiver_count_loaded", user=username, receiver_count=count, window_minutes=minutes)
    return count


def get_daily_transfer_total(username):
    since = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0).isoformat()
    if log_full_details():
        log_event(logger, "db_read_start", table="transactions", operation="DAILY_TRANSFER_TOTAL", user=username, since=since)
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
    total = float(row["total"]) if row else 0.0
    log_event(logger, "daily_transfer_total_loaded", user=username, total=total)
    return total


def trust_suspicious_transactions(username):
    log_event(logger, "db_write_start", table="transactions", operation="TRUST_SUSPICIOUS", user=username)
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
    log_event(logger, "db_write_commit", table="transactions", operation="TRUST_SUSPICIOUS", user=username, changed=changed)
    log_event(logger, "suspicious_transactions_trusted", user=username, changed=changed)
    return changed


def count_transactions(username):
    if log_full_details():
        log_event(logger, "db_read_start", table="transactions", operation="COUNT_BY_USER", user=username)
    connection = get_connection()
    cursor = connection.cursor()
    cursor.execute("SELECT COUNT(*) AS total FROM transactions WHERE username = ?", (username,))
    row = cursor.fetchone()
    connection.close()
    total = int(row["total"]) if row else 0
    log_event(logger, "transaction_count_loaded", user=username, total=total)
    return total


def add_audit_log(username, action, details="", ip_address="RPC"):
    log_event(logger, "db_write_start", table="audit_logs", operation="INSERT", user=username, action=action, details=details, ip_address=ip_address)
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
    row_id = cursor.lastrowid
    connection.close()
    log_event(logger, "db_write_commit", table="audit_logs", operation="INSERT", user=username, action=action, row_id=row_id)
    log_event(logger, "audit_log_saved", user=username, action=action)


def get_audit_logs(username, limit=50):
    if log_full_details():
        log_event(logger, "db_read_start", table="audit_logs", operation="SELECT_BY_USER", user=username, limit=limit)
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
    result = [dict(row) for row in rows]
    log_event(logger, "audit_logs_loaded", user=username, count=len(result), limit=limit, audit_logs=result if log_full_details() else None)
    return result
