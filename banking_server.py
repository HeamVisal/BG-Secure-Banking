import os
import threading
from socketserver import ThreadingMixIn
from xmlrpc.server import SimpleXMLRPCServer

from app_logging import get_logger, log_event, sensitive_fields, summarize_token
import database
import fraud_detection
import security


logger = get_logger("BANK_RPC")
bank_lock = threading.Lock()


class ThreadedXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer):
    """Handle concurrent RPC calls; banking writes are protected by bank_lock."""


def response(success, message, data=None):
    return {"success": success, "message": message, "data": data or {}}


def _username_from_ticket(ticket):
    data = security.decrypt_ticket(ticket)
    if not data:
        log_event(logger, "ticket_invalid", **summarize_token(ticket), **sensitive_fields(full_encrypted_ticket=ticket))
        return None
    username = data.get("username")
    log_event(
        logger,
        "ticket_valid",
        user=username,
        issue_time=data.get("issue_time"),
        expiry_time=data.get("expiry_time"),
        **summarize_token(ticket),
        **sensitive_fields(full_encrypted_ticket=ticket),
    )
    return username


def _clean_amount(amount):
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        return None
    return amount if amount > 0 else None


def _verify_action_password(username, action_password):
    user = database.get_user(username)
    if not user:
        log_event(logger, "action_password_failed", user=username, reason="User not found")
        return False, "User not found"
    if not user.get("action_password_hash"):
        log_event(logger, "action_password_failed", user=username, reason="Action password is not set")
        return False, "Action password is not set. Please register a new demo account or reset the database."
    if not security.verify_password(action_password, user["action_password_hash"]):
        log_event(logger, "action_password_failed", user=username, reason="Invalid action password")
        return False, "Invalid action password"
    log_event(logger, "action_password_verified", user=username)
    return True, ""


def _account_or_error(username):
    account = database.get_account(username)
    if not account:
        return None, response(False, "Account not found")
    if account["status"] != "active":
        return account, response(False, "Account must be active")
    return account, None


def _record_transaction(username, transaction_type, amount, receiver_username, status, risk, reason, account, balance_before, balance_after, receiver_account=None):
    transaction_row_id = database.add_transaction(
        username=username,
        transaction_type=transaction_type,
        amount=amount,
        receiver_username=receiver_username,
        status=status,
        fraud_flag=risk.get("fraud_flag", 0),
        risk_score=risk.get("risk_score", 0),
        reason=reason or "; ".join(risk.get("reasons", [])),
        account_number=account.get("account_number") if account else None,
        currency=account.get("currency", "USD") if account else "USD",
        receiver_account_number=receiver_account.get("account_number") if receiver_account else None,
        balance_before=balance_before,
        balance_after=balance_after,
    )
    log_event(
        logger,
        "transaction_recorded",
        row_id=transaction_row_id,
        user=username,
        type=transaction_type,
        amount=f"{float(amount):.2f}",
        status=status,
        receiver=receiver_username,
        risk_score=risk.get("risk_score", 0),
        fraud_flag=risk.get("fraud_flag", 0),
    )


def get_balance(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    account = database.get_account(username)
    if not account:
        return response(False, "Account not found")

    return response(True, "Balance loaded", {"balance": account["balance"], "currency": account["currency"]})


def deposit(ticket, amount):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    log_event(logger, "deposit_request", user=username, amount=amount)
    amount = _clean_amount(amount)
    if amount is None:
        account = database.get_account(username)
        _record_transaction(username, "DEPOSIT", 0, None, "failed", {}, "Invalid amount", account, 0, 0)
        return response(False, "Amount must be greater than zero")

    with bank_lock:
        account, error = _account_or_error(username)
        if error:
            _record_transaction(username, "DEPOSIT", amount, None, "failed", {"fraud_flag": 1, "risk_score": 40}, error["message"], account, 0, 0)
            return error

        balance_before = float(account["balance"])
        balance_after = balance_before + amount
        risk = fraud_detection.check_transaction_risk(username, "DEPOSIT", amount, balance_before, balance_after, account=account)
        database.update_balance(username, balance_after)
        log_event(logger, "balance_updated", user=username, before=f"{balance_before:.2f}", after=f"{balance_after:.2f}")
        _record_transaction(username, "DEPOSIT", amount, None, "success", risk, "", account, balance_before, balance_after)
        database.add_audit_log(username, "DEPOSIT", f"Deposited {amount:.2f} {account['currency']}")

    log_event(logger, "deposit_success", user=username, balance=f"{balance_after:.2f}", risk_score=risk.get("risk_score", 0), fraud_flag=risk.get("fraud_flag", 0))
    return response(True, "Deposit successful", {"balance": balance_after, "risk": risk})


def withdraw(ticket, amount, action_password):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    log_event(logger, "withdraw_request", user=username, amount=amount)
    amount = _clean_amount(amount)
    if amount is None:
        account = database.get_account(username)
        _record_transaction(username, "WITHDRAW", 0, None, "failed", {}, "Invalid amount", account, 0, 0)
        return response(False, "Amount must be greater than zero")

    with bank_lock:
        account, error = _account_or_error(username)
        if error:
            _record_transaction(username, "WITHDRAW", amount, None, "failed", {"fraud_flag": 1, "risk_score": 40}, error["message"], account, 0, 0)
            return error

        action_ok, action_message = _verify_action_password(username, action_password)
        if not action_ok:
            balance = float(account["balance"])
            _record_transaction(username, "WITHDRAW", amount, None, "failed", {}, action_message, account, balance, balance)
            database.add_audit_log(username, "WITHDRAW_BLOCKED", action_message)
            return response(False, action_message)

        balance_before = float(account["balance"])
        if balance_before < amount:
            _record_transaction(username, "WITHDRAW", amount, None, "failed", {}, "Insufficient balance", account, balance_before, balance_before)
            return response(False, "Insufficient balance")

        balance_after = balance_before - amount
        risk = fraud_detection.check_transaction_risk(username, "WITHDRAW", amount, balance_before, balance_after, account=account)
        database.update_balance(username, balance_after)
        log_event(logger, "balance_updated", user=username, before=f"{balance_before:.2f}", after=f"{balance_after:.2f}")
        _record_transaction(username, "WITHDRAW", amount, None, "success", risk, "", account, balance_before, balance_after)
        database.add_audit_log(username, "WITHDRAW", f"Withdrew {amount:.2f} {account['currency']}")

    log_event(logger, "withdraw_success", user=username, balance=f"{balance_after:.2f}", risk_score=risk.get("risk_score", 0), fraud_flag=risk.get("fraud_flag", 0))
    return response(True, "Withdrawal successful", {"balance": balance_after, "risk": risk})


def transfer(ticket, receiver_username, amount, action_password):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    receiver_username = receiver_username.strip().lower()
    log_event(logger, "transfer_request", user=username, receiver=receiver_username, amount=amount)
    amount = _clean_amount(amount)
    if amount is None:
        account = database.get_account(username)
        _record_transaction(username, "TRANSFER_OUT", 0, receiver_username, "failed", {}, "Invalid amount", account, 0, 0)
        return response(False, "Amount must be greater than zero")

    if not receiver_username:
        return response(False, "Receiver username is required")
    if receiver_username == username:
        account = database.get_account(username)
        _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, "Cannot transfer to yourself", account, 0, 0)
        return response(False, "Cannot transfer to yourself")

    with bank_lock:
        sender_account, error = _account_or_error(username)
        if error:
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {"fraud_flag": 1, "risk_score": 40}, error["message"], sender_account, 0, 0)
            return error

        action_ok, action_message = _verify_action_password(username, action_password)
        if not action_ok:
            balance = float(sender_account["balance"])
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, action_message, sender_account, balance, balance)
            database.add_audit_log(username, "TRANSFER_BLOCKED", action_message)
            return response(False, action_message)

        receiver_account = database.get_account(receiver_username)
        if not receiver_account:
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, "Receiver account not found", sender_account, sender_account["balance"], sender_account["balance"])
            return response(False, "Receiver account not found")
        if receiver_account["status"] != "active":
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, "Receiver account is not active", sender_account, sender_account["balance"], sender_account["balance"], receiver_account)
            return response(False, "Receiver account is not active")

        sender_before = float(sender_account["balance"])
        receiver_before = float(receiver_account["balance"])
        if sender_before < amount:
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, "Insufficient balance", sender_account, sender_before, sender_before, receiver_account)
            return response(False, "Insufficient balance")

        sender_after = sender_before - amount
        receiver_after = receiver_before + amount
        risk = fraud_detection.check_transaction_risk(
            username,
            "TRANSFER_OUT",
            amount,
            sender_before,
            sender_after,
            receiver_username,
            sender_account,
        )
        database.update_balance(username, sender_after)
        database.update_balance(receiver_username, receiver_after)
        log_event(logger, "balance_updated", user=username, before=f"{sender_before:.2f}", after=f"{sender_after:.2f}")
        log_event(logger, "balance_updated", user=receiver_username, before=f"{receiver_before:.2f}", after=f"{receiver_after:.2f}")
        _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "success", risk, "", sender_account, sender_before, sender_after, receiver_account)
        _record_transaction(receiver_username, "TRANSFER_IN", amount, username, "success", {"fraud_flag": 0, "risk_score": 0}, "Money received from transfer", receiver_account, receiver_before, receiver_after, sender_account)
        database.add_audit_log(username, "TRANSFER_OUT", f"Transferred {amount:.2f} {sender_account['currency']} to {receiver_username}")
        database.add_audit_log(receiver_username, "TRANSFER_IN", f"Received {amount:.2f} {receiver_account['currency']} from {username}")

    log_event(logger, "transfer_success", user=username, receiver=receiver_username, balance=f"{sender_after:.2f}", risk_score=risk.get("risk_score", 0), fraud_flag=risk.get("fraud_flag", 0))
    return response(True, "Transfer successful", {"balance": sender_after, "risk": risk})


def view_transaction_history(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")
    return response(True, "Transaction history loaded", {"transactions": database.get_transactions(username)})


def detect_fraud(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")
    report = fraud_detection.calculate_user_risk_score(username)
    log_event(logger, "fraud_report_loaded", user=username, risk_score=report["risk_score"], fraud_flag=report["fraud_flag"], suspicious_count=len(report["suspicious_transactions"]))
    return response(True, "Fraud report loaded", report)


def trust_fraud_report(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    trusted_count = database.trust_suspicious_transactions(username)
    database.add_audit_log(username, "TRUST_FRAUD_REPORT", f"Trusted and reset {trusted_count} suspicious transaction risk flags")
    log_event(logger, "fraud_report_trusted", user=username, trusted_count=trusted_count)
    return response(True, f"Trusted {trusted_count} suspicious transaction(s). Risk report reset.", {"trusted_count": trusted_count})


def get_risk_score(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")
    report = fraud_detection.calculate_user_risk_score(username)
    return response(True, "Risk score loaded", {"risk_score": report["risk_score"], "reasons": report["reasons"]})


def get_user_profile(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    user = database.get_user(username)
    profile = database.get_customer_profile(username) or {}
    account = database.get_account(username) or {}
    data = {**profile, **account, "username": username, "role": user.get("role"), "user_status": user.get("status"), "last_login": user.get("last_login")}
    return response(True, "Profile loaded", data)


def update_user_profile(ticket, profile_data):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    if not profile_data.get("full_name", "").strip():
        return response(False, "Full name is required")
    if not profile_data.get("phone_number", "").strip():
        return response(False, "Phone number is required")
    email = profile_data.get("email", "")
    if "@" not in email or "." not in email.split("@")[-1]:
        return response(False, "Please enter a valid email address")

    if database.update_customer_profile(username, profile_data):
        database.add_audit_log(username, "PROFILE_UPDATE", "Customer editable profile fields updated")
        return response(True, "Profile updated successfully")
    return response(False, "Profile not found")


def get_account_details(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")
    account = database.get_account(username)
    if not account:
        return response(False, "Account not found")
    return response(True, "Account details loaded", account)


def get_dashboard_summary(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    user = database.get_user(username) or {}
    profile = database.get_customer_profile(username) or {}
    account = database.get_account(username)
    if not account:
        return response(False, "Account not found")
    risk = fraud_detection.calculate_user_risk_score(username)
    return response(
        True,
        "Dashboard summary loaded",
        {
            "username": username,
            "full_name": profile.get("full_name", username),
            "profile_picture": profile.get("profile_picture", ""),
            "account_number": account["account_number"],
            "account_type": account["account_type"],
            "balance": account["balance"],
            "currency": account["currency"],
            "account_status": account["status"],
            "risk_score": risk["risk_score"],
            "total_transactions": database.count_transactions(username),
            "last_transactions": database.get_transactions(username, limit=5),
            "last_login": user.get("last_login"),
        },
    )


def get_audit_logs(ticket):
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")
    return response(True, "Audit logs loaded", {"audit_logs": database.get_audit_logs(username)})


def main():
    database.init_db()
    security.generate_key_if_not_exists()

    host = os.environ.get("BANK_HOST", "127.0.0.1")
    port = int(os.environ.get("BANK_PORT", "8002"))
    server = ThreadedXMLRPCServer((host, port), allow_none=True, logRequests=True)
    log_event(logger, "service_start", url=f"http://{host}:{port}")
    for function in [
        get_balance,
        deposit,
        withdraw,
        transfer,
        view_transaction_history,
        detect_fraud,
        trust_fraud_report,
        get_risk_score,
        get_user_profile,
        update_user_profile,
        get_account_details,
        get_dashboard_summary,
        get_audit_logs,
    ]:
        server.register_function(function, function.__name__)

    print(f"Banking Server running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
