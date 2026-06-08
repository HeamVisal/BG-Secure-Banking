import os
import threading
from socketserver import ThreadingMixIn
from xmlrpc.server import SimpleXMLRPCServer

from app_logging import get_logger, log_event, log_full_details, sensitive_fields, summarize_token, workflow_fields
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
    if log_full_details():
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
    log_event(logger, "amount_parse_start", raw_amount=amount, raw_type=type(amount).__name__)
    try:
        amount = float(amount)
    except (TypeError, ValueError):
        log_event(logger, "amount_parse_failed", raw_amount=amount)
        return None
    cleaned = amount if amount > 0 else None
    log_event(logger, "amount_parse_done", raw_amount=amount, cleaned_amount=cleaned, valid=cleaned is not None)
    return cleaned


def _verify_action_password(username, action_password):
    log_event(logger, "action_password_step", **workflow_fields("01", "load_user_for_action_password", user=username, password_length=len(action_password or "")))
    user = database.get_user(username)
    if not user:
        log_event(logger, "action_password_failed", user=username, reason="User not found")
        return False, "User not found"
    if not user.get("action_password_hash"):
        log_event(logger, "action_password_failed", user=username, reason="Action password is not set")
        return False, "Action password is not set. Please register a new demo account or reset the database."
    log_event(logger, "action_password_step", **workflow_fields("02", "compare_action_password_hash", user=username))
    if not security.verify_password(action_password, user["action_password_hash"]):
        log_event(logger, "action_password_failed", user=username, reason="Invalid action password")
        return False, "Invalid action password"
    log_event(logger, "action_password_verified", user=username)
    return True, ""


def _account_or_error(username):
    log_event(logger, "account_lookup_start", user=username)
    account = database.get_account(username)
    if not account:
        log_event(logger, "account_lookup_failed", user=username, reason="missing_account")
        return None, response(False, "Account not found")
    log_event(logger, "account_lookup_done", user=username, account_number=account.get("account_number"), balance=account.get("balance"), status=account.get("status"), daily_transfer_limit=account.get("daily_transfer_limit"))
    if account["status"] != "active":
        log_event(logger, "account_lookup_failed", user=username, reason="inactive_account", status=account.get("status"))
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
    log_event(logger, "deposit_step", **workflow_fields("00", "rpc_method_entered", raw_amount=amount))
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    log_event(logger, "deposit_request", user=username, amount=amount)
    log_event(logger, "deposit_step", **workflow_fields("01", "validate_amount", user=username, raw_amount=amount))
    amount = _clean_amount(amount)
    if amount is None:
        account = database.get_account(username)
        _record_transaction(username, "DEPOSIT", 0, None, "failed", {}, "Invalid amount", account, 0, 0)
        return response(False, "Amount must be greater than zero")

    log_event(logger, "deposit_step", **workflow_fields("02", "wait_for_bank_lock", user=username))
    with bank_lock:
        log_event(logger, "deposit_step", **workflow_fields("03", "bank_lock_acquired", user=username))
        account, error = _account_or_error(username)
        if error:
            _record_transaction(username, "DEPOSIT", amount, None, "failed", {"fraud_flag": 1, "risk_score": 40}, error["message"], account, 0, 0)
            return error

        balance_before = float(account["balance"])
        balance_after = balance_before + amount
        log_event(logger, "deposit_step", **workflow_fields("04", "calculate_new_balance", user=username, balance_before=balance_before, amount=amount, balance_after=balance_after))
        log_event(logger, "deposit_step", **workflow_fields("05", "run_fraud_detection", user=username, transaction_type="DEPOSIT"))
        risk = fraud_detection.check_transaction_risk(username, "DEPOSIT", amount, balance_before, balance_after, account=account)
        log_event(logger, "deposit_step", **workflow_fields("06", "save_new_balance", user=username, balance_after=balance_after))
        database.update_balance(username, balance_after)
        log_event(logger, "balance_updated", user=username, before=f"{balance_before:.2f}", after=f"{balance_after:.2f}")
        log_event(logger, "deposit_step", **workflow_fields("07", "insert_transaction_row", user=username, risk=risk))
        _record_transaction(username, "DEPOSIT", amount, None, "success", risk, "", account, balance_before, balance_after)
        log_event(logger, "deposit_step", **workflow_fields("08", "insert_audit_log", user=username))
        database.add_audit_log(username, "DEPOSIT", f"Deposited {amount:.2f} {account['currency']}")

    log_event(logger, "deposit_success", user=username, balance=f"{balance_after:.2f}", risk_score=risk.get("risk_score", 0), fraud_flag=risk.get("fraud_flag", 0))
    return response(True, "Deposit successful", {"balance": balance_after, "risk": risk})


def withdraw(ticket, amount, action_password):
    log_event(logger, "withdraw_step", **workflow_fields("00", "rpc_method_entered", raw_amount=amount, action_password_length=len(action_password or "")))
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    log_event(logger, "withdraw_request", user=username, amount=amount)
    log_event(logger, "withdraw_step", **workflow_fields("01", "validate_amount", user=username, raw_amount=amount))
    amount = _clean_amount(amount)
    if amount is None:
        account = database.get_account(username)
        _record_transaction(username, "WITHDRAW", 0, None, "failed", {}, "Invalid amount", account, 0, 0)
        return response(False, "Amount must be greater than zero")

    log_event(logger, "withdraw_step", **workflow_fields("02", "wait_for_bank_lock", user=username))
    with bank_lock:
        log_event(logger, "withdraw_step", **workflow_fields("03", "bank_lock_acquired", user=username))
        account, error = _account_or_error(username)
        if error:
            _record_transaction(username, "WITHDRAW", amount, None, "failed", {"fraud_flag": 1, "risk_score": 40}, error["message"], account, 0, 0)
            return error

        log_event(logger, "withdraw_step", **workflow_fields("04", "verify_action_password", user=username))
        action_ok, action_message = _verify_action_password(username, action_password)
        if not action_ok:
            balance = float(account["balance"])
            _record_transaction(username, "WITHDRAW", amount, None, "failed", {}, action_message, account, balance, balance)
            database.add_audit_log(username, "WITHDRAW_BLOCKED", action_message)
            return response(False, action_message)

        balance_before = float(account["balance"])
        log_event(logger, "withdraw_step", **workflow_fields("05", "check_sufficient_balance", user=username, balance_before=balance_before, amount=amount))
        if balance_before < amount:
            _record_transaction(username, "WITHDRAW", amount, None, "failed", {}, "Insufficient balance", account, balance_before, balance_before)
            return response(False, "Insufficient balance")

        balance_after = balance_before - amount
        log_event(logger, "withdraw_step", **workflow_fields("06", "calculate_new_balance", user=username, balance_before=balance_before, amount=amount, balance_after=balance_after))
        log_event(logger, "withdraw_step", **workflow_fields("07", "run_fraud_detection", user=username, transaction_type="WITHDRAW"))
        risk = fraud_detection.check_transaction_risk(username, "WITHDRAW", amount, balance_before, balance_after, account=account)
        log_event(logger, "withdraw_step", **workflow_fields("08", "save_new_balance", user=username, balance_after=balance_after))
        database.update_balance(username, balance_after)
        log_event(logger, "balance_updated", user=username, before=f"{balance_before:.2f}", after=f"{balance_after:.2f}")
        log_event(logger, "withdraw_step", **workflow_fields("09", "insert_transaction_row", user=username, risk=risk))
        _record_transaction(username, "WITHDRAW", amount, None, "success", risk, "", account, balance_before, balance_after)
        log_event(logger, "withdraw_step", **workflow_fields("10", "insert_audit_log", user=username))
        database.add_audit_log(username, "WITHDRAW", f"Withdrew {amount:.2f} {account['currency']}")

    log_event(logger, "withdraw_success", user=username, balance=f"{balance_after:.2f}", risk_score=risk.get("risk_score", 0), fraud_flag=risk.get("fraud_flag", 0))
    return response(True, "Withdrawal successful", {"balance": balance_after, "risk": risk})


def transfer(ticket, receiver_username, amount, action_password):
    log_event(logger, "transfer_step", **workflow_fields("00", "rpc_method_entered", raw_receiver=receiver_username, raw_amount=amount, action_password_length=len(action_password or "")))
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    receiver_username = receiver_username.strip().lower()
    log_event(logger, "transfer_step", **workflow_fields("01", "normalize_receiver", user=username, receiver=receiver_username))
    log_event(logger, "transfer_request", user=username, receiver=receiver_username, amount=amount)
    log_event(logger, "transfer_step", **workflow_fields("02", "validate_amount", user=username, raw_amount=amount))
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

    log_event(logger, "transfer_step", **workflow_fields("03", "wait_for_bank_lock", user=username, receiver=receiver_username))
    with bank_lock:
        log_event(logger, "transfer_step", **workflow_fields("04", "bank_lock_acquired", user=username, receiver=receiver_username))
        sender_account, error = _account_or_error(username)
        if error:
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {"fraud_flag": 1, "risk_score": 40}, error["message"], sender_account, 0, 0)
            return error

        log_event(logger, "transfer_step", **workflow_fields("05", "verify_action_password", user=username))
        action_ok, action_message = _verify_action_password(username, action_password)
        if not action_ok:
            balance = float(sender_account["balance"])
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, action_message, sender_account, balance, balance)
            database.add_audit_log(username, "TRANSFER_BLOCKED", action_message)
            return response(False, action_message)

        log_event(logger, "transfer_step", **workflow_fields("06", "load_receiver_account", user=username, receiver=receiver_username))
        receiver_account = database.get_account(receiver_username)
        if not receiver_account:
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, "Receiver account not found", sender_account, sender_account["balance"], sender_account["balance"])
            return response(False, "Receiver account not found")
        if receiver_account["status"] != "active":
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, "Receiver account is not active", sender_account, sender_account["balance"], sender_account["balance"], receiver_account)
            return response(False, "Receiver account is not active")

        sender_before = float(sender_account["balance"])
        receiver_before = float(receiver_account["balance"])
        log_event(logger, "transfer_step", **workflow_fields("07", "check_sufficient_balance", user=username, receiver=receiver_username, sender_before=sender_before, amount=amount))
        if sender_before < amount:
            _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "failed", {}, "Insufficient balance", sender_account, sender_before, sender_before, receiver_account)
            return response(False, "Insufficient balance")

        sender_after = sender_before - amount
        receiver_after = receiver_before + amount
        log_event(logger, "transfer_step", **workflow_fields("08", "calculate_sender_and_receiver_balances", user=username, receiver=receiver_username, sender_before=sender_before, sender_after=sender_after, receiver_before=receiver_before, receiver_after=receiver_after))
        log_event(logger, "transfer_step", **workflow_fields("09", "run_sender_fraud_detection", user=username, receiver=receiver_username, transaction_type="TRANSFER_OUT"))
        risk = fraud_detection.check_transaction_risk(
            username,
            "TRANSFER_OUT",
            amount,
            sender_before,
            sender_after,
            receiver_username,
            sender_account,
        )
        log_event(logger, "transfer_step", **workflow_fields("10", "save_sender_balance", user=username, balance_after=sender_after))
        database.update_balance(username, sender_after)
        log_event(logger, "transfer_step", **workflow_fields("11", "save_receiver_balance", receiver=receiver_username, balance_after=receiver_after))
        database.update_balance(receiver_username, receiver_after)
        log_event(logger, "balance_updated", user=username, before=f"{sender_before:.2f}", after=f"{sender_after:.2f}")
        log_event(logger, "balance_updated", user=receiver_username, before=f"{receiver_before:.2f}", after=f"{receiver_after:.2f}")
        log_event(logger, "transfer_step", **workflow_fields("12", "insert_sender_transaction_row", user=username, receiver=receiver_username, risk=risk))
        _record_transaction(username, "TRANSFER_OUT", amount, receiver_username, "success", risk, "", sender_account, sender_before, sender_after, receiver_account)
        log_event(logger, "transfer_step", **workflow_fields("13", "insert_receiver_transaction_row", user=receiver_username, sender=username))
        _record_transaction(receiver_username, "TRANSFER_IN", amount, username, "success", {"fraud_flag": 0, "risk_score": 0}, "Money received from transfer", receiver_account, receiver_before, receiver_after, sender_account)
        log_event(logger, "transfer_step", **workflow_fields("14", "insert_sender_and_receiver_audit_logs", user=username, receiver=receiver_username))
        database.add_audit_log(username, "TRANSFER_OUT", f"Transferred {amount:.2f} {sender_account['currency']} to {receiver_username}")
        database.add_audit_log(receiver_username, "TRANSFER_IN", f"Received {amount:.2f} {receiver_account['currency']} from {username}")

    log_event(logger, "transfer_success", user=username, receiver=receiver_username, balance=f"{sender_after:.2f}", risk_score=risk.get("risk_score", 0), fraud_flag=risk.get("fraud_flag", 0))
    return response(True, "Transfer successful", {"balance": sender_after, "risk": risk})


def view_transaction_history(ticket):
    log_event(logger, "history_step", **workflow_fields("00", "rpc_method_entered"))
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")
    transactions = database.get_transactions(username)
    log_event(logger, "history_step", **workflow_fields("01", "return_transaction_history", user=username, transaction_count=len(transactions)))
    return response(True, "Transaction history loaded", {"transactions": transactions})


def detect_fraud(ticket):
    log_event(logger, "fraud_step", **workflow_fields("00", "rpc_method_entered"))
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")
    log_event(logger, "fraud_step", **workflow_fields("01", "calculate_user_risk_score", user=username))
    report = fraud_detection.calculate_user_risk_score(username)
    log_event(logger, "fraud_report_loaded", user=username, risk_score=report["risk_score"], fraud_flag=report["fraud_flag"], suspicious_count=len(report["suspicious_transactions"]))
    return response(True, "Fraud report loaded", report)


def trust_fraud_report(ticket):
    log_event(logger, "trust_fraud_step", **workflow_fields("00", "rpc_method_entered"))
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    log_event(logger, "trust_fraud_step", **workflow_fields("01", "reset_suspicious_transaction_flags", user=username))
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
    log_event(logger, "profile_step", **workflow_fields("00", "rpc_method_entered"))
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    log_event(logger, "profile_step", **workflow_fields("01", "load_user_profile_account", user=username))
    user = database.get_user(username)
    profile = database.get_customer_profile(username) or {}
    account = database.get_account(username) or {}
    data = {**profile, **account, "username": username, "role": user.get("role"), "user_status": user.get("status"), "last_login": user.get("last_login")}
    return response(True, "Profile loaded", data)


def update_user_profile(ticket, profile_data):
    log_event(logger, "profile_update_step", **workflow_fields("00", "rpc_method_entered", profile_data=profile_data))
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

    log_event(logger, "profile_update_step", **workflow_fields("01", "validate_and_update_profile", user=username, profile_data=profile_data))
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
    if log_full_details():
        log_event(logger, "dashboard_step", **workflow_fields("00", "rpc_method_entered"))
    username = _username_from_ticket(ticket)
    if not username:
        return response(False, "Invalid or expired token")

    if log_full_details():
        log_event(logger, "dashboard_step", **workflow_fields("01", "load_user_profile_account", user=username))
    user = database.get_user(username) or {}
    profile = database.get_customer_profile(username) or {}
    account = database.get_account(username)
    if not account:
        return response(False, "Account not found")
    if log_full_details():
        log_event(logger, "dashboard_step", **workflow_fields("02", "calculate_risk_and_summary_counts", user=username))
    risk = fraud_detection.calculate_user_risk_score(username)
    total_transactions = database.count_transactions(username)
    last_transactions = database.get_transactions(username, limit=5)
    if not log_full_details():
        log_event(
            logger,
            "Dashboard()",
            user=username,
            full_name=profile.get("full_name", username),
            account=account["account_number"],
            balance=account["balance"],
            currency=account["currency"],
            transactions=total_transactions,
            risk_score=risk["risk_score"],
            fraud_flag=risk["fraud_flag"],
            recent_count=len(last_transactions),
        )
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
            "total_transactions": total_transactions,
            "last_transactions": last_transactions,
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
    server = ThreadedXMLRPCServer((host, port), allow_none=True, logRequests=log_full_details())
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
