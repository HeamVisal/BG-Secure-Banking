import hashlib
import os
from socketserver import ThreadingMixIn
from xmlrpc.server import SimpleXMLRPCServer

from app_logging import get_logger, log_event, sensitive_fields, summarize_token, workflow_fields
import database
import security


logger = get_logger("AUTH_RPC")


class ThreadedXMLRPCServer(ThreadingMixIn, SimpleXMLRPCServer):
    """Allow the RPC service to handle more than one client request at a time."""


def response(success, message, data=None):
    return {"success": success, "message": message, "data": data or {}}


def _valid_email(email):
    return "@" in email and "." in email.split("@")[-1]


def _validate_registration(data):
    required = ["username", "password", "confirm_password", "action_password", "confirm_action_password", "full_name", "phone_number", "email"]
    for field in required:
        if not data.get(field, "").strip():
            return f"{field.replace('_', ' ').title()} is required"
    if data["password"] != data["confirm_password"]:
        return "Password and confirm password must match"
    if data["action_password"] != data["confirm_action_password"]:
        return "Action password and confirm action password must match"
    if data["action_password"] == data["password"]:
        return "Action password should be different from login password"
    if not _valid_email(data["email"]):
        return "Please enter a valid email address"
    return None


def register_user(registration_data):
    username = registration_data.get("username", "").strip().lower()
    registration_data["username"] = username
    log_event(logger, "register_request", user=username, received_fields=sorted(registration_data.keys()))
    log_event(logger, "register_step", **workflow_fields("01", "normalize_username", raw_username=registration_data.get("username"), normalized_username=username))
    log_event(logger, "register_step", **workflow_fields("02", "validate_registration_form", required_fields="username,password,action_password,full_name,phone_number,email"))
    error = _validate_registration(registration_data)
    if error:
        log_event(logger, "register_rejected", user=username, reason=error)
        return response(False, error)

    log_event(logger, "register_step", **workflow_fields("03", "hash_login_and_action_passwords"))
    password_hash = security.hash_password(registration_data["password"])
    action_password_hash = security.hash_password(registration_data["action_password"])
    log_event(
        logger,
        "passwords_hashed",
        user=username,
        **sensitive_fields(
            login_password_hash=password_hash,
            action_password_hash=action_password_hash,
        ),
    )
    log_event(logger, "register_step", **workflow_fields("04", "create_user_record", user=username, role="customer", status="active"))
    if not database.create_user(username, password_hash, action_password_hash):
        log_event(logger, "register_rejected", user=username, reason="Username already exists")
        return response(False, "Username already exists")

    profile_data = {
        "full_name": registration_data.get("full_name", "").strip(),
        "gender": registration_data.get("gender", "").strip(),
        "date_of_birth": registration_data.get("date_of_birth", "").strip(),
        "phone_number": registration_data.get("phone_number", "").strip(),
        "email": registration_data.get("email", "").strip(),
        "profile_picture": registration_data.get("profile_picture", "").strip(),
        "national_id": registration_data.get("national_id", "").strip(),
        "address": registration_data.get("address", "").strip(),
        "city": registration_data.get("city", "").strip(),
        "country": registration_data.get("country", "").strip(),
        "occupation": registration_data.get("occupation", "").strip(),
    }
    log_event(logger, "register_step", **workflow_fields("05", "create_customer_profile", user=username, profile_data=profile_data))
    database.create_customer_profile(username, profile_data)
    log_event(logger, "register_step", **workflow_fields("06", "create_bank_account", user=username, account_type=registration_data.get("account_type", "Savings")))
    database.create_account(username, registration_data.get("account_type", "Savings"))
    log_event(logger, "register_step", **workflow_fields("07", "write_register_audit_log", user=username))
    database.add_audit_log(username, "REGISTER", "Customer registered and account created")
    log_event(logger, "register_success", user=username)
    return response(True, "Registration successful")


def login(username, password):
    raw_username = username
    username = username.strip().lower()
    log_event(logger, "login_request", user=username, raw_username=raw_username)
    log_event(logger, "login_step", **workflow_fields("01", "normalize_username", raw_username=raw_username, normalized_username=username))
    log_event(logger, "login_step", **workflow_fields("02", "load_user_from_database", user=username))
    user = database.get_user(username)
    log_event(logger, "login_step", **workflow_fields("03", "compare_submitted_password_with_hash", user=username, user_found=bool(user)))
    log_event(
        logger,
        "login_credentials_received",
        user=username,
        **sensitive_fields(
            submitted_password_sha256=hashlib.sha256(password.encode("utf-8")).hexdigest(),
            stored_password_hash=user.get("password_hash") if user else "missing_user",
        ),
    )
    if not user or not security.verify_password(password, user["password_hash"]):
        database.add_audit_log(username, "LOGIN_FAILED", "Invalid username or password")
        log_event(logger, "login_failed", user=username, reason="Invalid username or password")
        return response(False, "Invalid username or password")
    if user.get("status") != "active":
        database.add_audit_log(username, "LOGIN_BLOCKED", "User status is not active")
        log_event(logger, "login_blocked", user=username, status=user.get("status"))
        return response(False, "User account is not active")

    log_event(logger, "login_step", **workflow_fields("04", "update_last_login", user=username))
    database.update_last_login(username)
    log_event(logger, "login_step", **workflow_fields("05", "write_login_success_audit_log", user=username))
    database.add_audit_log(username, "LOGIN_SUCCESS", "User logged in")
    log_event(logger, "login_step", **workflow_fields("06", "create_encrypted_fernet_ticket", user=username))
    ticket = security.create_login_ticket(username)
    ticket_data = security.decrypt_ticket(ticket) or {}
    log_event(
        logger,
        "ticket_issued",
        user=username,
        issue_time=ticket_data.get("issue_time"),
        expiry_time=ticket_data.get("expiry_time"),
        **summarize_token(ticket),
        **sensitive_fields(full_encrypted_ticket=ticket),
    )
    log_event(logger, "login_success", user=username)
    return response(True, "Login successful", {"ticket": ticket, "username": username})


def main():
    database.init_db()
    security.generate_key_if_not_exists()

    host = os.environ.get("AUTH_HOST", "127.0.0.1")
    port = int(os.environ.get("AUTH_PORT", "8001"))
    server = ThreadedXMLRPCServer((host, port), allow_none=True, logRequests=True)
    log_event(logger, "service_start", url=f"http://{host}:{port}")
    server.register_function(register_user, "register_user")
    server.register_function(login, "login")

    print(f"Authentication Service running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
