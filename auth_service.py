import os
from socketserver import ThreadingMixIn
from xmlrpc.server import SimpleXMLRPCServer

import database
import security


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
    error = _validate_registration(registration_data)
    if error:
        return response(False, error)

    password_hash = security.hash_password(registration_data["password"])
    action_password_hash = security.hash_password(registration_data["action_password"])
    if not database.create_user(username, password_hash, action_password_hash):
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
    database.create_customer_profile(username, profile_data)
    database.create_account(username, registration_data.get("account_type", "Savings"))
    database.add_audit_log(username, "REGISTER", "Customer registered and account created")
    return response(True, "Registration successful")


def login(username, password):
    username = username.strip().lower()
    user = database.get_user(username)
    if not user or not security.verify_password(password, user["password_hash"]):
        database.add_audit_log(username, "LOGIN_FAILED", "Invalid username or password")
        return response(False, "Invalid username or password")
    if user.get("status") != "active":
        database.add_audit_log(username, "LOGIN_BLOCKED", "User status is not active")
        return response(False, "User account is not active")

    database.update_last_login(username)
    database.add_audit_log(username, "LOGIN_SUCCESS", "User logged in")
    ticket = security.create_login_ticket(username)
    return response(True, "Login successful", {"ticket": ticket, "username": username})


def main():
    database.init_db()
    security.generate_key_if_not_exists()

    host = os.environ.get("AUTH_HOST", "127.0.0.1")
    port = int(os.environ.get("AUTH_PORT", "8001"))
    server = ThreadedXMLRPCServer((host, port), allow_none=True, logRequests=True)
    server.register_function(register_user, "register_user")
    server.register_function(login, "login")

    print(f"Authentication Service running on http://{host}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
