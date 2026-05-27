import os
import uuid
from xmlrpc.client import Fault, ProtocolError, ServerProxy

from flask import Flask, flash, redirect, render_template, request, session, url_for
from PIL import Image, ImageOps
from werkzeug.utils import secure_filename

import security


AUTH_RPC_URL = "http://127.0.0.1:8001"
BANK_RPC_URL = "http://127.0.0.1:8002"

app = Flask(__name__)
app.secret_key = security.stable_flask_secret()
app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024

ALLOWED_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
PROFILE_IMAGE_SIZE = (300, 300)


def auth_rpc():
    return ServerProxy(AUTH_RPC_URL, allow_none=True)


def bank_rpc():
    return ServerProxy(BANK_RPC_URL, allow_none=True)


def current_ticket():
    return session.get("ticket")


def require_login():
    ticket = current_ticket()
    if not ticket:
        flash("Please log in first.", "error")
        return False
    try:
        if not security.decrypt_ticket(ticket):
            session.clear()
            flash("Your session has expired. Please log in again.", "error")
            return False
    except Exception:
        session.clear()
        flash("Session error. Please log in again.", "error")
        return False
    return True


def call_bank(method_name, *args):
    try:
        method = getattr(bank_rpc(), method_name)
        return method(current_ticket(), *args)
    except (OSError, Fault, ProtocolError) as error:
        return {"success": False, "message": f"Banking Server error: {error}", "data": {}}


def _form_dict():
    return {key: request.form.get(key, "").strip() for key in request.form.keys()}


def _valid_email(email):
    return "@" in email and "." in email.split("@")[-1]


def save_profile_picture(file_storage):
    if not file_storage or not file_storage.filename:
        return ""

    filename = secure_filename(file_storage.filename)
    extension = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in ALLOWED_IMAGE_EXTENSIONS:
        return ""

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    saved_name = f"{uuid.uuid4().hex}.jpg"
    saved_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_name)

    try:
        image = Image.open(file_storage.stream)
        image = ImageOps.exif_transpose(image)
        image = ImageOps.fit(image, PROFILE_IMAGE_SIZE, method=Image.Resampling.LANCZOS)
        image = image.convert("RGB")
        image.save(saved_path, "JPEG", quality=90, optimize=True)
        return saved_name
    except OSError:
        return ""


def validate_registration(data):
    required = ["username", "password", "confirm_password", "action_password", "confirm_action_password", "full_name", "phone_number", "email"]
    for field in required:
        if not data.get(field):
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


def validate_amount(value):
    try:
        amount = float(value)
    except (TypeError, ValueError):
        return False
    return amount > 0


@app.route("/")
def index():
    if current_ticket():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    form_data = {}
    if request.method == "POST":
        form_data = _form_dict()
        error = validate_registration(form_data)
        if error:
            flash(error, "error")
            return render_template("register.html", form_data=form_data)
        form_data["profile_picture"] = save_profile_picture(request.files.get("profile_picture"))
        try:
            result = auth_rpc().register_user(form_data)
        except OSError:
            result = {"success": False, "message": "Authentication Service is not running.", "data": {}}

        flash(result["message"], "success" if result["success"] else "error")
        if result["success"]:
            return redirect(url_for("login"))

    return render_template("register.html", form_data=form_data)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        try:
            result = auth_rpc().login(username, password)
        except OSError:
            result = {"success": False, "message": "Authentication Service is not running.", "data": {}}

        flash(result["message"], "success" if result["success"] else "error")
        if result["success"]:
            session["ticket"] = result["data"]["ticket"]
            session["username"] = result["data"]["username"]
            return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect(url_for("login"))

    result = call_bank("get_dashboard_summary")
    if not result["success"]:
        flash(result["message"], "error")
        summary = {
            "username": session.get("username"),
            "full_name": session.get("username"),
            "profile_picture": "",
            "account_number": "—",
            "account_type": "—",
            "balance": 0.0,
            "currency": "USD",
            "account_status": "inactive",
            "risk_score": 0,
            "total_transactions": 0,
            "last_transactions": [],
            "last_login": "—"
        }
    else:
        summary = result["data"]

    return render_template("dashboard.html", summary=summary)


@app.route("/deposit", methods=["GET", "POST"])
def deposit():
    if not require_login():
        return redirect(url_for("login"))
    if request.method == "POST":
        amount = request.form.get("amount", "0")
        if not validate_amount(amount):
            flash("Amount must be greater than zero", "error")
            return render_template("deposit.html")
        result = call_bank("deposit", amount)
        flash(result["message"], "success" if result["success"] else "error")
        if result["success"]:
            return redirect(url_for("dashboard"))
    return render_template("deposit.html")


@app.route("/withdraw", methods=["GET", "POST"])
def withdraw():
    if not require_login():
        return redirect(url_for("login"))
    if request.method == "POST":
        amount = request.form.get("amount", "0")
        if not validate_amount(amount):
            flash("Amount must be greater than zero", "error")
            return render_template("withdraw.html")
        action_password = request.form.get("action_password", "")
        if not action_password:
            flash("Action password is required for withdrawal", "error")
            return render_template("withdraw.html")
        result = call_bank("withdraw", amount, action_password)
        flash(result["message"], "success" if result["success"] else "error")
        if result["success"]:
            return redirect(url_for("dashboard"))
    return render_template("withdraw.html")


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if not require_login():
        return redirect(url_for("login"))
    if request.method == "POST":
        receiver = request.form.get("receiver_username", "").strip()
        amount = request.form.get("amount", "0")
        if not receiver:
            flash("Receiver username is required", "error")
            return render_template("transfer.html")
        if receiver.lower() == session.get("username"):
            flash("Sender cannot transfer to themselves", "error")
            return render_template("transfer.html")
        if not validate_amount(amount):
            flash("Amount must be greater than zero", "error")
            return render_template("transfer.html")
        action_password = request.form.get("action_password", "")
        if not action_password:
            flash("Action password is required for transfer", "error")
            return render_template("transfer.html")
        result = call_bank("transfer", receiver, amount, action_password)
        flash(result["message"], "success" if result["success"] else "error")
        if result["success"]:
            return redirect(url_for("dashboard"))
    return render_template("transfer.html")


@app.route("/history")
def history():
    if not require_login():
        return redirect(url_for("login"))
    result = call_bank("view_transaction_history")
    if not result["success"]:
        flash(result["message"], "error")
        transactions = []
    else:
        transactions = result["data"]["transactions"]
    return render_template("history.html", transactions=transactions)


@app.route("/fraud/trust", methods=["POST"])
def trust_fraud():
    if not require_login():
        return redirect(url_for("login"))
    result = call_bank("trust_fraud_report")
    flash(result["message"], "success" if result["success"] else "error")
    return redirect(url_for("fraud"))


@app.route("/fraud")
def fraud():
    if not require_login():
        return redirect(url_for("login"))
    result = call_bank("detect_fraud")
    if not result["success"]:
        flash(result["message"], "error")
        report = {"risk_score": 0, "reasons": [], "suspicious_transactions": [], "fraud_flag": 0}
    else:
        report = result["data"]
    return render_template("fraud.html", report=report)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/profile")
def profile():
    if not require_login():
        return redirect(url_for("login"))
    result = call_bank("get_user_profile")
    if not result["success"]:
        flash(result["message"], "error")
        return redirect(url_for("dashboard"))
    return render_template("profile.html", profile=result["data"])


@app.route("/profile/edit", methods=["GET", "POST"])
def edit_profile():
    if not require_login():
        return redirect(url_for("login"))

    current_profile_result = call_bank("get_user_profile")
    current_profile = current_profile_result["data"] if current_profile_result["success"] else {}

    if request.method == "POST":
        profile_data = _form_dict()
        profile_data["profile_picture"] = current_profile.get("profile_picture", "")
        if not profile_data.get("full_name"):
            flash("Full name is required", "error")
            return render_template("edit_profile.html", profile=profile_data)
        if not profile_data.get("phone_number"):
            flash("Phone number is required", "error")
            return render_template("edit_profile.html", profile=profile_data)
        if not _valid_email(profile_data.get("email", "")):
            flash("Please enter a valid email address", "error")
            return render_template("edit_profile.html", profile=profile_data)

        profile_picture = save_profile_picture(request.files.get("profile_picture"))
        if profile_picture:
            profile_data["profile_picture"] = profile_picture
        result = call_bank("update_user_profile", profile_data)
        flash(result["message"], "success" if result["success"] else "error")
        if result["success"]:
            return redirect(url_for("profile"))
        return render_template("edit_profile.html", profile=profile_data)

    if not current_profile_result["success"]:
        flash(current_profile_result["message"], "error")
        return redirect(url_for("profile"))
    return render_template("edit_profile.html", profile=current_profile)


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
