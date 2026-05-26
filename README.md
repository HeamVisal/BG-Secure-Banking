# SecureBG Banking Web

SecureBG Banking Web is a Python-based secure banking web application built with Flask, XML-RPC services, SQLite, Fernet encrypted login tickets, password hashing, profile management, transaction tracking, and rule-based fraud detection.

The project demonstrates a distributed banking workflow where the web interface communicates with separate Authentication and Banking services through RPC.

## Features

- Customer registration and login
- Separate login password and action password
- Encrypted session ticket using Fernet symmetric encryption
- Customer profile and profile picture upload
- Account dashboard with balance, account details, risk score, and recent transactions
- Deposit, withdraw, and transfer workflows
- Action password protection for withdraw and transfer
- Transaction history with transaction IDs, balances, status, and risk information
- Rule-based fraud detection report
- Audit logging for important user actions
- SQLite database initialization and migration helpers
- Threaded XML-RPC servers with lock-protected banking operations

## System Architecture

```text
Browser
  |
  v
Flask Web App
127.0.0.1:5000
  |
  | XML-RPC
  +--------------------------+
  |                          |
  v                          v
Authentication Service       Banking Server
127.0.0.1:8001              127.0.0.1:8002
  |                          |
  +------------+-------------+
               |
               v
          SQLite Database
          banking.db
```

The browser only talks to the Flask application. Flask calls the Authentication Service and Banking Server through XML-RPC.

## Main Workflow

1. A customer opens the web app and registers an account.
2. The Authentication Service validates the form, hashes the login password and action password, creates the user profile, creates a bank account, and writes an audit log.
3. The customer logs in with the login password.
4. The Authentication Service returns an encrypted Fernet ticket.
5. Flask stores the ticket in the user session.
6. Banking actions send the ticket to the Banking Server.
7. The Banking Server decrypts and validates the ticket before processing requests.
8. Deposits update the balance directly.
9. Withdrawals and transfers require the action password.
10. Each transaction is checked by the fraud detection rules and saved in the database.
11. The dashboard, history page, fraud page, and profile page read data through Banking Server RPC methods.

## Application Pages

| Page | Route | Description |
| --- | --- | --- |
| Login | `/login` | Customer login page |
| Register | `/register` | Customer registration and profile setup |
| Dashboard | `/dashboard` | Account summary, balance, risk score, and recent transactions |
| Deposit | `/deposit` | Add money to the account |
| Withdraw | `/withdraw` | Withdraw money with action password |
| Transfer | `/transfer` | Transfer money to another user with action password |
| History | `/history` | View transaction history |
| Fraud | `/fraud` | View fraud detection report |
| Profile | `/profile` | View customer and account details |
| Edit Profile | `/profile/edit` | Update editable profile fields and profile picture |
| About | `/about` | Project information page |
| Logout | `/logout` | Clear the session and return to login |

## RPC Services

### Authentication Service

Runs on:

```text
http://127.0.0.1:8001
```

Methods:

- `register_user(registration_data)`
- `login(username, password)`

Responsibilities:

- Validate registration data
- Hash login and action passwords
- Create customer user, profile, and account records
- Generate encrypted login tickets
- Update last login time
- Write authentication audit logs

### Banking Server

Runs on:

```text
http://127.0.0.1:8002
```

Methods:

- `get_balance(ticket)`
- `deposit(ticket, amount)`
- `withdraw(ticket, amount, action_password)`
- `transfer(ticket, receiver_username, amount, action_password)`
- `view_transaction_history(ticket)`
- `detect_fraud(ticket)`
- `get_risk_score(ticket)`
- `get_user_profile(ticket)`
- `update_user_profile(ticket, profile_data)`
- `get_account_details(ticket)`
- `get_dashboard_summary(ticket)`
- `get_audit_logs(ticket)`

All Banking Server methods validate the encrypted ticket before loading or changing account data.

## Database Schema

The project uses SQLite with the database file `banking.db`.

Tables:

```text
users:
id, username, password_hash, action_password_hash, role, status,
created_at, last_login

customer_profiles:
id, username, full_name, gender, date_of_birth, phone_number, email,
profile_picture, national_id, address, city, country, occupation,
created_at, updated_at

accounts:
id, account_number, username, account_type, balance, currency, status,
daily_transfer_limit, created_at, updated_at

transactions:
id, transaction_id, username, account_number, transaction_type, amount,
currency, receiver_username, receiver_account_number, balance_before,
balance_after, status, fraud_flag, risk_score, reason, created_at

audit_logs:
id, username, action, details, ip_address, created_at
```

`database.init_db()` creates missing tables and adds missing columns where possible.

## Security Design

- Passwords are stored as hashes, not plain text.
- The login password is used only for authentication.
- The action password is separate and required for sensitive operations.
- Login creates an encrypted Fernet ticket.
- Banking Server RPC methods reject invalid or expired tickets.
- Withdraw and transfer operations are protected by an action password.
- Local secrets and runtime files such as `secret.key` and `banking.db` are ignored by Git.

## Fraud Detection

Fraud detection is rule-based and calculates a risk score from `0` to `100`.

A transaction can be marked suspicious when:

- The amount is greater than `500`
- The amount is more than three times the user's average transaction amount
- The user makes at least five transactions within one minute
- A withdraw or transfer drops the balance by more than `80%`
- Transfers go to many different receivers quickly
- A transfer exceeds the daily transfer limit
- The account status is not active

Transactions with a risk score of `25` or higher are flagged as suspicious.

## Project Structure

```text
.
├── auth_service.py       # Authentication XML-RPC service
├── banking_server.py     # Banking XML-RPC service
├── database.py           # SQLite schema and data access helpers
├── fraud_detection.py    # Rule-based fraud detection logic
├── security.py           # Password hashing and Fernet ticket helpers
├── web_app.py            # Flask web application
├── requirements.txt      # Python dependencies
├── static/               # CSS, JavaScript, images, uploads
└── templates/            # Flask HTML templates
```

## Requirements

- Python 3.11 or newer
- Flask
- cryptography
- Werkzeug
- Pillow

Install dependencies from `requirements.txt`.

## Installation

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

On Windows PowerShell:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## How to Run

Open three terminal windows in the project folder.

Terminal 1:

```bash
python auth_service.py
```

Terminal 2:

```bash
python banking_server.py
```

Terminal 3:

```bash
python web_app.py
```

Then open:

```text
http://127.0.0.1:5000
```

## Demo Steps

1. Register two users, for example `alice` and `bob`.
2. Use different values for the login password and action password.
3. Log in as `alice`.
4. Review the dashboard summary.
5. Open the profile page and update editable profile information.
6. Deposit money into Alice's account.
7. Withdraw money using Alice's action password.
8. Transfer money from `alice` to `bob` using Alice's action password.
9. Try a large or unusual transaction to trigger fraud detection.
10. Open transaction history to review transaction IDs, balances, status, and risk score.
11. Open the fraud page to review suspicious transactions and risk reasons.

## Common Problems

### Authentication Service is not running

Start it with:

```bash
python auth_service.py
```

### Banking Server is not running

Start it with:

```bash
python banking_server.py
```

### Port already in use

Stop the process using the port, or update the port numbers in `web_app.py`, `auth_service.py`, and `banking_server.py`.

### Invalid or expired token

Log out and log in again.

### Reset demo data

Stop all three running services, delete `banking.db`, then start the services again. The database tables will be recreated automatically.
