# BG Bank: Secure RPC-Based Banking System with Fraud Detection and Web GUI

This is a small distributed banking system for an Introduction to Parallel and Distributed Systems course. Team 3 is an odd-numbered team, so this project uses RPC instead of RMI.

The project uses Python XML-RPC for service communication, Flask for the web GUI, Fernet symmetric encryption for login tickets, SQLite for storage, rule-based fraud detection, and `threading.Lock` for safe concurrent banking operations.

## System Architecture

```text
Web Browser
    |
    v
Flask Web App Client, port 5000
    | XML-RPC
    v
Authentication Service, port 8001

Flask Web App Client, port 5000
    | XML-RPC
    v
Banking Server, port 8002
```

The browser never calls the RPC servers directly. The browser talks to Flask, and Flask calls the Authentication Service and Banking Server through XML-RPC.

## RPC Explanation

RPC means Remote Procedure Call. It lets one program call a function running in another process. In this system, Flask calls methods such as `login`, `deposit`, `transfer`, `get_user_profile`, and `get_dashboard_summary` on separate XML-RPC servers.

## Improved Database Schema

SQLite tables:

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

`init_db()` creates missing tables and adds missing columns where possible. For a clean class demo, it is still okay to stop all servers and delete `banking.db`; the tables are recreated automatically.

## Authentication Service

The Authentication Service runs on port `8001`.

It provides:

- `register_user(registration_data)`
- `login(username, password)`

Registration stores login data in `users`, personal data in `customer_profiles`, creates an account with an account number like `AC2026123456`, and writes an audit log.

The login password and action password are separate. The login password is used to enter the system. The action password is required for sensitive money-moving actions like withdrawal and transfer. Deposit does not require the action password because adding money does not reduce the user's balance.

The profile picture is optional. If the user uploads one, Flask crops and resizes it to a fixed `300x300` JPG, saves it in `static/uploads`, and stores the filename in the profile table. If no picture is uploaded, the web UI shows a circular avatar using the first letter of the user's full name.

Login verifies the password hash, updates `last_login`, creates an encrypted Fernet ticket, and writes an audit log.

## Banking Server RPC Methods

The Banking Server runs on port `8002`.

It provides:

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

Every method verifies the encrypted ticket first and returns a dictionary:

```python
{
    "success": True,
    "message": "...",
    "data": {}
}
```

## Symmetric Encryption

The project uses Fernet symmetric encryption from the `cryptography` package. The same secret key encrypts and decrypts login tickets.

The key is stored in `secret.key`. The Authentication Service creates encrypted tickets, and the Banking Server decrypts and verifies them.

## Profile Page

The profile page shows customer and account details:

- username
- full name
- gender
- date of birth
- phone number
- email
- profile picture or first-letter avatar
- national ID
- address
- city
- country
- occupation
- account number
- account type
- account status
- currency
- created date
- last login

The edit profile page only allows editing customer contact fields: full name, phone number, email, address, city, country, and occupation. It does not allow changing username, national ID, account number, balance, role, or account status.

## Dashboard

The dashboard shows:

- full name
- account number
- account type
- current balance
- currency
- account status
- risk score
- total transactions
- last 5 transactions

## About Us Page

The `/about` page introduces BG Bank, displays the image from `static/bank-image/Full-Image.png`, and explains the project purpose, security focus, fraud detection, and RPC-based distributed design.

## Fraud Detection Rules

A transaction can be marked suspicious when:

- amount is greater than 500
- amount is more than 3 times the user's average transaction amount
- more than 5 transactions occur within 1 minute
- withdrawal or transfer drops balance by more than 80%
- transfer goes to many different receivers quickly
- amount exceeds the daily transfer limit
- account status is not active

The fraud module returns:

- `risk_score` from 0 to 100
- `fraud_flag`
- `reasons` list

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

Open three terminal windows in this project folder.

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

Open:

```text
http://127.0.0.1:5000
```

## Demo Steps

1. Register two users, for example `alice` and `bob`, with profile information.
2. Set a login password and a different action password during registration.
3. Login as `alice`.
4. Check the dashboard summary.
5. Open the profile page and edit allowed profile fields.
6. Deposit money, for example `1000`. No action password is required.
7. Withdraw or transfer money using the action password.
8. Try a large transfer, for example `700`, to trigger fraud detection.
9. View transaction history and confirm transaction IDs, balances before/after, risk score, and status.
10. View the fraud report.

## Common Problems and Solutions

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

Stop the process using the port, or change the port numbers in the Python files.

### Invalid or expired token

Login again. Tickets expire after 30 minutes.

### Missing dependency

Run:

```bash
pip install -r requirements.txt
```

### Database migration looks confusing during testing

Stop all servers and delete `banking.db`, then start the services again:

```bash
python auth_service.py
python banking_server.py
python web_app.py
```

The database tables are recreated automatically.

This is also the simplest fix for older demo users that were created before `action_password_hash` existed.
