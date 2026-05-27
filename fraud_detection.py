import database


def check_transaction_risk(
    username,
    transaction_type,
    amount,
    balance_before,
    balance_after,
    receiver_username=None,
    account=None,
):
    """Apply rule-based fraud checks and return score, flag, and clear reasons."""
    reasons = []
    risk_score = 0
    account = account or database.get_account(username)

    if account and account.get("status") != "active":
        reasons.append("Account status is not active")
        risk_score += 40

    if amount > 500:
        reasons.append("Large transaction amount")
        risk_score += 20

    average_amount = database.get_average_transaction_amount(username)
    if average_amount > 0 and amount > average_amount * 3:
        reasons.append("Unusual amount compared to average")
        risk_score += 15

    recent_transactions = database.get_recent_transactions(username, minutes=1)
    if len(recent_transactions) >= 5:
        reasons.append("Too many transactions in short time")
        risk_score += 20

    if transaction_type in ("WITHDRAW", "TRANSFER_OUT") and balance_before > 0:
        balance_drop = (balance_before - balance_after) / balance_before
        if balance_drop > 0.80:
            reasons.append("Balance dropped too quickly")
            risk_score += 20

    if transaction_type == "TRANSFER_OUT":
        recent_receiver_count = database.count_recent_receivers(username, minutes=5)
        if receiver_username:
            recent_receiver_count += 1
        if recent_receiver_count > 3:
            reasons.append("Transfers to many different accounts quickly")
            risk_score += 15

        daily_limit = float(account.get("daily_transfer_limit", 0)) if account else 0
        daily_total = database.get_daily_transfer_total(username)
        if daily_limit > 0 and daily_total + amount > daily_limit:
            reasons.append("Amount exceeds daily transfer limit")
            risk_score += 25

    risk_score = min(risk_score, 100)
    return {
        "fraud_flag": 1 if risk_score >= 25 else 0,
        "risk_score": risk_score,
        "reasons": reasons,
    }


def calculate_user_risk_score(username):
    transactions = database.get_transactions(username)
    suspicious = [item for item in transactions if item["fraud_flag"] == 1]

    score = min(100, sum(int(item.get("risk_score") or 0) for item in suspicious))
    reasons = []
    for transaction in suspicious:
        if transaction["reason"]:
            for reason in transaction["reason"].split("; "):
                if reason and reason not in reasons:
                    reasons.append(reason)

    return {
        "fraud_flag": 1 if suspicious else 0,
        "risk_score": score,
        "reasons": reasons,
        "suspicious_transactions": suspicious,
    }
