from app_logging import get_logger, log_event, workflow_fields
import database


logger = get_logger("FRAUD")


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
    log_event(logger, "fraud_rule_start", user=username, type=transaction_type, amount=float(amount), balance_before=float(balance_before), balance_after=float(balance_after), receiver=receiver_username)
    account = account or database.get_account(username)
    log_event(logger, "fraud_rule_step", **workflow_fields("01", "account_status_rule", user=username, account_status=account.get("status") if account else "missing"))

    if account and account.get("status") != "active":
        reasons.append("Account status is not active")
        risk_score += 40

    log_event(logger, "fraud_rule_step", **workflow_fields("02", "large_amount_rule", threshold=500, amount=float(amount), triggered=amount > 500))
    if amount > 500:
        reasons.append("Large transaction amount")
        risk_score += 20

    average_amount = database.get_average_transaction_amount(username)
    log_event(logger, "fraud_rule_step", **workflow_fields("03", "average_amount_rule", user=username, average_amount=average_amount, amount=float(amount), threshold=average_amount * 3, triggered=average_amount > 0 and amount > average_amount * 3))
    if average_amount > 0 and amount > average_amount * 3:
        reasons.append("Unusual amount compared to average")
        risk_score += 15

    recent_transactions = database.get_recent_transactions(username, minutes=1)
    log_event(logger, "fraud_rule_step", **workflow_fields("04", "rapid_transaction_rule", user=username, recent_count=len(recent_transactions), window_minutes=1, threshold=5, triggered=len(recent_transactions) >= 5))
    if len(recent_transactions) >= 5:
        reasons.append("Too many transactions in short time")
        risk_score += 20

    if transaction_type in ("WITHDRAW", "TRANSFER_OUT") and balance_before > 0:
        balance_drop = (balance_before - balance_after) / balance_before
        log_event(logger, "fraud_rule_step", **workflow_fields("05", "balance_drop_rule", user=username, balance_drop=balance_drop, threshold=0.80, triggered=balance_drop > 0.80))
        if balance_drop > 0.80:
            reasons.append("Balance dropped too quickly")
            risk_score += 20

    if transaction_type == "TRANSFER_OUT":
        recent_receiver_count = database.count_recent_receivers(username, minutes=5)
        if receiver_username:
            recent_receiver_count += 1
        log_event(logger, "fraud_rule_step", **workflow_fields("06", "many_receivers_rule", user=username, receiver_count=recent_receiver_count, window_minutes=5, threshold=3, triggered=recent_receiver_count > 3))
        if recent_receiver_count > 3:
            reasons.append("Transfers to many different accounts quickly")
            risk_score += 15

        daily_limit = float(account.get("daily_transfer_limit", 0)) if account else 0
        daily_total = database.get_daily_transfer_total(username)
        log_event(logger, "fraud_rule_step", **workflow_fields("07", "daily_limit_rule", user=username, daily_total=daily_total, amount=float(amount), daily_limit=daily_limit, projected_total=daily_total + amount, triggered=daily_limit > 0 and daily_total + amount > daily_limit))
        if daily_limit > 0 and daily_total + amount > daily_limit:
            reasons.append("Amount exceeds daily transfer limit")
            risk_score += 25

    log_event(logger, "fraud_rule_step", **workflow_fields("08", "finalize_risk_score", raw_score=risk_score, reasons=reasons))
    risk_score = min(risk_score, 100)
    fraud_flag = 1 if risk_score >= 25 else 0
    log_event(
        logger,
        "transaction_risk_checked",
        user=username,
        type=transaction_type,
        amount=f"{float(amount):.2f}",
        risk_score=risk_score,
        fraud_flag=fraud_flag,
        reasons="; ".join(reasons),
    )
    return {
        "fraud_flag": fraud_flag,
        "risk_score": risk_score,
        "reasons": reasons,
    }


def calculate_user_risk_score(username):
    log_event(logger, "user_risk_step", **workflow_fields("01", "load_all_transactions", user=username))
    transactions = database.get_transactions(username)
    suspicious = [item for item in transactions if item["fraud_flag"] == 1]
    log_event(logger, "user_risk_step", **workflow_fields("02", "filter_suspicious_transactions", user=username, total_transactions=len(transactions), suspicious_count=len(suspicious)))

    score = min(100, sum(int(item.get("risk_score") or 0) for item in suspicious))
    reasons = []
    for transaction in suspicious:
        if transaction["reason"]:
            for reason in transaction["reason"].split("; "):
                if reason and reason not in reasons:
                    reasons.append(reason)

    fraud_flag = 1 if suspicious else 0
    log_event(
        logger,
        "user_risk_calculated",
        user=username,
        risk_score=score,
        fraud_flag=fraud_flag,
        suspicious_count=len(suspicious),
        reasons="; ".join(reasons),
    )
    return {
        "fraud_flag": fraud_flag,
        "risk_score": score,
        "reasons": reasons,
        "suspicious_transactions": suspicious,
    }
