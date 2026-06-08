import hashlib
import json
import logging
import os
import sys


LOG_LEVEL = os.environ.get("APP_LOG_LEVEL", "INFO").upper()
LOG_SENSITIVE_DATA = os.environ.get("APP_LOG_SENSITIVE", "0") == "1"
LOG_DETAIL = os.environ.get("APP_LOG_DETAIL", "summary").lower()


def get_logger(component):
    logger = logging.getLogger(component)
    if logger.handlers:
        return logger

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s [%(name)s] %(message)s"))
    logger.addHandler(handler)
    logger.setLevel(getattr(logging, LOG_LEVEL, logging.INFO))
    logger.propagate = False
    return logger


def log_event(logger, event, **fields):
    clean_fields = {
        key: value
        for key, value in fields.items()
        if value is not None and value != ""
    }
    details = " ".join(f"{key}={_format_value(value)}" for key, value in clean_fields.items())
    logger.info("%s%s", event, f" {details}" if details else "")


def _format_value(value):
    if isinstance(value, float):
        return f"{value:.2f}"
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, default=str, sort_keys=True)
    return value


def workflow_fields(step, action, **fields):
    return {"step": step, "action": action, **fields}


def log_full_details():
    return LOG_DETAIL == "full"


def log_detail_mode():
    return LOG_DETAIL


def summarize_token(token):
    if not token:
        return {}
    token = str(token)
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
    preview = token if len(token) <= 24 else f"{token[:12]}...{token[-8:]}"
    return {
        "token_preview": preview,
        "token_len": len(token),
        "token_sha256_16": digest,
    }


def sensitive_fields(**fields):
    if not LOG_SENSITIVE_DATA:
        return {}
    return {
        key: value
        for key, value in fields.items()
        if value is not None
        and value != ""
        and (LOG_DETAIL == "full" or not key.startswith("full_"))
    }
