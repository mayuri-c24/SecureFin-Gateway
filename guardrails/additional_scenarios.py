
"""Additional deterministic BFSI safeguards.

These functions demonstrate policy checks with simulated state.
They do not connect to a real bank or execute transactions.
"""

import re


def result(allowed: bool, scenario: str, reason: str) -> dict:
    return {
        "allowed": allowed,
        "scenario": scenario,
        "decision": "ALLOW" if allowed else "BLOCK",
        "reason": reason,
    }


# 1. Expired session
def check_session(session_active: bool) -> dict:
    if not session_active:
        return result(
            False, "SESSION-01",
            "Session expired. Re-authentication is required."
        )
    return result(True, "SESSION-01", "Session is active.")


# 2. Request-rate limiting
def check_rate_limit(request_count: int, limit: int = 10) -> dict:
    if limit < 1 or request_count < 0:
        raise ValueError("Request count must be >= 0 and limit must be >= 1.")
    if request_count >= limit:
        return result(
            False, "RATE-01",
            f"Request limit reached ({limit}). Try again later."
        )
    return result(True, "RATE-01", "Request is within the configured limit.")


# 3. Duplicate transaction request
def check_duplicate_request(
    request_id: str, processed_request_ids: set[str]
) -> dict:
    if not request_id.strip():
        return result(False, "TXN-DUP-01", "Request ID is required.")
    if request_id in processed_request_ids:
        return result(
            False, "TXN-DUP-01",
            "Duplicate request detected; do not process it again."
        )
    return result(
        True, "TXN-DUP-01",
        "Request ID has not been seen in the supplied test state."
    )


# 4. Transaction approval must match submitted details
def check_transaction_approval(
    approved_amount: float,
    submitted_amount: float,
    approved_beneficiary: str,
    submitted_beneficiary: str,
) -> dict:
    if approved_amount <= 0 or submitted_amount <= 0:
        return result(False, "TXN-INTEGRITY-01", "Amount must be positive.")
    if (
        approved_amount != submitted_amount
        or approved_beneficiary.strip().casefold()
        != submitted_beneficiary.strip().casefold()
    ):
        return result(
            False, "TXN-INTEGRITY-01",
            "Transaction details changed after approval. Approve again."
        )
    return result(
        True, "TXN-INTEGRITY-01",
        "Submitted details match the approved test details."
    )


# 5. Beneficiary changes require an authorization flag
def check_beneficiary_change(
    is_change: bool, authorization_verified: bool
) -> dict:
    if is_change and not authorization_verified:
        return result(
            False, "BENEFICIARY-01",
            "Beneficiary change requires verified authorization."
        )
    return result(
        True, "BENEFICIARY-01",
        "No unauthorized beneficiary change detected."
    )


# 6. Redact common sensitive values before logging
def redact_log_text(text: str) -> str:
    # PAN-like values
    text = re.sub(
        r"(?i)\b[A-Z]{5}\d{4}[A-Z]\b",
        "[REDACTED_PAN]", text
    )
    # Aadhaar-like 12 digits, optionally separated by spaces or hyphens
    text = re.sub(
        r"(?<!\d)(?:\d[ -]?){11}\d(?!\d)",
        "[REDACTED_AADHAAR]", text
    )
    # OTP values after an explicit OTP label
    text = re.sub(
        r"(?i)(\bOTP\s*[:=]?\s*)\d{4,8}\b",
        r"\1[REDACTED_OTP]", text
    )
    # Password values after an explicit password label
    text = re.sub(
        r"(?i)(\bpassword\s*[:=]\s*)\S+",
        r"\1[REDACTED]", text
    )
    return text


def check_log_is_safe(log_text: str) -> dict:
    redacted = redact_log_text(log_text)
    safe = redacted == log_text
    return {
        "allowed": safe,
        "scenario": "LOG-PII-01",
        "decision": "ALLOW" if safe else "REDACT",
        "reason": (
            "No supported sensitive pattern detected in this log text."
            if safe else "Sensitive-looking values were redacted."
        ),
        "safe_text": redacted,
    }


# 7. Account-specific claims require verified data
def check_account_claim(data_available: bool, data_verified: bool) -> dict:
    if not data_available or not data_verified:
        return result(
            False, "ACCOUNT-CLAIM-01",
            "Cannot make an account-specific claim without verified data."
        )
    return result(
        True, "ACCOUNT-CLAIM-01",
        "Verified test data is available."
    )


# 8. Product disclosures must be current and complete
def check_disclosure(
    disclosure_version: str,
    current_version: str,
    required_terms_present: bool,
) -> dict:
    if not disclosure_version or disclosure_version != current_version:
        return result(
            False, "DISCLOSURE-01",
            "Disclosure is missing or out of date."
        )
    if not required_terms_present:
        return result(
            False, "DISCLOSURE-01",
            "Required disclosure terms are missing."
        )
    return result(
        True, "DISCLOSURE-01",
        "Disclosure version and required terms passed the check."
    )


# 9. Required fields for a transfer must be present
def check_transfer_details(amount, beneficiary: str) -> dict:
    if amount is None or not beneficiary.strip():
        return result(
            False, "TXN-CLARIFY-01",
            "Ask for the missing amount or beneficiary before proceeding."
        )
    try:
        numeric_amount = float(amount)
    except (TypeError, ValueError):
        return result(
            False, "TXN-CLARIFY-01",
            "The transfer amount must be a valid number."
        )
    if numeric_amount <= 0:
        return result(
            False, "TXN-CLARIFY-01",
            "The transfer amount must be positive."
        )
    return result(
        True, "TXN-CLARIFY-01",
        "Required transfer details are present in this test."
    )


# 10. Conflicting instructions need clarification
def check_conflicting_instructions(
    requested_actions: list[str],
) -> dict:
    actions = {action.strip().casefold() for action in requested_actions}
    has_cancel = "cancel" in actions
    has_continue = "continue" in actions

    if has_cancel and has_continue:
        return result(
            False, "CONFLICT-01",
            "Conflicting instructions detected. Ask the customer to clarify."
        )
    return result(
        True, "CONFLICT-01",
        "No cancel/continue conflict detected by this check."
    )

