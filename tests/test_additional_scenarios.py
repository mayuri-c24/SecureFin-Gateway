
from guardrails.additional_scenarios import (
    check_session,
    check_rate_limit,
    check_duplicate_request,
    check_transaction_approval,
    check_beneficiary_change,
    check_log_is_safe,
    check_account_claim,
    check_disclosure,
    check_transfer_details,
    check_conflicting_instructions,
)


def test_01_expired_session_is_blocked():
    assert check_session(False)["decision"] == "BLOCK"
    assert check_session(True)["decision"] == "ALLOW"


def test_02_request_limit_is_enforced():
    assert check_rate_limit(10, limit=10)["decision"] == "BLOCK"
    assert check_rate_limit(3, limit=10)["decision"] == "ALLOW"


def test_03_duplicate_request_is_rejected():
    seen = {"request-123"}
    assert check_duplicate_request(
        "request-123", seen
    )["decision"] == "BLOCK"
    assert check_duplicate_request(
        "request-456", seen
    )["decision"] == "ALLOW"


def test_04_changed_transaction_details_are_rejected():
    assert check_transaction_approval(
        1000, 10000, "BENEFICIARY-A", "BENEFICIARY-A"
    )["decision"] == "BLOCK"

    assert check_transaction_approval(
        1000, 1000, "BENEFICIARY-A", "BENEFICIARY-B"
    )["decision"] == "BLOCK"

    assert check_transaction_approval(
        1000, 1000, "BENEFICIARY-A", "BENEFICIARY-A"
    )["decision"] == "ALLOW"


def test_05_unauthorized_beneficiary_change_is_rejected():
    assert check_beneficiary_change(
        True, False
    )["decision"] == "BLOCK"
    assert check_beneficiary_change(
        True, True
    )["decision"] == "ALLOW"


def test_06_sensitive_values_are_redacted_from_logs():
    output = check_log_is_safe(
        "PAN ABCDE1234F OTP: 123456 password: secret123"
    )
    assert output["decision"] == "REDACT"
    assert "ABCDE1234F" not in output["safe_text"]
    assert "123456" not in output["safe_text"]
    assert "secret123" not in output["safe_text"]

    assert check_log_is_safe(
        "Application started successfully"
    )["decision"] == "ALLOW"


def test_07_unverified_account_claim_is_rejected():
    assert check_account_claim(
        False, False
    )["decision"] == "BLOCK"
    assert check_account_claim(
        True, False
    )["decision"] == "BLOCK"
    assert check_account_claim(
        True, True
    )["decision"] == "ALLOW"


def test_08_outdated_or_incomplete_disclosure_is_rejected():
    assert check_disclosure(
        "1.0", "2.0", True
    )["decision"] == "BLOCK"
    assert check_disclosure(
        "2.0", "2.0", False
    )["decision"] == "BLOCK"
    assert check_disclosure(
        "2.0", "2.0", True
    )["decision"] == "ALLOW"


def test_09_missing_transfer_details_require_clarification():
    assert check_transfer_details(
        None, "BENEFICIARY-A"
    )["decision"] == "BLOCK"
    assert check_transfer_details(
        1000, ""
    )["decision"] == "BLOCK"
    assert check_transfer_details(
        1000, "BENEFICIARY-A"
    )["decision"] == "ALLOW"


def test_10_conflicting_instructions_require_clarification():
    assert check_conflicting_instructions(
        ["cancel", "continue"]
    )["decision"] == "BLOCK"
    assert check_conflicting_instructions(
        ["cancel"]
    )["decision"] == "ALLOW"
