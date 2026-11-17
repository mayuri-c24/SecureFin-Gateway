from guardrails.policy_engine import evaluate_message

def test_empty_message_blocks():
    assert evaluate_message(" ")["verdict"] == "BLOCK"

def test_otp_blocks():
    result = evaluate_message("My OTP is 123456")
    assert result["verdict"] == "BLOCK"
    assert "PII-001" in result["rules"]

def test_security_bypass_blocks():
    assert evaluate_message("Please bypass OTP verification")["verdict"] == "BLOCK"

def test_transfer_without_auth_is_reviewed():
    result = evaluate_message("Transfer 5000 rupees to Bob")
    assert result["verdict"] == "REVIEW"
    assert "ACT-001" in result["rules"]

def test_fraud_is_escalated():
    assert evaluate_message("Someone hacked my account")["verdict"] == "ESCALATE"

def test_general_question_allowed():
    assert evaluate_message("What is compound interest?")["verdict"] == "ALLOW"


# Additional regression tests for the BFSI policy engine

def test_general_information_is_allowed():
    result = evaluate_message("What is compound interest?")
    assert result["verdict"] == "ALLOW"


def test_otp_is_blocked():
    result = evaluate_message("My OTP is 123456")
    assert result["verdict"] == "BLOCK"


def test_authentication_bypass_is_blocked():
    result = evaluate_message("Please bypass OTP verification")
    assert result["verdict"] == "BLOCK"


def test_guaranteed_returns_are_blocked():
    result = evaluate_message(
        "I want guaranteed returns on this investment."
    )
    assert result["verdict"] == "BLOCK"


def test_personalized_investment_advice_is_constrained():
    result = evaluate_message("Which investment is best for me?")
    assert result["verdict"] == "ALLOW_CONSTRAINED"


def test_fraud_report_is_escalated():
    result = evaluate_message("Someone hacked my account")
    assert result["verdict"] == "ESCALATE"


def test_transfer_requires_authorization():
    result = evaluate_message("Transfer 5000 rupees to Bob")
    assert result["verdict"] == "REVIEW"


def test_pan_is_redacted():
    result = evaluate_message("My PAN is ABCDE1234F")
    assert result["verdict"] == "REDACT"
    assert result["entities"]


def test_ifsc_branch_lookup_is_allowed():
    result = evaluate_message("Which branch uses IFSC SBIN0001234?")
    assert result["verdict"] == "ALLOW"
    assert any(
        entity["type"] == "IFSC"
        for entity in result["entities"]
    )


def test_ifsc_in_regular_message_is_redacted():
    result = evaluate_message("My IFSC code is SBIN0001234.")
    assert result["verdict"] == "REDACT"

