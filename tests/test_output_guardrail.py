
from guardrails.output_guardrail import validate_output


def test_safe_general_answer_is_allowed():
    result = validate_output(
        "Compound interest means earning interest on previous interest."
    )
    assert result["verdict"] == "ALLOW"


def test_guaranteed_return_claim_is_blocked():
    result = validate_output(
        "This investment offers guaranteed returns."
    )
    assert result["verdict"] == "BLOCK"


def test_pan_in_output_is_redacted():
    result = validate_output(
        "The customer's PAN is ABCDE1234F."
    )
    assert result["verdict"] == "REDACT"
    assert "ABCDE1234F" not in result["safe_text"]


def test_aadhaar_in_output_is_redacted():
    result = validate_output(
        "The Aadhaar number is 553275027545."
    )
    assert result["verdict"] == "REDACT"
    assert "553275027545" not in result["safe_text"]


def test_empty_output_is_blocked():
    result = validate_output("")
    assert result["verdict"] == "BLOCK"
