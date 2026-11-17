from guardrails.output_guardrail import validate_output


def test_guaranteed_returns_are_blocked():
    result = validate_output(
        "This investment guarantees 20% returns every year."
    )
    assert result["verdict"] == "BLOCK"


def test_pan_is_redacted():
    result = validate_output(
        "The customer's PAN is ABCDE1234F."
    )
    assert result["verdict"] == "REDACT"
    assert "ABCDE1234F" not in result["safe_text"]


def test_general_educational_answer_is_allowed():
    result = validate_output(
        "Compound interest means earning interest on accumulated interest."
    )
    assert result["verdict"] == "ALLOW"


def test_empty_output_is_blocked():
    result = validate_output("")
    assert result["verdict"] == "BLOCK"


def test_whitespace_only_output_is_blocked():
    result = validate_output("   ")
    assert result["verdict"] == "BLOCK"