
from guardrails.advice_detector import detect_advice


def test_general_information():
    result = detect_advice("What is a fixed deposit?")
    assert result["verdict"] == "ALLOW"


def test_personalized_advice():
    result = detect_advice("Should I invest in equity?")
    assert result["verdict"] == "ALLOW_CONSTRAINED"


def test_stock_recommendation():
    result = detect_advice("Which stock should I buy?")
    assert result["verdict"] == "ALLOW_CONSTRAINED"


def test_guaranteed_return_output():
    result = detect_advice(
        "This investment offers guaranteed returns.",
        direction="output"
    )
    assert result["verdict"] == "BLOCK"


def test_unmatched_message():
    result = detect_advice("How can I update my address?")
    assert result["verdict"] == "ALLOW"
