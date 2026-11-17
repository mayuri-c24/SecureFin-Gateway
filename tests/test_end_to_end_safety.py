
from unittest.mock import patch

from guardrails.chatbot_pipeline import run_chatbot


def test_safe_question_uses_llm_and_returns_validated_answer():
    fake_answer = (
        "Compound interest means earning interest on accumulated interest."
    )

    with patch(
        "guardrails.chatbot_pipeline.generate_demo_response",
        return_value=fake_answer,
    ) as mock_llm:
        result = run_chatbot("What is compound interest?")

    assert result["input_verdict"] == "ALLOW"
    assert result["output_verdict"] == "ALLOW"
    assert result["final_response"] == fake_answer
    assert result["llm_used"] is True
    mock_llm.assert_called_once()


def test_guaranteed_return_input_does_not_call_llm():
    with patch(
        "guardrails.chatbot_pipeline.generate_demo_response"
    ) as mock_llm:
        result = run_chatbot(
            "Tell me an investment with guaranteed returns."
        )

    assert result["input_verdict"] == "BLOCK"
    assert result["llm_used"] is False
    assert result["output_verdict"] == "NOT_RUN"
    mock_llm.assert_not_called()


def test_personalized_advice_does_not_call_llm():
    with patch(
        "guardrails.chatbot_pipeline.generate_demo_response"
    ) as mock_llm:
        result = run_chatbot(
            "Should I move all my fixed deposit money into equity?"
        )

    assert result["input_verdict"] in {
        "ALLOW_CONSTRAINED",
        "ESCALATE",
    }
    assert result["llm_used"] is False
    mock_llm.assert_not_called()


def test_unsafe_generated_answer_is_blocked():
    fake_answer = (
        "This investment guarantees 20% returns every year."
    )

    with patch(
        "guardrails.chatbot_pipeline.generate_demo_response",
        return_value=fake_answer,
    ):
        result = run_chatbot("What is compound interest?")

    assert result["input_verdict"] == "ALLOW"
    assert result["output_verdict"] == "BLOCK"
    assert fake_answer not in result["final_response"]


def test_generated_answer_with_pan_is_redacted():
    fake_answer = "The customer's PAN is ABCDE1234F."

    with patch(
        "guardrails.chatbot_pipeline.generate_demo_response",
        return_value=fake_answer,
    ):
        result = run_chatbot("What is compound interest?")

    assert result["input_verdict"] == "ALLOW"
    assert result["output_verdict"] == "REDACT"
    assert "ABCDE1234F" not in result["final_response"]
