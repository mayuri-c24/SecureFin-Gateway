"""Output guardrail for proposed BFSI chatbot responses."""

from typing import Any

from guardrails.policy_engine import (
    GUARANTEE_RE,
    detect_entities,
    redact_sensitive_data,
)


def validate_output(response: str) -> dict[str, Any]:
    """Check a proposed response before returning it to a user."""

    if not isinstance(response, str) or not response.strip():
        return {
            "verdict": "BLOCK",
            "rules": ["OUTPUT-EMPTY-001"],
            "rule_ids": ["OUTPUT-EMPTY-001"],
            "safe_text": "",
            "reason": "The proposed response is empty or invalid.",
        }

    if GUARANTEE_RE.search(response):
        return {
            "verdict": "BLOCK",
            "rules": ["OUTPUT-GUARANTEE-001"],
            "rule_ids": ["OUTPUT-GUARANTEE-001"],
            "safe_text": (
                "The response was withheld because it may contain "
                "an investment-return guarantee."
            ),
            "reason": "Potential guaranteed-return claim detected.",
        }

    entities = detect_entities(response)

    sensitive_types = {
        "PAN",
        "AADHAAR",
        "CARD_NUMBER",
        "ACCOUNT_NUMBER",
        "IFSC",
    }

    sensitive_entities = [
        entity
        for entity in entities
        if entity.get("type") in sensitive_types
    ]

    if sensitive_entities:
        return {
            "verdict": "REDACT",
            "rules": ["OUTPUT-PII-001"],
            "rule_ids": ["OUTPUT-PII-001"],
            "safe_text": redact_sensitive_data(response),
            "reason": "Potential sensitive identifier detected.",
        }

    return {
        "verdict": "ALLOW",
        "rules": ["OUTPUT-ALLOW-001"],
            "rule_ids": ["OUTPUT-ALLOW-001"],
        "safe_text": response,
        "reason": "No configured output violation was detected.",
    }
