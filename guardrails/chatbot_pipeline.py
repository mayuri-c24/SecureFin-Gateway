
"""Demonstration pipeline connecting input and output guardrails."""

from typing import Any

from guardrails.policy_engine import evaluate_message
from guardrails.output_guardrail import validate_output



def generate_demo_response(message: str) -> str:
    """Generate a response using the local Llama model through Ollama."""

    import json
    import urllib.request
    import urllib.error

    payload = {
        "model": "llama3.2:3b",
        "prompt": (
            "You are a helpful banking education assistant. "
            "Answer in simple language. Provide general information only. "
            "Never claim investment returns are guaranteed. "
            "Never ask the user to share passwords, PINs, or OTPs. "
            "Do not claim to have performed a banking transaction. "
            "For account-specific issues, direct the user to their bank's "
            "official secure channel.\n\n"
            f"User question: {message}\n\nAssistant answer:"
        ),
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    request = urllib.request.Request(
        "http://localhost:11434/api/generate",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            result = json.loads(response.read().decode("utf-8"))

        answer = result.get("response", "").strip()

        if not answer:
            return (
                "I couldn't generate a response. "
                "Please try again or use your bank's official channel."
            )

        return answer

    except (urllib.error.URLError, TimeoutError, OSError):
        return (
            "The local language model is currently unavailable. "
            "Please try again shortly."
        )
    except (json.JSONDecodeError, KeyError, TypeError):
        return (
            "I couldn't process the model response. "
            "Please try again shortly."
        )



def run_chatbot(
    message: str,
    auth_level: str = "unauthenticated",
    tool_call: str | None = None,
) -> dict[str, Any]:
    """Check the input, then validate generated output when appropriate."""

    input_decision = evaluate_message(
        message,
        auth_level=auth_level,
        tool_call=tool_call,
    )

    input_verdict = input_decision["verdict"]

    # Only ordinary ALLOW requests proceed to the demo response generator.
    # All other decisions return the policy engine's existing safe message.
    if input_verdict != "ALLOW":
        return {
            "input_verdict": input_verdict,
            "input_rule_ids": input_decision["rule_ids"],
            "output_verdict": "NOT_RUN",
            "output_rule_ids": [],
            "final_response": input_decision["message"],
            "input_decision": input_decision,
            "output_decision": None,
            "llm_used": False,
        }

    # Generate a demo response only after the input passes policy checks.
    proposed_response = generate_demo_response(message)

    # Validate the proposed answer before returning it.
    output_decision = validate_output(proposed_response)

    return {
        "input_verdict": input_verdict,
        "input_rule_ids": input_decision["rule_ids"],
        "output_verdict": output_decision["verdict"],
        "output_rule_ids": output_decision["rule_ids"],
        "final_response": output_decision["safe_text"],
        "input_decision": input_decision,
        "output_decision": output_decision,
        "llm_used": True,
    }
