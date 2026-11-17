

from pathlib import Path
import yaml

RULES_FILE = (
    Path(__file__).resolve().parent.parent
    / "rules"
    / "advice.yaml"
)


def load_rules():
    with RULES_FILE.open("r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def detect_advice(message, direction="input"):
    text = " ".join(message.lower().split())
    rules = load_rules()

    if direction == "output":
        for phrase in rules["guaranteed_return_patterns"]:
            if phrase in text:
                return {
                    "verdict": "BLOCK",
                    "rule_id": "ADVICE-GUARANTEED-RETURN",
                    "reason": "Potentially misleading guaranteed-return claim."
                }

    for phrase in rules["information_patterns"]:
        if phrase in text:
            return {
                "verdict": "ALLOW",
                "rule_id": "ADVICE-GENERAL-INFORMATION",
                "reason": "General financial education."
            }

    for phrase in rules["advice_patterns"]:
        if phrase in text:
            return {
                "verdict": "ALLOW_CONSTRAINED",
                "rule_id": "ADVICE-PERSONALIZED",
                "reason": "Potential personalized financial advice."
            }

    return {
        "verdict": "ALLOW",
        "rule_id": "ADVICE-NO-MATCH",
        "reason": "No configured advice phrase matched."
    }
