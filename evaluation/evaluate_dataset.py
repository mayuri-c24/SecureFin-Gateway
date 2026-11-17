from pathlib import Path
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from guardrails.policy_engine import evaluate_message

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "bfsi_guardrail_multilingual_5000.csv"

def main():
    if not DATA_PATH.exists():
        raise SystemExit(
            f"Dataset not found: {DATA_PATH}\n"
            "Copy your CSV into the data folder with the expected filename."
        )
    df = pd.read_csv(DATA_PATH, encoding="utf-8-sig")
    required = {"text", "expected_verdict"}
    missing = required - set(df.columns)
    if missing:
        raise SystemExit(f"Missing CSV columns: {sorted(missing)}")

    df = df.dropna(subset=["text", "expected_verdict"]).copy()
    df["expected"] = df["expected_verdict"].astype(str).str.strip().str.upper()
    df["predicted"] = df["text"].astype(str).map(
        lambda message: evaluate_message(message)["verdict"]
    )
    labels = sorted(set(df["expected"]) | set(df["predicted"]))
    print("Rows evaluated:", len(df))
    print("Exact agreement:", round((df["expected"] == df["predicted"]).mean(), 4))
    print(classification_report(df["expected"], df["predicted"],
                                labels=labels, zero_division=0))
    print("Confusion matrix labels:", labels)
    print(confusion_matrix(df["expected"], df["predicted"], labels=labels))
    mismatches = df[df["expected"] != df["predicted"]]
    out = ROOT / "evaluation" / "mismatches.csv"
    mismatches.to_csv(out, index=False, encoding="utf-8-sig")
    print("Mismatches saved to:", out)
    print("This is a baseline diagnostic, not a production certification.")

if __name__ == "__main__":
    main()
