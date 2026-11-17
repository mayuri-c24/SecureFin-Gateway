
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix

from guardrails.policy_engine import evaluate_message

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "evaluation" / "unique_text_audit.csv"
MISMATCH_PATH = ROOT / "evaluation" / "unique_text_mismatches.csv"


def main():
    if not DATA_PATH.exists():
        raise SystemExit(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(DATA_PATH, encoding="utf-8-sig")

    required = {"text", "expected_verdict"}
    missing = required - set(df.columns)

    if missing:
        raise SystemExit(f"Missing columns: {sorted(missing)}")

    df = df.dropna(subset=["text", "expected_verdict"]).copy()

    # Normalize expected verdict labels.
    df["expected"] = (
        df["expected_verdict"].astype(str).str.strip().str.upper()
    )

    # Apply the existing deterministic policy engine.
    df["predicted"] = df["text"].astype(str).map(
        lambda message: evaluate_message(message)["verdict"]
    )

    # Overall evaluation.
    labels = sorted(set(df["expected"]) | set(df["predicted"]))
    correct = (df["expected"] == df["predicted"]).sum()
    accuracy = (df["expected"] == df["predicted"]).mean()

    print("\n===== UNIQUE-TEXT POLICY ENGINE EVALUATION =====")
    print("Dataset:", DATA_PATH)
    print("Unique rows evaluated:", len(df))
    print("Correct verdicts:", int(correct))
    print("Incorrect verdicts:", int(len(df) - correct))
    print("Exact agreement:", round(float(accuracy), 4))

    print("\nClassification report:")
    print(
        classification_report(
            df["expected"],
            df["predicted"],
            labels=labels,
            zero_division=0,
        )
    )

    print("Confusion matrix labels:", labels)
    print(confusion_matrix(df["expected"], df["predicted"], labels=labels))

    # Report performance by the original split assignment.
    if "split" in df.columns:
        print("\n===== RESULTS BY SPLIT =====")
        for split, group in df.groupby("split", dropna=False):
            split_accuracy = (
                group["expected"] == group["predicted"]
            ).mean()

            print(
                f"{split}: rows={len(group)}, "
                f"agreement={split_accuracy:.4f}"
            )

    # Save mismatches separately so the original report is preserved.
    mismatches = df[df["expected"] != df["predicted"]].copy()
    mismatches.to_csv(
        MISMATCH_PATH,
        index=False,
        encoding="utf-8-sig",
    )

    print("\nMismatches:", len(mismatches))
    print("Mismatch report:", MISMATCH_PATH)
    print("This is a diagnostic evaluation, not production certification.")


if __name__ == "__main__":
    main()
