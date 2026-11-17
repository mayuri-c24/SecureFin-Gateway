
from pathlib import Path

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from guardrails.policy_engine import evaluate_message

ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "evaluation" / "independent_holdout.csv"
OUTPUT_PATH = ROOT / "evaluation" / "independent_holdout_results.csv"


def main():
    df = pd.read_csv(DATA_PATH, encoding="utf-8-sig")
    df["expected"] = df["expected_verdict"].astype(str).str.strip().str.upper()

    df["predicted"] = df["text"].astype(str).map(
        lambda message: evaluate_message(message)["verdict"]
    )

    labels = sorted(set(df["expected"]) | set(df["predicted"]))
    matches = df["expected"] == df["predicted"]

    print("\n===== PRELIMINARY HOLDOUT EVALUATION =====")
    print("Rows evaluated:", len(df))
    print("Correct:", int(matches.sum()))
    print("Incorrect:", int((~matches).sum()))
    print("Exact agreement:", round(float(matches.mean()), 4))

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

    print("\nIndividual results:")
    print(
        df[["id", "category", "expected", "predicted"]]
        .to_string(index=False)
    )

    df.to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")
    print("\nResults saved to:", OUTPUT_PATH)
    print("This is a preliminary test, not production certification.")


if __name__ == "__main__":
    main()
