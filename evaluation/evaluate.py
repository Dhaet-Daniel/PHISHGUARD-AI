from __future__ import annotations

import asyncio
import argparse
import json
from pathlib import Path

from backend.services.detector import detect_phishing

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "sample_emails.json"


def _load_dataset(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def _summarize_rows(rows: list[dict], total_samples: int) -> dict:
    prediction_matches = sum(int(row["prediction_match"]) for row in rows)
    category_matches = sum(int(row["category_match"]) for row in rows)
    false_positives = [
        row for row in rows if row["expected_prediction"] == "Safe" and row["actual_prediction"] == "Phishing"
    ]
    false_negatives = [
        row for row in rows if row["expected_prediction"] == "Phishing" and row["actual_prediction"] == "Safe"
    ]
    category_misses = [row for row in rows if not row["category_match"]]

    return {
        "samples": total_samples,
        "prediction_accuracy": round(prediction_matches / total_samples, 3),
        "category_accuracy": round(category_matches / total_samples, 3),
        "false_positives": len(false_positives),
        "false_negatives": len(false_negatives),
        "category_misses": len(category_misses),
        "rows": rows,
    }


async def main(dataset_path: Path) -> None:
    dataset = _load_dataset(dataset_path)
    rows = []

    for sample in dataset:
        result = await detect_phishing(
            sample["subject"],
            sample["sender"],
            sample["body"],
            sample.get("headers"),
            sample.get("attachments"),
        )
        prediction_ok = result["prediction"] == sample["expected_prediction"]
        category_ok = result["category"] == sample["expected_category"]
        rows.append(
            {
                "name": sample["name"],
                "notes": sample.get("notes", ""),
                "expected_prediction": sample["expected_prediction"],
                "actual_prediction": result["prediction"],
                "expected_category": sample["expected_category"],
                "actual_category": result["category"],
                "score": result["score"],
                "prediction_match": prediction_ok,
                "category_match": category_ok,
            }
        )

    summary = _summarize_rows(rows, len(dataset))
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Evaluate PhishGuardAI detector against a labeled dataset.")
    parser.add_argument(
        "--dataset",
        default=str(DATASET_PATH),
        help="Path to a labeled JSON dataset. Defaults to backend/evaluation/sample_emails.json",
    )
    args = parser.parse_args()
    asyncio.run(main(Path(args.dataset)))
