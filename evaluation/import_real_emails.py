from __future__ import annotations

import argparse
import json
from pathlib import Path

ALLOWED_PREDICTIONS = {"Safe", "Phishing"}
ALLOWED_CATEGORIES = {
    "phishing",
    "suspicious",
    "legitimate_marketing",
    "transactional",
    "security_notice",
    "general_safe",
}
REQUIRED_FIELDS = {
    "name",
    "notes",
    "expected_prediction",
    "expected_category",
    "subject",
    "sender",
    "body",
    "headers",
    "attachments",
}

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATASET = BASE_DIR / "sample_emails.json"


def load_json(path: Path) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_entry(entry: dict) -> None:
    missing = REQUIRED_FIELDS - set(entry)
    if missing:
        raise ValueError(f"Entry '{entry.get('name', '<unknown>')}' is missing fields: {sorted(missing)}")
    if entry["expected_prediction"] not in ALLOWED_PREDICTIONS:
        raise ValueError(f"Entry '{entry['name']}' has invalid expected_prediction: {entry['expected_prediction']}")
    if entry["expected_category"] not in ALLOWED_CATEGORIES:
        raise ValueError(f"Entry '{entry['name']}' has invalid expected_category: {entry['expected_category']}")
    if not isinstance(entry["headers"], dict):
        raise ValueError(f"Entry '{entry['name']}' must use an object for headers.")
    if not isinstance(entry["attachments"], list):
        raise ValueError(f"Entry '{entry['name']}' must use a list for attachments.")
    if "@" not in entry["sender"]:
        raise ValueError(f"Entry '{entry['name']}' must use a valid sender email address.")


def merge_entries(existing: list[dict], incoming: list[dict]) -> list[dict]:
    by_name = {entry["name"]: entry for entry in existing}
    for entry in incoming:
        validate_entry(entry)
        by_name[entry["name"]] = entry
    return [by_name[name] for name in sorted(by_name)]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Merge sanitized real-email samples into the evaluation dataset."
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Path to a JSON file containing sanitized labeled email entries.",
    )
    parser.add_argument(
        "--dataset",
        default=str(DEFAULT_DATASET),
        help="Target evaluation dataset path. Defaults to backend/evaluation/sample_emails.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate and preview the merged entry count without writing the dataset.",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    dataset_path = Path(args.dataset)
    incoming = load_json(input_path)
    existing = load_json(dataset_path)
    merged = merge_entries(existing, incoming)

    if args.dry_run:
        print(
            json.dumps(
                {
                    "input_entries": len(incoming),
                    "existing_entries": len(existing),
                    "merged_entries": len(merged),
                },
                indent=2,
            )
        )
        return

    dataset_path.write_text(json.dumps(merged, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "written_to": str(dataset_path),
                "merged_entries": len(merged),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
