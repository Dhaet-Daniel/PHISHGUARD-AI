from __future__ import annotations

import json
from pathlib import Path

FLAGS_FILE = Path(__file__).resolve().parent.parent / "feature_flags.json"

DEFAULT_FLAGS = {
    "ENABLE_SPACY": False,
    "ENABLE_TRANSFORMERS": False,
    "ENABLE_WHOIS": False,
}


def load_flags() -> dict[str, bool]:
    """Return current feature flags. If the file is missing, create it with defaults."""
    if not FLAGS_FILE.exists():
        save_flags(DEFAULT_FLAGS)
        return DEFAULT_FLAGS.copy()

    with FLAGS_FILE.open("r", encoding="utf-8") as handle:
        loaded = json.load(handle)

    flags = DEFAULT_FLAGS.copy()
    for key, default_value in DEFAULT_FLAGS.items():
        flags[key] = bool(loaded.get(key, default_value))
    return flags


def save_flags(flags: dict[str, bool]) -> None:
    merged_flags = DEFAULT_FLAGS.copy()
    for key in DEFAULT_FLAGS:
        if key in flags:
            merged_flags[key] = bool(flags[key])

    with FLAGS_FILE.open("w", encoding="utf-8") as handle:
        json.dump(merged_flags, handle, indent=2)


def get_flag(name: str) -> bool:
    """Get a single flag (e.g. ENABLE_SPACY)."""
    return bool(load_flags().get(name, False))


def set_flag(name: str, value: bool) -> None:
    flags = load_flags()
    flags[name] = bool(value)
    save_flags(flags)
