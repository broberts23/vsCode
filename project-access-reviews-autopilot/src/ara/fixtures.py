"""Load Graph-shaped fixture JSON from config/simulated-events."""

from __future__ import annotations

import json
from pathlib import Path

from ara.models import ReviewWorkMessage


def load_fixture_file(path: Path) -> ReviewWorkMessage:
    data = json.loads(path.read_text(encoding="utf-8"))
    return ReviewWorkMessage.model_validate(data)


def load_all_fixtures(directory: Path) -> list[ReviewWorkMessage]:
    if not directory.is_dir():
        raise FileNotFoundError(f"Fixtures directory not found: {directory}")
    messages: list[ReviewWorkMessage] = []
    for path in sorted(directory.glob("*.json")):
        messages.append(load_fixture_file(path))
    return messages


def load_fixture_by_stem(directory: Path, stem: str) -> ReviewWorkMessage:
    path = directory / f"{stem}.json"
    if not path.is_file():
        raise FileNotFoundError(f"Fixture not found: {path}")
    return load_fixture_file(path)
