"""Tests for prompt routing and target extraction in the CLI."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.app import _extract_target_from_prompt


def test_extract_target_from_update_wiki_prompt() -> None:
    result = _extract_target_from_prompt(
        'update the wiki for MyFunction function')
    assert result == 'MyFunction'


def test_extract_target_from_create_wiki_prompt() -> None:
    result = _extract_target_from_prompt(
        'create a new wiki for CalculateTotal function')
    assert result == 'CalculateTotal'


def test_extract_target_from_document_command() -> None:
    result = _extract_target_from_prompt(
        'document the AuthService class')
    assert result == 'AuthService'


def test_extract_target_no_match_returns_none() -> None:
    result = _extract_target_from_prompt(
        'tell me about something unrelated')
    assert result is None


def test_extract_target_from_function_keyword() -> None:
    result = _extract_target_from_prompt(
        'function MyParser needs documentation')
    assert result == 'MyParser'
