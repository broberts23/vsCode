"""CLI entry point for the Identity Security Copilot.

PowerShell bridge:
- This file is like a small script with a parameter block and a switch statement.
- `argparse` fills the same role as a script-level `param(...)` block.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.config import AppConfig
from src.rag.chat import answer_question, summarize_evidence


def main() -> None:
    parser = argparse.ArgumentParser(description='Run the Identity Security Copilot.')
    parser.add_argument('--prompt', help='Natural-language question to answer.')
    parser.add_argument('--summarize', help='Topic text to summarize with the summary deployment.')
    args = parser.parse_args()

    settings = AppConfig.from_env()

    if args.summarize:
        print(summarize_evidence(args.summarize, settings))
        return

    if not args.prompt:
        raise SystemExit('Provide --prompt or --summarize.')

    print(answer_question(args.prompt, settings))


if __name__ == '__main__':
    main()
