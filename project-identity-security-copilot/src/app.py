"""CLI entry point for the Identity Security Copilot.

PowerShell bridge:
- This file is like a small script with a `param(...)` block and a simple branch for
    choosing between two execution paths.
- `argparse` is the Python equivalent of collecting named parameters before the
    script body runs.
- The module is intentionally thin so the interesting logic lives in reusable helper
    functions instead of being buried in the entry point.
"""

from __future__ import annotations
from src.rag import chat
from src.config import AppConfig

import argparse
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def main() -> None:
    """Parse command-line input and route it to the correct copilot action.

    PowerShell bridge:
    - Think of this like the top of a script that reads parameters, decides which
      branch to run, and then calls one helper function.
    - The function keeps the control flow explicit so the code remains easy to scan.
    """

    parser = argparse.ArgumentParser(
        description='Run the Identity Security Copilot.')
    parser.add_argument(
        '--prompt', help='Natural-language question to answer.')
    parser.add_argument(
        '--summarize', help='Topic text to summarize with the summary deployment.')
    args = parser.parse_args()

    # Load the environment-driven configuration once so both code paths use the same
    # settings object, just like loading a hashtable of script settings up front.
    settings = AppConfig.from_env()

    if args.summarize:
        # Summary mode is a separate path because it uses a different deployment name.
        summarize_handler = getattr(chat, 'summarize_evidence')
        print(summarize_handler(args.summarize, settings))
        return

    if not args.prompt:
        raise SystemExit('Provide --prompt or --summarize.')

    # The default mode is the grounded question-answering path.
    print(chat.answer_question(args.prompt, settings))


if __name__ == '__main__':
    # Python's direct-execution guard is the same idea as checking whether a script
    # is being run directly versus imported as a helper module.
    main()
