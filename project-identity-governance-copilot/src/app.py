"""CLI entry point for the lab.

PowerShell bridge:
- Think of this file like a small script that wires parameters to one main function.
- `from __future__ import annotations` lets Python store type hints lazily, which keeps
    cross-file type references simple in a way similar to deferring type resolution.
- `-> None` means the function returns nothing, similar to a PowerShell function that
    only writes to the pipeline intentionally.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import sys


# `__file__` is a Python-provided variable containing the current file path.
# We use it to calculate the project root so imports work no matter where the script runs from.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = PROJECT_ROOT.parent
for path_value in (PROJECT_ROOT, REPO_ROOT):
        # `sys.path` is the Python import search path, similar to extending a module lookup path.
    if str(path_value) not in sys.path:
        sys.path.insert(0, str(path_value))

from src.rag.chat import answer_question


def main() -> None:
        # `argparse` fills the same role as a PowerShell `param(...)` block for a script.
    parser = argparse.ArgumentParser(description="Run a grounded identity-governance query.")
    parser.add_argument("--prompt", required=True, help="Natural-language question to answer.")
    args = parser.parse_args()
    print(answer_question(args.prompt))


# `__name__ == "__main__"` is Python's "this file was run directly" check.
# It is conceptually similar to the executable portion of a script versus imported helper code.
if __name__ == "__main__":
    main()