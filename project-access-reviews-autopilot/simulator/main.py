"""Cron / CLI simulator: publish fixture events onto Service Bus."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_src = Path(__file__).resolve().parents[1] / "src"
if _src.is_dir() and str(_src) not in sys.path:
    sys.path.insert(0, str(_src))

from ara.fixtures import load_all_fixtures, load_fixture_by_stem
from ara.messaging import ensure_local_entities, publish_review_work
from ara.settings import get_settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ara.simulator")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Publish simulated Graph-shaped access-review events"
    )
    parser.add_argument(
        "--fixture",
        help="Fixture stem (e.g. review-pending). Default: all except poison.",
    )
    parser.add_argument(
        "--include-poison",
        action="store_true",
        help="Also publish the poison DLQ fixture when selecting all.",
    )
    args = parser.parse_args()

    settings = get_settings()
    ensure_local_entities(settings)

    if args.fixture:
        works = [load_fixture_by_stem(settings.fixtures_path, args.fixture)]
    else:
        works = [
            w
            for w in load_all_fixtures(settings.fixtures_path)
            if args.include_poison or not w.force_poison
        ]

    for work in works:
        publish_review_work(settings, work)
        logger.info("Published %s (%s)", work.event_type.value, work.correlation_id)

    logger.info("Done. published=%s", len(works))


if __name__ == "__main__":
    main()
