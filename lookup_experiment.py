"""Run the repeatable 30-target FIND_NODE experiment from the project root."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from overlay_node.experiment import (  # noqa: E402
    print_lookup_experiment_summary,
    run_lookup_experiment,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure iterative FIND_NODE lookups for targets absent from the overlay"
    )
    parser.add_argument("--count", type=int, default=30, help="число поисков (по умолчанию 30)")
    parser.add_argument(
        "--output",
        default="results/lookup_experiment.csv",
        help="путь CSV с метриками",
    )
    parser.add_argument("--seed", type=int, default=20261007, help="seed генератора целей")
    args = parser.parse_args()
    if args.count < 1:
        parser.error("--count должен быть не меньше 1")

    summary = asyncio.run(
        run_lookup_experiment(count=args.count, output_path=args.output, seed=args.seed)
    )
    print_lookup_experiment_summary(summary)


if __name__ == "__main__":
    main()
