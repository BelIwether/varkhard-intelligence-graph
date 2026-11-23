"""Command-line entry point for the Relate-backed demo and analysis."""

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

import relate

from .demo import seed_demo
from .detection import detect_findings
from .store import DEFAULT_DB_PATH, GraphStore, GraphStoreError


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m varkhard",
        description="Seed or analyze a VARKHARD Relate Single File graph.",
    )
    parser.add_argument(
        "--db",
        type=Path,
        default=DEFAULT_DB_PATH,
        help=f"path to the Relate .rl file (default: {DEFAULT_DB_PATH})",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("seed", help="add the deterministic synthetic graph")
    commands.add_parser("analyze", help="print findings as JSON without writing to the graph")
    args = parser.parse_args(argv)

    try:
        if args.command == "seed":
            with GraphStore(args.db) as store:
                seed_demo(store)
            print(f"Seeded synthetic graph at {args.db}")
        else:
            with GraphStore(args.db, read_only=True) as store:
                findings = detect_findings(store)
            print(json.dumps([asdict(finding) for finding in findings], indent=2))
    except (GraphStoreError, relate.Error, OSError) as error:
        print(f"VARKHARD: {error}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
