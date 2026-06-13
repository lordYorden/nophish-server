#!/usr/bin/env python3
"""Combine existing detection evaluation JSONL files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def dedupe_key(row: dict[str, Any]) -> tuple[str, str, str | None]:
    metadata = row.get("metadata") or {}
    checked_url = metadata.get("checked_url", metadata.get("raw_url"))
    serialized_url = json.dumps(checked_url, ensure_ascii=False, sort_keys=True) if checked_url is not None else None
    return (str(row.get("case_id")), str(row.get("module")), serialized_url)


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"input file is missing: {path}")

    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                value = json.loads(stripped)
            except json.JSONDecodeError as exc:
                preview = stripped[:160]
                raise ValueError(f"{path}:{line_number}: invalid JSONL row: {preview!r}") from exc
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{line_number}: expected JSON object row")
            rows.append(value)
    return rows


def combine(inputs: list[Path]) -> tuple[list[dict[str, Any]], dict[Path, int]]:
    combined: list[dict[str, Any]] = []
    rows_read: dict[Path, int] = {}
    seen: set[tuple[str, str, str | None]] = set()

    for path in inputs:
        rows = load_jsonl(path)
        rows_read[path] = len(rows)
        for row in rows:
            key = dedupe_key(row)
            if key in seen:
                continue
            seen.add(key)
            combined.append(row)

    return combined, rows_read


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, nargs="+", required=True, help="Input JSONL files to concatenate.")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "eval/results/non_llm_eval.jsonl")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    try:
        rows, rows_read = combine(args.input)
    except (FileNotFoundError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1) from None

    modules = sorted({str(row.get("module")) for row in rows})

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as output:
        for row in rows:
            output.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    print("Input files:")
    for path in args.input:
        print(f"  {path}")
    print("Rows read:")
    for path, count in rows_read.items():
        print(f"  {path}: {count}")
    print(f"Rows written: {len(rows)}")
    print("Modules included: " + (", ".join(modules) if modules else "none"))


if __name__ == "__main__":
    main()
