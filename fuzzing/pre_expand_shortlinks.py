#!/usr/bin/env python3
"""One-off browser-based shortlink expansion for fuzzing seed data."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.detectors.url_scanner.browser import expand_with_browser
from app.detectors.url_scanner.heuristics import is_shortener
from app.detectors.url_scanner.normalization import canonicalize_url_for_lookup
from fuzzing.seed_malicious_urls import (
    DATA_DIR,
    DEFAULT_SOURCES,
    hostname,
    iter_urls_from_jsonl,
)

DEFAULT_OUTPUT = DATA_DIR / "expanded_shortlinks.jsonl"


def shortlinks_from_sources(paths: list[Path]) -> list[tuple[Path, str]]:
    seen: set[str] = set()
    shortlinks: list[tuple[Path, str]] = []
    for path in paths:
        for raw_url in iter_urls_from_jsonl(path, include_all_eval_labels=False):
            host = hostname(raw_url)
            if not host or not is_shortener(host) or raw_url in seen:
                continue
            seen.add(raw_url)
            shortlinks.append((path, raw_url))
    return shortlinks


async def expand_shortlinks(paths: list[Path]) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for path, raw_url in shortlinks_from_sources(paths):
        result = await expand_with_browser(raw_url)
        final_url = canonicalize_url_for_lookup(result.final_url or "") or result.final_url
        if not final_url or final_url.strip() == raw_url.strip():
            print(f"Skipped unchanged shortlink: {raw_url}")
            continue
        final_host = hostname(final_url)
        if final_host and is_shortener(final_host):
            print(f"Skipped nested shortlink: {raw_url} -> {final_url}")
            continue
        if result.error:
            print(f"Skipped failed shortlink: {raw_url} reason={result.error}")
            continue

        rows.append(
            {
                "url": final_url,
                "source": f"{path.name}:browser_expanded_shortlink",
                "raw_url": raw_url,
                "redirect_chain": result.redirect_chain,
            }
        )
        print(f"Expanded shortlink: {raw_url} -> {final_url}")
    return rows


def write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        nargs="*",
        default=[source for source in DEFAULT_SOURCES if source != DEFAULT_OUTPUT],
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUTPUT)
    return parser


async def async_main() -> None:
    os.environ.setdefault("DYNAMIC_URL_SCANNER_ENABLE_BROWSER", "true")
    args = build_parser().parse_args()
    rows = await expand_shortlinks(args.source)
    write_jsonl(args.out, rows)
    print(f"Wrote {len(rows)} expanded shortlinks to {args.out}")


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
