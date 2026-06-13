#!/usr/bin/env python3
"""Seed malicious URL embeddings into the local database."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import httpx
from dotenv import load_dotenv
from sqlalchemy import func
from sqlmodel import Session, select

from app.database import get_engine
from app.detectors.url_scanner import canonicalize_url_for_lookup
from app.detectors.url_scanner.heuristics import is_shortener
from app.scheme.malicious_url import MaliciousUrl
from llm.openr import get_url_embedding

try:
    from eval.url_fuzzing import fuzz_urls
except ModuleNotFoundError:
    from url_fuzzing import fuzz_urls

DEFAULT_ENV_FILES = (
    REPO_ROOT / ".env",
    REPO_ROOT / "llm/.env",
)
DEFAULT_SOURCES = (
    REPO_ROOT / "eval/detection_cases.jsonl",
    REPO_ROOT / "phising-fetcher/data/processed/israel_elderly_urls_sources.jsonl",
    REPO_ROOT / "phising-fetcher/data/processed/quality_ranked_urls_sources.jsonl",
)


def load_env_files() -> None:
    for path in DEFAULT_ENV_FILES:
        if path.exists():
            load_dotenv(path, override=False)


def iter_urls_from_jsonl(path: Path, include_all_eval_labels: bool) -> Iterable[str]:
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON") from exc

            if "urls" in row:
                if not include_all_eval_labels and row.get("label") != "phishing":
                    continue
                for url in row.get("urls") or []:
                    yield str(url)
            elif "url" in row:
                yield str(row["url"])


def hostname(raw_url: str) -> str | None:
    split = urlsplit(raw_url.strip())
    if not split.hostname:
        return None
    return split.hostname.lower().rstrip(".")


def append_candidate(
    candidates: list[str],
    candidate: str,
    *,
    fuzz_variants: int,
    fuzz_start_index: int,
) -> None:
    candidates.append(candidate)
    if fuzz_variants:
        variants = fuzz_urls(candidate, fuzz_variants, start_index=fuzz_start_index)
        if variants:
            print(
                f"Generated same-origin variants: source={candidate} count={len(variants)}"
            )
        candidates.extend(variants)


def expand_shortlink(
    raw_url: str,
    *,
    timeout_seconds: float,
    max_redirects: int,
) -> str | None:
    try:
        with httpx.Client(
            follow_redirects=True,
            max_redirects=max_redirects,
            timeout=timeout_seconds,
        ) as client:
            response = client.get(raw_url)
            return str(response.url)
    except Exception as exc:
        print(f"Shortlink expansion failed: {raw_url} reason={type(exc).__name__}")
        return None


def candidate_urls_for_source(
    raw_url: str,
    *,
    fuzz_variants: int,
    fuzz_start_index: int,
    expand_shortlinks: bool,
    shortlink_timeout_seconds: float,
    shortlink_max_redirects: int,
    shortlink_seed_raw: bool,
) -> list[str]:
    candidates: list[str] = []
    host = hostname(raw_url)
    if host and is_shortener(host):
        print(f"Shortlink detected: {raw_url}")
        if shortlink_seed_raw:
            candidates.append(raw_url)

        if not expand_shortlinks:
            print(f"Skipping variants for shortlink host: {host}")
            return candidates

        final_url = expand_shortlink(
            raw_url,
            timeout_seconds=shortlink_timeout_seconds,
            max_redirects=shortlink_max_redirects,
        )
        if not final_url or final_url.strip() == raw_url.strip():
            print(f"Skipping variants for shortlink host: {host}")
            return candidates

        print(f"Shortlink expanded: {raw_url} -> {final_url}")
        final_host = hostname(final_url)
        if final_host and is_shortener(final_host):
            candidates.append(final_url)
            print(f"Skipping variants for shortlink host: {final_host}")
            return candidates

        append_candidate(
            candidates,
            final_url,
            fuzz_variants=fuzz_variants,
            fuzz_start_index=fuzz_start_index,
        )
        return candidates

    append_candidate(
        candidates,
        raw_url,
        fuzz_variants=fuzz_variants,
        fuzz_start_index=fuzz_start_index,
    )
    return candidates


def collect_urls(
    paths: list[Path],
    include_all_eval_labels: bool,
    limit: int | None,
    fuzz_variants: int,
    fuzz_start_index: int,
    excluded_urls: set[str],
    expand_shortlinks: bool,
    shortlink_timeout_seconds: float,
    shortlink_max_redirects: int,
    shortlink_seed_raw: bool,
) -> list[str]:
    seen: set[str] = set()
    urls: list[str] = []
    for path in paths:
        if not path.exists():
            print(f"Skipping missing source: {path}")
            continue
        for raw_url in iter_urls_from_jsonl(path, include_all_eval_labels):
            candidates = candidate_urls_for_source(
                raw_url,
                fuzz_variants=fuzz_variants,
                fuzz_start_index=fuzz_start_index,
                expand_shortlinks=expand_shortlinks,
                shortlink_timeout_seconds=shortlink_timeout_seconds,
                shortlink_max_redirects=shortlink_max_redirects,
                shortlink_seed_raw=shortlink_seed_raw,
            )
            for candidate in candidates:
                canonical = canonicalize_url_for_lookup(candidate)
                url = canonical or candidate.strip()
                if not url or url in seen or url in excluded_urls:
                    continue
                seen.add(url)
                urls.append(url)
                if limit is not None and len(urls) >= limit:
                    return urls
    return urls


def collect_excluded_urls(paths: list[Path]) -> set[str]:
    excluded: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        for raw_url in iter_urls_from_jsonl(path, include_all_eval_labels=True):
            canonical = canonicalize_url_for_lookup(raw_url)
            excluded.add(canonical or raw_url.strip())
    excluded.discard("")
    return excluded


def existing_urls(session: Session) -> set[str]:
    return set(session.exec(select(MaliciousUrl.url)).all())


def seed_urls(urls: list[str], batch_size: int, dry_run: bool) -> None:
    engine = get_engine()
    with Session(engine) as session:
        before = session.exec(select(func.count(MaliciousUrl.id))).one()
        existing = existing_urls(session)
        pending = [url for url in urls if url not in existing]

        print(f"Database rows before: {before}")
        print(f"Candidate URLs: {len(urls)}")
        print(f"Already present: {len(urls) - len(pending)}")
        print(f"To insert: {len(pending)}")

        if dry_run or not pending:
            print("Dry run complete." if dry_run else "Nothing to insert.")
            return

        inserted = 0
        for index, url in enumerate(pending, start=1):
            embedding = get_url_embedding(url)
            session.add(MaliciousUrl(url=url, embedding=embedding))
            inserted += 1
            if inserted % batch_size == 0:
                session.commit()
                print(f"Inserted {inserted}/{len(pending)}")

        session.commit()
        after = session.exec(select(func.count(MaliciousUrl.id))).one()
        print(f"Inserted total: {inserted}")
        print(f"Database rows after: {after}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source",
        type=Path,
        nargs="*",
        default=list(DEFAULT_SOURCES),
        help="JSONL source files with either `url` or eval-style `urls` fields.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Maximum unique canonical URLs to seed. Use 0 for no limit.",
    )
    parser.add_argument("--batch-size", type=int, default=50)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--fuzz-variants",
        type=int,
        default=0,
        help="Seed this many deterministic same-origin variants per non-shortener source URL in addition to the exact URL.",
    )
    parser.add_argument(
        "--fuzz-start-index",
        type=int,
        default=0,
        help="Starting variant index for deterministic same-origin variant generation.",
    )
    parser.add_argument(
        "--expand-shortlinks",
        action="store_true",
        help="Resolve known shortener URLs and seed the final destination. Network access is required.",
    )
    parser.add_argument(
        "--shortlink-timeout-seconds",
        type=float,
        default=5.0,
        help="Timeout for shortlink expansion requests.",
    )
    parser.add_argument(
        "--shortlink-max-redirects",
        type=int,
        default=5,
        help="Maximum redirects to follow during shortlink expansion.",
    )
    parser.add_argument(
        "--shortlink-seed-raw",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Seed the observed shortlink exactly. Enabled by default.",
    )
    parser.add_argument(
        "--exclude-urls-from",
        type=Path,
        nargs="*",
        default=[],
        help="JSONL files whose URLs must not be inserted exactly.",
    )
    parser.add_argument(
        "--include-all-eval-labels",
        action="store_true",
        help="For eval/detection_cases.jsonl, include benign URLs too. Default only includes phishing cases.",
    )
    return parser


def main() -> None:
    load_env_files()
    parser = build_parser()
    args = parser.parse_args()
    limit = None if args.limit == 0 else args.limit
    excluded_urls = collect_excluded_urls(args.exclude_urls_from)
    if excluded_urls:
        print(f"Excluded exact URLs: {len(excluded_urls)}")
    urls = collect_urls(
        args.source,
        args.include_all_eval_labels,
        limit,
        args.fuzz_variants,
        args.fuzz_start_index,
        excluded_urls,
        args.expand_shortlinks,
        args.shortlink_timeout_seconds,
        args.shortlink_max_redirects,
        args.shortlink_seed_raw,
    )
    seed_urls(urls, batch_size=args.batch_size, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
