#!/usr/bin/env python3
"""Build same-origin non-exact diagnostic cases for embedding distance checks."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.detectors.url_scanner.heuristics import is_shortener
from url_fuzzing import fuzz_url


def is_shortlink(raw_url: str) -> bool:
    split = urlsplit(raw_url.strip())
    return bool(split.hostname and is_shortener(split.hostname.lower().rstrip(".")))


def build_cases(input_path: Path, output_path: Path, start_index: int) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with input_path.open(encoding="utf-8") as source, output_path.open("w", encoding="utf-8") as output:
        for line_number, line in enumerate(source, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            case = json.loads(stripped)
            if case.get("label") != "phishing" or not case.get("urls"):
                output.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")
                continue

            fuzzed_urls = []
            skipped_shortlinks = []
            for url_index, url in enumerate(case["urls"]):
                raw_url = str(url)
                if is_shortlink(raw_url):
                    skipped_shortlinks.append(raw_url)
                    fuzzed_urls.append(raw_url)
                    continue
                fuzzed = fuzz_url(raw_url, start_index + line_number + url_index)
                fuzzed_urls.append(fuzzed or raw_url)

            original_urls = case["urls"]
            case = dict(case)
            case["id"] = f"{case['id']}_fuzzy"
            case["body"] = replace_urls(case["body"], original_urls, fuzzed_urls)
            case["urls"] = fuzzed_urls
            case["source"] = f"{case.get('source', 'unknown')}:same_origin_diagnostic"
            case["tags"] = sorted(
                set(case.get("tags", [])) | {"same_origin", "non_exact", "diagnostic"}
            )
            case["notes"] = (
                "Same-origin non-exact diagnostic variant; not primary accuracy truth; "
                f"original_urls={original_urls}"
            )
            if skipped_shortlinks:
                case["notes"] += f"; shortlink_fuzzing_skipped={skipped_shortlinks}"
            output.write(json.dumps(case, ensure_ascii=False, sort_keys=True) + "\n")


def replace_urls(body: str, original_urls: list[str], fuzzed_urls: list[str]) -> str:
    result = body
    for original, fuzzed in zip(original_urls, fuzzed_urls, strict=False):
        result = result.replace(original, fuzzed)
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=REPO_ROOT / "eval/detection_cases.jsonl")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "eval/detection_cases_fuzzy.jsonl")
    parser.add_argument(
        "--start-index",
        type=int,
        default=100,
        help="Use a high range so eval variants do not match seed variants.",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    build_cases(args.input, args.out, args.start_index)


if __name__ == "__main__":
    main()
