#!/usr/bin/env python3
"""Build eval cases whose phishing URLs are similar variants, not exact seed URLs."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from url_fuzzing import fuzz_url

REPO_ROOT = Path(__file__).resolve().parents[1]


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
            for url_index, url in enumerate(case["urls"]):
                fuzzed = fuzz_url(str(url), start_index + line_number + url_index)
                fuzzed_urls.append(fuzzed or url)

            original_urls = case["urls"]
            case = dict(case)
            case["id"] = f"{case['id']}_fuzzy"
            case["body"] = replace_urls(case["body"], original_urls, fuzzed_urls)
            case["urls"] = fuzzed_urls
            case["source"] = f"{case.get('source', 'unknown')}:fuzzy_eval"
            case["tags"] = sorted(set(case.get("tags", [])) | {"fuzzy", "non_exact"})
            case["notes"] = (
                f"Fuzzy non-exact variant generated from {case.get('id', '')}; "
                f"original_urls={original_urls}"
            )
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
