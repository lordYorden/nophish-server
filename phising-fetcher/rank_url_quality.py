from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from urllib.parse import parse_qsl, urlparse


ROOT = Path(__file__).resolve().parent
PROCESSED_DIR = ROOT / "data" / "processed"


SOURCE_WEIGHT = {
    "openphish": 100,
    "phishstats": 90,
    "phishtank": 95,
    "urlhaus_recent": 35,
}

PHISHING_HINTS = {
    "account",
    "auth",
    "bank",
    "billing",
    "confirm",
    "login",
    "password",
    "recover",
    "secure",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
}

BRAND_HINTS = {
    "adobe",
    "amazon",
    "apple",
    "binance",
    "coinbase",
    "dhl",
    "dropbox",
    "facebook",
    "google",
    "instagram",
    "ledger",
    "metamask",
    "microsoft",
    "netflix",
    "office",
    "onedrive",
    "outlook",
    "paypal",
    "telegram",
    "whatsapp",
}


def load_records(path: Path) -> list[dict]:
    records = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            record = json.loads(line)
            if record.get("indicator_type") == "url":
                records.append(record)
    return records


def source_score(source: str) -> int:
    parts = source.split("|")
    score = max(SOURCE_WEIGHT.get(part, 0) for part in parts)
    if len(parts) > 1:
        score += 10
    return score


def url_tokens(url: str) -> set[str]:
    parsed = urlparse(url)
    text = " ".join([parsed.netloc, parsed.path, parsed.query]).lower()
    return {token for token in re.split(r"[^a-z0-9]+", text) if token}


def quality_score(record: dict, domain_frequency: Counter[str]) -> tuple[int, dict]:
    url = record["indicator"]
    source = record["source"]
    domain = record.get("domain") or (urlparse(url).hostname or "")
    metadata = record.get("metadata") or {}
    parsed = urlparse(url)
    tokens = url_tokens(url)

    score = source_score(source)
    reasons = [f"source:{source}"]

    if record.get("label") == "phishing_url":
        score += 25
        reasons.append("phishing-specific-label")
    elif record.get("label") == "malicious_url":
        score -= 5
        reasons.append("malicious-not-phishing-only")

    hint_hits = sorted(tokens & PHISHING_HINTS)
    if hint_hits:
        score += min(20, len(hint_hits) * 5)
        reasons.append("phishing-keywords:" + ",".join(hint_hits[:4]))

    brand_hits = sorted(tokens & BRAND_HINTS)
    if brand_hits:
        score += min(15, len(brand_hits) * 5)
        reasons.append("brand-keywords:" + ",".join(brand_hits[:3]))

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    if query_pairs:
        score += min(8, len(query_pairs) * 2)
        reasons.append("has-query-params")

    if len(parsed.path.strip("/").split("/")) >= 2:
        score += 4
        reasons.append("multi-segment-path")

    if metadata.get("url_status") == "online":
        score += 5
        reasons.append("urlhaus-online")

    tags = str(metadata.get("tags") or "").lower()
    if "clearfake" in tags:
        score += 8
        reasons.append("clearfake-campaign")

    # Very common domains are still useful, but the cap will do most of the pruning.
    if domain_frequency[domain] > 25:
        score -= 8
        reasons.append("high-domain-repetition")

    if re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
        score -= 12
        reasons.append("ip-host-less-phishing-context")

    details = {
        "domain": domain,
        "quality_score": score,
        "quality_reasons": reasons,
        "original_label": record.get("label", ""),
    }
    return score, details


def main() -> int:
    parser = argparse.ArgumentParser(description="Rank URL indicators for phishing vector-search coverage.")
    parser.add_argument("--input", type=Path, default=PROCESSED_DIR / "phishing_indicators.jsonl")
    parser.add_argument("--max-per-domain", type=int, default=5)
    parser.add_argument("--output", type=Path, default=PROCESSED_DIR / "quality_ranked_urls.jsonl")
    parser.add_argument("--slim-output", type=Path, default=PROCESSED_DIR / "quality_ranked_urls_sources.jsonl")
    args = parser.parse_args()

    records = load_records(args.input)
    domain_frequency = Counter(record.get("domain") or (urlparse(record["indicator"]).hostname or "") for record in records)

    ranked = []
    for record in records:
        score, details = quality_score(record, domain_frequency)
        ranked.append(
            {
                "url": record["indicator"],
                "source": record["source"],
                "domain": details["domain"],
                "quality_score": score,
                "quality_reasons": details["quality_reasons"],
                "original_label": details["original_label"],
            }
        )

    ranked.sort(key=lambda row: (-row["quality_score"], row["source"], row["domain"], row["url"]))

    selected = []
    per_domain: defaultdict[str, int] = defaultdict(int)
    for row in ranked:
        if per_domain[row["domain"]] >= args.max_per_domain:
            continue
        per_domain[row["domain"]] += 1
        row["domain_rank"] = per_domain[row["domain"]]
        row["global_rank"] = len(selected) + 1
        selected.append(row)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as f:
        for row in selected:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")

    with args.slim_output.open("w", encoding="utf-8", newline="\n") as f:
        for row in selected:
            f.write(json.dumps({"url": row["url"], "source": row["source"]}, ensure_ascii=False, sort_keys=True) + "\n")

    summary = {
        "input_url_records": len(records),
        "selected_url_records": len(selected),
        "max_per_domain": args.max_per_domain,
        "unique_domains_selected": len(per_domain),
        "output": str(args.output),
        "slim_output": str(args.slim_output),
        "top_sources": Counter(row["source"] for row in selected).most_common(),
    }
    summary_path = args.output.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
