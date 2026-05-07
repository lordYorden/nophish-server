from __future__ import annotations

import argparse
import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
PROCESSED_DIR = ROOT / "data" / "processed"
RAW_DIR = ROOT / "data" / "raw" / "urlscan_israel"
USER_AGENT = "NoPhish Israel citizen phishing research/0.1"


@dataclass(frozen=True)
class Target:
    name: str
    category: str
    terms: tuple[str, ...]
    official_domains: tuple[str, ...]
    base_weight: int


TARGETS = (
    Target(
        "Israel Post delivery",
        "delivery",
        (
            "israelpost",
            "israel-post",
            "israelpost-co-il",
            "israel-post-co",
            "postil",
            "postil-co-il",
            "doarisrael",
            "doar-israel",
            "post-israel",
            "israelpost-delivery",
        ),
        ("israelpost.co.il", "postil.co.il"),
        95,
    ),
    Target(
        "National Insurance",
        "benefits",
        (
            "bituachleumi",
            "bituach-leumi",
            "bituah-leumi",
            "btl-gov",
            "btl-gov-il",
            "btlgov",
            "btl-israel",
            "btl-co-il",
        ),
        ("btl.gov.il",),
        100,
    ),
    Target(
        "Israeli government services",
        "government",
        ("govil", "gov-il", "israelgov", "taxes-gov-il", "misim-gov-il", "tax-gov-il", "govil-online"),
        ("gov.il", "my.gov.il", "taxes.gov.il"),
        90,
    ),
    Target(
        "Bank Leumi",
        "banking",
        ("bankleumi", "bank-leumi", "leumi-bank", "leumi-co-il", "leumiil", "leumi-online"),
        ("bankleumi.co.il", "leumi.co.il"),
        92,
    ),
    Target(
        "Bank Hapoalim",
        "banking",
        ("hapoalim", "bankhapoalim", "bankhapoalim-co-il", "hapoalim-co-il", "poalim-co-il"),
        ("bankhapoalim.co.il", "poalim.co.il"),
        92,
    ),
    Target(
        "Mizrahi Tefahot",
        "banking",
        ("mizrahi-tefahot", "mizrahi-tefahot-co-il", "mizrahi-bank", "tefahot-bank"),
        ("mizrahi-tefahot.co.il",),
        90,
    ),
    Target(
        "Discount Bank",
        "banking",
        ("discountbank", "discount-bank", "discountbank-co-il", "bankdiscount", "mercantile-bank"),
        ("discountbank.co.il", "mercantile.co.il"),
        90,
    ),
    Target("Bank Yahav", "banking", ("bank-yahav", "bankyahav", "yahav-co-il"), ("bank-yahav.co.il",), 84),
    Target("Bank Massad", "banking", ("bankmassad", "massad-bank", "massad-co-il"), ("bankmassad.co.il",), 78),
    Target("Bank Otsar Hahayal", "banking", ("otsar-hahayal", "bankotsar", "otsar-co-il"), ("bankotsar.co.il",), 76),
    Target("Isracard", "credit_card", ("isracard", "isracard-co-il", "isracard-pay"), ("isracard.co.il",), 88),
    Target("CAL credit card", "credit_card", ("cal-online", "cal-online-co-il", "calcard", "visa-cal"), ("cal-online.co.il",), 86),
    Target("MAX credit card", "credit_card", ("maxcard", "max-card", "max-pay", "max-co-il"), ("max.co.il",), 84),
    Target("American Express Israel", "credit_card", ("americanexpress-israel", "amex-israel"), ("americanexpress.co.il",), 78),
    Target("Clalit health services", "health", ("clalit", "clalit-health", "clalit-co-il", "clalit-online"), ("clalit.co.il",), 82),
    Target("Maccabi health services", "health", ("maccabi-health", "maccabi4u", "maccabi4u-co-il", "maccabi-online"), ("maccabi4u.co.il",), 82),
    Target("Meuhedet health services", "health", ("meuhedet", "meuhedet-co-il", "meuhedet-online"), ("meuhedet.co.il",), 80),
    Target("Leumit health services", "health", ("leumit-health", "leumit-co-il", "leumit-online"), ("leumit.co.il",), 78),
    Target("Bezeq", "telecom", ("bezeq", "bezeq-co-il", "bezeqint"), ("bezeq.co.il", "bezeqint.net"), 76),
    Target("Cellcom", "telecom", ("cellcom", "cellcom-co-il"), ("cellcom.co.il",), 74),
    Target("Partner", "telecom", ("partner-il", "partner-co-il", "partnercoil"), ("partner.co.il",), 72),
    Target("Pelephone", "telecom", ("pelephone", "pelephone-co-il"), ("pelephone.co.il",), 72),
    Target("HOT", "telecom", ("hotnet-il", "hot-co-il", "hotmobile-il"), ("hot.net.il", "hotmobile.co.il"), 70),
    Target("Israel Electric Corporation", "utility", ("iec-il", "iec-co-il", "israelelectric", "electric-israel"), ("iec.co.il",), 80),
    Target("Water bills", "utility", ("water-bill", "mei-avivim", "hagihon", "miftah-hazahav"), ("mei-avivim.co.il", "hagihon.co.il"), 72),
    Target("Highway 6 toll", "toll", ("kvish6", "kvis6", "kvish-6", "derech-eretz"), ("kvish6.co.il", "derech-eretz.co.il"), 78),
    Target("Rav Kav transit card", "transport", ("ravkav", "rav-kav", "ravkavonline"), ("ravkavonline.co.il",), 74),
    Target("Israel Railways", "transport", ("rail-israel", "israelrail", "rail-co-il"), ("rail.co.il",), 70),
    Target("Arnona municipal payment", "municipal_payment", ("arnona", "citypay", "citypay-co-il", "municipal-payment"), ("citypay.co.il",), 74),
    Target("Municipal tickets and payments", "municipal_payment", ("metropark", "parking-ticket-il", "city-ticket"), ("metropark.co.il",), 70),
    Target("Bit payment app", "payment_app", ("bit-pay", "bitpay-il", "bit-app-il"), ("bitpay.co.il",), 70),
    Target("PayBox payment app", "payment_app", ("paybox", "paybox-il", "payboxapp"), ("payboxapp.co.il",), 68),
)

PHISHING_ACTION_TOKENS = {
    "account",
    "auth",
    "billing",
    "card",
    "confirm",
    "delivery",
    "fee",
    "login",
    "otp",
    "package",
    "pay",
    "payment",
    "refund",
    "secure",
    "signin",
    "sms",
    "update",
    "verify",
}

BENIGN_REFERENCE_TOKENS = {
    "article",
    "blog",
    "magazine",
    "news",
    "press",
    "research",
    "security",
}

RISKY_TLDS = {
    "app",
    "buzz",
    "cfd",
    "click",
    "cyou",
    "icu",
    "lat",
    "live",
    "lol",
    "me",
    "monster",
    "online",
    "pages.dev",
    "site",
    "sbs",
    "shop",
    "store",
    "top",
    "vip",
    "win",
    "xyz",
}


def now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def is_subdomain_or_same(host: str, domain: str) -> bool:
    host = host.lower().strip(".")
    domain = domain.lower().strip(".")
    return host == domain or host.endswith("." + domain)


def is_official(host: str, target: Target) -> bool:
    return any(is_subdomain_or_same(host, official) for official in target.official_domains)


def url_text(url: str) -> str:
    parsed = urlparse(url)
    return " ".join([parsed.netloc, parsed.path, parsed.query]).lower()


def tokens_for(url: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", url_text(url)) if token}


def matched_targets(url: str) -> list[tuple[Target, list[str]]]:
    text = url_text(url).replace("_", "-")
    matches = []
    host = (urlparse(url).hostname or "").lower()
    for target in TARGETS:
        terms = [term for term in target.terms if term in text]
        if terms and not is_official(host, target):
            matches.append((target, terms))
    return matches


def source_weight(source: str) -> int:
    if source in {"openphish", "phishstats", "phishtank"}:
        return 35
    if source == "urlscan_public_search":
        return 25
    if source == "urlhaus_recent":
        return 8
    return 0


def tld_score(host: str) -> int:
    labels = host.split(".")
    if len(labels) >= 2 and ".".join(labels[-2:]) in RISKY_TLDS:
        return 8
    if labels and labels[-1] in RISKY_TLDS:
        return 6
    return 0


def score_url(url: str, source: str, metadata: dict[str, Any], target: Target, matched_terms: list[str]) -> tuple[int, list[str]]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    tokens = tokens_for(url)
    score = target.base_weight + source_weight(source)
    reasons = [f"target:{target.name}", f"category:{target.category}", f"source:{source}"]

    if any(term in host for term in matched_terms):
        score += 20
        reasons.append("target-term-in-host")
    else:
        score += 8
        reasons.append("target-term-in-url")

    action_hits = sorted(tokens & PHISHING_ACTION_TOKENS)
    if action_hits:
        score += min(24, 4 * len(action_hits))
        reasons.append("phishing-actions:" + ",".join(action_hits[:5]))

    if parsed.query:
        score += 5
        reasons.append("query-params")

    risky_tld_points = tld_score(host)
    if risky_tld_points:
        score += risky_tld_points
        reasons.append("risky-or-common-abuse-tld")

    if re.search(r"\d", host):
        score += 4
        reasons.append("host-contains-digits")

    if metadata.get("urlscan_overall_malicious") is True:
        score += 20
        reasons.append("urlscan-malicious-verdict")

    tags = {str(tag).lower() for tag in metadata.get("urlscan_tags") or []}
    if "phishing" in tags:
        score += 16
        reasons.append("urlscan-phishing-tag")

    if source == "urlhaus_recent":
        score -= 18
        reasons.append("urlhaus-not-phishing-only")

    return score, reasons


def is_impersonation_candidate(url: str, metadata: dict[str, Any], matched_terms: list[str]) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    tokens = tokens_for(url)
    tags = {str(tag).lower() for tag in metadata.get("urlscan_tags") or []}
    has_threat_signal = metadata.get("urlscan_overall_malicious") is True or bool(tags & {"phishing", "possiblethreat"})
    has_action_signal = bool(tokens & PHISHING_ACTION_TOKENS)
    has_risky_host_signal = bool(tld_score(host))

    if tokens & BENIGN_REFERENCE_TOKENS and not has_threat_signal and not has_action_signal and not has_risky_host_signal:
        return False
    if any(term in host for term in matched_terms):
        return True
    if has_threat_signal:
        return True
    if has_risky_host_signal and has_action_signal:
        return True
    return False


def fetch_urlscan(term: str, size: int, timeout: int) -> dict[str, Any]:
    query = urlencode({"q": f'task.url:"{term}"', "size": str(size)})
    url = f"https://urlscan.io/api/v1/search/?{query}"
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def load_existing(path: Path) -> list[dict[str, Any]]:
    records = []
    if not path.exists():
        return records
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            item = json.loads(line)
            if item.get("indicator_type") != "url":
                continue
            records.append(
                {
                    "url": item["indicator"],
                    "source": item.get("source", ""),
                    "first_seen": item.get("metadata", {}).get("date") or item.get("metadata", {}).get("dateadded") or "",
                    "metadata": {"original_label": item.get("label", "")},
                }
            )
    return records


def records_from_urlscan_payload(data: dict[str, Any], fallback_term: str = "") -> list[dict[str, Any]]:
    records = []
    for result in data.get("results") or []:
        task = result.get("task") or {}
        page = result.get("page") or {}
        verdict = ((result.get("verdicts") or {}).get("overall") or {})
        url = task.get("url") or page.get("url") or ""
        if not url:
            continue
        records.append(
            {
                "url": url,
                "source": "urlscan_public_search",
                "first_seen": task.get("time") or "",
                "metadata": {
                    "urlscan_term": fallback_term,
                    "urlscan_domain": task.get("domain") or page.get("domain"),
                    "urlscan_apex_domain": task.get("apexDomain") or page.get("apexDomain"),
                    "urlscan_result": result.get("result"),
                    "urlscan_screenshot": result.get("screenshot"),
                    "urlscan_tags": task.get("tags") or [],
                    "urlscan_overall_malicious": verdict.get("malicious"),
                    "urlscan_score": verdict.get("score"),
                },
            }
        )
    return records


def load_urlscan_cache() -> list[dict[str, Any]]:
    records = []
    if not RAW_DIR.exists():
        return records
    for path in RAW_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        fallback_term = path.stem.split("_", 1)[-1]
        records.extend(records_from_urlscan_payload(data, fallback_term=fallback_term))
    return records


def cached_terms() -> set[str]:
    if not RAW_DIR.exists():
        return set()
    terms = set()
    for path in RAW_DIR.glob("*.json"):
        terms.add(path.stem.split("_", 1)[-1])
    return terms


def collect_urlscan(size: int, timeout: int, pause: float, skip_cached_terms: bool) -> list[dict[str, Any]]:
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    collected = []
    seen_terms = set()
    already_cached = cached_terms() if skip_cached_terms else set()
    for target in TARGETS:
        for term in target.terms:
            if term in seen_terms or term in already_cached:
                continue
            seen_terms.add(term)
            try:
                data = fetch_urlscan(term, size=size, timeout=timeout)
            except HTTPError as exc:
                print(f"urlscan skipped {term}: HTTP {exc.code}")
                time.sleep(max(pause, 3))
                continue
            except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
                print(f"urlscan skipped {term}: {exc}")
                time.sleep(pause)
                continue

            raw_path = RAW_DIR / f"{now_stamp()}_{term}.json"
            raw_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            collected.extend(records_from_urlscan_payload(data, fallback_term=term))
            time.sleep(pause)
    return collected


def rank(records: list[dict[str, Any]], max_per_domain: int) -> list[dict[str, Any]]:
    candidates = []
    for record in records:
        url = record["url"]
        parsed = urlparse(url)
        domain = (parsed.hostname or "").lower()
        if not domain:
            continue
        matches = matched_targets(url)
        for target, terms in matches:
            if not is_impersonation_candidate(url, record.get("metadata") or {}, terms):
                continue
            score, reasons = score_url(url, record["source"], record.get("metadata") or {}, target, terms)
            candidates.append(
                {
                    "url": url,
                    "source": record["source"],
                    "domain": domain,
                    "matched_target": target.name,
                    "category": target.category,
                    "matched_terms": terms,
                    "citizen_relevance_score": score,
                    "relevance_reasons": reasons,
                    "first_seen": record.get("first_seen", ""),
                    "metadata": record.get("metadata") or {},
                }
            )

    best_by_url: dict[str, dict[str, Any]] = {}
    for item in candidates:
        existing = best_by_url.get(item["url"])
        if not existing or item["citizen_relevance_score"] > existing["citizen_relevance_score"]:
            best_by_url[item["url"]] = item

    ranked = sorted(
        best_by_url.values(),
        key=lambda row: (-row["citizen_relevance_score"], row["category"], row["domain"], row["url"]),
    )

    selected = []
    per_domain: defaultdict[str, int] = defaultdict(int)
    for row in ranked:
        if per_domain[row["domain"]] >= max_per_domain:
            continue
        per_domain[row["domain"]] += 1
        row["domain_rank"] = per_domain[row["domain"]]
        row["global_rank"] = len(selected) + 1
        selected.append(row)
    return selected


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build Israel citizen/elderly-focused phishing URL candidates.")
    parser.add_argument("--urlscan-size", type=int, default=40)
    parser.add_argument("--pause", type=float, default=1.5)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--max-per-domain", type=int, default=5)
    parser.add_argument("--skip-urlscan", action="store_true", help="Do not make network requests; use cached URLScan raw files if present.")
    parser.add_argument("--ignore-urlscan-cache", action="store_true", help="Ignore cached URLScan raw files.")
    parser.add_argument("--refetch-cached-terms", action="store_true", help="Query URLScan even when a raw result for the term is already cached.")
    args = parser.parse_args()

    existing = load_existing(PROCESSED_DIR / "phishing_indicators.jsonl")
    cached_urlscan = [] if args.ignore_urlscan_cache else load_urlscan_cache()
    fresh_urlscan = (
        []
        if args.skip_urlscan
        else collect_urlscan(
            args.urlscan_size,
            args.timeout,
            args.pause,
            skip_cached_terms=not args.refetch_cached_terms,
        )
    )
    urlscan_by_url = {record["url"]: record for record in cached_urlscan + fresh_urlscan}
    urlscan = list(urlscan_by_url.values())
    selected = rank(existing + urlscan, max_per_domain=args.max_per_domain)

    rich_output = PROCESSED_DIR / "israel_elderly_relevant_urls.jsonl"
    slim_output = PROCESSED_DIR / "israel_elderly_urls_sources.jsonl"
    write_jsonl(rich_output, selected)
    write_jsonl(slim_output, [{"url": row["url"], "source": row["source"]} for row in selected])

    max_seen = 0
    domain_counts = Counter(row["domain"] for row in selected)
    if domain_counts:
        max_seen = max(domain_counts.values())
    summary = {
        "input_existing_urls": len(existing),
        "input_urlscan_urls": len(urlscan),
        "selected_urls": len(selected),
        "unique_domains": len(domain_counts),
        "max_per_domain_requested": args.max_per_domain,
        "max_per_domain_observed": max_seen,
        "categories": Counter(row["category"] for row in selected).most_common(),
        "targets": Counter(row["matched_target"] for row in selected).most_common(),
        "sources": Counter(row["source"] for row in selected).most_common(),
        "rich_output": str(rich_output),
        "slim_output": str(slim_output),
    }
    (PROCESSED_DIR / "israel_elderly_relevant_urls.summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
