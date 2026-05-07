from __future__ import annotations

import argparse
import bz2
import csv
import hashlib
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parent
RAW_DIR = ROOT / "data" / "raw"
PROCESSED_DIR = ROOT / "data" / "processed"
USER_AGENT = "NoPhish research dataset fetcher/0.1 (+defensive phishing detection)"


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    parser: str
    label: str
    trusted_reason: str
    enabled: bool = True
    requires_key: bool = False


SOURCES: dict[str, Source] = {
    "openphish": Source(
        name="openphish",
        url="https://openphish.com/feed.txt",
        parser="line_urls",
        label="phishing_url",
        trusted_reason="OpenPhish community phishing URL feed.",
    ),
    "cert_pl": Source(
        name="cert_pl",
        url="https://hole.cert.pl/domains/v2/domains.txt",
        parser="line_domains",
        label="phishing_or_dangerous_domain",
        trusted_reason="CERT Polska national warning list for dangerous/phishing domains.",
    ),
    "phishstats": Source(
        name="phishstats",
        url="https://api.phishstats.info/api/phishing?_size=100&_p={page}",
        parser="phishstats_json_pages",
        label="phishing_url",
        trusted_reason="PhishStats public API for phishing intelligence.",
    ),
    "urlhaus_recent": Source(
        name="urlhaus_recent",
        url="https://urlhaus.abuse.ch/downloads/csv_recent/",
        parser="urlhaus_csv",
        label="malicious_url",
        trusted_reason="abuse.ch URLhaus recent malicious URL exchange. Not phishing-only.",
    ),
    "phishtank": Source(
        name="phishtank",
        url="http://data.phishtank.com/data/{app_key}/online-valid.json.bz2",
        parser="phishtank_json_bz2",
        label="phishing_url",
        trusted_reason="PhishTank verified online phishing feed. Requires PHISHTANK_APP_KEY.",
        enabled=False,
        requires_key=True,
    ),
}


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def safe_filename(name: str, suffix: str) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{name}.{suffix}"


def fetch_bytes(url: str, timeout: int) -> bytes:
    request = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path or "/"
    normalized = f"{scheme}://{netloc}{path}"
    if parsed.params:
        normalized += f";{parsed.params}"
    if parsed.query:
        normalized += f"?{parsed.query}"
    if parsed.fragment:
        normalized += f"#{parsed.fragment}"
    return normalized


def extract_domain(value: str) -> str:
    parsed = urlparse(normalize_url(value))
    return parsed.hostname or ""


def defang(value: str) -> str:
    return value.replace("http://", "hxxp://").replace("https://", "hxxps://").replace(".", "[.]")


def record_id(indicator: str, source: str) -> str:
    material = f"{source}\0{indicator}".encode("utf-8", errors="ignore")
    return hashlib.sha256(material).hexdigest()[:20]


def build_record(
    *,
    indicator: str,
    indicator_type: str,
    source: Source,
    fetched_at: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    normalized = normalize_url(indicator) if indicator_type == "url" else indicator.strip().lower()
    domain = extract_domain(normalized) if indicator_type == "url" else normalized
    metadata = metadata or {}
    return {
        "id": record_id(normalized, source.name),
        "indicator": normalized,
        "indicator_type": indicator_type,
        "domain": domain,
        "defanged_indicator": defang(normalized),
        "label": source.label,
        "source": source.name,
        "source_url": source.url,
        "trusted_reason": source.trusted_reason,
        "fetched_at": fetched_at,
        "metadata": metadata,
    }


def parse_line_urls(text: str, source: Source, fetched_at: str) -> list[dict[str, Any]]:
    records = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        records.append(build_record(indicator=line, indicator_type="url", source=source, fetched_at=fetched_at))
    return records


def parse_line_domains(text: str, source: Source, fetched_at: str) -> list[dict[str, Any]]:
    records = []
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        records.append(build_record(indicator=line, indicator_type="domain", source=source, fetched_at=fetched_at))
    return records


def parse_urlhaus_csv(text: str, source: Source, fetched_at: str) -> list[dict[str, Any]]:
    rows: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("# id,"):
            rows.append(line[2:].strip())
            continue
        if line.startswith("#"):
            continue
        rows.append(line)
    reader = csv.DictReader(rows)
    records = []
    for row in reader:
        url = (row.get("url") or "").strip()
        if not url:
            continue
        metadata = {
            "url_status": row.get("url_status"),
            "dateadded": row.get("dateadded"),
            "threat": row.get("threat"),
            "tags": row.get("tags"),
            "reporter": row.get("reporter"),
            "urlhaus_link": row.get("urlhaus_link"),
        }
        records.append(build_record(indicator=url, indicator_type="url", source=source, fetched_at=fetched_at, metadata=metadata))
    return records


def parse_phishstats_json(text: str, source: Source, fetched_at: str) -> list[dict[str, Any]]:
    records = []
    for item in json.loads(text):
        url = (item.get("url") or "").strip()
        if not url:
            continue
        metadata = {
            "phishstats_id": item.get("id"),
            "score": item.get("score"),
            "ip": item.get("ip"),
            "countrycode": item.get("countrycode"),
            "date": item.get("date"),
            "host": item.get("host"),
        }
        records.append(build_record(indicator=url, indicator_type="url", source=source, fetched_at=fetched_at, metadata=metadata))
    return records


def parse_phishtank_json_bz2(data: bytes, source: Source, fetched_at: str) -> list[dict[str, Any]]:
    text = bz2.decompress(data).decode("utf-8", errors="replace")
    records = []
    for item in json.loads(text):
        url = (item.get("url") or "").strip()
        if not url:
            continue
        metadata = {
            "phish_id": item.get("phish_id"),
            "submission_time": item.get("submission_time"),
            "verification_time": item.get("verification_time"),
            "target": item.get("target"),
            "phish_detail_url": item.get("phish_detail_url"),
        }
        records.append(build_record(indicator=url, indicator_type="url", source=source, fetched_at=fetched_at, metadata=metadata))
    return records


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")


def write_csv(path: Path, records: list[dict[str, Any]]) -> None:
    fieldnames = [
        "id",
        "indicator",
        "indicator_type",
        "domain",
        "defanged_indicator",
        "label",
        "source",
        "source_url",
        "fetched_at",
        "metadata",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for record in records:
            row = {key: record.get(key, "") for key in fieldnames}
            row["metadata"] = json.dumps(record.get("metadata") or {}, ensure_ascii=False, sort_keys=True)
            writer.writerow(row)


def fetch_source(source: Source, timeout: int, phishstats_pages: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    fetched_at = utc_now()
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    try:
        if source.parser == "phishstats_json_pages":
            all_records: list[dict[str, Any]] = []
            raw_pages: list[Any] = []
            page_errors: list[str] = []
            exhausted = False
            for page in range(1, phishstats_pages + 1):
                url = source.url.format(page=page)
                for attempt in range(1, 4):
                    try:
                        text = fetch_bytes(url, timeout).decode("utf-8", errors="replace")
                        raw_page = json.loads(text)
                        raw_pages.extend(raw_page)
                        page_records = parse_phishstats_json(text, source, fetched_at)
                        all_records.extend(page_records)
                        if len(raw_page) < 100:
                            exhausted = True
                        break
                    except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
                        if attempt == 3:
                            page_errors.append(f"page {page}: {exc}")
                        else:
                            time.sleep(attempt)
                if page_errors:
                    break
                if exhausted:
                    break
            raw_path = RAW_DIR / safe_filename(source.name, "json")
            raw_path.write_text(json.dumps(raw_pages, ensure_ascii=False, indent=2), encoding="utf-8")
            status = "partial" if page_errors else "ok"
            result: dict[str, Any] = {"source": source.name, "status": status, "raw_path": str(raw_path), "records": len(all_records)}
            if page_errors:
                result["reason"] = "; ".join(page_errors)
            return all_records, result

        url = source.url
        if source.requires_key:
            app_key = os.environ.get("PHISHTANK_APP_KEY")
            if not app_key:
                return [], {"source": source.name, "status": "skipped", "reason": "set PHISHTANK_APP_KEY to enable"}
            url = url.format(app_key=app_key)

        data = fetch_bytes(url, timeout)
        suffix = "json.bz2" if source.parser == "phishtank_json_bz2" else "txt"
        if source.parser == "urlhaus_csv":
            suffix = "csv"
        raw_path = RAW_DIR / safe_filename(source.name, suffix)
        raw_path.write_bytes(data)

        if source.parser == "phishtank_json_bz2":
            records = parse_phishtank_json_bz2(data, source, fetched_at)
        else:
            text = data.decode("utf-8", errors="replace")
            if source.parser == "line_urls":
                records = parse_line_urls(text, source, fetched_at)
            elif source.parser == "line_domains":
                records = parse_line_domains(text, source, fetched_at)
            elif source.parser == "urlhaus_csv":
                records = parse_urlhaus_csv(text, source, fetched_at)
            else:
                raise ValueError(f"unknown parser: {source.parser}")
        return records, {"source": source.name, "status": "ok", "raw_path": str(raw_path), "records": len(records)}
    except HTTPError as exc:
        return [], {"source": source.name, "status": "error", "reason": f"HTTP {exc.code}: {exc.reason}"}
    except (URLError, TimeoutError, OSError, json.JSONDecodeError, csv.Error, ValueError) as exc:
        return [], {"source": source.name, "status": "error", "reason": str(exc)}


def main() -> int:
    parser = argparse.ArgumentParser(description="Fetch phishing URL/domain data from trusted public feeds.")
    parser.add_argument("--sources", nargs="*", default=["openphish", "cert_pl", "phishstats", "urlhaus_recent"])
    parser.add_argument("--include-phishtank", action="store_true", help="Enable PhishTank when PHISHTANK_APP_KEY is set.")
    parser.add_argument("--phishstats-pages", type=int, default=9, help="100 records per page; keep polite.")
    parser.add_argument("--timeout", type=int, default=45)
    args = parser.parse_args()

    selected = list(args.sources)
    if args.include_phishtank and "phishtank" not in selected:
        selected.append("phishtank")

    unknown = [name for name in selected if name not in SOURCES]
    if unknown:
        print(f"Unknown sources: {', '.join(unknown)}", file=sys.stderr)
        return 2

    all_records: list[dict[str, Any]] = []
    report: list[dict[str, Any]] = []
    for name in selected:
        source = SOURCES[name]
        records, status = fetch_source(source, timeout=args.timeout, phishstats_pages=args.phishstats_pages)
        report.append(status)
        all_records.extend(records)

    deduped: dict[tuple[str, str], dict[str, Any]] = {}
    for record in all_records:
        key = (record["indicator_type"], record["indicator"])
        existing = deduped.get(key)
        if not existing:
            deduped[key] = record
            continue
        existing_sources = set(str(existing["source"]).split("|"))
        existing_sources.add(record["source"])
        existing["source"] = "|".join(sorted(existing_sources))

    records = sorted(deduped.values(), key=lambda row: (row["indicator_type"], row["indicator"]))
    write_jsonl(PROCESSED_DIR / "phishing_indicators.jsonl", records)
    write_csv(PROCESSED_DIR / "phishing_indicators.csv", records)
    (PROCESSED_DIR / "phishing_urls.txt").write_text(
        "\n".join(row["indicator"] for row in records if row["indicator_type"] == "url") + "\n",
        encoding="utf-8",
    )
    (PROCESSED_DIR / "phishing_domains.txt").write_text(
        "\n".join(row["indicator"] for row in records if row["indicator_type"] == "domain") + "\n",
        encoding="utf-8",
    )
    (PROCESSED_DIR / "defanged_indicators.txt").write_text(
        "\n".join(row["defanged_indicator"] for row in records) + "\n",
        encoding="utf-8",
    )

    summary = {
        "fetched_at": utc_now(),
        "selected_sources": selected,
        "source_results": report,
        "total_records_before_dedupe": len(all_records),
        "total_records_after_dedupe": len(records),
        "url_records": sum(1 for row in records if row["indicator_type"] == "url"),
        "domain_records": sum(1 for row in records if row["indicator_type"] == "domain"),
        "outputs": {
            "jsonl": str(PROCESSED_DIR / "phishing_indicators.jsonl"),
            "csv": str(PROCESSED_DIR / "phishing_indicators.csv"),
            "urls": str(PROCESSED_DIR / "phishing_urls.txt"),
            "domains": str(PROCESSED_DIR / "phishing_domains.txt"),
            "defanged": str(PROCESSED_DIR / "defanged_indicators.txt"),
        },
    }
    (PROCESSED_DIR / "fetch_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
