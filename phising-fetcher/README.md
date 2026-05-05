# Phising Fetcher

Small defensive dataset fetcher for phishing URL/domain indicators.

The folder name keeps the requested spelling (`phising-fetcher`), but the generated files use `phishing_*` names.

## Sources Tested

| Source | Type | Status | Notes |
| --- | --- | --- | --- |
| OpenPhish Community Feed | phishing URLs | enabled | Free community feed from OpenPhish. Limited but fresh. |
| PhishStats API | phishing URLs | enabled | Public API. The script fetches pages politely, 100 records per page. |
| CERT Polska Warning List | dangerous/phishing domains | enabled | National CERT warning list. Domain-only, not full URL paths. |
| URLhaus Recent CSV | malicious URLs | enabled | Reliable abuse.ch feed, but malware/malicious URL focused rather than phishing-only. Keep the `label` column if using it for ML. |
| PhishTank verified online feed | phishing URLs | optional | Requires `PHISHTANK_APP_KEY`. Public no-key access returned 403 during testing. |

## Run

```powershell
python .\fetch_phishing_data.py
```

Optional PhishTank:

```powershell
$env:PHISHTANK_APP_KEY = "your-key"
python .\fetch_phishing_data.py --include-phishtank
```

Fetch more PhishStats pages:

```powershell
python .\fetch_phishing_data.py --phishstats-pages 20
```

The default is 9 pages because the public API returned HTTP 429 after page 9 during testing.

## Outputs

Generated under `data/processed/`:

| File | Purpose |
| --- | --- |
| `phishing_indicators.jsonl` | Full records with metadata and source labels. Best for ingestion. |
| `phishing_indicators.csv` | Spreadsheet-friendly version. |
| `phishing_urls.txt` | URL-only list. Includes phishing URL sources plus URLhaus malicious URLs. |
| `phishing_domains.txt` | Domain-only list from CERT Polska. |
| `defanged_indicators.txt` | Safer-to-open view for manual inspection. |
| `fetch_summary.json` | Run summary and per-source status. |
| `quality_ranked_urls.jsonl` | URL records ranked for phishing coverage, capped at 5 per domain. |
| `quality_ranked_urls_sources.jsonl` | Slim ranked URL/source-only file for ingestion. |
| `israel_elderly_relevant_urls.jsonl` | Israel citizen/senior-focused URL candidates with scoring reasons. |
| `israel_elderly_urls_sources.jsonl` | Slim Israel-focused URL/source-only file for ingestion. |

Raw downloads are timestamped under `data/raw/`.

## Rank URL Quality

For vector search, repeated paths on the same domain can crowd out more useful phishing patterns. This command ranks URL records by source trust and phishing-specific signals, then keeps at most 5 URLs from the same domain:

```powershell
python .\rank_url_quality.py
```

Change the cap if needed:

```powershell
python .\rank_url_quality.py --max-per-domain 3
```

## Israel/Senior-Focused URL Candidates

Generic phishing feeds overrepresent developer tooling, cloud infrastructure, and malware download paths. For NoPhish's Israeli senior audience, use the Israel-focused builder:

```powershell
python .\fetch_israel_elderly_urls.py
```

It combines the existing phishing feed data with public URLScan searches around Israeli daily-life targets: Israel Post, National Insurance, gov.il-style services, banks, credit cards, health funds, telecom, utilities, municipal payment, and Highway 6 tolls. It excludes official domains and caps each suspicious domain to 5 URLs.

If URLScan is rate-limiting, rerun from the cached URLScan raw files and the already downloaded feed data:

```powershell
python .\fetch_israel_elderly_urls.py --skip-urlscan
```

## Data Hygiene

These feeds contain live malicious indicators. Do not click raw URLs. For model training, prefer `phishing_indicators.jsonl` or `phishing_indicators.csv` and keep the `source`, `label`, and `indicator_type` fields. URLhaus is intentionally labeled `malicious_url`, because it is high-quality threat intel but not phishing-only.
