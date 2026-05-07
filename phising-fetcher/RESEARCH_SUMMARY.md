# Phishing URL Data Research Summary

## Goal

Build phishing URL data that is useful for NoPhish's vector-distance relevance flow, with special emphasis on common citizens and elderly users in Israel.

The main quality constraint is diversity: repeated URLs from the same domain add little value for vector search, so curated outputs cap each domain at 5 URLs.

## Source Review

| Source | Result | Keep? | Notes |
| --- | --- | --- | --- |
| OpenPhish community feed | 300 live phishing URLs | Yes | Small but phishing-specific and high quality. |
| PhishStats API | 900 phishing URLs before public rate limit | Yes | Useful, but API hit HTTP 429 after page 9. |
| CERT Polska warning list | 133,685 dangerous/phishing domains | Local only | Strong feed, but domain-only and did not add Israel-specific URL candidates in this run. |
| URLhaus recent CSV | 27,797 malicious URLs | Limited | Reliable threat intel, but malware-oriented, not phishing-only. Kept separate/lower ranked. |
| PhishTank | Not fetched | Optional | No-key access returned 403. Script supports `PHISHTANK_APP_KEY`. |
| URLScan public search | 701 cached Israel-targeted scan URLs | Yes | Best source for Israeli citizen/senior impersonation candidates. |

## Generic Ranking Output

The generic quality ranking is produced by:

```powershell
python .\rank_url_quality.py --max-per-domain 5
```

Relevant committed output:

| File | Records | Purpose |
| --- | ---: | --- |
| `data/processed/quality_ranked_urls_sources.jsonl` | 20,600 | Slim URL/source-only generic ranked list. |
| `data/processed/quality_ranked_urls.summary.json` | summary | Counts and source mix for the generic ranked list. |

The richer generic ranked JSONL is intentionally ignored because it is larger and mostly debug metadata.

## Israel/Senior-Focused Output

The Israel-focused collector is produced by:

```powershell
python .\fetch_israel_elderly_urls.py --skip-urlscan --max-per-domain 5
```

Use `--skip-urlscan` for reproducible offline reruns from cached raw URLScan files. To expand the cache later:

```powershell
python .\fetch_israel_elderly_urls.py --urlscan-size 100 --pause 1.2 --max-per-domain 5
```

Relevant committed output:

| File | Records | Purpose |
| --- | ---: | --- |
| `data/processed/israel_elderly_urls_sources.jsonl` | 281 | Slim ingestion file with only `url` and `source`. |
| `data/processed/israel_elderly_relevant_urls.jsonl` | 281 | Audit file with scores, category, matched target, and reasons. |
| `data/processed/israel_elderly_relevant_urls.summary.json` | summary | Distribution by category, target, and source. |

Current category distribution:

| Category | Count |
| --- | ---: |
| Israel Post delivery | 153 |
| Banking | 41 |
| Telecom | 31 |
| Municipal/Arnona payment | 15 |
| Government/tax-style services | 10 |
| Credit cards | 10 |
| Health funds | 9 |
| Bituach Leumi/National Insurance | 7 |
| Highway 6 toll | 5 |

## Quality Controls

The Israel-focused matcher keeps a URL only when it resembles an impersonation candidate. A mere mention of an Israeli brand in an article or reference page is not enough.

Accepted signals include:

- Israeli target term appears in the host.
- URLScan tags include phishing or possible threat.
- URLScan marks the scan malicious.
- Risky/common-abuse host plus phishing action words such as login, payment, delivery, verify, account, or OTP.

Filtered/guarded cases include:

- Official domains, such as `btl.gov.il`, `gov.il`, bank official domains, and health fund official domains.
- News/reference-style URLs where the brand appears only in article text or path.
- The earlier false positive `www.securityweek.com/cellcom-service-disruption-caused-by-cyberattack/` is no longer included.

## Recommendation

For app ingestion focused on elderly Israeli users, use:

```text
data/processed/israel_elderly_urls_sources.jsonl
```

For broader fallback coverage, use:

```text
data/processed/quality_ranked_urls_sources.jsonl
```

Keep the rich Israel audit file nearby during evaluation so false positives can be traced to score reasons and URLScan result links.

## Limitations

- URLScan rate-limited further expansion with HTTP 429 during this run, so additional high-quality terms should be fetched later.
- URLScan public-search data is best treated as suspicious candidate data, not guaranteed confirmed phishing.
- Israel-specific Hebrew-script scam URLs may still be underrepresented because many public feeds index ASCII/transliterated hostnames more reliably than Hebrew content.
