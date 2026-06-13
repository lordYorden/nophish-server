# Detection Evaluation Harness

This directory contains a standalone evaluation harness for the phishing detection modules. It is intentionally separate from the application runtime and does not require the repo to have a test framework.

The harness tests each detector independently, then evaluates aggregation policies separately.

## Modules

- `llm`: calls `app.detectors.tasks.run_llm_and_decide` in live mode.
- `url_scanner`: calls `app.detectors.tasks.module_dynamic_url_scanner` for the real module verdict and emits separate breakdown rows for normalization, static heuristics, safety, HTTP redirects, browser expansion, and `scan_url`.
- `url_embedding`: calls `app.detectors.tasks.module_url_embedding` in live mode. Offline mode marks this module skipped because the actual module depends on Postgres/pgvector and the embedding model.
- `aggregator`: replays isolated module votes and compares aggregation policies without sending FCM or writing production alerts.

## Case File

`detection_cases.jsonl` is a JSONL corpus. Required fields:

```json
{
  "id": "benign_restaurant_shortlink_001",
  "label": "benign",
  "body": "Message body",
  "packageName": "com.whatsapp",
  "urls": ["https://example.org/"],
  "source": "curated",
  "tags": ["hebrew", "shortener"],
  "notes": "Optional context"
}
```

`label` must be `phishing` or `benign`.

## Offline Run

Offline mode requires no API keys, database, Redis, browser, or network.

```bash
uv run python eval/run_detection_eval.py \
  --cases eval/detection_cases.jsonl \
  --mode offline \
  --modules llm,url_scanner,url_embedding \
  --out eval/results/module_eval.jsonl
```

Offline behavior:

- LLM rows are marked skipped because the real module requires an API call.
- URL scanner runs normalization/static breakdowns and derives an offline scanner row from those static checks; live DNS/HTTP/browser submodules are skipped.
- URL embedding rows are marked skipped unless a case has no URLs and can be evaluated by the actual early-return path.

## Hybrid/Live Run

Hybrid mode uses live behavior where credentials and services are available, and records skipped/error rows where they are not.

```bash
uv run python eval/run_detection_eval.py \
  --cases eval/detection_cases.jsonl \
  --mode hybrid \
  --modules llm,url_scanner,url_embedding \
  --live-limit 50 \
  --out eval/results/module_eval.jsonl
```

Useful environment variables:

- `OPEN_ROUTER_KEY`
- `LLM_MODEL`
- `EMBED_MODEL`
- `DATABASE_URL`
- `DYNAMIC_URL_SCANNER_ENABLE_BROWSER=true`

## Single Module Runs

```bash
uv run python eval/run_detection_eval.py \
  --cases eval/detection_cases.jsonl \
  --mode offline \
  --modules url_scanner \
  --out eval/results/url_scanner_eval.jsonl
```

`url_embedding` should be run in `hybrid`/live mode when Postgres, pgvector, the schema, and seeded `maliciousurl` rows are available.

## Seed URL Embeddings

The live URL embedding detector compares submitted URL embeddings against rows in the `maliciousurl` table. Seed that table before using live embedding checks:

```bash
uv run python eval/seed_malicious_urls.py --dry-run
uv run python eval/seed_malicious_urls.py --limit 500
```

Defaults:

- Loads `.env` and `llm/.env`.
- Reads phishing URLs from `eval/detection_cases.jsonl`, `phising-fetcher/data/processed/israel_elderly_urls_sources.jsonl`, and `phising-fetcher/data/processed/quality_ranked_urls_sources.jsonl`.
- Canonicalizes URLs with the app URL scanner.
- Skips URLs already present in `maliciousurl`.

Use `--limit 0` to seed all available source URLs.

For non-exact similarity testing, generate fuzzy eval cases and seed different fuzzy variants:

```bash
uv run python eval/build_fuzzy_cases.py \
  --input eval/detection_cases.jsonl \
  --out eval/detection_cases_fuzzy.jsonl \
  --start-index 100

uv run python eval/seed_malicious_urls.py \
  --limit 500 \
  --fuzz-variants 2 \
  --fuzz-start-index 0 \
  --exclude-urls-from eval/detection_cases_fuzzy.jsonl
```

This setup avoids exact URL overlap between evaluated phishing URLs and newly seeded fuzzy rows.

```bash
uv run python eval/run_detection_eval.py \
  --cases eval/detection_cases.jsonl \
  --mode hybrid \
  --modules aggregator \
  --out eval/results/aggregator_eval.jsonl
```

## Report

```bash
uv run python eval/report_detection_eval.py \
  --input eval/results/module_eval.jsonl \
  --out eval/results/detection_eval_report.md
```

The report includes:

- Per-module metrics and confusion matrices
- False positives and false negatives per module
- URL scanner reason breakdown
- LLM confidence threshold analysis
- URL embedding threshold sweep using nearest-match distance metadata
- URL embedding distance breakdown with checked URL and nearest matched DB URL
- Aggregator policy comparison
- Ranked improvement backlog

## Notes

- Result files under `eval/results/` are generated artifacts and should normally stay untracked.
- The harness does not add or change migrations.
- Aggregator evaluation mocks side effects and does not send FCM.
