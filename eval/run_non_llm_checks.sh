#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CASES="${CASES:-$ROOT_DIR/eval/detection_cases.jsonl}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/eval/results}"
LIVE_LIMIT="${LIVE_LIMIT:-50}"
RUN_LIVE_EMBEDDING="${RUN_LIVE_EMBEDDING:-false}"

mkdir -p "$RESULTS_DIR"

export DYNAMIC_URL_SCANNER_ENABLE_BROWSER="${DYNAMIC_URL_SCANNER_ENABLE_BROWSER:-true}"

count_cases() {
  python - "$CASES" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
print(sum(1 for line in path.read_text(encoding="utf-8").splitlines() if line.strip()))
PY
}

summarize_report() {
  local report="$1"
  local title="$2"
  echo
  echo "== $title =="
  python - "$report" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
if not path.exists():
    print(f"Report missing: {path}")
    raise SystemExit(0)

lines = path.read_text(encoding="utf-8").splitlines()
in_metrics = False
printed = 0
for line in lines:
    if line == "## Metrics By Module":
        in_metrics = True
        continue
    if in_metrics and line.startswith("## "):
        break
    if not in_metrics or not line.startswith("| "):
        continue
    if line.startswith("| ---"):
        continue
    if printed == 0:
        print(line)
        printed += 1
        continue
    parts = [part.strip() for part in line.strip("|").split("|")]
    if len(parts) < 15:
        continue
    module, scored, skipped, tp, tn, fp, fn, precision, recall, fpr, fnr, accuracy, median, p95, priority = parts[:15]
    print(
        f"{module}: scored={scored}, skipped={skipped}, "
        f"TP={tp}, TN={tn}, FP={fp}, FN={fn}, "
        f"precision={precision}, recall={recall}, FPR={fpr}, accuracy={accuracy}, p95_ms={p95}"
    )
    printed += 1

if printed <= 1:
    print("No metrics found in report.")
PY
  echo "Report: $report"
}

run_and_log() {
  echo
  echo "+ $*"
  "$@"
}

CASE_COUNT="$(count_cases)"

echo "NoPhish non-LLM detection checks"
echo "Root: $ROOT_DIR"
echo "Cases: $CASES ($CASE_COUNT cases)"
echo "Live limit: $LIVE_LIMIT"
echo "Browser scanner enabled: $DYNAMIC_URL_SCANNER_ENABLE_BROWSER"
echo "Run live embedding: $RUN_LIVE_EMBEDDING"
echo "Results: $RESULTS_DIR"

echo
echo "Running URL scanner checks against app.detectors.tasks.module_dynamic_url_scanner..."
START_SECONDS=$SECONDS
uv run python "$ROOT_DIR/eval/run_detection_eval.py" \
  --cases "$CASES" \
  --mode hybrid \
  --modules url_scanner \
  --live-limit "$LIVE_LIMIT" \
  --out "$RESULTS_DIR/url_scanner_eval.jsonl"

uv run python "$ROOT_DIR/eval/report_detection_eval.py" \
  --input "$RESULTS_DIR/url_scanner_eval.jsonl" \
  --out "$RESULTS_DIR/url_scanner_eval_report.md"
echo "URL scanner checks finished in $((SECONDS - START_SECONDS))s"
summarize_report "$RESULTS_DIR/url_scanner_eval_report.md" "URL Scanner Summary"

if [[ "$RUN_LIVE_EMBEDDING" == "true" ]]; then
  echo
  echo "Running URL embedding live checks against app.detectors.tasks.module_url_embedding..."
  START_SECONDS=$SECONDS
  uv run python "$ROOT_DIR/eval/run_detection_eval.py" \
    --cases "$CASES" \
    --mode hybrid \
    --modules url_embedding \
    --live-limit "$LIVE_LIMIT" \
    --out "$RESULTS_DIR/url_embedding_live_eval.jsonl"

  uv run python "$ROOT_DIR/eval/report_detection_eval.py" \
    --input "$RESULTS_DIR/url_embedding_live_eval.jsonl" \
    --out "$RESULTS_DIR/url_embedding_live_report.md"
  echo "URL embedding live checks finished in $((SECONDS - START_SECONDS))s"
  summarize_report "$RESULTS_DIR/url_embedding_live_report.md" "URL Embedding Summary"
else
  echo
  echo "Skipping URL embedding module checks. Set RUN_LIVE_EMBEDDING=true when Postgres/pgvector is ready and seeded."
fi

echo
echo "Running combined non-LLM checks..."
COMBINED_MODULES="url_scanner"
if [[ "$RUN_LIVE_EMBEDDING" == "true" ]]; then
  COMBINED_MODULES="url_scanner,url_embedding"
fi

START_SECONDS=$SECONDS
uv run python "$ROOT_DIR/eval/run_detection_eval.py" \
  --cases "$CASES" \
  --mode hybrid \
  --modules "$COMBINED_MODULES" \
  --live-limit "$LIVE_LIMIT" \
  --out "$RESULTS_DIR/non_llm_eval.jsonl"

uv run python "$ROOT_DIR/eval/report_detection_eval.py" \
  --input "$RESULTS_DIR/non_llm_eval.jsonl" \
  --out "$RESULTS_DIR/non_llm_report.md"
echo "Combined non-LLM checks finished in $((SECONDS - START_SECONDS))s"
summarize_report "$RESULTS_DIR/non_llm_report.md" "Combined Non-LLM Summary"

echo
echo "Done. Reports:"
echo "  $RESULTS_DIR/url_scanner_eval_report.md"
if [[ "$RUN_LIVE_EMBEDDING" == "true" ]]; then
  echo "  $RESULTS_DIR/url_embedding_live_report.md"
fi
echo "  $RESULTS_DIR/non_llm_report.md"
