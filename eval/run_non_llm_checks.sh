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

describe_cases() {
  python - "$CASES" "$LIVE_LIMIT" <<'PY'
from collections import Counter
from pathlib import Path
import json
import sys

path = Path(sys.argv[1])
live_limit = int(sys.argv[2])
rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
selected = rows[:live_limit]

labels = Counter(row["label"] for row in selected)
url_counts = Counter("with_urls" if row.get("urls") else "no_urls" for row in selected)
tags = Counter(tag for row in selected for tag in row.get("tags", []))
sources = Counter(row.get("source", "unknown") for row in selected)

print(f"Selected cases: {len(selected)} of {len(rows)}")
print("Labels: " + ", ".join(f"{key}={value}" for key, value in sorted(labels.items())))
print("URL presence: " + ", ".join(f"{key}={value}" for key, value in sorted(url_counts.items())))
print("Sources: " + ", ".join(f"{key}={value}" for key, value in sources.most_common(8)))
print("Top tags: " + ", ".join(f"{key}={value}" for key, value in tags.most_common(12)))
print("First selected case IDs: " + ", ".join(row["id"] for row in selected[:10]))

print()
print("Payload sent to app detector modules per case:")
print("  NotificationSubmission(")
print("    eventId=<case id>, sourceUserId='eval-user', circleId='eval-circle',")
print("    title=None, body=<case body>, packageName=<case packageName>,")
print("    timestamp=0, contentHash='eval-<case id>', urls=<case urls>")
print("  )")
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

display_path() {
  local path="$1"
  if [[ "$path" == "$ROOT_DIR/"* ]]; then
    echo "${path#"$ROOT_DIR/"}"
  else
    echo "$path"
  fi
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
describe_cases

echo
echo "Running URL scanner checks against app.detectors.tasks.module_dynamic_url_scanner..."
echo "Module payload: app.detectors.tasks.module_dynamic_url_scanner(NotificationSubmission)"
START_SECONDS=$SECONDS
rm -f "$RESULTS_DIR/url_scanner_eval.jsonl" "$RESULTS_DIR/url_scanner_eval_report.md"
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
  echo "Module payload: app.detectors.tasks.module_url_embedding(NotificationSubmission)"
  START_SECONDS=$SECONDS
  rm -f "$RESULTS_DIR/url_embedding_live_eval.jsonl" "$RESULTS_DIR/url_embedding_live_report.md"
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
echo "Combining existing module outputs..."
COMBINE_INPUTS=("$RESULTS_DIR/url_scanner_eval.jsonl")
if [[ "$RUN_LIVE_EMBEDDING" == "true" ]]; then
  COMBINE_INPUTS+=("$RESULTS_DIR/url_embedding_live_eval.jsonl")
fi
echo "Inputs:"
for input in "${COMBINE_INPUTS[@]}"; do
  echo "  $(display_path "$input")"
done
echo "No detector modules are rerun for this combined report."

START_SECONDS=$SECONDS
rm -f "$RESULTS_DIR/non_llm_eval.jsonl" "$RESULTS_DIR/non_llm_report.md"
uv run python "$ROOT_DIR/eval/combine_detection_results.py" \
  --input "${COMBINE_INPUTS[@]}" \
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
