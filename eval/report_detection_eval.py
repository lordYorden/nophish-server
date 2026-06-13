#!/usr/bin/env python3
"""Build a Markdown report from detection evaluation JSONL output."""

from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]


def load_rows(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if stripped:
                rows.append(json.loads(stripped))
    return rows


def is_expected_positive(row: dict[str, Any]) -> bool:
    return row["label"] == "phishing"


def is_scored(row: dict[str, Any]) -> bool:
    return row.get("verdict") is not None and not row.get("metadata", {}).get("skipped")


def compute_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [row for row in rows if is_scored(row)]
    tp = sum(1 for row in scored if row["verdict"] is True and is_expected_positive(row))
    tn = sum(1 for row in scored if row["verdict"] is False and not is_expected_positive(row))
    fp = sum(1 for row in scored if row["verdict"] is True and not is_expected_positive(row))
    fn = sum(1 for row in scored if row["verdict"] is False and is_expected_positive(row))
    errors = sum(1 for row in rows if row.get("error") and not row.get("metadata", {}).get("skipped"))
    skipped = sum(1 for row in rows if row.get("metadata", {}).get("skipped"))
    latencies = [float(row.get("latency_ms") or 0.0) for row in scored]
    total = tp + tn + fp + fn
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    false_positive_rate = safe_div(fp, fp + tn)
    false_negative_rate = safe_div(fn, fn + tp)
    accuracy = safe_div(tp + tn, total)
    priority = fp * 2.0 + fn * 1.5 + errors + latency_penalty(latencies)
    return {
        "total": len(rows),
        "scored": total,
        "skipped": skipped,
        "errors": errors,
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "fpr": false_positive_rate,
        "fnr": false_negative_rate,
        "accuracy": accuracy,
        "median_latency_ms": percentile(latencies, 50),
        "p95_latency_ms": percentile(latencies, 95),
        "priority": priority,
    }


def safe_div(numerator: float, denominator: float) -> float | None:
    if denominator == 0:
        return None
    return numerator / denominator


def percentile(values: list[float], pct: int) -> float | None:
    if not values:
        return None
    if len(values) == 1:
        return round(values[0], 3)
    ordered = sorted(values)
    index = (len(ordered) - 1) * (pct / 100)
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    if lower == upper:
        return round(ordered[lower], 3)
    weight = index - lower
    return round(ordered[lower] * (1 - weight) + ordered[upper] * weight, 3)


def latency_penalty(latencies: list[float]) -> float:
    p95 = percentile(latencies, 95)
    if p95 is None:
        return 0.0
    return max(0.0, (p95 - 1000.0) / 1000.0)


def format_rate(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.3f}"


def format_number(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.1f}" if isinstance(value, float) else str(value)


def group_by_module(rows: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row["module"]].append(row)
    return dict(sorted(grouped.items()))


def markdown_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
    return "\n".join(lines)


def metrics_table(module_metrics: dict[str, dict[str, Any]]) -> str:
    rows = []
    for module, metrics in module_metrics.items():
        rows.append(
            [
                module,
                metrics["scored"],
                metrics["skipped"],
                metrics["tp"],
                metrics["tn"],
                metrics["fp"],
                metrics["fn"],
                format_rate(metrics["precision"]),
                format_rate(metrics["recall"]),
                format_rate(metrics["fpr"]),
                format_rate(metrics["fnr"]),
                format_rate(metrics["accuracy"]),
                format_number(metrics["median_latency_ms"]),
                format_number(metrics["p95_latency_ms"]),
                f"{metrics['priority']:.2f}",
            ]
        )
    return markdown_table(
        [
            "Module",
            "Scored",
            "Skipped",
            "TP",
            "TN",
            "FP",
            "FN",
            "Precision",
            "Recall",
            "FPR",
            "FNR",
            "Accuracy",
            "Median ms",
            "P95 ms",
            "Priority",
        ],
        rows,
    )


def confusion_matrix_table(module_metrics: dict[str, dict[str, Any]]) -> str:
    rows = []
    for module, metrics in module_metrics.items():
        rows.append([module, metrics["tp"], metrics["fp"], metrics["fn"], metrics["tn"]])
    return markdown_table(["Module", "Pred phishing / Actual phishing", "Pred phishing / Actual benign", "Pred benign / Actual phishing", "Pred benign / Actual benign"], rows)


def false_rows(rows: list[dict[str, Any]], false_positive: bool, limit: int) -> list[dict[str, Any]]:
    selected = []
    for row in rows:
        if not is_scored(row):
            continue
        if false_positive and row["verdict"] is True and not is_expected_positive(row):
            selected.append(row)
        if not false_positive and row["verdict"] is False and is_expected_positive(row):
            selected.append(row)
    selected.sort(key=lambda row: (-(row.get("confidence") or 0.0), row.get("latency_ms") or 0.0))
    return selected[:limit]


def failure_table(rows: list[dict[str, Any]], limit: int = 10) -> str:
    table_rows = []
    for row in rows[:limit]:
        metadata = row.get("metadata", {})
        table_rows.append(
            [
                row["module"],
                row["case_id"],
                row["label"],
                row["verdict"],
                ",".join(row.get("reasons") or []),
                row.get("error") or "",
                ",".join(metadata.get("tags") or []),
            ]
        )
    if not table_rows:
        return "No rows."
    return markdown_table(["Module", "Case", "Label", "Verdict", "Reasons", "Error", "Tags"], table_rows)


def reason_breakdown(rows: list[dict[str, Any]]) -> str:
    counter: Counter[str] = Counter()
    benign_counter: Counter[str] = Counter()
    for row in rows:
        if not row["module"].startswith("url_scanner") or not is_scored(row):
            continue
        for reason in row.get("reasons") or []:
            counter[reason] += 1
            if row["label"] == "benign" and row["verdict"] is True:
                benign_counter[reason] += 1
    if not counter:
        return "No URL scanner reasons were recorded."
    table_rows = [
        [reason, count, benign_counter.get(reason, 0)]
        for reason, count in counter.most_common()
    ]
    return markdown_table(["Reason", "Total count", "Benign false-positive count"], table_rows)


def llm_threshold_analysis(rows: list[dict[str, Any]]) -> str:
    llm_rows = [
        row
        for row in rows
        if row["module"] == "llm" and is_scored(row) and row.get("confidence") is not None
    ]
    if not llm_rows:
        return "No scored LLM confidence rows were available."
    near_threshold = [
        row for row in llm_rows if 0.6 <= float(row["confidence"]) <= 0.8
    ]
    benign_conf = [float(row["confidence"]) for row in llm_rows if row["label"] == "benign"]
    phishing_conf = [float(row["confidence"]) for row in llm_rows if row["label"] == "phishing"]
    lines = [
        f"- Rows near current 0.7 threshold: {len(near_threshold)}",
        f"- Benign median confidence: {format_number(percentile(benign_conf, 50))}",
        f"- Phishing median confidence: {format_number(percentile(phishing_conf, 50))}",
    ]
    if near_threshold:
        lines.append("")
        lines.append(
            markdown_table(
                ["Case", "Label", "Verdict", "Confidence"],
                [
                    [row["case_id"], row["label"], row["verdict"], f"{float(row['confidence']):.3f}"]
                    for row in near_threshold[:10]
                ],
            )
        )
    return "\n".join(lines)


def embedding_threshold_sweep(rows: list[dict[str, Any]]) -> str:
    embedding_rows = [
        row
        for row in rows
        if row["module"] == "url_embedding"
        and row.get("metadata", {}).get("distance") is not None
        and not row.get("metadata", {}).get("skipped")
    ]
    if not embedding_rows:
        return "No embedding distance metadata was available. Live module output currently returns only a boolean verdict."
    table_rows = []
    for threshold in (0.05, 0.10, 0.15, 0.20, 0.25):
        synthetic = []
        for row in embedding_rows:
            copy = dict(row)
            copy["verdict"] = float(row["metadata"]["distance"]) < threshold
            synthetic.append(copy)
        metrics = compute_metrics(synthetic)
        table_rows.append(
            [
                f"{threshold:.2f}",
                metrics["tp"],
                metrics["tn"],
                metrics["fp"],
                metrics["fn"],
                format_rate(metrics["precision"]),
                format_rate(metrics["recall"]),
                format_rate(metrics["fpr"]),
            ]
        )
    return markdown_table(["Threshold", "TP", "TN", "FP", "FN", "Precision", "Recall", "FPR"], table_rows)


def best_worst_summary(module_metrics: dict[str, dict[str, Any]]) -> str:
    scored = {
        module: metrics
        for module, metrics in module_metrics.items()
        if metrics["scored"] > 0 and not module.startswith("aggregator.")
    }
    if not scored:
        return "No scored non-aggregator modules were available."
    best_fpr = min(scored.items(), key=lambda item: item[1]["fpr"] if item[1]["fpr"] is not None else 999)
    worst_fpr = max(scored.items(), key=lambda item: item[1]["fpr"] if item[1]["fpr"] is not None else -1)
    best_recall = max(scored.items(), key=lambda item: item[1]["recall"] if item[1]["recall"] is not None else -1)
    worst_recall = min(scored.items(), key=lambda item: item[1]["recall"] if item[1]["recall"] is not None else 999)
    highest_priority = max(scored.items(), key=lambda item: item[1]["priority"])
    return "\n".join(
        [
            f"- Best false-positive rate: `{best_fpr[0]}` ({format_rate(best_fpr[1]['fpr'])})",
            f"- Worst false-positive rate: `{worst_fpr[0]}` ({format_rate(worst_fpr[1]['fpr'])})",
            f"- Best recall: `{best_recall[0]}` ({format_rate(best_recall[1]['recall'])})",
            f"- Worst recall: `{worst_recall[0]}` ({format_rate(worst_recall[1]['recall'])})",
            f"- Highest improvement priority: `{highest_priority[0]}` (score {highest_priority[1]['priority']:.2f})",
        ]
    )


def aggregator_comparison(module_metrics: dict[str, dict[str, Any]]) -> str:
    aggregator = {
        module: metrics
        for module, metrics in module_metrics.items()
        if module.startswith("aggregator.")
    }
    if not aggregator:
        return "No aggregator rows were available."
    return metrics_table(aggregator)


def improvement_backlog(module_metrics: dict[str, dict[str, Any]]) -> str:
    scored = [
        (module, metrics)
        for module, metrics in module_metrics.items()
        if metrics["scored"] > 0 and not module.startswith("aggregator.")
    ]
    scored.sort(key=lambda item: item[1]["priority"], reverse=True)
    if not scored:
        return "No scored modules were available."
    rows = []
    for index, (module, metrics) in enumerate(scored[:10], start=1):
        if metrics["fp"] > metrics["fn"]:
            reason = "false positives dominate"
        elif metrics["fn"] > metrics["fp"]:
            reason = "false negatives dominate"
        elif metrics["errors"]:
            reason = "runtime errors observed"
        else:
            reason = "latency or mixed residual risk"
        rows.append([index, module, f"{metrics['priority']:.2f}", reason])
    return markdown_table(["Rank", "Module", "Priority", "Why"], rows)


def build_report(rows: list[dict[str, Any]], input_path: Path) -> str:
    grouped = group_by_module(rows)
    module_metrics = {module: compute_metrics(module_rows) for module, module_rows in grouped.items()}
    false_positives = []
    false_negatives = []
    for module_rows in grouped.values():
        false_positives.extend(false_rows(module_rows, false_positive=True, limit=10))
        false_negatives.extend(false_rows(module_rows, false_positive=False, limit=10))

    lines = [
        "# Detection Evaluation Report",
        "",
        f"Input: `{input_path}`",
        f"Rows: {len(rows)}",
        "",
        "## Summary",
        "",
        best_worst_summary(module_metrics),
        "",
        "## Metrics By Module",
        "",
        metrics_table(module_metrics),
        "",
        "## Confusion Matrices",
        "",
        confusion_matrix_table(module_metrics),
        "",
        "## Top False Positives",
        "",
        failure_table(false_positives, limit=25),
        "",
        "## Top False Negatives",
        "",
        failure_table(false_negatives, limit=25),
        "",
        "## URL Scanner Reason Breakdown",
        "",
        reason_breakdown(rows),
        "",
        "## LLM Confidence Threshold Analysis",
        "",
        llm_threshold_analysis(rows),
        "",
        "## URL Embedding Threshold Sweep",
        "",
        embedding_threshold_sweep(rows),
        "",
        "## Aggregator Comparison",
        "",
        aggregator_comparison(module_metrics),
        "",
        "## Final Ranked Improvement Backlog",
        "",
        improvement_backlog(module_metrics),
        "",
    ]
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "eval/results/detection_eval_report.md")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    rows = load_rows(args.input)
    report = build_report(rows, args.input)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(report, encoding="utf-8")


if __name__ == "__main__":
    main()
