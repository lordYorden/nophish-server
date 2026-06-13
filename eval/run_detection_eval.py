#!/usr/bin/env python3
"""Run isolated detection-module evaluations and write JSONL results."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import random
import sys
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from app.detectors.url_scanner.heuristics import has_strong_static_signal, unsafe_ip_reason
from app.detectors.url_scanner.http_redirects import expand_http_redirects
from app.detectors.url_scanner.normalization import canonicalize_url_for_lookup, normalize_url
from app.detectors.url_scanner.safety import reject_unsafe_target
from app.detectors.url_scanner.scanner import scan_url
from app.detectors.url_scanner.types import UrlScanResult
from app.detectors.url_scanner.utils import hostname
from app.database import get_engine
from app.scheme.malicious_url import MaliciousUrl
from app.scheme.notification import NotificationSubmission
from sqlalchemy import func
from sqlmodel import Session, select

DEFAULT_PHISHING_SOURCES = (
    REPO_ROOT / "phising-fetcher/data/processed/israel_elderly_urls_sources.jsonl",
    REPO_ROOT / "phising-fetcher/data/processed/quality_ranked_urls_sources.jsonl",
)
DEFAULT_ENV_FILES = (
    REPO_ROOT / ".env",
    REPO_ROOT / "llm/.env",
)
DEFAULT_MODULE_TIMEOUT_SECONDS = 30.0
PRIMARY_MODULES = ("llm", "url_scanner", "url_embedding")
AGGREGATOR_POLICIES = (
    "current_majority",
    "llm_only",
    "url_scanner_only",
    "url_embedding_only",
    "any_module_positive",
    "weighted_vote",
)


@dataclass(frozen=True)
class EvalCase:
    id: str
    label: str
    body: str
    package_name: str
    urls: list[str]
    source: str
    tags: list[str]
    notes: str = ""
    skip_live: bool = False

    @property
    def expected(self) -> bool:
        return self.label == "phishing"


def now_ms() -> float:
    return time.perf_counter() * 1000


def load_env_files() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:
        return
    for path in DEFAULT_ENV_FILES:
        if path.exists():
            load_dotenv(path, override=False)


def configure_logging(verbose: bool) -> None:
    level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s:%(name)s:%(message)s")
    if not verbose:
        logging.getLogger("app.detectors.url_scanner.browser").setLevel(logging.ERROR)


def module_timeout_seconds() -> float:
    raw_value = os.getenv("EVAL_MODULE_TIMEOUT_SECONDS", str(DEFAULT_MODULE_TIMEOUT_SECONDS))
    try:
        return max(1.0, float(raw_value))
    except ValueError:
        return DEFAULT_MODULE_TIMEOUT_SECONDS


def load_cases(path: Path) -> list[EvalCase]:
    cases: list[EvalCase] = []
    with path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            raw = json.loads(stripped)
            missing = {
                key
                for key in ("id", "label", "body", "packageName", "urls", "source", "tags")
                if key not in raw
            }
            if missing:
                raise ValueError(f"{path}:{line_number} missing required fields: {sorted(missing)}")
            if raw["label"] not in {"phishing", "benign"}:
                raise ValueError(f"{path}:{line_number} label must be phishing or benign")
            cases.append(
                EvalCase(
                    id=str(raw["id"]),
                    label=str(raw["label"]),
                    body=str(raw["body"]),
                    package_name=str(raw["packageName"]),
                    urls=list(raw["urls"]),
                    source=str(raw["source"]),
                    tags=list(raw["tags"]),
                    notes=str(raw.get("notes", "")),
                    skip_live=bool(raw.get("skip_live", False)),
                )
            )
    return cases


def load_phishing_seed_urls(paths: Iterable[Path]) -> set[str]:
    urls: set[str] = set()
    for path in paths:
        if not path.exists():
            continue
        with path.open(encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    raw = json.loads(stripped)
                except json.JSONDecodeError:
                    continue
                url = raw.get("url")
                if not url:
                    continue
                urls.add(url)
                canonical = canonicalize_url_for_lookup(url)
                if canonical:
                    urls.add(canonical)
    return urls


def submission_for(case: EvalCase) -> NotificationSubmission:
    return NotificationSubmission(
        eventId=case.id,
        sourceUserId="eval-user",
        circleId="eval-circle",
        title=None,
        body=case.body,
        packageName=case.package_name,
        timestamp=0,
        contentHash=f"eval-{case.id}",
        urls=case.urls,
    )


def base_result(case: EvalCase, module: str, latency_ms: float) -> dict[str, Any]:
    return {
        "case_id": case.id,
        "module": module,
        "label": case.label,
        "verdict": None,
        "confidence": None,
        "reasons": [],
        "latency_ms": round(latency_ms, 3),
        "error": None,
        "metadata": {
            "source": case.source,
            "tags": case.tags,
            "notes": case.notes,
        },
    }


def skipped_result(case: EvalCase, module: str, reason: str, latency_ms: float = 0.0) -> dict[str, Any]:
    row = base_result(case, module, latency_ms)
    row["error"] = reason
    row["metadata"]["skipped"] = True
    return row


def result_from_url_scan(
    case: EvalCase,
    module: str,
    scan_result: UrlScanResult,
    latency_ms: float,
) -> dict[str, Any]:
    row = base_result(case, module, latency_ms)
    row["verdict"] = bool(scan_result.suspicious)
    row["reasons"] = scan_result.reasons
    row["error"] = scan_result.error
    row["metadata"].update(
        {
            "raw_url": scan_result.raw_url,
            "normalized_url": scan_result.normalized_url,
            "final_url": scan_result.final_url,
            "hostname": scan_result.hostname,
            "final_hostname": scan_result.final_hostname,
            "redirect_chain": scan_result.redirect_chain,
            "used_browser": scan_result.used_browser,
        }
    )
    return row


async def run_llm(case: EvalCase, mode: str) -> list[dict[str, Any]]:
    if mode == "offline":
        return [skipped_result(case, "llm", "requires_live_llm")]
    if case.skip_live:
        return [skipped_result(case, "llm", "case_skip_live")]
    if not os.getenv("OPEN_ROUTER_KEY") or not os.getenv("LLM_MODEL"):
        return [skipped_result(case, "llm", "missing_OPEN_ROUTER_KEY_or_LLM_MODEL")]

    start = now_ms()
    row = base_result(case, "llm", 0.0)
    try:
        tasks = import_detector_tasks_safely()
        verdict = await tasks.run_llm_and_decide(submission_for(case))
        row["verdict"] = bool(verdict)
        row["metadata"]["direct_app_module"] = "app.detectors.tasks.run_llm_and_decide"
    except Exception as exc:
        row["error"] = type(exc).__name__
    row["latency_ms"] = round(now_ms() - start, 3)
    return [row]


async def run_url_scanner(case: EvalCase, mode: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    urls = case.urls or []
    if not urls:
        rows.append(no_url_result(case, "url_scanner.normalization"))
        rows.append(no_url_result(case, "url_scanner.static"))
        module_row = no_url_result(case, "url_scanner")
        if mode != "offline" and not case.skip_live:
            start = now_ms()
            try:
                tasks = import_detector_tasks_safely()
                module_row["verdict"] = bool(
                    await asyncio.wait_for(
                        tasks.module_dynamic_url_scanner(submission_for(case)),
                        timeout=module_timeout_seconds(),
                    )
                )
                module_row["metadata"]["direct_app_module"] = "app.detectors.tasks.module_dynamic_url_scanner"
            except TimeoutError:
                module_row["verdict"] = False
                module_row["reasons"] = ["eval_timeout"]
                module_row["error"] = "TimeoutError"
            except Exception as exc:
                module_row["error"] = type(exc).__name__
            module_row["latency_ms"] = round(now_ms() - start, 3)
        else:
            module_row["metadata"]["offline_static_breakdown_used"] = True
        rows.append(module_row)
        return rows

    final_reasons: list[str] = []
    final_latency_values: list[float] = []

    for raw_url in urls:
        start = now_ms()
        normalized = normalize_url(raw_url)
        latency = now_ms() - start
        normalization_row = base_result(case, "url_scanner.normalization", latency)
        normalization_row["verdict"] = bool(
            normalized.url is None or has_strong_static_signal(normalized.reasons)
        )
        normalization_row["reasons"] = normalized.reasons
        normalization_row["error"] = normalized.parse_error
        normalization_row["metadata"].update(
            {
                "raw_url": raw_url,
                "normalized_url": normalized.url,
                "hostname": normalized.hostname,
                "display_hostname": normalized.display_hostname,
            }
        )
        rows.append(normalization_row)

        static_row = base_result(case, "url_scanner.static", 0.0)
        static_row["verdict"] = bool(has_strong_static_signal(normalized.reasons))
        static_row["reasons"] = normalized.reasons
        static_row["error"] = normalized.parse_error
        static_row["metadata"].update(
            {
                "raw_url": raw_url,
                "normalized_url": normalized.url,
                "hostname": normalized.hostname,
            }
        )
        rows.append(static_row)

        if normalized.url and mode != "offline" and not case.skip_live:
            rows.append(await run_url_safety(case, normalized.url))
            rows.append(await run_http_redirect(case, normalized.url))
            if os.getenv("DYNAMIC_URL_SCANNER_ENABLE_BROWSER", "").strip().lower() == "true":
                rows.append(await run_browser(case, normalized.url))
            else:
                rows.append(skipped_result(case, "url_scanner.browser", "browser_disabled"))
        elif normalized.url:
            host = hostname(normalized.url)
            direct_private_reason = unsafe_ip_reason(host) if host else None
            if direct_private_reason:
                safety_row = base_result(case, "url_scanner.safety", 0.0)
                safety_row["verdict"] = True
                safety_row["reasons"] = [direct_private_reason]
                safety_row["error"] = direct_private_reason
                safety_row["metadata"].update({"raw_url": raw_url, "normalized_url": normalized.url})
                rows.append(safety_row)
            else:
                rows.append(skipped_result(case, "url_scanner.safety", "requires_live_dns"))
            rows.append(skipped_result(case, "url_scanner.http_redirect", "requires_live_network"))
            rows.append(skipped_result(case, "url_scanner.browser", "requires_live_browser"))
        else:
            rows.append(skipped_result(case, "url_scanner.safety", "normalization_failed"))
            rows.append(skipped_result(case, "url_scanner.http_redirect", "normalization_failed"))
            rows.append(skipped_result(case, "url_scanner.browser", "normalization_failed"))

        breakdown_start = now_ms()
        if mode == "offline" or case.skip_live:
            scan_result = UrlScanResult(
                suspicious=bool(normalized.url is None or has_strong_static_signal(normalized.reasons)),
                reasons=normalized.reasons or (["parse_failure"] if normalized.url is None else []),
                raw_url=raw_url,
                normalized_url=normalized.url,
                final_url=normalized.url,
                error=normalized.parse_error,
            )
        else:
            try:
                scan_result = await asyncio.wait_for(scan_url(raw_url), timeout=module_timeout_seconds())
            except TimeoutError:
                scan_result = UrlScanResult(
                    suspicious=False,
                    reasons=["eval_timeout"],
                    raw_url=raw_url,
                    error="TimeoutError",
                )
            except Exception as exc:
                scan_result = UrlScanResult(
                    suspicious=False,
                    reasons=[],
                    raw_url=raw_url,
                    error=type(exc).__name__,
                )
        breakdown_latency = now_ms() - breakdown_start
        final_latency_values.append(breakdown_latency)
        final_reasons.extend(scan_result.reasons)
        rows.append(result_from_url_scan(case, "url_scanner.scan_url", scan_result, breakdown_latency))

    module_start = now_ms()
    module_row = base_result(case, "url_scanner", 0.0)
    try:
        if mode == "offline" or case.skip_live:
            module_row["verdict"] = any(
                row["module"] == "url_scanner.scan_url" and row["verdict"] is True
                for row in rows
            )
            module_row["metadata"]["offline_static_breakdown_used"] = True
        else:
            tasks = import_detector_tasks_safely()
            module_row["verdict"] = bool(
                await asyncio.wait_for(
                    tasks.module_dynamic_url_scanner(submission_for(case)),
                    timeout=module_timeout_seconds(),
                )
            )
            module_row["metadata"]["direct_app_module"] = "app.detectors.tasks.module_dynamic_url_scanner"
    except TimeoutError:
        module_row["verdict"] = False
        module_row["reasons"] = ["eval_timeout"]
        module_row["error"] = "TimeoutError"
    except Exception as exc:
        module_row["error"] = type(exc).__name__
    module_row["latency_ms"] = round(now_ms() - module_start, 3)
    module_row["reasons"] = sorted(set(final_reasons))
    module_row["metadata"]["url_count"] = len(urls)
    rows.append(module_row)
    return rows


def no_url_result(case: EvalCase, module: str) -> dict[str, Any]:
    row = base_result(case, module, 0.0)
    row["verdict"] = False
    row["metadata"]["url_count"] = 0
    return row


async def run_url_safety(case: EvalCase, url: str) -> dict[str, Any]:
    start = now_ms()
    row = base_result(case, "url_scanner.safety", 0.0)
    try:
        reason = await reject_unsafe_target(url)
        row["verdict"] = bool(reason)
        if reason == "url_resolution_failure":
            row["verdict"] = False
        row["reasons"] = [reason] if reason else []
        row["error"] = reason
    except Exception as exc:
        row["error"] = type(exc).__name__
    row["latency_ms"] = round(now_ms() - start, 3)
    row["metadata"]["normalized_url"] = url
    return row


async def run_http_redirect(case: EvalCase, url: str) -> dict[str, Any]:
    start = now_ms()
    try:
        scan_result = await asyncio.wait_for(expand_http_redirects(url), timeout=module_timeout_seconds())
        return result_from_url_scan(case, "url_scanner.http_redirect", scan_result, now_ms() - start)
    except TimeoutError:
        row = base_result(case, "url_scanner.http_redirect", now_ms() - start)
        row["verdict"] = False
        row["reasons"] = ["eval_timeout"]
        row["error"] = "TimeoutError"
        row["metadata"]["normalized_url"] = url
        return row
    except Exception as exc:
        row = base_result(case, "url_scanner.http_redirect", now_ms() - start)
        row["error"] = type(exc).__name__
        row["metadata"]["normalized_url"] = url
        return row


async def run_browser(case: EvalCase, url: str) -> dict[str, Any]:
    start = now_ms()
    try:
        from app.detectors.url_scanner.browser import expand_with_browser

        scan_result = await asyncio.wait_for(expand_with_browser(url), timeout=module_timeout_seconds())
        return result_from_url_scan(case, "url_scanner.browser", scan_result, now_ms() - start)
    except TimeoutError:
        row = base_result(case, "url_scanner.browser", now_ms() - start)
        row["verdict"] = False
        row["reasons"] = ["eval_timeout"]
        row["error"] = "TimeoutError"
        row["metadata"]["normalized_url"] = url
        return row
    except Exception as exc:
        row = base_result(case, "url_scanner.browser", now_ms() - start)
        row["error"] = type(exc).__name__
        row["metadata"]["normalized_url"] = url
        return row


async def run_url_embedding(case: EvalCase, mode: str, seed_urls: set[str]) -> list[dict[str, Any]]:
    if not case.urls:
        start = now_ms()
        row = base_result(case, "url_embedding", 0.0)
        try:
            tasks = import_detector_tasks_safely()
            row["verdict"] = bool(await tasks.module_url_embedding(submission_for(case)))
            row["metadata"]["direct_app_module"] = "app.detectors.tasks.module_url_embedding"
        except Exception as exc:
            row["error"] = type(exc).__name__
        row["latency_ms"] = round(now_ms() - start, 3)
        row["metadata"]["url_count"] = 0
        return [row]

    if mode == "offline" or case.skip_live:
        return [skipped_result(case, "url_embedding", "requires_live_database_and_embedding_model")]

    start = now_ms()
    row = base_result(case, "url_embedding", 0.0)
    try:
        tasks = import_detector_tasks_safely()
        verdict = await tasks.module_url_embedding(submission_for(case))
        row["verdict"] = bool(verdict)
        row["metadata"]["direct_app_module"] = "app.detectors.tasks.module_url_embedding"
        row["metadata"]["embedding_checks"] = await collect_embedding_checks(case.urls, tasks)
        distances = [
            check["distance"]
            for check in row["metadata"]["embedding_checks"]
            if check.get("distance") is not None
        ]
        if distances:
            best = min(
                row["metadata"]["embedding_checks"],
                key=lambda check: check["distance"]
                if check.get("distance") is not None
                else float("inf"),
            )
            row["metadata"]["distance"] = best.get("distance")
            row["metadata"]["matched_url"] = best.get("matched_url")
            row["metadata"]["checked_url"] = best.get("checked_url")
        exact_matches = [
            check for check in row["metadata"]["embedding_checks"] if check.get("exact_match")
        ]
        if exact_matches:
            row["metadata"]["exact_match"] = True
            row["metadata"]["matched_url"] = exact_matches[0].get("matched_url")
            row["metadata"]["checked_url"] = exact_matches[0].get("checked_url")
    except Exception as exc:
        row["error"] = type(exc).__name__
    row["latency_ms"] = round(now_ms() - start, 3)
    row["metadata"]["mode"] = "live_module_url_embedding"
    return [row]


async def collect_embedding_checks(urls: list[str], tasks: Any) -> list[dict[str, Any]]:
    checks: list[dict[str, Any]] = []
    with Session(get_engine()) as session:
        db_count = session.exec(select(func.count(MaliciousUrl.id))).one()
        for raw_url in urls:
            checked_url = tasks.url_for_embedding(raw_url)
            exact_match = tasks.get_existing_malicious_url(session, raw_url)
            check: dict[str, Any] = {
                "raw_url": raw_url,
                "checked_url": checked_url,
                "db_count": db_count,
                "exact_match": bool(exact_match),
                "matched_url": exact_match.url if exact_match else None,
                "distance": 0.0 if exact_match else None,
            }
            checks.append(check)

    for check in checks:
        if check["exact_match"] or check["db_count"] == 0:
            continue
        embedding = await tasks.get_url_embedding_async(check["checked_url"])
        nearest = await asyncio.to_thread(get_nearest_embedding_match, embedding)
        if nearest:
            check["distance"] = round(float(nearest["distance"]), 6)
            check["matched_url"] = nearest["url"]
    return checks


def get_nearest_embedding_match(embedding: list[float]) -> dict[str, Any] | None:
    distance_expr = MaliciousUrl.embedding.cosine_distance(embedding).label("distance")
    statement = (
        select(MaliciousUrl.url, distance_expr)
        .order_by(distance_expr)
        .limit(1)
    )
    with Session(get_engine()) as session:
        row = session.exec(statement).first()
    if not row:
        return None
    url, distance = row
    return {"url": url, "distance": distance}


def import_detector_tasks_safely():
    """Import app.detectors.tasks without initializing Firebase or sending alerts."""
    import fcm.firebase as firebase

    firebase.initialize_firebase = lambda: None
    firebase.send_fcm_message = lambda *args, **kwargs: {"eval_mocked": True}

    import app.detectors.tasks as tasks

    tasks.initialize_firebase = lambda: None
    tasks.send_fcm_message = lambda *args, **kwargs: {"eval_mocked": True}
    tasks.mark_event_alerted = lambda event_id: True
    return tasks


async def run_aggregator(case: EvalCase, mode: str, seed_urls: set[str]) -> list[dict[str, Any]]:
    vote_rows: list[dict[str, Any]] = []
    for module in PRIMARY_MODULES:
        vote_rows.extend(await run_module(case, module, mode, seed_urls))

    votes = {
        "llm": verdict_for_module(vote_rows, "llm"),
        "url_scanner": verdict_for_module(vote_rows, "url_scanner"),
        "url_embedding": verdict_for_module(vote_rows, "url_embedding"),
    }
    policies = {
        "current_majority": sum(1 for value in votes.values() if value) >= 2,
        "llm_only": votes["llm"],
        "url_scanner_only": votes["url_scanner"],
        "url_embedding_only": votes["url_embedding"],
        "any_module_positive": any(votes.values()),
        "weighted_vote": (
            (0.45 if votes["llm"] else 0.0)
            + (0.35 if votes["url_scanner"] else 0.0)
            + (0.20 if votes["url_embedding"] else 0.0)
        )
        >= 0.5,
    }
    skipped_modules = sorted(
        {
            row["module"]
            for row in vote_rows
            if row.get("metadata", {}).get("skipped") and row["module"] in PRIMARY_MODULES
        }
    )

    rows = []
    for policy, verdict in policies.items():
        row = base_result(case, f"aggregator.{policy}", 0.0)
        row["verdict"] = bool(verdict)
        row["reasons"] = [name for name, vote in votes.items() if vote]
        row["metadata"].update(
            {
                "votes": votes,
                "vote_count": sum(1 for value in votes.values() if value),
                "skipped_modules": skipped_modules,
                "side_effects_mocked": True,
            }
        )
        rows.append(row)
    return rows


def verdict_for_module(rows: list[dict[str, Any]], module: str) -> bool:
    for row in rows:
        if row["module"] == module and row["verdict"] is not None:
            return bool(row["verdict"])
    return False


async def run_module(
    case: EvalCase,
    module: str,
    mode: str,
    seed_urls: set[str],
) -> list[dict[str, Any]]:
    if module == "llm":
        return await run_llm(case, mode)
    if module == "url_scanner":
        return await run_url_scanner(case, mode)
    if module == "url_embedding":
        return await run_url_embedding(case, mode, seed_urls)
    if module == "aggregator":
        return await run_aggregator(case, mode, seed_urls)
    raise ValueError(f"unknown module: {module}")


def parse_modules(value: str) -> list[str]:
    modules = [part.strip() for part in value.split(",") if part.strip()]
    allowed = set(PRIMARY_MODULES) | {"aggregator"}
    unknown = sorted(set(modules) - allowed)
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown modules: {', '.join(unknown)}")
    return modules


async def run(args: argparse.Namespace) -> None:
    cases = load_cases(args.cases)
    random.Random(args.seed).shuffle(cases)
    if args.live_limit is not None and args.mode in {"live", "hybrid"}:
        live_cases = [case for case in cases if not case.skip_live]
        limited = set(case.id for case in live_cases[: args.live_limit])
        cases = [case for case in cases if args.mode == "offline" or case.id in limited or case.skip_live]

    seed_urls = load_phishing_seed_urls(args.phishing_sources)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    total_work = len(cases) * len(args.modules)
    completed_work = 0

    print(
        f"Eval start: cases={len(cases)} modules={','.join(args.modules)} "
        f"mode={args.mode} out={args.out}",
        flush=True,
    )

    with args.out.open("w", encoding="utf-8") as output:
        for index, case in enumerate(cases, start=1):
            for module in args.modules:
                completed_work += 1
                print(
                    f"[{completed_work}/{total_work}] module={module} "
                    f"case={case.id} label={case.label} urls={len(case.urls)}",
                    flush=True,
                )
                try:
                    rows = await run_module(case, module, args.mode, seed_urls)
                except Exception as exc:
                    rows = [skipped_result(case, module, type(exc).__name__)]
                    if args.fail_fast:
                        raise
                for row in rows:
                    row["metadata"]["mode"] = row["metadata"].get("mode", args.mode)
                    row["metadata"]["case_index"] = index
                    output.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=REPO_ROOT / "eval/detection_cases.jsonl")
    parser.add_argument("--mode", choices=("offline", "live", "hybrid"), default="offline")
    parser.add_argument("--modules", type=parse_modules, default=list(PRIMARY_MODULES))
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "eval/results/module_eval.jsonl")
    parser.add_argument("--live-limit", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--verbose", action="store_true", help="Show detector warning logs and tracebacks.")
    parser.add_argument(
        "--phishing-sources",
        type=Path,
        nargs="*",
        default=list(DEFAULT_PHISHING_SOURCES),
        help="JSONL files containing phishing seed URLs for offline exact-match embedding evaluation.",
    )
    return parser


def main() -> None:
    load_env_files()
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
