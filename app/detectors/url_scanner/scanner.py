from collections.abc import Iterable

from app.detectors.url_scanner.browser import expand_with_browser
from app.detectors.url_scanner.config import browser_enabled
from app.detectors.url_scanner.heuristics import has_strong_static_signal, is_shortener
from app.detectors.url_scanner.http_redirects import expand_http_redirects
from app.detectors.url_scanner.normalization import normalize_url
from app.detectors.url_scanner.types import UrlScanResult
from app.detectors.url_scanner.utils import hostname, unique


async def scan_urls(urls: Iterable[str]) -> list[UrlScanResult]:
    results: list[UrlScanResult] = []
    for raw_url in urls:
        result = await scan_url(raw_url)
        results.append(result)
        if result.suspicious:
            break
    return results


async def scan_url(raw_url: str) -> UrlScanResult:
    normalized = normalize_url(raw_url)
    if normalized.url is None:
        return UrlScanResult(
            suspicious=True,
            reasons=normalized.reasons or ["parse_failure"],
            raw_url=raw_url,
            error=normalized.parse_error,
        )

    reasons = list(normalized.reasons)
    if has_strong_static_signal(reasons):
        return UrlScanResult(
            suspicious=True,
            reasons=reasons,
            raw_url=raw_url,
            normalized_url=normalized.url,
            final_url=normalized.url,
        )

    redirect_result = await expand_http_redirects(normalized.url)
    redirect_result.raw_url = raw_url
    redirect_result.normalized_url = normalized.url
    redirect_result.reasons = unique(reasons + redirect_result.reasons)

    if redirect_result.suspicious:
        return redirect_result

    final_normalized = normalize_url(redirect_result.final_url or normalized.url)
    final_reasons = final_normalized.reasons
    if final_reasons:
        redirect_result.reasons = unique(redirect_result.reasons + final_reasons)
        if has_strong_static_signal(final_reasons):
            redirect_result.suspicious = True
            return redirect_result

    if should_use_browser(redirect_result):
        browser_result = await expand_with_browser(redirect_result.final_url or normalized.url)
        browser_result.raw_url = raw_url
        browser_result.normalized_url = normalized.url
        browser_result.redirect_chain = unique(
            redirect_result.redirect_chain + browser_result.redirect_chain
        )
        browser_result.reasons = unique(redirect_result.reasons + browser_result.reasons)
        return browser_result

    return redirect_result


def should_use_browser(result: UrlScanResult) -> bool:
    if result.used_browser:
        return False
    if not browser_enabled():
        return False
    host = hostname(result.final_url or result.normalized_url)
    return bool(host and is_shortener(host))
