import re
from urllib.parse import urljoin

import httpx

from app.detectors.url_scanner.browser import expand_with_browser
from app.detectors.url_scanner.config import (
    HTTP_TIMEOUT_SECONDS,
    MAX_BODY_BYTES,
    MAX_REDIRECTS,
    USER_AGENT,
    browser_enabled,
)
from app.detectors.url_scanner.heuristics import is_shortener
from app.detectors.url_scanner.normalization import canonicalize_url_for_lookup
from app.detectors.url_scanner.safety import reject_unsafe_target
from app.detectors.url_scanner.types import UrlScanResult
from app.detectors.url_scanner.utils import hostname, unique


async def expand_http_redirects(start_url: str) -> UrlScanResult:
    current_url = start_url
    redirect_chain: list[str] = [start_url]
    visited: set[str] = set()

    async with httpx.AsyncClient(
        follow_redirects=False,
        timeout=httpx.Timeout(HTTP_TIMEOUT_SECONDS),
        headers={"User-Agent": USER_AGENT},
    ) as client:
        for _ in range(MAX_REDIRECTS + 1):
            if current_url in visited:
                return UrlScanResult(
                    suspicious=True,
                    reasons=["redirect_loop"],
                    raw_url=start_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    error="redirect_loop",
                )
            visited.add(current_url)

            safety_error = await reject_unsafe_target(current_url)
            if safety_error:
                return UrlScanResult(
                    suspicious=True,
                    reasons=[safety_error],
                    raw_url=start_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    error=safety_error,
                )

            try:
                response = await client.request("HEAD", current_url)
                if response.status_code in {403, 405, 501}:
                    response = await get_small_response(client, current_url)
            except httpx.HTTPError as exc:
                return UrlScanResult(
                    suspicious=True,
                    reasons=["url_resolution_failure"],
                    raw_url=start_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    error=type(exc).__name__,
                )

            if response.status_code in {401, 403, 407, 429, 503}:
                return UrlScanResult(
                    suspicious=False,
                    reasons=["http_blocked"],
                    raw_url=start_url,
                    final_url=current_url,
                    redirect_chain=redirect_chain,
                    error=f"http_status={response.status_code}",
                )

            location = response.headers.get("location")
            if 300 <= response.status_code < 400 and location:
                next_url = canonicalize_url_for_lookup(urljoin(current_url, location))
                if not next_url:
                    return UrlScanResult(
                        suspicious=True,
                        reasons=["parse_failure"],
                        raw_url=start_url,
                        final_url=current_url,
                        redirect_chain=redirect_chain,
                        error="invalid_redirect_location",
                    )
                redirect_chain.append(next_url)
                current_url = next_url
                continue

            html_probe = await probe_html_redirect(client, current_url, response)
            if html_probe and browser_enabled():
                browser_result = await expand_with_browser(current_url)
                browser_result.raw_url = start_url
                browser_result.redirect_chain = unique(
                    redirect_chain + browser_result.redirect_chain
                )
                browser_result.reasons = unique([html_probe] + browser_result.reasons)
                return browser_result

            return UrlScanResult(
                suspicious=False,
                reasons=[],
                raw_url=start_url,
                final_url=current_url,
                redirect_chain=redirect_chain,
            )

    return UrlScanResult(
        suspicious=True,
        reasons=["redirect_limit_exceeded"],
        raw_url=start_url,
        final_url=current_url,
        redirect_chain=redirect_chain,
        error="redirect_limit_exceeded",
    )


async def get_small_response(client: httpx.AsyncClient, url: str) -> httpx.Response:
    async with client.stream("GET", url, headers={"Range": f"bytes=0-{MAX_BODY_BYTES - 1}"}) as response:
        body = b""
        async for chunk in response.aiter_bytes():
            body += chunk
            if len(body) >= MAX_BODY_BYTES:
                break
        return httpx.Response(
            response.status_code,
            headers=response.headers,
            content=body[:MAX_BODY_BYTES],
            request=response.request,
        )


async def probe_html_redirect(
    client: httpx.AsyncClient,
    url: str,
    response: httpx.Response,
) -> str | None:
    host = hostname(url)
    content_type = response.headers.get("content-type", "").lower()
    should_probe = is_shortener(host) or "text/html" in content_type
    if not should_probe:
        return None

    try:
        small_response = response if response.content else await get_small_response(client, url)
    except (httpx.HTTPError, httpx.ResponseNotRead):
        return "html_redirect_suspected"

    text = small_response.text[:MAX_BODY_BYTES].lower()
    if re.search(r"<meta[^>]+http-equiv=[\"']?refresh[^>]+url\s*=", text):
        return "html_redirect_suspected"
    if re.search(
        r"^\s*(?:window\.)?location(?:\.href)?\s*=\s*[\"']https?://|^\s*(?:window\.)?location\.replace\s*\(\s*[\"']https?://",
        text,
        re.MULTILINE,
    ):
        return "javascript_redirect_suspected"
    return None
