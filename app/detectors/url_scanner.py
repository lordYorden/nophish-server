import asyncio
import ipaddress
import logging
import os
import re
import socket
import unicodedata
from dataclasses import dataclass, field
from typing import Iterable
from urllib.parse import quote, unquote, urljoin, urlsplit, urlunsplit

import httpx
import idna

logger = logging.getLogger(__name__)

HTTP_TIMEOUT_SECONDS = 2.0
BROWSER_TIMEOUT_MS = 5_000
MAX_REDIRECTS = 5
MAX_SUBDOMAINS = 4
MAX_BODY_BYTES = 4096
USER_AGENT = "NoPhish dynamic URL scanner/0.1"

ZERO_WIDTH_OR_INVISIBLE = {
    "\u200b",  # zero width space
    "\u200c",  # zero width non-joiner
    "\u200d",  # zero width joiner
    "\u2060",  # word joiner
    "\ufeff",  # zero width no-break space
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "buff.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "lnkd.in",
    "ow.ly",
    "rebrand.ly",
    "s.id",
    "shorturl.at",
    "snip.ly",
    "t.co",
    "tiny.cc",
    "tinyurl.com",
    "t.ly",
    "tbit.be",
    "trib.al",
}

BRAND_DOMAINS = {
    "paypal": ("paypal.com",),
    "google": ("google.com", "google.co.il"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "office365.com"),
    "apple": ("apple.com",),
    "amazon": ("amazon.com",),
    "facebook": ("facebook.com", "fb.com"),
    "instagram": ("instagram.com",),
    "whatsapp": ("whatsapp.com",),
    "netflix": ("netflix.com",),
    "leumi": ("leumi.co.il",),
    "hapoalim": ("bankhapoalim.co.il",),
    "mizrahi": ("mizrahi-tefahot.co.il",),
    "discount": ("discountbank.co.il",),
    "isracard": ("isracard.co.il",),
    "max": ("max.co.il",),
    "cal": ("cal-online.co.il",),
    "israelpost": ("israelpost.co.il",),
    "gov": ("gov.il",),
}

CONFUSABLE_CODEPOINTS = {
    # Common Cyrillic/Greek characters that visually overlap Latin characters.
    "\u0430",  # Cyrillic small a
    "\u0435",  # Cyrillic small ie
    "\u043e",  # Cyrillic small o
    "\u0440",  # Cyrillic small er
    "\u0441",  # Cyrillic small es
    "\u0445",  # Cyrillic small ha
    "\u0443",  # Cyrillic small u
    "\u0456",  # Cyrillic small byelorussian-ukrainian i
    "\u03bf",  # Greek small omicron
    "\u03c1",  # Greek small rho
    "\u03bd",  # Greek small nu
}


@dataclass
class UrlScanResult:
    suspicious: bool
    reasons: list[str]
    raw_url: str
    normalized_url: str | None = None
    final_url: str | None = None
    redirect_chain: list[str] = field(default_factory=list)
    used_browser: bool = False
    error: str | None = None

    @property
    def hostname(self) -> str | None:
        return _hostname(self.normalized_url)

    @property
    def final_hostname(self) -> str | None:
        return _hostname(self.final_url)


@dataclass
class _NormalizedUrl:
    url: str | None
    hostname: str | None
    display_hostname: str | None
    reasons: list[str]
    parse_error: str | None = None


def canonicalize_url_for_lookup(raw_url: str) -> str | None:
    """Return the scanner's canonical URL form, or None if it cannot parse safely."""
    normalized = _normalize_url(raw_url)
    return normalized.url


async def scan_urls(urls: Iterable[str]) -> list[UrlScanResult]:
    results: list[UrlScanResult] = []
    for raw_url in urls:
        result = await scan_url(raw_url)
        results.append(result)
        if result.suspicious:
            break
    return results


async def scan_url(raw_url: str) -> UrlScanResult:
    normalized = _normalize_url(raw_url)
    if normalized.url is None:
        return UrlScanResult(
            suspicious=True,
            reasons=normalized.reasons or ["parse_failure"],
            raw_url=raw_url,
            error=normalized.parse_error,
        )

    reasons = list(normalized.reasons)
    if _has_strong_static_signal(reasons):
        return UrlScanResult(
            suspicious=True,
            reasons=reasons,
            raw_url=raw_url,
            normalized_url=normalized.url,
            final_url=normalized.url,
        )

    redirect_result = await _expand_http_redirects(normalized.url)
    redirect_result.raw_url = raw_url
    redirect_result.normalized_url = normalized.url
    redirect_result.reasons = _unique(reasons + redirect_result.reasons)

    if redirect_result.suspicious:
        return redirect_result

    final_normalized = _normalize_url(redirect_result.final_url or normalized.url)
    final_reasons = final_normalized.reasons
    if final_reasons:
        redirect_result.reasons = _unique(redirect_result.reasons + final_reasons)
        if _has_strong_static_signal(final_reasons):
            redirect_result.suspicious = True
            return redirect_result

    if _should_use_browser(redirect_result):
        browser_result = await _expand_with_browser(redirect_result.final_url or normalized.url)
        browser_result.raw_url = raw_url
        browser_result.normalized_url = normalized.url
        browser_result.redirect_chain = _unique(
            redirect_result.redirect_chain + browser_result.redirect_chain
        )
        browser_result.reasons = _unique(redirect_result.reasons + browser_result.reasons)
        return browser_result

    return redirect_result


def _normalize_url(raw_url: str) -> _NormalizedUrl:
    reasons: list[str] = []
    value = raw_url.strip()
    if not value:
        return _NormalizedUrl(None, None, None, ["parse_failure"], "empty_url")

    if any(ch in value for ch in ZERO_WIDTH_OR_INVISIBLE) or any(
        unicodedata.category(ch) == "Cf" for ch in value
    ):
        reasons.append("zero_width_character")
        value = "".join(ch for ch in value if ch not in ZERO_WIDTH_OR_INVISIBLE and unicodedata.category(ch) != "Cf")

    value = unicodedata.normalize("NFKC", value)
    split = urlsplit(value)
    if not split.scheme and not split.netloc and _looks_like_schemeless_url(split.path):
        value = f"https://{value}"
        split = urlsplit(value)

    if split.scheme.lower() not in {"http", "https"}:
        return _NormalizedUrl(None, None, None, ["non_http_scheme"], f"scheme={split.scheme or 'missing'}")

    if not split.hostname:
        return _NormalizedUrl(None, None, None, ["parse_failure"], "missing_hostname")

    try:
        display_host = unicodedata.normalize("NFKC", split.hostname.rstrip(".").lower())
        ascii_host = idna.encode(display_host, uts46=True).decode("ascii").lower()
        decoded_host = idna.decode(ascii_host, uts46=True).lower()
    except idna.IDNAError as exc:
        return _NormalizedUrl(None, None, None, ["parse_failure"], type(exc).__name__)

    if ascii_host.startswith("xn--") or ".xn--" in ascii_host:
        reasons.append("punycode_hostname")
    if _has_confusable_hostname(decoded_host):
        reasons.append("unicode_confusable_hostname")
    if _has_mixed_scripts(decoded_host):
        reasons.append("mixed_script_hostname")
    if _is_ip_host(ascii_host):
        reasons.append("ip_address_host")
    if _has_excessive_subdomains(ascii_host):
        reasons.append("excessive_subdomains")
    if _has_brand_token_in_wrong_domain(ascii_host):
        reasons.append("brand_token_in_wrong_domain")

    try:
        netloc = ascii_host
        if split.port and not _is_default_port(split.scheme.lower(), split.port):
            netloc = f"{netloc}:{split.port}"
    except ValueError as exc:
        return _NormalizedUrl(None, None, None, ["parse_failure"], type(exc).__name__)

    path = quote(unquote(split.path or "/"), safe="/:@!$&'()*+,;=-._~%")
    query = quote(unquote(split.query), safe="=&?/:@!$'()*+,;%-._~")
    normalized_url = urlunsplit((split.scheme.lower(), netloc, path, query, ""))
    return _NormalizedUrl(normalized_url, ascii_host, decoded_host, _unique(reasons))


async def _expand_http_redirects(start_url: str) -> UrlScanResult:
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

            safety_error = await _reject_unsafe_target(current_url)
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
                    response = await _get_small_response(client, current_url)
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

            html_probe = await _probe_html_redirect(client, current_url, response)
            if html_probe and _browser_enabled():
                browser_result = await _expand_with_browser(current_url)
                browser_result.raw_url = start_url
                browser_result.redirect_chain = _unique(
                    redirect_chain + browser_result.redirect_chain
                )
                browser_result.reasons = _unique([html_probe] + browser_result.reasons)
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


async def _get_small_response(client: httpx.AsyncClient, url: str) -> httpx.Response:
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


async def _probe_html_redirect(
    client: httpx.AsyncClient,
    url: str,
    response: httpx.Response,
) -> str | None:
    host = _hostname(url)
    content_type = response.headers.get("content-type", "").lower()
    should_probe = _is_shortener(host) or "text/html" in content_type
    if not should_probe:
        return None

    try:
        small_response = response if response.content else await _get_small_response(client, url)
    except (httpx.HTTPError, httpx.ResponseNotRead):
        return "html_redirect_suspected"

    text = small_response.text[:MAX_BODY_BYTES].lower()
    if re.search(r"<meta[^>]+http-equiv=[\"']?refresh[^>]+url\s*=", text):
        return "html_redirect_suspected"
    if re.search(
        r"^\s*(?:window\.)?location(?:\.href|\.replace)?\s*=\s*[\"']https?://",
        text,
        re.MULTILINE,
    ):
        return "javascript_redirect_suspected"
    return None


async def _expand_with_browser(url: str) -> UrlScanResult:
    if not _browser_enabled():
        return UrlScanResult(
            suspicious=True,
            reasons=["browser_fallback_disabled"],
            raw_url=url,
            final_url=url,
            error="browser_fallback_disabled",
        )

    try:
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError
        from playwright.async_api import async_playwright
    except ImportError as exc:
        return UrlScanResult(
            suspicious=True,
            reasons=["browser_unavailable"],
            raw_url=url,
            final_url=url,
            used_browser=True,
            error=type(exc).__name__,
        )

    redirect_chain = [url]
    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(headless=True)
            context = await browser.new_context(
                permissions=[],
                user_agent=USER_AGENT,
            )
            page = await context.new_page()
            page.set_default_timeout(BROWSER_TIMEOUT_MS)
            page.set_default_navigation_timeout(BROWSER_TIMEOUT_MS)

            async def route_handler(route):
                request = route.request
                resource_type = request.resource_type
                if resource_type in {"font", "image", "media"}:
                    await route.abort()
                    return
                target_error = await _reject_unsafe_target(request.url)
                if target_error:
                    await route.abort()
                    return
                await route.continue_()

            await page.route("**/*", route_handler)
            page.on("framenavigated", lambda frame: redirect_chain.append(frame.url) if frame == page.main_frame else None)
            await page.goto(url, wait_until="domcontentloaded")
            final_url = canonicalize_url_for_lookup(page.url) or page.url
            await context.close()
            await browser.close()
    except PlaywrightTimeoutError as exc:
        return UrlScanResult(
            suspicious=True,
            reasons=["browser_timeout"],
            raw_url=url,
            final_url=url,
            redirect_chain=redirect_chain,
            used_browser=True,
            error=type(exc).__name__,
        )
    except Exception as exc:
        logger.warning("Browser expansion failed for %s: %s", url, exc, exc_info=True)
        return UrlScanResult(
            suspicious=True,
            reasons=["browser_failure"],
            raw_url=url,
            final_url=url,
            redirect_chain=redirect_chain,
            used_browser=True,
            error=type(exc).__name__,
        )

    final_normalized = _normalize_url(final_url)
    reasons = final_normalized.reasons
    return UrlScanResult(
        suspicious=_has_strong_static_signal(reasons),
        reasons=reasons,
        raw_url=url,
        final_url=final_normalized.url or final_url,
        redirect_chain=_unique(redirect_chain),
        used_browser=True,
    )


async def _reject_unsafe_target(url: str) -> str | None:
    normalized = _normalize_url(url)
    if normalized.url is None or not normalized.hostname:
        return "parse_failure"

    host = normalized.hostname
    if _unsafe_ip_reason(host):
        return "private_ip_host"

    try:
        addrinfos = await asyncio.to_thread(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
    except OSError:
        return "url_resolution_failure"

    for addrinfo in addrinfos:
        ip = addrinfo[4][0]
        if _unsafe_ip_reason(ip):
            return "private_ip_host"
    return None


def _unsafe_ip_reason(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return None if ip.is_global else "private_ip_host"


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _has_strong_static_signal(reasons: list[str]) -> bool:
    strong_reasons = {
        "zero_width_character",
        "unicode_confusable_hostname",
        "punycode_hostname",
        "mixed_script_hostname",
        "non_http_scheme",
        "parse_failure",
        "ip_address_host",
        "excessive_subdomains",
        "brand_token_in_wrong_domain",
    }
    return any(reason in strong_reasons for reason in reasons)


def _should_use_browser(result: UrlScanResult) -> bool:
    if not _browser_enabled():
        return False
    host = _hostname(result.final_url or result.normalized_url)
    return bool(host and _is_shortener(host))


def _browser_enabled() -> bool:
    return os.getenv("DYNAMIC_URL_SCANNER_ENABLE_BROWSER", "").lower() in {"1", "true", "yes"}


def _looks_like_schemeless_url(value: str) -> bool:
    first = value.split("/", 1)[0]
    return "." in first and not first.startswith(".")


def _is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "http" and port == 80) or (scheme == "https" and port == 443)


def _has_excessive_subdomains(host: str) -> bool:
    labels = [label for label in host.split(".") if label]
    return max(len(labels) - 2, 0) > MAX_SUBDOMAINS


def _has_brand_token_in_wrong_domain(host: str) -> bool:
    labels = re.split(r"[^a-z0-9]+", host.lower())
    label_text = "-".join(labels)
    for brand, legitimate_suffixes in BRAND_DOMAINS.items():
        if brand not in label_text:
            continue
        if any(host == suffix or host.endswith(f".{suffix}") for suffix in legitimate_suffixes):
            return False
        return True
    return False


def _has_confusable_hostname(host: str) -> bool:
    return any(ch in CONFUSABLE_CODEPOINTS for ch in host)


def _has_mixed_scripts(host: str) -> bool:
    scripts = {_script_for(ch) for ch in host if ch.isalpha()}
    scripts.discard("common")
    return len(scripts) > 1


def _script_for(ch: str) -> str:
    try:
        name = unicodedata.name(ch)
    except ValueError:
        return "common"
    if "LATIN" in name:
        return "latin"
    if "CYRILLIC" in name:
        return "cyrillic"
    if "GREEK" in name:
        return "greek"
    if "HEBREW" in name:
        return "hebrew"
    if "ARABIC" in name:
        return "arabic"
    if "DIGIT" in name or "FULL STOP" in name or "HYPHEN" in name:
        return "common"
    return "other"


def _is_shortener(host: str | None) -> bool:
    if not host:
        return False
    return any(host == domain or host.endswith(f".{domain}") for domain in SHORTENER_DOMAINS)


def _hostname(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _unique(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result
