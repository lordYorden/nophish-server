import unicodedata
from urllib.parse import quote, unquote, urlsplit, urlunsplit

import idna

from app.detectors.url_scanner.config import ZERO_WIDTH_OR_INVISIBLE
from app.detectors.url_scanner.heuristics import (
    has_brand_token_in_wrong_domain,
    has_confusable_hostname,
    has_excessive_subdomains,
    has_mixed_scripts,
    is_default_port,
    is_ip_host,
    looks_like_schemeless_url,
)
from app.detectors.url_scanner.types import NormalizedUrl
from app.detectors.url_scanner.utils import unique


def canonicalize_url_for_lookup(raw_url: str) -> str | None:
    """Return the scanner's canonical URL form, or None if it cannot parse safely."""
    normalized = normalize_url(raw_url)
    return normalized.url


def normalize_url(raw_url: str) -> NormalizedUrl:
    reasons: list[str] = []
    value = raw_url.strip()
    if not value:
        return NormalizedUrl(None, None, None, ["parse_failure"], "empty_url")

    if any(ch in value for ch in ZERO_WIDTH_OR_INVISIBLE) or any(
        unicodedata.category(ch) == "Cf" for ch in value
    ):
        reasons.append("zero_width_character")
        value = "".join(
            ch
            for ch in value
            if ch not in ZERO_WIDTH_OR_INVISIBLE and unicodedata.category(ch) != "Cf"
        )

    value = unicodedata.normalize("NFKC", value)
    split = urlsplit(value)
    if not split.scheme and not split.netloc and looks_like_schemeless_url(split.path):
        value = f"https://{value}"
        split = urlsplit(value)

    if split.scheme.lower() not in {"http", "https"}:
        return NormalizedUrl(
            None,
            None,
            None,
            ["non_http_scheme"],
            f"scheme={split.scheme or 'missing'}",
        )

    if not split.hostname:
        return NormalizedUrl(None, None, None, ["parse_failure"], "missing_hostname")

    try:
        display_host = unicodedata.normalize("NFKC", split.hostname.rstrip(".").lower())
        ascii_host = idna.encode(display_host, uts46=True).decode("ascii").lower()
        decoded_host = idna.decode(ascii_host, uts46=True).lower()
    except idna.IDNAError as exc:
        return NormalizedUrl(None, None, None, ["parse_failure"], type(exc).__name__)

    if ascii_host.startswith("xn--") or ".xn--" in ascii_host:
        reasons.append("punycode_hostname")
    if has_confusable_hostname(decoded_host):
        reasons.append("unicode_confusable_hostname")
    if has_mixed_scripts(decoded_host):
        reasons.append("mixed_script_hostname")
    if is_ip_host(ascii_host):
        reasons.append("ip_address_host")
    if has_excessive_subdomains(ascii_host):
        reasons.append("excessive_subdomains")
    if has_brand_token_in_wrong_domain(ascii_host):
        reasons.append("brand_token_in_wrong_domain")

    try:
        netloc = ascii_host
        if split.port and not is_default_port(split.scheme.lower(), split.port):
            netloc = f"{netloc}:{split.port}"
    except ValueError as exc:
        return NormalizedUrl(None, None, None, ["parse_failure"], type(exc).__name__)

    path = quote(unquote(split.path or "/"), safe="/:@!$&'()*+,;=-._~%")
    query = quote(unquote(split.query), safe="=&?/:@!$'()*+,;%-._~")
    normalized_url = urlunsplit((split.scheme.lower(), netloc, path, query, ""))
    return NormalizedUrl(normalized_url, ascii_host, decoded_host, unique(reasons))
