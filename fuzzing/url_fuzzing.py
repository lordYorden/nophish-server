"""Deterministic same-origin URL variants for embedding seed diagnostics."""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit, urlunsplit

from app.detectors.url_scanner.heuristics import is_shortener

PATH_VARIANTS = (
    None,
    "/",
    "/index.html",
    "/login",
    "/account",
    "/verify",
    "/update",
)
QUERY_VARIANTS = (
    None,
    "",
    "utm_source=sms",
    "ref=sms",
    "session=1",
)
FRAGMENT_VARIANTS = ("", "login", "verify")


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def _host_variants(host: str) -> list[str]:
    variants = [host]
    if _is_ip_host(host) or host == "localhost":
        return variants
    if host.startswith("www."):
        variants.append(host.removeprefix("www."))
    else:
        variants.append(f"www.{host}")
    return variants


def _netloc(host: str, port: int | None) -> str:
    return f"{host}:{port}" if port else host


def _path_variant(original_path: str, index: int) -> str:
    variant = PATH_VARIANTS[index % len(PATH_VARIANTS)]
    if variant is None:
        return original_path or "/"
    return variant


def _query_variant(original_query: str, index: int) -> str:
    variant = QUERY_VARIANTS[index % len(QUERY_VARIANTS)]
    if variant is None:
        return original_query
    return variant


def fuzz_url(raw_url: str, variant_index: int) -> str | None:
    split = urlsplit(raw_url.strip())
    if not split.scheme or not split.netloc or not split.hostname:
        return None

    scheme = split.scheme.lower()
    if scheme not in {"http", "https"}:
        return None

    host = split.hostname.lower().rstrip(".")
    if is_shortener(host):
        return None

    try:
        port = split.port
    except ValueError:
        return None

    schemes = [scheme, "https" if scheme == "http" else "http"]
    hosts = _host_variants(host)
    combinations: list[tuple[str, str, str, str, str]] = []
    for fragment in FRAGMENT_VARIANTS:
        for candidate_scheme in schemes:
            for candidate_host in hosts:
                for path_index in range(len(PATH_VARIANTS)):
                    for query_index in range(len(QUERY_VARIANTS)):
                        combinations.append(
                            (
                                candidate_scheme,
                                candidate_host,
                                _path_variant(split.path, path_index),
                                _query_variant(split.query, query_index),
                                fragment,
                            )
                        )

    if not combinations:
        return None

    original = raw_url.strip()
    start = variant_index % len(combinations)
    for offset in range(len(combinations)):
        scheme, candidate_host, path, query, fragment = combinations[
            (start + offset) % len(combinations)
        ]
        variant = urlunsplit((scheme, _netloc(candidate_host, port), path, query, fragment))
        if variant != original:
            return variant
    return None


def fuzz_urls(raw_url: str, count: int, start_index: int = 0) -> list[str]:
    variants: list[str] = []
    original = raw_url.strip()
    seen = {original}
    offset = 0
    attempts = 0
    max_attempts = max(count * 20, 50)
    while len(variants) < count and attempts < max_attempts:
        variant = fuzz_url(raw_url, start_index + offset)
        offset += 1
        attempts += 1
        if variant and variant not in seen:
            seen.add(variant)
            variants.append(variant)
    return variants
