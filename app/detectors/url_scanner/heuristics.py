import ipaddress
import re
import unicodedata

from app.detectors.url_scanner.config import (
    BRAND_DOMAINS,
    CONFUSABLE_CODEPOINTS,
    MAX_SUBDOMAINS,
    SHORTENER_DOMAINS,
)


def unsafe_ip_reason(value: str) -> str | None:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    return None if ip.is_global else "private_ip_host"


def is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


def has_strong_static_signal(reasons: list[str]) -> bool:
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


def looks_like_schemeless_url(value: str) -> bool:
    first = value.split("/", 1)[0]
    return "." in first and not first.startswith(".")


def is_default_port(scheme: str, port: int) -> bool:
    return (scheme == "http" and port == 80) or (scheme == "https" and port == 443)


def has_excessive_subdomains(host: str) -> bool:
    labels = [label for label in host.split(".") if label]
    return max(len(labels) - 2, 0) > MAX_SUBDOMAINS


def has_brand_token_in_wrong_domain(host: str) -> bool:
    labels = re.split(r"[^a-z0-9]+", host.lower())
    label_text = "-".join(labels)
    for brand, legitimate_suffixes in BRAND_DOMAINS.items():
        if brand not in label_text:
            continue
        if any(host == suffix or host.endswith(f".{suffix}") for suffix in legitimate_suffixes):
            return False
        return True
    return False


def has_confusable_hostname(host: str) -> bool:
    return any(ch in CONFUSABLE_CODEPOINTS for ch in host)


def has_mixed_scripts(host: str) -> bool:
    scripts = {script_for(ch) for ch in host if ch.isalpha()}
    scripts.discard("common")
    return len(scripts) > 1


def script_for(ch: str) -> str:
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


def is_shortener(host: str | None) -> bool:
    if not host:
        return False
    return any(host == domain or host.endswith(f".{domain}") for domain in SHORTENER_DOMAINS)
