from app.detectors.url_scanner.browser import PLAYWRIGHT_AVAILABLE
from app.detectors.url_scanner.browser import expand_with_browser as _expand_with_browser
from app.detectors.url_scanner.config import (
    BROWSER_TIMEOUT_MS,
    BRAND_DOMAINS,
    CONFUSABLE_CODEPOINTS,
    HTTP_TIMEOUT_SECONDS,
    MAX_BODY_BYTES,
    MAX_REDIRECTS,
    MAX_SUBDOMAINS,
    SHORTENER_DOMAINS,
    USER_AGENT,
    ZERO_WIDTH_OR_INVISIBLE,
    browser_enabled as _browser_enabled,
)
from app.detectors.url_scanner.heuristics import (
    has_brand_token_in_wrong_domain as _has_brand_token_in_wrong_domain,
    has_confusable_hostname as _has_confusable_hostname,
    has_excessive_subdomains as _has_excessive_subdomains,
    has_mixed_scripts as _has_mixed_scripts,
    has_strong_static_signal as _has_strong_static_signal,
    is_default_port as _is_default_port,
    is_ip_host as _is_ip_host,
    is_shortener as _is_shortener,
    looks_like_schemeless_url as _looks_like_schemeless_url,
    script_for as _script_for,
    unsafe_ip_reason as _unsafe_ip_reason,
)
from app.detectors.url_scanner.http_redirects import (
    expand_http_redirects as _expand_http_redirects,
    get_small_response as _get_small_response,
    probe_html_redirect as _probe_html_redirect,
)
from app.detectors.url_scanner.normalization import (
    canonicalize_url_for_lookup,
    normalize_url as _normalize_url,
)
from app.detectors.url_scanner.safety import reject_unsafe_target as _reject_unsafe_target
from app.detectors.url_scanner.scanner import scan_url, scan_urls
from app.detectors.url_scanner.scanner import should_use_browser as _should_use_browser
from app.detectors.url_scanner.types import NormalizedUrl as _NormalizedUrl
from app.detectors.url_scanner.types import UrlScanResult
from app.detectors.url_scanner.utils import hostname as _hostname
from app.detectors.url_scanner.utils import unique as _unique

__all__ = ["UrlScanResult", "canonicalize_url_for_lookup", "scan_url", "scan_urls"]
