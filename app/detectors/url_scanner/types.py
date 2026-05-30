from dataclasses import dataclass, field

from app.detectors.url_scanner.utils import hostname


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
        return hostname(self.normalized_url)

    @property
    def final_hostname(self) -> str | None:
        return hostname(self.final_url)


@dataclass
class NormalizedUrl:
    url: str | None
    hostname: str | None
    display_hostname: str | None
    reasons: list[str]
    parse_error: str | None = None
