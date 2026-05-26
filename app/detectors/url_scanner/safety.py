import asyncio
import socket

from app.detectors.url_scanner.heuristics import unsafe_ip_reason
from app.detectors.url_scanner.normalization import normalize_url


async def reject_unsafe_target(url: str) -> str | None:
    normalized = normalize_url(url)
    if normalized.url is None or not normalized.hostname:
        return "parse_failure"

    host = normalized.hostname
    if unsafe_ip_reason(host):
        return "private_ip_host"

    try:
        addrinfos = await asyncio.to_thread(socket.getaddrinfo, host, None, type=socket.SOCK_STREAM)
    except OSError:
        return "url_resolution_failure"

    for addrinfo in addrinfos:
        ip = addrinfo[4][0]
        if unsafe_ip_reason(ip):
            return "private_ip_host"
    return None
