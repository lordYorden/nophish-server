"""Deterministic URL mutations for non-exact embedding evaluation."""

from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def fuzz_url(raw_url: str, variant_index: int) -> str | None:
    split = urlsplit(raw_url.strip())
    if not split.scheme or not split.netloc or not split.hostname:
        return None

    host = split.hostname.lower().rstrip(".")
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return None

    registrable = labels[-2]
    suffix = labels[-1]
    prefix = ".".join(labels[:-2])

    host_variants = [
        f"{registrable}-verify.{suffix}",
        f"{registrable}-secure.{suffix}",
        f"login-{registrable}.{suffix}",
        f"{registrable}-account.{suffix}",
        f"{registrable}-support.{suffix}",
        f"secure-{registrable}.{suffix}",
    ]
    new_host = host_variants[variant_index % len(host_variants)]
    if prefix and variant_index % 2 == 1:
        new_host = f"{prefix}.{new_host}"

    path = split.path or "/"
    path_variants = [
        path,
        "/login",
        "/account/verify",
        "/secure/update",
        "/payment/confirm",
        "/support/check",
    ]
    new_path = path_variants[(variant_index // len(host_variants)) % len(path_variants)]

    query_pairs = parse_qsl(split.query, keep_blank_values=True)
    query_pairs.append(("ref", f"eval{variant_index}"))
    new_query = urlencode(query_pairs)

    port = f":{split.port}" if split.port else ""
    return urlunsplit((split.scheme.lower(), f"{new_host}{port}", new_path, new_query, ""))


def fuzz_urls(raw_url: str, count: int, start_index: int = 0) -> list[str]:
    variants: list[str] = []
    seen = {raw_url}
    for offset in range(count):
        variant = fuzz_url(raw_url, start_index + offset)
        if variant and variant not in seen:
            seen.add(variant)
            variants.append(variant)
    return variants
