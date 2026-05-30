import logging

from app.detectors.url_scanner.config import BROWSER_TIMEOUT_MS, USER_AGENT, browser_enabled
from app.detectors.url_scanner.heuristics import has_strong_static_signal
from app.detectors.url_scanner.normalization import canonicalize_url_for_lookup, normalize_url
from app.detectors.url_scanner.safety import reject_unsafe_target
from app.detectors.url_scanner.types import UrlScanResult
from app.detectors.url_scanner.utils import unique

logger = logging.getLogger(__name__)

try:
    import playwright.async_api as playwright_async_api
except ImportError:
    playwright_async_api = None

PLAYWRIGHT_AVAILABLE = playwright_async_api is not None


async def expand_with_browser(url: str) -> UrlScanResult:
    if not browser_enabled():
        return UrlScanResult(
            suspicious=True,
            reasons=["browser_fallback_disabled"],
            raw_url=url,
            final_url=url,
            error="browser_fallback_disabled",
        )

    if not PLAYWRIGHT_AVAILABLE:
        return UrlScanResult(
            suspicious=True,
            reasons=["browser_unavailable"],
            raw_url=url,
            final_url=url,
            used_browser=False,
            error="ImportError",
        )

    redirect_chain = [url]
    try:
        async with playwright_async_api.async_playwright() as playwright:
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
                target_error = await reject_unsafe_target(request.url)
                if target_error:
                    await route.abort()
                    return
                await route.continue_()

            await page.route("**/*", route_handler)
            page.on(
                "framenavigated",
                lambda frame: redirect_chain.append(frame.url)
                if frame == page.main_frame
                else None,
            )
            await page.goto(url, wait_until="domcontentloaded")
            final_url = canonicalize_url_for_lookup(page.url) or page.url
            await page.unroute_all(behavior="ignoreErrors")
            await context.close()
            await browser.close()
    except playwright_async_api.TimeoutError as exc:
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

    final_normalized = normalize_url(final_url)
    reasons = final_normalized.reasons
    return UrlScanResult(
        suspicious=has_strong_static_signal(reasons),
        reasons=reasons,
        raw_url=url,
        final_url=final_normalized.url or final_url,
        redirect_chain=unique(redirect_chain),
        used_browser=True,
    )
