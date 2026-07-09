import logging
import time
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class FetchResult:
    html: str
    final_url: str
    http_status: int
    response_headers: dict
    redirect_chain: list
    page_title: str
    load_time_ms: float
    error: Optional[str] = None


class PlaywrightFetcher:
    """Fetches a URL using headless Chromium via Playwright."""

    NAV_TIMEOUT = 25000
    CAPTURE_TIMEOUT = 5000

    def __init__(self) -> None:
        self._playwright = None
        self._browser = None

    def _get_browser(self):
        """Lazy import and browser launch to avoid circular imports at module level."""
        from playwright.sync_api import sync_playwright

        if self._browser is not None:
            return self._browser

        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(
            headless=True,
            args=[
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--disable-dev-shm-usage",
                "--disable-gpu",
            ],
        )
        return self._browser

    def _clean_url(self, raw: str) -> str:
        raw = raw.strip()
        if not raw:
            raise ValueError("URL is empty")
        parsed = urlparse(raw)
        if not parsed.scheme:
            raw = "https://" + raw
        parsed = urlparse(raw)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"Invalid URL scheme: {parsed.scheme}")
        if not parsed.netloc:
            raise ValueError("URL has no hostname")
        return raw

    def fetch(self, url: str) -> FetchResult:
        """Fetch a URL and return the rendered HTML + metadata."""
        url = self._clean_url(url)
        browser = self._get_browser()
        context = None
        page = None
        redirect_chain = []
        start = time.time()

        try:
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                locale="en-US",
                timezone_id="America/New_York",
                viewport={"width": 1366, "height": 768},
                ignore_https_errors=False,
            )
            page = context.new_page()
            page.set_default_timeout(self.NAV_TIMEOUT)

            response = None

            def _on_response(resp):
                nonlocal response
                if resp.url == page.url or response is None:
                    response = resp

            page.on("response", _on_response)

            resp = page.goto(url, wait_until="domcontentloaded", timeout=self.NAV_TIMEOUT)
            page.wait_for_timeout(self.CAPTURE_TIMEOUT)

            final_url = page.url
            html = page.content()
            page_title = page.title() or ""

            http_status = resp.status if resp else 0
            resp_headers = dict(resp.headers) if resp else {}

            if response:
                chain = self._build_redirect_chain(page, response)
                redirect_chain = chain

            elapsed = round((time.time() - start) * 1000, 2)

            return FetchResult(
                html=html,
                final_url=final_url,
                http_status=http_status,
                response_headers=resp_headers,
                redirect_chain=redirect_chain,
                page_title=page_title,
                load_time_ms=elapsed,
            )

        except Exception as exc:
            elapsed = round((time.time() - start) * 1000, 2)
            error_msg = self._classify_error(exc)
            logger.warning("Playwright fetch failed for %s: %s", url, error_msg, exc_info=True)
            return FetchResult(
                html="",
                final_url=url,
                http_status=0,
                response_headers={},
                redirect_chain=[],
                page_title="",
                load_time_ms=elapsed,
                error=error_msg,
            )

        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass
            if context:
                try:
                    context.close()
                except Exception:
                    pass

    def _build_redirect_chain(self, page, final_response) -> list:
        chain = []
        seen = set()
        try:
            for resp in page.context.pages[0].context.cookies():
                pass
            req = final_response.request
            while req:
                if req.url in seen:
                    break
                seen.add(req.url)
                chain.append({
                    "url": req.url,
                    "status": req.response.status if req.response else 0,
                })
                req = req.redirected_from
        except Exception:
            pass
        chain.reverse()
        return chain

    def _classify_error(self, exc: Exception) -> str:
        msg = str(exc).lower()
        if "timeout" in msg:
            return "Timeout"
        if "certificate" in msg or "ssl" in msg:
            return "SSL Error"
        if "refused" in msg or "connect" in msg:
            return "Connection Refused"
        if "dns" in msg or "dnsresolution" in msg or "enetunreach" in msg:
            return "DNS Failure"
        if "redirect" in msg:
            return "Too Many Redirects"
        if "blocked" in msg or "block" in msg:
            return "Blocked"
        if "ns_binding_aborted" in msg or "net::err" in msg:
            return "Website Unreachable"
        return f"Internal Error: {type(exc).__name__}"

    def close(self) -> None:
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        self._browser = None
        self._playwright = None

    def __del__(self) -> None:
        self.close()
