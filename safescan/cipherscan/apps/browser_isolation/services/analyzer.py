import logging
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from urllib.parse import urlparse

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)


@dataclass
class AnalysisResult:
    page_title: str
    final_url: str
    http_status: int
    server_header: str
    content_type: str
    content_length: int
    redirect_count: int
    load_time_ms: float
    dom_nodes: int
    images: int
    links: int
    css_files: int
    scripts_removed: int
    inline_scripts_removed: int
    external_scripts_removed: int
    forms_removed: int
    iframes_removed: int
    objects_removed: int
    event_handlers_removed: int
    dangerous_urls_removed: int
    meta_refresh_removed: int
    mixed_content_found: int
    risk_score: int
    risk_level: str
    security_headers: Dict[str, str]


SECURITY_HEADER_KEYS = [
    "content-security-policy",
    "strict-transport-security",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-embedder-policy",
    "cross-origin-resource-policy",
]

SECURITY_HEADER_LABELS = {
    "content-security-policy": "Content-Security-Policy",
    "strict-transport-security": "Strict-Transport-Security",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
    "cross-origin-opener-policy": "Cross-Origin-Opener-Policy",
    "cross-origin-embedder-policy": "Cross-Origin-Embedder-Policy",
    "cross-origin-resource-policy": "Cross-Origin-Resource-Policy",
}


class SecurityAnalyzer:
    """Analyzes raw HTML and fetch metadata to generate a real security report."""

    def analyze(
        self,
        html: str,
        fetch_result: "FetchResult",
        sanitize_result: "SanitizeResult",
    ) -> AnalysisResult:
        soup = BeautifulSoup(html, "lxml")
        headers = fetch_result.response_headers

        dom_nodes = len(soup.find_all(True))
        images = len(soup.find_all("img"))
        links = len(soup.find_all("a", href=True))
        css_files = len(soup.find_all("link", rel=lambda v: v and "stylesheet" in v))

        secheaders = self._extract_security_headers(headers)

        risk_score, risk_level = self._calculate_risk(
            html=html,
            redirect_count=fetch_result.redirect_chain,
            has_login_form=sanitize_result.forms_removed > 0,
            has_hidden_iframe=sanitize_result.iframes_removed > 0,
            scripts_removed=sanitize_result.scripts_removed,
            meta_refresh=sanitize_result.meta_refresh_removed,
            has_executable_download=self._has_executable_download(soup),
        )

        return AnalysisResult(
            page_title=fetch_result.page_title,
            final_url=fetch_result.final_url,
            http_status=fetch_result.http_status,
            server_header=headers.get("server", ""),
            content_type=headers.get("content-type", ""),
            content_length=len(html.encode("utf-8")),
            redirect_count=len(fetch_result.redirect_chain),
            load_time_ms=fetch_result.load_time_ms,
            dom_nodes=dom_nodes,
            images=images,
            links=links,
            css_files=css_files,
            scripts_removed=sanitize_result.scripts_removed,
            inline_scripts_removed=sanitize_result.inline_scripts_removed,
            external_scripts_removed=sanitize_result.external_scripts_removed,
            forms_removed=sanitize_result.forms_removed,
            iframes_removed=sanitize_result.iframes_removed,
            objects_removed=sanitize_result.objects_removed,
            event_handlers_removed=sanitize_result.event_handlers_removed,
            dangerous_urls_removed=sanitize_result.dangerous_urls_removed,
            meta_refresh_removed=sanitize_result.meta_refresh_removed,
            mixed_content_found=sanitize_result.mixed_content_found,
            risk_score=risk_score,
            risk_level=risk_level,
            security_headers=secheaders,
        )

    def _extract_security_headers(self, headers: dict) -> Dict[str, str]:
        result = {}
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for key in SECURITY_HEADER_KEYS:
            label = SECURITY_HEADER_LABELS.get(key, key)
            result[label] = lower_headers.get(key) or ""
        return result

    def _calculate_risk(
        self,
        html: str,
        redirect_count: list,
        has_login_form: bool,
        has_hidden_iframe: bool,
        scripts_removed: int,
        meta_refresh: int,
        has_executable_download: bool,
    ) -> tuple:
        score = 0

        if has_login_form:
            score += 20
        if has_hidden_iframe:
            score += 15
        if scripts_removed > 20:
            score += 10
        elif scripts_removed > 5:
            score += 5
        if self._has_obfuscated_js(html):
            score += 20
        if meta_refresh > 0:
            score += 10
        if len(redirect_count) > 2:
            score += 15
        elif len(redirect_count) > 1:
            score += 5
        if has_executable_download:
            score += 10

        score = max(0, min(100, score))

        if score >= 80:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 25:
            level = "medium"
        else:
            level = "low"

        return score, level

    def _has_obfuscated_js(self, html: str) -> bool:
        indicators = [
            r"\\x[0-9a-fA-F]{2}",
            r"eval\s*\(",
            r"atob\s*\(",
            r"String\.fromCharCode",
            r"document\.write\s*\(\s*['\"]",
            r"\\u[0-9a-fA-F]{4}",
            r"escape\s*\(\s*['\"]",
        ]
        count = 0
        for pattern in indicators:
            matches = re.findall(pattern, html, re.IGNORECASE)
            count += len(matches)
        return count > 5

    def _has_executable_download(self, soup: BeautifulSoup) -> bool:
        exec_extensions = {".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".jar", ".sh"}
        for a in soup.find_all("a", href=True):
            href = a["href"].lower().strip()
            for ext in exec_extensions:
                if href.endswith(ext):
                    return True
        return False
