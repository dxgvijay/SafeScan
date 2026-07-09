import logging
import re
from dataclasses import dataclass
from typing import List, Dict
from urllib.parse import urlparse

from bs4 import BeautifulSoup, NavigableString, Tag

logger = logging.getLogger(__name__)


@dataclass
class SanitizeResult:
    safe_html: str
    removed_elements: List[Dict[str, str]]
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


class HTMLSanitizer:
    """Sanitizes raw HTML by removing dangerous elements while preserving safe content."""

    DANGEROUS_TAGS = {"script", "iframe", "embed", "object", "noscript", "form"}
    MEDIA_TAGS = {"video", "audio", "canvas", "svg"}
    EVENT_ATTR_PATTERN = re.compile(r"^on\w+$", re.IGNORECASE)
    DANGEROUS_SCHEMES = {"javascript:", "data:", "vbscript:"}
    MIXED_CONTENT_PATTERNS = [
        re.compile(r"^http://", re.IGNORECASE),
    ]

    def sanitize(self, html: str, base_url: str = "") -> SanitizeResult:
        removed = []
        scripts_removed = 0
        inline_scripts = 0
        external_scripts = 0
        forms_removed = 0
        iframes_removed = 0
        objects_removed = 0
        event_handlers_removed = 0
        dangerous_urls_removed = 0
        meta_refresh_removed = 0
        mixed_content_found = 0

        soup = BeautifulSoup(html, "lxml")

        base_domain = urlparse(base_url).netloc if base_url else ""

        # Remove meta refresh
        for meta in soup.find_all("meta"):
            http_equiv = (meta.get("http-equiv") or "").lower()
            if http_equiv == "refresh":
                meta_refresh_removed += 1
                removed.append({
                    "type": "META REFRESH",
                    "source": meta.get("content", "")[:100],
                    "reason": "Automatic redirect blocked",
                })
                meta.decompose()

        # Remove base tag
        for base in soup.find_all("base"):
            removed.append({
                "type": "BASE",
                "source": base.get("href", "")[:100],
                "reason": "Base URL override blocked",
            })
            base.decompose()

        # Remove dangerous tags
        for tag in soup.find_all(self.DANGEROUS_TAGS):
            tag_name = tag.name.upper()
            src = tag.get("src") or tag.get("action") or tag.get("data") or ""
            reason = self._removal_reason(tag_name)
            removed.append({
                "type": tag_name,
                "source": src[:200],
                "reason": reason,
            })
            if tag_name == "SCRIPT":
                if src:
                    external_scripts += 1
                else:
                    inline_scripts += 1
                scripts_removed += 1
            elif tag_name == "FORM":
                forms_removed += 1
            elif tag_name == "IFRAME":
                iframes_removed += 1
            elif tag_name in ("OBJECT", "EMBED"):
                objects_removed += 1
            tag.decompose()

        # Remove media/plugin tags
        for tag in soup.find_all(self.MEDIA_TAGS):
            tag_name = tag.name.upper()
            removed.append({
                "type": tag_name,
                "source": tag.get("src", "")[:200],
                "reason": f"Embedded {tag_name.lower()} content blocked",
            })
            tag.decompose()

        # Remove link rel=preload, rel=prefetch, rel=modulepreload
        for link in soup.find_all("link"):
            rel = (link.get("rel") or [""])[0].lower() if isinstance(link.get("rel"), list) else ""
            if rel in ("preload", "prefetch", "modulepreload", "dns-prefetch", "preconnect"):
                removed.append({
                    "type": "LINK",
                    "source": link.get("href", "")[:200],
                    "reason": f"Resource hint ({rel}) blocked",
                })
                link.decompose()

        # Strip event handlers from all remaining tags
        for tag in soup.find_all(True):
            if not hasattr(tag, "attrs"):
                continue
            to_delete = []
            for attr in tag.attrs:
                if self.EVENT_ATTR_PATTERN.match(attr):
                    to_delete.append(attr)
            for attr in to_delete:
                event_handlers_removed += 1
                removed.append({
                    "type": "EVENT HANDLER",
                    "source": f"{tag.name}[{attr}]",
                    "reason": f"Inline event handler ({attr}) blocked",
                })
                del tag[attr]

        # Strip dangerous URLs in href/src
        for attr_name in ("href", "src", "action", "data", "formaction"):
            for tag in soup.find_all(attrs={attr_name: True}):
                val = tag[attr_name].strip()
                normalized = val.strip().lower()
                matched_scheme = None
                for scheme in self.DANGEROUS_SCHEMES:
                    if normalized.startswith(scheme):
                        matched_scheme = scheme
                        break
                if matched_scheme:
                    dangerous_urls_removed += 1
                    removed.append({
                        "type": f"DANGEROUS URL [{attr_name}]",
                        "source": val[:200],
                        "reason": f"Dangerous scheme ({matched_scheme}) blocked",
                    })
                    if tag.name == "a" and attr_name == "href":
                        tag["href"] = "#"
                        tag.string = tag.get_text() or val
                    else:
                        del tag[attr_name]

        # Check for mixed content in src/href
        if base_domain:
            for attr_name in ("src", "href"):
                for tag in soup.find_all(attrs={attr_name: True}):
                    val = tag[attr_name].strip().lower()
                    if val.startswith("http://"):
                        mixed_content_found += 1

        return SanitizeResult(
            safe_html=str(soup),
            removed_elements=removed,
            scripts_removed=scripts_removed,
            inline_scripts_removed=inline_scripts,
            external_scripts_removed=external_scripts,
            forms_removed=forms_removed,
            iframes_removed=iframes_removed,
            objects_removed=objects_removed,
            event_handlers_removed=event_handlers_removed,
            dangerous_urls_removed=dangerous_urls_removed,
            meta_refresh_removed=meta_refresh_removed,
            mixed_content_found=mixed_content_found,
        )

    def _removal_reason(self, tag_name: str) -> str:
        reasons = {
            "SCRIPT": "JavaScript execution blocked",
            "IFRAME": "Embedded remote content blocked",
            "FORM": "Credential collection disabled",
            "OBJECT": "Active plugin blocked",
            "EMBED": "Active plugin blocked",
            "NOSCRIPT": "Fallback content removed",
        }
        return reasons.get(tag_name, f"{tag_name} tag removed")
