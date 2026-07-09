import logging
import time
from typing import Optional

import requests
from django.core.cache import cache

from apps.darkweb.clients.base import DarkWebProvider, BreachSearchResult

logger = logging.getLogger(__name__)

HIBP_API_BASE = "https://haveibeenpwned.com/api/v3"
REQUEST_TIMEOUT = 15
RATE_LIMIT_DELAY = 1.6

SEVERITY_MAP = {
    "Social Security numbers": "critical",
    "Payment card data": "critical",
    "Bank account numbers": "critical",
    "Passport numbers": "critical",
    "Government IDs": "critical",
    "Medical records": "critical",
    "Credit card": "critical",
    "Credit cards": "critical",
    "Financial data": "high",
    "Passwords": "high",
    "Phone numbers": "high",
    "Physical addresses": "high",
    "Password hints": "high",
    "Security questions": "high",
    "Driver's licenses": "high",
    "National ID": "high",
    "Email addresses": "medium",
    "Names": "medium",
    "IP addresses": "medium",
    "Dates of birth": "medium",
    "Usernames": "low",
    "Gender": "low",
    "Job titles": "low",
    "Browser user agent": "low",
    "Device information": "medium",
}


class HIBPProvider(DarkWebProvider):

    def __init__(self, api_key: str):
        logger.info("[HIBP] Provider initialized (key length: %d)", len(api_key))
        self.api_key = api_key
        self._last_request = 0.0

    def _cache_key(self, indicator: str) -> str:
        return f"hibp_breach_{indicator}"

    def _rate_limit(self):
        elapsed = time.time() - self._last_request
        if elapsed < RATE_LIMIT_DELAY:
            time.sleep(RATE_LIMIT_DELAY - elapsed)
        self._last_request = time.time()

    def _derive_severity(self, pwn_count: Optional[int], data_classes: list) -> str:
        severity_score = 0

        if data_classes:
            for dc in data_classes:
                sev = SEVERITY_MAP.get(dc, "medium")
                if sev == "critical":
                    severity_score = max(severity_score, 3)
                elif sev == "high":
                    severity_score = max(severity_score, 2)
                elif sev == "medium":
                    severity_score = max(severity_score, 1)

        if pwn_count:
            if pwn_count > 50_000_000:
                severity_score += 2
            elif pwn_count > 5_000_000:
                severity_score += 1

        mapping = {0: "low", 1: "medium", 2: "high", 3: "critical", 4: "critical", 5: "critical"}
        return mapping.get(severity_score, "low")

    def search_breaches(
        self, indicator: str, indicator_type: Optional[str] = None
    ) -> BreachSearchResult:
        normalised = indicator.strip().lower()

        if not indicator_type:
            indicator_type = self.detect_asset_type(indicator)

        if indicator_type != "email":
            logger.info("[HIBP] Non-email type %s — returning empty", indicator_type)
            return BreachSearchResult(
                success=True,
                indicator=normalised,
                indicator_type=indicator_type,
                breaches=[],
            )

        cache_key = self._cache_key(normalised)
        cached = cache.get(cache_key)
        if cached is not None:
            logger.info("[HIBP] Cache HIT for %s (%d breaches)", normalised, len(cached.breaches))
            return cached

        logger.info("[HIBP] Cache MISS for %s — making API call", normalised)
        self._rate_limit()

        try:
            url = f"{HIBP_API_BASE}/breachedaccount/{normalised}"
            logger.info("[HIBP] GET %s", url)

            resp = requests.get(
                url,
                headers={
                    "hibp-api-key": self.api_key,
                    "user-agent": "SafeScan-CipherScan/1.0",
                },
                params={"truncateResponse": "false"},
                timeout=REQUEST_TIMEOUT,
            )

            logger.info("[HIBP] Response: HTTP %d, Content-Length: %s",
                        resp.status_code, resp.headers.get("Content-Length", "unknown"))

            if resp.status_code == 404:
                logger.info("[HIBP] 404 — no breaches found for %s", normalised)
                result = BreachSearchResult(
                    success=True,
                    indicator=normalised,
                    indicator_type=indicator_type,
                    breaches=[],
                )
                cache.set(cache_key, result, 300)
                return result

            if resp.status_code == 401:
                logger.error("[HIBP] 401 — invalid API key")
                return BreachSearchResult(
                    success=False,
                    indicator=normalised,
                    indicator_type=indicator_type,
                    breaches=[],
                    error="Invalid HIBP API key",
                )

            if resp.status_code == 429:
                logger.warning("[HIBP] 429 — rate limited")
                return BreachSearchResult(
                    success=False,
                    indicator=normalised,
                    indicator_type=indicator_type,
                    breaches=[],
                    error="Rate limited by HIBP",
                )

            if resp.status_code != 200:
                logger.error("[HIBP] Unexpected status %s", resp.status_code)
                return BreachSearchResult(
                    success=False,
                    indicator=normalised,
                    indicator_type=indicator_type,
                    breaches=[],
                    error=f"HIBP returned status {resp.status_code}",
                )

            raw = resp.json()
            logger.info("[HIBP] Parsed %d breach entries from response", len(raw))
            breaches = []

            for entry in raw:
                name = entry.get("Name", "Unknown")
                title = entry.get("Title", name)
                domain = entry.get("Domain", "")
                breach_date = entry.get("BreachDate", "")
                pwn_count = entry.get("PwnCount")
                data_classes = entry.get("DataClasses", [])
                description = entry.get("Description", "")
                is_verified = entry.get("IsVerified", False)
                is_fabricated = entry.get("IsFabricated", False)
                is_retired = entry.get("IsRetired", False)
                is_spam_list = entry.get("IsSpamList", False)
                logo_path = entry.get("LogoPath", "")

                if is_fabricated or is_retired:
                    logger.info("[HIBP] Skipping fabricated/retired: %s", name)
                    continue

                severity = self._derive_severity(pwn_count, data_classes)
                logger.debug("[HIBP] Breach: %s, date=%s, records=%s, verified=%s, classes=%d",
                            name, breach_date, pwn_count, is_verified, len(data_classes))

                breaches.append({
                    "name": name,
                    "title": title,
                    "domain": domain,
                    "date": breach_date,
                    "records": pwn_count or 0,
                    "data_classes": data_classes,
                    "description": description,
                    "source": "Have I Been Pwned",
                    "risk": severity,
                    "incident_type": "Data Breach",
                    "is_verified": is_verified,
                    "is_spam_list": is_spam_list,
                    "logo_path": logo_path,
                    "references": [f"https://haveibeenpwned.com/PwnedWebsites#{name}"],
                })

            logger.info("[HIBP] Returning %d breaches for %s", len(breaches), normalised)
            result = BreachSearchResult(
                success=True,
                indicator=normalised,
                indicator_type=indicator_type,
                breaches=breaches,
            )
            cache.set(cache_key, result, 300)
            return result

        except requests.ConnectionError:
            logger.warning("[HIBP] Connection error for %s — HIBP may be unreachable", normalised)
            return BreachSearchResult(
                success=False,
                indicator=normalised,
                indicator_type=indicator_type,
                breaches=[],
                error="Could not connect to HIBP",
            )
        except requests.Timeout:
            logger.warning("[HIBP] Timeout for %s (timeout=%ss)", normalised, REQUEST_TIMEOUT)
            return BreachSearchResult(
                success=False,
                indicator=normalised,
                indicator_type=indicator_type,
                breaches=[],
                error="HIBP request timed out",
            )
        except Exception as exc:
            logger.exception("[HIBP] Unexpected error for %s: %s", normalised, exc)
            return BreachSearchResult(
                success=False,
                indicator=normalised,
                indicator_type=indicator_type,
                breaches=[],
                error=str(exc),
            )
