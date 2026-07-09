import logging
from datetime import datetime, timezone
from typing import Optional

from django.conf import settings

from apps.darkweb.clients.base import DarkWebProvider
from apps.darkweb.clients.router import get_provider
from apps.darkweb.engines.risk import calculate_risk_score, _risk_level
from apps.darkweb.engines.confidence import calculate_confidence
from apps.darkweb.engines.timeline import get_dates
from apps.darkweb.engines.recommendations import generate_recommendations

logger = logging.getLogger(__name__)


class DarkWebService:

    def __init__(self, provider: DarkWebProvider):
        self.provider = provider

    @staticmethod
    def _overall_status(risk_score: int) -> str:
        return _risk_level(risk_score)

    @staticmethod
    def _generate_exposure_flags(asset_type: str, breaches: list) -> dict:
        flags = {
            "credential_exposed": False,
            "phone_exposed": False,
            "username_exposed": False,
            "social_accounts": False,
            "government_id": False,
            "financial_data": False,
            "vpn_association": False,
            "malware_association": False,
        }

        if asset_type == "email":
            flags["credential_exposed"] = True
            flags["username_exposed"] = True
        elif asset_type == "phone":
            flags["phone_exposed"] = True
        elif asset_type == "domain":
            flags["vpn_association"] = True

        for breach in breaches:
            for data_class in breach.get("data_classes", []):
                dc = data_class.lower()
                if "password" in dc:
                    flags["credential_exposed"] = True
                if "phone" in dc:
                    flags["phone_exposed"] = True
                if "username" in dc or data_class == "Names":
                    flags["username_exposed"] = True
                if "social" in dc:
                    flags["social_accounts"] = True
                if "government" in dc or "ssn" in dc or data_class == "Social Security numbers":
                    flags["government_id"] = True
                if "financial" in dc or "credit" in dc or "payment" in dc or "bank" in dc:
                    flags["financial_data"] = True
                if "vpn" in dc or "ip" in dc:
                    flags["vpn_association"] = True
                if "malware" in dc:
                    flags["malware_association"] = True

        return flags

    @staticmethod
    def _generate_recommendations(risk_score: int, asset_type: str, breaches: list) -> list:
        return [r["text"] for r in generate_recommendations(breaches, [], {"score": risk_score}, asset_type, asset_type)]

    def scan(self, asset: str, asset_type: Optional[str] = None) -> dict:
        logger.info("[DarkWeb][scan] start: asset=%s, type=%s", asset, asset_type)
        a = asset.strip()
        if not a:
            logger.warning("[DarkWeb][scan] Empty asset")
            return {"success": False, "error": "Asset is required."}

        result = self.provider.search_breaches(a, indicator_type=asset_type)
        logger.info("[DarkWeb][scan] search_breaches: success=%s, breaches=%d, error=%s",
                    result.success, len(result.breaches), result.error)

        if not result.success:
            return {"success": False, "error": result.error or "Scan failed."}

        detected_type = result.indicator_type
        breaches = result.breaches
        breach_count = len(breaches)

        exposures = self._generate_exposure_flags(detected_type, breaches)
        risk_info = calculate_risk_score(breaches)
        risk_score = risk_info["score"]
        overall_status = risk_info["level"]
        first_seen, last_seen = get_dates(breaches)
        recommendations = self._generate_recommendations(risk_score, detected_type, breaches)

        logger.info("[DarkWeb][scan] complete: breaches=%d, risk=%d, status=%s",
                    breach_count, risk_score, overall_status)

        return {
            "asset": a,
            "asset_type": detected_type,
            "risk_score": risk_score,
            "overall_status": overall_status,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "breach_count": breach_count,
            "credential_exposed": exposures["credential_exposed"],
            "phone_exposed": exposures["phone_exposed"],
            "username_exposed": exposures["username_exposed"],
            "social_accounts": exposures["social_accounts"],
            "government_id": exposures["government_id"],
            "financial_data": exposures["financial_data"],
            "vpn_association": exposures["vpn_association"],
            "malware_association": exposures["malware_association"],
            "breaches": breaches,
            "recommendations": recommendations,
            "risk_factors": risk_info["factors"],
        }


def _normalize_query(query: str) -> str:
    return query.strip().lower()


def _derive_categories(breaches: list, query: str) -> dict:
    category_keywords = {
        "email": ["Email"],
        "username": ["Username", "Name"],
        "phone": ["Phone"],
        "password": ["Password"],
        "address": ["Address"],
        "financial_data": ["Financial", "Credit", "Bank", "Payment"],
        "government_id": ["Government", "SSN", "Driver", "ID"],
        "social_accounts": ["Social"],
    }
    statuses = {k: "unknown" for k in list(category_keywords.keys()) + ["vpn_leak", "malware_association"]}

    found_classes = set()
    for b in breaches:
        for dc in b.get("data_classes", []):
            found_classes.add(dc.lower())

    for cat, keywords in category_keywords.items():
        for kw in keywords:
            if any(kw.lower() in fc for fc in found_classes):
                statuses[cat] = "found"
                break

    for cat in statuses:
        if statuses[cat] == "unknown":
            statuses[cat] = "not_found"

    return statuses


def generate_analysis(query: str, asset_type: str, risk: dict, breaches: list) -> dict:
    score = risk["score"]
    breach_count = len(breaches)
    total_records = sum(b.get("records", 0) for b in breaches)

    if score <= 20:
        level = "low"
        summary = (
            f"CipherScan's analysis indicates a low risk profile for the queried asset. "
            f"Minimal breach activity was detected across monitored dark web sources. "
            f"While no significant exposure was found, continued monitoring is recommended."
        )
        posture = "Your current exposure posture appears healthy. Continue practicing good security hygiene to maintain this status."
        key_actions = [
            "Enable breach monitoring alerts for early warnings",
            "Use unique, complex passwords across all services",
            "Enable two-factor authentication wherever supported",
        ]
    elif score <= 50:
        level = "medium"
        summary = (
            f"CipherScan detected moderate exposure activity for the queried asset. "
            f"Found across {breach_count} breach source(s) with approximately {total_records:,} records involved. "
            f"While the overall risk remains moderate, some data types may be circulating on dark web channels."
        )
        posture = "Your exposure profile suggests partial compromise. Prioritize credential rotation for affected services."
        key_actions = [
            "Change passwords for all accounts associated with this asset",
            "Enable two-factor authentication on critical accounts",
            "Monitor financial statements for unauthorized activity",
            "Consider using a password manager for unique credentials",
        ]
    elif score <= 75:
        level = "high"
        summary = (
            f"CipherScan's deep scan reveals significant exposure across {breach_count} breach source(s) "
            f"affecting {total_records:,}+ records. The asset appears in multiple dark web datasets, "
            f"indicating a high likelihood of credential and personal data circulation."
        )
        posture = "Elevated risk detected. Immediate action is recommended to mitigate potential account takeover and phishing attacks."
        key_actions = [
            "Immediately change passwords on all linked accounts",
            "Enable two-factor authentication everywhere possible",
            "Scan devices for malware and keyloggers",
            "Place a fraud alert on your credit file if financial data exposed",
            "Monitor accounts closely for suspicious activity over the next 90 days",
        ]
    else:
        level = "critical"
        summary = (
            f"Critical alert \u2014 CipherScan has identified extensive exposure for the queried asset. "
            f"Found in {breach_count} major breach incident(s) spanning {total_records:,}+ compromised records. "
            f"The presence of highly sensitive data types on dark web forums suggests active targeting."
        )
        posture = "Your asset is at severe risk. Comprehensive action is required immediately to prevent identity theft and account compromise."
        key_actions = [
            "Change ALL passwords immediately \u2014 prioritize email and banking accounts",
            "Enable two-factor authentication on every account",
            "Freeze your credit with all major bureaus",
            "Run a full antivirus and anti-malware scan on all devices",
            "Monitor all financial accounts daily for 90+ days",
            "Consider identity theft protection services",
            "Review and rotate API keys, tokens, and recovery codes",
        ]

    return {
        "summary": summary,
        "posture": posture,
        "key_actions": key_actions,
        "breach_count": breach_count,
        "exposure_count": 0,
        "total_records": total_records,
        "found_categories": [],
        "risk_level": level,
        "risk_score": score,
    }


def analyze(query: str, provider: Optional[DarkWebProvider] = None, asset_type: Optional[str] = None) -> dict:
    normalized = _normalize_query(query)
    detected_type = asset_type or "email"

    _debug = {}
    _debug["query"] = normalized
    _debug["asset_type_param"] = asset_type
    _debug["detected_type"] = detected_type
    _debug["step_provider"] = "pending"
    _debug["step_search"] = "pending"
    _debug["step_risk"] = "pending"
    _debug["step_confidence"] = "pending"
    _debug["step_timeline"] = "pending"
    _debug["step_recommendations"] = "pending"

    logger.info("[DarkWeb][analyze] STEP 1/7 — Normalize: query=%s, type=%s", normalized, detected_type)

    if provider is None:
        provider = get_provider()

    _debug["provider_type"] = type(provider).__name__ if provider else None
    _debug["hibp_key_configured"] = bool(getattr(settings, "HIBP_API_KEY", ""))

    logger.info("[DarkWeb][analyze] STEP 2/7 — Provider: %s, HIBP key set=%s",
                _debug["provider_type"], _debug["hibp_key_configured"])

    _debug["step_provider"] = "completed"

    if provider is None:
        logger.info("[DarkWeb][analyze] No provider — returning early (provider_unavailable)")
        resp = {
            "success": True,
            "query": normalized,
            "type": detected_type,
            "data": {
                "risk": {"score": 0, "level": "low", "factors": []},
                "confidence": 15,
                "breaches": [],
                "exposure_count": 0,
                "exposures": [],
                "total_records_exposed": 0,
                "recommendations": [
                    {"icon": "\u2705", "text": "No breach activity detected. Continue practicing good security hygiene.", "priority": "low"},
                    {"icon": "\ud83d\udd04", "text": "Re-scan periodically. New breaches surface daily and your exposure status may change over time.", "priority": "low"},
                ],
                "first_seen": None,
                "last_seen": None,
                "compromised_fields": [],
                "scan_date": datetime.now(timezone.utc).isoformat(),
                "sources_checked": ["Have I Been Pwned"],
                "categories": {},
                "analysis": {
                    "summary": "Breach data source not configured. Set a HaveIBeenPwned API key to enable breach detection.",
                    "posture": "Unable to check breach history.",
                    "key_actions": ["Configure a HIBP API key in the .env file to enable breach scanning."],
                    "breach_count": 0,
                    "exposure_count": 0,
                    "total_records": 0,
                    "found_categories": [],
                    "risk_level": "low",
                    "risk_score": 0,
                },
                "provider_unavailable": True,
            },
        }
        if settings.DEBUG:
            resp["data"]["_debug"] = _debug
        return resp

    logger.info("[DarkWeb][analyze] STEP 3/7 — Search breaches via %s for %s", _debug["provider_type"], normalized)

    result = provider.search_breaches(normalized, indicator_type=asset_type)
    _debug["search_success"] = result.success
    _debug["search_error"] = result.error
    _debug["breaches_raw_count"] = len(result.breaches)
    _debug["step_search"] = "completed"

    logger.info("[DarkWeb][analyze] search_breaches result: success=%s, breaches=%d, error=%s",
                result.success, len(result.breaches), result.error)

    if not result.success:
        logger.error("[DarkWeb][analyze] Search failed: %s", result.error)
        resp = {"success": False, "error": result.error or "Search failed."}
        if settings.DEBUG:
            resp["_debug"] = _debug
        return resp

    detected_type = result.indicator_type
    breaches = result.breaches
    _debug["detected_type"] = detected_type
    _debug["breach_count"] = len(breaches)

    logger.info("[DarkWeb][analyze] STEP 4/7 — Calculate risk: %d breaches", len(breaches))

    risk_info = calculate_risk_score(breaches)
    risk = {"score": risk_info["score"], "level": risk_info["level"], "factors": risk_info["factors"]}
    _debug["risk_score"] = risk_info["score"]
    _debug["risk_level"] = risk_info["level"]
    _debug["risk_factors"] = risk_info["factors"]
    _debug["step_risk"] = "completed"

    logger.info("[DarkWeb][analyze] Risk: score=%d, level=%s, factors=%d",
                risk_info["score"], risk_info["level"], len(risk_info["factors"]))

    logger.info("[DarkWeb][analyze] STEP 5/7 — Generate recommendations")

    recommendations = generate_recommendations(breaches, [], risk, normalized, detected_type)
    _debug["recommendations_count"] = len(recommendations)
    _debug["step_recommendations"] = "completed"

    categories = _derive_categories(breaches, normalized)
    analysis = generate_analysis(normalized, detected_type, risk, breaches)

    logger.info("[DarkWeb][analyze] STEP 6/7 — Timeline: first_seen/last_seen")

    first_seen, last_seen = get_dates(breaches)
    _debug["first_seen"] = first_seen
    _debug["last_seen"] = last_seen
    _debug["step_timeline"] = "completed"

    found_classes = set()
    for b in breaches:
        for dc in b.get("data_classes", []):
            found_classes.add(dc)

    logger.info("[DarkWeb][analyze] STEP 7/7 — Calculate confidence")

    confidence = calculate_confidence(breaches)
    _debug["confidence"] = confidence
    _debug["compromised_fields_count"] = len(found_classes)
    _debug["compromised_fields"] = sorted(found_classes)
    _debug["step_confidence"] = "completed"

    total_records = sum(b.get("records", 0) for b in breaches)
    _debug["total_records_exposed"] = total_records

    logger.info("[DarkWeb][analyze] DONE: breaches=%d, risk=%d, confidence=%d%%, first=%s, last=%s, records=%s",
                len(breaches), risk_info["score"], confidence, first_seen, last_seen, f"{total_records:,}")

    resp = {
        "success": True,
        "query": normalized,
        "type": detected_type,
        "data": {
            "risk": risk,
            "confidence": confidence,
            "breaches": breaches,
            "exposure_count": 0,
            "exposures": [],
            "total_records_exposed": total_records,
            "recommendations": recommendations,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "compromised_fields": sorted(found_classes),
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "sources_checked": ["Have I Been Pwned"],
            "categories": categories,
            "analysis": analysis,
        },
    }

    if settings.DEBUG:
        resp["data"]["_debug"] = _debug

    return resp
