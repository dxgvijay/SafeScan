import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)
TIMEOUT = 10


def check_ip_api(ip: str) -> dict:
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,lat,lon,timezone,zip,query,mobile,proxy,hosting",
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "success":
            return {
                "name": "ip-api.com",
                "status": "found",
                "data": {
                    "country": data.get("country"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as", "").split(" ")[0] if data.get("as") else None,
                    "as_org": data.get("as", ""),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "proxy": data.get("proxy", False),
                    "hosting": data.get("hosting", False),
                    "mobile": data.get("mobile", False),
                },
            }
        return {"name": "ip-api.com", "status": "no_data", "data": None, "message": "Lookup failed"}
    except requests.Timeout:
        return {"name": "ip-api.com", "status": "error", "data": None, "message": "Request timed out"}
    except requests.RequestException as e:
        return {"name": "ip-api.com", "status": "error", "data": None, "message": str(e)[:200]}


def check_abuseipdb(ip: str) -> dict:
    api_key = getattr(settings, "ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {"name": "AbuseIPDB", "status": "error", "data": None, "message": "API key not configured"}
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        if data:
            score = data.get("abuseConfidenceScore", 0)
            return {
                "name": "AbuseIPDB",
                "status": "found" if score > 0 else "no_data",
                "data": {
                    "abuse_confidence_score": score,
                    "total_reports": data.get("totalReports", 0),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "country": data.get("countryCode"),
                    "usage_type": data.get("usageType"),
                    "last_reported_at": data.get("lastReportedAt"),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "is_tor": data.get("isTor", False),
                },
            }
        return {"name": "AbuseIPDB", "status": "no_data", "data": None, "message": "No reports found"}
    except requests.Timeout:
        return {"name": "AbuseIPDB", "status": "error", "data": None, "message": "Request timed out"}
    except requests.RequestException as e:
        status_code = getattr(e.response, "status_code", None) if hasattr(e, "response") else None
        if status_code == 429:
            return {"name": "AbuseIPDB", "status": "error", "data": None, "message": "Rate limited (429)"}
        return {"name": "AbuseIPDB", "status": "error", "data": None, "message": str(e)[:200]}
