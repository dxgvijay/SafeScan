import logging

import requests
from django.conf import settings

logger = logging.getLogger(__name__)
TIMEOUT = 15
BASE = "https://www.virustotal.com/api/v3"


def _api_key():
    key = getattr(settings, "VIRUSTOTAL_API_KEY", "")
    if not key:
        return None
    if key in ("your_api_key_here", "YOUR_VIRUSTOTAL_API_KEY"):
        return None
    return key


def _headers():
    key = _api_key()
    if not key:
        return None
    return {"x-apikey": key, "Accept": "application/json"}


def _handle_response(resp, source_name):
    if resp.status_code == 404:
        return {"name": source_name, "status": "no_data", "data": None, "message": "No intelligence available."}
    if resp.status_code == 429:
        retry = int(resp.headers.get("Retry-After", 60))
        return {"name": source_name, "status": "error", "data": None, "message": f"Rate limited. Retry after {retry}s."}
    if resp.status_code == 401:
        return {"name": source_name, "status": "error", "data": None, "message": "API key invalid or unauthorized."}
    resp.raise_for_status()
    return None


def _build_result(attrs, extra=None):
    stats = attrs.get("last_analysis_stats") or {}
    total = sum(stats.values()) if stats else 0
    result = {
        "stats": {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "total": total,
        },
        "reputation": attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "categories": attrs.get("categories"),
        "tags": attrs.get("tags") or [],
    }
    if extra:
        result.update(extra)
    return result


def check_ip(ip: str) -> dict:
    headers = _headers()
    if not headers:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": "API key not configured"}
    try:
        resp = requests.get(f"{BASE}/ip_addresses/{ip}", headers=headers, timeout=TIMEOUT)
        err = _handle_response(resp, "VirusTotal")
        if err:
            return err
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        return {
            "name": "VirusTotal",
            "status": "found",
            "data": _build_result(attrs, {
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "network": attrs.get("network"),
                "regional_internet_registry": attrs.get("regional_internet_registry"),
                "continent": attrs.get("continent"),
            }),
        }
    except requests.Timeout:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": "Request timed out"}
    except requests.RequestException as e:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": str(e)[:200]}


def check_domain(domain: str) -> dict:
    headers = _headers()
    if not headers:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": "API key not configured"}
    try:
        resp = requests.get(f"{BASE}/domains/{domain}", headers=headers, timeout=TIMEOUT)
        err = _handle_response(resp, "VirusTotal")
        if err:
            return err
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        whois_data = {}
        if attrs.get("whois"):
            import whois as whois_lib
            try:
                w = whois_lib.parser.WhoisEntry(domain, attrs["whois"])
                whois_data = {
                    "registrar": w.registrar,
                    "creation_date": str(w.creation_date[0]) if w.creation_date and isinstance(w.creation_date, list) else str(w.creation_date) if w.creation_date else None,
                    "expiration_date": str(w.expiration_date[0]) if w.expiration_date and isinstance(w.expiration_date, list) else str(w.expiration_date) if w.expiration_date else None,
                }
            except Exception:
                pass
        return {
            "name": "VirusTotal",
            "status": "found",
            "data": _build_result(attrs, {
                "country": attrs.get("country"),
                "registrar": whois_data.get("registrar"),
                "creation_date": whois_data.get("creation_date"),
                "expiration_date": whois_data.get("expiration_date"),
                "popularity_ranks": attrs.get("popularity_ranks"),
            }),
        }
    except requests.Timeout:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": "Request timed out"}
    except requests.RequestException as e:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": str(e)[:200]}


def check_url(url: str) -> dict:
    headers = _headers()
    if not headers:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": "API key not configured"}
    try:
        resp = requests.post(f"{BASE}/urls", headers=headers, data={"url": url}, timeout=TIMEOUT)
        err = _handle_response(resp, "VirusTotal")
        if err:
            return err
        resp.raise_for_status()
        analysis_id = resp.json().get("data", {}).get("id", "")
        if not analysis_id:
            return {"name": "VirusTotal", "status": "error", "data": None, "message": "No analysis ID returned from VirusTotal"}

        result_resp = requests.get(f"{BASE}/analyses/{analysis_id}", headers=headers, timeout=TIMEOUT)
        err = _handle_response(result_resp, "VirusTotal")
        if err:
            return err
        result_resp.raise_for_status()
        attrs = result_resp.json().get("data", {}).get("attributes", {})
        stats = attrs.get("stats") or {}
        total = sum(stats.values()) if stats else 0

        return {
            "name": "VirusTotal",
            "status": "found",
            "data": {
                "stats": {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total": total,
                },
                "reputation": None,
                "last_analysis_date": attrs.get("date"),
                "categories": attrs.get("categories"),
                "tags": attrs.get("tags") or [],
                "analysis_status": attrs.get("status"),
                "url": url,
            },
        }
    except requests.Timeout:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": "Request timed out"}
    except requests.RequestException as e:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": str(e)[:200]}


def check_hash(hash_value: str) -> dict:
    headers = _headers()
    if not headers:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": "API key not configured"}
    try:
        resp = requests.get(f"{BASE}/files/{hash_value}", headers=headers, timeout=TIMEOUT)
        err = _handle_response(resp, "VirusTotal")
        if err:
            return err
        resp.raise_for_status()
        attrs = resp.json().get("data", {}).get("attributes", {})
        return {
            "name": "VirusTotal",
            "status": "found",
            "data": _build_result(attrs, {
                "file_name": attrs.get("meaningful_name") or (attrs.get("names") or [None])[0],
                "file_type": attrs.get("type_description"),
                "file_size": attrs.get("size"),
                "magic": attrs.get("magic"),
                "md5": attrs.get("md5"),
                "sha1": attrs.get("sha1"),
                "sha256": attrs.get("sha256"),
                "first_submission_date": attrs.get("first_submission_date"),
                "last_submission_date": attrs.get("last_submission_date"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "times_submitted": attrs.get("times_submitted"),
                "type_tags": attrs.get("type_tags") or [],
            }),
        }
    except requests.Timeout:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": "Request timed out"}
    except requests.RequestException as e:
        return {"name": "VirusTotal", "status": "error", "data": None, "message": str(e)[:200]}
