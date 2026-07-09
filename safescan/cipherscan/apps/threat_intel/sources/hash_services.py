import logging

import requests
from django.conf import settings

from apps.threat_intel.sources.virustotal import check_hash as vt_check_hash

logger = logging.getLogger(__name__)
TIMEOUT = 15


def check_malwarebazaar(hash_value: str) -> dict:
    api_key = getattr(settings, "MALWAREBAZAAR_API_KEY", "")
    headers = {}
    if api_key:
        headers["API-KEY"] = api_key
    try:
        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": hash_value},
            headers=headers,
            timeout=TIMEOUT,
        )
        if resp.status_code == 401:
            return {"name": "MalwareBazaar", "status": "error", "data": None, "message": "API key required"}
        resp.raise_for_status()
        data = resp.json()
        if data.get("query_status") == "ok" and data.get("data"):
            entry = data["data"][0]
            return {
                "name": "MalwareBazaar",
                "status": "found",
                "data": {
                    "file_name": entry.get("file_name"),
                    "file_type": entry.get("file_type"),
                    "file_size": entry.get("file_size"),
                    "md5": entry.get("md5_hash"),
                    "sha1": entry.get("sha1_hash"),
                    "sha256": entry.get("sha256_hash"),
                    "signature": entry.get("signature"),
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen"),
                    "delivery_method": entry.get("delivery_method"),
                    "tags": (entry.get("tags") or "").split(",") if entry.get("tags") else [],
                    "reporter": entry.get("reporter"),
                    "intelligence": entry.get("intelligence"),
                },
            }
        if data.get("query_status") == "hash_not_found":
            return {"name": "MalwareBazaar", "status": "no_data", "data": None, "message": "Hash not found in MalwareBazaar"}
        return {"name": "MalwareBazaar", "status": "no_data", "data": None, "message": data.get("query_status", "Unknown response")}
    except requests.Timeout:
        return {"name": "MalwareBazaar", "status": "error", "data": None, "message": "Request timed out"}
    except requests.RequestException as e:
        return {"name": "MalwareBazaar", "status": "error", "data": None, "message": str(e)[:200]}
