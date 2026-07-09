import logging

import requests

logger = logging.getLogger(__name__)
TIMEOUT = 10
API_URL = "https://threatfox-api.abuse.ch/api/v1/"


def search_indicator(indicator: str) -> dict:
    try:
        resp = requests.post(
            API_URL,
            json={"query": "search_indicator", "indicator": indicator},
            timeout=TIMEOUT,
        )
        if resp.status_code == 429:
            return {"name": "ThreatFox", "status": "error", "data": None, "message": "Rate limited (429)"}
        resp.raise_for_status()
        data = resp.json()
        qs = data.get("query_status", "")
        if qs == "ok" and data.get("data"):
            entries = data["data"]
            families = list(set(e.get("malware", "") for e in entries if e.get("malware")))
            first_seen = min((e.get("first_seen", "") for e in entries if e.get("first_seen")), default=None)
            last_seen = max((e.get("last_seen", "") for e in entries if e.get("last_seen")), default=None)
            return {
                "name": "ThreatFox",
                "status": "found",
                "data": {
                    "malware_families": families[:20],
                    "family_count": len(families),
                    "total_entries": len(entries),
                    "first_seen": first_seen,
                    "last_seen": last_seen,
                    "entries": [
                        {
                            "malware": e.get("malware"),
                            "threat_type": e.get("threat_type"),
                            "first_seen": e.get("first_seen"),
                            "last_seen": e.get("last_seen"),
                            "reporter": e.get("reporter"),
                            "reference": e.get("reference"),
                            "tags": (e.get("tags") or "").split(",") if e.get("tags") else [],
                        }
                        for e in entries[:50]
                    ],
                },
            }
        if qs == "no_result":
            return {"name": "ThreatFox", "status": "no_data", "data": None, "message": "No intelligence available."}
        return {"name": "ThreatFox", "status": "no_data", "data": None, "message": qs}
    except requests.Timeout:
        return {"name": "ThreatFox", "status": "error", "data": None, "message": "Source Unavailable"}
    except requests.RequestException as e:
        return {"name": "ThreatFox", "status": "error", "data": None, "message": "Source Unavailable"}
