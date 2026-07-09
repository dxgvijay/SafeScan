import logging

import requests

logger = logging.getLogger(__name__)
TIMEOUT = 10
API_URL = "https://urlhaus-api.abuse.ch/v1/url/"


def check_url(url: str) -> dict:
    try:
        resp = requests.post(API_URL, data={"url": url}, timeout=TIMEOUT)
        if resp.status_code == 429:
            return {"name": "URLHaus", "status": "error", "data": None, "message": "Rate limited (429)"}
        resp.raise_for_status()
        data = resp.json()
        qs = data.get("query_status", "")
        if qs == "ok" and data.get("url"):
            return {
                "name": "URLHaus",
                "status": "found",
                "data": {
                    "url": data.get("url"),
                    "host": data.get("host"),
                    "threat": data.get("threat"),
                    "tags": (data.get("tags") or "").split(",") if data.get("tags") else [],
                    "date_added": data.get("date_added"),
                    "last_online": data.get("last_online"),
                    "reporter": data.get("reporter"),
                    "payload": data.get("payload"),
                    "urlhaus_reference": data.get("urlhaus_reference"),
                },
            }
        if qs == "no_results":
            return {"name": "URLHaus", "status": "no_data", "data": None, "message": "No intelligence available."}
        if qs == "invalid_url":
            return {"name": "URLHaus", "status": "no_data", "data": None, "message": "No intelligence available."}
        return {"name": "URLHaus", "status": "no_data", "data": None, "message": qs}
    except requests.Timeout:
        return {"name": "URLHaus", "status": "error", "data": None, "message": "Source Unavailable"}
    except requests.RequestException as e:
        return {"name": "URLHaus", "status": "error", "data": None, "message": "Source Unavailable"}
