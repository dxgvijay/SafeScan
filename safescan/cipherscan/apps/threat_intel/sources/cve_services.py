import logging

import requests

logger = logging.getLogger(__name__)
TIMEOUT = 10
NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def check_nvd(cve_id: str) -> dict:
    try:
        resp = requests.get(
            NVD_BASE,
            params={"cveId": cve_id.upper()},
            timeout=TIMEOUT,
        )
        if resp.status_code == 404:
            return {"name": "NVD", "status": "no_data", "data": None, "message": "CVE not found in NVD"}
        if resp.status_code == 403:
            return {"name": "NVD", "status": "error", "data": None, "message": "Rate limited (403)"}
        resp.raise_for_status()
        body = resp.json()
        vulns = body.get("vulnerabilities", [])
        if not vulns:
            return {"name": "NVD", "status": "no_data", "data": None, "message": "No data returned from NVD"}
        cve_data = vulns[0].get("cve", {})
        metrics = cve_data.get("metrics", {})

        cvss_scores = {}
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_scores = {
                    "version": cvss_data.get("version"),
                    "score": cvss_data.get("baseScore"),
                    "severity": cvss_data.get("baseSeverity"),
                    "vector": cvss_data.get("vectorString"),
                    "attack_vector": cvss_data.get("attackVector"),
                    "attack_complexity": cvss_data.get("attackComplexity"),
                    "privileges_required": cvss_data.get("privilegesRequired"),
                    "user_interaction": cvss_data.get("userInteraction"),
                    "scope": cvss_data.get("scope"),
                    "confidentiality": cvss_data.get("confidentialityImpact"),
                    "integrity": cvss_data.get("integrityImpact"),
                    "availability": cvss_data.get("availabilityImpact"),
                    "exploitability_score": metric_list[0].get("exploitabilityScore"),
                    "impact_score": metric_list[0].get("impactScore"),
                }
                break

        descriptions = cve_data.get("descriptions", [])
        description = None
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value")
                break
        if not description and descriptions:
            description = descriptions[0].get("value")

        references = cve_data.get("references", [])
        refs = [{"source": r.get("source"), "url": r.get("url"), "tags": r.get("tags")} for r in references[:20]]

        weaknesses = cve_data.get("weaknesses", [])
        cwes = []
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("value"):
                    cwes.append(d["value"])

        return {
            "name": "NVD",
            "status": "found",
            "data": {
                "id": cve_data.get("id"),
                "description": description,
                "published": cve_data.get("published"),
                "last_modified": cve_data.get("lastModified"),
                "vuln_status": cve_data.get("vulnStatus"),
                "cvss": cvss_scores,
                "cwes": cwes[:10],
                "references": refs[:20],
                "source_identifier": cve_data.get("sourceIdentifier"),
            },
        }
    except requests.Timeout:
        return {"name": "NVD", "status": "error", "data": None, "message": "Request timed out"}
    except requests.RequestException as e:
        return {"name": "NVD", "status": "error", "data": None, "message": str(e)[:200]}
