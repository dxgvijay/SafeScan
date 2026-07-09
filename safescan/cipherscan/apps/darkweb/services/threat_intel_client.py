import logging

import requests

logger = logging.getLogger(__name__)

THREAT_INTEL_URL = "http://localhost:8000/api/threat-intel/"
REQUEST_TIMEOUT = 8


def _extract_domain(asset: str, asset_type: str) -> str | None:
    if asset_type == "domain":
        return asset.strip().lower()
    if asset_type == "email":
        return asset.strip().lower().split("@")[-1]
    return None


class ThreatIntelClient:
    def __init__(self, endpoint_url: str = THREAT_INTEL_URL, timeout: int = REQUEST_TIMEOUT):
        self.endpoint_url = endpoint_url
        self.timeout = timeout

    def query(self, indicator: str) -> dict | None:
        try:
            resp = requests.post(
                self.endpoint_url,
                json={"indicator": indicator},
                timeout=self.timeout,
                headers={"User-Agent": "SafeScan-DarkWeb/1.0"},
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("success"):
                    return data
            logger.debug("ThreatIntel returned status %s for %s", resp.status_code, indicator)
            return None
        except requests.ConnectionError:
            logger.debug("ThreatIntel service unreachable for %s", indicator)
            return None
        except requests.Timeout:
            logger.debug("ThreatIntel query timed out for %s", indicator)
            return None
        except Exception as exc:
            logger.warning("ThreatIntel query failed for %s: %s", indicator, exc)
            return None

    def extract_related_intel(self, asset: str, asset_type: str) -> dict:
        domain = _extract_domain(asset, asset_type)
        if not domain:
            return {"available": False}

        raw = self.query(domain)
        if not raw:
            return {"available": False}

        data = raw.get("data", {})
        technical = data.get("technical", {})
        reputation = data.get("reputation", {})
        sources = data.get("sources", [])

        out: dict = {
            "available": True,
            "domain": domain,
        }

        # Domain Reputation
        out["domain_reputation"] = {
            "verdict": reputation.get("verdict", "unknown"),
            "score": reputation.get("score"),
            "details": reputation.get("details", ""),
        }

        # IOC Matches
        ioc_matches = []
        for s in sources:
            if s.get("status") == "found":
                ioc_matches.append({
                    "source": s.get("name", "Unknown"),
                    "summary": s.get("message", "Data found"),
                })

        vt_stats = technical.get("vt_stats", {})
        if vt_stats:
            mal = vt_stats.get("malicious", 0)
            sus = vt_stats.get("suspicious", 0)
            if mal > 0 or sus > 0:
                if not any(m["source"] == "VirusTotal" for m in ioc_matches):
                    ioc_matches.append({
                        "source": "VirusTotal",
                        "summary": f"{mal} malicious, {sus} suspicious out of {vt_stats.get('total', 0)} engines ({vt_stats.get('undetected', 0)} undetected)",
                    })

        abuse_score = technical.get("abuse_confidence_score")
        if abuse_score is not None and abuse_score > 0:
            if not any("AbuseIPDB" in m["source"] for m in ioc_matches):
                ioc_matches.append({
                    "source": "AbuseIPDB",
                    "summary": f"Abuse confidence score: {abuse_score}/100 ({technical.get('total_reports', 0)} reports)",
                })

        threatfox_families = technical.get("threatfox_malware_families", [])
        if threatfox_families:
            if not any("ThreatFox" in m["source"] for m in ioc_matches):
                ioc_matches.append({
                    "source": "ThreatFox",
                    "summary": f"{len(threatfox_families)} malware familie(s): {', '.join(threatfox_families[:5])}",
                })

        if technical.get("signature"):
            if not any("MalwareBazaar" in m["source"] for m in ioc_matches):
                ioc_matches.append({
                    "source": "MalwareBazaar",
                    "summary": f"Signature: {technical['signature']}",
                })

        if technical.get("urlhaus_threat"):
            if not any("URLHaus" in m["source"] for m in ioc_matches):
                ioc_matches.append({
                    "source": "URLHaus",
                    "summary": f"Threat: {technical['urlhaus_threat']}",
                })

        out["ioc_matches"] = ioc_matches

        # Known Campaigns
        campaigns = []
        if threatfox_families:
            campaigns.append({
                "source": "ThreatFox",
                "name": ", ".join(threatfox_families[:5]),
                "first_seen": technical.get("threatfox_first_seen", ""),
                "last_seen": technical.get("threatfox_last_seen", ""),
            })
        if technical.get("urlhaus_threat"):
            campaigns.append({
                "source": "URLHaus",
                "name": technical["urlhaus_threat"],
                "tags": technical.get("urlhaus_tags", []),
            })
        if technical.get("cve_description"):
            campaigns.append({
                "source": "NVD",
                "name": f"CVE: {technical.get('cve_id', 'Unknown')}",
                "description": technical["cve_description"][:200],
            })
        out["known_campaigns"] = campaigns

        # Malware Association
        out["malware_association"] = {
            "detected": len(threatfox_families) > 0 or bool(technical.get("signature")),
            "families": threatfox_families[:10],
            "malwarebazaar_signature": technical.get("signature"),
            "total_malicious_vt": vt_stats.get("malicious", 0) if vt_stats else 0,
        }

        # Threat Score
        threat_score = None
        if reputation.get("score") is not None:
            threat_score = {
                "score": reputation["score"],
                "verdict": reputation.get("verdict", "unknown"),
                "source": "VirusTotal / Aggregate",
            }
        elif abuse_score is not None:
            threat_score = {
                "score": abuse_score,
                "verdict": "malicious" if abuse_score >= 50 else "suspicious" if abuse_score >= 25 else "low",
                "source": "AbuseIPDB",
            }
        if vt_stats:
            mal = vt_stats.get("malicious", 0)
            total = vt_stats.get("total", 1)
            vt_score = int((mal / total) * 100) if total > 0 else 0
            if not threat_score or vt_score > threat_score.get("score", 0):
                threat_score = {
                    "score": vt_score,
                    "verdict": "malicious" if vt_score >= 50 else "suspicious" if vt_score > 0 else "safe",
                    "source": "VirusTotal",
                }
        out["threat_score"] = threat_score

        # MITRE ATT&CK
        out["mitre_attack"] = {
            "available": False,
        }

        return out
