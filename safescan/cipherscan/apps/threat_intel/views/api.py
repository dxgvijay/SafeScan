import json
import logging

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from apps.threat_intel.detector import TYPE_LABELS, detect_type
from apps.threat_intel.sources.cve_services import check_nvd
from apps.threat_intel.sources.domain_services import check_dns, check_whois
from apps.threat_intel.sources.executor import run_parallel
from apps.threat_intel.sources.hash_services import check_malwarebazaar
from apps.threat_intel.sources.ip_services import check_abuseipdb, check_ip_api
from apps.threat_intel.sources.threatfox import search_indicator as check_threatfox
from apps.threat_intel.sources.urlhaus import check_url as check_urlhaus
from apps.threat_intel.sources.virustotal import check_domain as vt_check_domain
from apps.threat_intel.sources.virustotal import check_hash as vt_check_hash
from apps.threat_intel.sources.virustotal import check_ip as vt_check_ip
from apps.threat_intel.sources.virustotal import check_url as vt_check_url

logger = logging.getLogger(__name__)


@require_http_methods(["POST"])
@csrf_exempt
def threat_intel_view_api(request):
    try:
        body = json.loads(request.body)
        indicator = (body.get("indicator") or "").strip()
    except (json.JSONDecodeError, AttributeError):
        return JsonResponse({"success": False, "error": "Invalid JSON"}, status=400)

    if not indicator:
        return JsonResponse({"success": False, "error": "Missing 'indicator' field"}, status=400)

    detected_type = detect_type(indicator)
    if not detected_type:
        return JsonResponse(
            {"success": False, "error": "Could not detect indicator type. Supported types: IPv4, IPv6, Domain, URL, MD5, SHA-1, SHA-256, CVE."},
            status=400,
        )

    parallel_checks = []
    timeline = []

    if detected_type in ("ipv4", "ipv6"):
        parallel_checks = [
            ("virustotal", lambda i=indicator: vt_check_ip(i)),
            ("ip_api", lambda i=indicator: check_ip_api(i)),
            ("abuseipdb", lambda i=indicator: check_abuseipdb(i)),
            ("threatfox", lambda i=indicator: check_threatfox(i)),
        ]

    elif detected_type == "domain":
        parallel_checks = [
            ("virustotal", lambda i=indicator: vt_check_domain(i)),
            ("whois", lambda i=indicator: check_whois(i)),
            ("dns", lambda i=indicator: check_dns(i)),
            ("threatfox", lambda i=indicator: check_threatfox(i)),
        ]

    elif detected_type == "url":
        parallel_checks = [
            ("virustotal", lambda i=indicator: vt_check_url(i)),
            ("urlhaus", lambda i=indicator: check_urlhaus(i)),
            ("threatfox", lambda i=indicator: check_threatfox(i)),
        ]

    elif detected_type in ("md5", "sha1", "sha256"):
        parallel_checks = [
            ("virustotal", lambda i=indicator: vt_check_hash(i)),
            ("malwarebazaar", lambda i=indicator: check_malwarebazaar(i)),
            ("threatfox", lambda i=indicator: check_threatfox(i)),
        ]

    elif detected_type == "cve":
        parallel_checks = [
            ("nvd", lambda i=indicator: check_nvd(i)),
        ]

    raw = run_parallel(parallel_checks)
    sources_list = list(raw.values())
    technical = {}
    provenance = {}

    vt_result = raw.get("virustotal", {})

    def set_vt(key, value):
        if value is not None:
            technical[key] = value
            provenance[key] = "VirusTotal"

    if vt_result.get("status") == "found":
        d = vt_result["data"]
        set_vt("vt_stats", d.get("stats"))
        set_vt("vt_reputation", d.get("reputation"))
        set_vt("vt_last_analysis", d.get("last_analysis_date"))
        set_vt("vt_categories", d.get("categories"))
        set_vt("vt_tags", d.get("tags"))

        if detected_type in ("ipv4", "ipv6"):
            if d.get("country"):
                set_vt("country", d["country"])
            if d.get("asn"):
                set_vt("asn", f"AS{d['asn']}" if isinstance(d["asn"], (int, float)) else d["asn"])
            if d.get("network"):
                set_vt("network", d["network"])

        elif detected_type == "domain":
            if d.get("country"):
                set_vt("country", d["country"])
            if d.get("registrar"):
                set_vt("registrar", d["registrar"])
            if d.get("creation_date"):
                set_vt("creation_date", d["creation_date"])
            if d.get("expiration_date"):
                set_vt("expiration_date", d["expiration_date"])

        elif detected_type in ("md5", "sha1", "sha256"):
            for k in ("file_name", "file_type", "file_size", "magic", "md5", "sha1", "sha256"):
                if d.get(k) is not None:
                    set_vt(k, d[k])

        elif detected_type == "url":
            if d.get("analysis_status"):
                set_vt("vt_analysis_status", d["analysis_status"])

    def _deep_get(d, key):
        if isinstance(key, tuple):
            val = d
            for k in key:
                if isinstance(val, dict):
                    val = val.get(k)
                else:
                    return None
            return val
        return d.get(key)

    def set_from(prefix, result, key_map):
        if result.get("status") != "found":
            return
        d = result.get("data", {})
        for vt_key, src_key in key_map.items():
            if vt_key not in technical and _deep_get(d, src_key) is not None:
                technical[vt_key] = _deep_get(d, src_key)
                provenance[vt_key] = prefix

    if detected_type in ("ipv4", "ipv6"):
        ip_api = raw.get("ip_api", {})
        set_from("ip-api.com", ip_api, {
            "isp": "isp", "organization": "org", "city": "city",
            "country": "country", "region": "region", "asn": "asn",
            "timezone": "timezone", "lat": "lat", "lon": "lon",
            "proxy": "proxy", "hosting": "hosting", "mobile": "mobile",
        })

        abuse = raw.get("abuseipdb", {})
        set_from("AbuseIPDB", abuse, {
            "abuse_confidence_score": "abuse_confidence_score",
            "total_reports": "total_reports", "usage_type": "usage_type",
            "isp": "isp",
        })

        thf = raw.get("threatfox", {})
        set_from("ThreatFox", thf, {
            "threatfox_malware_families": "malware_families",
            "threatfox_first_seen": "first_seen",
            "threatfox_last_seen": "last_seen",
        })

    elif detected_type == "domain":
        whois = raw.get("whois", {})
        set_from("WHOIS", whois, {
            "registrar": "registrar", "organization": "organization",
            "country": "country", "creation_date": "creation_date",
            "expiration_date": "expiration_date", "name_servers": "name_servers",
        })
        dns = raw.get("dns", {})
        set_from("DNS", dns, {
            "dns_a": "a", "dns_aaaa": "aaaa", "dns_mx": "mx",
            "dns_ns": "ns", "dns_record_count": "record_count",
        })
        thf = raw.get("threatfox", {})
        set_from("ThreatFox", thf, {
            "threatfox_malware_families": "malware_families",
            "threatfox_first_seen": "first_seen",
            "threatfox_last_seen": "last_seen",
        })

    elif detected_type == "url":
        urlh = raw.get("urlhaus", {})
        set_from("URLHaus", urlh, {
            "urlhaus_threat": "threat", "urlhaus_tags": "tags",
            "urlhaus_date_added": "date_added",
            "urlhaus_last_online": "last_online",
        })
        thf = raw.get("threatfox", {})
        set_from("ThreatFox", thf, {
            "threatfox_malware_families": "malware_families",
            "threatfox_first_seen": "first_seen",
        })

    elif detected_type in ("md5", "sha1", "sha256"):
        mb = raw.get("malwarebazaar", {})
        set_from("MalwareBazaar", mb, {
            "file_name": "file_name", "file_type": "file_type",
            "file_size": "file_size", "signature": "signature",
            "md5": "md5", "sha1": "sha1", "sha256": "sha256",
        })
        thf = raw.get("threatfox", {})
        set_from("ThreatFox", thf, {
            "threatfox_malware_families": "malware_families",
            "threatfox_first_seen": "first_seen",
        })

    elif detected_type == "cve":
        nvd = raw.get("nvd", {})
        set_from("NVD", nvd, {
            "cvss_score": ("cvss", "score"), "cvss_severity": ("cvss", "severity"),
            "cvss_vector": ("cvss", "vector"), "cwes": "cwes",
            "published": "published", "last_modified": "last_modified",
            "vuln_status": "vuln_status", "cve_description": "description",
            "references": "references",
        })
        if nvd.get("status") == "found":
            nd = nvd["data"]
            if nd.get("published"):
                timeline.append({"date": nd["published"], "event": "CVE published"})
            if nd.get("last_modified") and nd.get("last_modified") != nd.get("published"):
                timeline.append({"date": nd["last_modified"], "event": "CVE last modified"})

    if detected_type == "domain":
        whois = raw.get("whois", {})
        if whois.get("status") == "found" and whois.get("data", {}).get("creation_date"):
            timeline.append({"date": whois["data"]["creation_date"], "event": "Domain registered"})

    for dt in ("md5", "sha1", "sha256"):
        if detected_type == dt:
            mb = raw.get("malwarebazaar", {})
            if mb.get("status") == "found" and mb.get("data", {}).get("first_seen"):
                timeline.append({"date": mb["data"]["first_seen"], "event": "First seen on MalwareBazaar"})

    reputation = build_reputation(sources_list, detected_type)
    overview = {
        "indicator": indicator,
        "type_label": TYPE_LABELS.get(detected_type, detected_type.upper()),
        "first_seen": timeline[0]["date"] if timeline else None,
        "last_seen": timeline[-1]["date"] if len(timeline) > 1 else (timeline[0]["date"] if timeline else None),
    }
    recommendations = build_recommendations(sources_list, detected_type, indicator)

    return JsonResponse({
        "success": True,
        "indicator": indicator,
        "type": detected_type,
        "data": {
            "overview": overview,
            "reputation": reputation,
            "sources": sources_list,
            "timeline": timeline,
            "technical": technical,
            "provenance": provenance,
            "recommendations": recommendations,
        },
    })


def build_reputation(sources, detected_type):
    for src in sources:
        if src["name"] == "VirusTotal" and src.get("status") == "found":
            stats = src.get("data", {}).get("stats", {})
            malicious = stats.get("malicious", 0)
            total = stats.get("total", 1) or 1
            if malicious > 0:
                score = int((malicious / total) * 100)
                verdict = "malicious" if score >= 50 else "suspicious"
            else:
                score = 0
                verdict = "safe"
            return {"score": score, "verdict": verdict, "details": f"VirusTotal: {malicious}/{total} vendors flagged as malicious."}

    for src in sources:
        if src["name"] == "AbuseIPDB" and src.get("status") == "found":
            s = src.get("data", {}).get("abuse_confidence_score", 0)
            v = "malicious" if s >= 50 else ("suspicious" if s >= 25 else "safe")
            return {"score": s, "verdict": v, "details": f"AbuseIPDB confidence score: {s}/100."}

        if src["name"] == "MalwareBazaar" and src.get("status") == "found":
            return {"score": 100, "verdict": "malicious", "details": "This hash is associated with known malware in MalwareBazaar."}

        if src["name"] == "NVD" and src.get("status") == "found":
            cvss = src.get("data", {}).get("cvss", {})
            s = cvss.get("score")
            if s is not None:
                v = "critical" if s >= 9.0 else ("high" if s >= 7.0 else ("medium" if s >= 4.0 else "low"))
                return {"score": s, "verdict": v, "details": f"CVSS score: {s}."}

        if src["name"] == "ThreatFox" and src.get("status") == "found":
            fams = src.get("data", {}).get("malware_families", [])
            if fams:
                return {"score": 75, "verdict": "malicious", "details": f"ThreatFox: associated with {len(fams)} malware families ({', '.join(fams[:3])})."}

        if src["name"] == "URLHaus" and src.get("status") == "found":
            threat = src.get("data", {}).get("threat", "")
            return {"score": 70, "verdict": "malicious", "details": f"URLHaus: {threat}" if threat else "URLHaus: listed as malicious."}

    return {"score": None, "verdict": "unknown", "details": "No threat intelligence data available for this indicator."}


def build_recommendations(sources, detected_type, indicator):
    recs = []
    error_count = sum(1 for s in sources if s.get("status") == "error")
    vt_found = any(s.get("name") == "VirusTotal" and s.get("status") == "found" for s in sources)

    if error_count > 0:
        recs.append({"icon": "\u26a0\ufe0f", "text": "Some threat intelligence sources could not be reached. Consider retrying the analysis later."})

    if vt_found:
        recs.append({"icon": "\ud83d\udccb", "text": "Cross-reference this data with your internal logs and SIEM for any related events."})
    else:
        recs.append({"icon": "\ud83d\udd0d", "text": "Run this indicator through a secondary threat intelligence feed for cross-validation."})

    templates = {
        ("md5", "sha1", "sha256"): "\ud83d\udee1\ufe0f Consider adding this file hash to your blocklist if it poses a confirmed threat to your environment.",
        ("ipv4", "ipv6"): "\ud83d\udee1\ufe0f Monitor network traffic for any communication with this IP address. Consider blocking if malicious activity is confirmed.",
        ("domain",): "\ud83d\udee1\ufe0f Review DNS logs for any queries to this domain. Consider adding to blocklist if confirmed malicious.",
        ("url",): "\ud83d\udee1\ufe0f Block this URL at the proxy/gateway level if confirmed malicious. Check access logs for any users who may have visited it.",
        ("cve",): "\ud83d\udd27 Check if this CVE affects any software in your environment. Apply patches or mitigations as recommended by the vendor.",
    }
    for types, msg in templates.items():
        if detected_type in types:
            recs.append({"icon": msg[:2], "text": msg[2:]})

    if detected_type == "cve":
        recs.append({"icon": "\ud83d\udccb", "text": "Review your asset inventory for vulnerable versions and prioritize patching based on CVSS score."})

    recs.append({"icon": "\ud83d\udd04", "text": "Re-run this analysis periodically as threat intelligence databases are updated continuously."})
    return recs
