import ipaddress
import logging
import socket
import time
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

IP_API_TIMEOUT = 5
ABUSEIPDB_TIMEOUT = 5
WHOIS_TIMEOUT = 10
PORT_TIMEOUT = 0.7

SAFE_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    3306, 3389, 8080,
]

PORT_SERVICE_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-Proxy",
}


def validate_and_resolve_input(target):
    target = (target or "").strip()
    if not target:
        return None, None, None, "Please enter an IP address or hostname."

    if len(target) > 253:
        return None, None, None, "Input too long (max 253 characters)."

    try:
        addr = ipaddress.ip_address(target)
        return str(addr), "ip", target, None
    except ValueError:
        pass

    try:
        resolved = socket.gethostbyname(target)
        return resolved, "hostname", target, None
    except socket.gaierror:
        return None, None, None, f"Could not resolve hostname: {target}"


def check_private_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_loopback:
            return True, "Loopback address (127.x.x.x / ::1)"
        if addr.is_private:
            return True, "Private/reserved IP (RFC 1918) — external lookups skipped"
        if addr.is_reserved:
            return True, "Reserved address range"
        if addr.is_link_local:
            return True, "Link-local address (169.254.x.x / fe80::)"
        if addr.is_multicast:
            return True, "Multicast address"
        return False, None
    except ValueError:
        return False, None


def scan_geolocation(ip):
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": "status,country,regionName,city,isp,org,as,lat,lon,timezone,zip,query,mobile,proxy,hosting"
            },
            timeout=IP_API_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json()
        if data.get("status") == "success":
            return {
                "status": "ok",
                "country": data.get("country"),
                "region": data.get("regionName"),
                "city": data.get("city"),
                "isp": data.get("isp"),
                "org": data.get("org"),
                "asn": data.get("as", ""),
                "latitude": data.get("lat"),
                "longitude": data.get("lon"),
                "timezone": data.get("timezone"),
                "zip_code": data.get("zip"),
                "is_proxy": data.get("proxy", False),
                "is_hosting": data.get("hosting", False),
                "is_mobile": data.get("mobile", False),
            }
        return {"status": "error", "message": "Geolocation lookup failed"}
    except requests.Timeout:
        return {"status": "error", "message": "Geolocation API timed out"}
    except requests.RequestException as e:
        return {"status": "error", "message": f"Geolocation error: {str(e)[:100]}"}


def scan_reverse_dns(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return {"status": "ok", "hostname": hostname}
    except socket.herror:
        return {"status": "not_found", "message": "No PTR record found"}
    except socket.gaierror:
        return {"status": "not_found", "message": "Reverse DNS lookup failed"}
    except Exception as e:
        return {"status": "error", "message": str(e)[:100]}


def scan_whois(ip):
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        result = obj.lookup_rdap(
            timeout=WHOIS_TIMEOUT,
            allow_permutations=False,
        )
        network = result.get("network", {})
        objects = result.get("objects", {})

        org_name = None
        contact = result.get("entities", {})
        if contact:
            for entity_key in contact:
                entity = contact[entity_key]
                if isinstance(entity, dict):
                    vcard = entity.get("vcard", [])
                    if isinstance(vcard, list) and len(vcard) > 0:
                        if isinstance(vcard[0], list) and len(vcard[0]) > 1:
                            org_name = vcard[0][3]
                            break

        if not org_name:
            for key, obj_data in objects.items():
                if isinstance(obj_data, dict):
                    roles = obj_data.get("roles", [])
                    if "registrant" in roles or "org" in roles:
                        vcard = obj_data.get("vcard", [])
                        if isinstance(vcard, list) and len(vcard) > 0:
                            if isinstance(vcard[0], list) and len(vcard[0]) > 1:
                                org_name = vcard[0][3]
                                break

        return {
            "status": "ok",
            "network_name": network.get("name"),
            "cidr": network.get("cidr"),
            "country": network.get("country"),
            "org_name": org_name or network.get("name"),
            "registration_date": network.get("events", [{}])[0].get("date") if network.get("events") else None,
            "asn": result.get("asn"),
            "asn_description": result.get("asn_description"),
            "asn_country": result.get("asn_country_code"),
            "asn_registry": result.get("asn_registry"),
            "asn_date": result.get("asn_date"),
        }
    except ImportError:
        return {"status": "error", "message": "ipwhois package not installed"}
    except Exception as e:
        msg = str(e)[:200]
        return {"status": "error", "message": f"WHOIS lookup failed: {msg}"}


def _scan_single_port(ip, port, timeout):
    result = {"port": port, "state": "closed", "service": PORT_SERVICE_NAMES.get(port, "unknown"), "latency_ms": None}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        start = time.time()
        code = s.connect_ex((ip, port))
        elapsed = round((time.time() - start) * 1000, 1)
        result["latency_ms"] = elapsed

        if code == 0:
            result["state"] = "open"
        elif code == socket.errno.ECONNREFUSED:
            result["state"] = "closed"
        elif code in (socket.errno.EHOSTUNREACH, socket.errno.ENETUNREACH, socket.errno.ETIMEDOUT):
            result["state"] = "filtered"
        else:
            result["state"] = "filtered"

        s.close()
    except socket.timeout:
        result["state"] = "filtered"
    except (OSError, ConnectionError):
        result["state"] = "filtered"

    return result


def scan_ports(ip, ports=None, timeout=PORT_TIMEOUT, max_time=8):
    if ports is None:
        ports = SAFE_SCAN_PORTS

    start = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=min(len(ports), 15)) as pool:
        future_map = {pool.submit(_scan_single_port, ip, p, timeout): p for p in ports}
        for future in as_completed(future_map):
            if time.time() - start > max_time:
                break
            try:
                results.append(future.result())
            except Exception:
                pass

    results.sort(key=lambda r: r["port"])
    open_count = sum(1 for r in results if r["state"] == "open")
    closed_count = sum(1 for r in results if r["state"] == "closed")
    filtered_count = sum(1 for r in results if r["state"] == "filtered")

    return {
        "status": "ok",
        "results": results,
        "open_count": open_count,
        "closed_count": closed_count,
        "filtered_count": filtered_count,
        "total_scanned": len(results),
        "duration_ms": round((time.time() - start) * 1000, 1),
    }


def scan_abuse_check(ip):
    api_key = getattr(settings, "ABUSEIPDB_API_KEY", "")
    if not api_key:
        return {
            "status": "unavailable",
            "message": "AbuseIPDB API key not configured. Add ABUSEIPDB_API_KEY to your .env file.",
        }
    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": True},
            timeout=ABUSEIPDB_TIMEOUT,
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        if data:
            score = data.get("abuseConfidenceScore", 0)
            return {
                "status": "ok",
                "abuse_confidence_score": score,
                "total_reports": data.get("totalReports", 0),
                "is_whitelisted": data.get("isWhitelisted", False),
                "is_tor": data.get("isTor", False),
                "usage_type": data.get("usageType"),
                "domain": data.get("domain"),
                "isp": data.get("isp"),
                "country_code": data.get("countryCode"),
                "last_reported_at": data.get("lastReportedAt"),
                "verdict": "malicious" if score >= 50 else ("suspicious" if score >= 25 else "clean"),
            }
        return {"status": "ok", "abuse_confidence_score": 0, "verdict": "clean", "message": "No reports found"}
    except requests.Timeout:
        return {"status": "error", "message": "AbuseIPDB API timed out"}
    except requests.RequestException as e:
        status_code = getattr(e.response, "status_code", None) if hasattr(e, "response") else None
        if status_code == 429:
            return {"status": "error", "message": "AbuseIPDB rate limited. Try again later."}
        return {"status": "error", "message": f"AbuseIPDB error: {str(e)[:100]}"}


def run_full_scan(target):
    ip, input_type, original_input, error = validate_and_resolve_input(target)
    if error:
        return {"success": False, "error": error}

    is_private, private_reason = check_private_ip(ip)

    results = {
        "success": True,
        "input": original_input,
        "resolved_ip": ip,
        "input_type": input_type,
        "is_private": is_private,
        "private_reason": private_reason,
        "geolocation": None,
        "reverse_dns": None,
        "whois": None,
        "ports": None,
        "abuse_check": None,
        "scan_time_ms": 0,
    }

    if is_private:
        results["geolocation"] = {"status": "skipped", "message": private_reason}
        results["reverse_dns"] = {"status": "skipped", "message": private_reason}
        results["whois"] = {"status": "skipped", "message": private_reason}
        results["ports"] = {"status": "skipped", "message": private_reason}
        results["abuse_check"] = {"status": "skipped", "message": private_reason}
        return results

    scan_start = time.time()

    with ThreadPoolExecutor(max_workers=5) as pool:
        geo_future = pool.submit(scan_geolocation, ip)
        rdns_future = pool.submit(scan_reverse_dns, ip)
        whois_future = pool.submit(scan_whois, ip)
        ports_future = pool.submit(scan_ports, ip)
        abuse_future = pool.submit(scan_abuse_check, ip)

        futures = {
            "geolocation": geo_future,
            "reverse_dns": rdns_future,
            "whois": whois_future,
            "ports": ports_future,
            "abuse_check": abuse_future,
        }

        for key, future in futures.items():
            try:
                results[key] = future.result(timeout=15)
            except concurrent.futures.TimeoutError:
                results[key] = {"status": "error", "message": f"{key.replace('_', ' ').title()} timed out"}
            except Exception as e:
                results[key] = {"status": "error", "message": str(e)[:200]}

    results["scan_time_ms"] = round((time.time() - scan_start) * 1000, 1)
    return results
