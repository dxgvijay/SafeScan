import ipaddress
import logging
import re
import time
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.resolver
import dns.rdatatype
import dns.exception
import dns.name

logger = logging.getLogger(__name__)

QUERY_TIMEOUT = 4
LIFETIME = 8

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "DNSKEY", "RRSIG"]


def validate_domain(target):
    target = (target or "").strip().rstrip(".")
    if not target:
        return None, "Please enter a domain name to look up."
    if len(target) > 253:
        return None, "Domain name too long (max 253 characters)."
    try:
        ipaddress.ip_address(target)
        return None, "That looks like an IP address, not a domain. Use the IP Scanner for IP lookups."
    except ValueError:
        pass
    if not DOMAIN_RE.match(target):
        return None, "Invalid domain format. Please enter a valid hostname (e.g. example.com)."
    return target, None


def _make_resolver():
    resolver = dns.resolver.Resolver()
    resolver.timeout = QUERY_TIMEOUT
    resolver.lifetime = LIFETIME
    return resolver


def _query_records(domain, rtype):
    resolver = _make_resolver()
    result = {"type": rtype, "records": [], "status": "ok", "message": None, "query_ms": 0}
    start = time.time()
    try:
        answers = resolver.resolve(domain, rtype)
        result["query_ms"] = round((time.time() - start) * 1000, 1)

        if rtype == "MX":
            for rdata in answers:
                result["records"].append({
                    "priority": rdata.preference,
                    "exchange": str(rdata.exchange).rstrip("."),
                    "ttl": answers.rrset.ttl if answers.rrset else None,
                })
            result["records"].sort(key=lambda x: x["priority"])
        elif rtype == "SOA":
            for rdata in answers:
                result["records"].append({
                    "mname": str(rdata.mname).rstrip("."),
                    "rname": str(rdata.rname).rstrip("."),
                    "serial": rdata.serial,
                    "refresh": rdata.refresh,
                    "retry": rdata.retry,
                    "expire": rdata.expire,
                    "minimum": rdata.minimum,
                    "ttl": answers.rrset.ttl if answers.rrset else None,
                })
        elif rtype in ("DNSKEY", "RRSIG"):
            for rdata in answers:
                entry = {"flags": rdata.flags, "protocol": rdata.protocol, "algorithm": rdata.algorithm}
                if rtype == "DNSKEY":
                    entry["key_tag"] = rdata.key_tag
                    entry["key_size"] = len(rdata.key) * 8 if hasattr(rdata, "key") else None
                elif rtype == "RRSIG":
                    entry["type_covered"] = dns.rdatatype.to_text(rdata.type_covered)
                    entry["key_tag"] = rdata.key_tag
                    entry["signer"] = str(rdata.signer).rstrip(".")
                    entry["expiration"] = str(rdata.expiration)
                entry["ttl"] = answers.rrset.ttl if answers.rrset else None
                result["records"].append(entry)
        else:
            for rdata in answers:
                val = str(rdata).strip('"')
                result["records"].append({
                    "value": val.rstrip("."),
                    "ttl": answers.rrset.ttl if answers.rrset else None,
                })

    except dns.resolver.NXDOMAIN:
        result["status"] = "nxdomain"
        result["message"] = "Domain does not exist (NXDOMAIN)"
        result["query_ms"] = round((time.time() - start) * 1000, 1)
    except dns.resolver.NoAnswer:
        result["status"] = "no_data"
        result["message"] = f"No {rtype} records found"
        result["query_ms"] = round((time.time() - start) * 1000, 1)
    except dns.resolver.NoNameservers:
        result["status"] = "no_nameservers"
        result["message"] = "All nameservers failed to respond"
        result["query_ms"] = round((time.time() - start) * 1000, 1)
    except dns.resolver.Timeout:
        result["status"] = "timeout"
        result["message"] = f"Query for {rtype} records timed out"
        result["query_ms"] = round((time.time() - start) * 1000, 1)
    except dns.exception.DNSException as e:
        result["status"] = "error"
        result["message"] = f"DNS error: {str(e)[:150]}"
        result["query_ms"] = round((time.time() - start) * 1000, 1)

    return result


def _query_nameservers(domain):
    resolver = _make_resolver()
    result = {"status": "ok", "nameservers": [], "query_ms": 0}
    start = time.time()
    try:
        ns_records = resolver.resolve(domain, "NS")
        result["query_ms"] = round((time.time() - start) * 1000, 1)
        for rdata in ns_records:
            result["nameservers"].append(str(rdata).rstrip("."))
    except Exception:
        result["status"] = "error"
        result["query_ms"] = round((time.time() - start) * 1000, 1)
    return result


def run_dns_lookup(target):
    domain, error = validate_domain(target)
    if error:
        return {"success": False, "error": error}

    scan_start = time.time()
    query_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    results = {
        "success": True,
        "domain": domain,
        "records": {},
        "security": {},
        "nameservers": None,
        "scan_time_ms": 0,
    }

    with ThreadPoolExecutor(max_workers=min(len(query_types), 8)) as pool:
        futures = {pool.submit(_query_records, domain, rt): rt for rt in query_types}
        for future in as_completed(futures):
            rt = futures[future]
            try:
                results["records"][rt] = future.result(timeout=10)
            except concurrent.futures.TimeoutError:
                results["records"][rt] = {"type": rt, "records": [], "status": "timeout", "message": "Query timed out", "query_ms": 0}
            except Exception as e:
                results["records"][rt] = {"type": rt, "records": [], "status": "error", "message": str(e)[:150], "query_ms": 0}

        ns_future = pool.submit(_query_nameservers, domain)
        try:
            results["nameservers"] = ns_future.result(timeout=10)
        except Exception:
            results["nameservers"] = {"status": "error", "nameservers": [], "query_ms": 0}

    dnskey_result = _query_records(domain, "DNSKEY")
    rrsig_result = _query_records(domain, "RRSIG")

    has_dnskey = dnskey_result["status"] == "ok" and len(dnskey_result.get("records", [])) > 0
    has_rrsig = rrsig_result["status"] == "ok" and len(rrsig_result.get("records", [])) > 0

    txt_result = results["records"].get("TXT", {})
    txt_records = [r.get("value", "") for r in txt_result.get("records", [])]
    txt_blob = " ".join(txt_records).lower()

    has_spf = "v=spf1" in txt_blob
    has_dmarc = any("v=dmarc1" in tr.lower() for tr in txt_records)

    has_dkim = False
    for tr in txt_records:
        tl = tr.lower()
        if "v=dkim1" in tl or "k=rsa" in tl or "p=" in tl:
            has_dkim = True
            break

    results["security"] = {
        "dnssec_enabled": has_dnskey and has_rrsig,
        "dnskey_found": has_dnskey,
        "rrsig_found": has_rrsig,
        "spf_found": has_spf,
        "dmarc_found": has_dmarc,
        "dkim_found": has_dkim,
    }

    results["scan_time_ms"] = round((time.time() - scan_start) * 1000, 1)
    return results
