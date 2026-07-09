import logging
from typing import Optional

import dns.resolver
import whois as whois_lib

logger = logging.getLogger(__name__)


def check_whois(domain: str) -> dict:
    try:
        w = whois_lib.whois(domain)
        creation = None
        if w.creation_date:
            dates = w.creation_date if isinstance(w.creation_date, list) else [w.creation_date]
            creation = str(dates[0]) if dates else None

        expiration = None
        if w.expiration_date:
            dates = w.expiration_date if isinstance(w.expiration_date, list) else [w.expiration_date]
            expiration = str(dates[0]) if dates else None

        updated = None
        if w.updated_date:
            dates = w.updated_date if isinstance(w.updated_date, list) else [w.updated_date]
            updated = str(dates[0]) if dates else None

        name_servers = w.name_servers if isinstance(w.name_servers, list) else (
            [w.name_servers] if w.name_servers else []
        )

        registrar = w.registrar or None
        org = w.org or None
        country = w.country or None
        status_list = w.status if isinstance(w.status, list) else ([w.status] if w.status else [])

        return {
            "name": "WHOIS",
            "status": "found",
            "data": {
                "registrar": registrar,
                "organization": org,
                "country": country,
                "creation_date": creation,
                "expiration_date": expiration,
                "updated_date": updated,
                "name_servers": name_servers[:10],
                "status": status_list[:20],
                "name": w.name or None,
            },
        }
    except Exception as e:
        return {"name": "WHOIS", "status": "error", "data": None, "message": str(e)[:200]}


def resolve_dns_a(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "A", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def resolve_dns_aaaa(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "AAAA", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def resolve_dns_mx(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def resolve_dns_ns(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "NS", lifetime=5)
        return [str(r) for r in answers]
    except Exception:
        return []


def resolve_dns_txt(domain: str) -> list:
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5)
        return ["".join(r.strings) for r in answers]
    except Exception:
        return []


def check_dns(domain: str) -> dict:
    a_records = resolve_dns_a(domain)
    aaaa_records = resolve_dns_aaaa(domain)
    mx_records = resolve_dns_mx(domain)
    ns_records = resolve_dns_ns(domain)
    txt_records = resolve_dns_txt(domain)

    return {
        "name": "DNS",
        "status": "found" if (a_records or aaaa_records or mx_records or ns_records) else "no_data",
        "data": {
            "a": a_records,
            "aaaa": aaaa_records,
            "mx": mx_records,
            "ns": ns_records,
            "txt": txt_records[:20],
            "record_count": {
                "a": len(a_records),
                "aaaa": len(aaaa_records),
                "mx": len(mx_records),
                "ns": len(ns_records),
                "txt": len(txt_records),
            },
        },
    }
