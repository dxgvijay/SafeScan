import re
from typing import Optional


def detect_type(value: str) -> Optional[str]:
    v = value.strip()

    if not v:
        return None

    if re.match(
        r"^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$",
        v,
    ):
        return "ipv4"

    if re.match(
        r"^\[?([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\]?$", v
    ) or v.startswith("::"):
        if v.count(":") >= 2:
            return "ipv6"

    if re.match(r"^CVE-\d{4}-\d{4,}$", v, re.IGNORECASE):
        return "cve"

    if re.match(r"^[a-fA-F0-9]{32}$", v):
        return "md5"

    if re.match(r"^[a-fA-F0-9]{40}$", v):
        return "sha1"

    if re.match(r"^[a-fA-F0-9]{64}$", v):
        return "sha256"

    if re.match(r"^https?://", v, re.IGNORECASE):
        return "url"

    if re.match(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$", v
    ):
        return "domain"

    return None


TYPE_LABELS = {
    "ipv4": "IPv4",
    "ipv6": "IPv6",
    "domain": "Domain",
    "url": "URL",
    "md5": "MD5",
    "sha1": "SHA-1",
    "sha256": "SHA-256",
    "cve": "CVE",
}
