"""
destinations.py — Extract and classify network destinations in TDL source.

A URL on its own says little; *where* it points says a lot. This module pulls
every http(s) host out of the text (raw or decoded) and buckets it:

    allowlisted      - a host the reviewer has explicitly trusted (config/CLI)
    private          - localhost / RFC1918 / link-local / bare hostname / *.local
                       (a sync server on the LAN — usually not exfiltration)
    unknown-internet - a public host nobody vouched for  --> escalate

The classification feeds confidence scoring: a network finding pointing at an
unknown public host is worse than one pointing at 127.0.0.1.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


URL_RE = re.compile(r"(?:https?|ftps?)://([^/\s\"'<>:\\]+)(?::(\d+))?", re.IGNORECASE)

PRIVATE_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".test", ".invalid")

CLASS_ALLOWLISTED = "allowlisted"
CLASS_PRIVATE = "private"
CLASS_UNKNOWN = "unknown-internet"


@dataclass(frozen=True)
class Destination:
    host: str
    url: str
    classification: str
    loopback: bool = False


def is_loopback(host: str) -> bool:
    """Strictly this-machine addresses (localhost / 127.x / ::1)."""
    h = host.lower().strip().strip("[]").rstrip(".")
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


def _matches_allowlist(host: str, allowlist) -> bool:
    host = host.lower()
    for a in allowlist:
        a = a.lower().strip()
        if not a:
            continue
        if host == a or host.endswith("." + a):
            return True
    return False


def _is_private_host(host: str) -> bool:
    h = host.lower().strip().rstrip(".")
    if not h:
        return False
    if h == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(h)
        return (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_unspecified or ip.is_reserved)
    except ValueError:
        pass
    if any(h.endswith(sfx) for sfx in PRIVATE_SUFFIXES):
        return True
    if "." not in h:          # bare hostname → resolved on the local network
        return True
    return False


def classify_host(host: str, allowlist=frozenset()) -> str:
    if _matches_allowlist(host, allowlist):
        return CLASS_ALLOWLISTED
    if _is_private_host(host):
        return CLASS_PRIVATE
    return CLASS_UNKNOWN


def classify_url(url: str, allowlist=frozenset()) -> Destination | None:
    m = URL_RE.search(url)
    if not m:
        return None
    host = m.group(1).lower()
    return Destination(host, m.group(0), classify_host(host, allowlist), is_loopback(host))


def extract_destinations(text: str, allowlist=frozenset()) -> list[Destination]:
    """All unique destinations in the text, in first-seen order."""
    seen: set[str] = set()
    out: list[Destination] = []
    for m in URL_RE.finditer(text):
        url = m.group(0)
        if url in seen:
            continue
        seen.add(url)
        host = m.group(1).lower()
        out.append(Destination(host, url, classify_host(host, allowlist), is_loopback(host)))
    return out
