"""
egress.py — "Data Leaving the Machine" report.

The scanner's detection engine finds *where* sensitive data is read and *where*
it can be sent. This module turns those findings into the headline a human can
actually decide on: one plain-language statement per egress —

    [what confidential data]  →  [which channel]  →  [which destination]
    (external / internal / unverifiable), [trigger].

The reviewer then makes a yes/no call: is it OK for THIS data to go THERE?

Destination states, in order of concern:
    external   — a named outside destination (unknown host / hard-coded address)
    unknown    — built at runtime; we could NOT verify where it goes (most suspicious)
    internal   — loopback/localhost, or an allowlisted/known destination
    dynamic    — a recipient chosen from data at runtime (e.g. the customer's own
                 email) — the normal, legitimate pattern
    local file — written to a file on this disk
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from dataflow import find_blocks, block_for_line
from destinations import URL_RE, classify_host, is_loopback, CLASS_UNKNOWN

SINK_CATEGORIES = {"network", "email", "db-export", "network-share",
                   "filesystem", "code-exec"}

CHANNEL_LABELS = {
    "network": "the internet",
    "email": "email",
    "db-export": "an external database",
    "network-share": "a network share",
    "filesystem": "a file",
    "code-exec": "an external program",
}

LOCATION_PHRASE = {
    "external": "an EXTERNAL destination",
    "unknown": "a destination we could NOT verify (built at runtime)",
    "internal": "an internal/known destination",
    "dynamic": "a recipient chosen at runtime (e.g. the customer)",
    "local file": "a file on this machine",
}

# rule id / category → human label for the *data* involved.
_DATA_LABELS = {
    "DAT001": "ledger / voucher / company records",
    "DAT002": "company identity",
    "PII001": "tax IDs (GST / PAN)",
    "PII002": "bank details",
    "PII003": "contact numbers",
}

_EMAIL_ADDR_RE = re.compile(r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})")
_UNC_RE = re.compile(r"\\\\[A-Za-z0-9._-]+\\[^\s\"']+")
_KIND_RE = re.compile(r"→\s*([\w-]+)\s*\(")


@dataclass(frozen=True)
class EgressItem:
    data: list[str]        # what confidential data
    channel: str           # network / email / db-export / network-share / filesystem
    destination: str       # the concrete destination, or a description
    location: str          # external / unknown / internal / dynamic / local file
    trigger: str           # when it happens
    concern: str           # HIGH / MEDIUM / LOW


def _data_labels(findings) -> list[str]:
    labels = set()
    for f in findings:
        if f.rule_id in _DATA_LABELS:
            labels.add(_DATA_LABELS[f.rule_id])
        elif f.category == "file-read":
            labels.add("local files")
    return sorted(labels) or ["business data"]


def _trigger(text: str) -> str:
    if re.search(r"\[System\s*:\s*Startup\]", text, re.IGNORECASE):
        return "automatically at startup"
    if re.search(r"\bOn\s*:\s*'?\s*(Load|Focus|Form Accept)", text, re.IGNORECASE):
        return "on a load/open event"
    return "on a user action (or unspecified trigger)"


def _first_sink_line(lines, block, sink_rules) -> int | None:
    if block is None:
        return None
    for i in range(block.start, block.end + 1):
        if 1 <= i <= len(lines):
            for r in sink_rules:
                if r.pattern.search(lines[i - 1]):
                    return i
    return None


def _channel_of(line: str, sink_rules) -> str | None:
    for r in sink_rules:
        if r.pattern.search(line):
            return r.category
    return None


def _destination(sink_text: str, channel: str, allowlist) -> tuple[str, str]:
    """Return (destination_string, location) for a sink line."""
    if channel == "network":
        m = URL_RE.search(sink_text)
        if m:
            host = m.group(1).lower()
            cls = classify_host(host, allowlist)
            loc = "external" if cls == CLASS_UNKNOWN else "internal"
            return m.group(0), loc
        return "a destination set at runtime", "unknown"

    if channel == "email":
        m = _EMAIL_ADDR_RE.search(sink_text)
        if m:
            domain = m.group(1).lower()
            allowed = any(domain == a.lower() or domain.endswith("." + a.lower())
                          for a in allowlist)
            return m.group(0), ("internal" if allowed else "external")
        return "a recipient from a data field", "dynamic"

    if channel == "network-share":
        m = _UNC_RE.search(sink_text)
        return (m.group(0) if m else "a network share"), "external"

    if channel == "db-export":
        return "an external database", "external"

    if channel == "filesystem":
        m = re.search(r'"([^"]+)"', sink_text)
        return (m.group(1) if m else "a file"), "local file"

    if channel == "code-exec":
        return "an external program", "external"

    return "an unknown destination", "unknown"


def _concern(location: str, channel: str) -> str:
    if location in ("external", "unknown"):
        return "HIGH"
    if channel == "filesystem" or location == "dynamic":
        return "MEDIUM"
    return "LOW"


def build_egress(text: str, findings, rules, allowlist=frozenset()) -> list[EgressItem]:
    """One EgressItem per distinct data-flow (read → send)."""
    lines = text.splitlines()
    blocks = find_blocks(text)
    sink_rules = [r for r in rules if r.category in SINK_CATEGORIES]
    data = _data_labels(findings)
    trigger = _trigger(text)

    items: list[EgressItem] = []
    seen: set[tuple] = set()
    for f in findings:
        if f.category != "data-flow":
            continue

        if f.rule_id == "FLOW001":
            block = block_for_line(blocks, f.line_no)
            sink_no = _first_sink_line(lines, block, sink_rules)
        elif f.rule_id == "FLOW003":
            # Transmission is inside the called function — destination not local.
            channel = (_KIND_RE.search(f.line_text) or [None, "network"])[1] \
                if _KIND_RE.search(f.line_text) else "network"
            key = (tuple(data), channel, "inside a called function")
            if key not in seen:
                seen.add(key)
                items.append(EgressItem(data, channel, "a destination inside a called function",
                                        "unknown", trigger, "HIGH"))
            continue
        else:                       # FLOW002
            sink_no = f.line_no

        sink_text = lines[sink_no - 1] if sink_no and 1 <= sink_no <= len(lines) else f.line_text
        channel = _channel_of(sink_text, sink_rules)
        if channel is None:
            m = _KIND_RE.search(f.line_text)
            channel = m.group(1) if m else "network"
        dest, location = _destination(sink_text, channel, allowlist)

        key = (tuple(data), channel, dest)
        if key in seen:
            continue
        seen.add(key)
        items.append(EgressItem(data, channel, dest, location, trigger,
                                _concern(location, channel)))
    return items


def format_egress(items: list[EgressItem]) -> list[str]:
    out = []
    for it in items:
        data = ", ".join(it.data)
        via = CHANNEL_LABELS.get(it.channel, it.channel)
        loc = LOCATION_PHRASE.get(it.location, it.location)
        out.append(f"[{it.concern}] {data} → would be sent via {via} to "
                   f"{it.destination} ({loc}), {it.trigger}.")
    return out
