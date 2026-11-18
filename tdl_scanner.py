#!/usr/bin/env python3
"""
tdl_scanner.py — Static safety scanner for Tally TDL add-ons.

WHAT IT IS
    A defensive review tool. Point it at a .tdl / .txt add-on file (or a folder)
    and it reports, per file, whether the add-on can reach the network, write
    files, run at startup, hide its behaviour, read sensitive data, or tamper
    with licensing — with line numbers, confidence, and plain-English advice.

DETECTION INTELLIGENCE (why it's hard to fool)
    1. Deobfuscation    - decodes $$StrByCharCode / base64 / hex and re-scans the
                          revealed text, so hidden URLs/keywords still get caught.
    2. Data-flow pairing- flags when a block both reads sensitive data AND can send
                          it out (the actual theft shape), not just each in isolation.
    3. Destination triage- classifies every URL host as allowlisted / private /
                          unknown-internet and scores accordingly.
    4. Confidence scoring- every finding is HIGH/MEDIUM/LOW, adjusted by context.
    5. Rule packs       - enable/disable groups: exfiltration, persistence,
                          privacy, licensing-bypass.

WHAT IT IS NOT
    It does not execute TDL, send anything anywhere, or generate add-ons. It only
    reads and classifies source text.

USAGE
    python tdl_scanner.py addon.tdl
    python tdl_scanner.py folder --recursive --min-severity HIGH
    python tdl_scanner.py addon.tdl --packs exfiltration,persistence
    python tdl_scanner.py addon.tdl --allow mycrm.example.com --json report.json
    python tdl_scanner.py --list-packs

EXIT CODES
    0  ok
    1  usage / path error
    2  findings at/above --fail-on severity (for CI / pre-install gates)
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path

from rules import (
    ALL_PACKS, ALL_RULES, PACKS, SEVERITY_ORDER, SEVERITY_WEIGHT,
    CONFIDENCE_ORDER, CONFIDENCE_FACTOR, adjust_confidence, rules_for_packs, Rule,
)
import reputation
from egress import build_egress, format_egress
from deobfuscate import deobfuscate
from destinations import (
    extract_destinations, classify_url, URL_RE,
    CLASS_ALLOWLISTED, CLASS_PRIVATE, CLASS_UNKNOWN,
)
from dataflow import find_blocks, taint_flows

try:  # tomllib is stdlib on 3.11+; config file support degrades gracefully without it
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None


TDL_EXTENSIONS = {".tdl", ".txt", ".tcp"}

# Categories that move data off the machine.
OUTBOUND_CATS = {"network", "db-export", "email", "network-share"}
# Categories a tainted variable can flow *into* to cause harm.
SINK_CATS = OUTBOUND_CATS | {"filesystem", "code-exec"}
# Categories that count as reading sensitive data (a data-flow *source*).
SOURCE_CATS = {"data-access", "pii", "file-read"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class Config:
    packs: frozenset = ALL_PACKS
    allowlist: frozenset = frozenset()
    min_confidence: str = "LOW"
    extra_rules: tuple = ()          # custom Rule objects loaded from config


def _active_rules(config: Config) -> list[Rule]:
    """Enabled built-in rules plus any custom rules whose pack is enabled."""
    return rules_for_packs(config.packs) + [
        r for r in config.extra_rules if r.pack in config.packs
    ]


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    category: str
    pack: str
    severity: str
    confidence: str
    source: str          # "source" | "deobfuscated" | "dataflow"
    line_no: int
    line_text: str
    why: str
    recommend: str
    detail: str = ""
    strong: bool = True          # a single hit implies the capability
    escalate: bool = False        # this finding shows *abuse*, not just capability


@dataclass
class FileReport:
    path: str
    findings: list[Finding]
    destinations: list[dict]
    risk_score: int
    verdict: str
    capabilities: list[str] = field(default_factory=list)
    egress: list = field(default_factory=list)      # list[EgressItem]


def default_config() -> Config:
    return Config()


# ---------------------------------------------------------------------------
# Low-level matching
# ---------------------------------------------------------------------------
def _iter_matches(text: str, rules: list[Rule], skip_comments: bool):
    """Yield (rule, line_no, line_text) for every rule hit in the text."""
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        is_comment = line.lstrip().startswith(";")
        # A comment line does not execute in TDL, so raw rules don't apply to it.
        # (Encoded payloads in comments are still revealed by the deobfuscator,
        # which runs over every line independently.)
        if skip_comments and is_comment:
            continue
        for rule in rules:
            if rule.pattern.search(line):
                yield rule, line_no, line.strip()[:200]


def _finding_from(rule: Rule, line_no: int, line_text: str,
                  source: str, confidence: str, detail: str = "") -> Finding:
    return Finding(
        rule_id=rule.id, rule_name=rule.name, category=rule.category,
        pack=rule.pack, severity=rule.severity, confidence=confidence,
        source=source, line_no=line_no, line_text=line_text,
        why=rule.why, recommend=rule.recommend, detail=detail, strong=rule.strong,
    )


def scan_source(text: str, config: Config | None = None) -> list[Finding]:
    """Raw, line-by-line rule matches on the literal source (no extras)."""
    config = config or default_config()
    rules = _active_rules(config)
    return [
        _finding_from(rule, ln, lt, "source", rule.base_confidence)
        for rule, ln, lt in _iter_matches(text, rules, skip_comments=True)
    ]


# ---------------------------------------------------------------------------
# Feature 1: deobfuscated findings
# ---------------------------------------------------------------------------
def _deobfuscated_findings(artifacts, rules: list[Rule]) -> list[Finding]:
    out: list[Finding] = []
    for art in artifacts:
        preview = art.decoded.strip()[:120]
        for rule, _ln, _lt in _iter_matches(art.decoded, rules, skip_comments=False):
            out.append(_finding_from(
                rule, art.line_no,
                f"[{art.method}-decoded] {preview}",
                source="deobfuscated",
                # Hidden content is more suspicious than the same thing in the clear.
                confidence=adjust_confidence(rule.base_confidence, +1),
                detail=f"Revealed by decoding {art.method} at line {art.line_no}; "
                       f"decoded value: {art.decoded[:200]}",
            ))
    return out


# ---------------------------------------------------------------------------
# Feature 3: destination-aware confidence for URL findings
# ---------------------------------------------------------------------------
_EMAIL_ADDR_RE = re.compile(r"[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})")


def _email_hardcoded_recipient(line: str, allowlist) -> bool:
    """True if the email line hard-codes a recipient address at a non-allowlisted
    domain. A dynamic recipient (a customer's address pulled from a field/variable)
    has no literal `x@y.z` and returns False — that's the legitimate invoice pattern.
    """
    for m in _EMAIL_ADDR_RE.finditer(line):
        domain = m.group(1).lower()
        if not any(domain == a.lower() or domain.endswith("." + a.lower())
                   for a in allowlist):
            return True
    return False


def _apply_escalation(findings: list[Finding], allowlist) -> None:
    """Mark which outbound findings show *abuse* vs mere *capability*.

    A capability alone (can email, can talk to a DB) is routine in accounting
    add-ons. What escalates it: a real HTTP call whose destination can't be
    verified, a URL to an unknown public host, or an email to a hard-coded
    unknown recipient.
    """
    for f in findings:
        if f.rule_id in ("NET001", "NET002", "NET003", "NET004"):
            f.escalate = True        # an actual network call — verify the destination
        elif f.rule_id == "NET005":
            dest = classify_url(f.line_text, allowlist) or classify_url(f.detail, allowlist)
            f.escalate = bool(dest and dest.classification == CLASS_UNKNOWN)
        elif f.rule_id == "EML001":
            f.escalate = _email_hardcoded_recipient(f.line_text, allowlist)


def _apply_destination_confidence(findings: list[Finding], allowlist) -> None:
    for f in findings:
        if f.rule_id != "NET005":
            continue
        dest = classify_url(f.line_text, allowlist)
        if dest is None:
            # URL might live in the decoded detail text.
            dest = classify_url(f.detail, allowlist)
        if dest is None:
            continue
        if dest.classification == CLASS_UNKNOWN:
            f.confidence = adjust_confidence(f.confidence, +1)
        elif dest.classification in (CLASS_ALLOWLISTED, CLASS_PRIVATE):
            f.confidence = adjust_confidence(f.confidence, -1)
        f.detail = (f"host {dest.host} → {dest.classification}"
                    + (f" | {f.detail}" if f.detail else ""))


# ---------------------------------------------------------------------------
# Feature 2: data-flow pairing
# ---------------------------------------------------------------------------
def _dataflow_findings(text: str, findings: list[Finding]) -> list[Finding]:
    """FLOW001 — read and transmit co-occur in the SAME block (structural)."""
    blocks = find_blocks(text)
    out: list[Finding] = []
    considered = [f for f in findings if f.source in ("source", "deobfuscated")]
    for b in blocks:
        cats = {f.category for f in considered if b.start <= f.line_no <= b.end}
        if not (cats & SOURCE_CATS):
            continue
        sinks = cats & SINK_CATS
        if not sinks:
            continue
        sink = sorted(sinks)[0]
        label = b.header or (f"{b.kind}: {b.name}".strip(": "))
        out.append(Finding(
            rule_id="FLOW001",
            rule_name="Sensitive data + outbound capability in same block",
            category="data-flow",
            pack="exfiltration",
            severity="CRITICAL",
            confidence="HIGH",
            source="dataflow",
            line_no=b.start,
            line_text=label,
            why=f"This block both reads sensitive business data and has a way to send it "
                f"off the machine ({sink}). That pairing — read then transmit — is how "
                f"add-ons steal data.",
            recommend="High risk. Read this block line-by-line and confirm the data cannot leave.",
            detail=f"block '{b.kind}: {b.name}' (lines {b.start}-{b.end}) "
                   f"contains data-access + {sink}",
        ))
    return out


_BULK_TYPE_RE = re.compile(r"\b(Type|Collection)\s*:\s*(Ledger|Voucher|Company|Bank|StockItem)", re.IGNORECASE)
_FILTER_RE = re.compile(r"\b(Filter|Child\s+Of|Belongs\s+To|Search|By\s*:|Name\s+Set)\b", re.IGNORECASE)


def _bulk_harvest_findings(text: str, rules: list[Rule]) -> list[Finding]:
    """A collection over an entire sensitive type with no filter = bulk harvest."""
    if not any(r.category == "data-access" for r in rules):
        return []
    lines = text.splitlines()
    out: list[Finding] = []
    for b in find_blocks(text):
        body = "\n".join(lines[b.start - 1:b.end])
        if _BULK_TYPE_RE.search(body) and not _FILTER_RE.search(body):
            out.append(Finding(
                rule_id="BULK001",
                rule_name="Unfiltered bulk read of a sensitive record type",
                category="bulk-harvest", pack="privacy",
                severity="MEDIUM", confidence="MEDIUM", source="analysis",
                line_no=b.start, line_text=b.header or f"{b.kind}: {b.name}".strip(": "),
                why="Reads an entire class of records (e.g. every ledger/voucher) with no "
                    "filter — the shape of bulk data harvesting rather than a lookup.",
                recommend="Confirm the add-on genuinely needs every record; unfiltered bulk "
                          "reads pair naturally with exfiltration.",
                detail=f"block '{b.kind}: {b.name}' (lines {b.start}-{b.end}) reads a full type without a filter",
            ))
    return out


def _cross_block_findings(text: str, rules: list[Rule]) -> list[Finding]:
    """FLOW002 — a variable read from a sensitive source is transmitted in a
    DIFFERENT block (interprocedural taint). The sneaky 'look innocent' case."""
    data_rules = [r for r in rules if r.category in ("data-access", "pii", "file-read")]
    sink_rules = [r for r in rules if r.category in SINK_CATS]
    if not data_rules or not sink_rules:
        return []

    def is_source(expr: str) -> bool:
        return any(r.pattern.search(expr) for r in data_rules)

    def is_sink(line: str):
        for r in sink_rules:
            if r.pattern.search(line):
                return r.category
        return None

    out: list[Finding] = []
    for flow in taint_flows(text, is_source, is_sink):
        if flow.mode == "interprocedural":
            rule_id = "FLOW003"
            name = "Sensitive data passed to a function that transmits"
            why = ("A variable holding sensitive data is handed to a function whose "
                   "body sends data out. Hiding the transmission one call away doesn't "
                   "change that the data leaves.")
            detail = (f"'{flow.var}' (read near line {flow.source_line}) passed at line "
                      f"{flow.sink_line} into {flow.sink_block.kind}:{flow.sink_block.name}, "
                      f"which performs {flow.sink_kind}")
        else:
            rule_id = "FLOW002"
            name = "Sensitive data carried across blocks to an outbound sink"
            why = ("A variable holding sensitive data read elsewhere is transmitted here. "
                   "Splitting the read and the send across blocks is a common way for a "
                   "stealer to look innocent — the data still leaves.")
            detail = (f"'{flow.var}' read in {flow.source_block.kind}:{flow.source_block.name} "
                      f"(line {flow.source_line}) → sent from "
                      f"{flow.sink_block.kind}:{flow.sink_block.name} (line {flow.sink_line})")
        out.append(Finding(
            rule_id=rule_id, rule_name=name, category="data-flow", pack="exfiltration",
            severity="CRITICAL", confidence="HIGH", source="dataflow",
            line_no=flow.sink_line,
            line_text=f"variable '{flow.var}' → {flow.sink_kind} ({flow.mode})",
            why=why,
            recommend="Trace this variable back to its source and confirm the transmission is intended.",
            detail=detail,
        ))
    return out


# ---------------------------------------------------------------------------
# Scoring & verdict
# ---------------------------------------------------------------------------
def score(findings: list[Finding]) -> int:
    return int(sum(
        SEVERITY_WEIGHT.get(f.severity, 0) * CONFIDENCE_FACTOR.get(f.confidence, 1.0)
        for f in findings
    ))


def verdict_for(findings: list[Finding], destinations: list[dict] | None = None,
                egress: list | None = None) -> str:
    cats = {f.category for f in findings}
    outbound = cats & OUTBOUND_CATS

    # Soften a lone hard-coded URL literal (no actual call construct) that points
    # ONLY at loopback/localhost (or explicitly allowlisted) hosts — a plausible
    # local integration, not exfiltration. Anything that could actually leave the
    # machine (LAN, public, IPv6, unknown) keeps the flag. Conservative on purpose.
    if destinations is not None and outbound == {"network"}:
        real_call = any(f.rule_id in {"NET001", "NET002", "NET003", "NET004"}
                        for f in findings)
        all_safe = bool(destinations) and all(
            d.get("loopback") or d["classification"] == "allowlisted" for d in destinations)
        if not real_call and all_safe and not (cats & {"obfuscation", "data-flow", "code-exec"}):
            outbound = set()

    strong_codeexec = any(f.category == "code-exec" and f.strong for f in findings)
    strong_obf = any(f.category == "obfuscation" and f.strong for f in findings)
    strong_autorun = any(f.category == "autorun" and f.strong for f in findings)
    hidden_out = any(f.category in OUTBOUND_CATS and f.source == "deobfuscated"
                     for f in findings)
    # An outbound finding that shows abuse (unknown/hard-coded destination or a
    # real HTTP call), as opposed to a routine capability (emailing a customer).
    escalated_out = any(f.category in OUTBOUND_CATS and f.escalate for f in findings)

    if strong_codeexec:
        return ("DANGEROUS — can run external code (DLL/program), which can do anything. "
                "Do not install without full source review.")
    if "data-flow" in cats:
        # A read→send pairing is serious, but emailing a customer their own data
        # (dynamic recipient, no bulk/startup) is legitimate — review, not damning.
        hard = ("bulk-harvest" in cats or strong_autorun or strong_obf
                or egress is None
                or any(getattr(e, "concern", "HIGH") == "HIGH" for e in egress))
        if hard:
            return ("DANGEROUS — reads sensitive data and can move it off-machine "
                    "(read → transmit). Do not install without full source review.")
        return ("REVIEW REQUIRED — confidential data is sent to a recipient (e.g. a "
                "customer). Confirm it is their own data, not a bulk/hidden export.")
    if hidden_out:
        return ("DANGEROUS — hidden (obfuscated) exfiltration destination. "
                "Do not install without full source review.")
    if outbound and (strong_autorun or strong_obf or "bulk-harvest" in cats):
        return ("DANGEROUS — data-egress that is automatic, hidden, or bulk. "
                "Do not install without source review.")
    if outbound and escalated_out:
        channel = ", ".join(sorted(outbound))
        return f"REVIEW REQUIRED — sends data to an unverified destination ({channel}). Verify it."
    if outbound:
        channel = ", ".join(sorted(outbound))
        return (f"CAUTION — can send data ({channel}), but to a dynamic/known recipient "
                f"(e.g. emailing a customer). Likely routine; confirm the recipient.")
    if "filesystem" in cats and "autorun" in cats:
        return "SUSPICIOUS — writes files automatically. Confirm what and where."
    if strong_obf:
        return "SUSPICIOUS — contains obfuscation. Decode before trusting."
    if "licensing" in cats:
        return "SUSPICIOUS — touches licensing/activation/config. Confirm it's justified."
    if findings:
        return "CAUTION — sensitive capability present; likely benign but confirm."
    return "CLEAN — no risky constructs detected by current rules."


# ---------------------------------------------------------------------------
# Top-level analysis pipeline
# ---------------------------------------------------------------------------
def analyze(text: str, config: Config | None = None) -> FileReport:
    config = config or default_config()
    rules = _active_rules(config)

    # A leading UTF-8 BOM would hide the first "[...]" header from block parsing.
    text = text.lstrip("﻿")

    artifacts = deobfuscate(text)

    findings = scan_source(text, config)
    findings += _deobfuscated_findings(artifacts, rules)
    _apply_destination_confidence(findings, config.allowlist)
    _apply_escalation(findings, config.allowlist)
    findings += _dataflow_findings(text, findings)
    findings += _cross_block_findings(text, rules)
    findings += _bulk_harvest_findings(text, rules)

    # Destinations from both the literal text and anything we decoded.
    dest_text = text + "\n" + "\n".join(a.decoded for a in artifacts)
    destinations = [asdict(d) for d in extract_destinations(dest_text, config.allowlist)]

    findings.sort(key=lambda f: (
        -SEVERITY_ORDER.index(f.severity),
        -CONFIDENCE_ORDER.index(f.confidence),
        f.line_no,
    ))

    egress = build_egress(text, findings, rules, config.allowlist)
    return FileReport(
        path="<text>",
        findings=findings,
        destinations=destinations,
        risk_score=score(findings),
        verdict=verdict_for(findings, destinations, egress),
        capabilities=sorted({f.category for f in findings}),
        egress=egress,
    )


def scan_file(path: Path, config: Config | None = None) -> FileReport:
    # utf-8-sig transparently strips a BOM if present, plain UTF-8 otherwise.
    text = path.read_text(encoding="utf-8-sig", errors="replace")
    report = analyze(text, config)
    report.path = str(path)
    return report


def _merged_text(paths: list[Path]) -> str:
    parts = []
    for p in paths:
        text = p.read_text(encoding="utf-8-sig", errors="replace")
        parts.append(f";; ===== FILE: {p.name} =====\n{text}")
    return "\n\n".join(parts)


def analyze_files(paths: list[Path], config: Config | None = None) -> FileReport:
    """Analyze several TDL files as ONE add-on so taint can cross files.

    Real add-ons are often multiple .tdl modules loaded together; a stealer can
    read data in one file and transmit it from another. Merging defeats that.
    """
    report = analyze(_merged_text(paths), config)
    report.path = f"<merged: {len(paths)} file(s)>"
    return report


# ---------------------------------------------------------------------------
# Diff mode — what changed between two versions of an add-on
# ---------------------------------------------------------------------------
def diff_reports(old: FileReport, new: FileReport) -> dict:
    old_caps, new_caps = set(old.capabilities), set(new.capabilities)
    old_rules = {(f.rule_id, f.line_no) for f in old.findings}
    new_rules = {(f.rule_id, f.line_no) for f in new.findings}
    return {
        "capabilities_added": sorted(new_caps - old_caps),
        "capabilities_removed": sorted(old_caps - new_caps),
        "verdict_old": old.verdict,
        "verdict_new": new.verdict,
        "findings_added": sorted({r for r, _ in (new_rules - old_rules)}),
        "findings_removed": sorted({r for r, _ in (old_rules - new_rules)}),
    }


def collect_targets(root: Path, recursive: bool) -> list[Path]:
    if root.is_file():
        return [root]
    globber = root.rglob if recursive else root.glob
    return sorted(
        p for p in globber("*")
        if p.is_file() and p.suffix.lower() in TDL_EXTENSIONS
    )


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
_COLOR = {
    "CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m",
    "INFO": "\033[36m", "RESET": "\033[0m", "BOLD": "\033[1m",
    CLASS_UNKNOWN: "\033[1;31m", CLASS_PRIVATE: "\033[36m", CLASS_ALLOWLISTED: "\033[32m",
}


def _c(text: str, key: str, use_color: bool) -> str:
    return f"{_COLOR.get(key, '')}{text}{_COLOR['RESET']}" if use_color else text


def _passes(f: Finding, min_sev: str, min_conf: str) -> bool:
    return (SEVERITY_ORDER.index(f.severity) >= SEVERITY_ORDER.index(min_sev)
            and CONFIDENCE_ORDER.index(f.confidence) >= CONFIDENCE_ORDER.index(min_conf))


def print_report(report: FileReport, cfg_min_sev: str, cfg_min_conf: str,
                 use_color: bool) -> None:
    shown = [f for f in report.findings if _passes(f, cfg_min_sev, cfg_min_conf)]

    print()
    print(_c(f"── {report.path}", "BOLD", use_color))
    print(f"   verdict     : {report.verdict}")
    print(f"   risk score  : {report.risk_score}")
    print(f"   capabilities: {', '.join(report.capabilities) or 'none'}")

    if report.egress:
        print(_c("   ── DATA LEAVING THE MACHINE (approve only if you trust each destination) ──",
                 "BOLD", use_color))
        for line in format_egress(report.egress):
            sev = line.split("]")[0].strip("[")
            print("     " + _c(line, sev if sev in _COLOR else "RESET", use_color))

    if report.destinations:
        print("   destinations:")
        for d in report.destinations:
            tag = _c(f"[{d['classification']}]", d['classification'], use_color)
            print(f"      {tag} {d['host']}  ({d['url']})")

    if not shown:
        print(f"   findings    : none at/above {cfg_min_sev}/{cfg_min_conf}")
        return

    print(f"   findings    : {len(shown)} (>= {cfg_min_sev}/{cfg_min_conf} confidence)")
    for f in shown:
        sev = _c(f"[{f.severity}]", f.severity, use_color)
        print(f"     {sev} {f.rule_id} {f.rule_name}  "
              f"(line {f.line_no}, {f.confidence} conf, {f.source}, pack:{f.pack})")
        print(f"        > {f.line_text}")
        if f.detail:
            print(f"        ! {f.detail}")
        print(f"        why : {f.why}")
        print(f"        do  : {f.recommend}")


def summarize(reports: list[FileReport], use_color: bool) -> None:
    flagged = [r for r in reports if r.findings]
    print()
    print(_c("=" * 64, "BOLD", use_color))
    print(_c("SCAN SUMMARY", "BOLD", use_color))
    print(f"  files scanned : {len(reports)}")
    print(f"  with findings : {len(flagged)}")
    for r in sorted(flagged, key=lambda r: -r.risk_score)[:8]:
        print(f"    {r.risk_score:>4}  {Path(r.path).name}  — {r.verdict.split('—')[0].strip()}")
    print(_c("=" * 64, "BOLD", use_color))


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------
def _build_custom_rules(entries: list) -> tuple:
    rules = []
    for i, e in enumerate(entries):
        try:
            severity = str(e["severity"]).upper()
            pack = str(e["pack"])
            confidence = str(e.get("confidence", "HIGH")).upper()
            if severity not in SEVERITY_ORDER:
                raise ValueError(f"bad severity {severity!r}")
            if confidence not in CONFIDENCE_ORDER:
                raise ValueError(f"bad confidence {confidence!r}")
            if pack not in ALL_PACKS:
                raise ValueError(f"unknown pack {pack!r}")
            rules.append(Rule(
                id=str(e.get("id", f"CUSTOM{i+1:03d}")),
                name=str(e.get("name", "Custom rule")),
                category=str(e.get("category", "custom")),
                pack=pack, severity=severity, base_confidence=confidence,
                pattern=re.compile(str(e["regex"]), re.IGNORECASE),
                why=str(e.get("why", "Matched a custom organisation rule.")),
                recommend=str(e.get("recommend", "Review against your policy.")),
                strong=bool(e.get("strong", True)),
            ))
        except (KeyError, ValueError, re.error) as exc:
            raise SystemExit(f"error: invalid [[rule]] #{i+1} in config: {exc}")
    return tuple(rules)


def _reputation_pass(args, targets: list[Path], reports: list[FileReport],
                     use_color: bool) -> None:
    """Report new / known / CHANGED status per file and optionally record it."""
    db_path = args.reputation_db or ("reputation.json" if args.remember else None)
    if not db_path:
        return

    # (key, digest, report) for each scanned unit.
    entries: list[tuple[str, str, FileReport]] = []
    if args.merge:
        digest = reputation.sha256_text(_merged_text(targets))
        key = (targets[0].parent.name or "merged") + " (merged)"
        entries.append((key, digest, reports[0]))
    else:
        for p, rep in zip(targets, reports):
            text = p.read_text(encoding="utf-8-sig", errors="replace")
            entries.append((p.name, reputation.sha256_text(text), rep))

    db = reputation.load(db_path)
    print()
    print(_c("REPUTATION", "BOLD", use_color))
    for key, digest, rep in entries:
        st, prev = reputation.status(db, key, digest)
        if st == reputation.STATUS_NEW:
            print(f"  {key}: new (not recorded before)")
        elif st == reputation.STATUS_KNOWN:
            print(f"  {key}: known — unchanged since {prev.get('first_seen', '?')}")
        else:
            msg = (f"  {key}: ⚠ CHANGED since {prev.get('last_recorded', '?')} "
                   f"(was: {prev.get('verdict', '?').split('—')[0].strip()})")
            print(_c(msg, "CRITICAL", use_color))
        if args.remember:
            reputation.remember(db, key, digest, verdict=rep.verdict,
                                risk_score=rep.risk_score, capabilities=rep.capabilities)
    if args.remember:
        reputation.save(db_path, db)
        print(f"  (recorded {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} to {db_path})")


def load_config(args) -> Config:
    packs = set(ALL_PACKS)
    allowlist: set[str] = set()
    min_conf = "LOW"
    extra_rules: tuple = ()

    if args.config:
        if tomllib is None:
            print("warning: --config ignored (tomllib unavailable on this Python).",
                  file=sys.stderr)
        else:
            # utf-8-sig strips a BOM some editors add, which tomllib would reject.
            data = tomllib.loads(Path(args.config).read_text(encoding="utf-8-sig"))
            if "packs" in data:
                packs = set(data["packs"])
            if "allow" in data:
                allowlist |= {str(h) for h in data["allow"]}
            if "min_confidence" in data:
                min_conf = str(data["min_confidence"]).upper()
            if "rule" in data:
                extra_rules = _build_custom_rules(data["rule"])

    if args.packs:
        packs = {p.strip() for p in args.packs.split(",") if p.strip()}
    if args.allow:
        allowlist |= {h.strip() for h in args.allow.split(",") if h.strip()}
    if args.min_confidence:
        min_conf = args.min_confidence

    unknown = packs - set(ALL_PACKS)
    if unknown:
        raise SystemExit(f"error: unknown pack(s): {', '.join(sorted(unknown))}. "
                         f"Valid: {', '.join(sorted(ALL_PACKS))}")

    return Config(packs=frozenset(packs), allowlist=frozenset(allowlist),
                  min_confidence=min_conf, extra_rules=extra_rules)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Static safety scanner for Tally TDL add-ons (defensive).")
    ap.add_argument("target", nargs="?", help="A .tdl/.txt file or a folder of them.")
    ap.add_argument("--recursive", "-r", action="store_true",
                    help="Recurse into subfolders when target is a directory.")
    ap.add_argument("--merge", action="store_true",
                    help="Treat all files in a folder as ONE add-on (cross-file taint).")
    ap.add_argument("--min-severity", default="INFO", choices=SEVERITY_ORDER,
                    help="Only display findings at/above this severity.")
    ap.add_argument("--min-confidence", default=None, choices=CONFIDENCE_ORDER,
                    help="Only display findings at/above this confidence.")
    ap.add_argument("--packs", default=None,
                    help=f"Comma list of packs to enable. Default: all "
                         f"({', '.join(sorted(ALL_PACKS))}).")
    ap.add_argument("--allow", default=None,
                    help="Comma list of trusted hosts (suppresses their escalation).")
    ap.add_argument("--config", default=None, help="Path to a scanner.toml config file.")
    ap.add_argument("--fail-on", default=None, choices=SEVERITY_ORDER,
                    help="Exit 2 if any finding at/above this severity exists.")
    ap.add_argument("--json", metavar="PATH", default=None,
                    help="Also write a machine-readable JSON report to PATH.")
    ap.add_argument("--list-packs", action="store_true",
                    help="List available rule packs and exit.")
    ap.add_argument("--egress", action="store_true",
                    help="Show only the 'data leaving the machine' report per file.")
    ap.add_argument("--diff", nargs=2, metavar=("OLD", "NEW"), default=None,
                    help="Compare two add-on files and show what capabilities changed.")
    ap.add_argument("--reputation-db", metavar="PATH", default=None,
                    help="JSON reputation store; reports new / known / CHANGED per file.")
    ap.add_argument("--remember", action="store_true",
                    help="Record the current scan into the reputation DB (default reputation.json).")
    ap.add_argument("--no-color", action="store_true", help="Disable ANSI colours.")
    args = ap.parse_args(argv)

    if args.list_packs:
        print("Available rule packs:")
        for name in sorted(ALL_PACKS):
            n_rules = sum(1 for r in ALL_RULES if r.pack == name)
            print(f"  {name:<18} {PACKS[name]}  ({n_rules} rules)")
        return 0

    if args.diff:
        old_p, new_p = Path(args.diff[0]), Path(args.diff[1])
        for p in (old_p, new_p):
            if not p.exists():
                print(f"error: no such file: {p}", file=sys.stderr)
                return 1
        config = load_config(args)
        old_r, new_r = scan_file(old_p, config), scan_file(new_p, config)
        d = diff_reports(old_r, new_r)
        print(f"\nDIFF  {old_p.name}  →  {new_p.name}")
        print(f"  verdict : {d['verdict_old']}")
        print(f"          → {d['verdict_new']}")
        print(f"  capabilities added   : {', '.join(d['capabilities_added']) or 'none'}")
        print(f"  capabilities removed : {', '.join(d['capabilities_removed']) or 'none'}")
        print(f"  findings added   : {', '.join(d['findings_added']) or 'none'}")
        print(f"  findings removed : {', '.join(d['findings_removed']) or 'none'}")
        if d["capabilities_added"]:
            print("  ⚠ NEW capabilities appeared in the update — review before trusting.")
            return 2
        return 0

    if not args.target:
        ap.error("target is required (a .tdl/.txt file or folder), unless --list-packs")

    root = Path(args.target)
    if not root.exists():
        print(f"error: no such path: {root}", file=sys.stderr)
        return 1

    config = load_config(args)
    display_min_conf = config.min_confidence

    use_color = (not args.no_color) and sys.stdout.isatty()
    targets = collect_targets(root, args.recursive)
    if not targets:
        print("No TDL-like files (.tdl/.txt/.tcp) found at target.", file=sys.stderr)
        return 1

    if args.merge:
        reports = [analyze_files(targets, config)]
    else:
        reports = [scan_file(p, config) for p in targets]

    if args.egress:
        for rep in reports:
            print()
            print(_c(f"── {rep.path}", "BOLD", use_color))
            if rep.egress:
                for line in format_egress(rep.egress):
                    print("   " + line)
            else:
                print("   No confidential data is sent off the machine.")
        return 0

    for rep in reports:
        print_report(rep, args.min_severity, display_min_conf, use_color)
    if len(reports) > 1:
        summarize(reports, use_color)

    _reputation_pass(args, targets, reports, use_color)

    if args.json:
        payload = [
            {"path": r.path, "verdict": r.verdict, "risk_score": r.risk_score,
             "capabilities": r.capabilities, "destinations": r.destinations,
             "egress": [asdict(e) for e in r.egress],
             "findings": [asdict(f) for f in r.findings]}
            for r in reports
        ]
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        print(f"\nJSON report written to {args.json}")

    if args.fail_on:
        threshold = SEVERITY_ORDER.index(args.fail_on)
        for r in reports:
            if any(SEVERITY_ORDER.index(f.severity) >= threshold for f in r.findings):
                return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
