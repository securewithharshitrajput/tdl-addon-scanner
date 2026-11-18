"""
rules.py — Signature/rule knowledge base for the TDL add-on scanner.

Each rule describes a *code construct* that a reviewer should look at before
trusting a third-party Tally add-on (TDL). The scanner is a DEFENSIVE tool:
it reads TDL source and tells a human "this add-on can reach the network, write
files, read your ledgers, run at startup, hide its behaviour, or tamper with
licensing" so the human can decide whether to trust it.

Nothing here executes TDL. The rules are just regexes over source text plus
metadata (severity, confidence, pack, why it matters, what to do).

Severity scale (what the construct *could* do):
    CRITICAL - can move data off the machine (outbound network)
    HIGH     - enables theft/persistence/evasion (file export, autorun, obfuscation)
    MEDIUM   - touches sensitive business data / config
    INFO     - worth noting, usually benign on its own

Confidence scale (how sure we are this construct is what it looks like):
    HIGH   - unambiguous construct
    MEDIUM - real signal but context-dependent
    LOW    - weak signal on its own; meaningful only when paired

Packs (thematic groups the user can enable/disable):
    exfiltration     - getting data out (network, file export, obfuscation)
    persistence      - running without being asked (startup / load hooks)
    privacy          - reading sensitive business data (ledgers, vouchers, company)
    licensing-bypass - tampering with Tally licensing / activation / config
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Pattern


# ---------------------------------------------------------------------------
# Shared scales
# ---------------------------------------------------------------------------
SEVERITY_ORDER = ["INFO", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 8, "INFO": 2}

CONFIDENCE_ORDER = ["LOW", "MEDIUM", "HIGH"]
CONFIDENCE_FACTOR = {"HIGH": 1.0, "MEDIUM": 0.6, "LOW": 0.3}

# Thematic rule packs. Value is a human-readable description.
PACKS = {
    "exfiltration": "Getting data off the machine — network, DB export, email, file/share exports, obfuscation.",
    "persistence": "Running automatically without user action — startup, load hooks, module loaders.",
    "privacy": "Reading sensitive business data — ledgers, vouchers, PII, local files, machine recon.",
    "licensing-bypass": "Tampering with Tally licensing / activation / configuration.",
    "code-execution": "Running external native code — DLLs and external programs.",
}
ALL_PACKS = frozenset(PACKS)


def adjust_confidence(level: str, delta: int) -> str:
    """Move a confidence level up (+) or down (-), clamped to the scale."""
    i = CONFIDENCE_ORDER.index(level)
    i = max(0, min(len(CONFIDENCE_ORDER) - 1, i + delta))
    return CONFIDENCE_ORDER[i]


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str          # what the construct is (network, filesystem, ...)
    pack: str              # thematic group (must be a key of PACKS)
    severity: str          # CRITICAL / HIGH / MEDIUM / INFO
    base_confidence: str   # starting HIGH / MEDIUM / LOW (scanner may adjust)
    pattern: Pattern[str]  # applied line-by-line, IGNORECASE
    why: str
    recommend: str
    strong: bool = True    # a single hit implies the capability


def _rx(expr: str) -> Pattern[str]:
    return re.compile(expr, re.IGNORECASE)


# ---------------------------------------------------------------------------
# NETWORK  (pack: exfiltration) — outbound communication. Turns "reads data"
# into "steals data". The single most important category.
# ---------------------------------------------------------------------------
NETWORK_RULES = [
    Rule("NET001", "HTTP GET helper ($$HttpGet)", "network", "exfiltration",
         "CRITICAL", "HIGH", _rx(r"\$\$HttpGet"),
         "Built-in TDL function that performs an outbound HTTP request. Can carry any string in the URL/query, including ledger data.",
         "Confirm the destination host is expected and documented. Any request to an unknown host is a red flag."),
    Rule("NET002", "HTTP POST action", "network", "exfiltration",
         "CRITICAL", "HIGH", _rx(r"\bHTTP\s+Post\b"),
         "Sends a payload to a remote server. The payload can contain exported report/ledger content.",
         "Trace what expression builds the POST body and where it is sent."),
    Rule("NET003", "Remote URL on a Collection (RemoteURL / HTTPXMLData)", "network", "exfiltration",
         "CRITICAL", "HIGH", _rx(r"\b(RemoteURL|HTTPXMLData)\b"),
         "Points a data Collection at a network endpoint — data can flow in or out of the machine.",
         "Verify the endpoint. Legitimate sync integrations disclose it; hidden endpoints do not."),
    Rule("NET004", "TallyHTTP / HTTP object instantiation", "network", "exfiltration",
         "CRITICAL", "HIGH", _rx(r"NEW\s+OBJECT\s*:?\s*.*HTTP"),
         "Creates an HTTP-capable object to drive requests from within the add-on.",
         "Read the method calls on this object to see request target and body."),
    Rule("NET005", "Hard-coded URL literal", "network", "exfiltration",
         "HIGH", "MEDIUM", _rx(r"(?:https?|ftps?)://[^\s\"']+"),
         "An embedded http(s)/ftp address. Combined with any network call, this is the likely exfil/callback destination.",
         "Ask: does this add-on legitimately need to talk to this host? Unknown domains warrant rejection.",
         strong=False),
]

# ---------------------------------------------------------------------------
# FILESYSTEM  (pack: exfiltration) — writing data out to disk.
# ---------------------------------------------------------------------------
FILE_RULES = [
    Rule("FS001", "File write / export action", "filesystem", "exfiltration",
         "HIGH", "HIGH", _rx(r"\b(Set\s+File|Open\s+File|Write\s*File|Append\s*File)\b"),
         "Writes add-on-controlled content to a file on disk. Can dump report/ledger data to an arbitrary path.",
         "Check the target path and what content is written. Exports to temp/hidden paths are suspicious."),
    Rule("FS002", "Report export / DUMP to file", "filesystem", "exfiltration",
         "MEDIUM", "MEDIUM", _rx(r"\b(DUMP|Export|Print)\b.*\b(File|ASCII|XML|CSV|HTML)\b"),
         "Renders a report to a file format on disk — a common precursor to sending it elsewhere.",
         "Legitimate exports are user-initiated. Automatic/background exports are the concern.",
         strong=False),
]

# ---------------------------------------------------------------------------
# PERSISTENCE / AUTO-EXECUTION  (pack: persistence)
# ---------------------------------------------------------------------------
AUTORUN_RULES = [
    Rule("RUN001", "System startup hook", "autorun", "persistence",
         "HIGH", "HIGH", _rx(r"\[System\s*:\s*Startup\]"),
         "Registers logic that runs when Tally/the company loads — no user action required.",
         "Anything that runs automatically deserves extra scrutiny of what it does."),
    Rule("RUN002", "Load / form-open event handler", "autorun", "persistence",
         "MEDIUM", "MEDIUM", _rx(r"\bOn\s*:\s*'?\s*(Load|Form Accept|Focus)\b"),
         "Fires actions on load/open events, enabling background behaviour.",
         "Confirm the triggered actions are benign UI logic, not network/file operations.",
         strong=False),
]

# ---------------------------------------------------------------------------
# OBFUSCATION  (pack: exfiltration) — hiding what the code does.
# ---------------------------------------------------------------------------
OBFUSCATION_RULES = [
    Rule("OBF001", "String built from character codes ($$StrByCharCode)", "obfuscation", "exfiltration",
         "HIGH", "HIGH", _rx(r"\$\$StrByCharCode"),
         "Assembles strings (e.g. hidden URLs/keywords) from numeric codes to evade simple text scans.",
         "Decode the constructed string manually to reveal what it really is (this scanner does it for you)."),
    Rule("OBF002", "Long encoded/hex blob", "obfuscation", "exfiltration",
         "MEDIUM", "MEDIUM", _rx(r"[A-Za-z0-9+/]{120,}={0,2}"),
         "A very long contiguous token often indicates base64/hex-encoded hidden data or logic.",
         "Decode and inspect. Legitimate config is rarely a 120+ char single token.",
         strong=False),
]

# ---------------------------------------------------------------------------
# DATA ACCESS  (pack: privacy) — reading sensitive business objects. Benign on
# its own; dangerous only when paired with a way to send it out.
# ---------------------------------------------------------------------------
DATA_RULES = [
    Rule("DAT001", "Sensitive Collection (Ledger/Voucher/Company/Bank)", "data-access", "privacy",
         "MEDIUM", "MEDIUM", _rx(r"\b(Type\s*:\s*)?(Ledger|Voucher|Company|Bank|GroupCompany)\b"),
         "Reads sensitive business data. Only dangerous when combined with a way to send it out.",
         "Cross-reference with any network/file findings — that pairing is the real risk.",
         strong=False),
    Rule("DAT002", "Company mailing / identity fields", "data-access", "privacy",
         "INFO", "LOW", _rx(r"\$\$Cmp(MailingName|Name|Address)"),
         "Pulls company identity fields — often used legitimately, sometimes harvested.",
         "Note it; escalate only if paired with exfil capability.",
         strong=False),
]

# ---------------------------------------------------------------------------
# LICENSING / CONFIG TAMPERING  (pack: licensing-bypass)
# These can be legitimate (status checks), so confidence starts conservative.
# ---------------------------------------------------------------------------
LICENSING_RULES = [
    Rule("LIC001", "Writes to Tally configuration (tally.ini)", "licensing", "licensing-bypass",
         "HIGH", "MEDIUM", _rx(r"tally\.ini"),
         "Touches Tally's configuration file — can alter licensing, data paths, or ODBC/network settings.",
         "Confirm the add-on has a legitimate reason to edit tally.ini and what it changes."),
    Rule("LIC002", "License / serial / activation field assignment", "licensing", "licensing-bypass",
         "HIGH", "MEDIUM", _rx(r"\bSet\b[^;\n]*\b(License|Serial\s*Number|SerialNumber|Activation|AccountId|Account\s*ID)\b"),
         "Assigns to a licensing/serial/activation field — a hallmark of license tampering.",
         "License data should not be set by an add-on. Treat as suspicious unless clearly justified."),
    Rule("LIC003", "License-status / edition probing", "licensing", "licensing-bypass",
         "MEDIUM", "LOW", _rx(r"\$\$(LicenseInfo|Is(Educational|Silver|Gold)Mode)"),
         "Queries license status/edition. Common in legitimate add-ons, but also the first step of a bypass.",
         "Benign on its own; escalate only if paired with tally.ini writes or license-field assignments.",
         strong=False),
]


# ---------------------------------------------------------------------------
# CODE EXECUTION  (pack: code-execution) — running native code. Arbitrary code
# can do anything, including exfiltration; this is the most severe capability.
# ---------------------------------------------------------------------------
CODE_EXEC_RULES = [
    Rule("EXEC001", "External DLL / native library call", "code-exec", "code-execution",
         "CRITICAL", "HIGH",
         _rx(r"\b(CALL\s+DLL|LOAD\s+DLL|External\s+DLL|Import\s+DLL|Plugin\s*:)\b"),
         "Invokes a native DLL — arbitrary machine code outside TDL's sandbox.",
         "Native code can do anything. Reject unless the DLL is known and trusted."),
    Rule("EXEC002", "Launch external program / OS command", "code-exec", "code-execution",
         "CRITICAL", "HIGH",
         _rx(r"\b(EXECUTE|WinExec|ShellExecute|CreateProcess|Launch\s+Application|RunApp|xp_cmdshell)\b"),
         "Starts an external program or OS command from within the add-on.",
         "Confirm exactly what is launched and why. Treat unknown launches as hostile."),
    Rule("EXEC003", "Reference to a .dll / .exe file", "code-exec", "code-execution",
         "HIGH", "MEDIUM", _rx(r"[\"'\s=:]\S*\.(dll|exe|bat|cmd|ps1|vbs)\b"),
         "Names an executable/script file — often the target of a native call or launch.",
         "Trace how this file is used. Bundled executables in an accounting add-on are a red flag.",
         strong=False),
]

# ---------------------------------------------------------------------------
# DATABASE EXPORT  (pack: exfiltration) — pushing data to a database/ODBC.
# ---------------------------------------------------------------------------
DB_RULES = [
    Rule("DBX001", "Database / ODBC / SQL export", "db-export", "exfiltration",
         "HIGH", "MEDIUM",
         _rx(r"\b(ODBC|SQLConnect|SQLExecute|OpenDatabase|\$\$SqlObject|SQLQuery|Insert\s+Into|Update\s+.+\s+Set|SELECT\s+.+\s+INTO\s+OUTFILE)\b"),
         "Moves data into an external/ODBC database — a data egress channel that isn't HTTP.",
         "Confirm the database target is expected. Unknown/remote DBs can be exfiltration."),
]

# ---------------------------------------------------------------------------
# EMAIL / SMTP  (pack: exfiltration) — mailing data out.
# ---------------------------------------------------------------------------
EMAIL_RULES = [
    Rule("EML001", "Email / SMTP send", "email", "exfiltration",
         "HIGH", "MEDIUM",
         _rx(r"\b(SMTP|SendMail|Send\s+Mail|MailServer|Mail\s+Report|EMailID|Email\s+Address)\b|\[System\s*:\s*SMTP\]"),
         "Sends email — a report emailed to an attacker's inbox leaves the machine just like an HTTP post.",
         "Verify recipient/server. Automatic or hidden email is exfiltration."),
]

# ---------------------------------------------------------------------------
# NETWORK SHARE  (pack: exfiltration) — writing to a UNC/LAN path.
# ---------------------------------------------------------------------------
SHARE_RULES = [
    Rule("SHR001", "Write to network share (UNC path)", "network-share", "exfiltration",
         "HIGH", "MEDIUM", _rx(r"\\\\[A-Za-z0-9._-]+\\[^\s\"']+"),
         "A \\\\server\\share path — data written here leaves the machine over the LAN.",
         "Confirm the share is an expected destination, not an attacker-controlled endpoint."),
]

# ---------------------------------------------------------------------------
# LOCAL FILE READ  (pack: privacy) — reading files off the disk.
# ---------------------------------------------------------------------------
FILE_READ_RULES = [
    Rule("FR001", "Reads local files", "file-read", "privacy",
         "MEDIUM", "MEDIUM",
         _rx(r"\b(\$\$FileExists|Open\s+File[^,\n]*\bRead\b|Read\s+File|Input\s+File|Import\s+File)\b"),
         "Reads files from disk — potentially sensitive files beyond Tally's own data.",
         "Check which paths are read. Reading outside the add-on's own folder is suspicious.",
         strong=False),
]

# ---------------------------------------------------------------------------
# MACHINE RECON  (pack: privacy) — fingerprinting the host.
# ---------------------------------------------------------------------------
RECON_RULES = [
    Rule("RCN001", "Machine / user fingerprinting", "recon", "privacy",
         "INFO", "LOW",
         _rx(r"\$\$(SysName|SysInfo|MachineName|ComputerName|WinUser|UserName|IPAddress|MacAddress|OSInfo)\b"),
         "Collects machine/user identity — common in tracking and targeted attacks.",
         "Benign on its own; note it if paired with any exfil channel.",
         strong=False),
]

# ---------------------------------------------------------------------------
# MODULE LOADER  (pack: persistence) — loading additional TDL code.
# ---------------------------------------------------------------------------
LOADER_RULES = [
    Rule("LOAD001", "Loads additional TDL modules", "loader", "persistence",
         "MEDIUM", "MEDIUM", _rx(r"\[System\s*:\s*TDL\]|\bLoad\s+TDL\b|\bTDL\s*="),
         "Pulls in more TDL code — the loaded code may be where the real behaviour hides.",
         "Identify and scan every module this loads, including any remote ones.",
         strong=False),
]

# ---------------------------------------------------------------------------
# PII FIELDS  (pack: privacy) — specific personal/financial data touched.
# Low severity, but they tell a reviewer *what* would be exposed.
# ---------------------------------------------------------------------------
PII_RULES = [
    Rule("PII001", "Tax identifiers (GSTIN / PAN / VAT / TIN)", "pii", "privacy",
         "INFO", "LOW", _rx(r"\b(GSTIN|GST\s*No\.?|GSTNo|PAN\b|VAT\s*No\.?|TIN\b)\b"),
         "Touches tax identity fields.", "Note as exposed PII if any exfil channel exists.",
         strong=False),
    Rule("PII002", "Bank details (account / IFSC / IBAN / SWIFT)", "pii", "privacy",
         "MEDIUM", "LOW", _rx(r"\b(Bank\s*Account|Account\s*Number|AccountNo|IFSC|IBAN|SWIFT)\b"),
         "Touches bank/financial identifiers.", "High-value PII — flag strongly if exfil is possible.",
         strong=False),
    Rule("PII003", "Contact details (mobile / phone)", "pii", "privacy",
         "INFO", "LOW", _rx(r"\b(Mobile\s*No\.?|MobileNo|Phone\s*No\.?|PhoneNo|Contact\s*No\.?|LedgerMobile)\b"),
         "Touches contact numbers.", "Note as exposed PII if any exfil channel exists.",
         strong=False),
]


ALL_RULES: list[Rule] = (
    NETWORK_RULES
    + FILE_RULES
    + AUTORUN_RULES
    + OBFUSCATION_RULES
    + DATA_RULES
    + LICENSING_RULES
    + CODE_EXEC_RULES
    + DB_RULES
    + EMAIL_RULES
    + SHARE_RULES
    + FILE_READ_RULES
    + RECON_RULES
    + LOADER_RULES
    + PII_RULES
)


def rules_for_packs(packs) -> list[Rule]:
    """Return the rules whose pack is enabled."""
    enabled = set(packs)
    return [r for r in ALL_RULES if r.pack in enabled]


def rules_by_category() -> dict[str, list[Rule]]:
    out: dict[str, list[Rule]] = {}
    for r in ALL_RULES:
        out.setdefault(r.category, []).append(r)
    return out
