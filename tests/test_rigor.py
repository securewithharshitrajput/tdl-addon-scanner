"""
test_rigor.py — Measurement, fuzzing, and performance.

  * Benchmark gate — the scanner must catch every sample in the labeled malicious
    corpus and stay quiet on every benign one.
  * Fuzzing — random and mutated input must never crash the analyzer.
  * Performance — a large add-on must scan quickly (guards against O(n^2) blow-ups).
"""

import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tdl_scanner import analyze          # noqa: E402
import benchmark                          # noqa: E402


# --- Measurement ----------------------------------------------------------
def test_benchmark_full_recall_no_false_alarms():
    m = benchmark.compute_metrics()
    assert m["recall"] == 1.0, f"missed: {m['missed']}"
    assert m["fp_rate"] == 0.0, f"false alarms: {m['false_alarms']}"
    assert m["n_malicious"] >= 15 and m["n_benign"] >= 3


# --- Fuzzing --------------------------------------------------------------
_ALPHABET = list(' \n\t:;[]"\'+#@$%\\/.0123456789abcdefghijklmnopqrstuvwxyzABCXYZ_')


def test_fuzz_random_input_never_crashes():
    rng = random.Random(20260814)
    for _ in range(400):
        n = rng.randint(0, 500)
        s = "".join(rng.choice(_ALPHABET) for _ in range(n))
        analyze(s)          # must not raise


def test_fuzz_mutated_samples_never_crash():
    rng = random.Random(99)
    demo = (Path(__file__).resolve().parent.parent / "samples" / "risky_demo.tdl"
            ).read_text(encoding="utf-8-sig")
    chars = list(demo)
    for _ in range(150):
        m = chars[:]
        for _ in range(rng.randint(1, 40)):
            i = rng.randrange(len(m))
            m[i] = rng.choice(_ALPHABET)
        analyze("".join(m))


# --- Performance ----------------------------------------------------------
def test_large_addon_scans_quickly():
    block = ("[Function : F{i}]\n"
             "    10 : SET : X{i} : $$CmpMailingName\n"
             "    20 : SET : Y{i} : $$HttpGet:@@U:##X{i}\n"
             "    30 : Type : Ledger\n")
    big = "".join(block.format(i=i) for i in range(2000))
    start = time.perf_counter()
    report = analyze(big)
    elapsed = time.perf_counter() - start
    assert isinstance(report.findings, list)
    assert elapsed < 15.0, f"too slow: {elapsed:.1f}s"
