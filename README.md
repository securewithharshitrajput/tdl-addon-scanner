# TDL Add-on Safety Scanner

A **defensive** tool for the Tally ecosystem. It reviews third-party TDL add-ons
*before* you install them and tells you, in plain English, whether an add-on can
do the dangerous things — reach the network, write files, run at startup, hide
its behaviour, read your ledgers, or tamper with licensing — with line numbers,
confidence levels, and recommendations.

The goal: let a CA, an accountant, or a small business owner drop an unknown
`.tdl` file onto this tool and get a clear **CLEAN / CAUTION / SUSPICIOUS /
REVIEW REQUIRED / DANGEROUS** verdict without having to read TDL themselves.

---

## Detection intelligence

This is what makes the scanner hard to fool. Five layers work together:

| # | Feature | What it does |
|---|---------|--------------|
| 1 | **Deobfuscation engine** | Decodes `$$StrByCharCode`, base64, hex, single-byte **XOR**, **reversed** strings, and **ROT13** — **recursively** (a layer inside a layer inside a layer is peeled until nothing's left) and reassembles **split strings** joined with `+`, including values built across several lines via variables. A URL hidden any of these ways is revealed and re-scanned. |
| 2 | **Data-flow pairing** | `FLOW001` flags read + send in the *same* block. `FLOW002` goes further with **cross-block taint tracking**: it follows a variable that holds sensitive data from where it's read to where it's transmitted, even in a different function — the "look innocent by splitting it up" trick. |
| 3 | **Destination analysis** | Extracts every URL host and classifies it `allowlisted` / `private` / `unknown-internet`. A call to an unknown public host is escalated; a call to `127.0.0.1` is not. |
| 4 | **Confidence scoring** | Every finding is `HIGH` / `MEDIUM` / `LOW`, adjusted by context (obfuscation raises it, an allowlisted destination lowers it). Score weights findings by confidence to cut false alarms. |
| 5 | **Rule packs** | Group rules into `exfiltration`, `persistence`, `privacy`, `licensing-bypass` and enable only what you care about. |

---

## What's in here

| File | What it does |
|------|--------------|
| `tdl_scanner.py` | The scanner + `analyze()` pipeline + CLI. Stdlib only. |
| `rules.py` | The signature knowledge base — every construct, its severity, base confidence, and pack. |
| `deobfuscate.py` | Recursive char-code / base64 / hex / XOR / reverse / ROT13 / URL / gzip decoding + split-string reassembly. |
| `dataflow.py` | Definition-block parsing + interprocedural taint (cross-block & cross-function). |
| `destinations.py` | Extracts and classifies URL hosts. |
| `egress.py` | "Data Leaving the Machine" report — what data → which destination → decide. |
| `reputation.py` | Hash + verdict memory (new / known / CHANGED). |
| `benchmark.py` | Detection benchmark — recall / false-positive / precision on a labeled corpus. |
| `listener.py` | Optional lab capture server for **your own isolated VM**. |
| `tests/test_scanner.py`, `tests/test_rigor.py` | 97 tests: every feature, an evasion corpus, adversarial hardening cases, fuzzing, performance, and the benchmark gate. |
| `tests/corpus/benign/` | Genuinely benign add-ons that must stay quiet (false-alarm corpus). |
| `pyproject.toml`, `.github/workflows/ci.yml` | Packaging + CI (tests and the benchmark gate on every push). |
| `samples/clean_addon.tdl` | A harmless add-on → CLEAN pass. |
| `samples/risky_demo.tdl` | A non-functional demo fixture (like an EICAR test file) → DANGEROUS, to show a flagged report. |

---

## Quick start

```bash
# Scan the harmless sample (no install needed — scanner is pure stdlib)
python tdl_scanner.py samples/clean_addon.tdl

# See a fully-flagged report on the demo fixture
python tdl_scanner.py samples/risky_demo.tdl

# Scan a whole folder of downloaded add-ons
python tdl_scanner.py path/to/addons --recursive

# Machine-readable output + a pre-install gate for CI
python tdl_scanner.py addon.tdl --json report.json --fail-on CRITICAL
```

Example (trimmed) output:

```
── samples/risky_demo.tdl
   verdict     : DANGEROUS — reads sensitive data and can move it off-machine in the same block.
   risk score  : 155
   capabilities: autorun, data-access, data-flow, licensing, network, obfuscation
   destinations:
      [private] collect.example.invalid  (https://collect.example.invalid)
   findings    : 9 (>= INFO/LOW confidence)
     [CRITICAL] FLOW001 Sensitive data + outbound capability in same block  (line 14, HIGH conf, dataflow, pack:exfiltration)
        ! block 'Function: Demo_Flagged' (lines 14-21) contains data-access + network
     [HIGH] NET005 Hard-coded URL literal  (line 23, MEDIUM conf, deobfuscated, pack:exfiltration)
        > [charcode-decoded] http://x.invalid
        ! host x.invalid → private | Revealed by decoding charcode at line 23
```

---

## CLI options

| Flag | Purpose |
|------|---------|
| `--recursive`, `-r` | Recurse into subfolders. |
| `--min-severity {INFO,MEDIUM,HIGH,CRITICAL}` | Only show findings at/above this severity. |
| `--min-confidence {LOW,MEDIUM,HIGH}` | Only show findings at/above this confidence. |
| `--packs a,b,c` | Enable only these rule packs (default: all). |
| `--allow host1,host2` | Trust these hosts (suppresses their escalation). |
| `--config scanner.toml` | Load packs / allowlist / min-confidence from a file. |
| `--fail-on SEVERITY` | Exit code 2 if any finding at/above this severity (CI gate). |
| `--json PATH` | Also write a machine-readable JSON report. |
| `--egress` | Show only the "data leaving the machine" report per file. |
| `--merge` | Treat all files in a folder as ONE add-on (cross-file taint). |
| `--diff OLD NEW` | Compare two versions; flag capabilities added in an update. |
| `--reputation-db PATH` | Report `new` / `known` / `CHANGED` per file against a store. |
| `--remember` | Record the current scan into the reputation DB. |
| `--list-packs` | List rule packs and exit. |
| `--no-color` | Disable ANSI colours. |

### Config file (`scanner.toml`)
```toml
packs = ["exfiltration", "persistence", "privacy", "licensing-bypass", "code-execution"]
allow = ["api.mycrm.com", "sync.myerp.local"]
min_confidence = "LOW"

# Custom organisation rules — add your own patterns without touching code.
[[rule]]
id = "ORG100"
name = "Company-forbidden host"
category = "network"
pack = "exfiltration"
severity = "CRITICAL"
confidence = "HIGH"
regex = "evilcorp\\.internal"
why = "Traffic to evilcorp is banned by policy."
recommend = "Reject this add-on."
```
CLI flags override the config file.

### Measuring detection quality
```bash
python benchmark.py            # recall / false-positive / precision on a labeled corpus
```
Currently **100% recall, 0% false positives** on 26 malicious technique samples +
8 benign add-ons. The malicious corpus is generated in memory from technique
templates, so no usable stealer is stored in the repo.

### Adversarial testing & known limits
The scanner was stress-tested against dozens of evasions and benign-lookalikes.
Two deliberate behaviours are worth knowing:
- **A bare `.exe`/`.dll` *mention*** (e.g. "run setup.exe" in help text) is reported
  as a capability but stays **CAUTION**, not DANGEROUS — only an actual `CALL DLL` /
  `EXECUTE` is treated as code execution.
- **A hard-coded URL literal pointing only at loopback/localhost** (with no real
  call construct) is softened to CAUTION. Any LAN/public/unknown host, IPv6, real
  call, or obfuscation keeps the flag.

Known limitation: **multi-byte (repeating-key) XOR** is only recovered when a URL
appears near the start of the blob (crib-dragging). Arbitrary custom encodings
that a human couldn't recognise by reading are, by nature, out of scope for static
analysis — that is what the sealed-VM dynamic check is for.

---

## What the scanner flags

| Category | Pack | Severity | Meaning |
|----------|------|----------|---------|
| `network` | exfiltration | CRITICAL | Send data off the machine (`$$HttpGet`, `HTTP Post`, `RemoteURL`, URLs). |
| `db-export` | exfiltration | HIGH | Push data to a database / ODBC / SQL. |
| `email` | exfiltration | HIGH | Mail data out (SMTP / SendMail). |
| `network-share` | exfiltration | HIGH | Write to a `\\server\share` (LAN egress). |
| `filesystem` | exfiltration | HIGH | Writes/exports files — a staging step for exfiltration. |
| `obfuscation` | exfiltration | HIGH | Hides behaviour (char-code strings, long encoded blobs). |
| `code-exec` | code-execution | CRITICAL | Runs native code — DLLs or external programs. Can do *anything*. |
| `autorun` | persistence | HIGH | Runs automatically at startup / on load. |
| `loader` | persistence | MEDIUM | Loads more TDL modules (where behaviour may hide). |
| `data-access` | privacy | MEDIUM | Reads sensitive ledgers/vouchers/company data. |
| `bulk-harvest` | privacy | MEDIUM | Reads an entire record type with no filter (mass harvest). |
| `pii` | privacy | INFO–MEDIUM | Names *what* PII is touched (GST/PAN, bank, contact). |
| `file-read` | privacy | MEDIUM | Reads local files off the disk. |
| `recon` | privacy | INFO | Fingerprints the machine/user. |
| `licensing` | licensing-bypass | HIGH | Touches licensing/activation/`tally.ini`. |
| `data-flow` | (derived) | CRITICAL | `FLOW001` read+send in one block; `FLOW002` sensitive data carried **across blocks** to a sink; `FLOW003` sensitive data passed **into a function** that transmits. |

### Deobfuscation covers
character-codes, base64, hex, single-byte XOR, reversed text, ROT13,
URL-encoding, gzip/zlib — **recursively** (layers within layers) and with
**split-string reassembly** across lines/variables.

The **verdict** highlights dangerous *combinations* — network **+** startup, or
network revealed through obfuscation, or read **+** transmit in one block —
because that pairing, not any single line, is what actually matters.

## The headline: "Data Leaving the Machine"

Rather than only listing capabilities, the scanner produces the concrete,
decidable statement a reviewer actually needs — **what data goes where** — and
lets a human approve or reject it:

```
── DATA LEAVING THE MACHINE (approve only if you trust each destination) ──
  [HIGH] bank details, ledger records → would be sent via email to
         collector@evil-drop.tld (an EXTERNAL destination), automatically at startup.
```

Each egress line names the **data** (ledgers, company identity, GST/PAN, bank
details), the **channel** (internet / email / database / share / file), the
**destination**, and the **trigger**. Destinations are graded:

| State | Meaning | Concern |
|-------|---------|---------|
| external | a named outside destination (unknown host / hard-coded address) | HIGH |
| **unknown** | built at runtime — we could NOT verify where it goes | **HIGH** |
| internal | loopback/localhost or an allowlisted host | LOW |
| dynamic | recipient chosen from data at runtime (e.g. the customer's own email) | MEDIUM |

This is why emailing a customer their own statement reads as **REVIEW** ("confirm
it's their own data"), while emailing all ledgers to a hard-coded address reads as
**DANGEROUS**. Run `python tdl_scanner.py addon.tdl --egress` for just this report.

---

## Running the tests

```bash
pip install pytest
pytest -q          # 106 passing
```

The suite includes an **evasion corpus** (every obfuscation trick — char-code,
base64, hex, XOR, reverse, ROT13, double-encoded, split-across-variables — must
be caught), a **false-alarm corpus** (`tests/corpus/benign/` — genuinely benign
add-ons must stay CLEAN/CAUTION), and **robustness tests** (empty, binary, huge,
deeply-nested, and BOM-prefixed inputs must never crash).

The positive test inputs are tiny inline snippets built from the rule tokens, not
shippable add-ons — this repo never contains a working malicious TDL. The only
on-disk specimen, `samples/risky_demo.tdl`, is deliberately inert (its endpoints
are the reserved, non-resolving `*.invalid` domain and it has no data-harvesting
logic — it exists purely to trip the detector, like an EICAR test file).

---

## Optional: watching behaviour in a sealed lab

To *confirm* a scanner finding against real behaviour, do it safely:

1. Build an **isolated Tally VM**: host-only / no-internet networking, a throwaway
   company with **fake** data, snapshot it so you can roll back.
2. Run the listener **inside that VM** (or on the host-only address):
   ```bash
   pip install flask
   python listener.py            # 127.0.0.1:8899, logs everything to capture.log
   ```
3. Install the add-on you're evaluating *in that VM only*. Anything it tries to
   send to your listener shows up in the console and `capture.log`, confirming
   what the scanner predicted from the source.

**Rules of the lab:** only add-ons you own/control, only a VM you own, only
host-only networking, only fake data. The listener binds to localhost by design.

---

## Extending the rules

Add a `Rule(...)` to the relevant list in `rules.py` — give it an id, category,
pack, severity, base confidence, a regex, and (importantly) a `why` and
`recommend` a non-technical user can act on. Re-run `pytest`. The scanner picks
up new rules automatically via `ALL_RULES`.

---

## Scope & intent

This project detects and explains risky capability in TDL source. It does not
execute TDL, generate add-ons, or transmit data. It exists to protect the people
who install add-ons — CAs and small businesses — by making an add-on's true
capabilities legible before it's trusted.
