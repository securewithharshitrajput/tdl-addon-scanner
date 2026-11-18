# Contributing

The single most valuable thing you can contribute right now isn't code — it's
**real-world `.tdl` samples**. The detection benchmark (`benchmark.py`) currently
runs on a synthetic corpus built from technique templates. Real add-ons, good
and bad, are the strongest proof this scanner actually holds up outside a lab.

## Submitting a TDL sample

**Please open an Issue first — don't submit a raw `.tdl` file directly in a PR.**
Every sample that goes into this repo gets manually reviewed and sanitized
before it's added, so that:

- no real company data, ledger names, GSTINs, or customer/vendor records ever
  land in a public repo,
- no sample is a *working* piece of malware — this repo is a detection
  benchmark, not a malware archive,
- the benign corpus stays genuinely benign (so it keeps testing for false
  positives, not accidentally testing for true positives).

### How to submit

1. Open a new Issue using the **"TDL sample submission"** template (or just
   title it `[sample] short description`).
2. Attach the `.tdl` file, or paste its contents in a code block.
3. Tell us:
   - **Label**: is this a *benign* add-on, or does it demonstrate a
     *malicious/risky technique*?
   - **What it does** in your own words (e.g. "sends ledger data to a remote
     server on startup", "just reformats the invoice header — no network/file
     access").
   - **Where it came from** (a forum, a client's installed add-on, something
     you wrote yourself to test an evasion idea, etc.) — this helps us judge
     how realistic the technique is.
4. **Sanitize it before posting**, following the checklist below. If you're
   not sure how, say so in the issue and we'll help — just don't post an
   un-sanitized file with real data in it.

### Sanitization checklist (required before we accept it)

- [ ] Any real domain, IP, or hostname is replaced with something clearly
      fake — use the reserved `*.invalid` TLD (e.g. `collect.example.invalid`),
      or a private/example address. Never leave a real, resolvable destination
      in a sample.
- [ ] Any real company name, ledger/account name, GSTIN, PAN, bank account
      number, email address, or phone number is replaced with placeholder
      values.
- [ ] Any real API key, password, or token is removed or replaced with an
      obviously fake placeholder (e.g. `REDACTED`).
- [ ] If the sample demonstrates a malicious *technique* (e.g. exfiltration,
      obfuscation, persistence), it should be **inert** — pointed at a
      non-resolving destination and/or stripped of any logic that would
      actually harvest or transmit real data if run. Think of it the way an
      EICAR test file works for antivirus: it should trip the detector
      without being a functional threat. `samples/risky_demo.tdl` is the
      existing example of this.
- [ ] No obfuscation layer is left un-decoded by you if you already know
      what it decodes to — tell us in the issue, so we're not trying to
      reverse-engineer a mystery blob blind.

If a submitted sample can't be safely sanitized without destroying what makes
it interesting (e.g. the malicious logic can't be separated from the real
destination), describe the technique in the issue instead and we'll build a
synthetic equivalent — that's exactly how the current corpus started.

### What happens after you submit

- A maintainer runs the scanner against your sample locally and checks the
  verdict against your claimed label.
- If it's benign: it goes into `tests/corpus/benign/`.
- If it demonstrates a technique we don't already cover (or covers one
  better than our synthetic version): it goes into the malicious corpus used
  by `benchmark.py`, and if it reveals a detection gap, that becomes a new
  rule in `rules.py`.
- `benchmark.py` is re-run to confirm recall/false-positive rates still hold
  with the sample added.
- You're credited in the commit message (and here, if you'd like a mention)
  as the contributor who found it.

A sample that doesn't match its claimed label, still contains real data after
the checklist, or turns out to be a genuinely working piece of malware will be
rejected — we'll explain why in the issue rather than silently closing it.

## Contributing code / rules

Smaller, equally welcome contributions:

- **New detection rules** — add a `Rule(...)` to `rules.py` with an id,
  category, pack, severity, base confidence, a regex, and a `why`/`recommend`
  a non-technical user can act on. Add a test case to
  `tests/test_scanner.py` or `tests/test_rigor.py` and run `pytest -q`.
- **False-positive reports** — if the scanner flags something you believe is
  genuinely benign, open an issue with the snippet (sanitized per the
  checklist above) and we'll either tune the rule's confidence or add it to
  the benign corpus as a regression test.
- **Bug reports / evasions you've found** — if you can make the scanner miss
  something it should catch, that's a real finding. Open an issue describing
  the technique (sanitized sample preferred, description is fine too).

Before opening a PR for code changes:

```bash
pip install pytest flask
pytest -q
python benchmark.py --min-recall 1.0 --max-fp 0.0
```

Both should pass — CI will run the same checks on every PR.
