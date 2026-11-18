---
name: TDL sample submission
about: Submit a real-world .tdl add-on (benign or malicious-technique) for the benchmark corpus
title: "[sample] "
labels: sample-submission
---

<!--
Before posting, please read CONTRIBUTING.md's sanitization checklist.
Do NOT paste a file that still contains real company names, ledger data,
GSTINs, bank details, real domains/IPs, or real credentials.
-->

### Label
<!-- Delete the one that doesn't apply -->
- Benign (should scan CLEAN/CAUTION)
- Malicious / risky technique (should scan SUSPICIOUS or above)

### What it does
<!-- Plain-English description. For a malicious sample, what capability
     does it demonstrate (exfiltration, obfuscation, persistence, etc.)? -->



### Where it came from
<!-- A forum, a client's installed add-on, something you wrote to test an
     evasion idea, etc. This helps us judge how realistic it is. -->



### Sanitization checklist
- [ ] Any real domain/IP/hostname replaced with a fake one (prefer the
      reserved `*.invalid` TLD)
- [ ] Any real company name, ledger/account name, GSTIN, PAN, bank details,
      email, or phone number replaced with placeholders
- [ ] Any real API key, password, or token removed or replaced with
      `REDACTED`
- [ ] If malicious: made inert (points at a non-resolving destination and/or
      stripped of logic that would actually harvest/transmit real data)
- [ ] Any obfuscation you've already decoded is explained below, rather than
      left for us to reverse blind

### Sample

```
<!-- Paste the sanitized .tdl contents here, or attach the file -->
```
