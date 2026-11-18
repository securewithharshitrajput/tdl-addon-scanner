"""
deobfuscate.py — Reveal hidden content in TDL source.

Add-ons that want to hide a URL, keyword, or command from a plain text scan
build the string indirectly. This module undoes the common tricks and returns
the plaintext so the scanner can re-run its rules against what the code actually
assembles at runtime. It is read-only: it decodes text, it never executes.

Techniques handled
    * $$StrByCharCode:NN + $$StrByCharCode:NN + ...   (character codes)
    * base64 blobs
    * hex blobs
    * single-byte XOR blobs (brute-forced when the result reveals a signal)
    * reversed strings
    * ROT13
    * split strings — literals/variables concatenated with '+', including values
      assembled across several lines (SET : A : "htt"  /  SET : U : ##A + ##B)
    * MULTIPLE LAYERS — every decode is fed back through every decoder (bounded
      by depth + a global budget) so base64-inside-charcode-inside-... is unwound.

Safety of the approach
    A wrong guess is harmless: an artifact only becomes a *finding* if the decoded
    text matches a scanner rule. Decoders that are prone to noise (reverse, ROT13,
    XOR) additionally require a "signal" (a URL/protocol/TDL-call marker) before
    they surface anything, so they don't fire on ordinary text.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import gzip
import re
import zlib
from dataclasses import dataclass
from urllib.parse import unquote


CHARCODE_RE = re.compile(r"\$\$StrByCharCode\s*:\s*(\d{1,7})", re.IGNORECASE)
BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}){8,}\b")
HEX_0X_RE = re.compile(r"0x([0-9a-fA-F]{16,})", re.IGNORECASE)
HEX_SPACED_RE = re.compile(r"(?:[0-9a-fA-F]{2}[ ,]){7,}[0-9a-fA-F]{2}")

ASSIGN_RE = re.compile(r"\bSET\b\s*:\s*([\w.]+)\s*:\s*(.+)$", re.IGNORECASE)
VARREF_RE = re.compile(r"(?:##|@@|\$)([\w.]+)")

# Markers that a decoded blob is worth surfacing on the noisier decoders.
_SIGNALS = (
    "http://", "https://", "ftp://", "smtp", "://", "remoteurl", "httpget",
    "http post", "httpxmldata", "tally.ini", "$$", "new object",
)

# Strong markers used to gate reverse/ROT13 — these must be *revealed* by the
# transform (present after, absent before), so ordinary text isn't churned.
_STRONG_SIGNALS = (
    "http://", "https://", "ftp://", "smtp:", "httpget", "remoteurl",
    "httpxmldata", "http post", "tally.ini", "new object", "$$strbycharcode",
)

MAX_DEPTH = 4
MAX_ARTIFACTS = 4000
MAX_XOR_BYTES = 512


@dataclass(frozen=True)
class Artifact:
    line_no: int
    method: str      # decode chain, e.g. "base64→charcode"
    decoded: str
    raw: str         # short preview of the encoded source


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------
def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if 32 <= ord(ch) < 127 or ch in "\t\r\n")
    return ok / len(s)


def _looks_meaningful(s: str) -> bool:
    s = s.strip()
    if len(s) < 3 or len(set(s)) < 2 or _printable_ratio(s) < 0.85:
        return False
    return any(ch.isalnum() for ch in s)


def _has_signal(s: str) -> bool:
    low = s.lower()
    return any(sig in low for sig in _SIGNALS)


def _has_strong_signal(s: str) -> bool:
    low = s.lower()
    return any(sig in low for sig in _STRONG_SIGNALS)


def _bytes_to_text(raw: bytes) -> str | None:
    try:
        return raw.decode("utf-8", "strict")
    except UnicodeDecodeError:
        try:
            return raw.decode("latin-1")
        except (UnicodeDecodeError, ValueError):
            return None


def _b64_bytes(token: str) -> bytes | None:
    if len(token) < 16:
        return None
    try:
        return base64.b64decode(token + ("=" * ((-len(token)) % 4)), validate=True)
    except (binascii.Error, ValueError):
        return None


def _hex_bytes(token: str) -> bytes | None:
    if len(token) % 2:
        token = token[:-1]
    if len(token) < 16:
        return None
    try:
        return bytes.fromhex(token)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Individual decoders
# ---------------------------------------------------------------------------
def _decode_charcodes(s: str) -> str | None:
    codes = [int(m.group(1)) for m in CHARCODE_RE.finditer(s)]
    if len(codes) < 2:
        return None
    try:
        chars = "".join(chr(c) for c in codes if 0 < c < 0x110000)
    except (ValueError, OverflowError):
        return None
    return chars if len(chars) >= 2 else None


def _decode_base64(token: str) -> str | None:
    raw = _b64_bytes(token)
    if raw is None or len(raw) < 3:
        return None
    text = _bytes_to_text(raw)
    return text if text and _looks_meaningful(text) else None


def _decode_hex(token: str) -> str | None:
    raw = _hex_bytes(token)
    if raw is None:
        return None
    text = _bytes_to_text(raw)
    return text if text and _looks_meaningful(text) else None


def _url_decode(s: str) -> str | None:
    if "%" not in s:
        return None
    try:
        out = unquote(s)
    except (ValueError, TypeError):
        return None
    return out if out != s else None


def _inflate(raw: bytes) -> str | None:
    """Try gzip / zlib / raw-deflate on a byte blob."""
    if not raw or len(raw) > 1_000_000:
        return None
    for fn in (gzip.decompress,
               zlib.decompress,
               lambda b: zlib.decompress(b, -15)):
        try:
            out = fn(raw)
        except (OSError, zlib.error, EOFError, ValueError):
            continue
        text = _bytes_to_text(out)
        if text and _looks_meaningful(text):
            return text
    return None


def _xor_decodes(s: str) -> list[tuple[str, str]]:
    """Brute single-byte XOR over base64/hex blobs; surface only signalled results.

    A hex blob is also valid base64, so we try *both* byte interpretations of each
    token rather than committing to one.
    """
    out: list[tuple[str, str]] = []
    tokens = set(BASE64_RE.findall(s)) | set(HEX_RE.findall(s))
    for tok in tokens:
        candidates = [raw for raw in (_hex_bytes(tok), _b64_bytes(tok)) if raw]
        for raw in candidates:
            if len(raw) > MAX_XOR_BYTES:
                continue
            hit = False
            for key in range(1, 256):
                text = _bytes_to_text(bytes(b ^ key for b in raw))
                # Strong marker only: a 255-key brute force trips weak signals
                # ("$$", "://") on garbage output almost every time.
                if text and _printable_ratio(text) > 0.9 and _has_strong_signal(text):
                    out.append((f"xor:{key}", text))
                    hit = True
                    break
            if not hit:                                  # multi-byte repeating key
                multi = _repeating_xor(raw)
                if multi:
                    out.append(("xor-multi", multi))
                    hit = True
            if hit:
                break
    return out


_XOR_CRIBS = (b"http://", b"https://", b"ftp://")
# A *realistic* URL (valid dotted domain), used to reject crib-dragging that
# merely forces the crib bytes and leaves garbage after them.
_STRICT_URL_RE = re.compile(r"(?:https?|ftp)://[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.IGNORECASE)


def _repeating_xor(raw: bytes) -> str | None:
    """Recover a short repeating-key XOR by crib-dragging a URL prefix.

    Catches multi-byte keys (up to the crib length) when a URL appears near the
    start of the blob — the realistic case. Cheap and bounded.
    """
    for crib in _XOR_CRIBS:
        span = len(crib)
        for p in range(min(len(raw) - span + 1, 12)):
            for k in range(1, span + 1):
                key = bytearray(k)
                known = [False] * k
                ok = True
                for i in range(span):
                    kb = raw[p + i] ^ crib[i]
                    idx = (p + i) % k
                    if known[idx] and key[idx] != kb:
                        ok = False
                        break
                    key[idx], known[idx] = kb, True
                if not ok or not all(known):
                    continue
                dec = bytes(raw[j] ^ key[j % k] for j in range(len(raw)))
                text = _bytes_to_text(dec)
                # Must decode to a *real* URL, not just the forced crib prefix.
                if text and _printable_ratio(text) > 0.9 and _STRICT_URL_RE.search(text):
                    return text
    return None


def _decoders(s: str, allow_xor: bool) -> list[tuple[str, str]]:
    res: list[tuple[str, str]] = []

    cc = _decode_charcodes(s)
    if cc and _looks_meaningful(cc):
        res.append(("charcode", cc))

    url = _url_decode(s)
    if url and _has_signal(url):
        res.append(("urldecode", url))

    for tok in BASE64_RE.findall(s):
        dec = _decode_base64(tok)
        if dec:
            res.append(("base64", dec))
        rdec = _decode_base64(tok[::-1])        # reversed-then-base64
        if rdec:
            res.append(("base64-reversed", rdec))
    for tok in HEX_RE.findall(s):
        dec = _decode_hex(tok)
        if dec:
            res.append(("hex", dec))
    for m in HEX_0X_RE.finditer(s):             # 0xDEADBEEF... form
        dec = _decode_hex(m.group(1))
        if dec:
            res.append(("hex-0x", dec))
    for m in HEX_SPACED_RE.finditer(s):         # "68 74 74 70 ..." form
        dec = _decode_hex(re.sub(r"[ ,]", "", m.group(0)))
        if dec:
            res.append(("hex-spaced", dec))

    # Compression hidden inside a base64/hex blob.
    for tok in set(BASE64_RE.findall(s)) | set(HEX_RE.findall(s)):
        for raw in (_hex_bytes(tok), _b64_bytes(tok)):
            if not raw:
                continue
            inf = _inflate(raw)
            if inf:
                res.append(("inflate", inf))

    low_s = s.lower()

    def _reveals_strong(transformed: str) -> bool:
        tl = transformed.lower()
        return any(sig in tl and sig not in low_s for sig in _STRONG_SIGNALS)

    rev = s[::-1]
    if _reveals_strong(rev):
        res.append(("reverse", rev))
    try:
        rot = codecs.encode(s, "rot_13")
    except (TypeError, LookupError):
        rot = s
    if _reveals_strong(rot):
        res.append(("rot13", rot))

    if allow_xor:
        res.extend(_xor_decodes(s))
    return res


# ---------------------------------------------------------------------------
# Split-string reassembly (across lines, via a variable map)
# ---------------------------------------------------------------------------
def _strip_comment(s: str) -> str:
    out = []
    q = False
    for ch in s:
        if ch == '"':
            q = not q
        if ch == ';' and not q:
            break
        out.append(ch)
    return "".join(out).strip()


def _split_plus(expr: str) -> list[str]:
    parts, cur, q = [], [], False
    for ch in expr:
        if ch == '"':
            q = not q
            cur.append(ch)
        elif ch == '+' and not q:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts]


def _resolve(rhs: str, varmap: dict[str, str], depth: int = 0) -> str | None:
    if depth > 6:
        return None
    out = []
    for part in _split_plus(_strip_comment(rhs)):
        if not part:
            return None
        if part.startswith('"') and part.endswith('"') and len(part) >= 2:
            out.append(part[1:-1])
            continue
        m = VARREF_RE.fullmatch(part)
        if m and m.group(1).lower() in varmap:
            out.append(varmap[m.group(1).lower()])
            continue
        cc = _decode_charcodes(part)
        if cc:
            out.append(cc)
            continue
        return None       # a component we can't resolve → give up on this expr
    return "".join(out)


def _reconstruct(text: str) -> list[Artifact]:
    lines = text.splitlines()
    varmap: dict[str, str] = {}

    # Pass 1 (repeated to a fixpoint): learn variable → literal string bindings.
    for _ in range(4):
        changed = False
        for raw in lines:
            m = ASSIGN_RE.search(raw)
            if not m:
                continue
            var = m.group(1).lower()
            val = _resolve(m.group(2), varmap)
            if val and varmap.get(var) != val:
                varmap[var] = val
                changed = True
        if not changed:
            break

    # Pass 2: any concatenation that resolves to a signalled string is an artifact.
    arts: list[Artifact] = []
    for i, raw in enumerate(lines, start=1):
        m = ASSIGN_RE.search(raw)
        rhs = m.group(2) if m else raw
        if "+" not in rhs:
            continue
        val = _resolve(rhs, varmap)
        if val and len(val) >= 6 and _has_signal(val):
            arts.append(Artifact(i, "reassembled", val, raw.strip()[:120]))
    return arts


# ---------------------------------------------------------------------------
# Recursive expansion
# ---------------------------------------------------------------------------
def _expand(s: str, line_no: int, depth: int, seen: set[str],
            out: list[Artifact], chain: str) -> None:
    if depth > MAX_DEPTH or len(out) >= MAX_ARTIFACTS:
        return
    for method, dec in _decoders(s, allow_xor=(depth == 0)):
        if not dec or dec in seen:
            continue
        seen.add(dec)
        label = f"{chain}{method}"
        out.append(Artifact(line_no, label, dec,
                            s.strip()[:120] if depth == 0 else "(decoded layer)"))
        _expand(dec, line_no, depth + 1, seen, out, chain=f"{label}→")


def deobfuscate(text: str) -> list[Artifact]:
    """Every decoded/reconstructed artifact in the source, anchored to its line."""
    out: list[Artifact] = []
    seen: set[str] = set()

    reconstructed = _reconstruct(text)
    for art in reconstructed:
        if art.decoded not in seen:
            seen.add(art.decoded)
            out.append(art)

    for line_no, raw in enumerate(text.splitlines(), start=1):
        if raw.strip():
            _expand(raw, line_no, 0, seen, out, chain="")

    # Peel further layers off anything we reconstructed.
    for art in reconstructed:
        _expand(art.decoded, art.line_no, 1, seen, out, chain=f"{art.method}→")

    return out
