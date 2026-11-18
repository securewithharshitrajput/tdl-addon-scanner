"""
dataflow.py — Block-level pairing analysis for TDL.

A separate "reads ledgers" finding and a separate "makes HTTP calls" finding are
each weak on their own — lots of honest add-ons do one or the other. The strong
signal is when *both happen inside the same definition* (Function, Collection,
System:Startup, ...), because that is the shape of code that harvests data and
then ships it out.

This module splits TDL source into its top-level definition blocks so the
scanner can ask, per block: "does this block both read sensitive data AND have a
way to send it off the machine?" TDL is not fully parsed — blocks are delimited
by their `[Kind : Name]` headers, which is enough to attribute findings to the
definition they live in.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable


# A TDL definition header, e.g. "[Function : Foo]", "[#Part : Bar]",
# "[System : Startup]", "[Collection : Ledgers]".
HEADER_RE = re.compile(r"^\s*\[#?\s*[A-Za-z][\w ]*\s*:\s*.+\]\s*$")

# Variable assignment / reference syntax used for taint tracking.
ASSIGN_RE = re.compile(r"\bSET\b\s*:\s*([\w.]+)\s*:\s*(.+)$", re.IGNORECASE)
VARREF_RE = re.compile(r"(?:##|@@|\$)([\w.]+)")

TOP_LEVEL = "(top-level)"


@dataclass(frozen=True)
class Block:
    kind: str
    name: str
    start: int      # 1-based, inclusive
    end: int        # 1-based, inclusive
    header: str


def _parse_header(line: str) -> tuple[str, str]:
    inner = line.strip()
    inner = inner[1:-1] if inner.startswith("[") and inner.endswith("]") else inner
    inner = inner.lstrip("#").strip()
    if ":" in inner:
        kind, name = inner.split(":", 1)
        return kind.strip(), name.strip()
    return inner.strip(), ""


def find_blocks(text: str) -> list[Block]:
    """Split source into definition blocks (plus a leading top-level block)."""
    lines = text.splitlines()
    if not lines:
        return [Block(TOP_LEVEL, "", 1, 1, "")]

    header_idx = [i + 1 for i, l in enumerate(lines) if HEADER_RE.match(l)]
    blocks: list[Block] = []

    if not header_idx:
        return [Block(TOP_LEVEL, "", 1, len(lines), "")]

    if header_idx[0] > 1:
        blocks.append(Block(TOP_LEVEL, "", 1, header_idx[0] - 1, ""))

    for i, start in enumerate(header_idx):
        end = header_idx[i + 1] - 1 if i + 1 < len(header_idx) else len(lines)
        kind, name = _parse_header(lines[start - 1])
        blocks.append(Block(kind, name, start, end, lines[start - 1].strip()))

    return blocks


def block_for_line(blocks: list[Block], line_no: int) -> Block | None:
    for b in blocks:
        if b.start <= line_no <= b.end:
            return b
    return None


# ---------------------------------------------------------------------------
# Cross-block taint tracking
#
# The structural pairing (data-access + sink in the SAME block) is handled by the
# scanner directly. This adds the harder case: an add-on reads sensitive data into
# a variable in one place and transmits that variable somewhere else, so the read
# and the send never share a block. We follow the variable.
# ---------------------------------------------------------------------------
CALL_RE = re.compile(r"(?:\bCALL\b|\bDO\b)\s*:\s*([\w.]+)", re.IGNORECASE)
FUNCVAL_RE = re.compile(r"\$\$([\w.]+)")


@dataclass(frozen=True)
class Flow:
    var: str
    source_line: int
    source_block: Block
    sink_line: int
    sink_block: Block
    sink_kind: str          # sink category, e.g. "network" | "filesystem" | "email"
    mode: str               # "cross-block" | "interprocedural"


def _strip_comment(s: str) -> str:
    out, q = [], False
    for ch in s:
        if ch == '"':
            q = not q
        if ch == ';' and not q:
            break
        out.append(ch)
    return "".join(out)


def _refs(s: str) -> set[str]:
    return {m.group(1).lower() for m in VARREF_RE.finditer(s)}


def taint_flows(text: str,
                is_source: Callable[[str], bool],
                is_sink: Callable[[str], str | None]) -> list[Flow]:
    """Return flows where sensitive data reaches a sink, following variables AND
    function boundaries.

    Two ways data crosses a boundary:
      * cross-block   — a tainted variable read in one block is transmitted in
                        another (this includes data returned by a "source
                        function" and then sent).
      * interprocedural — a tainted variable is passed as an argument to a
                        function whose body transmits ("sink function").
    """
    lines = text.splitlines()
    blocks = find_blocks(text)

    func_blocks = {b.name.lower(): b for b in blocks
                   if b.kind.lower() == "function" and b.name}

    def body(b: Block) -> list[str]:
        return lines[b.start:b.end]        # exclude the header line itself

    source_funcs = {name for name, b in func_blocks.items()
                    if any(is_source(l) for l in body(b))}
    sink_funcs: dict[str, str] = {}
    for name, b in func_blocks.items():
        for l in body(b):
            k = is_sink(l)
            if k:
                sink_funcs[name] = k
                break

    def refs_source_func(expr: str) -> str | None:
        for m in FUNCVAL_RE.finditer(expr):
            if m.group(1).lower() in source_funcs:
                return m.group(1).lower()
        return None

    assigns: list[tuple[int, str, str]] = []
    for i, line in enumerate(lines, start=1):
        m = ASSIGN_RE.search(line)
        if m:
            assigns.append((i, m.group(1).lower(), _strip_comment(m.group(2))))

    # tainted[var] = origin line (points into the block where the data is *read*,
    # which for a source-function call is that function's definition).
    tainted: dict[str, int] = {}
    for _ in range(len(assigns) + 1):
        changed = False
        for ln, var, rhs in assigns:
            if var in tainted:
                continue
            origin = None
            if is_source(rhs):
                origin = ln
            elif (sf := refs_source_func(rhs)) is not None:
                origin = func_blocks[sf].start
            else:
                inherited = _refs(rhs) & tainted.keys()
                if inherited:
                    origin = tainted[sorted(inherited)[0]]
            if origin is not None:
                tainted[var] = origin
                changed = True
        if not changed:
            break

    flows: list[Flow] = []
    if not tainted:
        return flows

    for i, line in enumerate(lines, start=1):
        refs = _refs(line)
        hit = refs & tainted.keys()

        # Direct sink on this line reached by a tainted variable.
        kind = is_sink(line)
        if kind and hit:
            var = sorted(hit)[0]
            s_block = block_for_line(blocks, tainted[var])
            k_block = block_for_line(blocks, i)
            if s_block and k_block and s_block.start != k_block.start:
                flows.append(Flow(var, tainted[var], s_block, i, k_block,
                                  kind, "cross-block"))
                continue

        # Tainted variable handed to a function whose body transmits.
        if hit:
            callees = ({m.group(1).lower() for m in CALL_RE.finditer(line)}
                       | {m.group(1).lower() for m in FUNCVAL_RE.finditer(line)})
            for callee in callees & sink_funcs.keys():
                var = sorted(hit)[0]
                s_block = block_for_line(blocks, tainted[var])
                k_block = func_blocks[callee]
                flows.append(Flow(var, tainted[var], s_block, i, k_block,
                                  sink_funcs[callee], "interprocedural"))
                break
    return flows
