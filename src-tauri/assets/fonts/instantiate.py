"""Regenerate the bundled static face with fonttools==4.63.0.

Usage: uv run --with fonttools==4.63.0 python instantiate.py /path/to/NotoSansSC-VF.ttf
The upstream input SHA-256 and source URL are pinned in README.md.
"""
import hashlib
from copy import deepcopy
from pathlib import Path
import sys

from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

source = Path(sys.argv[1])
assert hashlib.sha256(source.read_bytes()).hexdigest() == (
    "d68bafcb48a2707749396aa12bbbd833cb70401f3a9a689fd2902c7e0d295964"
), "Unexpected upstream font input"
font = TTFont(source, recalcTimestamp=False)
font = instantiateVariableFont(font, {"wght": 400}, inplace=True)
# Avoid the upstream reserved font name and distinguish this static derivative.
# Preserve the copyright, license, and version records.
names = {
    1: "oxAudit Sans SC",
    2: "Regular",
    3: "oxAudit Sans SC Regular 2.004",
    4: "oxAudit Sans SC Regular",
    6: "oxAuditSansSC-Regular",
    16: "oxAudit Sans SC",
    17: "Regular",
}
for record in font["name"].names:
    if record.nameID in names:
        record.string = names[record.nameID].encode(record.getEncoding())
# printpdf maps one Unicode value per glyph ID in ToUnicode. Give each Unicode
# cmap alias its own (visually identical) glyph, preserving copy/search semantics
# for e.g. ASCII/nonbreaking spaces, bullets/middle dots, and Han/radical pairs.
seen = set()
order = list(font.getGlyphOrder())
for codepoint, glyph in sorted(font.getBestCmap().items()):
    if glyph not in seen:
        seen.add(glyph)
        continue
    alias = f"oxAudit.uni{codepoint:06X}"
    font["glyf"][alias] = deepcopy(font["glyf"][glyph])
    font["hmtx"][alias] = font["hmtx"][glyph]
    if "vmtx" in font:
        font["vmtx"][alias] = font["vmtx"][glyph]
    order.append(alias)
    for subtable in font["cmap"].tables:
        if subtable.isUnicode() and subtable.format != 14 and codepoint in subtable.cmap:
            subtable.cmap[codepoint] = alias
font.setGlyphOrder(order)
font.save(Path(__file__).parent / "oxAuditSansSC-Regular.ttf")
