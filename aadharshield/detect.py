"""Aadhaar number detection/masking on plain text (Excel cells, PDF text layers)."""
import re
from . import verhoeff

AADHAAR_RE = re.compile(r"(?<!\d)(\d{4})([ \-]?)(\d{4})([ \-]?)(\d{4})(?!\d)")
VID_RE = re.compile(r"(?<!\d)(\d{4})([ \-]?)(\d{4})([ \-]?)(\d{4})([ \-]?)(\d{4})(?!\d)")
HEADER_HINT = re.compile(r"aadh?a+r|adhar|\buid\b|uidai", re.I)


def mask_first8(s: str, ch: str = "X") -> str:
    """Replace the first 8 digits in s with ch, keeping separators."""
    n = 0
    out = []
    for c in s:
        if c.isdigit() and n < 8:
            out.append(ch)
            n += 1
        else:
            out.append(c)
    return "".join(out)


def mask_text(s: str, force: bool = False, mask_vid: bool = True):
    """Mask Aadhaar numbers (first 8 digits) in a string; 16-digit VIDs keep only the last 4.
    force=True also masks Verhoeff-invalid 12-digit numbers (used under an Aadhaar-titled column).
    Returns (new_text, count)."""
    cnt = 0

    def vid(m):
        nonlocal cnt
        cnt += 1
        out, n = [], 0
        for c in m.group(0):
            if c.isdigit():
                out.append("X" if n < 12 else c)
                n += 1
            else:
                out.append(c)
        return "".join(out)

    def aad(m):
        nonlocal cnt
        d = m.group(1) + m.group(3) + m.group(5)
        if verhoeff.is_aadhaar(d) or (force and d[0] in "23456789"):
            cnt += 1
            return mask_first8(m.group(0))
        return m.group(0)

    if mask_vid:
        s = VID_RE.sub(vid, s)
    s = AADHAAR_RE.sub(aad, s)
    return s, cnt
