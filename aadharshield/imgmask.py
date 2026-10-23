"""Pixel-level irreversible masking of Aadhaar numbers (first 8 digits), VIDs and QR codes in images."""
import re
from contextvars import ContextVar
from dataclasses import dataclass, field
import cv2
import numpy as np
from . import verhoeff, config, settings
from .ocr import run_ocr

KEYWORDS = re.compile(r"aadh?a+r|adhar|unique identification|uidai|government of india|आधार|ఆధార్", re.I)
# per-request override of config.MASK_QR (None = use the global setting)
MASK_QR_OVERRIDE: ContextVar = ContextVar("mask_qr_override", default=None)
_CONF = str.maketrans({"O": "0", "o": "0", "I": "1", "l": "1", "|": "1"})


@dataclass
class Finding:
    kind: str                 # aadhaar | vid | qr
    last4: str = ""
    verhoeff: bool = False
    low_conf: bool = False
    bbox: tuple = ()


@dataclass
class ImageResult:
    image: np.ndarray
    findings: list = field(default_factory=list)
    aadhaar_like: bool = False
    needs_review: bool = False
    verified: bool = True
    notes: list = field(default_factory=list)


def _tokens(ocr):
    toks = []
    for quad, text, _ in ocr:
        if sum(c.isdigit() for c in text) < 2:
            continue
        core = text.replace(" ", "").replace("-", "")
        dig = sum(c.isdigit() for c in core)
        t = text.translate(_CONF) if core and dig / len(core) >= 0.7 else text
        q = quad
        toks.append({"q": q, "t": t, "L": max(len(t), 1),
                     "cx": float(q[:, 0].mean()), "cy": float(q[:, 1].mean()),
                     "h": float(np.linalg.norm(q[3] - q[0])) or 1.0})
    return toks


def _edge(q, f):
    return q[0] + (q[1] - q[0]) * f, q[3] + (q[2] - q[3]) * f


def _lines(toks):
    """Group digit tokens that sit on one visual line (left to right)."""
    toks = sorted(toks, key=lambda t: (t["cy"], t["cx"]))
    used, lines = set(), []
    for t in toks:
        if id(t) in used:
            continue
        row = [u for u in toks if id(u) not in used
               and abs(u["cy"] - t["cy"]) < 0.6 * t["h"] and abs(u["h"] - t["h"]) < 0.5 * t["h"]]
        for u in row:
            used.add(id(u))
        row.sort(key=lambda u: u["cx"])
        cur = [row[0]]
        for u in row[1:]:
            gap = u["q"][:, 0].min() - cur[-1]["q"][:, 0].max()
            if gap > 1.6 * t["h"]:
                lines.append(cur)
                cur = [u]
            else:
                cur.append(u)
        lines.append(cur)
    return lines


def _find_targets(toks):
    """-> [(digit_map slice, kind, verhoeff_ok)]; digit_map entries are (token, char_idx, digit)."""
    out = []
    for line in _lines(toks):
        dm = [(t, i, c) for t in line for i, c in enumerate(t["t"]) if c.isdigit()]
        s = "".join(d for _, _, d in dm)
        n, i = len(s), 0
        while i < n:
            if settings.get("mask_vid") and n - i >= 16 and not verhoeff.is_aadhaar(s[i:i + 12]) and s[i + 12:i + 16] != "":
                if re.search(r"\d{4}\s*\d{4}\s*\d{4}\s*\d{4}", " ".join(t["t"] for t in line)):
                    out.append((dm[i:i + 16], "vid", False))
                    i += 16
                    continue
            if n - i >= 12 and s[i] in "23456789":
                ok = verhoeff.is_aadhaar(s[i:i + 12])
                txt = " ".join(t["t"] for t, _, _ in dm[i:i + 12])
                grouped = bool(re.search(r"\d{4}\s+\d{4}\s+\d{4}", txt)) or len({id(t) for t, _, _ in dm[i:i + 12]}) == 3
                if ok or grouped:
                    out.append((dm[i:i + 12], "aadhaar", ok))
                    i += 12
                    continue
            i += 1
    return out


def _refine_boundary(gray, tok, f_est, dw_frac):
    """Snap the digit-8 | digit-9 boundary to the nearest ink gap inside the token."""
    q = tok["q"]
    x0, x1 = int(max(q[:, 0].min(), 0)), int(min(q[:, 0].max(), gray.shape[1]))
    y0, y1 = int(max(q[:, 1].min(), 0)), int(min(q[:, 1].max(), gray.shape[0]))
    if x1 - x0 < 8 or y1 - y0 < 4:
        return f_est, False
    crop = gray[y0:y1, x0:x1]
    _, bw = cv2.threshold(crop, 0, 1, cv2.THRESH_BINARY_INV + cv2.THRESH_OTSU)
    prof = bw.sum(axis=0).astype(float)
    if prof.max() <= 0:
        return f_est, False
    gap = prof <= 0.08 * prof.max()
    W = x1 - x0
    est, span = f_est * W, max(2.0, dw_frac * W * 0.8)
    best, bd, i = None, 1e9, 0
    while i < W:
        if gap[i]:
            j = i
            while j < W and gap[j]:
                j += 1
            c = (i + j) / 2
            if abs(c - est) < span and abs(c - est) < bd:
                best, bd = c, abs(c - est)
            i = j
        else:
            i += 1
    return (best / W, True) if best is not None else (f_est, False)


def _poly(tok, fa, fb, pad=0.14):
    ta, ba = _edge(tok["q"], fa)
    tb, bb = _edge(tok["q"], fb)
    return np.array([ta + (ta - ba) * pad, tb + (tb - bb) * pad, bb + (bb - tb) * pad, ba + (ba - ta) * pad], dtype=np.int32)


def _mask_one(img, gray, sl, kind):
    """Black out digits [0,8) of an Aadhaar (or [0,12) of a VID)."""
    nmask = 12 if kind == "vid" else 8
    last_tok, nxt = sl[nmask - 1][0], sl[nmask]
    by_tok = {}
    for tok, idx, _ in sl[:nmask]:
        by_tok.setdefault(id(tok), (tok, []))[1].append(idx)
    for tok, idxs in by_tok.values():
        fa = max(min(idxs) / tok["L"] - 0.02, 0.0)
        hi = max(idxs)
        if tok is last_tok and nxt[0] is tok:
            f_est = (hi + 1 + nxt[1]) / 2 / tok["L"]
            dw = 1.0 / tok["L"]
            f_ref, ok = _refine_boundary(gray, tok, f_est, dw)
            fb = f_ref + (0.0 if ok else 0.25 * dw)
        else:
            fb = (hi + 1) / tok["L"] + 0.03
        cv2.fillPoly(img, [_poly(tok, fa, min(fb, 1.0))], (0, 0, 0))
    allq = np.vstack([t["q"] for t, _, _ in sl])
    return (int(allq[:, 0].min()), int(allq[:, 1].min()), int(allq[:, 0].max()), int(allq[:, 1].max()))


def _qr_boxes(bgr):
    det = cv2.QRCodeDetector()
    h, w = bgr.shape[:2]
    quads = []
    for s in ([1.0, 2.0] if max(h, w) < 1500 else [1.0]):
        v = bgr if s == 1.0 else cv2.resize(bgr, None, fx=s, fy=s, interpolation=cv2.INTER_CUBIC)
        try:
            ok, pts = det.detectMulti(v)
        except cv2.error:
            ok, pts = False, None
        if ok and pts is not None:
            quads += [p.astype(np.float32) / s for p in pts]
    for y0 in range(0, h, max(h // 3, 1)):          # tiles: small QRs are missed on a whole page
        tile = bgr[y0:y0 + h // 2 + 1]
        v = cv2.resize(tile, None, fx=2, fy=2, interpolation=cv2.INTER_CUBIC)
        try:
            ok, pts = det.detectMulti(v)
        except cv2.error:
            ok, pts = False, None
        if ok and pts is not None:
            quads += [p.astype(np.float32) / 2 + np.array([0, y0], dtype=np.float32) for p in pts]
    quads = quads + _qr_heuristic(bgr)      # union: cv2 often finds only the clearest QR on a page
    uniq = []
    for q in quads:
        c = q.mean(axis=0)
        if all(np.linalg.norm(c - u.mean(axis=0)) > 0.3 * np.linalg.norm(q[0] - q[2]) for u in uniq):
            uniq.append(q)
    return uniq


def _qr_heuristic(bgr):
    """Fallback for dense QRs cv2 cannot localise: sliding square windows whose four quadrants all show
    QR-like texture (mid ink density, many transitions in BOTH directions), then non-max suppression."""
    h, w = bgr.shape[:2]
    sc = 700 / max(h, w) if max(h, w) > 700 else 1.0
    g = cv2.cvtColor(cv2.resize(bgr, None, fx=sc, fy=sc, interpolation=cv2.INTER_AREA) if sc != 1 else bgr, cv2.COLOR_BGR2GRAY)
    bw = (cv2.adaptiveThreshold(g, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY_INV, 15, 8) > 0).astype(np.float32)
    tx = np.zeros_like(bw); tx[:, 1:] = np.abs(np.diff(bw, axis=1))
    ty = np.zeros_like(bw); ty[1:, :] = np.abs(np.diff(bw, axis=0))
    I = [cv2.integral(a) for a in (bw, tx, ty)]
    H, W = g.shape

    def grid(ii, xs, ys, s):
        X, Y = np.meshgrid(xs, ys)
        return (ii[Y + s, X + s] - ii[Y, X + s] - ii[Y + s, X] + ii[Y, X]) / (s * s)

    hits = []
    for frac in (0.09, 0.12, 0.15, 0.19, 0.24):
        s = int(W * frac)
        q = s // 2
        st = max(s // 5, 2)
        xs, ys = np.arange(0, W - s, st), np.arange(0, H - s, st)
        if len(xs) == 0 or len(ys) == 0:
            continue
        ok = np.ones((len(ys), len(xs)), bool)
        score = np.ones((len(ys), len(xs)), np.float32)
        for dx, dy in ((0, 0), (q, 0), (0, q), (q, q)):
            d = grid(I[0], xs + dx, ys + dy, q)
            t1, t2 = grid(I[1], xs + dx, ys + dy, q), grid(I[2], xs + dx, ys + dy, q)
            ok &= (d > 0.3) & (d < 0.7) & (t1 > 0.22) & (t2 > 0.22)
            score = np.minimum(score, np.minimum(t1, t2))
        for yi, xi in zip(*np.nonzero(ok)):
            hits.append((float(score[yi, xi]), int(xs[xi]), int(ys[yi]), s))
    # merge overlapping windows into one box per code
    boxes = [[x, y, x + s, y + s] for _, x, y, s in hits]
    merged = True
    while merged:
        merged = False
        for i in range(len(boxes)):
            for j in range(i + 1, len(boxes)):
                A, B = boxes[i], boxes[j]
                if A[0] < B[2] and B[0] < A[2] and A[1] < B[3] and B[1] < A[3]:
                    boxes[i] = [min(A[0], B[0]), min(A[1], B[1]), max(A[2], B[2]), max(A[3], B[3])]
                    del boxes[j]
                    merged = True
                    break
            if merged:
                break
    return [np.array([[x0, y0], [x1, y0], [x1, y1], [x0, y1]], dtype=np.float32) / sc
            for x0, y0, x1, y1 in boxes if 0.7 < (x1 - x0) / max(y1 - y0, 1) < 1.4]


def _mask_qr(img, quad, grow=0.10):
    c = quad.mean(axis=0)
    p = (c + (quad - c) * (1 + grow)).astype(np.int32)
    cv2.fillPoly(img, [p], (0, 0, 0))
    return (int(p[:, 0].min()), int(p[:, 1].min()), int(p[:, 0].max()), int(p[:, 1].max()))


def _scan(bgr):
    ocr = run_ocr(bgr)
    return ocr, _find_targets(_tokens(ocr)), bool(KEYWORDS.search(" ".join(t for _, t, _ in ocr)))


def mask_image(bgr: np.ndarray, verify: bool = None) -> ImageResult:
    verify = config.VERIFY_AFTER_MASK if verify is None else verify
    img = bgr.copy()
    gray = cv2.cvtColor(bgr, cv2.COLOR_BGR2GRAY)
    _, targets, kw = _scan(bgr)
    res = ImageResult(image=img, aadhaar_like=kw)
    originals = []
    for sl, kind, ok in targets:
        digits = "".join(d for _, _, d in sl)
        bb = _mask_one(img, gray, sl, kind)
        originals.append(digits)
        res.findings.append(Finding(kind, digits[-4:], ok, low_conf=not ok, bbox=bb))
    qrs = _qr_boxes(bgr) if (settings.get("mask_qr") if MASK_QR_OVERRIDE.get() is None else MASK_QR_OVERRIDE.get()) and (kw or targets) else []
    for q in qrs:
        res.findings.append(Finding("qr", bbox=_mask_qr(img, q)))
    res.aadhaar_like = res.aadhaar_like or bool(qrs or targets)
    if res.aadhaar_like and not targets:
        res.needs_review = True
        res.notes.append("Aadhaar-like page but no number located by OCR - manual review")
    if any(f.low_conf for f in res.findings if f.kind != "qr"):
        res.notes.append("number masked without Verhoeff validation (OCR uncertainty)")
    if verify and originals:
        res.verified = _verify(img, originals)
        if not res.verified:
            res.needs_review = True
            res.notes.append("post-mask verification found residual digits")
    return res


def _verify(masked, originals):
    """Re-OCR the masked image: no original digit run (5+) of the masked 8 may survive."""
    ocr, targets, _ = _scan(masked)
    comp = re.sub(r"\D", "", " ".join(t for _, t, _ in ocr))
    for d in originals:
        if any(d[a:a + 5] in comp for a in range(0, 4)):   # windows inside digits 1-8
            return False
    return not any(k == "aadhaar" and ok for _, k, ok in targets)
