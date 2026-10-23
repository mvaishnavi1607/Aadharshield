"""Local OCR (RapidOCR / ONNX) - nothing leaves the machine."""
import threading
import cv2
import numpy as np

_lock = threading.Lock()
_engine = None


def _get():
    global _engine
    if _engine is None:
        from rapidocr_onnxruntime import RapidOCR
        _engine = RapidOCR()
    return _engine


def run_ocr(bgr: np.ndarray):
    """Return [(quad 4x2 float32 in original pixel coords, text, conf)]."""
    h, w = bgr.shape[:2]
    m = max(h, w)
    s = 1.0
    if m < 1400:
        s = 1800 / m
    elif m > 2800:
        s = 2800 / m
    if s != 1.0:
        img = cv2.resize(bgr, None, fx=s, fy=s, interpolation=cv2.INTER_CUBIC if s > 1 else cv2.INTER_AREA)
    else:
        img = bgr
    with _lock:
        res, _ = _get()(img)
    return [(np.array(quad, dtype=np.float32) / s, str(text), float(conf)) for quad, text, conf in (res or [])]
