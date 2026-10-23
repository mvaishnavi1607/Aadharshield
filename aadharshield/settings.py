"""Runtime settings editable from the console (stored in PostgreSQL, audited).
Env/config values are only the first-run defaults."""
import json
import time
from pathlib import Path

from . import config, db

DEFAULTS = {
    "masked_dir": str(config.OUT_DIR),     # where masked copies are written
    "vault_dir": str(config.VAULT_DIR),    # where encrypted originals are written
    "backfill_roots": [],                  # saved folders offered on the Back-fill page
    "manifest": "",                        # default manifest CSV (extracted image -> source scan page)
    "watch_folders": [],                   # drop-folders masked in place by the watcher
    "watch_enabled": False,                # start those watchers automatically when the service starts
    "allowed_roots": [],
    "default_unmask_limit": 10,            # daily unmask allowance given to newly created users (per-user value can be changed afterwards)
    "mask_qr": config.MASK_QR,             # also black out QR codes (old-format Aadhaar QR carries the full number)
    "mask_vid": config.MASK_VID,           # also mask the first 12 digits of 16-digit Virtual IDs                   # if non-empty, back-fill/watch folders must sit inside one of these
}
_cache = {"t": 0, "v": None}


def get_all(force=False):
    if not force and _cache["v"] is not None and time.time() - _cache["t"] < 3:
        return _cache["v"]
    v = dict(DEFAULTS)
    try:
        with db.connect() as c:
            for r in c.execute("select key,value from settings"):
                v[r["key"]] = r["value"]
    except Exception:
        pass                                # DB not ready (first run): defaults
    _cache.update(t=time.time(), v=v)
    return v


def get(key):
    return get_all()[key]


def out_dir() -> Path:
    p = Path(get("masked_dir"))
    p.mkdir(parents=True, exist_ok=True)
    return p


def vault_dir() -> Path:
    p = Path(get("vault_dir"))
    if config.ROLE != "unmask":              # an unmask server only points at the masking server's vault; never creates it
        p.mkdir(parents=True, exist_ok=True)
    return p


def managed_dirs():
    """Folders the tool itself writes into - never treated as input."""
    return [config.DATA_DIR.resolve(), Path(get("masked_dir")).resolve(), Path(get("vault_dir")).resolve()]


def inside(p: Path, parent: Path) -> bool:
    p, parent = p.resolve(), parent.resolve()
    return p == parent or parent in p.parents


def check_path(path: str, writable: bool = False, storage: bool = False):
    """Describe a folder for the UI 'Test path' button."""
    from . import masking
    p = Path(path.strip()) if path else None
    out = {"path": path, "exists": False, "is_dir": False, "writable": None, "supported_files": None, "managed": False, "problems": []}
    if not p or not str(p).strip():
        out["problems"].append("empty path")
        return out
    out["exists"] = p.exists()
    out["is_dir"] = p.is_dir()
    if not p.is_dir():
        if storage and not p.exists():
            out["note"] = "does not exist yet - it will be created when you save"
        else:
            out["problems"].append("folder does not exist" if not p.exists() else "not a folder")
    else:
        out["managed"] = any(inside(p, m) for m in managed_dirs())
        if out["managed"] and not storage:
            out["problems"].append("inside AadharShield's own output/vault/data area")
        n = 0
        for i, f in enumerate(p.rglob("*")):
            if i > 20000:
                out["supported_files"] = f"{n}+ (stopped counting)"
                break
            if f.is_file() and masking.supported(f.suffix):
                n += 1
        else:
            out["supported_files"] = n
        try:
            t = p / ".ashield_write_test"
            t.write_text("x")
            t.unlink()
            out["writable"] = True
        except OSError:
            out["writable"] = False
            if writable:
                out["problems"].append("folder is not writable")
    return out


def validate(changes: dict):
    """Raise ValueError with a readable message if the proposed settings are unsafe."""
    cur = {**get_all(True), **changes}
    for k in changes:
        if k not in DEFAULTS:
            raise ValueError(f"unknown setting {k}")
    for k in ("masked_dir", "vault_dir"):
        if k in changes and config.ROLE == "unmask":
            if k == "vault_dir" and not Path(changes[k]).is_dir():
                raise ValueError(f"vault_dir: {changes[k]} is not an existing folder (mount or copy the masking server's vault first)")
            continue
        if k in changes:
            p = Path(changes[k])
            try:
                p.mkdir(parents=True, exist_ok=True)
            except OSError as e:
                raise ValueError(f"{k}: cannot create {p} ({e.strerror})")
            c = check_path(str(p), writable=True)
            if not c["writable"]:
                raise ValueError(f"{k}: {p} is not writable")
    m, v = Path(cur["masked_dir"]).resolve(), Path(cur["vault_dir"]).resolve()
    if config.ROLE != "unmask" and (m == v or inside(m, v) or inside(v, m)):
        raise ValueError("masked folder and vault folder must be separate, non-nested folders")
    inputs = list(cur["backfill_roots"]) + list(cur["watch_folders"])
    for r in inputs:
        rp = Path(r)
        if inside(rp, m) or inside(rp, v) or inside(rp, config.DATA_DIR):
            raise ValueError(f"{r} is inside the masked/vault/data area - input folders must be elsewhere")
        if inside(m, rp) or inside(v, rp):
            raise ValueError(f"{r} contains the masked or vault folder - choose a folder that does not")
    if "default_unmask_limit" in changes:
        v = changes["default_unmask_limit"]
        if isinstance(v, bool) or not isinstance(v, int) or not 0 <= v <= 1000:
            raise ValueError("default daily unmask limit must be a whole number from 0 to 1000")
    allowed = [Path(a) for a in cur["allowed_roots"] if str(a).strip()]
    if allowed:
        for r in inputs:
            if not any(inside(Path(r), a) for a in allowed):
                raise ValueError(f"{r} is not inside any allowed root")
    if cur["manifest"] and not Path(cur["manifest"]).is_file():
        raise ValueError(f"manifest file not found: {cur['manifest']}")


def save(changes: dict, actor: str):
    validate(changes)
    old = get_all(True)
    with db.connect() as c:
        for k, v in changes.items():
            c.execute("insert into settings(key,value) values(%s,%s) on conflict(key) do update set value=excluded.value",
                      (k, json.dumps(v)))
        db.audit(c, actor, "settings_update", "", {k: {"from": old.get(k), "to": v} for k, v in changes.items()})
    _cache["v"] = None
    return get_all(True)
