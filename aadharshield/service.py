"""Core pipeline: mask -> vault original -> register. Used by the API, the back-fill job and the folder watcher."""
import csv
import os
import threading
import uuid
from pathlib import Path

from . import config, db, vault, masking, settings


def _row(c, d):
    cols = ",".join(d)
    c.execute(f"insert into documents({cols}) values({','.join(['%s'] * len(d))})", list(d.values()))


def ingest(data: bytes, name: str, origin: str, actor: str, source_path: str = None, job_id: int = None,
           in_place_path: Path = None, linked_source: str = None):
    """Process one file. Returns (status, doc_id, masked_bytes|None, report).
    status: masked | clean | review | duplicate
    - clean  : no Aadhaar found - file is left untouched, nothing vaulted
    - masked : masked copy produced, original encrypted into the vault
    - review : masked as far as possible but flagged for manual check (nothing is hidden silently)"""
    sha = vault.sha256(data)
    with db.connect() as c:
        dup = c.execute("select id,status,orig_sha256,masked_path from documents where orig_sha256=%s or masked_sha256=%s limit 1", (sha, sha)).fetchone()
    if dup:
        # Same content already processed. If THIS file is still the unmasked original (e.g. a second copy in
        # another folder), it must still be replaced - otherwise the unmasked copy would survive the back-fill.
        if in_place_path is not None and dup["orig_sha256"] == sha and dup["masked_path"] and Path(dup["masked_path"]).exists():
            tmp = in_place_path.with_name(in_place_path.name + ".ashield.tmp")
            tmp.write_bytes(Path(dup["masked_path"]).read_bytes())
            os.replace(tmp, in_place_path)
            with db.connect() as c:
                db.audit(c, actor, "mask_duplicate_replaced", str(dup["id"]), {"name": name, "path": str(in_place_path)})
            return "masked", str(dup["id"]), None, None
        return "duplicate", str(dup["id"]), None, None
    out, rep = masking.mask_bytes(data, name)
    changed = rep.numbers > 0 or rep.qr > 0
    doc_id = str(uuid.uuid4())
    base = dict(id=doc_id, name=name, source_path=source_path, kind=rep.kind, origin=origin, orig_sha256=sha,
                numbers=rep.numbers, qr=rep.qr, needs_review=rep.needs_review, verified=rep.verified,
                details=__import__("json").dumps(rep.dict()), job_id=job_id, linked_source=linked_source)
    if not changed and not rep.needs_review:
        with db.connect() as c:
            _row(c, {**base, "status": "clean", "vaulted": False})
        return "clean", doc_id, None, rep
    will_replace = in_place_path is not None and changed
    status = "review" if rep.needs_review else "masked"
    meta = {"name": name, "kind": rep.kind, "status": status, "source_path": source_path, "orig_sha256": sha,
            "masked_sha256": vault.sha256(out), "numbers": rep.numbers, "qr": rep.qr, "in_place": will_replace,
            "created": __import__("datetime").datetime.now().astimezone().isoformat()}
    vpath = vault.put(doc_id, data, meta)                   # original safe BEFORE anything is replaced; meta travels with it
    mpath = settings.out_dir() / doc_id / name
    mpath.parent.mkdir(parents=True, exist_ok=True)
    mpath.write_bytes(out)
    in_place = False
    if in_place_path is not None and changed:
        tmp = in_place_path.with_name(in_place_path.name + ".ashield.tmp")
        tmp.write_bytes(out)
        os.replace(tmp, in_place_path)
        in_place = True
    with db.connect() as c:
        _row(c, {**base, "status": status, "masked_sha256": vault.sha256(out), "masked_path": str(mpath),
                 "in_place": in_place, "vaulted": True, "vault_path": vpath})
        _index(c, doc_id, vpath, meta)
        db.audit(c, actor, "mask", doc_id, {"name": name, "origin": origin, "numbers": rep.numbers, "qr": rep.qr,
                                             "status": status, "in_place": in_place})
    return status, doc_id, out, rep


def _index(c, doc_id, vpath, meta):
    """Register a vault object (from our own masking or from a scan of another server's vault)."""
    c.execute("""insert into vault_index(doc_id,vault_path,name,kind,status,source_path,orig_sha256,masked_sha256,numbers,qr,in_place,key_id,created_at)
                 values(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,coalesce(%s::timestamptz, now()))
                 on conflict(doc_id) do update set vault_path=excluded.vault_path, name=excluded.name, kind=excluded.kind, status=excluded.status,
                   source_path=excluded.source_path, orig_sha256=excluded.orig_sha256, masked_sha256=excluded.masked_sha256, numbers=excluded.numbers,
                   qr=excluded.qr, in_place=excluded.in_place, key_id=excluded.key_id, indexed_at=now()""",
              (doc_id, vpath, meta.get("name"), meta.get("kind"), meta.get("status"), meta.get("source_path"), meta.get("orig_sha256"),
               meta.get("masked_sha256"), meta.get("numbers", 0), meta.get("qr", 0), bool(meta.get("in_place")), vault.key_id(), meta.get("created")))


def scan_vault(path: str, actor: str):
    """Point this server at a vault folder (searched recursively) or a single .vault file written by ANY server
    that shares the master key, and register what is found. Reads headers only; originals stay encrypted."""
    p = Path(str(path).strip())
    if not p.exists():
        raise ValueError(f"not found: {path}")
    files = [p] if p.is_file() else sorted(p.rglob("*.vault"))
    res = {"path": str(p), "found": len(files), "indexed": 0, "wrong_key": 0, "legacy_no_meta": 0, "unreadable": 0, "problems": []}
    for f in files:
        try:
            meta = vault.read_meta(f)
        except vault.WrongKey as e:
            res["wrong_key"] += 1
            if len(res["problems"]) < 5:
                res["problems"].append(f"{f.name}: {e}")
            continue
        except Exception as e:
            res["unreadable"] += 1
            if len(res["problems"]) < 5:
                res["problems"].append(f"{f.name}: {e!r}"[:160])
            continue
        if not meta:
            res["legacy_no_meta"] += 1       # ASV1: only the masking server's database knows what it is
            continue
        with db.connect() as c:
            _index(c, meta["doc_id"], str(f), meta)
        res["indexed"] += 1
    with db.connect() as c:
        db.audit(c, actor, "vault_scan", str(p), {k: v for k, v in res.items() if k != "problems"})
    return res


def unmask(doc_id: str, user: dict, reason: str, ticket: str, ip: str):
    """Return original bytes. Caller has already enforced RBAC/limits; this logs and decrypts."""
    with db.connect() as c:
        d = c.execute("select name,vault_path from vault_index where doc_id=%s", (doc_id,)).fetchone()
        if not d:
            raise LookupError("no original held for this document")
        try:
            data = vault.get(doc_id, d["vault_path"])
        except vault.WrongKey as e:
            c.execute("insert into unmask_events(doc_id,username,reason,ticket,ip,outcome) values(%s,%s,%s,%s,%s,%s)",
                      (doc_id, user["username"], reason, ticket, ip, "failed:key mismatch"))
            db.audit(c, user["username"], "unmask_failed", doc_id, {"why": str(e)})
            raise PermissionError(f"cannot open this vault file: {e}")
        except FileNotFoundError:
            raise LookupError("the vault file is no longer at the indexed location - rescan the vault folder")
        c.execute("insert into unmask_events(doc_id,username,reason,ticket,ip,outcome) values(%s,%s,%s,%s,%s,'granted')",
                  (doc_id, user["username"], reason, ticket, ip))
        db.audit(c, user["username"], "unmask", doc_id, {"reason": reason, "ticket": ticket, "ip": ip, "name": d["name"]})
    return d["name"], data


# ---------------------------------------------------------------- back-fill
def load_manifest(path):
    """CSV columns: extracted_path, source_path, source_page  ->  {extracted_path: (source_path, page)}"""
    m = {}
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            m[str(Path(r["extracted_path"]))] = (r.get("source_path", ""), r.get("source_page", ""))
    return m


def validate_roots(roots):
    """Reject empty input, missing folders, the tool's own output/vault/data folders and (if configured)
    folders outside the allowed roots."""
    roots = [str(r).strip() for r in (roots or []) if str(r).strip()]
    if not roots:
        raise ValueError("give at least one folder")
    allowed = [Path(a) for a in settings.get("allowed_roots") if str(a).strip()]
    for r in roots:
        rp = Path(r)
        if not rp.is_dir():
            raise ValueError(f"not a folder: {r}")
        if any(settings.inside(rp, m) for m in settings.managed_dirs()):
            raise ValueError(f"{r} is inside the AadharShield output/vault/data area - choose the folder holding the files to mask")
        if allowed and not any(settings.inside(rp, a) for a in allowed):
            raise ValueError(f"{r} is not inside an allowed root (Settings > Allowed roots)")


def backfill(job_id: int, roots, mode: str, actor: str, manifest: str = None, stop: threading.Event = None):
    """Walk roots; mask every supported file. mode='inplace' replaces files (originals vaulted), 'copy' leaves
    them and writes masked copies to the managed output area. Already-processed files are skipped by hash,
    so the job is resumable. Source scans named in the manifest are processed first."""
    validate_roots(roots)
    manifest = manifest or settings.get("manifest") or None
    links = load_manifest(manifest) if manifest else {}
    files = []
    managed = settings.managed_dirs()
    for r in roots:
        for p in Path(r).rglob("*"):
            if p.is_file() and masking.supported(p.suffix) and not any(settings.inside(p, m) for m in managed) and not p.name.endswith(".ashield.tmp"):
                files.append(p)
    pri = {str(Path(s)) for s, _ in links.values() if s}
    files.sort(key=lambda p: (str(p) not in pri, str(p)))
    with db.connect() as c:
        c.execute("update jobs set total=%s, status='running' where id=%s", (len(files), job_id))
    cnt = dict(masked=0, clean=0, review=0, failed=0, skipped=0)
    for p in files:
        if stop is not None and stop.is_set():
            break
        try:
            link = links.get(str(p))
            st, _, _, _ = ingest(p.read_bytes(), p.name, "backfill", actor, str(p), job_id,
                                 in_place_path=p if mode == "inplace" else None,
                                 linked_source=f"{link[0]}#{link[1]}" if link else None)
            cnt["skipped" if st == "duplicate" else st] += 1
        except Exception as e:                                     # one bad file must not stop the job
            cnt["failed"] += 1
            with db.connect() as c:
                db.audit(c, actor, "backfill_error", str(p), {"error": repr(e)[:300]})
        with db.connect() as c:
            c.execute("update jobs set masked=%s,clean=%s,review=%s,failed=%s,skipped=%s where id=%s",
                      (cnt["masked"], cnt["clean"], cnt["review"], cnt["failed"], cnt["skipped"], job_id))
    with db.connect() as c:
        c.execute("update jobs set status=%s, finished_at=now() where id=%s",
                  ("stopped" if stop is not None and stop.is_set() else "done", job_id))
        db.audit(c, actor, "backfill_done", str(job_id), cnt)
    return cnt


# ---------------------------------------------------------------- folder watchers (managed from the console)
import time as _time

_watchers = {}          # folder -> (thread, stop_event, state)


def _watch_loop(folder, stop, state):
    seen = {}
    while not stop.is_set():
        try:
            for p in Path(folder).rglob("*"):
                if stop.is_set():
                    break
                if p.is_file() and masking.supported(p.suffix) and not p.name.endswith(".ashield.tmp"):
                    st = p.stat()
                    key = (st.st_size, st.st_mtime)
                    if seen.get(p) == key or _time.time() - st.st_mtime < 2:          # still being written
                        continue
                    try:
                        s, _, _, _ = ingest(p.read_bytes(), p.name, "watch", "watcher", str(p), in_place_path=p)
                        state["last"] = f"{s}: {p.name}"
                        state["count"] += 1
                        st2 = p.stat()
                        seen[p] = (st2.st_size, st2.st_mtime)
                    except Exception as e:
                        state["last"] = f"error: {p.name}: {e!r}"[:200]
                        seen[p] = key
        except Exception as e:
            state["last"] = f"error: {e!r}"[:200]
        stop.wait(3)


def start_watcher(folder):
    validate_roots([folder])
    if folder in _watchers and _watchers[folder][0].is_alive() and not _watchers[folder][1].is_set():
        return
    stop, state = threading.Event(), {"count": 0, "last": ""}
    t = threading.Thread(target=_watch_loop, args=(folder, stop, state), daemon=True)
    _watchers[folder] = (t, stop, state)
    t.start()


def stop_watcher(folder):
    if folder in _watchers:
        _watchers[folder][1].set()


def watcher_status():
    folders = settings.get("watch_folders")
    out = []
    for f in dict.fromkeys(list(folders) + list(_watchers)):
        w = _watchers.get(f)
        out.append({"folder": f, "configured": f in folders, "running": bool(w and w[0].is_alive() and not w[1].is_set()),
                    "processed": w[2]["count"] if w else 0, "last": w[2]["last"] if w else ""})
    return out
