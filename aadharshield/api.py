"""AadharShield REST API + admin console (static)."""
import hashlib
import io
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
import jwt
from fastapi import Depends, FastAPI, File, Header, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel, Field

from . import config, db, imgmask, service, masking, settings, vault

app = FastAPI(title="AadharShield", version="1.0")
STATIC = Path(__file__).parent / "static"


@app.middleware("http")
async def _role_gate(request, call_next):
    """AADHARSHIELD_ROLE splits the product across servers: a mask server never unmasks, an unmask server never masks."""
    p = request.url.path
    if config.ROLE == "unmask" and (p == "/api/mask" or p.startswith(("/api/jobs", "/api/watchers"))):
        return JSONResponse({"detail": "this server only unmasks (AADHARSHIELD_ROLE=unmask)"}, status_code=404)
    if config.ROLE == "mask" and (p.startswith(("/api/unmask", "/api/vault")) or p.endswith("/unmask")):
        return JSONResponse({"detail": "this server only masks (AADHARSHIELD_ROLE=mask)"}, status_code=404)
    return await call_next(request)
_stops = {}


# ---------------------------------------------------------------- auth
def _jwt_key():
    return config.secret("AADHARSHIELD_JWT_KEY")


def _token(u, perms):
    exp = datetime.now(timezone.utc) + timedelta(minutes=config.JWT_TTL_MIN)
    return jwt.encode({"sub": u["username"], "perms": perms, "exp": exp}, _jwt_key(), "HS256")


def current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "missing token")
    try:
        claims = jwt.decode(authorization[7:], _jwt_key(), algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(401, "invalid or expired token")
    with db.connect() as c:           # permissions re-read from DB each call: role changes bite immediately
        u = c.execute("select u.*, r.name as role from users u left join roles r on r.id=u.role_id where username=%s",
                      (claims["sub"],)).fetchone()
        if not u or not u["active"]:
            raise HTTPException(401, "user disabled")
        u["perms"] = [r["perm"] for r in c.execute("select perm from role_permissions where role_id=%s", (u["role_id"],))]
    return u


def need(perm):
    def dep(u=Depends(current_user)):
        if perm not in u["perms"]:
            raise HTTPException(403, f"requires {perm}")
        return u
    return dep


class Login(BaseModel):
    username: str
    password: str


@app.post("/api/auth/login")
def login(b: Login, request: Request):
    with db.connect() as c:
        u = c.execute("select u.*, r.name as role from users u left join roles r on r.id=u.role_id where username=%s", (b.username,)).fetchone()
        now = datetime.now(timezone.utc)
        if u and u["locked_until"] and u["locked_until"] > now:
            raise HTTPException(423, "account locked - try later")
        if not u or not u["active"] or not bcrypt.checkpw(b.password.encode(), u["pwhash"].encode()):
            if u:
                n = u["failed_logins"] + 1
                c.execute("update users set failed_logins=%s, locked_until=%s where id=%s",
                          (n, now + timedelta(minutes=15) if n >= 5 else None, u["id"]))
            db.audit(c, b.username, "login_failed", "", {"ip": request.client.host})
            raise HTTPException(401, "bad credentials")
        c.execute("update users set failed_logins=0, locked_until=null where id=%s", (u["id"],))
        perms = [r["perm"] for r in c.execute("select perm from role_permissions where role_id=%s", (u["role_id"],))]
        db.audit(c, b.username, "login", "", {"ip": request.client.host})
    return {"token": _token(u, perms), "username": u["username"], "role": u["role"], "perms": perms}


@app.get("/api/me")
def me(u=Depends(current_user)):
    return {"username": u["username"], "role": u["role"], "perms": u["perms"]}


def _api_key_or_user(x_api_key: str = Header(None), authorization: str = Header(None)):
    """Machine clients (the KYC extraction tool) use X-Api-Key; humans use a bearer token with doc.mask."""
    if x_api_key:
        h = hashlib.sha256(x_api_key.encode()).hexdigest()
        with db.connect() as c:
            k = c.execute("select name from api_keys where key_hash=%s and active", (h,)).fetchone()
        if not k:
            raise HTTPException(401, "bad api key")
        return "apikey:" + k["name"]
    u = current_user(authorization)
    if "doc.mask" not in u["perms"]:
        raise HTTPException(403, "requires doc.mask")
    return u["username"]


# ---------------------------------------------------------------- masking (ongoing extraction)
@app.post("/api/mask")
async def mask(file: UploadFile = File(...), mask_qr: bool = None, actor: str = Depends(_api_key_or_user)):
    """Called by the KYC extraction pipeline for every extracted file. Returns the file to store:
    the masked version, or the untouched original when nothing sensitive was found."""
    data = await file.read()
    if not masking.supported("." + (file.filename or "").rsplit(".", 1)[-1]):
        raise HTTPException(415, "unsupported file type")
    # optional per-request override of the global QR setting (?mask_qr=false keeps QR codes visible)
    tok = imgmask.MASK_QR_OVERRIDE.set(mask_qr)
    try:
        st, doc_id, out, rep = service.ingest(data, file.filename, "api", actor)
    finally:
        imgmask.MASK_QR_OVERRIDE.reset(tok)
    if st == "duplicate":
        with db.connect() as c:
            d = c.execute("select masked_path,status from documents where id=%s", (doc_id,)).fetchone()
        out = Path(d["masked_path"]).read_bytes() if d["masked_path"] else data
        st = d["status"]
    hdr = {"X-AadharShield-Status": st, "X-AadharShield-Doc": doc_id}
    return Response(out if out is not None else data, media_type="application/octet-stream", headers=hdr)


# ---------------------------------------------------------------- registers
@app.get("/api/documents")
def documents(status: str = None, q: str = None, limit: int = 100, offset: int = 0, u=Depends(need("doc.view"))):
    sql, args = "select id,name,kind,origin,status,numbers,qr,needs_review,verified,in_place,vaulted,source_path,linked_source,created_at from documents where true", []
    if status:
        sql += " and status=%s"; args.append(status)
    if q:
        sql += " and (name ilike %s or source_path ilike %s)"; args += [f"%{q}%"] * 2
    with db.connect() as c:
        rows = c.execute(sql + " order by created_at desc limit %s offset %s", args + [min(limit, 500), offset]).fetchall()
        tot = c.execute("select count(*) n from documents where true" + (" and status=%s" if status else ""), [status] if status else []).fetchone()["n"]
    return {"total": tot, "items": rows}


@app.get("/api/documents/{doc_id}/masked")
def masked_copy(doc_id: str, u=Depends(need("doc.view"))):
    with db.connect() as c:
        d = c.execute("select name,masked_path from documents where id=%s", (doc_id,)).fetchone()
    if not d or not d["masked_path"]:
        raise HTTPException(404, "no masked copy")
    return FileResponse(d["masked_path"], filename=d["name"])


@app.get("/api/stats")
def stats(u=Depends(need("doc.view"))):
    with db.connect() as c:
        return {"by_status": c.execute("select status, count(*) n, coalesce(sum(numbers),0) numbers, coalesce(sum(qr),0) qr from documents group by status").fetchall(),
                "indexed": c.execute("select count(*) n from vault_index").fetchone()["n"],
                "unmask_today": c.execute("select count(*) n from unmask_events where at::date=now()::date").fetchone()["n"]}


# ---------------------------------------------------------------- back-fill jobs
class BackfillReq(BaseModel):
    roots: list[str]
    mode: str = "copy"              # copy | inplace
    manifest: str | None = None


@app.post("/api/jobs/backfill")
def start_backfill(b: BackfillReq, u=Depends(need("job.run"))):
    if b.mode not in ("copy", "inplace"):
        raise HTTPException(400, "mode must be copy or inplace")
    try:
        service.validate_roots(b.roots)
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db.connect() as c:
        jid = c.execute("insert into jobs(kind,status,params,actor) values('backfill','queued',%s,%s) returning id",
                        (__import__("json").dumps(b.model_dump()), u["username"])).fetchone()["id"]
        db.audit(c, u["username"], "backfill_start", str(jid), b.model_dump())
    ev = threading.Event()
    _stops[jid] = ev
    threading.Thread(target=service.backfill, args=(jid, b.roots, b.mode, u["username"], b.manifest, ev), daemon=True).start()
    return {"job_id": jid}


@app.get("/api/jobs")
def jobs(u=Depends(need("doc.view"))):
    with db.connect() as c:
        return c.execute("select * from jobs order by id desc limit 50").fetchall()


@app.post("/api/jobs/{jid}/stop")
def stop_job(jid: int, u=Depends(need("job.run"))):
    if jid in _stops:
        _stops[jid].set()
    return {"ok": True}


# ---------------------------------------------------------------- unmask (restricted)
class UnmaskReq(BaseModel):
    reason: str
    ticket: str = ""


def _guard_unmask(u, ip, reason, ticket, doc_ids):
    """Reason, source-address and daily-allowance checks for N documents; every refusal is logged per document."""
    with db.connect() as c:
        def deny(code, msg):
            for d in doc_ids:
                c.execute("insert into unmask_events(doc_id,username,reason,ticket,ip,outcome) values(%s,%s,%s,%s,%s,%s)",
                          (d, u["username"], reason, ticket, ip, "denied:" + msg))
            db.audit(c, u["username"], "unmask_denied", ",".join(doc_ids)[:200], {"why": msg, "ip": ip, "count": len(doc_ids)})
            raise HTTPException(code, msg)
        if len(reason.strip()) < config.MIN_REASON_LEN:
            deny(400, f"reason must be at least {config.MIN_REASON_LEN} characters")
        allowed = [x.strip() for x in (u["allowed_ips"] or "").split(",") if x.strip()]
        if allowed and ip not in allowed:
            deny(403, "source address not allowed for this user")
        used = c.execute("select count(*) n from unmask_events where username=%s and outcome='granted' and at::date=now()::date",
                         (u["username"],)).fetchone()["n"]
        if used + len(doc_ids) > u["daily_unmask_limit"]:
            deny(429, f"daily unmask limit would be exceeded ({used} used of {u['daily_unmask_limit']}, {len(doc_ids)} requested)")


@app.post("/api/documents/{doc_id}/unmask")
def unmask(doc_id: str, b: UnmaskReq, request: Request, u=Depends(need("unmask.execute"))):
    _guard_unmask(u, request.client.host, b.reason, b.ticket, [doc_id])
    try:
        name, data = service.unmask(doc_id, u, b.reason.strip(), b.ticket, request.client.host)
    except LookupError as e:
        raise HTTPException(404, str(e))
    except PermissionError as e:
        raise HTTPException(409, str(e))
    return Response(data, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


class BulkUnmask(BaseModel):
    doc_ids: list[str]
    reason: str
    ticket: str = ""


@app.post("/api/unmask/bulk")
def unmask_bulk(b: BulkUnmask, request: Request, u=Depends(need("unmask.execute"))):
    """Unmask several selected documents under one reason. One doc -> the file itself; several -> a zip.
    All-or-nothing on the checks (reason, address, allowance); each document is logged separately."""
    ids = list(dict.fromkeys(b.doc_ids))
    if not ids:
        raise HTTPException(400, "select at least one document")
    if len(ids) > 25:
        raise HTTPException(400, "at most 25 documents per request")
    ip = request.client.host
    with db.connect() as c:
        have = {str(r["id"]) for r in c.execute("select doc_id as id from vault_index where doc_id = any(%s::uuid[])", (ids,))}
    missing = [i for i in ids if i not in have]
    if missing:
        raise HTTPException(404, f"no original held for {len(missing)} of the selected documents")
    _guard_unmask(u, ip, b.reason, b.ticket, ids)
    files = []
    for i in ids:
        try:
            files.append(service.unmask(i, u, b.reason.strip(), b.ticket, ip))
        except PermissionError as e:
            raise HTTPException(409, str(e))
        except LookupError as e:
            raise HTTPException(404, str(e))
    hdr = {"Cache-Control": "no-store"}
    if len(files) == 1:
        hdr["Content-Disposition"] = f'attachment; filename="{files[0][0]}"'
        return Response(files[0][1], media_type="application/octet-stream", headers=hdr)
    import zipfile
    buf, used = io.BytesIO(), set()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            n, k = name, 1
            while n in used:
                k += 1
                stem, dot, ext = name.rpartition(".")
                n = f"{stem} ({k}).{ext}" if dot else f"{name} ({k})"
            used.add(n)
            z.writestr(n, data)
    hdr["Content-Disposition"] = 'attachment; filename="unmasked_originals.zip"'
    return Response(buf.getvalue(), media_type="application/zip", headers=hdr)


_DOC_COLS = "doc_id as id,name,kind,status,source_path,numbers,qr,in_place,created_at"


@app.get("/api/unmask/allowance")
def unmask_allowance(u=Depends(need("unmask.execute"))):
    """Today's unmask allowance for the signed-in user (every released file counts)."""
    with db.connect() as c:
        used = c.execute("select count(*) n from unmask_events where username=%s and outcome='granted' and at::date=now()::date",
                         (u["username"],)).fetchone()["n"]
    lim = u["daily_unmask_limit"]
    return {"limit": lim, "used": used, "remaining": max(lim - used, 0)}


@app.get("/api/unmask/search")
def unmask_search(folder: str = "", q: str = "", limit: int = 100, u=Depends(need("unmask.execute"))):
    """Find documents whose original we hold, by the folder they were processed from and/or a name fragment.
    Searches the register only - never the server file system."""
    sql, args = f"select {_DOC_COLS} from vault_index where true", []
    f = folder.strip().replace("/", "\\").rstrip("\\")
    if f:                                    # prefix match without LIKE (backslash is LIKE's escape character)
        pre = f + "\\"
        sql += " and (lower(left(source_path, %s)) = lower(%s) or lower(source_path) = lower(%s))"
        args += [len(pre), pre, f]
    if q.strip():
        sql += " and name ilike %s"
        args.append(f"%{q.strip()}%")
    with db.connect() as c:
        rows = c.execute(sql + " order by created_at desc limit %s", args + [min(limit, 200)]).fetchall()
        db.audit(c, u["username"], "unmask_search", f or "(any)", {"q": q, "found": len(rows)})
    return rows


@app.post("/api/unmask/identify")
async def unmask_identify(file: UploadFile = File(...), u=Depends(need("unmask.execute"))):
    """Browse for a masked file on the user's machine: identify it by content hash. Nothing is stored."""
    data = await file.read()
    sha = hashlib.sha256(data).hexdigest()
    with db.connect() as c:
        rows = c.execute(f"select {_DOC_COLS}, (orig_sha256=%s) as is_original from vault_index where (masked_sha256=%s or orig_sha256=%s) order by created_at desc",
                         (sha, sha, sha)).fetchall()
        db.audit(c, u["username"], "unmask_lookup", sha[:16], {"file": file.filename, "size": len(data), "found": len(rows)})
    return {"sha256": sha, "matches": rows}


class VaultScan(BaseModel):
    path: str


@app.post("/api/vault/scan")
def vault_scan(b: VaultScan, u=Depends(need("unmask.execute"))):
    """Point this server at a vault folder or a single .vault file (from this or another server sharing the key)."""
    try:
        return service.scan_vault(b.path, u["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/api/vault/status")
def vault_status(u=Depends(need("unmask.execute"))):
    with db.connect() as c:
        n = c.execute("select count(*) n from vault_index").fetchone()["n"]
    return {"role": config.ROLE, "key_id": vault.key_id(), "vault_dir": str(settings.get("vault_dir")), "indexed": n}


@app.get("/api/unmask-events")
def unmask_events(u=Depends(need("unmask.view_log"))):
    with db.connect() as c:
        return c.execute("select e.*, coalesce(v.name, d.name) as name from unmask_events e left join vault_index v on v.doc_id=e.doc_id left join documents d on d.id=e.doc_id order by e.id desc limit 200").fetchall()


# ---------------------------------------------------------------- audit + admin
@app.get("/api/audit")
def audit(limit: int = 200, u=Depends(need("audit.view"))):
    with db.connect() as c:
        return c.execute("select seq,at,actor,action,target,detail from audit_log order by seq desc limit %s", (min(limit, 1000),)).fetchall()


@app.get("/api/audit/verify")
def audit_verify(u=Depends(need("audit.view"))):
    with db.connect() as c:
        return db.verify_audit(c)


class NewUser(BaseModel):
    username: str
    password: str
    role: str
    daily_unmask_limit: int | None = Field(None, ge=0, le=1000)      # blank = the default set in Settings
    allowed_ips: str = ""


@app.get("/api/users")
def users(u=Depends(need("admin.users"))):
    with db.connect() as c:
        return c.execute("select u.id,username,active,daily_unmask_limit,allowed_ips,r.name role from users u left join roles r on r.id=u.role_id order by u.id").fetchall()


@app.post("/api/users")
def new_user(b: NewUser, u=Depends(need("admin.users"))):
    if len(b.password) < 12:
        raise HTTPException(400, "password must be at least 12 characters")
    with db.connect() as c:
        r = c.execute("select id from roles where name=%s", (b.role,)).fetchone()
        if not r:
            raise HTTPException(400, "unknown role")
        try:
            c.execute("insert into users(username,pwhash,role_id,daily_unmask_limit,allowed_ips) values(%s,%s,%s,%s,%s)",
                      (b.username, bcrypt.hashpw(b.password.encode(), bcrypt.gensalt()).decode(), r["id"],
                       b.daily_unmask_limit if b.daily_unmask_limit is not None else settings.get("default_unmask_limit"), b.allowed_ips))
        except Exception:
            raise HTTPException(409, "username exists")
        db.audit(c, u["username"], "user_create", b.username, {"role": b.role})
    return {"ok": True}


class UserPatch(BaseModel):
    active: bool | None = None
    role: str | None = None
    daily_unmask_limit: int | None = Field(None, ge=0, le=1000)
    allowed_ips: str | None = None


@app.patch("/api/users/{username}")
def patch_user(username: str, b: UserPatch, u=Depends(need("admin.users"))):
    with db.connect() as c:
        if b.role:
            r = c.execute("select id from roles where name=%s", (b.role,)).fetchone()
            if not r:
                raise HTTPException(400, "unknown role")
            c.execute("update users set role_id=%s where username=%s", (r["id"], username))
        for f in ("active", "daily_unmask_limit", "allowed_ips"):
            v = getattr(b, f)
            if v is not None:
                c.execute(f"update users set {f}=%s where username=%s", (v, username))
        db.audit(c, u["username"], "user_update", username, b.model_dump(exclude_none=True))
    return {"ok": True}


@app.get("/api/roles")
def roles(u=Depends(need("admin.users"))):
    with db.connect() as c:
        return c.execute("select r.name, array_agg(rp.perm order by rp.perm) perms from roles r left join role_permissions rp on rp.role_id=r.id group by r.name order by r.name").fetchall()


class RolePerms(BaseModel):
    perms: list[str]


@app.put("/api/roles/{name}")
def set_role_perms(name: str, b: RolePerms, u=Depends(need("admin.users"))):
    with db.connect() as c:
        r = c.execute("select id from roles where name=%s", (name,)).fetchone()
        if not r:
            raise HTTPException(404, "no such role")
        c.execute("delete from role_permissions where role_id=%s", (r["id"],))
        for p in b.perms:
            if c.execute("select 1 from permissions where code=%s", (p,)).fetchone():
                c.execute("insert into role_permissions values(%s,%s)", (r["id"], p))
        db.audit(c, u["username"], "role_update", name, {"perms": b.perms})
    return {"ok": True}


class NewKey(BaseModel):
    name: str


@app.post("/api/apikeys")
def new_key(b: NewKey, u=Depends(need("admin.users"))):
    key = "ash_" + secrets.token_urlsafe(32)
    with db.connect() as c:
        c.execute("insert into api_keys(name,key_hash) values(%s,%s)", (b.name, hashlib.sha256(key.encode()).hexdigest()))
        db.audit(c, u["username"], "apikey_create", b.name)
    return {"name": b.name, "api_key": key, "note": "shown once"}


# ---------------------------------------------------------------- settings (folder paths) + watchers
@app.get("/api/features")
def features(u=Depends(current_user)):
    """What the UI should show: which masking options are switched on."""
    return {"mask_qr": bool(settings.get("mask_qr")), "mask_vid": bool(settings.get("mask_vid")), "role": config.ROLE, "key_id": vault.key_id()}


@app.get("/api/settings")
def get_settings(u=Depends(current_user)):
    s = settings.get_all(True)
    if "admin.settings" in u["perms"]:
        return {**s, "editable": True}
    if "job.run" in u["perms"]:                       # operators only need the saved folders
        return {"backfill_roots": s["backfill_roots"], "manifest": s["manifest"], "editable": False}
    raise HTTPException(403, "requires admin.settings or job.run")


class SettingsPatch(BaseModel):
    masked_dir: str | None = None
    vault_dir: str | None = None
    backfill_roots: list[str] | None = None
    manifest: str | None = None
    watch_folders: list[str] | None = None
    watch_enabled: bool | None = None
    allowed_roots: list[str] | None = None
    mask_qr: bool | None = None
    mask_vid: bool | None = None
    default_unmask_limit: int | None = None


@app.put("/api/settings")
def put_settings(b: SettingsPatch, u=Depends(need("admin.settings"))):
    changes = b.model_dump(exclude_none=True)
    for k in ("backfill_roots", "watch_folders", "allowed_roots"):
        if k in changes:
            changes[k] = [x.strip() for x in changes[k] if x.strip()]
    try:
        new = settings.save(changes, u["username"])
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {**new, "editable": True}


class PathCheck(BaseModel):
    path: str
    storage: bool = False


@app.post("/api/settings/check-path")
def check_path(b: PathCheck, u=Depends(need("admin.settings"))):
    return settings.check_path(b.path, writable=b.storage, storage=b.storage)


@app.get("/api/watchers")
def watchers(u=Depends(need("job.run"))):
    return service.watcher_status()


@app.post("/api/watchers/{action}")
def watcher_action(action: str, b: PathCheck, u=Depends(need("job.run"))):
    if action not in ("start", "stop"):
        raise HTTPException(404, "unknown action")
    if b.path not in settings.get("watch_folders"):
        raise HTTPException(400, "folder is not in the configured watch folders (Settings)")
    try:
        (service.start_watcher if action == "start" else service.stop_watcher)(b.path)
    except ValueError as e:
        raise HTTPException(400, str(e))
    with db.connect() as c:
        db.audit(c, u["username"], "watcher_" + action, b.path)
    return service.watcher_status()


@app.on_event("startup")
def _autostart_watchers():
    try:
        if settings.get("watch_enabled") and config.ROLE != "unmask":
            for f in settings.get("watch_folders"):
                try:
                    service.start_watcher(f)
                except ValueError:
                    pass
    except Exception:
        pass


@app.get("/api/health")
def health():
    with db.connect() as c:
        c.execute("select 1")
    return {"ok": True, "time": time.time()}


@app.get("/")
def console():
    return FileResponse(STATIC / "index.html", headers={"Cache-Control": "no-store"})
