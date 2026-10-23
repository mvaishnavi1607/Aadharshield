"""PostgreSQL schema + helpers (own database/role: no sharing with any other Finverge product)."""
import hashlib
import json
import psycopg
from psycopg.rows import dict_row
from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS permissions(code text PRIMARY KEY, description text);
CREATE TABLE IF NOT EXISTS roles(id serial PRIMARY KEY, name text UNIQUE NOT NULL, description text);
CREATE TABLE IF NOT EXISTS role_permissions(role_id int REFERENCES roles(id) ON DELETE CASCADE,
  perm text REFERENCES permissions(code) ON DELETE CASCADE, PRIMARY KEY(role_id, perm));
CREATE TABLE IF NOT EXISTS users(id serial PRIMARY KEY, username text UNIQUE NOT NULL, pwhash text NOT NULL,
  role_id int REFERENCES roles(id), active boolean DEFAULT true, daily_unmask_limit int DEFAULT 10,
  allowed_ips text DEFAULT '', failed_logins int DEFAULT 0, locked_until timestamptz, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS api_keys(id serial PRIMARY KEY, name text UNIQUE NOT NULL, key_hash text NOT NULL,
  active boolean DEFAULT true, created_at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS jobs(id serial PRIMARY KEY, kind text, status text, params jsonb, total int DEFAULT 0,
  masked int DEFAULT 0, clean int DEFAULT 0, review int DEFAULT 0, failed int DEFAULT 0, skipped int DEFAULT 0,
  started_at timestamptz DEFAULT now(), finished_at timestamptz, actor text, message text);
CREATE TABLE IF NOT EXISTS documents(id uuid PRIMARY KEY, name text, source_path text, kind text, origin text,
  status text, orig_sha256 text, masked_sha256 text, masked_path text, in_place boolean DEFAULT false,
  numbers int DEFAULT 0, qr int DEFAULT 0, needs_review boolean DEFAULT false, verified boolean DEFAULT true,
  vaulted boolean DEFAULT false, linked_source text, details jsonb, job_id int, created_at timestamptz DEFAULT now());
CREATE INDEX IF NOT EXISTS ix_doc_orig ON documents(orig_sha256);
CREATE INDEX IF NOT EXISTS ix_doc_masked ON documents(masked_sha256);
CREATE TABLE IF NOT EXISTS unmask_events(id serial PRIMARY KEY, doc_id uuid, username text, reason text, ticket text,
  ip text, outcome text, at timestamptz DEFAULT now());
CREATE TABLE IF NOT EXISTS settings(key text PRIMARY KEY, value jsonb);
CREATE TABLE IF NOT EXISTS vault_index(doc_id uuid PRIMARY KEY, vault_path text NOT NULL, name text, kind text, status text,
  source_path text, orig_sha256 text, masked_sha256 text, numbers int DEFAULT 0, qr int DEFAULT 0, in_place boolean DEFAULT false,
  key_id text, created_at timestamptz DEFAULT now(), indexed_at timestamptz DEFAULT now());
CREATE INDEX IF NOT EXISTS ix_vi_masked ON vault_index(masked_sha256);
CREATE INDEX IF NOT EXISTS ix_vi_orig ON vault_index(orig_sha256);
ALTER TABLE documents ADD COLUMN IF NOT EXISTS vault_path text;
CREATE TABLE IF NOT EXISTS audit_log(seq bigserial PRIMARY KEY, at timestamptz DEFAULT now(), actor text, action text,
  target text, detail jsonb, prev_hash text, hash text);
"""

PERMS = {
    "doc.view": "View document register and masked copies",
    "doc.mask": "Submit files for masking",
    "job.run": "Run back-fill jobs",
    "unmask.execute": "Unmask (retrieve original) a document",
    "unmask.view_log": "View unmask events",
    "audit.view": "View and verify the audit trail",
    "admin.users": "Manage users, roles, API keys",
    "admin.settings": "Change folder paths and watcher settings",
}
ROLES = {
    "Administrator": ["doc.view", "job.run", "admin.users", "admin.settings", "audit.view"],
    "Operator": ["doc.view", "doc.mask", "job.run"],
    "Unmask Officer": ["doc.view", "unmask.execute", "unmask.view_log"],
    "Auditor": ["doc.view", "audit.view", "unmask.view_log"],
}


def connect():
    return psycopg.connect(config.DB_URL, row_factory=dict_row, autocommit=True)


def init_db():
    """Create role+database (needs admin URL once), schema, permissions, roles. Role/database names, and the
    password, come from AADHARSHIELD_DB_URL so a second instance (e.g. an unmask server) gets its own database."""
    from urllib.parse import urlparse
    from psycopg import sql
    u = urlparse(config.DB_URL)
    role, pw, dbname = u.username, u.password or "", u.path.lstrip("/")
    with psycopg.connect(config.ADMIN_DB_URL, autocommit=True) as c:
        if not c.execute("select 1 from pg_roles where rolname=%s", (role,)).fetchone():
            c.execute(sql.SQL("create role {} login password {}").format(sql.Identifier(role), sql.Literal(pw)))
        if not c.execute("select 1 from pg_database where datname=%s", (dbname,)).fetchone():
            c.execute(sql.SQL("create database {} owner {}").format(sql.Identifier(dbname), sql.Identifier(role)))
    with connect() as c:
        c.execute(SCHEMA)
        # one-time: older documents (vault format ASV1) become searchable through the vault index
        c.execute("""insert into vault_index(doc_id,vault_path,name,kind,status,source_path,orig_sha256,masked_sha256,numbers,qr,in_place,created_at)
                     select id,vault_path,name,kind,status,source_path,orig_sha256,masked_sha256,numbers,qr,in_place,created_at
                     from documents where vaulted and vault_path is not null on conflict do nothing""")
        for code, desc in PERMS.items():
            c.execute("insert into permissions values(%s,%s) on conflict do nothing", (code, desc))
        for name, perms in ROLES.items():
            c.execute("insert into roles(name) values(%s) on conflict do nothing", (name,))
            rid = c.execute("select id from roles where name=%s", (name,)).fetchone()["id"]
            for p in perms:
                c.execute("insert into role_permissions values(%s,%s) on conflict do nothing", (rid, p))


def audit(c, actor, action, target="", detail=None):
    """Append to the hash-chained audit trail (tamper-evident); advisory lock keeps the chain linear."""
    c.execute("select pg_advisory_lock(7001)")
    try:
        prev = c.execute("select hash from audit_log order by seq desc limit 1").fetchone()
        prev_hash = prev["hash"] if prev else "GENESIS"
        d = json.loads(json.dumps(detail or {}, default=str))
        body = json.dumps({"actor": actor, "action": action, "target": target, "detail": d}, sort_keys=True)
        h = hashlib.sha256((prev_hash + body).encode()).hexdigest()
        c.execute("insert into audit_log(actor,action,target,detail,prev_hash,hash) values(%s,%s,%s,%s,%s,%s)",
                  (actor, action, target, json.dumps(d), prev_hash, h))
    finally:
        c.execute("select pg_advisory_unlock(7001)")


def verify_audit(c):
    prev, n = "GENESIS", 0
    for r in c.execute("select * from audit_log order by seq"):
        body = json.dumps({"actor": r["actor"], "action": r["action"], "target": r["target"], "detail": r["detail"]},
                          sort_keys=True)
        if r["prev_hash"] != prev or hashlib.sha256((prev + body).encode()).hexdigest() != r["hash"]:
            return {"ok": False, "broken_at": r["seq"], "checked": n}
        prev, n = r["hash"], n + 1
    return {"ok": True, "checked": n}
