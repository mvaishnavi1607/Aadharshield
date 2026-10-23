"""CLI:  python -m aadharshield.cli <command>
  init-db [--dev-users]      create DB/schema/roles; --dev-users writes random test users to .dev-credentials.txt
  create-user USER ROLE      prompts for password
  backfill ROOT [ROOT..] [--inplace] [--manifest m.csv]
  mask IN OUT                mask one file locally (no DB, no vault)
  watch FOLDER               mask files as they appear (ongoing extraction drop-folder), in place
  serve                      run API + console on AADHARSHIELD_PORT"""
import argparse
import getpass
import secrets
import sys
import time
from pathlib import Path

import bcrypt

from . import config, db


def _mkuser(c, username, role, pw, limit=10):
    rid = c.execute("select id from roles where name=%s", (role,)).fetchone()["id"]
    c.execute("insert into users(username,pwhash,role_id,daily_unmask_limit) values(%s,%s,%s,%s) on conflict(username) do nothing",
              (username, bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode(), rid, limit))


def main(argv=None):
    ap = argparse.ArgumentParser(prog="aadharshield")
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("init-db"); p.add_argument("--dev-users", action="store_true")
    p = sp.add_parser("create-user"); p.add_argument("username"); p.add_argument("role")
    p = sp.add_parser("backfill"); p.add_argument("roots", nargs="+"); p.add_argument("--inplace", action="store_true"); p.add_argument("--manifest")
    p = sp.add_parser("mask"); p.add_argument("src"); p.add_argument("dst")
    p = sp.add_parser("watch"); p.add_argument("folder")
    sp.add_parser("key-id")
    sp.add_parser("serve")
    a = ap.parse_args(argv)

    if a.cmd == "init-db":
        db.init_db()
        if a.dev_users:
            lines = []
            with db.connect() as c:
                for u, r in (("admin", "Administrator"), ("operator", "Operator"), ("officer", "Unmask Officer"), ("auditor", "Auditor")):
                    pw = secrets.token_urlsafe(14)
                    _mkuser(c, u, r, pw)
                    lines.append(f"{u}\t{r}\t{pw}")
            import os
            cred = Path(os.getenv("AADHARSHIELD_CREDENTIALS_FILE", config.ROOT / ".dev-credentials.txt"))
            cred.write_text("\n".join(lines))
            print("dev users created; passwords in", cred, "(keep out of git)")
        print("database ready")
    elif a.cmd == "create-user":
        pw = getpass.getpass("password (min 12): ")
        assert len(pw) >= 12
        with db.connect() as c:
            _mkuser(c, a.username, a.role, pw)
            db.audit(c, "cli", "user_create", a.username, {"role": a.role})
    elif a.cmd == "backfill":
        from . import service
        import json
        with db.connect() as c:
            jid = c.execute("insert into jobs(kind,status,params,actor) values('backfill','queued',%s,'cli') returning id",
                            (json.dumps(vars(a), default=str),)).fetchone()["id"]
        print(service.backfill(jid, a.roots, "inplace" if a.inplace else "copy", "cli", a.manifest))
    elif a.cmd == "mask":
        from . import masking
        out, rep = masking.mask_bytes(Path(a.src).read_bytes(), a.src)
        Path(a.dst).write_bytes(out)
        print(rep.dict())
    elif a.cmd == "watch":
        import threading
        from . import service
        print("watching", a.folder, "(Ctrl+C to stop)")
        service._watch_loop(a.folder, threading.Event(), {"count": 0, "last": ""})
    elif a.cmd == "key-id":
        from . import vault
        print("key id:", vault.key_id(), "  (must be identical on the masking and unmasking servers)")
    elif a.cmd == "serve":
        import uvicorn
        uvicorn.run("aadharshield.api:app", host=config.HOST, port=config.API_PORT, proxy_headers=True,
                    forwarded_allow_ips=config.TRUSTED_PROXIES)


if __name__ == "__main__":
    main()
