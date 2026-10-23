import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("AADHARSHIELD_DATA_DIR", ROOT / "data"))
VAULT_DIR = DATA_DIR / "vault"
OUT_DIR = DATA_DIR / "masked"
DB_URL = os.getenv("AADHARSHIELD_DB_URL", "postgresql://aadharshield:aadharshield@localhost:5432/aadharshield")
ADMIN_DB_URL = os.getenv("AADHARSHIELD_ADMIN_DB_URL", "postgresql://postgres:postgres@localhost:5432/postgres")
API_PORT = int(os.getenv("AADHARSHIELD_PORT", "8790"))
HOST = os.getenv("AADHARSHIELD_HOST", "127.0.0.1")                 # 127.0.0.1 behind a reverse proxy on the same machine; 0.0.0.0 only if clients connect directly
TRUSTED_PROXIES = os.getenv("AADHARSHIELD_TRUSTED_PROXIES", "127.0.0.1")   # whose X-Forwarded-For is believed, so unmask logs and the IP allow-list see the real client
JWT_TTL_MIN = int(os.getenv("AADHARSHIELD_JWT_TTL_MIN", "30"))
MIN_REASON_LEN = int(os.getenv("AADHARSHIELD_MIN_REASON_LEN", "15"))
ROLE = os.getenv("AADHARSHIELD_ROLE", "all").lower()    # all | mask | unmask  (which half of the product this server runs)
assert ROLE in ("all", "mask", "unmask"), "AADHARSHIELD_ROLE must be all, mask or unmask"
MASK_QR = os.getenv("AADHARSHIELD_MASK_QR", "1") == "1"       # QR on old letters encodes the full UID
MASK_VID = os.getenv("AADHARSHIELD_MASK_VID", "1") == "1"
VERIFY_AFTER_MASK = os.getenv("AADHARSHIELD_VERIFY", "1") == "1"
for d in (DATA_DIR, VAULT_DIR, OUT_DIR):
    d.mkdir(parents=True, exist_ok=True)


def secret(name: str) -> bytes:
    """Env value, else a per-install random secret persisted in the data dir (dev convenience)."""
    import base64, secrets
    v = os.getenv(name)
    if v:
        return base64.b64decode(v)
    p = DATA_DIR / f"{name.lower()}.key"
    if not p.exists():
        p.write_bytes(secrets.token_bytes(32))
    return p.read_bytes()
