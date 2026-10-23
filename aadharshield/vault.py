"""Encrypted vault for original (unmasked) files. AES-256-GCM, one random data key per object, wrapped by a
master key (AADHARSHIELD_VAULT_KEY: base64, 32 bytes). Two servers that share the same master key can
read each other's vault files - masking can run on one server and unmasking on another.

File format ASV2 (self-describing, so no database is needed to find or open an object):
  "ASV2" | key id (4 bytes) | doc id (16 bytes) | nonce1 (12) | wrapped-key length (2) | wrapped data key
  | meta nonce (12) | meta length (4) | encrypted meta (name, hashes, source path, counts...) | nonce2 (12) | encrypted body
ASV1 (older, no meta) is still readable with the right key; its details live only in the masking server's database."""
import hashlib
import hmac
import json
import os
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config, settings


class WrongKey(Exception):
    """The vault object was written with a different master key than this server has."""


def _master() -> bytes:
    return config.secret("AADHARSHIELD_VAULT_KEY")


def key_id() -> str:
    """Short fingerprint of the master key (8 hex chars). Shown in the console; equal on both servers or the
    keys differ. Reveals nothing usable about the key."""
    return hmac.new(_master(), b"aadharshield-key-id", hashlib.sha256).hexdigest()[:8]


def put(doc_id: str, data: bytes, meta: dict = None) -> str:
    dek = os.urandom(32)
    n1, nm, n2 = os.urandom(12), os.urandom(12), os.urandom(12)
    aad = doc_id.encode()
    wrapped = AESGCM(_master()).encrypt(n1, dek, aad)
    meta_ct = AESGCM(_master()).encrypt(nm, json.dumps({**(meta or {}), "doc_id": doc_id}).encode(), aad + b"|meta")
    body = AESGCM(dek).encrypt(n2, data, aad)
    blob = (b"ASV2" + bytes.fromhex(key_id()) + uuid.UUID(doc_id).bytes + n1 + len(wrapped).to_bytes(2, "big") + wrapped
            + nm + len(meta_ct).to_bytes(4, "big") + meta_ct + n2 + body)
    path = settings.vault_dir() / f"{doc_id}.vault"
    tmp = path.with_suffix(".tmp")
    tmp.write_bytes(blob)
    os.replace(tmp, path)
    return str(path)


def _parse(raw: bytes):
    """-> dict with version, doc_id, kid, and the offsets/values needed to decrypt."""
    if raw[:4] == b"ASV1":
        n1 = raw[4:16]
        wl = int.from_bytes(raw[16:18], "big")
        return {"v": 1, "n1": n1, "wrapped": raw[18:18 + wl], "rest": raw[18 + wl:]}
    if raw[:4] != b"ASV2":
        raise ValueError("not an AadharShield vault file")
    kid = raw[4:8].hex()
    doc_id = str(uuid.UUID(bytes=raw[8:24]))
    n1 = raw[24:36]
    wl = int.from_bytes(raw[36:38], "big")
    o = 38 + wl
    wrapped = raw[38:o]
    nm = raw[o:o + 12]
    ml = int.from_bytes(raw[o + 12:o + 16], "big")
    meta_ct = raw[o + 16:o + 16 + ml]
    rest = raw[o + 16 + ml:]
    return {"v": 2, "kid": kid, "doc_id": doc_id, "n1": n1, "wrapped": wrapped, "nm": nm, "meta_ct": meta_ct, "rest": rest}


def _check_key(p):
    if p["v"] == 2 and p["kid"] != key_id():
        raise WrongKey(f"written with key {p['kid']}, this server has key {key_id()}")


def read_meta(path) -> dict:
    """Decrypt only the metadata block (cheap; the body is not touched). ASV1 files have none -> returns {}.
    Raises WrongKey if the master key differs."""
    p = _parse(Path(path).read_bytes())
    if p["v"] == 1:
        return {}
    _check_key(p)
    try:
        return json.loads(AESGCM(_master()).decrypt(p["nm"], p["meta_ct"], p["doc_id"].encode() + b"|meta"))
    except InvalidTag:
        raise WrongKey("metadata could not be decrypted with this server's key")


def get(doc_id: str, path: str = None) -> bytes:
    """path = location recorded when indexed (survives a later change of the vault folder)."""
    f = Path(path) if path else settings.vault_dir() / f"{doc_id}.vault"
    p = _parse(f.read_bytes())
    _check_key(p)
    aad = (p["doc_id"] if p["v"] == 2 else doc_id).encode()
    try:
        dek = AESGCM(_master()).decrypt(p["n1"], p["wrapped"], aad)
        return AESGCM(dek).decrypt(p["rest"][:12], p["rest"][12:], aad)
    except InvalidTag:
        raise WrongKey("could not decrypt with this server's key (different key, or the file was altered)")


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()
