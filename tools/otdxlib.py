"""Shared helpers for OTDX tools: canonicalisation, signing, schema loading.

Canonicalisation note: the OTDX signature is computed over the JCS (RFC 8785)
canonical form of the envelope with the "signature" member removed. OTDX
envelopes contain only strings, integers, booleans, arrays, and objects — no
floating-point numbers — so Python's json.dumps with sorted keys and compact
separators produces byte-identical output to full JCS for every conforming
envelope. (Event payload bytes are covered via payload_sha256 inside the
envelope, so events themselves are not canonicalised.)
"""

import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SCHEMA_DIR = Path(__file__).resolve().parent.parent / "schemas"
SCHEMA_FILES = [
    "otdx-defs.schema.json",
    "otdx-envelope.schema.json",
    "otdx-presence.schema.json",
    "otdx-detection.schema.json",
    "otdx-payload.schema.json",
]
RECORD_SCHEMAS = {
    "presence": "otdx-presence.schema.json",
    "detection": "otdx-detection.schema.json",
    "payload": "otdx-payload.schema.json",
}
KNOWN_PROFILES = {"signal", "granular", "fineposition", "payload"}


def canonical_bytes(envelope: dict) -> bytes:
    env = {k: v for k, v in envelope.items() if k != "signature"}
    return json.dumps(
        env, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} is not an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path} is not an Ed25519 public key")
    return key


def sign_envelope(envelope: dict, key: Ed25519PrivateKey, key_id: str) -> dict:
    sig = key.sign(canonical_bytes(envelope))
    envelope["signature"] = {
        "alg": "Ed25519",
        "key_id": key_id,
        "sig": base64.b64encode(sig).decode("ascii"),
    }
    return envelope


def verify_envelope(envelope: dict, key: Ed25519PublicKey) -> bool:
    signature = envelope.get("signature")
    if not signature or signature.get("alg") != "Ed25519":
        return False
    try:
        key.verify(base64.b64decode(signature["sig"]), canonical_bytes(envelope))
        return True
    except Exception:
        return False


def make_validators():
    """Return {schema_filename: jsonschema validator} with cross-file refs resolved."""
    from jsonschema import Draft202012Validator
    from referencing import Registry, Resource

    resources = []
    schemas = {}
    for name in SCHEMA_FILES:
        doc = json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))
        schemas[name] = doc
        resources.append((name, Resource.from_contents(doc)))
    registry = Registry().with_resources(resources)
    return {
        name: Draft202012Validator(schemas[name], registry=registry)
        for name in SCHEMA_FILES
    }


def read_payload_bytes(path: Path) -> bytes:
    return path.read_bytes()


def decode_events(payload: bytes, encoding: str) -> list:
    if encoding == "jsonl+zstd":
        import zstandard

        payload = zstandard.ZstdDecompressor().decompress(payload)
    lines = [ln for ln in payload.decode("utf-8").splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


def encode_events(events: list, encoding: str) -> bytes:
    payload = ("\n".join(json.dumps(e, separators=(",", ":")) for e in events) + "\n").encode("utf-8")
    if encoding == "jsonl+zstd":
        import zstandard

        payload = zstandard.ZstdCompressor(level=19).compress(payload)
    return payload
