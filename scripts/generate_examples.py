#!/usr/bin/env python3
"""Regenerate examples/ deterministically. Run from anywhere:

  python3 scripts/generate_examples.py

Uses a deterministic TEST-ONLY keypair (derived from a fixed seed) so that
regeneration produces byte-identical output. Never use this key for anything
other than exercising the tooling.
"""

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import otdxlib  # noqa: E402

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

VALID = ROOT / "examples" / "valid"
INVALID = ROOT / "examples" / "invalid"
KEYS = ROOT / "examples" / "keys"
KEY_ID = "otdx-test-1"
PROVIDER = "example"
NSN = {"id": "loc:iata:station:NSN", "geo": {"lat": -41.2983, "lon": 173.221, "radius_m": 70}}


def uid(n):
    h = hashlib.sha256(f"otdx-example-{n}".encode()).hexdigest()
    return f"{h[0:8]}-{h[8:12]}-7{h[13:16]}-8{h[17:20]}-{h[20:32]}"


def test_key():
    seed = hashlib.sha256(b"OTDX 0.1 TEST KEY - DO NOT USE IN PRODUCTION").digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def write_keys(key):
    KEYS.mkdir(parents=True, exist_ok=True)
    (KEYS / "otdx-test-key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    (KEYS / "otdx-test-key.pub").write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    (KEYS / "README.md").write_text(
        "# TEST KEY ONLY\n\n"
        "This Ed25519 keypair is deterministic, public, and exists solely so the\n"
        "examples can be verified out of the box. It provides no security.\n"
        "**Never use it outside this repository's examples.**\n",
        encoding="utf-8",
    )


def presence(n, tag, first, last, open_, extra=None):
    ev = {
        "type": "presence",
        "event_id": uid(n),
        "provider": PROVIDER,
        "tag": tag,
        "location": dict(NSN),
        "window": {"first_seen": first, "last_seen": last, "open": open_},
        "observations": 12,
        "asserted_at": "2026-07-18T03:00:00Z",
    }
    if extra:
        ev.update(extra)
    return ev


def detection(n, tag, at, flag, extra=None):
    ev = {
        "type": "detection",
        "event_id": uid(n),
        "provider": PROVIDER,
        "tag": tag,
        "detector": "det:example:node:2561",
        "location": {"id": "loc:example:site:S01"},
        "at": at,
        "flag": flag,
        "rssi": -74,
        "channel": 37,
    }
    if extra:
        ev.update(extra)
    return ev


def write_batch(directory, name, batch_no, events, profiles, encoding, key, mutate=None):
    directory.mkdir(parents=True, exist_ok=True)
    payload = otdxlib.encode_events(events, encoding)
    envelope = {
        "otdx": "0.1",
        "batch_id": uid(f"batch-{batch_no}"),
        "provider": PROVIDER,
        "profiles": profiles,
        "created_at": "2026-07-18T03:00:05Z",
        "event_count": len(events),
        "payload_encoding": encoding,
        "payload_sha256": otdxlib.sha256_hex(payload),
    }
    if mutate:
        mutate(envelope)
    otdxlib.sign_envelope(envelope, key, KEY_ID)
    ext = ".jsonl.zst" if encoding == "jsonl+zstd" else ".jsonl"
    (directory / (envelope["batch_id"] + ext)).write_bytes(payload)
    env_path = directory / f"{name}.envelope.json"
    env_path.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    return envelope, env_path


def main():
    key = test_key()
    for d in (VALID, INVALID):
        if d.exists():
            for f in sorted(d.rglob("*"), reverse=True):
                if f.is_file():
                    f.unlink()
    write_keys(key)

    tag = "tag:example:mac48:2cdc78051a2b"
    tag2 = "tag:example:mac48:2cdc7811aa02"
    tag3 = "tag:acme:tid:00a1b2c3d4e5f607"

    # ---- valid ----
    write_batch(VALID / "01_core_minimal", "01_core_minimal", 1, [
        presence("1a", tag, "2026-07-18T02:14:07Z", "2026-07-18T02:56:41Z", False,
                 {"aliases": ["tag:acme:uld:AKE12345XX"]}),
        presence("1b", tag2, "2026-07-18T02:20:00Z", "2026-07-18T02:59:30Z", True),
        presence("1c", tag3, "2026-07-18T01:05:00Z", "2026-07-18T01:06:10Z", False),
    ], [], "jsonl", key)

    write_batch(VALID / "02_signal_profile", "02_signal_profile", 2, [
        presence("2a", tag, "2026-07-18T02:14:07Z", "2026-07-18T02:56:41Z", False, {
            "rssi": {"min": -88, "max": -61, "median": -71},
            "detector_count": 3,
            "channel_set": [37, 38, 39],
        }),
    ], [{"name": "signal", "critical": False}], "jsonl", key)

    write_batch(VALID / "03_granular", "03_granular", 3, [
        detection("3a", tag, "2026-07-18T02:14:07.412Z", "first"),
        detection("3b", tag, "2026-07-18T02:35:00.020Z", "heartbeat"),
        detection("3c", tag, "2026-07-18T02:56:41.900Z", "last"),
    ], [{"name": "granular", "critical": True}], "jsonl+zstd", key)

    write_batch(VALID / "04_payload_profile", "04_payload_profile", 4, [
        detection("4a", tag3, "2026-07-18T02:14:07Z", "first", {
            "data": "AgEGF/9MABIZAQI=",
            "payload_sha256": otdxlib.sha256_hex(b"\x02\x01\x06\x17\xffL\x00\x12\x19\x01\x02"),
            "encoding": "vendor:acme:sensorfmt2",
        }),
        {
            "type": "payload",
            "event_id": uid("4b"),
            "provider": PROVIDER,
            "tag": tag3,
            "location": {"id": "loc:example:site:S01"},
            "at": "2026-07-18T02:40:00Z",
            "payload_sha256": otdxlib.sha256_hex(b"\x02\x01\x06\x17\xffL\x00\x12\x19\x01\x02"),
            "encoding": "vendor:acme:sensorfmt2",
        },
    ], [{"name": "granular", "critical": True}, {"name": "payload", "critical": True}],
        "jsonl", key)

    seq = VALID / "05_window_sequence"
    write_batch(seq, "05a_open", "5a", [
        presence("5a", tag, "2026-07-18T02:14:07Z", "2026-07-18T02:14:07Z", True)], [], "jsonl", key)
    write_batch(seq, "05b_refresh", "5b", [
        presence("5b", tag, "2026-07-18T02:14:07Z", "2026-07-18T02:44:00Z", True,
                 {"supersedes": uid("5a")})], [], "jsonl", key)
    write_batch(seq, "05c_close", "5c", [
        presence("5c", tag, "2026-07-18T02:14:07Z", "2026-07-18T02:56:41Z", False,
                 {"supersedes": uid("5b")})], [], "jsonl", key)

    # ---- invalid (one rule violation each) ----
    bad_ev = presence("i1", tag, "2026-07-18T02:00:00Z", "2026-07-18T02:30:00Z", False)
    del bad_ev["window"]["open"]
    write_batch(INVALID / "schema_violation", "schema_violation", 11, [bad_ev], [], "jsonl", key)

    write_batch(INVALID / "overlapping_windows", "overlapping_windows", 12, [
        presence("i2a", tag, "2026-07-18T02:00:00Z", "2026-07-18T02:30:00Z", False),
        presence("i2b", tag, "2026-07-18T02:20:00Z", "2026-07-18T02:50:00Z", False),
    ], [], "jsonl", key)

    write_batch(INVALID / "unknown_critical_profile", "unknown_critical_profile", 13, [
        presence("i3", tag, "2026-07-18T02:00:00Z", "2026-07-18T02:30:00Z", False)],
        [{"name": "frobnicate", "critical": True}], "jsonl", key)

    write_batch(INVALID / "payload_hash_mismatch", "payload_hash_mismatch", 14, [
        presence("i4", tag, "2026-07-18T02:00:00Z", "2026-07-18T02:30:00Z", False)],
        [], "jsonl", key, mutate=lambda e: e.update(payload_sha256="0" * 64))

    env, env_path = write_batch(INVALID / "bad_signature", "bad_signature", 15, [
        presence("i5", tag, "2026-07-18T02:00:00Z", "2026-07-18T02:30:00Z", False)],
        [], "jsonl", key)
    env["created_at"] = "2026-07-18T03:59:59Z"  # tampered after signing
    env_path.write_text(json.dumps(env, indent=2) + "\n", encoding="utf-8")

    write_batch(INVALID / "undeclared_profile_fields", "undeclared_profile_fields", 16, [
        detection("i6", tag, "2026-07-18T02:14:07Z", "first", {"data": "AgEG"})],
        [{"name": "granular", "critical": True}], "jsonl", key)

    (INVALID / "README.md").write_text(
        "# Invalid examples\n\n"
        "Each directory violates exactly one rule; `otdx-validate --pubkey "
        "../keys/otdx-test-key.pub <dir>/<name>.envelope.json` must FAIL on all of them.\n\n"
        "| Directory | Violated rule |\n|---|---|\n"
        "| schema_violation | event missing required `window.open` |\n"
        "| overlapping_windows | two windows for same (tag, location) overlap (SPEC 4) |\n"
        "| unknown_critical_profile | profile unknown to receiver marked critical (SPEC 5) |\n"
        "| payload_hash_mismatch | envelope payload_sha256 does not match payload bytes (SPEC 6) |\n"
        "| bad_signature | envelope tampered after signing (SPEC 6) |\n"
        "| undeclared_profile_fields | payload-profile fields without payload profile declared (SPEC 5.4) |\n",
        encoding="utf-8",
    )
    print("examples regenerated")


if __name__ == "__main__":
    main()
