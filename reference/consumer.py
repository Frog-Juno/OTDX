#!/usr/bin/env python3
"""Reference OTDX consumer: verify a batch, dedup by event_id, store in SQLite.

Usage:
  python3 consumer.py --pubkey ../examples/keys/otdx-test-key.pub \
      --db otdx.sqlite <envelope.json> [<payload-file>]

Safe under redelivery: re-running on the same batch inserts nothing new.
This exists to demonstrate how little code a conforming Consumer-Core needs.
"""

import argparse
import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import otdxlib  # noqa: E402

DDL = """
CREATE TABLE IF NOT EXISTS otdx_events (
    event_id   TEXT PRIMARY KEY,
    batch_id   TEXT NOT NULL,
    provider   TEXT NOT NULL,
    type       TEXT NOT NULL,
    tag        TEXT NOT NULL,
    location   TEXT NOT NULL,
    body       TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS otdx_batches (
    batch_id    TEXT PRIMARY KEY,
    provider    TEXT NOT NULL,
    received_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--pubkey", required=True)
    p.add_argument("--db", default="otdx.sqlite")
    p.add_argument("envelope")
    p.add_argument("payload", nargs="?")
    args = p.parse_args()

    env_path = Path(args.envelope)
    envelope = json.loads(env_path.read_text(encoding="utf-8"))

    if args.payload:
        payload_path = Path(args.payload)
    else:
        base = env_path.parent / envelope["batch_id"]
        payload_path = next(
            (Path(str(base) + s) for s in (".jsonl", ".jsonl.zst") if Path(str(base) + s).exists()),
            None,
        )
        if payload_path is None:
            sys.exit("payload file not found")
    payload = payload_path.read_bytes()

    # verify before ingesting anything
    if otdxlib.sha256_hex(payload) != envelope["payload_sha256"]:
        sys.exit("REJECT: payload hash mismatch")
    if not otdxlib.verify_envelope(envelope, otdxlib.load_public_key(Path(args.pubkey))):
        sys.exit("REJECT: bad or missing signature")

    events = otdxlib.decode_events(payload, envelope["payload_encoding"])
    if len(events) != envelope["event_count"]:
        sys.exit("REJECT: event_count mismatch")

    db = sqlite3.connect(args.db)
    db.executescript(DDL)
    dup_batch = db.execute(
        "SELECT 1 FROM otdx_batches WHERE batch_id=?", (envelope["batch_id"],)
    ).fetchone()
    new = dup = 0
    for ev in events:
        cur = db.execute(
            "INSERT OR IGNORE INTO otdx_events VALUES (?,?,?,?,?,?,?)",
            (
                ev["event_id"],
                envelope["batch_id"],
                ev["provider"],
                ev["type"],
                ev["tag"],
                (ev.get("location") or {}).get("id", ""),
                json.dumps(ev, separators=(",", ":")),
            ),
        )
        new += cur.rowcount
        dup += 1 - cur.rowcount
    db.execute(
        "INSERT OR IGNORE INTO otdx_batches (batch_id, provider) VALUES (?,?)",
        (envelope["batch_id"], envelope["provider"]),
    )
    db.commit()
    redelivery = " (batch redelivery)" if dup_batch else ""
    print(f"accepted batch {envelope['batch_id']}{redelivery}: {new} new, {dup} duplicate events")


if __name__ == "__main__":
    main()
