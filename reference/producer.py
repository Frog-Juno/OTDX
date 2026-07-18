#!/usr/bin/env python3
"""Reference OTDX producer: CSV of presence observations -> signed OTDX batch.

Usage:
  python3 producer.py --provider example --key ../examples/keys/otdx-test-key.pem \
      --key-id otdx-test-1 --in sample_input.csv --out ./out

Input CSV columns: tag,location_id,sublocation,first_seen,last_seen,open,observations
Writes <batch_id>.envelope.json + <batch_id>.jsonl into --out.

This exists to demonstrate how little code a conforming Producer-Core needs.
"""

import argparse
import csv
import json
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import otdxlib  # noqa: E402


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--provider", required=True)
    p.add_argument("--key", required=True)
    p.add_argument("--key-id", required=True)
    p.add_argument("--in", dest="infile", required=True)
    p.add_argument("--out", default=".")
    args = p.parse_args()

    events = []
    with open(args.infile, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            ev = {
                "type": "presence",
                "event_id": str(uuid.uuid4()),  # use UUIDv7 in production
                "provider": args.provider,
                "tag": row["tag"],
                "location": {"id": row["location_id"]},
                "window": {
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                    "open": row["open"].strip().lower() == "true",
                },
                "asserted_at": now_iso(),
            }
            if row.get("sublocation"):
                ev["location"]["sublocation"] = row["sublocation"]
            if row.get("observations"):
                ev["observations"] = int(row["observations"])
            events.append(ev)

    payload = otdxlib.encode_events(events, "jsonl")
    batch_id = str(uuid.uuid4())
    envelope = {
        "otdx": "0.1",
        "batch_id": batch_id,
        "provider": args.provider,
        "profiles": [],
        "created_at": now_iso(),
        "event_count": len(events),
        "payload_encoding": "jsonl",
        "payload_sha256": otdxlib.sha256_hex(payload),
    }
    otdxlib.sign_envelope(envelope, otdxlib.load_private_key(Path(args.key)), args.key_id)

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{batch_id}.jsonl").write_bytes(payload)
    (out / f"{batch_id}.envelope.json").write_text(
        json.dumps(envelope, indent=2) + "\n", encoding="utf-8"
    )
    print(f"wrote {out / batch_id}.envelope.json ({len(events)} events)")


if __name__ == "__main__":
    main()
