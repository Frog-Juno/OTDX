# OTDX — Open Tag Detection eXchange

A proposed open standard for sharing tag detection events between networks and
providers. One provider tells another, in a verifiable and provider-neutral way:

> "These tags were detected at this location during this time window."

```json
{
  "type": "presence",
  "event_id": "0190b7a3-52e4-7cc0-9f4e-3d2a1b9c0d11",
  "provider": "example",
  "tag": "tag:example:mac48:2cdc78051a2b",
  "location": {
    "id": "loc:iata:station:NSN",
    "geo": {"lat": -41.2983, "lon": 173.2210, "radius_m": 70}
  },
  "window": {
    "first_seen": "2026-07-18T02:14:07Z",
    "last_seen": "2026-07-18T02:56:41Z",
    "open": false
  },
  "observations": 46,
  "asserted_at": "2026-07-18T03:00:02Z"
}
```

Events travel in signed batches (Ed25519), are immutable and uniquely identified
(dedup by `event_id`), and tolerate at-least-once delivery over unreliable links.
A tiny mandatory core carries the presence assertion; optional named profiles add
signal quality, granular per-detection records, fine positioning, and (opt-in,
claim-bound) raw payload relay. See **[SPEC.md](SPEC.md)** for the full standard.

## Repository layout

| Path | Contents |
|---|---|
| `SPEC.md` | The standard (draft 0.1) |
| `schemas/` | JSON Schemas (draft 2020-12) for envelope and record types |
| `examples/valid/` | Golden batches — all must PASS validation |
| `examples/invalid/` | One rule violation each — all must FAIL validation |
| `examples/keys/` | Deterministic TEST-ONLY Ed25519 keypair |
| `tools/otdx-validate` | Batch validator (schema, hash, signature, windowing, profiles) |
| `tools/otdx-sign` | Keygen / sign / verify for envelopes |
| `reference/` | Minimal conforming producer and consumer (~100 lines each) |
| `scripts/generate_examples.py` | Regenerates `examples/` deterministically |
| `registry/` | Issuer short-name registry |

## Quickstart

Requires Python 3.10+:

```bash
pip install -r requirements.txt
```

Validate a golden example (signature checked with the test key):

```bash
python3 tools/otdx-validate --pubkey examples/keys/otdx-test-key.pub \
    examples/valid/01_core_minimal/01_core_minimal.envelope.json
```

Produce and consume a batch end-to-end:

```bash
cd reference
python3 producer.py --provider example --key ../examples/keys/otdx-test-key.pem \
    --key-id otdx-test-1 --in sample_input.csv --out ./out
python3 consumer.py --pubkey ../examples/keys/otdx-test-key.pub \
    --db otdx.sqlite out/*.envelope.json
```

Run the consumer twice: the second run reports every event as a duplicate —
redelivery safety is a conformance requirement, not an optimisation.

## Conformance

- **Consumer-Core** — accepts valid core batches, verifies hash and signature,
  deduplicates by `event_id` and `batch_id`, ignores unknown fields and unknown
  non-critical profiles, rejects unknown critical profiles.
- **Producer-Core** — emits schema-valid, signed core batches with correct
  `payload_sha256` and `event_count`, and never emits overlapping windows for
  the same (tag, location).
- Per-profile conformance adds the corresponding record types/fields.

The `examples/` tree is the test suite: a conforming validator passes everything
under `valid/` and fails everything under `invalid/` for the stated reason.

## Status

Draft 0.1 — open for comment. Anything may change before 1.0. See
[CHANGELOG.md](CHANGELOG.md). Field meanings are never reused; deprecate-and-add
only.

## Licence

Specification text (`SPEC.md`): [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/).
Code, schemas, and examples: MIT (see [LICENSE](LICENSE)).
