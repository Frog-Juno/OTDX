# Changelog

## Unreleased

- §4 PresenceEvent: optional `detector` (det:{issuer}:{scheme}:{value}) naming the reader that
  observed the window, so a receiver can apply per-reader visibility when `location.id` is a
  shared place. Schema: `detector` in `otdx-presence`.
- §3.5 Relay and provenance: optional `origin`, `path` on every record and `via` on
  liveness records; receivers discard records whose `path` contains themselves.
  Schemas: `origin` / `path` / `via` definitions in `otdx-defs`, referenced from the
  presence and detector_status records.

## 0.1 (draft) — 2026-07-18

Initial public draft.

- Core PresenceEvent (tag, location, window, provider) with signed batch envelope.
- Uniform `radius_m` likely-containment semantics on all geo objects.
- Profiles: `signal`, `granular`, `fineposition`, `payload` (opt-in, claim-bound).
- Transport bindings: HTTPS pull-with-cursor, HTTPS push, file drop.
- Per-field privacy classification (C0/C1/C2/CP/C3).
- JSON Schemas, validator, signing tool, golden valid/invalid examples,
  reference producer/consumer.
