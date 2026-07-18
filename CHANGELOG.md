# Changelog

## 0.1 (draft) — 2026-07-18

Initial public draft.

- Core PresenceEvent (tag, location, window, provider) with signed batch envelope.
- Uniform `radius_m` likely-containment semantics on all geo objects.
- Profiles: `signal`, `granular`, `fineposition`, `payload` (opt-in, claim-bound).
- Transport bindings: HTTPS pull-with-cursor, HTTPS push, file drop.
- Per-field privacy classification (C0/C1/C2/CP/C3).
- JSON Schemas, validator, signing tool, golden valid/invalid examples,
  reference producer/consumer.
