# OTDX — Open Tag Detection eXchange

## A proposed standard for sharing tag detection events between networks and providers

Draft 0.1 (July 18, 2026) — skeleton for review.

---

## 1. Purpose and scope

OTDX defines a provider-neutral format for one network operator to tell another:
**"these tags were detected at this location during this time window."**

In scope: presence assertions (the core), optional richer detail (profiles, including
opt-in relay of claimed tags' advertisement payloads), a batch envelope with signing,
and transport bindings. Out of scope: commands to devices, provisioning, firmware,
billing itself (though OTDX events are designed to be usable as billing/SLA evidence),
and payloads of tags not claimed by the receiving peer (§5.4, §8).

Design principles (normative for the spec's own evolution):

1. **Events, not state.** Every OTDX record is an immutable, uniquely identified fact.
   Receivers deduplicate by event ID. Records are never updated; corrections are new
   records that supersede old ones by ID reference.
2. **Small mandatory core.** Anything not universally required lives in a named
   extension profile. A conforming receiver MUST accept a core-only stream.
3. **Ignore what you don't understand.** Unknown fields and unknown profiles MUST be
   ignored, never rejected (except where a batch declares a profile as `critical`).
4. **No provider-internal identifiers in the core.** Tag and location identifiers are
   namespaced URIs; nothing in the core assumes any provider's internal numbering.
5. **At-least-once, idempotent.** Every transport binding is allowed to redeliver;
   correctness comes from event-ID dedup, not delivery guarantees.
6. **Per-field privacy classification.** Every field in this spec carries a data
   classification so cross-border/regulatory review is a table lookup (§8).

## 2. Terminology

- **Provider** — an organisation operating a detection network.
- **Peer** — a provider or consumer exchanging OTDX data under an agreement.
- **Detection point** — a reader/gateway/site at which tags are detected.
- **Presence event** — the core record type: one tag, one location, one time window.
- **Batch** — a signed envelope containing 1..N events.
- Key words MUST / SHOULD / MAY per RFC 2119.

## 3. Identifiers

### 3.1 Event ID
`event_id` — UUIDv7 (time-ordered, globally unique), assigned by the originating
provider. The (sole) deduplication key. UUIDv7 is REQUIRED for new events; receivers
MUST treat the value as opaque.

### 3.2 Tag identifiers
A tag is identified by a namespaced URI:

```
tag:{issuer}:{scheme}:{value}
tag:example:mac48:2cdc78051a2b     (full 48-bit MAC, hex, no separators)
tag:example:tid:00A1B2C3D4E5F607   (derived 64-bit Tag ID)
tag:acme:epc:urn:epc:id:giai:...   (peer using GS1 EPC)
```

- `issuer` — registered peer short-name (registry maintained per agreement, §10).
- `scheme` — how `value` is derived: `mac48`, `tid` (device-derived 64-bit ID for
  MAC-randomising tags), `epc`, `uld` (IATA ULD code), or peer-defined.
- Raw MACs are permitted as a scheme but SHOULD be avoided for third-party devices
  where MAC randomisation makes them unstable; `tid` is preferred where available.
- A presence event MAY additionally carry `aliases[]` — other identifiers for the same
  physical tag (e.g. the customer's ULD code alongside the MAC). Aliases are
  informational; `tag` is authoritative for dedup/joins.

### 3.3 Location identifiers

```
loc:{issuer}:{scheme}:{value}
loc:example:site:S01               (provider site code)
loc:iata:station:NSN               (IATA station — RECOMMENDED for air cargo peers)
loc:unlocode:NZNSN                 (UN/LOCODE — general logistics)
```

A location reference is an opaque code plus OPTIONAL geo:

```json
"location": {
  "id": "loc:iata:station:NSN",
  "sublocation": "Warehouse",
  "geo": {"lat": -41.2983, "lon": 173.2210, "radius_m": 70}
}
```

- `geo` is WGS-84, always. Providers in jurisdictions with datum restrictions transform
  at their own boundary; OTDX carries WGS-84 or no geo at all. Omitting `geo` is always
  conforming.
- `radius_m` (OPTIONAL, metres) — the likely-containment radius: the subject of the
  assertion is, with high likelihood, within `radius_m` of the stated point. This single
  field covers both detection-method range and positional uncertainty — e.g. ~70 for
  simple BLE presence at a reader, ~2 for a trilaterated fix (§5.3). Where a geo has no
  `radius_m`, the point conveys locality only and MUST NOT be treated as a precision fix.
  This definition of `radius_m` applies to every geo object in OTDX.
- `sublocation` is free text scoped to the location id.

### 3.4 Provider identity
`provider` — the issuer short-name of the asserting provider. Bound to the batch
signature (§6); an event's `provider` MUST match the signing identity of its batch.

### 3.5 Relay and provenance (optional)
A provider MAY re-assert a record it received from another provider, for example when
one operator runs several regional servers and a consumer peers with only one of them.
The relaying provider signs the batch, so `provider` is the relay (3.4 is unchanged);
two optional fields carry the provenance:

| Field | Req | Notes |
|---|---|---|
| `origin` | MAY | Issuer short-name of the provider that observed the record. Absent = the signer observed it |
| `path` | MAY | Issuer short-names the record has traversed, oldest first, excluding the signer |

Rules: a relay MUST NOT rewrite the record's identifiers (`tag`, `location.id`,
`detector`), its `window` or `since`; it MAY drop fields its agreement with the receiver
does not permit (geo, payload). A relay MUST set `origin` when it differs from itself and
MUST append the previous signer to `path`. A receiver MUST discard a record whose `path`
contains its own issuer, or whose `origin` is itself: that is the loop guard. Records
that carry a liveness assertion (such as the `detectorstatus` profile) SHOULD add a
`via` object `{origin, asserted_at, received_at}` giving the origin's assertion time and
when the relay received it, so a consumer can tell a stale link from a stale detector.

## 4. Core record: PresenceEvent

One tag, one detection scope, one contiguous time window.

```json
{
  "type": "presence",
  "event_id": "0190b7a3-52e4-7cc0-9f4e-3d2a1b9c0d11",
  "provider": "example",
  "tag": "tag:example:mac48:2cdc78051a2b",
  "aliases": ["tag:acme:uld:AKE12345XX"],
  "location": {
    "id": "loc:iata:station:NSN",
    "sublocation": "Return",
    "geo": {"lat": -41.2983, "lon": 173.2210, "radius_m": 70}
  },
  "window": {
    "first_seen": "2026-07-18T02:14:07Z",
    "last_seen":  "2026-07-18T02:56:41Z",
    "open": false
  },
  "observations": 46,
  "asserted_at": "2026-07-18T03:00:02Z"
}
```

Field rules:

| Field | Req | Notes |
|---|---|---|
| `type` | MUST | `"presence"` for the core record |
| `event_id` | MUST | UUIDv7, dedup key |
| `provider` | MUST | Must match batch signer |
| `tag` | MUST | §3.2 URI |
| `aliases` | MAY | Other IDs for the same tag |
| `location` | MUST | §3.3; `geo` optional |
| `detector` | MAY | §3.4-style `det:{issuer}:{scheme}:{value}` naming the reader that observed the window (the same URI the `detectorstatus` profile uses). Lets a receiver apply per-reader visibility when `location.id` names a shared place such as a station. Providers that expose reader-scoped feeds SHOULD send it |
| `window.first_seen` / `last_seen` | MUST | RFC 3339 UTC, `Z` suffix, seconds resolution min; sub-second MAY |
| `window.open` | MUST | `true` = tag still present at assertion time; a later event with the same tag+location continues or closes the interval |
| `observations` | SHOULD | Count of underlying detections in the window — a cheap quality signal |
| `asserted_at` | MUST | When the provider generated the event (≠ detection time) |
| `supersedes` | MAY | `event_id` of a record this one corrects |
| `expires_at` | MAY | Hint that the assertion should not be relied on after this time |

Time semantics: all times UTC. Providers SHOULD state their clock discipline in the peer
agreement; a `time_quality` extension field (`"gps"`, `"ntp"`, `"device"`) MAY be
included when windows are built from device-reported timestamps.

Windowing rules (normative): a provider MUST NOT emit overlapping windows for the same
(tag, location) pair. Recommended emission policy: emit with `open:true` on first
detection (or first summary interval), refresh at an agreed cadence while present, emit
`open:false` when a gap exceeds the provider's presence timeout. This maps directly onto
first/heartbeat/last detection lifecycle models.

## 5. Extension profiles

Profiles add fields or record types. A batch lists the profiles used; each is marked
`critical: true|false`. Non-critical unknown profiles are ignored; a critical unknown
profile causes batch rejection (the only permitted rejection-on-unknown).

### 5.1 `signal` (non-critical)
Adds to PresenceEvent: `rssi` `{min, max, median}` (dBm), `detector_count` (distinct
detection points contributing), `channel_set`. For peers who want confidence data.

### 5.2 `granular` (typically private / intra-provider)
New record type `"detection"` — one row per raw detection:

```json
{
  "type": "detection",
  "event_id": "0190b7a3-...",
  "provider": "example",
  "tag": "tag:example:mac48:2cdc78051a2b",
  "detector": "det:example:node:2561",
  "location": {"id": "loc:example:site:S01"},
  "at": "2026-07-18T02:14:07.412Z",
  "flag": "first",
  "rssi": -74,
  "channel": 37
}
```

Intended for high-trust links, such as between servers operated by the same provider,
where full RSSI and heartbeat fidelity is needed. `detector` URIs may be
provider-internal — that is why this profile is not part of the core and SHOULD NOT be
offered to external peers by default.

### 5.3 `fineposition` (non-critical)
Adds per-event or per-detection `geo` for the *tag itself* (not the site):
`{lat, lon, radius_m}` per §3.3 semantics, plus `method` (`"trilateration"`,
`"ranging"`, `"fingerprint"`, `"reader"`). Typical `radius_m` by method: `reader`
(presence at a detection point) ~70; `fingerprint` ~5–10; `trilateration`/`ranging`
~1–3. Producers SHOULD derive `radius_m` from their actual error estimate where one
exists rather than quoting the typical value.

### 5.4 `payload` (opt-in per peer; never enabled by default)
Relays the raw advertisement payload of **claimed tags** to their owner — the primary
use case being telemetry encrypted in the payload, decodable only by the tag owner.

Constraints (normative):
- **Claim binding**: payload data MUST only be relayed for tags the receiving peer has
  claimed under the peering agreement (a claim asserts ownership of, or authority over,
  the tag and attests to the nature of its payload content). Payloads of unclaimed tags
  MUST NOT appear in OTDX (§8, class C3).
- **Per-peer enablement**: the profile MUST be explicitly enabled per peer; producers
  SHOULD support a jurisdiction-level override that disables it at a given egress point
  regardless of peer configuration.
- **Change-only transmission**: producers SHOULD send payload bytes only when they
  differ from the previously relayed payload for that tag, and MAY send
  `payload_sha256` alone on unchanged observations for continuity.
- **Size cap**: `data` ≤ 255 bytes (BLE extended advertising maximum).

Fields added to `detection` records (when combined with `granular`), and available as a
standalone `"payload"` record type (tag, location, `at`, plus these) for peers not
taking the granular stream:

```json
"data": "base64...",
"payload_sha256": "9f2a...",
"encoding": "vendor:acme:sensorfmt2"
```

`encoding` is an opaque, issuer-scoped hint; `"encrypted"` MAY be used when the format
is private to the owner.

**Trust semantics** (normative note): advertisement payloads are unauthenticated
broadcast radio content. A OTDX payload record asserts only that these bytes were
received at this place and time — nothing about their authenticity or origin.
Consumers MUST authenticate content by means internal to the payload (e.g. the owner's
own MAC/signature within the encrypted payload) before acting on it.

### 5.5 Reserved
`billing` (rate/consumption references), `chainofcustody` (handover attestations) —
placeholders, not drafted.

## 6. Batch envelope and signing

Events travel in batches. A batch is a JSON envelope; the event payload is JSON Lines
(one event per line), optionally zstd-compressed, carried or referenced by the envelope.

```json
{
  "otdx": "0.1",
  "batch_id": "0190b7a4-...",
  "provider": "example",
  "profiles": [{"name": "signal", "critical": false}],
  "created_at": "2026-07-18T03:00:05Z",
  "event_count": 1284,
  "payload_encoding": "jsonl+zstd",
  "payload_sha256": "9f2a...",
  "signature": {"alg": "Ed25519", "key_id": "example-2026-1", "sig": "base64..."}
}
```

- **Signing**: Ed25519 detached signature over `payload_sha256` + the canonicalised
  envelope (JCS, RFC 8785). Public keys exchanged at peering time; `key_id` supports
  rotation. Rationale: when detections become billing/SLA evidence, transport-level auth
  (TLS) is not enough — the batch itself must be non-repudiable and archivable.
- **Idempotency**: `batch_id` dedups whole batches; `event_id` dedups events. Receivers
  MUST tolerate both batch-level and event-level redelivery.
- **Ordering**: none guaranteed, within or across batches. All records are
  self-describing facts; `asserted_at`/`supersedes` resolve conflicts.
- Batch size: RECOMMENDED ≤ 50,000 events or 5 MB compressed.

## 7. Transport bindings

The data model is transport-independent. Bindings, in order of expected use:

1. **HTTPS pull with cursor** — consumer calls
   `GET /otdx/v0/batches?after={cursor}&limit=N`; response is batch envelopes + an opaque
   `next_cursor`. The producer retains batches for an agreed replay horizon (RECOMMENDED
   ≥ 7 days). Preferred where the consumer is behind restrictive egress (this is the
   CN-initiated AU↔CN pattern).
2. **HTTPS push (webhook)** — producer POSTs batches to a consumer URL; 2xx = accepted
   (durable), anything else = retry with backoff. Consumer dedups.
3. **File drop** — batches as files (`{provider}_{batch_id}.otdx.zst` + `.json`
   envelope) over SFTP/object storage, for low-tech peers.

Authentication per binding: mTLS or bearer token — peer agreement choice. The batch
signature is REQUIRED regardless of transport auth.

## 8. Privacy and data classification

Every core/profile field is classified so regulatory review (PIPL, GDPR, etc.) is a
lookup, and peering agreements can exclude classes wholesale:

| Class | Fields | Notes |
|---|---|---|
| C0 — operational, non-personal | `event_id`, `batch_id`, timestamps, `observations`, `rssi`, counts | Equipment telemetry |
| C1 — asset identity | `tag`, `aliases`, `location.id`, `sublocation` | Pseudonymous asset data; personal only if a tag is linkable to an individual by the *holder* of the mapping |
| C2 — precise geolocation | `location.geo`, `fineposition` fields | Optional everywhere; excludable per peer |
| CP — claimed-tag payloads | `payload` profile fields (`data`, `payload_sha256`, `encoding`) | Opt-in per peer, claim-bound (§5.4); jurisdiction-level kill switch RECOMMENDED |
| C3 — prohibited | payloads of unclaimed tags, plaintext personal data, device network credentials, any end-user identity | MUST NOT appear in OTDX |

Cross-border deployments: an OTDX egress point SHOULD be able to enforce a per-peer class
ceiling (e.g. "C1 max, no geo, to peers outside this jurisdiction") in configuration.

## 9. Conformance and tooling

A standard is testable or it is a PDF. The spec ships with:

- **JSON Schema** for envelope and each record type (`otdx-envelope.schema.json`,
  `otdx-presence.schema.json`, `otdx-detection.schema.json`).
- **`otdx-validate`** — CLI validator: schema check, signature check, windowing-rule
  check (overlap detection), classification lint (C3 patterns).
- **Test vectors** — golden batches (valid, and invalid-for-each-rule), including a
  signed batch with published test keypair.
- **Conformance levels**: *Consumer-Core* (accept core batches, dedup correctly),
  *Producer-Core* (emit valid signed core batches), plus per-profile add-ons.

A reference producer/consumer pair accompanies the spec, exercised in production across
an unreliable international network path before external peering.

## 10. Governance and versioning

- Public spec repo (Git), semver. 0.x = anything may change; 1.0 = additive-only within
  major. Changelog per release.
- Field meanings are never reused or changed — deprecate and add instead.
- `otdx` version in every envelope. Receivers accept same-major batches.
- Issuer registry (`tag:`/`loc:`/`det:` issuer short-names): flat file in the spec repo
  while the peer count is small; revisit if it grows.

## 11. Mappings to existing standards (informative)

### GS1 EPCIS 2.0
A PresenceEvent maps to an EPCIS `ObjectEvent`:
`tag`→`epcList` (natural when scheme is `epc`; otherwise via an alias),
`window`→`eventTime` (+ two events, or an `AssociationEvent` window pattern),
`location.id`→`bizLocation`/`readPoint`, `provider`→event source, `observations`/signal
profile→`sensorElementList`. An export tool (`otdx-to-epcis`) is the deliverable here, not
runtime EPCIS support. Divergence rationale: EPCIS mandates JSON-LD context machinery and
GS1 vocabularies that are disproportionate for small peers; OTDX keeps the core flat and
maps out.

### IATA ONE Record
Presence events correspond to logistics event objects attached to a piece/ULD via the
`uld` alias scheme. Mapping is a documented pattern (informative appendix), pursued only
if/when an airline peer requires it.

---

## Appendix A — Worked example: the sentence the standard exists for

"Here's a list of tags detected at NSN during the last hour" =

one batch, N presence events sharing `location.id: "loc:iata:station:NSN"`, windows
clipped to the hour, `open:true` for tags still present, signed by the asserting
provider. A consumer needs ~50 lines of code and the public key to verify and ingest it.

## Appendix B — Open design questions

1. Window continuation: refresh cadence for `open:true` events (fixed cadence vs.
   change-driven) — affects both chattiness and how stale a consumer's view can be.
2. `tid` derivation scheme for MAC-randomising third-party tags: standardise one
   derivation, or leave per-issuer with stability guarantees only?
3. Should `supersedes` allow retraction (asserting a prior event was wrong) as distinct
   from correction? Billing implications.
4. Location granularity discipline: when a peer knows sublocation but agreement is
   site-level only — enforced by egress class ceiling or by spec?
5. Compression: mandate zstd support, or negotiate (zstd/gzip/none) per peer?
6. Tag claims (§5.4): registration mechanics and verification — is a claim a static
   list in the peering agreement, or a dynamic registry (claim by MAC range / issuer
   prefix / signed challenge)? Also whether claims should expire.
