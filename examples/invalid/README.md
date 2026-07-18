# Invalid examples

Each directory violates exactly one rule; `otdx-validate --pubkey ../keys/otdx-test-key.pub <dir>/<name>.envelope.json` must FAIL on all of them.

| Directory | Violated rule |
|---|---|
| schema_violation | event missing required `window.open` |
| overlapping_windows | two windows for same (tag, location) overlap (SPEC 4) |
| unknown_critical_profile | profile unknown to receiver marked critical (SPEC 5) |
| payload_hash_mismatch | envelope payload_sha256 does not match payload bytes (SPEC 6) |
| bad_signature | envelope tampered after signing (SPEC 6) |
| undeclared_profile_fields | payload-profile fields without payload profile declared (SPEC 5.4) |
