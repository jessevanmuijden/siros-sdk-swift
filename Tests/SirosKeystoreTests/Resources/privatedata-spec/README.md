# Test Vectors for Private Data Encryption

This directory contains canonical test vectors for validating SIROS wallet private data encryption implementations.

## Test Vector Format

Each line in `vectors.jsonl` is a complete JSON object describing one test case:

```json
{
  "id": "unique-test-identifier",
  "description": "Human-readable description",
  "version": "3",
  "sections": ["4", "5", "6"],
  "tags": ["single-passkey", "basic"],
  "inputs": {
    "credentialId": "<base64url-encoded-credential-id>",
    "credentialIdBytes": 64,
    "prfOutput": "<base64url-encoded-prf-output>",
    "prfOutputBytes": 32,
    "hkdfSalt": "<base64url-encoded-hkdf-salt>",
    "hkdfSaltBytes": 32,
    "hkdfInfo": "eDiplomas PRF",
    "plaintextState": {
      "lastEventHash": "sha256-hash-of-previous-event",
      "events": [{"type": "...", ...}],
      "S": {
        "schemaVersion": 3,
        "credentials": [...],
        "keypairs": [...],
        "presentations": [...],
        "settings": {"openidRefreshTokenMaxAgeInSeconds": "3600"},
        "credentialIssuanceSessions": [...]
      }
    }
  },
  "expected": {
    "containerJsonBytes": "<serialized-container-as-json-string>",
    "containerHash": "sha256-hash-of-container-json-bytes",
    "jweCompact": "eyJ...eye...",
    "decryptedPayload": {...}
  },
  "validations": {
    "encryptMatch": "byte-for-byte match of serialized container JSON",
    "decryptMatch": "parsed state must match plaintextState",
    "roundTrip": "decrypt -> re-encrypt -> compare bytes (or compare with expected.roundTripState where given, see Round-trip below)",
    "metadata": ["credentials[].format", "credentials[].kid", "keypairs[].did"],
    "statePreservation": ["events", "lastEventHash", "presentations", "credentialIssuanceSessions"]
  }
}
```

## Categories

### Basic Vectors (fixtures/)

- **single-credential-v3.json**: One passkey, simple metadata
- **multi-passkey-v3.json**: Multiple credentials, tests PRF entry selection
- **metadata-preservation.json**: All credential/keypair metadata fields present, including the optional credential `metadata` member and the unknown-member rule
- **legacy-v1-symmetric.json**: Old symmetric mainKey format (read-only test)

### Edge Cases (edge-cases/)

- **max-size-container.json**: Large credential set, near practical limits
- **unicode-credentials.json**: Non-ASCII characters in credential names/issuers
- **unknown-credential-members.json**: Unknown per-credential and top-level members, duplicate `metadata` types
- **empty-presentations.json**: No presentations or issuance sessions
- **minimal-state.json**: Minimal required fields only
- **missing-optional-fields.json**: Test optional field handling

## Running Tests Manually

### Decrypt a Test Vector

```bash
# Extract plaintext from vector
cat vectors.jsonl | jq '.[] | select(.id == "single-credential-v3-001") | .expected.containerJsonBytes'

# Run your decrypt implementation
your-client decrypt <container-file>

# Validate against expected state
diff <(your-client decrypt <container-file>) \
     <(cat vectors.jsonl | jq '.[] | select(.id == "single-credential-v3-001") | .inputs.plaintextState')
```

### Encrypt and Verify

```bash
# Get plaintext state
cat vectors.jsonl | jq '.[] | select(.id == "single-credential-v3-001") | .inputs.plaintextState' > plaintext.json

# Get PRF inputs
cat vectors.jsonl | jq '.[] | select(.id == "single-credential-v3-001") | .inputs | {credentialId, prfOutput, hkdfSalt, hkdfInfo}' > prf-inputs.json

# Run encryption
your-client encrypt plaintext.json prf-inputs.json > encrypted.json

# Verify container hash
sha256sum encrypted.json | awk '{print $1}' | \
  diff <(cat) <(cat vectors.jsonl | jq -r '.[] | select(.id == "single-credential-v3-001") | .expected.containerHash')
```

## Normative Test Requirements

Every implementation MUST pass these validations for every vector:

1. **Encryption Determinism**: Encrypting the same plaintext + PRF inputs MUST produce byte-for-byte identical output
2. **Decryption Fidelity**: Decrypting the expected container MUST parse to the plaintext state
3. **Round-trip**: Decrypt → parse → re-encrypt MUST produce identical container bytes, except where a vector states `expected.roundTripState`: then the rewritten state MUST equal that state. Two changes are permitted, and only where `expected.roundTripState` states them: schema migration (version 3 to 4 changes `S.schemaVersion` and nothing else: `single-credential-v3-001`, `multi-passkey-v3-001`, `schema-version-migrate-v3-001`) and the removal of an empty `metadata` array, which a writer MUST NOT emit (`credential-metadata-empty-array-001`)
4. **Metadata Preservation**: All credential/keypair fields in plaintext MUST appear in encrypted state, as MUST every unknown member of a credential entry or of `S`, and credential `metadata` (SPEC.md Section 6)
5. **Event Preservation**: `events[]` and `lastEventHash` MUST be identical after round-trip
6. **Field Completeness**: `presentations`, `credentialIssuanceSessions` MUST be preserved (not empty if present)

### Metadata and delivered-secret vectors

All vectors except `single-credential-v3-001` and `multi-passkey-v3-001` are version 4.

Vectors with `expected.roundTripState` state the state a conforming reader writes back (compared as JSON, array order significant); `expected.plaintextStateSha256` / `roundTripStateSha256` are SHA-256 over the compact JSON encoding of the respective state with members in the order written. `conformance/check-vectors.sh` verifies these offline (needs only `jq`, `xxd`, `sha256sum`).

The delivered-secret vectors (SPEC.md Section 5A) are cases of the form `{response, jweEncrypted, commitmentNamespace, sscHex, expected}`, where `response` is an OpenID4VCI Credential Response using the response-level `credential_metadata` object. `delivered-secret-wire-001` (accept: single and multiple namespaces, batch, unknown member preserved), `delivered-secret-malformed-001` (refuse: hex case, length, over-cap, wrong types) and `delivered-secret-refusal-001` (refuse: plain response, missing `notification_id`, commitment mismatch, absent namespace, `credential_metadata` an array, deferred response carrying a seed). `delivered-secret-strip-001` (seed stripped before the merge into display metadata, seed absent from the merged result) and `delivered-secret-advertise-001` (issuer metadata lists namespace names only; hex values in issuer metadata are malformed) cover Sections 5A.3 and 5A.4. `check-vectors.sh` evaluates every case against the Section 5A rules.

### Schema-version vectors

The `schema-version-*` vectors cover the version rules of SPEC.md Section 6. A reader refuses to rewrite a container with an unknown `S.schemaVersion` (`schema-version-unknown-state-001`), an unknown event `schemaVersion` (`schema-version-unknown-event-version-001`) or an unknown event type (`schema-version-unknown-event-type-001`). Migrating version 3 to version 4 only sets `S.schemaVersion` (`schema-version-migrate-v3-001`), also when a version 3 container written before Spec 3.0 already carries `metadata` and `S.extensions` (`schema-version-v3-legacy-members-001`). A writer that stores `metadata` or an extension never leaves the container at version 3 (`schema-version-v3-writer-001`). An event without an integer `schemaVersion` is refused (`schema-version-event-missing-version-001`). `schema-version-event-types-001` carries one real event of each of the ten implemented event types. `keypair-unknown-entry-001` covers unparseable or unknown `S.keypairs[]` entries, which are preserved verbatim. `check-vectors.sh` checks that the migration vectors (including the two version 3 vectors `single-credential-v3-001` and `multi-passkey-v3-001`, whose expected output is version 4) change nothing but `S.schemaVersion`, that every accepted vector carries only real, versioned events of the ten types, and that each refusal vector is refusable under those rules.

## Vector Maintenance

When adding new test vectors:

1. Create a descriptive JSON object with all required fields
2. Add it to `vectors.jsonl` (one object per line)
3. Document the test case in appropriate `fixtures/` or `edge-cases/` subdirectory
4. Run all clients against it: `conformance-runner.sh --vector <id>`
5. Verify all pass before committing

## Implementation-Specific Notes

### TypeScript/JavaScript (wallet-frontend)

The reference implementation is `wallet-frontend`. Generate vectors by:

```bash
cd wallet-frontend
npm run conformance:generate-vectors > privatedata-spec/test-vectors/vectors-reference.jsonl
npm run conformance:validate -- --vectors privatedata-spec/test-vectors/vectors.jsonl
```

### Kotlin (siros-sdk-kotlin)

Generate and validate:

```bash
cd siros-sdk-kotlin
./gradlew generateConformanceVectors --output ../privatedata-spec/test-vectors/vectors-kotlin.jsonl
./gradlew validateConformance --vectors ../privatedata-spec/test-vectors/vectors.jsonl
```

### Swift (siros-sdk-swift)

Generate and validate:

```bash
cd siros-sdk-swift
swift run ConformanceGenerator > ../privatedata-spec/test-vectors/vectors-swift.jsonl
swift run ConformanceValidator --vectors ../privatedata-spec/test-vectors/vectors.jsonl
```

All outputs must be identical (bitwise) for shared test cases.
