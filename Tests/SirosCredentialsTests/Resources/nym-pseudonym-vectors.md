# nym_auth pseudonym test vectors

`nym-pseudonym-vectors.json` holds test vectors for `pseudonym-v1-sha256`, the
`nym_auth` rulebook's pseudonym function (rulebook v0.3, "Pseudonym generation
function" and "Configurations"):

    pseudonym = SHA256(DST || seed || prover_input || verifier_input)
    DST       = "nym_auth/v1/<config>"   (UTF-8, no separators)
    null input = 32 zero bytes

**Status: self-generated, not yet cross-checked with the circuit developers.**
The longfellow circuit note says `SHA-256(client_id)` where the rulebook hashes
`verifier_id`; the vectors take `verifier_id` as an opaque string and decide
nothing about that. Cross-check them before a real prover relies on them.

The file is shared between SDKs: the Kotlin SDK's `NymPseudonymTest` consumes
it, and it is meant to be copied unchanged into siros-sdk-swift next to a
parity check that the copy equals this one (the same arrangement as
`bridge-capabilities.json`).

## Format

Top level: `status`, `rulebook`, `generator` (informational), `vectors`,
`rejections`.

`vectors[]`, each a successful derivation:

| Field | Meaning |
|---|---|
| `name` | human description |
| `config` | config id |
| `seed_hex` | the seed, hex (16 bytes for every current config) |
| `verifier_id` | optional, opaque UTF-8 string, passed through verbatim |
| `verifier_context` | optional, UTF-8 string, any length (the 1-64 byte limit is a wallet satisfiability rule, not tested here) |
| `prover_input_hex` | optional, the user-supplied value for the xsite config, hex; the function hashes it |
| `expected_hex` | the 32-byte pseudonym, hex |

An absent field means the argument is not supplied (null), which is different
from an empty string: `verifier_context: ""` is supplied and empty.

`rejections[]`: same input fields, no `expected_hex`, plus `error`, one of
`UNKNOWN_CONFIG`, `MISSING_INPUT`, `UNUSED_INPUT`, `WRONG_SEED_LENGTH`. An
implementation must refuse these arguments with that error. They are
API-misuse errors, not rulebook satisfiability verdicts.

## How the expected values were generated

`tools/gen_nym_pseudonym_vectors.py` (Python `hashlib` only; it does not call
the Kotlin implementation) builds each pseudonym straight from the rulebook
formulas:

- `known-offender-matching-ssc` / `-psc`: prover_input = 32 zero bytes;
  verifier_input = SHA256(UTF-8 verifier_id).
- `account-recovery-ssc`: prover_input = 32 zero bytes; verifier_input =
  SHA256(SHA256(UTF-8 verifier_id) || SHA256(UTF-8 verifier_context)).
- `user-managed-pseudonym-xsite-ssc`: prover_input = SHA256(user value);
  verifier_input = 32 zero bytes.
- Result = SHA256(UTF-8("nym_auth/v1/" + config) || seed || prover_input ||
  verifier_input).

Regenerate with `python3 tools/gen_nym_pseudonym_vectors.py`; verify the
committed file is current with `--check`. The seeds are the fixed byte runs
`00..0f` and `f0..ff` (16 bytes each).
