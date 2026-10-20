# nym_auth pseudonym test vectors

`nym-pseudonym-vectors.json` holds test vectors for `pseudonym`, the
`nym_auth` rulebook's pseudonym function (rulebook v0.4, "Pseudonym generation
function" and "Configurations"):

    pseudonym = SHA256(DST || seed || prover_input || verifier_input)
    DST       = "nym_auth/v1/<config>"   (UTF-8, no separators)
    null input = 32 zero bytes

**Status: self-generated, and cross-checked against the circuit developers' reference pseudonyms.** The two
`archive reference` vectors are the `pseudonym.json` values of zk-cred-vega (`155f4337...aad1` for
`x509_san_dns:verifier.example`): the generator asserts them. `verifier_input = SHA-256(verifier_id)` with `verifier_id`
the PREFIXED string (rulebook v0.4): for `x509_san_dns` the Client Identifier including its prefix
(`x509_san_dns:<dns name>`), for `semantic` `semantic_id:` plus the identifier. The bare DNS name is not a `verifier_id`;
the derivation itself hashes whatever string it is given, byte for byte.

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
