# nym_auth secret_seed / ssc commitment test vectors

`secret-seed-commitment-vectors.json` holds test vectors for the relation between the
`nym_auth` credential's `ssc` data element and the `secret_seed` the issuer delivers to
the wallet (rulebook v0.3):

    ssc = SHA256(secret_seed)       secret_seed: exactly 16 bytes, ssc: exactly 32 bytes

A wallet that holds a delivered `secret_seed` must not use it on trust: the presenter
checks `SHA256(seed) == ssc` (constant time) against the credential's own `ssc` before it
calls a prover, and refuses otherwise.

**Status: self-generated, not yet cross-checked with the circuit developers.**

The file is shared between SDKs: the Kotlin SDK's `CircuitZkPresenterTest` consumes it,
and it is meant to be copied unchanged into siros-sdk-swift next to a parity check that
the copy equals this one (the same arrangement as `nym-pseudonym-vectors.json`).

## Format

Top level: `status`, `rulebook`, `generator` (informational), `vectors`, `rejections`.

`vectors[]`, a seed that opens its commitment (a presentation is produced):

| Field | Meaning |
|---|---|
| `name` | human description |
| `seed_hex` | the `secret_seed`, hex (16 bytes) |
| `ssc_hex` | the credential's `ssc`, hex (32 bytes) = SHA256(seed) |

`rejections[]`: same fields, plus `step`, the point at which the presenter refuses
(nothing is proved): `WITNESS` when the seed is not 16 bytes, `SECRET_COMMITMENT` when the
`ssc` is not 32 bytes or `SHA256(seed) != ssc`. The step is informational for an
implementation with other internals; the requirement is that no presentation is produced.

## How the expected values were generated

`tools/gen_secret_seed_commitment_vectors.py` (Python `hashlib` only; it does not call the
Kotlin implementation) computes `ssc = SHA256(seed)` for the seeds `00..0f`, `f0..ff`, 16
zero bytes and 16 `0xff` bytes, and derives each rejection from them (a seed of another
credential, a one-bit flip, a padded seed, a double hash, 15/17/32/0-byte seeds,
31/33/0-byte commitments).

Regenerate with `python3 tools/gen_secret_seed_commitment_vectors.py`; verify the
committed file is current with `--check`.
