# Mission Request Provenance vectors

These files define, as data, the request digest and assertion cases of `draft-mcguinness-oauth-mission-request-provenance` (#939, D1119). They are specification cases. A case passing in one implementation is evidence for that implementation only; it is not a claim that every implementation conforms. Two implementations agreeing on an HMAC value is evidence that the vectors are correct, not an interoperability or secrecy claim (D1119 Q6).

The files are independently consumable: a consumer needs only JSON, not this repository's implementation. `src/packages/request-provenance/scripts/generate-vectors.mjs` produced them from the draft's encoding, without the package's library code.

Every secret and key here is a fixed test value. An intake never uses one.

## Files

| File | Format | Contents |
|---|---|---|
| `request-digest.json` | `mission-request-provenance-digest-vectors/1` | Request digest vectors: the draft appendix's four, then short low-entropy and edge instructions |
| `assertion.json` | `mission-request-provenance-assertion-vector/1` | One positive assertion: inputs, the exact protected header and claims, a sample JWS, the recorded facts, and a verifier context |
| `assertion-cases.json` | `mission-request-provenance-assertion-cases/1` | Assertion-level cases derived from the positive vector, for the AS verifier |

## Request digest vectors

Each case carries:

| Member | Meaning |
|---|---|
| `id` | Stable identifier |
| `source` | The draft appendix, or this slice |
| `secret_hex` | The 32-byte capture secret, in hexadecimal |
| `media_type` | The media type exactly as recorded (US-ASCII) |
| `instruction_utf8`, `instruction_hex` | The instruction; `instruction_hex` is its exact bytes and governs |
| `hmac_input_hex` | The exact HMAC input: `mission-request-provenance/v1`, one zero byte, the media type's 4-byte big-endian length and bytes, the instruction's 8-byte big-endian length and bytes |
| `request_digest` | `hmac-sha-256:` followed by the unpadded base64url HMAC-SHA-256 output |

`rd-01` to `rd-04` are the draft appendix's vectors and reproduce its published values. `rd-05` to `rd-08` are low-entropy instructions of a few words: the cases a holder could guess, and so the reason the digest is keyed. `rd-09` is an empty instruction (an 8-byte zero length) and `rd-10` a short instruction with non-ASCII UTF-8 bytes, hashed as received.

## Positive assertion

`assertion.json` gives:

- `key`: the test ES256 key pair. `public_jwk` verifies the sample; `private_jwk_test_only` signed it.
- `intake`: the signer identifier, assertion lifetime and maximum capture age the producer used.
- `capture`: the workflow, media type, instruction, originator and channel the intake established, `captured_at`, and the fixed random values: `secret_hex` (the capture secret) and `capture_id` (the base64url of 16 fixed bytes).
- `sign`: the workflow, the intended AS (`audience`), the candidate Intent, the presenter, `iat`, and the fixed `jti` (the base64url of 16 fixed bytes).
- `expected.protected_header` and `expected.claims`: exact. `intent_hash` is the OAuth binding's integrity anchor over the candidate Intent with `iss` the AS that `aud` names; `request_digest` equals `rd-01`.
- `expected.entry`: the evidence entry with a sample JWS over that header and claims. ECDSA signatures are randomized, so a consumer checks that the sample verifies under `public_jwk` and that its header and claims equal the expected ones, never its signature bytes. Regenerating produces new signature bytes over the same content.
- `expected.recorded_facts`: the facts an AS records on acceptance (Recorded Facts), `captured_at` as an RFC 3339 timestamp.
- `verifier_context`: what an AS needs to verify the sample: its issuer identifier, the verification time `now`, its declared clock-skew allowance, maximum assertion lifetime and maximum capture age, its trust configuration (`trust.signers`: per signer, its `iss`, its keys with the evidence types and algorithms the configuration maps to each, the originator issuers and the channel types it may attest), the submitted Intent, and the presenter the containing exchange established.

## Assertion cases

Each case carries:

| Member | Meaning |
|---|---|
| `id` | Stable identifier |
| `description` | The defect |
| `step` | The draft's Verification step that refuses it, or `null` |
| `construction` | How the case differs from the positive vector: `header_set`, `header_delete`, `claims_set`, `claims_delete`, `payload_set` (after signing), `signature`, or `verifier_context_patch` |
| `token` | The assertion to verify |
| `expected` | `outcome` (`refuse` or `accept`); on `refuse`, `error`; on `accept`, `recorded_facts` |
| `producer` | `checked`, with the producer test showing this package's intake never emits the defect, or `not-applicable`, with the reason |
| `verifier` | `checked`, with the AS verifier test that runs the case: `<id>: refused at step <step>`, or, for an accepted case, `<id>: accepted, recording exactly the positive vector's facts` |

A consumer runs each case alone, against a fresh replay store, with `assertion.json`'s `verifier_context` after applying the case's `verifier_context_patch` as a JSON Merge Patch (RFC 7386; arrays are replaced whole). A case's `token` is signed with the test key unless `construction.signature` says otherwise, so a refusal in steps 2, 3, 5 and later never depends on a bad signature.

`neg-missing-iss` refuses at step 3, not step 5: step 3 looks the signer up by the `iss` claim, so an assertion without one names no signer.

`neg-presenter-cnf-unestablished` is the PAR case: the exchange established the client and no confirmation key, so a `presenter` carrying `cnf` does not agree, and no key is inferred from the assertion.

`ign-extra-content-claim` is accepted, not refused. A producer MUST NOT emit a claim that commits to request content, and this package's intake is checked never to emit one; a verifier ignores claims the draft does not define, as RFC 7519 requires, and records no fact from them. The expected recorded facts are the positive vector's.

## Status

The producer column is checked by `src/packages/request-provenance/test/`. The verifier column is checked by `src/services/authorization-server/test/request-provenance-verifier.test.ts`, which runs every case through the AS verifier module (`services/authorization-server/src/kernel/request-provenance.ts`, #939 slice 2a-1) with the case's patched trust configuration loaded through `@mission/demo-data`'s loader. The module does not reserve: the replay store and the AS endpoints that carry the type are later slices, so a case's "fresh replay store" is not yet exercised.
