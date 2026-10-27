# Attenuating Agent Tokens -02 test vectors

`aat-jws-vectors.json` is the machine-readable JWS test vector suite that
`draft-niyikiza-oauth-attenuating-agent-tokens-02` cites as `[AAT-VECTORS]`
(Appendix E.5). It is vendored byte-for-byte; do not edit it. To move to a
newer suite, replace the file and update the pin below.

| Field | Value |
|---|---|
| Repository | https://github.com/tenuo-ai/tenuo |
| Commit | `81b2802e4c76aaa16c0bb8bd11f7223999340a69` (2026-10-27, "ietf: add AAT vectors for split and union-covered any clauses") |
| Path | `tests/vectors/aat-jws-vectors.json` |
| SHA-256 | `b7a42e9dfdce7fbc1f623670bf060f90e6d6b25f64384cbab1bd79363e82209b` |
| Fetched | 2026-10-27, from `raw.githubusercontent.com` at that commit |
| Suite | 229 vectors (54 PERMIT, 175 DENY), `spec` `draft-niyikiza-oauth-attenuating-agent-tokens-02` |

## License

Copyright 2025-2026 Tenuo Contributors. The suite is licensed under the
Apache License, Version 2.0; `LICENSE` in this directory is a copy of the
license at the pinned commit. This repository's own code is under its own
license; the vendored file stays under Apache-2.0.

## How the suite is run

`test/aat-vectors.test.ts` verifies each vector's `presentation`
(`aat_chain`, `aat_pop`) with `verifyAatPresentation` for its `tool` and
`args_json` at its `now`, following the suite's `INTEROP.md` at the pinned
commit (`ietf/vectors/INTEROP.md`):

- the suite-level `trust_anchors` and `params` apply to every vector, and a
  vector's own `params` and `policy` override them;
- `policy` maps to the verifier's policy: `require_pop_aud`,
  `require_chain_aud`, `nonce` (the one nonce the enforcement point accepts)
  and `track_pop_jti`, with `replay_state.before` as the accepted PoP `jti`
  set and `replay_state.after` checked after the run;
- `args_json` and each token's payload are read losslessly, never through
  `JSON.parse`;
- verdicts are compared, not failing steps, since Section 8 permits some
  steps to be reordered. At this commit every DENY vector is also refused at
  the step the suite cites.

## Exclusions

None. Every vector of the pinned suite runs.

The other files under `tests/vectors/` at the pinned commit are not Section 8
cases: `holder-lifecycle.json` is Tenuo's connect-token and receipt
contract, `tenuo-meta*.json` are Tenuo metadata, and
`duplicate-argument-keys.json` is an argument object with a repeated member,
which J.9.5 and J.20.12 already cover.
