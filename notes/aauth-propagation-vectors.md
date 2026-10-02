# AAuth Mission Propagation Vectors (documentary)

These vectors trace how `draft-mcguinness-mission-aauth` fails closed
when a required Mission association breaks (issue #835). They are
documentary: no test executes them, no conformance row cites them, and
nothing here marks any runtime behavior tested. Issue #836 turns them
into executable negative vectors.

Baseline: `draft-hardt-oauth-aauth-protocol-11`. Section numbers are
-11's. "The rule" is the binding's Reference Propagation section:

- A required association that is missing, malformed, invalid,
  unresolvable, or mismatched fails the request under AAuth's own rules.
- The PS, or the AS in four-party access, MUST NOT evaluate a failed
  request as missionless authorization.
- The agent MUST NOT retry it without the reference.

Notation: `M` and `M2` are distinct `mission_s256` values approved by
the same PS for the same agent. `PT` is a person token, `AT` an auth
token, and `RT` a resource token. "Prohibited at" names the point after
which ordinary (missionless) authorization of the request is
prohibited.

## Vectors

### V1. Valid inherited association (three-party)

- Policy: the agent operates under `M`.
- Credentials: `PT{mission_s256: M}`. `RT{mission_s256: M, presented_jti: PT.jti}`. The agent forwards `presented_token = PT`.
- Receiver and checks: the PS verifies `presented_token` against `RT` (6.7.2 step 3) and verifies that `M` is active and unexpired (6.7.2 step 4).
- Expected: the governed path. The PS evaluates the mission context, and the issued `AT` carries `M` (9.4.1).
- Prohibited at: not applicable.

### V2. Stripped from a resource token derived from a Mission-bearing person token

- Credentials: `PT{M}`, and `RT` with no `mission_s256` and `presented_jti = PT.jti`.
- Receiver: the PS.
- Expected: `invalid_resource_token`, rejected on omission (6.7.2 step 3).
- Prohibited at: the resource-token check. The PS MUST NOT evaluate the request as missionless, and the agent MUST NOT retry without `M`.

### V3. Different Mission on the resource token

- Credentials: `PT{M}`, and `RT{M2, presented_jti: PT.jti}`.
- Receiver: the PS.
- Expected: `invalid_resource_token` on the mismatch (6.7.2 step 3). It SHOULD be surfaced to operators as evidence of tampering.
- Prohibited at: the resource-token check. No same-agent or same-resource heuristic replaces the named presented token.

### V4. Wrong presented token

- Credentials: `RT{M, presented_jti: PT.jti}`. The agent forwards a different `PT'{M}`.
- Receiver: the PS.
- Expected: `invalid_resource_token`, because `jti` does not equal `presented_jti` (6.7.2 step 3).
- Prohibited at: the resource-token check.

### V5. Step-up on a presented auth token

- Credentials: `AT{M}` presented to the resource. The challenge carries `RT` with no `mission_s256` and `presented_jti = AT.jti`. The agent forwards `presented_token = AT`.
- Receiver: the PS.
- Expected: `invalid_resource_token` on omission (6.7.1, 6.7.2 step 3).
- Prohibited at: the resource-token check.

### V6. Four-party stripped or mismatched

- Credentials: as V2 or V3, with `RT.aud` the resource's AS.
- Receiver: the AS, which verifies `presented_token` against `RT` (9.1.1).
- Expected: the AS rejects. The PS relays the AS's terminal error (9.1.3).
- Prohibited at: the AS check. Neither the AS nor the PS issues missionless.

### V7. Malformed reference at person-token issuance

- Credentials: a person token request whose `mission_s256` is not a well-formed value (for example, not an unpadded base64url SHA-256 digest).
- Receiver: the PS (person token endpoint).
- Expected: `invalid_request`, which "covers a missing or malformed resource or mission_s256" (7.1).
- Prohibited at: request validation. The agent MUST NOT retry without the reference.

### V8. Unknown or foreign reference at person-token issuance

- Credentials: a person token request whose well-formed `mission_s256` names no mission, or a mission of another agent.
- Receiver: the PS (person token endpoint).
- Expected: rejected; the PS "MUST reject the request otherwise" (7.1).
- Prohibited at: issuance. The agent MUST NOT retry without the reference.

### V9. Mission-governed agent sends a missionless request

- Policy: the PS places the agent under mission governance.
- Credentials: a person token or auth token request with no `mission_s256` and no presented token carrying one.
- Receiver: the PS.
- Expected: rejected. This is the binding's local rule; AAuth defines no dedicated error.
- Prohibited at: the request.

### V10. Mission no longer active, at the state check

- Credentials: a request naming `M` after `M` terminated (completed, revoked, superseded, or administrative), whose presented token, if any, still verifies.
- Receiver: the PS.
- Expected: `mission_terminated` (8.8; 6.7.2 step 4). `termination_reason` is OPTIONAL in the response.
- Prohibited at: the state check. There is no missionless continuation.

### V11. Mission past `expires_at`

- Credentials: a request naming `M` after `M.expires_at`, presenting a Mission-bound person token or auth token. The PS capped that token's `exp` at `expires_at` (7.1.2, 9.4.1), so the token has expired.
- Receiver: the PS.
- Expected: `expired_presented_token` at presented-token verification (6.7.2 step 3), before the state check at step 4 is reached.
- Prohibited at: presented-token verification. The PS MUST NOT evaluate the request as missionless, and the agent MUST NOT retry it without the reference.

### V12. Required state unavailable

- Credentials: a decision that depends on Management status, where status failed, is stale, or the status surface is unavailable.
- Receiver: the consumer of the status.
- Expected: the state-dependent decision is refused (Statement failure paragraph).
- Prohibited at: the decision.

### V13. Chained, with the upstream token invalid

- Credentials: an intermediary requests a person token for a downstream resource with `upstream_token = PT{M}` that fails verification.
- Receiver: the PS.
- Expected: `invalid_upstream_token`, `expired_upstream_token`, or `revoked_upstream_token` (9.4.5 step 1).
- Prohibited at: issuance. The PS issues no missionless downstream person token; on success it would copy `M` itself (7.1).

### V14. Intentionally missionless path

- Policy: deployment policy admits the agent's missionless access from the outset, and the agent is not under mission governance.
- Credentials: no `mission_s256` anywhere, and no presented or upstream token carrying one.
- Receiver: the PS.
- Expected: base AAuth processing. The request is outside the Lifecycle-Gated Authorization and Credential-Bound claims.
- Prohibited at: not applicable. This is not a fallback from V2-V13.

## What each negative vector shows

V2-V11 and V13 reject before any ordinary authorization: the failure
is at a validation, verification, or issuance step, in AAuth's order of
checks, and the rule forbids a missionless evaluation or retry of the
same request. V12 refuses only the decision that depends on state. V14
is the only missionless outcome, and it is reached by policy, not by a
failed validation.

## Reference confinement fixture (issue #840)

The reference is a deterministic digest, not a secret. This fixture
checks the binding's namespace confinement instead: every PS surface
keyed by the reference authenticates the caller and does not disclose
existence (the binding's Native Reference section).

Fixture: a low-entropy synthetic blob built from a predictable template.
Its `agent` is known, its `description` comes from a short list, and
its `approved_at` falls in a one-minute window. A tester can therefore
enumerate the candidate blobs and their `s256` values. Never treat the
digest's length as evidence of input entropy.

### P1. Guessed reference from a non-owner agent

- Credentials: an authenticated agent that does not own the mission names a correctly guessed `s256`. It does so at each endpoint that takes a `mission_s256` parameter (person token, permission, audit, interaction) and at `{mission_endpoint}/{mission_s256}`. The mission may be active or terminated.
- Receiver: the PS.
- Expected: the same response as for a mission that does not exist. That means the same status, error, body, header set, and observably equivalent timing (8.7 at the mission endpoint; the binding's ownership-first rule elsewhere). Never `mission_terminated`, which -11 Section 8.8 would otherwise report without an ownership condition.
- Shows: possession or a correct guess discloses nothing and authorizes nothing.

### P2. Guessed reference at the control plane

- Credentials: a caller without authorization for the mission names the guessed `s256` at `mission_control_endpoint`.
- Receiver: the PS (management companion).
- Expected: `mission_not_found`, identical for absent and unauthorized (the management companion's anti-oracle rules).
