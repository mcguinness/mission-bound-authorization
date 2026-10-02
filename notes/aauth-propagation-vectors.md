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

### V7. Malformed, unknown, or foreign reference at person-token issuance

- Credentials: a person token request with `mission_s256` naming no mission, or a mission of another agent.
- Receiver: the PS (person token endpoint).
- Expected: rejected; the PS "MUST reject the request otherwise" (7.1).
- Prohibited at: issuance. The agent MUST NOT retry without the reference.

### V8. Mission-governed agent sends a missionless request

- Policy: the PS places the agent under mission governance.
- Credentials: a person token or auth token request with no `mission_s256` and no presented token carrying one.
- Receiver: the PS.
- Expected: rejected. This is the binding's local rule; AAuth defines no dedicated error.
- Prohibited at: the request.

### V9. Mission no longer active

- Credentials: any request naming `M` after `M` terminated, including by `expires_at`.
- Receiver: the PS.
- Expected: `mission_terminated` with `termination_reason` (8.8). After expiry, 6.7.2 step 4 fails.
- Prohibited at: the state check. There is no missionless continuation.

### V10. Required state unavailable

- Credentials: a decision that depends on Management status, where status failed, is stale, or the status surface is unavailable.
- Receiver: the consumer of the status.
- Expected: the state-dependent decision is refused (Statement failure paragraph).
- Prohibited at: the decision.

### V11. Chained, with the upstream token invalid

- Credentials: an intermediary requests a person token for a downstream resource with `upstream_token = PT{M}` that fails verification.
- Receiver: the PS.
- Expected: `invalid_upstream_token`, `expired_upstream_token`, or `revoked_upstream_token` (9.4.5 step 1).
- Prohibited at: issuance. The PS issues no missionless downstream person token; on success it would copy `M` itself (7.1).

### V12. Intentionally missionless path

- Policy: deployment policy admits the agent's missionless access from the outset, and the agent is not under mission governance.
- Credentials: no `mission_s256` anywhere, and no presented or upstream token carrying one.
- Receiver: the PS.
- Expected: base AAuth processing. The request is outside the Lifecycle-Gated Authorization and Credential-Bound claims.
- Prohibited at: not applicable. This is not a fallback from V2-V11.

## What each negative vector shows

V2-V9 and V11 reject before any ordinary authorization: the failure is
at a verification or issuance step, and the rule forbids a missionless
evaluation or retry of the same request. V10 refuses only the decision
that depends on state. V12 is the only missionless outcome, and it is
reached by policy, not by a failed validation.
