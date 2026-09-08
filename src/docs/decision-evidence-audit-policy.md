# Decision Evidence audit projection

The reference deployment retains identifiers needed to correlate its own
decisions. This is a fixed runtime allowlist, not a claim that a narrow
TypeScript interface removes extra properties.

- Subject: `id`, optional `type`, and optional `properties.iss`.
- Actor: `client_id`, `client_instance_id`, and root-to-leaf `act` entries
  containing only `iss`, `sub` and optional `sub_profile`. No arbitrary hop
  claims, nested `act`, confirmation keys or token payloads are retained.
- Resource: `type` and `id`; resource-policy properties are not copied.
- Action: `name` only. Parameters appear only through their binding digest,
  never as raw or renamed action properties.
- Credential: verified `issuer` and `expires_at` only. Each credential
  validator constructs these after validation, the PEP copies only these
  members from token facts, and the PDP projects them again before signing.
  Tool arguments cannot supply them. The attenuation path uses the verified
  leaf credential, not the root's longer expiry. The mediated MCP fixture
  continues to make no live DPoP proof-of-possession claim.
- Mission: request `id`/`issuer`, PDP-owned `policy_view_id`, optional known
  anchors and `policy_version`. A view-mismatch denial never copies the
  unrelated loaded Mission's authority anchor.

The normalized evidence conditions contain validity and consumption bounds.
The parameter binding is recorded once at the record's top level, after an
equality check against the live permit conditions. All three high-consequence
classes require `use_limit: 1`. Unknown classes and inconsistent permit
bindings are refused before signing.

The no-parameter fallback remains the existing documented request-summary
digest (`requestDigestFallback`), not a commitment to every decision input.
The broader whole-request digest requirement remains partial. Required
conditional content such as evaluated constraints and returned obligations
is tracked in later #594 slices; this PR makes no complete object/profile
conformance claim. Sequence state remains in memory, now keyed by the
qualified Mission and emitter identity, with no restart-durability claim.
