# Enforcement boundary identifier and its change

How the reference names each enforcement boundary, checks a credential's
`aud` against it, and changes it (#853, D487; Runtime "Enforcement
Boundary Identifier" and "Changing a Boundary Identifier", Runtime OAuth
"Boundary and Audience", Runtime Evidence "Integrity"). Paths are relative
to `src/`.

## The declaration

Each `mediated` entry of the Enforcement Scope Statement's
`mediated_scope.resources` is an enforcement boundary, and its resource
string is the boundary identifier. On OAuth it is the protected resource's
RFC 9728 `resource` string, supplied by trusted static configuration: the
reference retrieves no metadata.

`config/enforcement-scope.json` carries the statement's versions as
`enforcement_boundaries`, the reference's representation of the versions
the specification describes in prose (not a Runtime wire member). Each
version has:

- `version` and `effective_at`, the RFC 3339 cutover instant;
- `boundaries`, each with its `boundary` string, the `pep_locations` whose
  routing serves it, its `audience_aliases` (each scoped to one `issuer`
  and `token_profile`, the credential's `typ` media type), and its
  `evidence_keys` (each a `kid`, `emitter` and `role`);
- `replaces`, the declared mapping from a new boundary to the one it
  replaces.

The shipped statement has one version, `payments-boundary-v1`: boundary
`http://localhost:4403/mcp` (tracking `MCP_PAYMENTS_RESOURCE`) for
`mcp-payments-pep`, no alias, and the keys `pdp-decision-evidence` (pdp),
`ephemeral-pep` (pep) and `ephemeral-executor` (executor). The loader
(`loadRuntimePosture`) refuses a declaration that does not resolve: an
unordered or duplicate version, a PEP location under two boundaries, a
last-version boundary that is not a mediated resource, or a PEP location
whose boundary changes with no `replaces` record.

## At each request

- The PEP establishes its boundary from its location and the version in
  force (`EnforcementBoundaryContext.establish`), before it reads any
  credential value. A PEP that cannot establish one refuses
  `boundary_unresolvable` and emits no evidence record of any form.
- The server checks `aud` against that boundary for every credential class
  (`McpPaymentsServer.requireAudience`): a string or an array, by
  membership, naming the boundary directly or through an alias declared
  for the verified issuer and the token's profile. Absent, malformed and
  nonmatching audiences refuse, and so does every token of an issuer and
  profile whose aliases map one value to two boundaries. Other members of
  an array are ignored. The transaction token keeps its singleton rule.
- `resource.properties.audience`, the permit's attempt, every Refusal
  Record, Decision Evidence and Execution Evidence carry the boundary,
  never an `aud` value or alias. The audience is in the PDP's
  authorization binding and cache key (`projections.ts`).
- Each producer signs only under a key the declaration authorizes for the
  record's `audience`: the PDP's Decision Evidence emitter and the PEP's
  Refusal Records under the version in force, the PEP's and executor's
  Execution Evidence under any version in force so far
  (`boundaryEvidenceAuthorization`). A remote PDP accepts a boundary only
  from a PEP the version in force authorizes for it (`AuthorizedPep.scopes`).
- A verifier (`buildBoundaryEvidenceKeyResolver`) selects the version by the
  record's (`audience`, `kid`) pair alone, never by `evaluated_at` or a
  clock, and fails when the declared versions do not determine one key
  authorization and one key for the pair.

The operation target stays separate: entries match the target the
Operation Profile establishes, never the audience, an alias, the transport
URL or the Resource-policy object.

## Changing the identifier

1. **Publish and load the new version.** Append a version naming the new
   boundary, the old identifier as an alias for each issuer and token
   profile that still mints it, the evidence keys authorized for the new
   boundary, a `replaces` record, and an `effective_at` ahead of now. Keep
   every earlier version for as long as its evidence must verify. Load the
   statement into every consumer before `effective_at`: the PEP's boundary
   context, the PDP's emitter authorization and PEP scope registration,
   the evidence store's authorization and every verifier. Each now verifies
   records of either version.
2. **Stop old admissions.** At `effective_at` every PEP establishes the new
   boundary. The reference refuses in-flight operations rather than
   draining them: the `enforcement_boundary` permit-use check suppresses a
   permit decided under the old boundary with `kill_switch`, and the
   client retries under the new one. To drain instead, stop routing new
   requests to the boundary before `effective_at` and wait for in-flight
   operations to finish.
3. **Invalidate old permits and caches.** The same check refuses every held
   permit for the old boundary, a cacheable read's and a compound action's
   later phase included, and no PDP retransmission matches across the
   change because its cache key names the audience.
4. **Switch producers together.** Every producer reads the same
   declaration and clock, so new decisions, permits and records carry only
   the new identifier from `effective_at`; no permit comparison accepts
   both.

Evidence from before the change keeps its meaning. A disposition recorded
after the cutover for a permit decided before it keeps the old `audience`
and verifies as historical evidence, never as a permit. No signed record is
rewritten; `boundarySuccessors` correlates an old identifier with its
successors after verification, and a `replaces` record never extends a
key to the new boundary.

A token naming the old identifier stays usable through the declared alias,
under its unchanged validation and lifetime. The alias never rewrites an
approved entry: an entry naming the old identifier no longer matches the
operation target and is refused `out_of_authority`, and keeping that
authority takes a new approval through Mission creation or derivation.

## Bounds

- **Idempotency across a change.** The idempotency scope names `audience`,
  so a keyed operation retried after the change under a key first used
  before it lands in a new scope, in both the PDP claim domain and the
  PEP's write reservations (each P7D). Schedule the change so that no such
  retry falls inside the horizon, or refuse those retries operationally.
- **Remote claim channel.** Settlement and reconciliation requests carry
  the channel's configured `audience`, not the version in force.
- **Gate refusals.** A token refused at the HTTP gate answers 401 and, as
  for every token-validation failure there, no Refusal Record is emitted.
- **One process.** "Together" means one declaration and one clock; a
  multi-process deployment relies on synchronized clocks at `effective_at`.

Witnesses: `services/pdp/test/enforcement-boundary.test.ts` and
`services/mcp-payments/test/boundary-identifier.test.ts`.
