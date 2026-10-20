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

`MCP_PAYMENTS_RESOURCE` templates the payments resource into the
statement only where that is configuration (`templatePaymentsResource` in
`packages/demo-data`): the mediated-scope resource, and a one-version
declaration with no `replaces` record, which is initial configuration.
A declaration that retains history is loaded byte for byte, earlier
versions, `replaces` records, aliases and emitter identities included,
since evidence produced under it verifies against those bytes; an
override the last version does not declare as a boundary is refused at
load rather than rewriting a retained version.

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
- The validated facts carry the boundary and statement version `aud` was
  validated against (`validatedBoundary`). Before any decision work, at
  intake and again at the decision, the PEP refuses
  `credential_boundary_changed` when the boundary or version it
  establishes differs: a cutover fell between validation and decision.
  The refusal is a token-validation failure at the boundary in force, so
  it is recorded there (`token_invalid`); the credential is never moved
  into a boundary that did not accept it, and the client's retry is
  validated afresh.
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
   statement into every consumer before `effective_at`. In the assembled
   stack (`demo/src/stack.ts`) one boundary context feeds the PEP, the
   PDP's emitter authorization, its Refusal Record scope and its PEP scope
   registration, the remote claim channel's scope, the evidence store's
   signing authorization and its Decision Evidence verifier, the claim
   domain's settlement verifier, and the key sets the stack publishes,
   which then serve records of either version. A consumer whose bindings
   live outside the statement holds the cutover until it is provisioned
   (below).
2. **Stop old admissions.** At `effective_at` every PEP establishes the new
   boundary. The reference refuses in-flight operations rather than
   draining them: a request whose credential was validated under the old
   version is refused `credential_boundary_changed`, and the
   `enforcement_boundary` permit-use check suppresses a permit decided
   under the old boundary or version with `kill_switch`. The client
   retries under the new one. To drain instead, stop routing new
   requests to the boundary before `effective_at` and wait for in-flight
   operations to finish.
3. **Invalidate old permits and caches.** The same check refuses every held
   permit for the old boundary, a cacheable read's and a compound action's
   later phase included. A permit the PDP holds for retransmission is never
   returned after the change: its claim records the statement version it
   was made under and retransmits only while that version is in force, so
   a retry with its key is `duplicate_suppressed` even where the
   identifier, and so the cache key, is unchanged. The PEP takes a permit's
   version from its retained Decision Evidence row, recorded when the
   record is first retained, never from the request that receives the
   permit, so a re-presented permit keeps its own version and the use
   check suppresses it.
4. **Switch producers together.** Every producer reads the same
   declaration and clock, so new decisions, permits and records carry only
   the new identifier from `effective_at`; no permit comparison accepts
   both.

The reference invalidates held permits at every new statement version,
one that keeps the identifier and changes only an alias or a key
included. That is the reference's conservative policy, not a requirement
that every deployment invalidate on a key-only change.

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

## Duplicate-effect protection across a change

The idempotency scope names `audience`, but a declared change renames the
boundary, not the operations already admitted at it, so no key becomes
fresh. The PDP's claim domain and the PEP's write reservations look a key
up under the request's scope and under the same scope at every identifier
the boundary replaces through declared `replaces` records
(`boundaryPredecessors`, `lineageScopeDigests`). The PEP reads that
lineage at retrieval and again inside the reservation's own transaction;
the claim domain reads it inside its claim transaction, from its own
statement.

A keyed operation retried after the change therefore meets its original
disposition: a completed reversible write returns its retained response
(a cancelled schedule is never recreated), and a high-consequence key
claimed before the change is suppressed rather than claimed again.
Records stay under the scope they were made in and nothing is rewritten.
Invalidating permits does not erase this: the retry is decided afresh at
the new identifier, an old permit is never reused, and a retained claim
never retransmits across the change, since its cache key names the old
audience and the statement version it was made under is no longer in
force. A rename that also moves the operation target changes the
operation identity, so the retry is refused (`operation_identity_conflict`
or `idempotency_conflict`), still with no second effect. Retention is
unchanged: each record is kept for its published horizon from when it was
made.

## Consumers are provisioned before the cutover

Some consumers hold bindings the statement cannot change by itself: a
published key set binds each key to one audience, append-only at its
location; a settlement verifier holds key material; the PDP's claim
domain reads the `replaces` lineage from its own copy of the statement.
Each is bound to the boundary context as a `BoundaryConsumer`, and the
version in force establishes a boundary only once every bound consumer is
provisioned for it (`EnforcementBoundaryContext.establish`). Until then
tokens refuse (`consumer_unprovisioned`), the PEP refuses
`boundary_unprovisioned` with no record, and held permits are suppressed
at use: no producer uses the new identifier while a consumer still holds
only the old bindings.

The stack binds three consumers:

- the published key set, provisioned for a boundary when that boundary's
  own location (`evidenceKeySetLocation`) publishes every key the version
  authorizes for it, bound to it;
- the claim domain's settlement verifier, which verifies by the record's
  (`audience`, `kid`) pair under the declared versions
  (`buildBoundaryEvidenceKeyResolver`), provisioned when it holds every
  enforcement key the version authorizes;
- the claim domain itself, provisioned when its statement declares the
  version byte for byte.

The stack publishes every key it holds at each declared boundary's
location that authorizes it, so a change that keeps its keys is
provisioned when the stack is composed; a version that authorizes a key
the stack does not hold (a rotated key) holds the cutover until the
deployment is reprovisioned with it. The remote claim channel's scope
follows the boundary in force (`claimAudience`) rather than a configured
audience.

While a consumer is unprovisioned the two decision-channel topologies
differ. Over the remote channel, settlement and reconciliation are scoped
to the boundary in force, which is not established, so the PEP sends
neither: they are held, a disclosed availability limitation. Unresolved
work stays retained in the claim domain, a retry with its key is
suppressed under the original claim, and none of it can become a fresh
operation; settlement and reconciliation resume once every consumer is
provisioned. Co-resident settlement reaches the claim domain directly and
keeps verifying historical records, each under the version that produced
it.

Earlier bindings stay available: the earlier boundary's key set keeps its
location and bindings (a published binding is append-only, and a retired
key stays resolvable for the retention window past its last record), the
settlement verifier still verifies records of every retained version, and
the claim domain keeps each claim under the scope it was made in.

## Bounds

- **Gate refusals.** A token refused at token validation (a 401 at the
  HTTP gate, `invalid_credential` on the mediated channel) emits no Refusal
  Record. That gap predates this change and is outside its claims: the
  no-boundary exception covers only a request whose boundary cannot be
  established, never an ordinary token-validation failure at an
  established boundary. A credential the PEP refuses because its validated
  boundary or version is no longer in force is recorded
  (`credential_boundary_changed`).
- **One process.** "Together" means one declaration and one clock; a
  multi-process deployment relies on synchronized clocks at `effective_at`.

The stack registers the payments operation target with the remote PDP
apart from the boundary (`operationTargets`), so a change of boundary
identifier leaves the target in scope. `composeStack` takes the statement
as an option, and one value feeds the boundary context, the claim domain,
the reconciler and the published statement.

Witnesses: `services/pdp/test/enforcement-boundary.test.ts`,
`services/pdp/test/boundary-history-template.test.ts`,
`services/pdp/test/idempotency-claim.test.ts` (a claim's statement
version), `services/mcp-payments/test/decision-evidence-retention.test.ts`
(the retained row's version),
`services/mcp-payments/test/boundary-identifier.test.ts` (the payments
server, PEP, PDP with its claim domain, evidence store, a published key
set and settlement), and `demo/test/boundary-cutover-stack.test.ts` (the
same change through `composeStack`, co-resident and over a remote hop).
Not witnessed: the late reconciliation record's `audience`
(`claim-reconciliation.ts`) and the PDP's Refusal Record scope function
after a change.
