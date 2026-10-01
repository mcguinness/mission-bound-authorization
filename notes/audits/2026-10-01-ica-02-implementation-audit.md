# ICA -00 -> -02 implementation audit

Scope: `draft-mcguinness-oauth-id-continuation-assertion` pin row (src/SPEC_VERSIONS.md:84), branch
`continuation/ica-02-published` at 39c186ad (2026-10-01). Read-only audit; no tests executed. Spec
texts: draft-mcguinness-oauth-id-continuation-assertion-00, -01 and -02 from the IETF archive.
Follow-up tracking: #907.
Paths below are relative to `src/`. AS = `services/authorization-server/src`.

Role map in this code: the AS plays the **IdP** (continuation exchange, hop store, onward ID-JAG).
No component plays the **CAI**: no source file mints an ICA (only tests do, with an injected
"chain-authority.example" key). `services/ras` is the only RAS. The chain roots at Mission approval
(`AS/index.ts:460-497`), not at a Token Exchange root exchange (Mission-layer profile).

Legend: CONFORMS-02 | GAP-new (-02 changed the requirement) | GAP-persist (required by -00 and -02,
never met) | OPT (-02 OPTIONAL/MAY, omitted) | N/A (role/surface not implemented) | ADVISORY (SHOULD
or judgment, not a MUST break).

## 1. Delta classification

| # | -02 delta / requirement | Code | Class |
|---|---|---|---|
| 1 | CAI rename (Chain Authority -> Continuation Assertion Issuer) | identifiers `chainAuthorityIssuers`, comments (see section 3) | rename only |
| 2 | CAI role split: CAI attests acceptance/eligibility/association; IdP authorizes (5.4, 5.2.1) | No CAI exists; IdP authorizes via Mission gate + audience-scoped authority | N/A (CAI); IdP side CONFORMS-02 |
| 3 | Assertion issuance via Token Exchange at CAI, access token or Transaction Token subject, DPoP, `token_type` N_A, no refresh_token (5.4.1-5.4.5) | not implemented | OPT (MAY; SHOULD only for a RAS acting as its own CAI) |
| 4 | `identity_continuation_authorization_server` response parameter (5.4.4, 11.2) | not implemented | N/A (CAI response only) |
| 5 | Client validates IdP metadata issuer before sending the assertion (5.4.4) | no workload client code | N/A |
| 6 | Separate CAI, Transaction Token carrier, introspection-sourced evidence (5.3, 5.4.6) | none | N/A |
| 7 | Token type / media type / `typ` (3.1) | `AS/kernel/continuation-assertion.ts:22-24,129-147` | CONFORMS-02 |
| 8 | Asymmetric alg allowlist, no jku/x5u/jwk key source, kid select (5.5.3 rule 2, 9.7) | `continuation-assertion.ts:29,128-134` (local JWKS) | CONFORMS-02 |
| 9 | JWS compact only, no JWE / nested (3.1) | jose `jwtVerify` | CONFORMS-02 |
| 10 | `aud` a single string equal to IdP issuer (3.2, rule 2) | `continuation-assertion.ts:129-134`: jose accepts an `aud` array containing the issuer | GAP-persist (S) |
| 11 | Forbidden top-level claims, `act` schema and forbidden `act` members (3.2) | `continuation-assertion.ts:35-49,192-217` | CONFORMS-02 |
| 12 | `cnf` exactly one method `jkt` (3.2) | `continuation-assertion.ts:162-169` | CONFORMS-02 |
| 13 | Lifetime: -00 MUST <=300 -> -02 CAI SHOULD <=300, IdP rejects above its max (3.2, rule 6) | max fixed 300, `continuation-assertion.ts:27,149-160`, maps to `invalid_request` | CONFORMS-02 |
| 14 | `nbf` now permitted (3.2) | not forbidden; jose enforces `nbf` | CONFORMS-02 |
| 15 | `jti` entropy relaxed to SHOULD (3.2) | no entropy check | CONFORMS-02 |
| 16 | `iat` within future clock skew (rule 6) | jose checks future `iat` only with `maxTokenAge`; none passed (`continuation-assertion.ts:129-134`) | GAP-persist (S) |
| 17 | Handle rules (4): 128-bit, base64url, SHOULD NOT exceed 256 (min length dropped) | `continuation-store.ts:174` mints `ich_`+18 random bytes (28 chars); validator still enforces 22-256 (`continuation-assertion.ts:178-190`), harmless because the IdP only resolves its own handles | CONFORMS-02 (comment refresh) |
| 18 | Handle may appear in a RAS access token / carrier; keep out of logs, traces, responses (5.3, 4) | RS records `continuation_handle` into execution evidence if a token carries it (`services/mcp-payments/src/pep.ts:1508-1516`, `server.ts:1211-1219`); latent (no shipped token carries the handle) | ADVISORY |
| 19 | `actor_token` removed; request carrying `actor_token`/`actor_token_type` MUST be rejected `invalid_request` (5.5.1, rule 1, 5.5.6) | `AS/adapters/continuation-grant.ts:332-369` REQUIRES `actor_token` and runs a four-signal check | **GAP-new (M with tests)** |
| 20 | Canonical actor from client authentication; default `(IdP issuer, client_id)`; derived from registration, never self-asserted (5.5.2) | `continuation-grant.ts:262-263` | CONFORMS-02 |
| 21 | `act` != canonical actor -> `invalid_request` (5.5.6) | `continuation-grant.ts:370-373` returns `invalid_grant` | **GAP-new (S)** |
| 22 | DPoP proof of `cnf` key; onward ID-JAG bound to that key (5.5.2) | `continuation-grant.ts:265-290,415`; validator `:170-176` | CONFORMS-02 (code ambiguity, row 39) |
| 23 | Chain authorization replaces -01 root envelope: recorded root facts + restrictions, fixed for chain life; current policy may only restrict (5.1.4) | Mission record = chain authorization (immutable Authority Set, subject, client); anchor holds auth context (`continuation-store.ts:36-46`); continuation gated by `issueCrossDomainGrant` effective set | CONFORMS-02 (Mission layer) |
| 24 | Root exchange via Token Exchange, root actor = authenticated client (5.1.1, 5.1.3) | root at Mission approval, root actor = Mission `client_id` (`AS/index.ts:492-496`) | N/A (Mission rooting); root actor CONFORMS-02 |
| 25 | Root exchange PoP removed (5.1.3) | root binds no `cnf` (`index.ts:476-480`, `continuation-store.ts:162-171`) | CONFORMS-02 (resolves a -00 deviation) |
| 26 | Root ID-JAG carries the root handle (5.1.2) | no root ID-JAG; initial handle reachable only via `handlesForMission` (tests) | profile divergence, noted (see G-notes) |
| 27 | IdP MUST record the RAS audience of every hop, root or child (5.1.2) | `continuation-store.ts:47-57,158-192`: no audience column; `continuation-grant.ts:386-392` does not pass `audience` | **GAP-persist (M, with row 28)** |
| 28 | Issuer trust: `iss` is the hop's accepting RAS or an issuer trusted for that RAS's hops; CAI trust scoped by issuer, keys, tenant, RAS (5.5.3 rule 3, 7.3) | `ContinuationIssuer` = `{iss, jwks}` only (`continuation-assertion.ts:61-64`); any trusted issuer attests any hop; default trusts the AS issuer with all four AS keys (`AS/index.ts:974-976`) | **GAP-persist (M)** |
| 29 | Issuer pairing with actor identity authority, tenant scope (5.5.3 rule 3, 9.4) | single tenant; actor authority always the AS issuer | CONFORMS-02 trivially (multi-tenant N/A) |
| 30 | Chain state: hop issued, chain active, hop/ancestors unrevoked (rule 4) | `store.resolve` (`continuation-store.ts:198-233`); revocation is whole-chain only, so ancestor check holds by construction | CONFORMS-02 |
| 31 | Subtree revocation MAY (6.2) | none | OPT |
| 32 | Unknown handle -> `invalid_request`; `invalid_continuation` only for permanently unusable hops (5.5.6) | `continuation-grant.ts:320-323` returns `invalid_continuation` for unknown AND terminal (`resolve` conflates them) | **GAP-new (S)** |
| 33 | Gate refusal mapping (5.5.6): suspended (reversible) Mission must not be `invalid_continuation`; limits are `invalid_grant` | `continuation-grant.ts:425-427` maps every `GateError` (incl. `mission_not_active` suspend, `derivation_cap_exhausted`, `authority_contained`) to `invalid_continuation`; test (b0) proves a suspended chain later succeeds with the same handle, contradicting "ended chain stays ended" | **GAP-new (S)** |
| 34 | Error precedence: earliest failing rule; params + well-formedness first; no chain-state code before issuer trust, client auth and key proof (5.5.6) | `continuation-grant.ts:216-218` `invalid_scope` first; `:266-290` DPoP before assertion well-formedness; `:320-330` `invalid_continuation`/`invalid_target` before act match at `:370` | **GAP-new (M)** |
| 35 | Finite hop-count limit on every chain, tenant value or IdP default (6.3 MUST) | no hop counter; Mission `derivation_limit` is `null` by default (`config/policy.json` has no `derivation_limit_ceiling`; `kernel.ts:2180-2186` `derivation_limit IS NULL` = unbounded) | **GAP-new (S)** |
| 36 | Fan-out and rate limits optional; actor-lineage depth bound is tenant policy (6.3) | none | OPT |
| 37 | Request params: zero or more `resource` (order-independent), at most one `scope`/`authorization_details` (rule 1) | `continuation-grant.ts:228,235-237` require exactly one string `resource`; `:327` checks one; oidc-provider rejects repeated params not listed as allowed duplicates (`provider.ts:1449-1487` passes no duplicates set; moderate confidence) | **GAP-new (S-M)** |
| 38 | Requested `authorization_details` evaluated; unimplemented type rejected; issued ID-JAG expresses granted authority (rule 7) | handler never reads `params.authorization_details`; issues full audience-scoped set (`kernel/cross-domain.ts:126-131,156`) | GAP-persist (M) |
| 39 | DPoP proof key != `cnf.jkt` code | validator returns `invalid_request` (`continuation-assertion.ts:171-176`); -02 lists `invalid_dpop_proof` for "a DPoP failure" | ADVISORY / ambiguous (S-entry candidate) |
| 40 | `scope`: evaluated by authorization rule; refusal is `invalid_scope` | refuses every scope (`continuation-grant.ts:216-218`), Mission scope-projection restriction | CONFORMS-02 as policy (precedence issue in row 34) |
| 41 | Subject and target client identity resolution, else `invalid_target` (rule 5, 5.5.5) | deterministic `subjectResolver`; `client_id` = IdP client_id (identity mapping) | CONFORMS-02 |
| 42 | Replay reservation keyed on `(iss, jti)`, atomic first-writer, retained through `exp`+skew, failed validation creates none (5.5.7) | `seen` early check + `recordOnce` after mint (`continuation-grant.ts:303-308,446-449`); in-memory Set, never evicts in-process | CONFORMS-02 with deviation note: reservation follows minting (two grants can be minted under concurrency; one returned) |
| 43 | Reserved assertion that is not recovery -> `invalid_request` (5.5.6) | concurrent loser returns `invalid_grant` (`continuation-grant.ts:446-448`); early path returns `invalid_request` | **GAP-new (S)** |
| 44 | Idempotent retry: -00 REQUIRED -> -02 MAY (5.5.7.1) | not implemented | OPT (resolves a -00 gap) |
| 45 | Successful response: ID-JAG in `access_token`, `token_type` N_A, no refresh_token, child hop recorded before return (5.5.4) | `continuation-grant.ts:386-392,451-462` | CONFORMS-02 (child hop is minted before issuance and left orphaned on gate/target failure, see G5 note) |
| 46 | Onward ID-JAG: audience-local `sub`, root `auth_time`/`acr`/`amr` copied unchanged (5.5.5) | `continuation-grant.ts:383-407`, `cross-domain.ts:158,169-174` | CONFORMS-02 |
| 47 | Onward `act` built from the hop's ancestry (root client origin), never copied from the assertion (5.5.5) | `continuation-grant.ts:393-400`: `extendChainCollapsing(currentActor, ica.act)`; ancestry (`prior_handle`, per-hop actor) is stored but never walked; actor B continuing A's hop yields `{B}` | **GAP-persist (M)** |
| 48 | Onward ID-JAG redeemed via `urn:ietf:params:oauth:grant-type:jwt-dpop` with a DPoP proof (5.5.5) | RAS `redeem(idJag, presenterJkt)` takes a caller-supplied thumbprint, advertises only `jwt-bearer` (`ras/src/index.ts:150,380`) | **GAP-new (M), or S if row 50 is fixed by de-advertising** |
| 49 | Continuation-aware RAS binds handle + issuer + tenant + key + eligibility, atomically with token issuance; one binding per ID-JAG (5.2) | no binding; minted local token omits the handle (`ras/src/index.ts:355-365`); comment `:381-383` claims claims are "preserved" | **GAP-persist (L to implement, S to de-advertise)** |
| 50 | RAS advertising `id-jag-continuation` MUST also advertise base profile, `jwt-bearer`, and `jwt-dpop` (7.2) | `ras/src/index.ts:377-390` lacks `jwt-dpop` | **GAP-new (S)** |
| 51 | RAS issues DPoP-bound access token when the ID-JAG has `cnf` (5.2 item 3) | local token `cnf.jkt` = presenter (`ras/src/index.ts:358`); no wire `token_type` (in-process) | CONFORMS-02 in substance |
| 52 | IdP metadata `identity_continuation_supported`; IdP setting it also lists `id-jag` in `identity_chaining_requested_token_types_supported` (7.1) | flag at `provider.ts:3197`; chaining member absent | flag CONFORMS-02; chaining member GAP-new (S, lowercase "also lists") |
| 53 | Removal of RAS `identity_continuation_issuers` (-01 only) | never implemented | N/A (nothing to remove) |
| 54 | Introspection response member `identity_continuation_handle` (11.6) | AS introspection never emits it | OPT / N/A (no separate CAI) |
| 55 | Anchors: session or grant; grant anchors OPTIONAL; no rooting from access token (6.1) | grant anchor per Mission; `rootSessionAnchor`/`terminateSession` exist but are never called from src | CONFORMS-02 |
| 56 | Ending a chain: anchor end, policy withdrawal, admin whole-chain revocation, reject on ended chain (6.2) | `onLifecycleCommit` terminal fan-out (`continuation-store.ts:255-263`, wired `index.ts:892`); Mission expiry refused at the gate | CONFORMS-02 (except the code mapping in row 33) |
| 57 | Authentication context never strengthened (5.5.5, 9.2) | root `auth_time` = approval timestamp (`index.ts:488-490`), may read fresher than the user's actual authentication; documented demo choice | ADVISORY (pre-existing) |
| 58 | Actor permission: `unauthorized_client` when chain authorization or policy disallows this actor (5.5.6) | no actor restriction recorded or checked; any authenticated client with a trusted ICA naming itself can continue | CONFORMS-02 (empty restriction set), ADVISORY: Mission delegation policy could feed it |
| 59 | DPoP proof hygiene at the token endpoint (RFC 9449) | no `iat` window on the proof (`continuation-grant.ts:278`), jti cache only | ADVISORY (outside ICA) |

## 2. Gaps (detail)

### GAP-new (-02 changed the requirement)

| ID | -02 section and quote | Location | Change | Size | Tests affected |
|---|---|---|---|---|---|
| G1 | 5.5.1: "The request carries no actor_token or actor_token_type ... the IdP rejects a request carrying either"; 5.5.3 rule 1: "no actor_token or actor_token_type" | `AS/adapters/continuation-grant.ts:332-369` (and the four-signal framing at `:8-11,258-265,352-356`) | Delete actor_token parse/verify and the two actor_token agreement checks; add a rule-1 rejection (`invalid_request`) when either parameter is present. Keep `actor_token` in the shared param set (`provider.ts:1455-1456`), since the expansion/child exchanges read it. | S source, M with tests | `continuation-grant.test.ts`: helper `tokenExchange` always sends `actor_token_type` (`:221`) and most cases pass `mintActorToken()`; case (c) `:490-500` loses its premise (rewrite as "actor_token present -> invalid_request" plus "ICA act != client -> invalid_request"); header `:7-14` |
| G2 | 5.5.6: "an act that does not equal the authenticated client's canonical actor identity" is `invalid_request` | `continuation-grant.ts:370-373` | `invalid_grant` -> `invalid_request` | S | new case for act mismatch |
| G3 | 5.5.6: "a missing hop is invalid_request ... The IdP MUST NOT return invalid_continuation in any other case" | `continuation-grant.ts:320-323`; `AS/kernel/continuation-store.ts:198-210` | Store returns a tri-state (unknown / terminal / active); unknown -> `invalid_request`, terminal -> `invalid_continuation` | S | `continuation-grant.test.ts` (e) `:514-524` flips to `invalid_request`; (g) unchanged; `continuation-store.test.ts` `:64-66` |
| G4 | 5.5.6: `invalid_continuation` only for "its chain has expired or ended, the hop or an ancestor is revoked, or the tenant has withdrawn the chain's permission"; `invalid_grant` for "fan-out, hop-count, or rate limits"; 6.2: "an ended chain stays ended" | `continuation-grant.ts:422-436` | Map `GateError.reason`: `mission_expired` (and terminal) -> `invalid_continuation`; `derivation_cap_exhausted` -> `invalid_grant`; `mission_not_active` (suspended, reversible) -> not `invalid_continuation` (recommend `unauthorized_client`, see S-entry candidate); `authority_contained`/`authority_exhausted`: OWNER DECISION. `kernel.ts:221-226` says both "refuse `invalid_grant` at the wire" (the family Containment convention), while -02 5.5.6 reserves `invalid_grant` for limits; `invalid_target` ("audience ... not permitted by ... current policy") is the -02 fit, keeping `invalid_grant` keeps the family convention | S | (b0) `:447-475` expects `invalid_continuation` for suspend; flip the code expectation, keep the unconsumed-retry assertion |
| G5 | 6.3: "The IdP MUST enforce a finite hop-count limit on every chain, either the tenant's configured value or the IdP's default" | `continuation-store.ts` (no counter); `continuation-grant.ts:386`; shipped `config/policy.json` has no `derivation_limit_ceiling`, so the Mission derivation cap is unbounded by default | Count hops per anchor (or per Mission, which -02 permits as the shared chain-authorization budget); refuse over a configured default with `invalid_grant`; move `store.mint` after the gate or delete the hop on failure, so failed attempts (orphan hops today) do not spend the budget | S (~25 lines) | new test in `continuation-grant.test.ts`; `continuation-store.test.ts` count test |
| G6 | 5.5.6 precedence: "Request-parameter and well-formedness failures (including signature verification) come first. No chain-state code is returned before issuer trust for the hop's RAS is established, nor before the client authentication and key proof of the current-actor rule succeed" | `continuation-grant.ts:216-218` (scope first), `:266-290` (DPoP before assertion), `:320-330` (chain state and target before act match at `:370`); `continuation-assertion.ts:149-176` mixes rule 2, 5 and 6 checks | Reorder: rule 1 params (scope deferred to rule 7), rule 2 well-formedness, rule 3 issuer trust, then DPoP + cnf + act (rule 5 gate), then chain state (rule 4: terminal -> `invalid_continuation`, limits -> `invalid_grant`), freshness, then target/scope/authorization_details. Split the validator into well-formedness and freshness phases. | M (~60-90 lines) | new precedence cases (malformed ICA + missing DPoP -> `invalid_request`; wrong actor + terminal hop -> `invalid_request`; scope + malformed ICA -> `invalid_request`) |
| G7 | 5.5.3 rule 1: "zero or more resource, treated as an order-independent set" | `continuation-grant.ts:228,235-237,327`; `provider.ts:1449-1487` (no allowed-duplicates set) | Accept absent or repeated `resource`; every value must be served by `audience`; register `resource` as an allowed duplicate for the grant | S-M | new cases: no resource; two resources; one unserved |
| G8 | 5.5.6: `invalid_request` for "a reserved assertion that cannot be processed as idempotent recovery" | `continuation-grant.ts:446-448` | Concurrent loser `invalid_grant` -> `invalid_request` | S | none existing (add a concurrency case if cheap) |
| G9 | 7.2: "It MUST also advertise urn:ietf:params:oauth:grant-type:jwt-dpop"; 5.5.5: "the actor redeems it with the DPoP-bound JWT grant, urn:ietf:params:oauth:grant-type:jwt-dpop ... and a DPoP proof of the bound key" | `services/ras/src/index.ts:150,377-390`; callers `demo/src/exhibit.ts:1628,1672` | Either stop advertising `id-jag-continuation` (S, then 7.2 no longer applies and G-P6 closes too), or accept a `jwt-dpop` redemption that verifies a DPoP proof rather than taking a thumbprint and advertise it (M) | S or M | `continuation-grant.test.ts:402-432` asserts the profile; `ras/test/mapping-entitlement.test.ts` continuation cases `:556-590` |
| G10 | 7.1: "an IdP that sets this flag also lists that type in identity_chaining_requested_token_types_supported" | `AS/adapters/provider.ts:3194-3197` | Add `identity_chaining_requested_token_types_supported: [id-jag]` when continuation is on (lowercase "also lists": soft) | S | `continuation-grant.test.ts:402-410`; `demo/test/issuance-only-capabilities.test.ts:475,562` (capability-gated member lists) |

### GAP-persist (required by -00 and -02; not a delta, but blocks an honest -02 claim)

| ID | -02 section and quote | Location | Change | Size | Tests |
|---|---|---|---|---|---|
| P1 | 5.1.2: "For every hop it creates, root or child, the IdP MUST record the RAS audience placed in the ID-JAG"; 5.5.3 rule 3: "the assertion iss is either the accepting RAS itself ... or another issuer the IdP trusts to attest that RAS's hops"; 7.3: "MUST scope CAI trust by issuer, keys, tenant, and the RAS it attests for" | `continuation-store.ts:47-57,158-192`; `continuation-assertion.ts:61-64`; `AS/index.ts:970-976`; `continuation-grant.ts:386-392` | Add `audience` to the handle row (root = the AS/Mission audience, child = requested `audience`); give `ContinuationIssuer` a per-RAS scope; check the ICA `iss` against the hop's audience; narrow the default from "all AS keys" to a CAI-purpose key | M (~60-80) | `continuation-grant.test.ts` setup `:263`; new "CAI not trusted for this hop's RAS -> invalid_request" |
| P2 | 5.5.5: "it never copies lineage from the assertion ... The IdP MUST derive lineage from that hop's ancestry to the root" | `continuation-grant.ts:393-400`; `continuation-store.ts` (no ancestry walk) | Walk `prior_handle` to the root, collect per-hop actors (root = Mission client), merge consecutive equal `(iss, sub)`, place the current actor on top | M (~40-60) | happy path `:321-324` still passes for the single actor; add a two-actor case expecting nested `act` |
| P3 | 5.5.3 rule 7: "This evaluation includes the audience, resources, scopes, and authorization details ... rejects a type whose authorization semantics it does not implement" | `continuation-grant.ts` (never reads `authorization_details`); `cross-domain.ts:126-131,156` | Parse and project requested `authorization_details` through the Mission effective set (the async path already does this at `continuation-grant.ts:678-705`); `invalid_authorization_details` on excess or unknown type | M | new cases |
| P4 | 5.5.3 rule 6: "iat is within the IdP's permitted clock skew" | `continuation-assertion.ts:129-134` | Pass `maxTokenAge` (max lifetime + skew) and one `clockTolerance` (<=60 s) used for `iat`, `exp`, `nbf` | S | `continuation-assertion.test.ts` future-iat case |
| P5 | 3.2: "aud: REQUIRED. A single string exactly matching the IdP issuer identifier" | `continuation-assertion.ts:129-136` | Reject non-string `aud` | S | `continuation-assertion.test.ts` array-aud case |
| P6 | 5.2: a continuation-aware RAS "advertises the continuation grant profile" and MUST "bind identity_continuation_handle, the ID-JAG's issuer, the tenant ..., and any confirmed key to the authorization state it establishes" as one outcome with the token | `services/ras/src/index.ts:250-261,355-365,381-387` | Same decision as G9: de-advertise (S) or implement binding + eligibility record + one binding per ID-JAG (L, and useful only with a CAI) | S or L | as G9 |

### Notes that are not gaps

- Root hop (row 26): the chain roots at Mission approval and no root ID-JAG carries H0 (5.1.2 "the IdP MUST include the root handle in the ID-JAG"). Under the Mission profile the root is the Mission grant anchor, so this is a profile divergence; the legacy `issueCrossDomainGrant` path (exhibit step 9) could carry the initial handle (S) if a root ID-JAG is wanted.
- Reservation timing (row 42): -02 says reserve "once validation succeeds and before it issues the grant". The code consumes after minting (the #617 ruling, so a gate refusal leaves the ICA unspent). Only one grant is returned, so at-most-one holds; the deviation is that a concurrent loser mints a discarded grant, a counted derivation and an orphan hop.
- Orphan hops: `store.mint` (`continuation-grant.ts:386`) runs before `issueCrossDomainGrant`; a gate or target failure leaves an active, undelivered child hop. Harmless today; it matters once G5 counts hops.

### -02 moved toward the code (resolved -00 deviations)

- Idempotent retry: -00 8.8 required "An identical retry MUST return the same previously issued grant"; -02 5.5.7.1 makes it MAY. The code never had it, so it now conforms.
- Root proof-of-possession: -00 8.2 required DPoP at the root and `cnf` on the root ID-JAG; -02 5.1.3 removes it. The approval-time root binds no key (`continuation-store.ts:162-171` comment becomes moot).
- Lifetime, `jti` entropy, handle min length: -02 relaxes to SHOULD; the code's stricter checks remain valid.
- Hop states PENDING/ACCEPTED/CONTINUABLE removed: the code only ever had active/terminal.
- Handle in an access token: -00 rule 4 forbade it; -02 permits it (5.3), so the RS evidence path (row 18) is no longer a MUST break, only a SHOULD concern.

## 3. "Chain Authority" and "-00" references

| File:line | Text | Class |
|---|---|---|
| `AS/kernel/continuation-assertion.ts:2` | `@spec ...-00` | tied (validator changes: P4, P5, G6 split) |
| `AS/kernel/continuation-assertion.ts:5` | "minted by a Chain Authority" | rename |
| `AS/kernel/continuation-assertion.ts:60` | "A trusted Chain Authority issuer of ICAs" | tied (P1 adds per-RAS scope to `ContinuationIssuer`) |
| `AS/kernel/continuation-store.ts:2` | `@spec ...-00` | tied (G3, G5, P1, P2) |
| `AS/kernel/continuation-store.ts:12` | "A Chain Authority mints a handle for each intra-domain hop" | rename and factually wrong under both revisions (the IdP mints handles) |
| `AS/kernel/continuation-store.ts:162-170` | root has no DPoP key; "four-signal check" | tied (G1 removes four-signal; root PoP removal makes the caveat moot) |
| `AS/kernel/delegation-family-store.ts:2` | `@spec ...-00` on the async-delegation family store | mis-tag (should cite async-delegation); rename only |
| `AS/adapters/continuation-grant.ts:2,8-11` | `@spec ...-00`; "FOUR-SIGNAL actor agreement ... actor_token" | tied (G1) |
| `AS/adapters/continuation-grant.ts:120` | "four-signal invalid_grant returns" | tied (G1, G2) |
| `AS/adapters/continuation-grant.ts:242` | `opts.chainAuthorityIssuers` | rename (identifier) |
| `AS/adapters/continuation-grant.ts:258-265,332-373,393-396` | Signal #1/#2/#4, "Chain Authority MUST mint", four-signal | tied (G1, G2, P2) |
| `AS/adapters/provider.ts:444-445` | `chainAuthorityIssuers` + "Trusted Chain Authority issuers" | rename (tied if P1 changes the type) |
| `AS/adapters/provider.ts:3194` | `@spec id-continuation-assertion#discovery` (no such anchor in -02; 7.1) | rename; tied if G10 lands |
| `AS/index.ts:478-480` | "four-signal contract" | tied (G1) |
| `AS/index.ts:630-634` | "trusted Chain Authority issuers ... own Chain Authority"; option `chainAuthorityIssuers` | rename (public build option; tied if P1 changes the shape) |
| `AS/index.ts:970-976,1056` | "OWN Chain Authority"; `chainAuthorityIssuers` | tied (P1: the default trusts all four AS keys) |
| `test/continuation-grant.test.ts:2,7-14,24,53,77,166,185,263,323` | `-00` tag, Chain Authority, four signals, Signal #2 | tied (G1) |
| `test/continuation-assertion.test.ts:3,19` | `-00` tag; `chain-authority.example` | rename |
| `test/continuation-store.test.ts:3` | `-00` tag | rename |
| `test/cross-domain-continuation.test.ts:2,32` | `-00` tag; `chain-authority.example` | rename |
| `SPEC_VERSIONS.md:84` | pin `-00`; "four-signal actor agreement"; "sender-constrained assertion (`exp-iat` <= 300)" | tied (row text must drop four-signal and describe the -02 surfaces) |
| `services/ras/src/index.ts:381-383` | "continuation claims preserved into the local token" | false today (no handle is carried); tied to G9/P6 |

## 4. Spec Feedback Log (src/PLAN.md section 8)

No S-entry concerns the ICA draft (S-1..S-15; none mention id-continuation, the continuation assertion, Chain Authority or the handle). The adjacent entries are base ID-JAG:

- S-12 (accepted; ID-JAG `client_id` vs the redeeming client): -02 5.5.5 says the onward `client_id` "may differ from its client identifier at the IdP", which fits the RAS's own-registration approach; -02 does not resolve or change S-12.
- S-13 (accepted; one-time `jti` at the RAS): -02 5.2 requires all redemptions of one ID-JAG to resolve to one binding, which one-time use satisfies as a subset; not resolved, not contradicted.

D51 (`PLAN.md:136`) records "full draft conformance (scheduled-continuation rooting, disclosed-depth)" as deferred; -02 makes scheduled continuation CAI-side and disclosed depth policy, so neither item now blocks the IdP slice.

S-entry candidates from this audit (spec friction, not code):
1. -02 has no code for a temporarily non-continuable chain (suspended chain authorization): `invalid_continuation` is permanent-only, and `unauthorized_client` is phrased per actor.
2. DPoP proof valid but for a key other than `cnf.jkt`: `invalid_dpop_proof` ("a DPoP failure") vs `invalid_request` is not pinned.
3. Strict earliest-failure order puts chain state (rule 4) before freshness (rule 6), so an expired assertion on an ended chain returns `invalid_continuation`; confirm that is intended.

## 5. Verdict

The pin cannot honestly move to -02 with comment changes. G1 is a behavioral inversion: the code requires a parameter that -02 requires the IdP to reject, so every -02-conformant continuation request fails today. G3/G4/G2/G8 return codes -02 now forbids, G5 is a new finite MUST that the shipped default does not meet, G6 is a new precedence MUST, and the RAS advertises a profile it does not implement while missing the -02 `jwt-dpop` advertisement.

Estimate:
- Pin-blocking -02 deltas (G1-G10, RAS by de-advertising): about 150-250 source lines in `continuation-grant.ts`, `continuation-assertion.ts`, `continuation-store.ts`, `provider.ts`, `ras/src/index.ts`; about 150-200 test lines across `continuation-grant.test.ts` (helper plus about 8 updated and 6 new cases), `continuation-assertion.test.ts`, `continuation-store.test.ts`, and `demo/test/issuance-only-capabilities.test.ts` if G10 lands.
- Adding the persisting MUSTs (P1-P5) brings it to about 300-450 source lines and about 300 test lines across the same files plus `AS/index.ts`; full RAS binding plus `jwt-dpop` redemption (P6/G9 the long way) adds an L item touching `exhibit.ts` and `ras/test/mapping-entitlement.test.ts`.
- Suggested split: PR1 = G1-G8 and G10 (IdP wire behavior, S/M); PR2 = P1-P5 (hop audience, issuer scoping, lineage walk, authorization_details, iat/aud); PR3 or a disclosed limitation in the row = RAS binding and `jwt-dpop`.

Uncertainties: oidc-provider's rejection of repeated `resource` for this custom grant is inferred from its `registerGrantType` duplicate handling, not run; the `jose` behavior (array `aud`, future `iat`) was read from jose 6.2.3 source in the main checkout's `node_modules`; no tests were executed.
