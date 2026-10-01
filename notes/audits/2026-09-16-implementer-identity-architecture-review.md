# Implementer and identity-architect review — 2026-09-16

Reviewed commit: `85a5ed2d2dea8ec89f80db1bc04142ba1965d201`.

This is a second, complementary review of the architecture and reference implementation. The [earlier architecture critique](2026-09-16-end-to-end-architecture-critique.md) and [GitHub tracker #824](https://github.com/mcguinness/mission-bound-authorization/issues/824) remain the broader architectural assessment. This pass asks whether an identity team can implement the design correctly, integrate it with an existing estate, operate it through identity changes, and substantiate the resulting claims.

**GitHub tracking**

[Ranked review tracker #833](https://github.com/mcguinness/mission-bound-authorization/issues/833). Eight new issues and three detailed comments on existing issues:

| Rank | Priority | Issue or review comment |
|---|---|---|
| 1 | P1 | [#825 ](https://github.com/mcguinness/mission-bound-authorization/issues/825) |
| 2 | P1 | [#826 ](https://github.com/mcguinness/mission-bound-authorization/issues/826) |
| 3 | P1 | [#827 ](https://github.com/mcguinness/mission-bound-authorization/issues/827) |
| 4 | P1 | [#828 ](https://github.com/mcguinness/mission-bound-authorization/issues/828) |
| 5 | P1 | [#829 ](https://github.com/mcguinness/mission-bound-authorization/issues/829) |
| 6 | P1 | [#830 ](https://github.com/mcguinness/mission-bound-authorization/issues/830) |
| 7 | P2 | [#831 ](https://github.com/mcguinness/mission-bound-authorization/issues/831) |
| 8 | P2 | [#818 — added review detail ](https://github.com/mcguinness/mission-bound-authorization/issues/818#issuecomment-5708321775) |
| 9 | P2 | [#253 — added review detail ](https://github.com/mcguinness/mission-bound-authorization/issues/253#issuecomment-5708322418) |
| 10 | P2 | [#594 — added review detail ](https://github.com/mcguinness/mission-bound-authorization/issues/594#issuecomment-5708323005) |
| 11 | P3 | [#832 ](https://github.com/mcguinness/mission-bound-authorization/issues/832) |

**Assessment**

The conceptual identity model is stronger than the integration recipe. Separating Subject, Approver, client, instance, authority-rooting mode and current resource permission is the right design. Several reference boundaries collapse distinctions that the specifications carefully preserve. The highest-value work is to make those boundaries executable and testable, then demonstrate one small deployment through approval, token issuance, resource authorization, identity revocation, restart and key rotation.

This is not a finding that the entire system fails open. Several gates are explicitly fail closed, and important cross-domain freshness and mapping checks already exist. Nor does a validator-level probe establish successful unauthorized business execution. Each finding below distinguishes reproduced behavior, static implementation evidence and a deployment/design recommendation.

The first two findings concern ordinary identity/token semantics and should be fixed before external integration. The next four concern whose authority is being activated, preserved and withdrawn. The remaining findings improve operability, adoption and evidence. Priority P1 means resolve before relying on the affected path in an adopter pilot; P2 means required implementation/operational work for the corresponding supported deployment; P3 is a bounded correctness issue. These priorities are review judgments, not CVSS ratings.

**Ranked findings**

| Rank | Priority | Finding | Evidence class |
|---|---|---|---|
| 1 | P1 | RS: enforce token profile and credential-specific authority through the PEP | Demonstrated implementation bug |
| 2 | P1 | OIDC: separate approver authentication from the Mission authorization subject | Demonstrated integration bug and specification composition gap |
| 3 | P1 | Authority sources: resolve ceilings for the actual principal rather than one global entry per mode | Implementability and authority-model gap |
| 4 | P1 | PDP: demonstrate current resource policy independently of Mission-derived FGA tuples | Missing independent enforcement demonstration |
| 5 | P1 | Authority-source gates: preserve issuer qualification when authorizing principals | Demonstrated internal authorization-boundary bug |
| 6 | P1 | Identity lifecycle: define offboarding and entitlement-change behavior for each authority-rooting mode | Deployment policy and identity-lifecycle gap |
| 7 | P2 | Credential operations: provide durable signing identities, key rotation and verifier refresh | Operational implementation gap |
| 8 | P2 | MAS migration needs a real subject/client mapping and credential-authority adapter | Adoption and adapter gap |
| 9 | P2 | Define a narrow AS integration port before treating the reference provider as an implementation recipe | Implementation portability and simplification |
| 10 | P2 | Add identity-boundary contract tests that cross implementation modules | Conformance and independent validation gap |
| 11 | P3 | Principal mapping: co-resolution must not report freshness from only the newer required fact | Demonstrated metadata bug; no current issuance bypass established |

## 1. RS: enforce token profile and credential-specific authority through the PEP

**P1 — Demonstrated implementation bug.**

A valid Mission-bound token can carry less authority than its Mission. The normal resource path verifies the signature and DPoP, but missionBoundFactsFrom drops authorization_details. The PEP then loads the Mission's broader authority_set. The special offline-attenuation path has a leafAuthority guard; a normally issued narrowed JWT does not receive that protection.

A sixth probe used a correctly formed at+jwt with all required standard claims and authorization_details limited to payments:invoice.read. Its active Mission allowed invoice.read and vendor.read. After the real HTTP token-validator method produced facts, the real PEP/PDP path permitted lookup_vendor (payments:vendor.read). The FGA dependency was explicitly stubbed to allow so the test isolated the credential bound; no live policy service or business side effect was exercised. Resource policy allowing an action must not restore authority omitted from the token.

The HTTP resource verifier checks the signature, issuer, audience and DPoP binding, but rejects only the transaction-token type. It does not require the Mission access-token type or the full required claim set before casting claims into trusted TokenFacts. The in-process validator repeats the same pattern; the attenuation-root path also needs its own profile audit.

A probe called the real public validateToken method with a test-trusted ES256 key and a valid DPoP proof. A JWT labeled mission-status+jwt, carrying a Mission reference and cnf, but omitting exp, iat, jti, sub and client_id, was accepted. Returned subject, client and expiry were undefined. This proves an admission defect, not successful execution of an unauthorized payment: downstream gates may refuse, and the probe controlled a trusted signing key. No claim is made that an attacker can acquire that key.

The core explicitly requires RFC 9068 tokens and RS verification of typ. Introspection already has a substantially stricter required-claim check. The divergent boundaries make an otherwise good specification unsafe to copy into a new resource adapter.

**Recommendation.** Preserve the verified token's own authority as an independent enforcement bound and intersect it with the current Mission and Resource policy. Carry and enforce resource, actions and all applicable constraints; an action-only leaf guard is insufficient for narrowed amounts/vendors or other supported constraints. Reject missing or unsupported authority carriage as the selected token profile requires.

Use one explicit, profile-aware verifier contract across HTTP, mediated and root-token entry points. Require the appropriate type, required claims and their shapes, time validity, audience, issuer, authority carriage and sender binding before constructing facts. Keep legacy/ordinary-token validation separately configured; do not impose the Mission profile on every opaque or vendor token. Where per-purpose signing keys are claimed as a trust boundary, select trusted key roles explicitly: a shared JWKS and different kid strings alone do not enforce purpose.

**Completion criteria**

- With an unchanged broader Mission and allowing Resource policy, an ordinary issued token narrowed to invoice.read must deny vendor.read; a broader valid token must still permit it.
- Test issuer narrowing of resource, action, vendor and amount constraints, plus delegation/refresh-produced tokens; verified authorization_details must reach the enforcing decision without widening.
- Reject missing/wrong typ and each missing or malformed required claim independently, with valid signatures and valid DPoP proofs.
- Verify valid Mission access tokens still work over HTTP and the mediated path; document the latter's intentional possession limitation.
- Test access, status, transaction, ID-token and continuation classes against their intended validators and reject cross-class presentation.
- Keep expected algorithms and key-role configuration local to the verifier; test any claimed purpose separation.
- Prove rejection occurs before TokenFacts reach policy evaluation or side effects; align introspection and RS negative vectors.

**Validation.** Two probes used the actual exported HTTP token verifier. One accepted wrong-class/missing-claim data; the other passed a correctly formed narrowed JWT through the real PEP/PDP and received a permit outside the token's actions with an explicitly allowing FGA stub. No business effect or production signing-key compromise was exercised.

**Existing work.** Related to the strict introspection work in #541, but this finding is on resource-side validators. It is separate from #820's harness isolation work.

**Sources**

[src/services/mcp-payments/src/server.ts:60](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/server.ts#L60)

[src/services/mcp-payments/src/server.ts:275](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/server.ts#L275)

[src/services/mcp-payments/src/server.ts:425](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/server.ts#L425)

[src/services/authorization-server/src/adapters/provider.ts:2286](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/adapters/provider.ts#L2286)

[draft-mcguinness-oauth-mission.md:2892](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-oauth-mission.md#L2892)

[src/services/mcp-payments/src/server.ts:295](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/server.ts#L295)

[src/services/mcp-payments/src/pep.ts:707](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/pep.ts#L707)

[src/services/mcp-payments/src/pep.ts:780](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/pep.ts#L780)

RFC 9068 §§2 and 4 require the access-token profile and validation rules; RFC 8725 §3.12 recommends mutually exclusive rules for token classes. [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12).

## 2. OIDC: separate approver authentication from the Mission authorization subject

**P1 — Demonstrated integration bug and specification composition gap.**

The Mission model correctly permits Bob to approve authority exercised for Alice. The provider adapter then creates the OAuth grant with accountId=Alice and finishes the OIDC interaction with login.accountId=Alice. Its supported scopes include openid, profile and email.

An end-to-end probe used the trusted test approver Bob, a PAR request selecting Alice under the configured approve-for policy, PKCE, private_key_jwt and DPoP. The token response contained an ID token with sub=Alice, while the committed Mission recorded approver Bob and subject Alice. Alice was not authenticated in this flow. Delegated authorization for Alice does not establish that Alice logged in.

This also exposes a standards-composition decision: the core profiles acr_values/max_age as requests about the Approver, while ordinary OIDC requests describe authentication of the End-User represented by the ID token. A mixed openid request needs unambiguous behavior. Merely excluding approver claims from the access token does not resolve the ID-token/session issue.

**Recommendation.** Keep the authenticated account and approval provenance distinct from the authorization subject in the provider integration. Choose and document a supported OIDC composition. A pragmatic initial option is to reject unsupported mixed OIDC/delegated-approval requests and use a separate approver login session for an OAuth-only Mission authorization flow. If mixed OIDC is supported, its ID token and session must represent the actually authenticated end user, and subject selection must remain separately authorized. Do not simply change the Mission access-token sub to Bob.

**Completion criteria**

- Add real HTTP regression tests for Bob approving Alice, self-approval and an organizational workload subject, requesting openid and without it.
- Ensure ID tokens, UserInfo and provider sessions cannot silently assert authentication of an unauthenticated Mission subject.
- Specify whose acr/auth_time/max_age/prompt/claims requirements apply when approver and subject differ; reject combinations the implementation cannot honor.
- Preserve the intended authorization subject on Mission access tokens and the accountable approver on the Mission record.
- Test refresh/session reuse after delegated approval and ensure an Alice login session is not created merely because Bob may approve for Alice.

**Validation.** Reproduced through PAR → approval → authorization code → token response. The fixture authenticates Bob through the explicitly enabled test approval service; it does not authenticate Alice.

**Existing work.** This is not a request to undo the Approver/Subject distinction or the trusted approval boundary. Existing approval-authentication tests do not cover the end-to-end OIDC identity assertion.

**Sources**

[src/services/authorization-server/src/adapters/provider.ts:656](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/adapters/provider.ts#L656)

[src/services/authorization-server/src/adapters/provider.ts:3031](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/adapters/provider.ts#L3031)

[src/services/authorization-server/src/adapters/provider.ts:3143](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/adapters/provider.ts#L3143)

[draft-mcguinness-oauth-mission.md:1941](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-oauth-mission.md#L1941)

OIDC defines the ID token as claims about End-User authentication. The review's delegated-approval conclusion follows from comparing that contract with the reproduced result. [OpenID Connect Core §2](https://openid.net/specs/openid-connect-core-1_0.html#IDToken).

## 3. Authority sources: resolve ceilings for the actual principal rather than one global entry per mode

**P1 — Implementability and authority-model gap.**

The source taxonomy is useful, but the reference catalog identifies user_delegated and service_owned sources by mode alone. Validation rejects a second entry with the same mode, even for different clients and subjects. Establishment selects an entry only by client_id; source ceilings do not resolve against the actual user/workload whose authority is being activated.

A probe with two service-owned entries, separate clients and separate workload subjects failed with duplicate source identity. The same shape prevents different delegated users from carrying different source ceilings under a shared agent registration. Combining everyone into one larger ceiling removes the distinction the source gate should establish; provisioning a client per user does not solve the global mode collision.

The current uniform seeded estate can legitimately assign identical permissions to everyone in that fixture. That does not demonstrate the core promise for heterogeneous enterprise identities. This is a reference-adapter limitation, not evidence that the wire model requires a new source identifier.

**Recommendation.** Introduce a trusted source-resolution contract keyed by the relevant issuer-qualified subject, authenticated client and deployment/tenant context, plus organizational policy identity where applicable. Preserve the immutable provenance mode and existing separate activation/ceiling checks. Re-resolution for drawdown must use sufficient committed context to recover the same authority root. Keep principal-specific entitlements in IAM rather than copying a large IAM database into Mission records.

**Completion criteria**

- Support two user-delegated principals and two workload principals with different ceilings without merging permissions or creating a new wire discriminator.
- Demonstrate a shared registered agent acting for two subjects while each remains bounded by its own source authority.
- Keep activation authority separate from operational authority; a reviewer need not personally possess the workload's permissions.
- Test ambiguous/missing source resolution, wrong tenant, changed organizational policy and inherited drawdown.
- Retain fail-closed behavior and the #646 rule that a source-ceiling violation refuses rather than silently changing the approval derivation.

**Validation.** The duplicate-mode restriction was reproduced against validateAuthoritySourceCatalog. The client-only ceiling lookup is directly visible in the implementation.

**Existing work.** Follow-through on #316 and #646; those established the taxonomy and five gates. This issue makes their implementation usable for more than the uniform demo estate. Separate from #819's RAR subset and from execution-time Resource policy.

**Sources**

[src/services/authorization-server/src/kernel/authority-source.ts:57](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/authority-source.ts#L57)

[src/services/authorization-server/src/kernel/authority-source.ts:109](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/authority-source.ts#L109)

[src/services/authorization-server/src/kernel/authority-source.ts:122](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/authority-source.ts#L122)

[src/services/authorization-server/src/kernel/authority-source.ts:164](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/authority-source.ts#L164)

[src/services/authorization-server/src/kernel/kernel.ts:595](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/kernel.ts#L595)

## 4. PDP: demonstrate current resource policy independently of Mission-derived FGA tuples

**P1 — Missing independent enforcement demonstration.**

The runtime and MAS describe an intersection with current Resource policy. In the reference FGA model, invoice payer/reader are direct relations. deriveContextualTuples produces the exact Mission-to-target relation that evaluate then asks FGA to check. Supplying that contextual tuple can satisfy the direct relation without an independent owner, account-status, tenant-membership or resource-entitlement predicate. The repository defines seedDomain but has no caller demonstrating a durable policy substrate.

The existing authority, vendor, amount and approval checks remain useful. The narrower finding is that a successful FGA call does not by itself prove the independently administered Resource-policy bound. Stubbed allow/deny tests demonstrate handling of an FGA answer, not that the shipped model can revoke a domain permission while Mission authority remains unchanged.

This also adds an external service dependency without demonstrating the independent policy value that justifies it. MINIMIZE_LATENCY is the normal consistency mode; a deployment claiming prompt revocation needs an explicit freshness choice.

**Recommendation.** Implement one real conjunction of Mission authority and resource-owned entitlement, with a negative test that changes only the latter. Either use stored resource-policy relations intersected with Mission contextual relations, or use an existing resource authorization API. If the demo intentionally has no independent Resource policy, simplify the dependency and narrow its claim until the independent check exists. Do not create a second enterprise IAM system inside the Mission issuer.

**Completion criteria**

- With an unchanged active Mission and valid token, removing the local principal's resource entitlement or changing target ownership/tenant must deny.
- Demonstrate positive and negative checks against the actual model/service or a faithful model evaluator, not only alwaysAllow/denyAll mocks.
- Declare Resource-policy freshness separately from Mission-state freshness and test an external writer's revocation.
- Show where durable domain policy is provisioned and identify its owner; keep Mission contextual tuples ephemeral.
- Update FGA hygiene, MAS rule-8 claims and runtime assessment to match exactly what is implemented.

**Validation.** Static inspection of the shipped model, tuple derivation and check call; no live OpenFGA service was started for this review.

**Existing work.** Complements #210's resource adapter and #249's resource semantics contract. This issue concerns an independent authorization axis, not just translating tool names.

**Sources**

[src/services/pdp/src/fga.ts:24](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/pdp/src/fga.ts#L24)

[src/services/pdp/src/fga.ts:91](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/pdp/src/fga.ts#L91)

[src/services/pdp/src/fga.ts:145](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/pdp/src/fga.ts#L145)

[src/services/pdp/src/policy-view.ts:179](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/pdp/src/policy-view.ts#L179)

[src/services/pdp/src/evaluate.ts:880](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/pdp/src/evaluate.ts#L880)

[src/docs/fga-hygiene.md:1](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/docs/fga-hygiene.md#L1)

OpenFGA distinguishes latency-oriented and higher-consistency checks; the latter bypasses cache. A consistency mode alone does not add a missing policy predicate. [OpenFGA consistency documentation](https://openfga.dev/docs/interacting/consistency).

## 5. Authority-source gates: preserve issuer qualification when authorizing principals

**P1 — Demonstrated internal authorization-boundary bug.**

The kernel accepts issuer-qualified Subject and Approver tuples, but assertApproverMayActivate checks only approver.sub against bare activator strings. Subject-discipline checks similarly compare only subject.sub against human/workload lists.

A probe called MissionKernel.approve with an approver {iss: https://untrusted.example, sub: bob} against the local Bob activator fixture. Approval succeeded and persisted the foreign issuer-qualified approver. The public kernel contract thus accepts identity from one namespace using authorization granted in another.

The shipped HTTP adapter constructs principals using its configured local issuer, which limits reachability. This review does not establish an unauthenticated remote exploit against that adapter. The defect matters at the exported kernel/integration boundary: a future federation adapter naturally passes the full tuples the API advertises.

**Recommendation.** Either make the catalog issuer-qualified end to end, or explicitly restrict the kernel/catalog to one trusted local issuer and validate that invariant before any sub-only lookup. If federation mapping is required, perform an authenticated, injective mapping first and retain provenance separately. Never let a typed issuer field imply protection that the authorization check discards.

**Completion criteria**

- Reject an unauthorized issuer using the same sub as a permitted activator, before creating a record or approval artifact.
- Apply the same rule to workload recognition and human/workload subject discipline.
- Test byte-distinct issuer namespaces, tenant separation, legitimate mapped principals and self-approval.
- Document whether each adapter accepts external principal tuples or only canonical local principals; validate at that boundary.
- Keep existing approval, template and child-source checks working without weakening source-ceiling or subject-discipline rules.

**Validation.** Reproduced against the actual exported MissionKernel.approve method using a trusted fixture and foreign same-sub approver.

**Existing work.** Related to #646 and the source-resolution architecture finding, but independently fixable by enforcing an explicit issuer invariant. No new federation protocol is required.

**Sources**

[src/services/authorization-server/src/kernel/authority-source.ts:223](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/authority-source.ts#L223)

[src/services/authorization-server/src/kernel/authority-source.ts:260](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/authority-source.ts#L260)

[src/services/authorization-server/src/kernel/kernel.ts:595](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/kernel.ts#L595)

[draft-mcguinness-oauth-mission.md:757](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-oauth-mission.md#L757)

## 6. Identity lifecycle: define offboarding and entitlement-change behavior for each authority-rooting mode

**P1 — Deployment policy and identity-lifecycle gap.**

Mission revocation, token expiry and identity offboarding are different events. The normal issuance gate checks Mission/ancestor state and effective authority. The seeded approval identities and approve-for relationships are loaded into local sets. There is no demonstrated end-to-end contract connecting a user's disablement, removal of a source entitlement, client deregistration or owner departure to the local approval, refresh, delegation and execution paths.

The cross-domain profile is stronger here: it explicitly separates current principal entitlement from Mission freshness, and RAS code checks an entitlement observation and bounds token expiry. That machinery should be credited and reused where appropriate; the finding is the absence of a complete local deployment policy and integration demonstration, not a missing cross-domain requirement.

A blanket rule to revoke every Mission when its approver leaves would also be wrong for some service-owned and organizational work. An approver is an accountable actor in a historical event, not necessarily the continuing resource owner.

**Recommendation.** Decide a small deployment matrix for user-delegated, service-owned and organizational roots. State which identity changes stop new approvals, derivations, refresh or current execution; which initiate Mission suspension/revocation; and which require accountable-owner reassignment without rewriting history. Choose a bounded, existing directory/IAM integration plus reconciliation before designing a new event protocol. Identity freshness and Mission freshness need separate owners and outage behavior.

**Completion criteria**

- Publish mode-specific behavior for user disablement, source-entitlement removal, workload disablement, client disablement and approver/owner departure.
- Demonstrate at least one disablement from the actual identity source through issuance and resource enforcement within a measured bound.
- Test delayed/lost change signals, cached entitlements, recovery reconciliation and fail-closed behavior where required.
- Preserve historical approval provenance; define governance for continuing organizational work without borrowing the departed user's identity.
- Keep #250's atomic issuance work and current cross-domain entitlement behavior intact; avoid implying this policy is already universally normative.

**Validation.** Architectural integration gap based on the local identity configuration and issuance gates. No claim that every account change is currently required to revoke every Mission.

**Existing work.** Owner decision needed before lifecycle implementation; complements #250, #310 and the independent Resource-policy finding. It does not reopen the already-landed standing-consent recency work.

**Sources**

[src/services/authorization-server/src/index.ts:898](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/index.ts#L898)

[src/services/authorization-server/src/kernel/kernel.ts:1838](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/kernel.ts#L1838)

[src/services/authorization-server/src/kernel/kernel.ts:1871](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/kernel/kernel.ts#L1871)

[draft-mcguinness-oauth-mission.md:3751](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-oauth-mission.md#L3751)

[draft-mcguinness-oauth-mission-cross-domain.md:970](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-oauth-mission-cross-domain.md#L970)

[src/services/ras/src/index.ts:284](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/ras/src/index.ts#L284)

## 7. Credential operations: provide durable signing identities, key rotation and verifier refresh

**P2 — Operational implementation gap.**

The builder generates AS token, status, transaction and continuation keys per boot using configured kid values. The demo resource fetches JWKS once and constructs local key resolvers. Restart therefore changes key material under the same configured identifiers, while already-running consumers retain the old snapshot.

This is a disclosed demo convention, not an allegation of a hidden production key leak. It nevertheless prevents the persistent-kernel work from demonstrating restart continuity of the full identity system. A restored Mission record is not enough if its provider grants, trust configuration or outstanding credentials cannot survive—or be deliberately invalidated under an explicit policy. The old and new credential populations need a deliberate overlap/retirement policy.

Per-purpose keys are a useful start, but operational rotation and verifier purpose restrictions are separate properties.

**Recommendation.** Add a small production-oriented key-provider interface with a durable development implementation and an HSM/KMS seam. Persist stable signing identities, give replacement key material new identifiers, publish a bounded verification overlap and define compromise retirement. Implement verifier refresh with bounded caching and safe behavior during JWKS outages. Scope keys by issuer and intended artifact role. Coordinate with provider/store persistence under #250 instead of treating JWKS as a standalone fix.

**Completion criteria**

- Restart the issuer and resource independently while an unexpired token and active Mission exist; demonstrate the declared continuity/invalidation behavior.
- Rotate one key role with old/new overlap and prove old credentials stop at the declared bound.
- Test unknown kid, stale JWKS, retrieval failure, retired key and role mismatch without accepting an arbitrary untrusted key source.
- Document the relation between credential lifetime, JWKS cache lifetime and retirement timing, including long-lived evidence verification.
- Keep per-boot fixture behavior available explicitly for tests; do not label it production recovery.

**Validation.** Static inspection of key creation and one-time consumer JWKS loading. No production rotation or KMS integration was exercised.

**Existing work.** Sequenced with #250 and its provider-state residuals; operational follow-through rather than a new cryptographic protocol. Related privacy/key-history requirements remain in #823.

**Sources**

[src/services/authorization-server/src/index.ts:642](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/index.ts#L642)

[src/services/authorization-server/src/index.ts:669](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/index.ts#L669)

[src/services/mcp-payments/src/server.ts:198](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/server.ts#L198)

[src/demo/src/stack.ts:318](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/demo/src/stack.ts#L318)

[src/docs/channel-key-matrix.md:1](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/docs/channel-key-matrix.md#L1)

## 8. MAS migration needs a real subject/client mapping and credential-authority adapter

**P2 — Adoption and adapter gap.**

The MAS specification already requires a versioned enterprise mapping contract and recognizes coarse joins. The pure join resolver correctly compares issuer-qualified subjects and requires explicit delegates. Its caller is expected to supply already-mapped identities. The reference PEP demonstrates the shared-namespace case and a synchronous resolveOrdinaryAuthority hook.

An adopter with another IdP still needs authenticated token/introspection integration, issuer-qualified subject mapping, client-namespace mapping, account-disable behavior and a trustworthy interpretation of scopes/resource permissions. Opaque tokens and vendor-specific credentials need adapters as well. Saying the AS need not change is useful, but it does not remove these tasks.

Many real identity/policy lookups are asynchronous. Requiring them to be materialized into synchronous hooks is workable only with an owned cache, refresh/revocation bounds and mapping provenance. This is an integration-cost finding; the correct normative mapping contract already exists.

**Recommendation.** Extend the #818 pilot with one genuinely different issuer/client namespace and a concrete mapping adapter. Choose asynchronous resolution or a governed pre-materialized cache explicitly. Return mapping version and freshness/provenance for auditing; fail on ambiguous mappings. Map actual credential authority independently of the joined Mission. Start with one supported credential format before claiming generic AS compatibility.

**Completion criteria**

- Prove the pilot with a different issuer and independently registered client identifiers, not only the issuer used by the Mission demo.
- Test same sub/client_id strings in different namespaces, disabled/reassigned accounts, many-to-one mappings and missing delegate records.
- Declare mapping and credential-authority cache freshness, invalidation and failure behavior.
- Demonstrate one real scope/introspection-to-authority adapter and reject unsupported credential formats.
- Record the AS capabilities and adopter code actually required for baseline join versus sender-bound Join Assertions.

**Validation.** Specification and adapter inspection; no third-party IdP integration was deployed.

**Existing work.** Additive evidence and acceptance criteria for #818; no duplicate issue and no change to its existing plan of record.

**Sources**

[draft-mcguinness-mission-authority-server.md:2076](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-authority-server.md#L2076)

[src/services/pdp/src/mas-join.ts:104](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/pdp/src/mas-join.ts#L104)

[src/services/mcp-payments/src/pep.ts:394](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/pep.ts#L394)

[src/services/mcp-payments/src/pep.ts:742](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/pep.ts#L742)

## 9. Define a narrow AS integration port before treating the reference provider as an implementation recipe

**P2 — Implementation portability and simplification.**

The reference provider adapter combines PAR/RAR, approval sessions, grant linkage, custom exchanges, refresh-family behavior, introspection, metadata and profile endpoints. This gives valuable vertical coverage, but an identity product implementer cannot port it by adding one custom claim. The required capabilities include control over grant persistence and issuance ordering, subject handling, provider refresh semantics and protected management surfaces.

The OIDC finding is a concrete example of a domain distinction crossing an off-the-shelf provider's account/grant model incorrectly. #250 already tracks the issuance atomicity seam; duplicating that issue as another generic production-readiness complaint would not help.

The family should specify the minimum provider integration obligations for the chosen deployment and demonstrate them before adding more optional token/grant mechanisms. Document bundling is useful; another core/extension reshuffle is not the immediate bottleneck.

**Recommendation.** Under #253, publish a small integration port and capability matrix: trusted approval input, canonical principal resolution, derive-and-commit issuance, grant-to-Mission lookup, refresh/revocation projection and protected state lookup. Separate pure validation/derivation from provider-specific lifecycle hooks. Demonstrate it first with the existing provider, then a second implementation or adopter binding. Keep optional profiles behind explicit capabilities, not silent partial support.

**Completion criteria**

- An implementer can identify which hooks are required, which must be transactional and which can run asynchronously.
- Document unsupported provider capabilities and the MAS fallback without promising zero integration.
- Use the delegated-approval and revoke-during-issuance cases as acceptance scenarios for the port.
- Choose a minimal pilot profile and avoid importing every optional companion endpoint into it.
- Preserve #253's owner decisions and #250's atomicity plan; do not mandate a provider rewrite or split the model solely to reduce file size.

**Validation.** Structural review of the provider integration; not a claim that any named commercial provider lacks a capability.

**Existing work.** Additional implementation lens for #253. Existing architecture priority #4 remains the main deployment-profile issue.

**Sources**

[src/services/authorization-server/src/adapters/provider.ts:650](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/adapters/provider.ts#L650)

[src/services/authorization-server/src/adapters/provider.ts:904](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/adapters/provider.ts#L904)

[src/services/authorization-server/src/adapters/provider.ts:3143](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/adapters/provider.ts#L3143)

[src/services/authorization-server/src/index.ts:884](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/index.ts#L884)

## 10. Add identity-boundary contract tests that cross implementation modules

**P2 — Conformance and independent validation gap.**

The targeted existing tests pass while the new identity probes reproduce behavior the design should reject. Approval tests cover requested authentication context and authority gates; they do not establish that resulting OIDC identity claims identify the authenticated principal. Introspection has strict token-shape checks that resource validation does not share. Authority-source tests use one issuer throughout.

This is a test-boundary problem, not evidence that the extensive suite is worthless. Module-local tests can encode the same simplifying assumption as the implementation. A conformance ledger marked tested therefore needs to say which observable contract and negative cases it proves.

**Recommendation.** Extend #594 with a compact identity interoperability pack: provider-produced tokens consumed by independent validators, delegated approval followed through ID token/session/refresh, issuer and tenant collisions, subject-specific source ceilings, identity/resource revocation independent of Mission state, and key-rotation continuity. Use independently specified expected results and a second implementation where feasible.

**Completion criteria**

- Map each test to the normative claim, actual producing/consuming paths and supported deployment/profile.
- Require positive and negative cases for token class, principal namespace and permission-axis independence.
- Turn the review's observing probes into rejecting regression tests when fixes land; a passing reproduction of a bug is not conformance.
- Keep tested/partial/todo statuses precise and retain explicit exclusions for production recovery and external IdP interoperability.
- Do not count aliases used to repair this checkout's test imports or an unsupported local Node runtime as product behavior.

**Validation.** 120 existing tests passed across four selected files using a temporary workspace-alias config; six additional observing probes passed including mapping freshness and enforcement of a normally issued narrowed token. No full-suite or second-implementation claim.

**Existing work.** Additive to #594, with #814 owning overall claim reconciliation and #819 owning independent RAR vectors.

**Sources**

[src/services/authorization-server/test/rar-carriage.test.ts:646](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/test/rar-carriage.test.ts#L646)

[src/services/authorization-server/test/authority-source.test.ts:84](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/test/authority-source.test.ts#L84)

[src/services/authorization-server/src/adapters/provider.ts:2286](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/authorization-server/src/adapters/provider.ts#L2286)

[src/services/mcp-payments/src/server.ts:275](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/mcp-payments/src/server.ts#L275)

## 11. Principal mapping: co-resolution must not report freshness from only the newer required fact

**P3 — Demonstrated metadata bug; no current issuance bypass established.**

resolveCoResolvedLocalPrincipal requires two authenticated identities to map to the same local principal. It returns the earlier valid_until, which is conservative, but the later observed_at and describes that as conservative too.

A probe combined a September 1 observation with a September 16 observation, both valid until October 1. The result reported September 16. A consumer applying a maximum observation-age bound to this summary could treat the September 1 prerequisite as freshly confirmed. Confirming one mapping does not reconfirm the other.

The current RAS caller uses the combined valid_until for its token clamp and independently evaluates entitlement freshness. It does not use this combined observed_at to authorize issuance, so this review does not claim a demonstrated RAS freshness bypass. The defect is in the reusable helper's summary contract and comment.

**Recommendation.** Define the combined timestamp explicitly. If observed_at is the freshness of all required mapping facts, use the oldest observation; alternatively expose both observations and require freshness on each. A separate resolution-time field can represent when the join was performed. Do not overload that with evidence freshness.

**Completion criteria**

- Test unequal observation times in both orders and verify the aggregate cannot make an old prerequisite look newly observed.
- Retain the minimum validity bound, same-principal check and existing missing/ambiguous/disabled mapping refusals.
- Confirm RAS token-clamp behavior is unchanged or conservatively tightened; do not claim this fixes an unobserved issuance exploit.
- Document observed_at versus lookup/resolution time for future consumers.

**Validation.** Reproduced with the real exported helper. Reviewed its RAS caller to bound impact.

**Existing work.** Small independent correction in the existing cross-domain mapping helper; no need for a new mapping profile.

**Sources**

[src/packages/mission-core/src/local-principal-mapping.ts:115](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/packages/mission-core/src/local-principal-mapping.ts#L115)

[src/services/ras/src/index.ts:269](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/ras/src/index.ts#L269)

[src/services/ras/src/index.ts:284](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/src/services/ras/src/index.ts#L284)


**What is good and should be preserved**

| Design choice | Why it matters to an implementer and identity architect | Evidence |
|---|---|---|
| Subject, Approver and client are separate roles | Supports delegated administration and organizational work without borrowing a human identity. The OIDC adapter should preserve this model. | Core Principal Model and Authority Sources; findings 2, 3 and 5 |
| Approval may activate existing authority but cannot manufacture it | Keeps approval workflow from becoming an alternate privilege-escalation path. Activation permission and source ceiling are correctly separate gates. | authority-source.ts; #646 |
| Mission identity outlives individual credentials | Gives refresh, delegation and multiple execution actors one bounded undertaking and lifecycle anchor. This is useful for operations and audit. | Core grant binding and issuance gating |
| Proposed authority differs from issuer-derived authority | Prevents client intent or a convincing approval screen from deciding its own permissions. Standard RAR carriage limits unnecessary wire invention. | provider.ts RAR hooks and passing rar-carriage tests |
| Issuer-qualified origin identity and destination-local identity remain separate | Avoids pretending that the same sub string or email is a globally meaningful person. Destination mapping and entitlement remain local decisions. | Cross-Domain origin-principal mapping; RAS co-resolution |
| Cross-domain mapping, entitlement and Mission state have separate validity/freshness checks | Recognizes that identity linkage, task liveness and current authorization age independently. RAS bounds token expiry using the relevant horizons. | ras/src/index.ts:269–340; existing RAS tests |
| Missing MAS credential-authority configuration denies | The adapter does not silently grant the Mission's whole authority to an ordinary credential. | pep.ts:394–421 and 742–756 |
| Mission contextual tuples are not persisted as standing domain grants | Avoids stale task authorization surviving as an unrelated FGA permission. Preserve this while adding a real independent resource-policy conjunction. | policy-view.ts and fga-hygiene.md |
| Experimental maturity and ledger gaps are visible | Makes honest adopter scoping possible. Tested rows still need contract-level interpretation and narrative consistency. | Earlier review #814; this review finding 10 |

The differentiator is **a governed undertaking that ties approval, bounded authority, multiple identities/credentials, lifecycle and attributable actions together**. The case is strongest when a long-running agent or workflow spans services and credentials. It is weaker for a single short API call already adequately governed by an ordinary OAuth grant, resource policy and existing audit records.

Missions should integrate with the estate's IdP, directory, entitlement engine, approval system and credential operations. Building substitutes for all of them would dilute the product and multiply implementation risk. An enterprise identity team will value a precise integration contract and an independently proven resource-policy intersection more than another optional token class.

**Core, extensions and experimental scope**

Architectural necessity, applicability and maturity are separate axes. A required security invariant can have an immature implementation. An optional profile can be indispensable for a deployment that chooses its claim. The table below is an implementation/adoption recommendation, not a claim that the current documents are stable or a proposal to force another document split.

| Boundary | Keep or establish here | Rationale |
|---|---|---|
| Semantic core | Canonical principal identity; Subject/Approver/client distinction; trusted authority establishment; immutable approval/provenance anchors; non-widening; Mission/grant linkage and lifecycle | Every meaningful binding depends on these semantics. Issuer qualification and identity correctness cannot be optional hardening. |
| Required baseline for the chosen deployment | Correct token or introspection verification; authentic approval context; principal-specific source authorization; independent resource policy; owned freshness behavior; durable issuance/state integration; identity-change and key-operation procedures | A pilot is not implementable merely because these obligations are spread across documents or delegated to local policy. Name the owner and tested adapter for each. |
| Optional integration bindings | Mission issuance versus MAS overlay; JWT versus supported introspected consumption; cross-domain projection; provider-specific federation/client authentication | Choose the minimum needed for the estate. Do not require one deployment to implement every carrier. |
| Conditional requirements | Sender-bound joins where credential-to-Mission substitution resistance is claimed; client-instance identity where shared registration is too coarse; exact budgets when aggregate bounds are promised; independent custody/isolation for compromise-resistance | Claims drive requirements. These should not become universal features of an unrelated deployment. |
| Extensions that can wait | Broad delegation/projection/continuation combinations, generalized approval portability and multi-provider discovery | Valuable when a pilot requires them, expensive to operate and test in all combinations before then. |
| Experimental work to constrain | Offline attenuation, generic metering modes, arbitrary policy mappings, research trust/evidence mechanisms | Keep demand triggers, a named adopter and a measurable validation target. No maturity promotion from specification completeness alone. |

The current separation of foundational model/substrate, issuance binding, MAS binding and companion profiles is broadly reasonable. The main correction is at the **deployment boundary**: identity correctness, actual resource authorization and operational continuity must be mandatory for the supported route, even when the relevant extension or adapter is optional across the family. Keep #207's existing model-split triggers and #424's parked schema decision; this review does not supply a reason to reopen either.

**Complexity to remove or defer**

- **Do not duplicate IAM.** Keep principals, permissions and account lifecycle under existing authorities. Resolve them through a narrow trusted interface; Mission records retain the approved context and needed provenance.
- **Do not centralize heterogeneous ceilings into one demo catalog.** A small resolver is simpler and safer than one global permission union plus compensating checks everywhere else.
- **Do not run a policy service merely to confirm a tuple just created by the caller.** Make the independent policy predicate real, or explicitly scope the demo down until it is.
- **Do not let every profile invent its own token validation.** Share parsing and required-claim primitives, while retaining explicit, mutually exclusive profile validation rules.
- **Do not introduce new token members to solve local identity mapping if authenticated local configuration is sufficient.** First fix the integration boundary and its ownership.
- **Do not make every lookup a synchronous call to a new central service.** A governed materialized view can be practical, but its freshness, invalidation and outages must be explicit.
- **Do not require the entire family to deliver one supported workflow.** A small vertical slice with real IdP/resource integration is more valuable than broad self-contained fixture coverage.

**What is currently too idealistic to claim**

“Works with an unchanged AS” can mean the AS does not understand Missions; it cannot mean there is no identity/credential mapping and resource integration work. “Current policy” needs an independent policy source with a declared freshness bound, not merely a fresh Mission view. “Restartable” needs provider state, signing identity and consumers to recover together, not just persisted Mission rows. “Issuer-qualified” needs the issuer checked wherever authorization is looked up, not only carried in a TypeScript type. “Standards-based” needs ordinary OIDC semantics to survive composition.

These are implementable goals. The impractical step would be presenting them as consequences of the protocol objects alone. The review recommends small adapters, explicit ownership and observable failure tests instead of another general framework.

**Practical implementation sequence**

1. Fix and regression-test the resource token verifier and delegated-approval OIDC behavior.
2. Establish a canonical principal boundary and principal-specific authority-source resolver; use two deliberately different subjects/tenants in fixtures.
3. Select one actual IdP and one resource-policy source. Prove approval and execution depend on the intended independent authorities.
4. Decide the mode-specific identity-lifecycle matrix. Demonstrate disablement, entitlement removal and recovery with measured bounds.
5. Complete the #250 issuance/provider recovery slice together with durable key identity and verifier rotation.
6. For the chosen #253 deployment, implement either the direct issuance integration or the #818 MAS pilot. Run the independent identity contract pack before widening profile support.
7. Add optional mechanisms only when that pilot demonstrates a requirement. Keep original architecture findings on metering, resource-side atomicity and harness isolation active where their claims apply.

**Validation and limits**

- Reviewed core Principal Model, Authority Sources, approval/authentication and token/issuance rules; MAS mapping/join obligations; cross-domain origin/entitlement behavior; authority-source/kernel/provider implementation; RS token validators; FGA model/tuple/check path; key creation/JWKS loading; related tests and existing GitHub decisions.
- Ran 120 existing tests across authority-source, local-principal-mapping, RAR-carriage and RAS suites. All passed using a temporary Vitest configuration that aliases this checkout's workspace packages to their source exports.
- Ran six temporary observing probes against actual exported code. They confirmed: foreign same-sub approver accepted at the kernel boundary; a second service-owned source rejected; wrong-class/missing-claim JWT accepted by the HTTP token validator; Bob approval for Alice yielding an Alice ID token; co-resolution returning the newer of two prerequisite observations; and the PEP/PDP permitting vendor.read using an ordinary JWT narrowed to invoice.read under an explicitly allowing FGA stub.
- The probes assert the observed defects. Their passing is **not** a conformance pass. The temporary test file was removed from the product test tree after preserving it under /tmp/mission-identity-review. No implementation fixes were made.
- Localhost tests initially hit sandbox socket restrictions and then passed with approved execution. The checkout's Node v23 runtime elicits an oidc-provider unsupported-runtime warning; this review does not mistake that environment condition for a product defect.
- Did not run the entire suite, a live OpenFGA deployment, external IdP federation, production KMS rotation, penetration testing or a second implementation. Static findings are labeled accordingly. No production exploit or payment side effect is claimed by the validator probes.
- Standards comparisons used [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html#IDToken), [RFC 9068](https://www.rfc-editor.org/rfc/rfc9068.html), [RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html#section-3.12) and [OpenFGA consistency documentation](https://openfga.dev/docs/interacting/consistency). Source-linked findings distinguish specification requirements from this review's recommendations.

