# AAuth architecture review — 2026-09-16

Local commit: `85a5ed2d2dea8ec89f80db1bc04142ba1965d201`.
Declared AAuth protocol pin: `fc5e972c58d42a4f899d43acba39995081b87712` (2026-08-14).
Current upstream comparison: `be01e9294e384f1209d906ea2a3e13a6f5c9ae86` (2026-09-14).
Published IETF revision checked on 2026-09-16: **-10**, dated 2026-08-06.

This review complements the [general architecture critique](2026-09-16-end-to-end-architecture-critique.md), [implementer/identity review](2026-09-16-implementer-identity-architecture-review.md), and trackers [#824](https://github.com/mcguinness/mission-bound-authorization/issues/824) and [#833](https://github.com/mcguinness/mission-bound-authorization/issues/833). It evaluates the Mission family as an AAuth integration, not as an OAuth implementation with renamed tokens.

**GitHub tracking**

[Ranked AAuth review tracker #841](https://github.com/mcguinness/mission-bound-authorization/issues/841). Seven new issues and four detailed comments on existing issues:

| Rank | Priority | Finding | Issue |
|---|---|---|---|
| 1 | P1 | AAuth management: account for Person Tokens and use issuer-owned revocation cascades | [#834 ](https://github.com/mcguinness/mission-bound-authorization/issues/834) |
| 2 | P1 | Reconcile the frozen AAuth baseline with merged upstream semantics before claiming current interoperability | [#445 — review detail ](https://github.com/mcguinness/mission-bound-authorization/issues/445#issuecomment-5708512575) |
| 3 | P1 | Define the AAuth PS commit boundary for termination, in-flight federation and delayed delivery | [#250 — review detail ](https://github.com/mcguinness/mission-bound-authorization/issues/250#issuecomment-5708513278) |
| 4 | P1 | AAuth binding: reject broken Mission propagation instead of permitting missionless fallback | [#835 ](https://github.com/mcguinness/mission-bound-authorization/issues/835) |
| 5 | P2 | AAuth: build a minimal native conformance pilot with signed-wire negative vectors | [#836 ](https://github.com/mcguinness/mission-bound-authorization/issues/836) |
| 6 | P2 | AAuth/R3 assessment: distinguish native commitments from the stronger transaction-profile gaps | [#837 ](https://github.com/mcguinness/mission-bound-authorization/issues/837) |
| 7 | P2 | AAuth management: make response examples and idempotent results an executable contract | [#838 ](https://github.com/mcguinness/mission-bound-authorization/issues/838) |
| 8 | P2 | Keep the AAuth binding thin and reconsider the standalone expiry companion before expanding it | [#822 — review detail ](https://github.com/mcguinness/mission-bound-authorization/issues/822#issuecomment-5708520766) |
| 9 | P2 | AAuth management: specify a practical Person-to-control-plane authentication path | [#839 ](https://github.com/mcguinness/mission-bound-authorization/issues/839) |
| 10 | P2 | AAuth substrate statement: do not infer reference unguessability from an unsalted content hash | [#840 ](https://github.com/mcguinness/mission-bound-authorization/issues/840) |
| 11 | P2 | Compose native AAuth per-resource budgets with explicit Mission-wide accounting only where promised | [#816 — review detail ](https://github.com/mcguinness/mission-bound-authorization/issues/816#issuecomment-5708523147) |

**Assessment**

The thin AAuth binding is one of the family's better scope decisions. It preserves a native contextual-governance model instead of forcing AAuth missions into portable Authority Sets, OAuth client identifiers or a cross-resource subset algebra. The weak point is the transition from that sound conceptual separation to a usable, versioned implementation contract.

The management companion needs the most substantive correction. Its accounting concentrates on Auth Tokens even though Person Tokens can support access independently. Current upstream's issuer-owned revocation cascade also differs substantially from the companion's old routing. Local termination, closing in-flight authorization, reporting a completed cascade and proving every resource stopped are separate properties.

The right next deliverable is a small native Agent–PS–Resource implementation with signed-wire negative tests and honest termination bounds. Another universal authority language, another event transport, or a full implementation of every AAuth companion would make adoption harder without resolving the immediate gaps.

**How to read the priorities**

P1 findings should be resolved before relying on the affected AAuth path in an adopter pilot. P2 findings are required implementation/interop work for the supported claim or a material simplification decision. These are architecture priorities, not vulnerability severity scores. No native AAuth runtime exists in this repository's implementation paths examined here, so specification defects and potential failure scenarios must not be presented as demonstrated deployment exploits.

Frozen maintenance is a legitimate policy. A draft that names an old pin is not automatically wrong because main moved. The review distinguishes contradictions already present at that pin from changes needed to adopt current upstream. Merged editor's-copy changes are not a published -11 release. The [Datatracker](https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/) and [upstream commit](https://github.com/dickhardt/AAuth/commit/be01e9294e384f1209d906ea2a3e13a6f5c9ae86) establish those separate baselines.

**Stack-ranked findings**

| Rank | Priority | Finding | Evidence class |
|---|---|---|---|
| 1 | P1 | AAuth management: account for Person Tokens and use issuer-owned revocation cascades | Incomplete lifecycle accounting; additional current-upstream incompatibility |
| 2 | P1 | Reconcile the frozen AAuth baseline with merged upstream semantics before claiming current interoperability | Versioned interoperability decision; deliberate pin distinguished from drift |
| 3 | P1 | Define the AAuth PS commit boundary for termination, in-flight federation and delayed delivery | Distributed implementation contract gap |
| 4 | P1 | AAuth binding: reject broken Mission propagation instead of permitting missionless fallback | Contradictory security/conformance wording at the existing pin |
| 5 | P2 | AAuth: build a minimal native conformance pilot with signed-wire negative vectors | Missing implementation and interoperability evidence |
| 6 | P2 | AAuth/R3 assessment: distinguish native commitments from the stronger transaction-profile gaps | Carrier assessment overstates absent native capabilities |
| 7 | P2 | AAuth management: make response examples and idempotent results an executable contract | Concrete example defect and underspecified replay contract |
| 8 | P2 | Keep the AAuth binding thin and reconsider the standalone expiry companion before expanding it | Scope, YAGNI and adoption decision |
| 9 | P2 | AAuth management: specify a practical Person-to-control-plane authentication path | Human authentication integration ambiguity |
| 10 | P2 | AAuth substrate statement: do not infer reference unguessability from an unsalted content hash | Unsupported privacy/identifier assurance claim |
| 11 | P2 | Compose native AAuth per-resource budgets with explicit Mission-wide accounting only where promised | Conditional budget-composition gap and reuse opportunity |

## 1. AAuth management: account for Person Tokens and use issuer-owned revocation cascades

**P1 — Incomplete lifecycle accounting; additional current-upstream incompatibility.**

The management companion's required ledger, counters and residual_until cover Tracked Auth Tokens. Person-identity access can remain usable with a Person Token and no Auth Token at all. The companion does not include Person Tokens in that ledger or explicitly identify their residual in its exclusions. An implementation can faithfully track every required Auth Token and still lack the data needed to bound all PS-issued access. The existing no-untracked-path condition is useful, but it does not supply the missing accounting.

There is a separate compatibility problem with current AAuth. The companion recommends that the PS revoke federated Auth Tokens at the resource and optionally notify the AS, using (iss,jti). Current upstream permits callers to revoke only tokens they issued, authenticates the issuer from the request signature, requires jti plus exp, and has the PS revoke its Person Token at the AS so the AS revokes its own Auth Tokens. A terminal 200 can carry downstream failure outcomes; it is not proof that every resource revoked successfully.

The Person Token omission matters at the existing person-token baseline. The new routing/response contract is an adoption prerequisite for current upstream, not a claim that the frozen draft violated its historical pin.

**Recommendation.** Make the tracked credential population explicit: mission-scoped Person Tokens, directly issued Auth Tokens, and the provenance needed to follow federated/chained descendants. Keep the terminal Mission commit independent of external completion. On a current-upstream lane, use native issuer-owned cascades and interpret per-resource outcomes; bound unconfirmed credentials by their own expiry. Preserve local (issuer,jti) accounting without inventing a foreign-issuer revocation parameter.

**Completion criteria**

- Terminate a mission with only a live Person Token; report a nonzero or explicitly unknown residual until effective revocation or expiry.
- Cover three-party, four-party, step-up and call-chained credentials, including an AS that never completes a cascade.
- Do not have a PS attempt to revoke an AS-issued token under the PS's signature.
- Treat 202 as pending and a 200 with downstream errors as terminal-but-incomplete; retry according to the native contract.
- Define counters and complete consistently across caller redaction, unsupported endpoints and unknown outcomes; do not report a complete bound from Auth Tokens alone.

**Evidence and limits.** Specification inspection against both pinned and current upstream. There is no local AAuth runtime, so no revocation execution was tested.

**Existing work.** Coordinate the current-upstream portion with #445 and its rebase decision; this issue owns the management residual model. #250 retains durable issuance/outbox ownership.

[draft-mcguinness-mission-aauth-management.md:539](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L539)

[draft-mcguinness-mission-aauth-management.md:755](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L755)

[draft-mcguinness-mission-aauth-management.md:772](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L772)

[Current upstream draft-hardt-oauth-aauth-protocol.md:2364](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-oauth-aauth-protocol.md#L2364)

## 2. Reconcile the frozen AAuth baseline with merged upstream semantics before claiming current interoperability

**P1 — Versioned interoperability decision; deliberate pin distinguished from drift.**

The family pins fc5e972c and explicitly freezes maintenance until upstream release. That is a legitimate compatibility choice. Current upstream main is be01e929 (2026-09-14), while the IETF Datatracker still publishes revision -10 (2026-08-06). These are three different baselines; the current editor's copy is not a newly published -11.

Several assumptions no longer describe current main: the mission blob no longer contains approver; the binding requires verifying that blob member. presented_jti can identify an Auth Token, and the caller forwards presented_token for verification, rather than resolving only retained Person Tokens. Resource-token lifetime is now independent of mission expiry, while access-credential bounds propagate through the presented credential. Server Signature-Key examples now identify the issuer through id/dwk/kid. Completion, revocation and call-chaining text also changed.

PRs #128, #131 and #132 merged September 6; later changes include #148, #153, #174 and #176. The banked package still describes the first three as open proposals. A19/A21 and the package need a current disposition record before future engagement or adoption. This review does not authorize or perform upstream posting.

**Recommendation.** Keep #445 as the canonical coordination record. Add a commit-bound compatibility matrix for the old pin, published -10 and chosen editor's-copy target; decide whether release remains the gate or a explicitly supported editor's-copy lane is justified. Rebase the three local AAuth documents, registry summaries and examples together when authorized by that decision. Retain an abstract PS-plus-digest identity without requiring a removed blob member. Refresh asks and their evidence before any separately authorized upstream engagement.

**Completion criteria**

- Record current merge/disposition states while preserving stable A-IDs and historical evidence.
- Test approval without a blob approver member on the current lane, initial Person Token flow, Auth Token step-up via presented_token, and chained person-token propagation.
- Update expiry statements to distinguish request artifacts from authority-bearing credentials; do not merely change the pin string.
- Update server signing examples and revocation routing consistently.
- Keep -10 publication, historical pin and current editor's copy visibly distinct; maintain the no-outbound-engagement posture of the banked package.

**Evidence and limits.** Read commit-pinned raw source at fc5e972c and be01e929, GitHub merge records, and the IETF Datatracker. A static comparison confirmed approver is required at the old pin and absent from the current required blob fields.

**Existing work.** This adds current evidence to existing A19/A21 and related coordination work, not duplicate upstream requests. Watches #25, #49 and #71 remain open; #92 remains closed.

[draft-mcguinness-mission-aauth.md:180](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L180)

[draft-mcguinness-mission-aauth.md:333](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L333)

[draft-mcguinness-mission-aauth.md:401](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L401)

[draft-mcguinness-mission-aauth.md:552](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L552)

[notes/aauth-engagement-package.md:1](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/notes/aauth-engagement-package.md#L1)

[Current upstream draft-hardt-oauth-aauth-protocol.md:1416](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-oauth-aauth-protocol.md#L1416)

[Current upstream draft-hardt-oauth-aauth-protocol.md:1487](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-oauth-aauth-protocol.md#L1487)

[Current upstream draft-hardt-oauth-aauth-protocol.md:2513](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-oauth-aauth-protocol.md#L2513)

## 3. Define the AAuth PS commit boundary for termination, in-flight federation and delayed delivery

**P1 — Distributed implementation contract gap.**

The management companion commits terminal state, makes it visible locally, starts external revocation and returns. It also says a transactional state evaluation prevents issuance after the terminal commit. That statement needs separate treatment for local signing, a request already sent to a federated AS, deferred delivery, and a credential received while termination is committing.

A local database transaction cannot atomically stop a remote AS from finishing an already accepted request. Suppressing delivery at the PS is feasible; discovering and revoking an externally minted credential requires durable tracking and recovery. An ordered Mission log is not itself proof that the decision and issuance used the same state version. Similarly, checking active state once before a long human/AI interaction is insufficient.

This is the AAuth form of #250's consistency problem. It should not trigger another generic control-plane framework or an impossible distributed transaction requirement across independent resources.

**Recommendation.** Specify the observable guarantees for local issuance, brokering/delivery and external residuals separately. Carry a governance version or equivalent internal fence through pending operations; recheck before committing or releasing authority. Persist in-flight requests, eventual token provenance and revocation work so restart and unknown AS outcomes remain conservative. Use native asynchronous revocation results, without holding a Mission-state transaction open across network calls.

**Completion criteria**

- Race termination with local Person Token issuance, direct Auth Token issuance, AS federation, user approval completion and pending-result retrieval.
- Demonstrate what happens when the AS signs after local termination but before the PS receives the response.
- Recover after terminal commit but before revocation dispatch and after external issuance but before its receipt is recorded.
- Keep local terminal state irreversible; suppress newly arriving authority and track/compensate external outcomes under declared residual bounds.
- Separate log ordering, request idempotency, local atomicity and remote revocation success in the implementation claim.

**Evidence and limits.** Failure-schedule analysis of the specified sequence. No distributed AAuth implementation or fault-injection run is claimed.

**Existing work.** Additive AAuth acceptance criteria under #250. The native conformance pilot should exercise these once an AAuth implementation exists; no OAuth-specific grant or status-list machinery is prescribed.

[draft-mcguinness-mission-aauth-management.md:539](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L539)

[draft-mcguinness-mission-aauth-management.md:905](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L905)

[draft-mcguinness-mission-aauth.md:431](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L431)

[Current upstream draft-hardt-oauth-aauth-protocol.md:897](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-oauth-aauth-protocol.md#L897)

[Current upstream draft-hardt-oauth-aauth-protocol.md:2380](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-oauth-aauth-protocol.md#L2380)

## 4. AAuth binding: reject broken Mission propagation instead of permitting missionless fallback

**P1 — Contradictory security/conformance wording at the existing pin.**

The propagation section requires the PS to reject a missing or mismatched mission claim against the credential it came from. It also requires a mission-governed agent's missionless token request to be rejected. The final Mission Substrate Statement instead says a required, invalid or mismatched mission reference is processed as missionless at best, then says unknown input never silently degrades.

Those are different behaviors. A developer reading the compact capability statement can interpret a broken Mission association as ordinary authorization. Relabeling the resulting work missionless does not preserve governance when the operation or agent was required to be governed.

The contradiction is present in the local draft independently of the current-upstream rebase. Base AAuth legitimately supports missionless requests; that is not a justification for falling back after a required or authenticated Mission association failed.

**Recommendation.** Make the compact statement match the normative propagation path. A failed required Mission association denies that request. Separately describe intentionally missionless requests admitted by explicit deployment policy from the outset. Use the selected AAuth version's native failure rules; add no new wire error merely to fix the prose.

**Completion criteria**

- Remove the ambiguity from the Statement, mode table and any generated summary that repeats it.
- Provide negative traces for stripped, mismatched, malformed and unresolvable mission references.
- Demonstrate that rejection occurs before ordinary authorization fallback.
- Provide a distinct positive missionless trace for a policy that intentionally supports it.
- Evaluate both initial presentation and step-up/presented-token flows when the current-upstream lane is adopted.

**Evidence and limits.** Direct textual comparison of the binding's propagation rules and its final failure-behavior statement; no runtime exploit claimed.

**Existing work.** Complements #445's version alignment. This is a local text inconsistency, not a new upstream extension ask.

[draft-mcguinness-mission-aauth.md:552](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L552)

[draft-mcguinness-mission-aauth.md:894](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L894)

## 5. AAuth: build a minimal native conformance pilot with signed-wire negative vectors

**P2 — Missing implementation and interoperability evidence.**

All three AAuth family documents report no implementation in the conformance ledger. A scan of local TypeScript found no native aa-person+jwt, aa-auth+jwt, mission_s256 or Signature-Key implementation. The extensive OAuth tests therefore provide no evidence for AAuth's wire binding, HTTP-signature rules, credential continuity or management operations.

The upstream repository already supplies an informational interop demo profile. Repeating architecture claims without implementing even its basic Agent–PS–Resource path leaves the costly integration details untested. Mechanical family/ledger/pin validation passes despite the local contradictory fallback language and incomplete response example found in this review.

A useful pilot does not require an AI decision-maker, every access mode, all R3 vocabularies or four independently deployed servers.

**Recommendation.** Choose one explicit protocol baseline and build an Agent, PS and Resource three-party slice: signed requests, mission approval/digest verification, Person Token issuance, resource challenge, direct Auth Token issuance, execution and termination. Use human or deterministic governance initially. Add a separate AS and one parent-mediated sub-agent only after the basic route works. Reuse upstream vectors/profile structure rather than creating another conformance taxonomy.

**Completion criteria**

- Verify cryptographic signatures and actual HTTP request bindings, not only decoded JWT fields.
- Test wrong issuer/audience/key, missing covered components, replay, swapped presented token, wrong mission and expired governance.
- Exercise termination with a live Person Token and Auth Token, including restart and residual reporting.
- Keep native AAuth results separate from OAuth-ledger coverage and static document checks.
- Document one supported deployment, its governance mode, direct/off-path exclusions and exact pin; seek a second implementation before claiming interoperability.

**Evidence and limits.** Static source/ledger inventory and passing repository validators. No native runtime tests were available or fabricated.

**Existing work.** Feeds #253's canonical deployment work and #594's coverage discipline. The issue is specifically for native AAuth evidence, not another OAuth demo or a universal family implementation.

[family-manifest.json:178](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/family-manifest.json#L178)

[draft-mcguinness-mission-aauth.md:636](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L636)

[draft-mcguinness-mission-aauth-management.md:975](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L975)

[Current upstream interop-demo-profile.md:1](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/interop-demo-profile.md#L1)

## 6. AAuth/R3 assessment: distinguish native commitments from the stronger transaction-profile gaps

**P2 — Carrier assessment overstates absent native capabilities.**

The local transaction matrix lists missing challenge members for mission and presenter commitments even though the native signed resource token already carries mission_s256 and agent_jkt. It lists execution proof bound to the artifact as missing, although AAuth mandates coverage of Signature-Key, which carries the presented JWT, and verification with that token's bound key. The banked A18 item wisely calls for verifying that native property before requesting any extra digest; the table should reflect that distinction.

R3's proposal hash commits to its complete resource-serialized document, including parameters, and the resource checks retry parameters against the proposal. That does not automatically prove equivalence to the family's normalized effective-parameter digest. It does mean a differently named standalone member is not, by itself, the missing security property.

The stronger family transaction profile can correctly remain unsupported: admission-instance identity, one-result semantics across workflows, class dispatch, current-state enforcement and operation lifecycle still need proof. Native R3 per-call authorization and the stronger family claim must not be treated as synonyms.

**Recommendation.** Reassess the matrix by invariant and supported delivery path, with entries for supplied, supplied conditionally, unproven equivalence and absent. Credit native signed commitments and exact-artifact coverage where verified. Describe the remaining parameter issue as normalization/effect equivalence, not a demand for an OAuth-named field. Distinguish execution approval from the newer R3 result-release path. Keep A16/A17 and the appropriate portions of A15/A18 in #445 without reopening upstream #92.

**Completion criteria**

- Map each floor requirement to actual signed native fields and verifier steps at the chosen baseline.
- Test or specify Signature-Key artifact coverage on both 401 retry and 202 completion before proposing another digest.
- Document why raw proposal commitment is or is not equivalent to normalized effective parameters for one resource operation.
- Keep the strong transaction-profile non-claim until its actual invariants are met; do not advertise R3 as generally incapable of per-call authorization.
- Treat release-of-existing-result approval separately from pre-execution approval, and refresh the banked asks accordingly.

**Evidence and limits.** Compared local carrier floor and assessment with native resource-token, signature and R3 proposal rules. This is a protocol analysis, not a completed equivalence or interoperability proof.

**Existing work.** Local assessment correction linked to #445 A15–A18 and #286. No new AAuth claim or wire field, no upstream posting.

[draft-mcguinness-mission-aauth.md:500](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L500)

[draft-mcguinness-oauth-mission-transaction-authorization.md:1066](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-oauth-mission-transaction-authorization.md#L1066)

[draft-mcguinness-oauth-mission-transaction-authorization.md:1118](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-oauth-mission-transaction-authorization.md#L1118)

[notes/aauth-engagement-package.md:160](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/notes/aauth-engagement-package.md#L160)

[Current upstream draft-hardt-aauth-r3.md:484](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-aauth-r3.md#L484)

[Current upstream draft-hardt-aauth-r3.md:631](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-aauth-r3.md#L631)

[Current upstream draft-hardt-oauth-aauth-protocol.md:2548](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-oauth-aauth-protocol.md#L2548)

## 7. AAuth management: make response examples and idempotent results an executable contract

**P2 — Concrete example defect and underspecified replay contract.**

The terminate operation says its 200 response contains the status representation plus a revocation summary. Status requires approved_at, observed_at and fresh_until. The terminate example omits all three. A simple parser/check against the stated required fields reproduces the mismatch.

Idempotency introduces a second implementation question. Repeating an identical (caller,request_id) returns the original result for at least 24 hours, but the represented status freshness and revocation summary can change during that period. The draft should distinguish an immutable termination receipt from a fresh status observation, rather than leaving clients to interpret a replayed result as current. The Mission target lives exclusively in the URL; that target must participate in the request-equivalence check, not only the JSON body.

These are interoperability gaps in a proposed management protocol, not findings against a running server.

**Recommendation.** Publish a small executable set of request/response examples and validation rules. Make the terminate representation consistent with its declared schema. Define which fields a retry repeats and how a client obtains current residuals through the existing status surface. Bind idempotency to authenticated caller, canonical PS/Mission target and request semantics. Avoid adding a second job/resource protocol to solve this.

**Completion criteria**

- Validate every status, terminate and delegation response example against required and conditional fields.
- Test a termination retry after fresh_until and after some revocations complete; the client can distinguish original outcome from current observation.
- Reuse one request_id with the same JSON at a different Mission URL and get a deterministic conflict or correctly scoped independent result, never the first mission's result.
- Specify request equivalence for member ordering, unknown fields and changed reasons/replacement references.
- Retain one terminal transition and original reason across concurrency, retries and automatic expiry.

**Evidence and limits.** Extracted the terminate JSON example and checked it against the draft's required status fields: approved_at, observed_at and fresh_until are missing.

**Existing work.** A bounded local companion-contract issue; #250 owns persistence/concurrency implementation and #445 owns upstream version selection.

[draft-mcguinness-mission-aauth-management.md:431](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L431)

[draft-mcguinness-mission-aauth-management.md:539](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L539)

[draft-mcguinness-mission-aauth-management.md:588](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L588)

## 8. Keep the AAuth binding thin and reconsider the standalone expiry companion before expanding it

**P2 — Scope, YAGNI and adoption decision.**

The native binding's refusal to import OAuth Authority Sets, client_id semantics, scope-subset algebra or child Mission objects is a strong architectural choice. Its small adoption closure should be preserved.

The expiry companion now mostly adds timestamp precision/order and documented clock posture to a native facility, while the binding itself requires expiry. Keeping a separate 210-line document, conformance line, status block and upstream recital for that small delta creates synchronized maintenance without much independent implementation value. The latest upstream expiry rewrite makes that cost concrete. Folding the few local requirements into the binding—or intentionally retaining an independently useful profile—is a decision, not an automatic rewrite.

Similarly, a delegation-tree UI, portable evidence, event profiles, generalized budgets and every R3 vocabulary are poor prerequisites for a first governed AAuth path. Sub-agents and call chains are different native relationships; a generic tree should not become another authority graph.

**Recommendation.** Under #822's demand-driven roadmap, make the first AAuth deliverable a verified native binding plus the minimum management capabilities its deployment actually needs. Decide expiry consolidation with #445 A21 after choosing the supported baseline. Keep management optional for the abstract binding but required for deployments promising externally observable state/admin termination. Leave events, audit-completeness and delegation-visibility expansions behind their existing upstream watches.

**Completion criteria**

- Name the minimal AAuth pilot and the exact capability claims it can support.
- Choose whether expiry has independent consumers sufficient to justify a separate profile; otherwise propose a small consolidation with preserved normative requirements.
- Do not equate native approved_tools or approved_resources with portable deterministic authority or closed resource allowlists.
- Preserve optional R3 and budget composition without importing the whole OAuth runtime dependency closure.
- Keep upstream #25/#49/#71 watches and local #207/#424 decisions intact; do not draft another transport, child-Mission model or universal management schema.

**Evidence and limits.** Adoption/dependency and document-scope review. This is a prioritization recommendation, not a claim that the current split violates a standard.

**Existing work.** AAuth-specific application of existing #822 and #445 A21. Does not authorize protocol changes or upstream engagement.

[draft-mcguinness-aauth-mission-expiry.md:115](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-aauth-mission-expiry.md#L115)

[draft-mcguinness-aauth-mission-expiry.md:169](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-aauth-mission-expiry.md#L169)

[draft-mcguinness-mission-aauth.md:180](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L180)

[draft-mcguinness-mission-aauth-management.md:606](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L606)

[family-manifest.json:123](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/family-manifest.json#L123)

## 9. AAuth management: specify a practical Person-to-control-plane authentication path

**P2 — Human authentication integration ambiguity.**

The companion says the Person authenticates through the PS's normal channel and keeps the PS's existing account/session protocol. It later forbids an automatically attached cookie/session from satisfying control-plane authentication. That protects against ambient-authority mistakes, but leaves a conventional signed-in browser UI without an explicit conforming path.

A PS can implement an explicit request proof or a backend that authenticates the person and calls the management plane as a service. Those are different trust boundaries. The latter needs to preserve the human identity, tenant and authorized action instead of turning every UI request into undifferentiated management-service power.

This is not a demand that AAuth standardize human login or weaken control-plane authorization. It is a request for one practical implementation recipe and clear normative intent.

**Recommendation.** Choose a supported pattern: a session-authenticated same-origin action with an explicit validated anti-CSRF/action proof if the ambient-credential text is intended to permit that, or an authenticated backend/service call carrying locally trusted human attribution and enforcing per-human authorization. Keep server signing distinct from agent signing. Document the relationship to the PS's normal UI rather than requiring every human browser to become a new AAuth agent.

**Completion criteria**

- Show the complete Person UI → authenticated action → per-Mission authorization → management operation trace.
- State precisely what extra proof makes the action explicit and which party validates it; a bare cookie remains insufficient.
- Test cross-site submission, account/tenant switching, stale sessions and service-principal confused-deputy cases.
- Preserve human audit attribution and separate administrator powers from ordinary Person termination.
- Keep login/session mechanisms deployment-owned and avoid creating a new user authentication protocol.

**Evidence and limits.** Compared the Person and Ambient Credentials sections. No browser or PS deployment was tested, and the text is not claimed to make every possible implementation impossible.

**Existing work.** Owner choice is needed because the alternatives place the authentication boundary differently. Current signing-example syntax should align under #445; this issue owns the human channel.

[draft-mcguinness-mission-aauth-management.md:337](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L337)

[draft-mcguinness-mission-aauth-management.md:347](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L347)

[draft-mcguinness-mission-aauth-management.md:423](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L423)

[draft-mcguinness-mission-aauth-management.md:942](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L942)

## 10. AAuth substrate statement: do not infer reference unguessability from an unsalted content hash

**P2 — Unsupported privacy/identifier assurance claim.**

The binding's Substrate Statement says the reference is unguessable to parties without the private blob. The reference is a deterministic SHA-256 digest of serialized content, and neither the binding nor the listed native mandatory fields guarantees high-entropy secret input. A predictable template, known agent and narrow approval-time range can produce an enumerable candidate set. Not knowing the blob beforehand is not the same as the blob having enough entropy to resist guessing.

The management companion correctly says the reference is not a secret and grants no authority. The binding also acknowledges cross-resource correlation. Those are the safer properties to rely on. A hash provides content integrity under the normal cryptographic assumptions; it does not provide confidentiality or unlinkability for low-entropy inputs.

No attack against real mission contents was performed. This is an overclaim in the generic capability statement.

**Recommendation.** Remove unconditional unguessability and document content-address correlation/dictionary-guessing limits. Maintain anti-oracle authorization and data minimization regardless of reference secrecy. If a deployment wants a stronger unpredictability claim, state and evaluate its additional entropy construction and retention implications explicitly; do not silently introduce another Mission identifier or change canonicalization.

**Completion criteria**

- Keep native PS-plus-s256 identity, exact-byte hashing and integrity verification unchanged.
- Make the binding, management privacy text and substrate assurance language consistent.
- State that possession or successful guessing cannot authorize status, logs or management actions.
- Document the conditions of any stronger deployment-specific unpredictability claim.
- Include a low-entropy synthetic fixture in future privacy tests; do not treat a large hash output as proof of input entropy.

**Evidence and limits.** Analysis of the content-address construction and native required fields; no cryptographic break or private-content recovery is claimed.

**Existing work.** AAuth-specific claim correction; complements #823's broader privacy defaults. No upstream protocol change is required to correct the local assurance statement.

[draft-mcguinness-mission-aauth.md:290](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L290)

[draft-mcguinness-mission-aauth.md:751](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L751)

[draft-mcguinness-mission-aauth.md:825](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L825)

[draft-mcguinness-mission-aauth-management.md:202](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth-management.md#L202)

[Current upstream draft-hardt-oauth-aauth-protocol.md:1463](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-oauth-aauth-protocol.md#L1463)

## 11. Compose native AAuth per-resource budgets with explicit Mission-wide accounting only where promised

**P2 — Conditional budget-composition gap and reuse opportunity.**

Native AAuth Budgets are an important existing resource-metering mechanism, and their explicit non-goal is a cross-resource Mission aggregate. A mission description mentioning a trip budget is contextual governance, not proof of an exact shared total. Per-token/per-resource allocations and delayed consumption reports do not, by themselves, establish a family-wide ceiling across concurrent actors and resources.

This is not an upstream defect: the native draft is explicit about its scope. It is a composition responsibility if this family or a deployment claims a total cap. Rebuilding resource metering in parallel would add another accounting truth, while treating the native allocation as a Mission-wide total would overstate it.

**Recommendation.** For an AAuth pilot, reuse native resource denominations, allocation enforcement and consumption reporting. If an exact Mission total is promised, map those allocations into #816's authoritative reservation/settlement domain and account for outstanding allocations before issuing more. Start with one resource and one unit; add cross-resource escrow/aggregation only for a concrete requirement. Keep business-budget semantics out of the mandatory native binding.

**Completion criteria**

- Document whether a claim is per token, per resource, per actor or Mission aggregate.
- For an aggregate claim, reserve outstanding allocations and handle concurrent issuance, token replacement, delayed final reports and unknown consumption conservatively.
- Use one authoritative resource meter and reconcile it with the Mission ledger rather than double-counting both reports and allocations.
- Test whether native omission/default behavior matches the deployment's intended no-spend or capped-spend policy.
- Defer currency conversion and general cross-domain accounting until demanded; do not reopen native AAuth's explicit non-goal as an upstream bug.

**Evidence and limits.** Reviewed the native budget scope and allocation/enforcement contract. No native budget implementation, accounting simulation or financial assurance was tested.

**Existing work.** AAuth integration detail for #816, with #822 controlling scope. Optional and conditional on making a spending-cap claim.

[Current upstream draft-hardt-aauth-budgets.md:214](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-aauth-budgets.md#L214)

[Current upstream draft-hardt-aauth-budgets.md:226](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-aauth-budgets.md#L226)

[Current upstream draft-hardt-aauth-budgets.md:539](https://github.com/dickhardt/AAuth/blob/be01e9294e384f1209d906ea2a3e13a6f5c9ae86/draft-hardt-aauth-budgets.md#L539)

[draft-mcguinness-mission-metering.md:1](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-metering.md#L1)

[draft-mcguinness-mission-aauth.md:365](https://github.com/mcguinness/mission-bound-authorization/blob/85a5ed2d2dea8ec89f80db1bc04142ba1965d201/draft-mcguinness-mission-aauth.md#L365)


**Baseline changes that matter**

This is a compatibility summary for the next supported editor's-copy lane, not a claim that the current family already adopts these changes.

| Topic | Family pin / local assumption | Current upstream implication |
|---|---|---|
| Approved blob identity | Agent verifies a blob `approver` member | Current blob omits it; retain authenticated PS identity beside the digest without requiring the removed member |
| Challenge continuity | `presented_jti` resolved against retained Person Tokens | Step-up can name an Auth Token; `presented_token` participates in verification and lifetime bounds |
| Expiry | Every token carrying the Mission hash is capped at Mission expiry | Request-artifact lifetime differs from authority-bearing credential lifetime; rewrite the propagation argument accurately |
| Revocation | PS attempts direct revocation of tracked federated Auth Tokens | Native issuer-owned cascade and outcome reporting need different callers, records and success interpretation |
| Server signing | Example identifies a raw management JWKS URI | Current server identity/discovery parameters require a version-matched example and trust registration |
| Call chaining | Older upstream-token account | Current lane includes person-token upstream chaining; preserve native PS provenance without inventing an OAuth act chain |
| Coordination state | PRs #128/#131/#132 described as open in the banked package | They merged September 6; refresh the package and later #148/#153/#174/#176 changes before adoption or dispatch |

Sources are pinned in the findings; the full primary files and comparison metadata were downloaded to `/tmp/mission-aauth-review`. The current protocol and R3 files have evolved since the GitHub Pages text last crawled by the web tool, so commit-pinned repository source is the comparison authority.

**What is good and why**

| Choice | Why it works in AAuth | What must remain true |
|---|---|---|
| A thin native binding | Avoids semantic translation errors and keeps the two-document contextual-governance adoption closure credible | Profile stronger behavior explicitly, without pretending it is native base conformance |
| PS contextual governance separate from Resource/AS authorization | Resources retain their own permission semantics; the PS need not interpret a universal enterprise policy language | A PS decision does not manufacture resource entitlement, and a resource permit does not prove the PS saw the action |
| Native PS-plus-digest reference | Gives stable correlation and exact-byte integrity without another Mission identifier or canonicalization | Authenticate the PS and preserve the committed bytes; do not infer secrecy from the hash |
| Person, agent and presenter-key roles | AAuth can represent agent identity at the PS while resources rely on directed person identity and possession | Do not translate the agent identifier into OAuth client_id or claim every resource sees agent/delegation identity |
| Native Person Token → resource challenge → Auth Token continuity | Provides a concrete place to check that authorization refers to the same presented identity, key and Mission context | Follow the selected version's complete verification contract; handle step-up as well as initial access |
| Two-state Mission lifecycle | Permanent termination is simpler to operate and reason about than a general pause/resume/revision system | Keep short waits in deferred workflows and treat later work as separately approved where required |
| Ordered private governance log | Gives the PS context for subsequent decisions without distributing sensitive task descriptions to every resource | Distinguish PS-observed facts, agent reports and off-path activity; ordering is not proof of completeness |
| Resource-owned R3 semantics | A resource can describe its operation using a vocabulary it actually implements and bind a concrete proposal | Start with one operation vocabulary; deterministic authorization still requires an evaluator and faithful effect binding |
| Explicit non-claims | Structured Authority, cross-boundary monotonicity, portable evidence and strong transaction hosting are not automatically promised | Assessment tables should credit what exists while describing exactly what remains unproven |
| Native budget extension | Supplies a useful resource allocation/metering mechanism that the family can reuse | Keep per-resource allocation distinct from a claimed exact Mission aggregate |

**Differentiators and limits**

From an AAuth perspective, contextual missions, independent agent identity, person-server governance, native signing and content-addressed R3 already belong to the substrate. The family should not claim those as new inventions. Its incremental value is a precise capability assessment, explicit reliance and failure rules, usable Mission management, and a disciplined way to relate AAuth deployments to the family's broader governance requirements.

The strongest product story is a person- or organization-controlled governance point that can understand an undertaking across resource interactions while each resource retains its authorization policy. Its limits matter just as much: the PS is not necessarily consulted for every resource action, it does not see every local/off-path effect, and an approved description is not a deterministic spending cap or exfiltration rule.

A PS does not need an LLM to implement the protocol. A human decision or deterministic policy is enough for the initial interoperability pilot. An AI supervisor can be added later, with deterministic signature, token, identity, state and resource-policy checks kept outside model judgment. The existing prompt-injection cautions are useful; there is no reason to make probabilistic governance a prerequisite for proving wire interoperability.

**Core, extensions and experimental placement**

| Category | Recommendation | Reason |
|---|---|---|
| Native AAuth substrate | Keep agent identity, proof of possession, Person Token/challenge/Auth Token flow, PS governance, native Mission identity and lifecycle native | Duplicating these in family objects increases disagreement between layers |
| Mission Context binding baseline | Keep exact-byte verification, authenticated PS/agent binding, required bounded reliance, correct propagation, fail-closed governance and honest mode-specific claims | These are the small profile deltas that make the binding useful |
| Management companion | Keep externally observable status, administrative termination and authorized topology inspection outside the abstract binding | A deployment promising those capabilities must implement them; native contextual governance does not require every management UI |
| Expiry requirements | Preserve the substantive lifetime/clock rules; decide whether the standalone companion still has enough independent value | A short local profile delta need not force another synchronized document indefinitely |
| R3 composition | Optional resource-owned structured authorization; select a vocabulary per supported operation | The binding does not need another generic Authority Set or RAR-shaped clone |
| Budget composition | Optional native resource allocations; extra Mission ledger only for an aggregate claim | Avoid duplicate meters and implicit global guarantees |
| Strong transaction profile | Conditional, with the non-claim retained until all required properties are proven | Native per-call authorization can be useful without satisfying the stronger family profile |
| Events and audit completeness | Keep deferred under #445's upstream watches | Avoid inventing another transport or claiming receipts prove unobserved actions |
| Delegation visibility | Keep PS-held observational relationships and minimal queries; defer graph expansion | Sub-agent identity and call chaining are not child-Mission authority inheritance |
| Maturity | Keep experimental until native tests and independent interop exist | A thorough specification and passing manifest checks are not runtime evidence |

The formal separation is broadly right. The adjustment is to make selected deployment obligations concrete and to reduce optional maintenance overhead. Do not unpark #207's model split or #424's universal schema merely because the documents are numerous.

**What to simplify or avoid**

- Preserve one native Mission identity and one byte commitment. Do not add intent_hash, authority_hash or an OAuth-style Mission object to AAuth.
- Use native HTTP signatures for artifact binding. Confirm their covered fields before requesting another digest or proof token.
- Treat source commitments and normalized business effects as different questions. R3 need not copy OAuth member names, but a resource still must prove the effect it executes matches what was approved.
- Make the Person's ordinary management UI practical without requiring every browser to become a new agent identity.
- Make status/termination idempotency testable with ordinary local persistence. Avoid a second job API solely to explain whether a termination receipt is old.
- Keep the first pilot to three-party access and a small operation surface. Add a separate AS and sub-agent only when basic issuance/termination behavior is proven.
- Use resource-side native budgets where needed. Do not pre-build cross-currency, multi-resource accounting for a pilot that promises no aggregate cap.
- Keep upstream asks focused on missing properties. Do not reopen the settled single-use/retained-result decision or ask for an extra field when native binding already supplies the property.

**What is impractical or too idealistic**

A local transaction cannot guarantee that an independent AS has not already signed a token. A successful revocation conversation cannot guarantee every downstream resource enforced it. A Mission log cannot be complete for paths that never report to its PS. A Mission hash cannot ensure the secrecy of predictable content. A natural-language approved-tools list cannot guarantee a compromised agent's physical confinement.

Those limits do not invalidate AAuth. They define which party can make which claim and what a deployment must add to justify stronger claims. The family already acknowledges several of them. The corrective work is to make those acknowledgments consistent with tables, token accounting, management responses and actual integration tests.

**Recommended implementation order**

1. Record a versioned compatibility decision in #445, keeping historical, published and current-editor baselines distinct.
2. Correct local fail-closed wording, management examples and assurance overclaims without changing native wire semantics.
3. Implement the three-party native pilot with real message-signature and token verification.
4. Add Person Token-aware termination accounting and the selected baseline's revocation behavior.
5. Run termination-versus-issuance/federation/restart scenarios under #250.
6. Reassess the R3 carrier matrix against concrete native paths; retain the strong transaction non-claim where its invariants remain absent.
7. Add one optional R3 operation or native budget integration demanded by the pilot. Then seek independent implementation evidence.
8. Decide whether to fold the small expiry delta into the binding and whether optional topology/evidence work has an actual adopter.

**Validation and scope**

- Read all three local AAuth drafts' relevant model, security, lifecycle, conformance and management sections; the carrier floor; manifests/pins; the banked engagement package; and existing issue decisions.
- Retrieved commit-pinned protocol and R3 source at both historical pin and current upstream head, plus current events, budgets and the interop demo profile. Inspected relevant merge states and checked the published Datatracker revision.
- Confirmed upstream coordination watches #25, #49 and #71 remain open and #92 remains closed. No upstream issues or comments were sent.
- Static checks confirmed the terminate example is missing three fields required by its stated status representation; the old/current mandatory blob fields differ on approver; the local fallback and unguessability statements exist; and the inspected TypeScript tree contains no native AAuth runtime vocabulary.
- Family validation passed for 47 drafts, four Substrate Statements, one Assessment and nine consumer tables. Conformance-manifest validation passed for 724 rows; external-pin structural validation passed. These checks validate bookkeeping/structure, not the semantic correctness of the AAuth profiles.
- No AAuth server, message-signature interoperability, revocation cascade, browser management channel, budget meter or distributed fault test was run. OAuth test results from the prior review are not reused as AAuth evidence.
- The review leaves specification pins, frozen drafts and implementation code unchanged. The deliverable is this report and detailed local issue tracking.
