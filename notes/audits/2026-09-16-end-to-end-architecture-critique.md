**End-to-end architecture critique — 2026-09-16**

Reviewed working-tree baseline: `85a5ed2d`. This is an architectural assessment of the specification family, adoption model, and selected implementation paths, not an exhaustive code-security audit or a claim of production conformance. No protocol or implementation changes accompany this review.

GitHub follow-through: [ranked tracker #824](https://github.com/mcguinness/mission-bound-authorization/issues/824) maps all 16 findings to 11 new labeled issues (#813–#823) and detailed review comments on five existing issues (#250, #210, #253, #576, #288). Each carries source references, scope boundaries, and acceptance criteria. Existing accepted plans remain authoritative unless the owner revises them.

**Overall judgment**

The central model is worth keeping: an approved undertaking is a durable authorization object, distinct from a credential, a running workflow, or a principal's standing entitlements. The family handles many difficult boundaries thoughtfully. Its biggest problem is the distance between that useful primitive and a deployment that delivers its strongest advertised benefits economically.

The design is implementable in a bounded estate with known operations and trusted enforcement points. It is not yet demonstrated as a general authorization architecture for arbitrary tools, legacy SaaS, open-world discovery, and distributed agent fleets. Much of the text acknowledges this. The next step should turn those acknowledgments into a small, proven deployment contract instead of adding mechanisms that cover more hypothetical combinations.

The existing split is directionally right. Separating Resource Access from OAuth issuance, keeping runtime enforcement distinct from issuance, and isolating federation and novel delegation are good decisions. The operational minimum is less well established: reliability, operation semantics, bounded automation, and aggregate effects remain more consequential than some of the mechanisms receiving prominent treatment.

**Ranking method**

The ordering weighs security consequences, adoption blockers, and architectural rework. P1 means resolve before making the relevant production or product claim; P2 means a significant improvement to adoption, cost, or maintainability; P3 means defer or refine after the first deployment is proven. No finding is labeled a demonstrated exploitable vulnerability. Several are deliberate tradeoffs whose costs should change the roadmap rather than trigger a protocol rewrite.

| Rank | Priority | Finding | Main disposition |
|---|---|---|---|
| 1 | P1 | Production consistency is more fundamental than its optional profile suggests | Complete and test one durable issuance/lifecycle implementation |
| 2 | P1 | Resource semantics and connector contracts are the actual implementation bottleneck | Standardize and demonstrate a small operational vocabulary |
| 3 | P1 | Template and Progressive restrictions substantially limit useful unattended automation | Design bounded standing approval for a narrow real use case |
| 4 | P1 | The protocol core is defensible; the deployment core needs a sharper boundary | Freeze one deployable profile and its conditional requirements |
| 5 | P1 | Readiness claims and conformance evidence are not consistently aligned | Publish a current, scoped conformance result and fix narrative drift |
| 6 | P1 where attribution is claimed | Mission binding does not complete work-item-to-action binding | Add a trusted cross-link on the existing action path |
| 7 | P1 where aggregate bounds are promised | Per-action narrowing and issuance counts do not bound total damage | Deliver a minimal exact budget profile before fleet claims |
| 8 | P1 for transaction-grade claims | Gateway checks cannot manufacture resource-side atomicity | Make connector execution capabilities explicit and binding |
| 9 | P2 | MAS lowers AS integration cost by increasing enforcement integration cost | Position it as a bounded migration mode |
| 10 | P2 | Expansion, cascade, carryover, and overlays create a large interaction space | Limit the first lifecycle composition and tree size |
| 11 | P2 | Runtime latency and outage costs lack deployment-scale evidence | Benchmark the complete enforcement path and fault recovery |
| 12 | P2 | The generic authority algebra can become a policy-language project | Freeze a small interoperable subset |
| 13 | P2 | Taint and mediation are useful but expensive deployment properties | Separate harness correctness from compromise containment |
| 14 | P2 | Evidence can dominate the implementation and operating cost | Keep accountability mandatory; make portability proportional |
| 15 | P2 | Research breadth is outrunning independent interoperability | Freeze speculative profiles until demand supplies a test |
| 16 | P3 | Correlation and evidence retention are product constraints | Supply one concrete privacy and retention deployment profile |

**1. Production consistency is more fundamental than its optional profile suggests**

The OAuth binding already requires the active-state check to be atomic with issuance. The consistency profile correctly says declining it cannot waive existing requirements. However, the reference deployment explicitly says asynchronous provider, continuation, and signed-grant issuance paths do not yet share the complete atomic domain. Its file-backed kernel is single-writer, some projections restart empty, and out-of-band restore fencing remains follow-on work. These are documented implementation limits, not conjectures inferred from using SQLite.

A durable record alone does not establish durable authorization. A restart that loses grants, issuance indexes, pending approval state, or replay protection can halt legitimate work; an incorrectly recovered state can resurrect authority. The first failure is a reliability problem even when it fails closed.

Keep multi-region architecture optional. Make the safety consequences mandatory wherever a deployment claims the corresponding gates: serialized lifecycle/issuance admission, durable issuance outcomes, no invented freshness, nonreuse, and recoverable publication. Define the issuance linearization point; do not confuse atomic issuance with impossible atomic network delivery. Prove one persistent single-writer deployment first, including crash/retry across provider and kernel stores, then introduce replication only when needed.

Acceptance evidence: revoke-versus-issue races, failure after reservation but before credential delivery, restart with outstanding credentials, lost acknowledgments, restore to an older backup, and stale replica observations. The existing outbox and conditional updates are good foundations.

Sources: [issuance gating](../../draft-mcguinness-oauth-mission.md), [consistency invariants](../../draft-mcguinness-mission-control-plane.md), [implementation boundary](../../src/docs/control-plane-deployment.md), [kernel admission](../../src/services/authorization-server/src/kernel/kernel.ts).

**2. Resource semantics and connector contracts are the actual implementation bottleneck**

The design correctly states that prose is disclosure, subset checking is representational, and derivation is local policy. The consequence deserves more prominence: the system can faithfully enforce the wrong envelope. An approved `max_amount` does not establish the intended beneficiary, aggregate spend, invoice eligibility, or purpose unless trusted resource facts and executable constraints express those conditions.

Scope Projection already refuses an unsafe mapping. That is the right security rule, but it means a legacy `write` scope cannot become a constrained payment or document operation merely by carrying a Mission. The integration needs a resource that understands the authority or a mandatory gateway that can observe and enforce the missing semantics. This is the main cost center.

Make the Operation Profile and connector SDK first-class deliverables. For two initial resource domains, pin action identity, normalized parameters, authoritative fact resolution, supported constraints, classification, request/response correlation, and failure behavior. Test an AS, PDP, and resource implementation that do not share one helper library. A schema digest establishes which schema was used; it does not establish that the executor implements its advertised behavior.

Success means an independent connector author can implement a safe operation without reverse-engineering the payments demo. Avoid expanding the common vocabulary until those implementations expose actual needs.

Sources: [derivation and Scope Projection](../../draft-mcguinness-oauth-mission.md), [Resource Access](../../draft-mcguinness-oauth-mission-resource-access.md), [payments Operation Profile](../../src/docs/operation-profile-payments-v1.md), [Capability Binding limits](../../draft-mcguinness-mission-capability-binding.md).

**3. Template and Progressive restrictions substantially limit useful unattended automation**

Template dispatch prohibits irreversible actions, external commitments, privileged administration, external communication, and cross-domain authority. Progressive authorization similarly reserves these classes for fresh human approval. These are coherent conservative policies, but together they exclude many central automation jobs: recurring payments, customer notifications, partner-system updates, and scheduled administration.

There is also a composition mismatch in the automation story: the harness permits pre-consented egress to concretely approved destinations without a new approval on taint grounds alone, while Template cannot dispatch authority satisfying the external-communication predicate. A manually approved Mission can therefore support work that the reusable dispatch path cannot activate. This is a design tradeoff, not necessarily a normative contradiction.

Do not simply remove the prohibitions. Define one narrow standing-approval capability around a real workflow: named destinations or beneficiaries, exact task classes, per-action and aggregate caps, instance/rate/concurrency limits, expiry, review cadence, and independent approval policy. Escalate deviations. Distinguish an irreversible effect from an unacceptable risk; a five-dollar authorized payment and an unbounded transfer need not share one automation policy.

Retain experimental maturity until the narrowed policy is implemented and tested. The desired outcome is economically useful bounded automation, with human approval reserved for changes to what was delegated.

Sources: [Template Prohibited Classes](../../draft-mcguinness-oauth-mission-template.md), [Progressive authorization](../../draft-mcguinness-oauth-mission-progressive.md), [Harness pre-consented egress](../../draft-mcguinness-mission-harness.md).

**4. The protocol core is defensible; the deployment core needs a sharper boundary**

Keeping issuance independently implementable is correct. Making all runtime machinery mandatory in OAuth core would destroy that advantage. Likewise, the Resource Access split is already done and should be preserved.

The missing emphasis is a firm operational floor for the deployment people are actually evaluating. Following the manifest's adoption edges with Status as the freshness source yields six documents for Runtime-Enforced and eight for Governed Agent, before operation-specific or conditional additions. The catalog's four/six headline counts describe stack membership, with closure explained elsewhere; they are not the whole implementation cost.

Freeze a named initial deployment: one issuer, one trust domain, fixed approved operation catalogs, one state source, trusted enforcement, a small authority vocabulary, and durable state. Require budgets only when approval promises a cumulative limit; require strong execution handling only for the relevant operations; require isolation only for the compromise-resistance claim. Use the existing deployment statement rather than inventing a new negotiation protocol.

The substrate is useful for binding authors, but its candidate status and `core` role do not mean it supplies a deployable authorization floor. It intentionally omits a common authority language, token shape, and wire protocol. Explain this directly at the entry point.

Sources: [family manifest](../../family-manifest.json), [substrate scope](../../draft-mcguinness-mission-substrate.md), [reference architecture](../../draft-mcguinness-mission-architecture.md), [submission split already completed](../oauth-wg-submission-set.md).

**5. Readiness claims and conformance evidence are not consistently aligned**

The manifest is commendably candid: 47 documents, comprising 39 experimental, four sketches, three informational guides, and one candidate. The conformance ledger has 724 rows: 242 tested, 78 partial, 401 todo, and three blocked. These are ledger statuses, not percentages of production correctness or a complete inventory of every requirement in the family. Existing tests can also lack a mapped ledger row.

Several narrative statements disagree with that more careful model:

- Architecture's Runtime-Enforced description says every normative family dependency is non-experimental; the manifest marks its major documents experimental.
- Architecture says assurance levels are guidance, never conformance classes or earned labels; Runtime says an Enforcement Scope Statement earns the Runtime-Enforced level.
- Control Plane's generated block reports two tested and four partial rows, immediately followed by prose saying it has no implemented coverage.
- The historical implementation self-assessment says all six invariants are demonstrated, while newer recovery documentation records unresolved atomicity and durability boundaries. The older result needs an explicit historical scope rather than serving as the current assessment.

The manifest validators pass, which means mechanical consistency is not enough to catch these claim-level conflicts. Produce one commit-bound deployment assessment with requirements, selected capabilities, tests, exclusions, and unresolved seams. Add a second implementation before promoting interoperability claims. Keep specification completeness, implementation coverage, operational validation, and independent interoperability separate.

Sources: [ledger](../../conformance-manifest.json), [Architecture assurance levels](../../draft-mcguinness-mission-architecture.md), [Runtime conformance](../../draft-mcguinness-mission-runtime.md), [Control Plane status](../../draft-mcguinness-mission-control-plane.md), [historical self-assessment](../../src/docs/CONFORMANCE.md).

**6. Mission binding does not complete work-item-to-action binding**

Architecture explicitly identifies this gap: work-item binding and action binding together do not prove that an action came from the claimed work item. No family carrier currently supplies the required verified cross-link. This matters when several tasks share a Mission, or one client legitimately holds credentials for several Missions.

A valid credential proves which Mission authorized it. A valid permit proves which action was allowed. Neither alone proves that a queue item, user request, or subtask was entitled to select that Mission. Accurate governance attribution is a central selling point, so this is more valuable than another portability artifact.

Have a trusted harness or dispatcher assign an immutable work-item identifier and authorized Mission mapping. Bind that context through the authenticated PEP request, permit validation, and execution evidence. Define inheritance, retries, and successor rebinding. Do not add another general-purpose token if the existing authenticated channel can carry the binding.

Test swapping work items between concurrent Missions and between concurrent items within one Mission. Keep the weaker, already supported Mission-level attribution claim explicit until this exists. Evaluation-Context Binding addresses resource facts, not this task-origin problem.

Source: [Architecture Mission Binding Properties](../../draft-mcguinness-mission-architecture.md).

**7. Per-action narrowing and issuance counts do not bound total damage**

Every action can be inside its approved envelope while the run as a whole exceeds the intended risk. A per-payment cap does not limit total spend, a per-request read constraint does not limit total disclosure, and independent child counters do not create a shared parent budget. A derivation limit mostly counts credential issuance, including refresh; it is not a business-effect budget.

The Metering document recognizes all of this and honestly makes lineage-wide accounting a separate shared consistency domain. Keeping its entire general mechanism experimental is reasonable. Leaving a minimal exact budget unproven while emphasizing safe fleets and bounded undertakings is a product gap.

Prioritize a small exact profile: one unit, one budget owner, one authoritative reservation store, idempotent reserve/settle, and conservative handling of unknown outcomes. Children share the budget identity or receive escrowed allocations whose sum cannot exceed the parent allocation. Defer bounded overshoot, arbitrary unit conversions, and generic exclusivity groups unless demanded by the pilot.

Do not make budgets universal in issuance core. Make them non-optional whenever the approved undertaking claims a total cap, and demonstrate the cap under concurrent actors and retries.

Sources: [Metering exactness and aggregate bounds](../../draft-mcguinness-mission-metering.md), [Child derivation budget](../../draft-mcguinness-oauth-mission-child-delegation.md), [core derivation issuance policy](../../draft-mcguinness-oauth-mission.md).

**8. Gateway checks cannot manufacture resource-side atomicity**

Parameter digests, short permits, single-use identifiers, and execution leases are useful. They cannot guarantee that a remote resource remained unchanged between a gateway reread and a write, that a timed-out payment never committed, or that an accepted external operation can be stopped after Mission revocation.

The new Evaluation-Context Binding text correctly distinguishes `verified` rereading from `enforced` resource-side atomic comparison. The runtime also correctly limits exactly-once claims to resources that support idempotency. These distinctions should determine deployment admission, not be details an adopter discovers after building a gateway.

Give every connector an explicit execution capability record: durable idempotency, conditional write support, authoritative result lookup, commit point, cancellation semantics, and compensation authority. For an unknown outcome without reliable lookup, hold the reservation and route to resolution; never blindly retry an irreversible effect. Bind idempotency to one intended operation while allowing an explicitly new operation with identical parameters.

Retain orchestration as an adapter to an existing workflow engine. Do not make the authorization protocol responsible for executing general compensation workflows. Compensation still needs its own current authority.

Sources: [Runtime idempotency and Evaluation-Context Binding](../../draft-mcguinness-mission-runtime.md), [payments operation state machine](../../src/docs/state-machines.md), [Orchestration compensation](../../draft-mcguinness-mission-orchestration.md).

**9. MAS lowers AS integration cost by increasing enforcement integration cost**

MAS is a valuable migration option, and the documentation correctly admits that association is weaker than issuance. An ordinary token joined to a Mission is not a token issued for that Mission; the AS continues issuing and refreshing independently; uncovered resource paths remain ordinary OAuth paths.

Consequently, an unchanged AS does not mean a low-change estate. The deployment still needs complete PEP coverage, reliable subject/client mapping, current Mission state, credential validation, and resource-policy intersection. Enterprise mode adds Join Assertions and requires Mission-bound issuance for high-consequence paths. That upgrade is justified, but it changes the adoption proposition.

Lead with a gateway-contained pilot whose paths can actually be controlled. Prefer MAS plus Issuance Grant where the AS can support the grant, and preserve mapping joins for the explicitly weaker compatibility case. Show exactly which component must change for each mode and which guarantees it gains. Avoid telling adopters to construct baseline mapping, enterprise assertions, and native issuance simultaneously.

Source: [MAS Join, Limitations, and Enterprise profile](../../draft-mcguinness-mission-authority-server.md).

**10. Expansion, cascade, carryover, and overlays create a large interaction space**

Immutable approval records and fresh successors for widening are strong choices. Their operational price rises quickly when parent expansion must supersede the predecessor, cascade descendants, optionally create directly approved replacements, preserve budgets, commit outcome maps, and schedule durable publication atomically. Suspension, expiry, containment, discharge, and retries add more combinations.

The required immediate cascade makes a delegation tree a coordination boundary. Carryover makes expansion a multi-record transaction. This qualifies the convenient claim that Mission state can simply be sharded per Mission; parents, descendants, successors, and shared budgets may need a larger consistency domain.

Keep successors and immutable lineage. For the first deployable profile, cap depth/fanout, use one root consistency domain, prohibit expansion while delegated work is active unless it is explicitly stopped, and leave carryover experimental. Internally compute one effective-authority projection from the approved set and narrowing overlays, while retaining separate reasons and evidence for containment versus completion.

Use a state-transition model and fault tests to cover the enabled combinations. Avoid solving every future combination normatively before it has a user.

Sources: [Child cascade and carryover](../../draft-mcguinness-oauth-mission-child-delegation.md), [Expansion atomic replacement](../../draft-mcguinness-oauth-mission-expansion.md), [Containment overlay](../../draft-mcguinness-oauth-mission-containment.md).

**11. Runtime latency and outage costs lack deployment-scale evidence**

The runtime already discusses locality, outage classes, ride-through, and fail-closed behavior. It also admits that an embedded PDP still pays for shared counters, latches, and single-use state. Those are good qualifications. The reference's single-process topology does not establish the latency or availability of the distributed version.

Measure a complete action, not a pure policy function: credential validation, state observation, policy/resource lookup, approval where required, reservation, permit consumption, resource commit, and required evidence persistence. Include bursty fanout and one hot Mission, not only many independent Missions.

Publish workload-specific p50/p95/p99 latency, throughput, cache/lease age, evidence volume, availability under dependency failures, and recovery time. Measure the declared revocation cutoff under delayed events and lost connections. Cache only inside the original validity windows; do not solve performance by re-stamping state or silently relaxing the claim.

The sensible starting topology is one regional authoritative domain with colocated enforcement. Replication, status lists, and offline fanout should be responses to measured bottlenecks.

Sources: [Runtime deployment and operational considerations](../../draft-mcguinness-mission-runtime.md), [reference deployment boundary](../../src/docs/control-plane-deployment.md).

**12. The generic authority algebra can become a policy-language project**

The type-owned subset rule and refusal of unknown semantics are excellent safety decisions. Supporting resource prefixes, wildcard action families, extensible constraints, delegation eligibility, transformations, and scope projection nevertheless creates a substantial language implementation burden. Cross-system portability depends on shared semantics, not just shared JSON.

The implementation illustrates the gap: its supported constraint list includes `max_amount`, `vendors`, `requires_action_approval`, and `terminal_when`, and explicitly does not implement every registered common constraint. That is legitimate scoped support, but adopters need to see it before integration.

Freeze an interoperable implementation profile with exact resource matching, explicit actions, and a few typed constraints. Keep other transformations optional and reject unsupported constraints before approval. Publish positive and negative vectors covering decimal amounts, unknown members, wildcard boundaries, URI normalization, and preservation of restrictions through every derivation path.

Do not invent a general per-argument theorem prover. Use domain-specific RAR types where their semantics are clearer. Keep the generic type separate from OAuth issuance, as it is today.

Sources: [Resource Access subset and tool modeling](../../draft-mcguinness-oauth-mission-resource-access.md), [implemented constraint subset](../../src/packages/mission-core/src/authority-subset.ts).

**13. Taint and mediation are useful but expensive deployment properties**

The harness is unusually candid that model transformation destroys reliable parameter provenance; session taint is the conservative fallback. It also preserves taint across summaries, child sessions, and writable stores. These are sensible rules. They mean ordinary browsing, retrieval, and summarization will often leave the whole run tainted.

The approved-destination carve-out makes that workable, but it authorizes a destination, not the suitability of every payload sent there. A permitted endpoint can still receive unintended sensitive content. A content trust list also does not make every value returned by a first-party tool trustworthy.

Keep resume checks, queue gating, and stale-connection handling in the basic harness profile. Treat resistance to a compromised process as a separately demonstrated execution-environment property: isolated credential custody, no alternative network/filesystem/child-process route, and independent approval resolution. The reference egress gate explicitly makes no containment claim and defers session taint; preserve that honesty.

For a pilot, use fixed destinations, payload schemas and volume budgets, then red-team the actual isolated environment. Do not present default-taint bookkeeping as general information-flow control.

Sources: [Harness taint rules and limitations](../../draft-mcguinness-mission-harness.md), [reference egress gate](../../src/services/agent/src/egress-gate.ts), [Runtime named claims](../../draft-mcguinness-mission-runtime.md).

**14. Evidence can dominate the implementation and operating cost**

The separation between approval evidence, decisions, execution outcomes, and receipts is sound. So is the insistence that evidence is not authority and a signature does not prove truth or completeness. The potential excess is making every adopter implement a portable evidence ecosystem when its immediate need is reliable local audit and reconciliation.

Runtime already permits append-only integrity mechanisms such as signed segments and hash-linked logs; the concrete evidence profile supplies portable signed objects. Preserve that distinction. Define exactly which evidence must be durable before an action is released, how unavailable storage affects execution, and which export/transparency operations can be asynchronous without losing required records.

Keep stable correlation and authenticated producers in the deployable minimum. Offer portable per-record signatures, Mandate, transparency registration, selective disclosure, and generic Evidence Envelope only when a relying party needs them. Reuse the existing shared conventions; do not create another envelope merely to unify terminology.

Also clarify scaling prose so its reference to strongly consistent per-Mission evidence sequences cannot be read as requiring one global sequence across emitters: the record definitions scope the sequence per emitter and only provide best-effort cross-emitter ordering. Replicas of one logical emitter still need coordination. Do not add unnecessary global coordination to implement a stronger ordering property than the evidence actually claims.

Sources: [Runtime retention and deployment considerations](../../draft-mcguinness-mission-runtime.md), [Runtime Evidence sequence and integrity](../../draft-mcguinness-mission-runtime-evidence.md), [Evidence Envelope pilot](../../draft-mcguinness-mission-evidence-envelope.md).

**15. Research breadth is outrunning independent interoperability**

The family has 47 documents and five binding approaches. Its explicit experimental labels are good. Yet the maintenance, conceptual, and composition costs exist even when a document is optional. OAuth, MAS, and AAuth do not provide identical semantics, so calling them peers is accurate organizationally but insufficient as an implementer's choice criterion.

Concentrate implementation work on OAuth and the MAS migration path. Keep AAuth tied to concrete upstream changes and user demand. Freeze UMA/GNAP sketches, AAM mapping expansion, open-world discovery, cross-organizational attenuation, general continuation, and new evidence abstractions until a named consumer supplies an interoperability test.

Offline attenuation is justified if issuance fanout is a measured bottleneck; it does not remove shared budget, freshness, or resource enforcement costs. Open-world discovery can authenticate a declaration's origin but cannot make the declaration truthful or create a partner trust agreement. Those should remain experimental limitations, not future capabilities assumed by the core story.

This is YAGNI at the active-roadmap level, not a recommendation to delete the research. Preserve the notes and experiments while refusing to let their composition needs continuously grow the first deployment's mandatory surface.

Sources: [family inventory](../../family-manifest.json), [binding comparison](../../README.md), [Discovery identity and lying-resource limits](../../draft-mcguinness-mission-discovery.md), [Offline Attenuation](../../draft-mcguinness-oauth-mission-attenuation.md).

**16. Correlation and evidence retention are product constraints**

The core intentionally propagates one stable Mission identifier across audiences and domains. This improves audit joins and creates correlation. The privacy text correctly explains that public digests of enumerable identities are not anonymization. Detailed decision and refusal evidence can reveal sensitive activities even without raw parameters.

This is not a missing privacy discussion; it is a deployment decision that needs implementation defaults. Provide a concrete enterprise profile for evidence authorization, pseudonyms, encryption, key history, retention, terminal tombstones, forensic payload separation, and deletion of detail after its horizon. Separate minimal nonreuse markers from full task history.

Keep pairwise cross-domain identifiers out of the first version unless an actual deployment requires them: they alter the useful common-reference property and introduce another resolution system. State that the initial cross-domain design assumes participants accept the correlation tradeoff.

Sources: [core Mission identifier correlation](../../draft-mcguinness-oauth-mission.md), [Runtime Evidence privacy](../../draft-mcguinness-mission-runtime-evidence.md), [consistency tombstone retention](../../draft-mcguinness-mission-control-plane.md).

**What is good, and what differentiates the architecture**

| Keep | Why it is valuable | Qualification |
|---|---|---|
| Durable approved undertaking above individual tokens | Gives operators one object to inspect, narrow, end, and audit across credentials and actors | Durability alone is not unique; the common task semantics and integration are the value |
| Proposed intent, proposed authority, and approved authority kept distinct | Prevents a model's request from silently becoming authority and preserves what changed at approval | Commitments do not prove the interpretation was correct |
| Issuance gating distinguished from runtime enforcement | Makes the residual lifetime of already-issued authority explicit | A kill switch is a path-specific latency claim, not instantaneous global cancellation |
| Resource policy remains independently authoritative | Enables incremental deployment without making the Mission issuer omnipotent | Connectors must actually intersect the bounds |
| Immutable approval records and monotonic derivation | Makes widening visible and preserves a defensible audit history | Operational overlays and successors still require current state and recovery |
| Evidence cannot grant authority; approval is input to a fresh decision | Avoids bearer-evidence and approval-bypass designs | The approval resolver and evidence producer remain trusted components |
| Delegation distinct from projection and continuation | Prevents identity continuity or information transfer from silently creating authority | Keep these concepts separate without requiring every mechanism in the first product |
| Explicit uncertainty and residuals | Unknown outcomes, stale state, unsupported semantics, and weaker MAS joins are not disguised as success | Turn the written limits into tested deployment boundaries |

The defensible differentiator is the composition: approval-backed task identity, bounded derived authority, lifecycle linkage, and attributable action evidence across many credentials and actors. RAR already carries fine-grained authorization, token exchange already supplies delegation/impersonation machinery, and introspection already communicates token activity. Missions should claim the governed undertaking that links those mechanisms, not novelty for the mechanisms themselves. See [RFC 9396](https://www.rfc-editor.org/rfc/rfc9396.html), [RFC 8693](https://www.rfc-editor.org/rfc/rfc8693.html), and [RFC 7662](https://www.rfc-editor.org/rfc/rfc7662.html).

**Recommended core, extension, and experimental boundaries**

Architectural necessity and specification maturity are independent. Moving a requirement into a deployable minimum does not make its implementation mature. The following is a proposed adoption boundary, not a relabeling of the current documents as stable.

| Placement | Include | Boundary |
|---|---|---|
| Protocol core | Approved record; authenticated approval/subject/authority source; qualified Mission reference; expiry and terminal revocation; commitments; bounded authority; state-gated issuance/refresh; strict unsupported-semantics behavior | Keep OAuth self-contained and type-agnostic. Keep Substrate as the binding-author contract |
| Required floor for a runtime deployment | A fixed operation vocabulary; trusted Mission establishment; current state within a bound; intersected resource policy; parameter binding where required; durable decision attribution; conditional execution recovery; tested persistence | These can remain separate specifications; the selected deployment must implement their applicable requirements |
| Conditional mandatory capabilities | Exact cumulative metering when a cap is promised; independent custody/isolation for compromise-resistance; resource-side atomicity for the enforced-context claim; task cross-link for work-item attribution | No claim without its implementation and tests; no universal requirement for unrelated deployments |
| Ordinary optional extensions | Suspend/resume/complete; management; Signals after a pull baseline; consent evidence; bounded child delegation; expansion; deferred approval; capability pinning for dynamic catalogs | Add for a concrete operational need, with a supported composition matrix |
| Migration/federation extensions | MAS; Issuance Grant; one-hop Cross-Domain Projection | Declare trust mappings, covered paths, credential guarantees, and revocation bounds separately |
| Evidence extensions | Portable Runtime Evidence forms beyond the chosen local minimum; Mandate; Audit Transparency; selective disclosure | Driven by external verifier requirements, not obligatory for every enterprise pilot |
| Experimental, with narrow investment now | Bounded Template automation; minimal exact Metering; selected resource-context binding | These address immediate adoption/safety needs, but need implementation evidence before maturity promotion |
| Experimental, frozen absent demand | Progressive combinations; child carryover; distributed approximate metering; offline/multi-org attenuation; open-world Discovery; generic Evidence Envelope; Work Products protocol; generalized orchestration; UMA/GNAP and other speculative bindings | Keep research available. Do not make baseline evolution depend on these designs |

The important adjustment is to separate the first deployable package from the whole research family. The current standards submission choice—OAuth core plus Resource Access as separate documents—is sensible. The proposed deployment floor is a different product and should be presented that way.

**Practical implementation sequence**

1. Freeze a single-domain supported profile and a commit-bound claim/requirement matrix. Reconcile the narrative contradictions. Keep the current specification maturity labels until their gates are met.
2. Build and prove persistent single-writer issuance, lifecycle, token/grant recovery, and publication. Extend the existing fault tests across the provider/kernel boundary.
3. Implement two real connector profiles with independent consumers: one bounded read/write workflow and one consequential operation with reliable idempotency and outcome lookup. Include a deliberately weaker connector to show which claims are unavailable.
4. Add work-item binding, one exact cumulative budget, and a narrowly scoped standing-approval use case. Demonstrate legitimate unattended success as well as denial.
5. Run crash/retry/partition tests, adversarial substitutions, consent usability tests, and end-to-end performance measurements. Obtain a second implementation before growing protocol breadth.

A pragmatic first deployment does not need a new protocol for every stage. It needs an issuer, a durable store, an enforcement boundary, a small resource contract, one freshness mechanism, an approval surface, and attributable execution. Existing workflow and logging systems can carry much of the supporting machinery.

**Verification performed and limits**

- Read the architecture, core approval/issuance/derivation/lifecycle/security sections, runtime and assurance sections, substrate contract, manifest/dependency/adoption material, and relevant companion sections across approval, delegation, projection, harness, metering, evidence, and recovery. Inspected selected store, issuer, PDP, and harness implementation paths. This was not a line-by-line review of every draft or service.
- `node scripts/check-family-manifest.mjs` passed: 47 documents, four Substrate Statements, one Assessment, nine consumer tables.
- `node scripts/check-conformance-manifest.mjs` passed: 724 mapped requirements, with the outstanding coverage stated above. Passing validates the ledger, not conformance of every listed requirement.
- Targeted Vitest execution: the authority-subset and anchor suites passed, totaling 25 tests. Control-plane fault, runtime-freshness, and egress-gate suites could not load because this checkout's workspace package resolution could not find `@mission/core` or `@mission/demo-data`. Those three suites were not executed; their failure is not reported as a protocol failure.
- No live deployment, production-load, cross-vendor interoperability, or full-system security claim was independently validated. The repository itself states that no production Mission deployment is known.
