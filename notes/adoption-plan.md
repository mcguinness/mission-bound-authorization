# Mission Adoption Plan (v3.4, plan of record)

Status: plan of record, 2026-08-18, after three author review rounds, the verb-taxonomy
preservation ruling, the AAuth bundle directive, and the composition-axis track correction
as amended by the third review (metadata made explicit; portability claims made checkable). Dispositions: execution
items 1, 2, 3, 4, and 10 approved; items 5 and 9 specified here and hold-lifted on the
author's confirmation; item 6 expanded; item 7 held on 6; item 8 deferred by ruling.
Refs #220, #238, #253.

The diagnosis this plan answers: the repository has a storefront problem, not a document-count
problem. The product inside the 41-document family is a small normative floor plus a preface,
and a newcomer currently meets all 41 as one flat surface. Reader editions and honest packaging
are the remedy; consolidation is not (see the final section).

## Decisions

- **The bundle is seven documents: six normative plus a preface.** The OAuth Implementation
  Floor is six normative documents (substrate, core, status, runtime, runtime-evidence,
  authzen) with architecture as the informative reader preface. Substrate is a normative
  dependency of runtime, runtime-evidence, and authzen, so it belongs to the floor; its
  pull-trigger reflects that runtime implementers consume its commitment construction and
  kernel contract. Cross-Domain is a conditional normative dependency the baseline disables.
  External normative dependencies (including AuthZEN's ARAP and Obligations profiles) are
  pinned alongside the family documents.
- **The bundle is named as an OAuth product:** working name **OAuth Mission Runtime Baseline
  v0** (alternative: Mission OAuth Adoption Bundle v0). "Mission Core Profile" is retired:
  it made the substrate-neutral family look OAuth-centric and collided with the OAuth core
  draft and the Mission Deployment Profile.
- **The RAR-free mode is excluded from v0 entirely.** It would override mandatory token
  carriage, define a new conformance mode, and create negotiation and downgrade requirements
  inside a guide whose one rule is never to invent requirements. It is not a monotonic lower
  tier: it is an alternate projection mode, properly framed as `oauth-rar` and
  `oauth-scope-reference` modes with explicit discovery and no silent downgrade. Existing
  machinery corrections are recorded: template mode already derives an Authority Set without
  a submitted proposal, core introspection already returns audience-filtered
  `authorization_details`, and Mission Status already returns the current audience-scoped
  set; the real gaps are mode negotiation, carriage overrides, reference-resolution behavior,
  failure semantics, privacy, and conformance. It waits for #220 to land normatively in core
  or a separate Standards-Track profile; the guide may mention it as a planned alternate
  mode only.
- **The PAR-ubiquity premise is not decision-grade.** Official material shows PAR in Keycloak
  and specialist providers, not established in Okta/Entra. The survey that gates any wire
  tier must test the actual integration surface: custom pushed parameters (`mission_intent`),
  Request Object preservation, approval rendering and policy hooks, JWT access-token claim
  customization, state-gated refresh, extended introspection. Even full PAR support does not
  solve the immutable-IdP estate; the MAS entry ramp remains that answer.
- **Conformance disclosure is bundle-level** (see the baseline section's gate below).
- **The verb taxonomy is preserved as the family's semantic signature.** The verb spine
  (propose; approve and record; govern; contain; enforce each action; run and wind down;
  delegate; dispatch; project; continue; prove; analyze, as the README diagram renders it)
  is the family's unique conceptual view, carried by the README architecture diagram, the
  architecture document's own spine, and the catalog's group-keyed sections, which are the
  spine's noun form. One source-of-truth mismatch is on record and resolves in item 3's PR:
  the architecture document's explicit spine folds Containment into Govern and has no
  Dispatch heading, so the author picks the canonical set (update architecture, or shrink
  the diagram's list) before the vocabulary is declared canonical. Zones do not replace the
  spine. Zones answer "what do I adopt, and when"; verbs answer "what does this document
  do in the Mission's life". Both views stay, explicitly named as two axes over one catalog.

## Zones and tracks

Three top-level zones with subordinate tracks, and names that cannot be mistaken for
conformance classes. Within Compose and Lab, the tracks follow the composition axis:
`oauth-mission-*` documents extend the OAuth AS's wire surfaces and apply only to the OAuth
path; **Mission components** (`mission-*`) live outside the OAuth AS, which is all the naming
rule promises. Portability is conditional, not implied by the prefix: a Mission component
composes with a given binding only where its Mission Substrate consumption declaration or
Statement is satisfied by that binding's supplied capabilities (mission-approval-governance
imports OAuth-core approval objects and anchors; mission-capability-binding normatively
depends on core, runtime, and authzen; neither is portable to the AAuth path today). Per-
document compatibility is therefore derived from the document's own Substrate declaration,
surfaced as explicit manifest metadata (`applicable_bindings` or
`required_substrate_capabilities`, shape decided in item 3's PR). An AAuth adopter reads
Compose as: pick your binding, take the Mission components whose declarations your binding
satisfies (checkable per document, never assumed from the prefix), skip the OAuth
extensions.

| Zone | Tracks | Contents |
|---|---|---|
| **Start** | Reader preface; OAuth Implementation Floor; Governed Agent Add-ons | architecture (preface); substrate, oauth-mission, status, runtime, runtime-evidence, authzen (floor); harness, consent-evidence (add-ons) |
| **Compose** | Bindings; OAuth extensions; Mission components; Security guide | authority-server, issuance-grant, the aauth cluster (bindings); expansion, child-delegation, cross-domain, signals, approval, management (OAuth extensions, cross-domain among them as the floor's conditional dependency); audit, mandate, approval-governance, shaping, capability-binding (Mission components, compatibility per declaration); security-model (guide) |
| **Lab** | OAuth experimental; Mission experimental; Sketches | attenuation, containment, continuation, cross-org-delegation, progressive, template, transaction-authorization, approval-revision, work-products (OAuth experimental; containment floor-referenced); discovery, metering, orchestration (Mission experimental; metering floor-referenced); uma, aam, gnap (sketches) |

**Zones are an overlay, never a regrouping.** The README's catalog keeps its group-keyed
sections, which are the verb spine's noun form; nothing is fragmented or re-headed. Zones
land as a manifest-derived **adoption map**: a compact table near the top of the README (zone,
track, documents, one-line trigger) carrying the five-minute path, with each entry linking
into the verb-organized catalog below. This also dissolves what the executability review
called the regrouping's real cost (one group section spans four zones; under the overlay
design that is a feature of having two axes, not a fragmentation problem).

Placement is manifest-derived and validator-enforced via a required `presentation_zone`
field. A deterministic mapping from `adoption_rung` is disproven by this plan's own
placements: substrate shares the By-binding rung with four documents that stay in Compose,
and architecture and security-model share outside-ordering but land in different zones.
Validation is table-membership, simpler than heading placement: the validator checks that
the adoption-map table lists every document exactly once under the zone and track the
manifest declares. Track derivation is NOT deterministic under prefix and group rules: the
AAuth cluster falsifies them (mission-aauth-management carries the `mission-*` prefix and
the `lifecycle` group; aauth-mission-expiry carries neither recognized prefix and the same
group; both belong to the Bindings track), and the manifest has no binding-cluster
membership field. Therefore `presentation_track` is REQUIRED now, alongside
`presentation_zone`, both validated by table membership; the prefix/group heuristics remain
useful as a validator cross-check that flags surprising assignments, never as the source of
truth. The two existing validator constraints still hold (every slug in the
catalog subtree; all 39 bolded nicknames in the adoption-order section). The adoption map keeps the two axes joined per document, but `group` cannot produce a
truthful per-document Verb column: the groups deliberately aggregate verbs (approval-time
holds Propose, Approve, and Dispatch; lifecycle holds Govern and Contain; agent-runtime
holds Enforce and Run). The map's column therefore ships as **Architectural group** (from
`group`, truthful today), and a per-document `verbs` array validated against the canonical
vocabulary is the target state. That vocabulary has a source-of-truth mismatch to resolve
first, in item 3's PR: the README diagram carries contain and dispatch as rows, while the
architecture document's explicit spine folds Containment into Govern and has no Dispatch
heading; the author picks the canonical set (update architecture, or shrink the list) before
any `verbs` field is declared canonical. Four fields stay orthogonal by convention:
`maturity` describes specification stability, `maintenance` describes repository
responsiveness, `presentation_zone`/`presentation_track` describe adoption placement, and
`group` describes the architectural grouping; none implies any of the others.

### Per-document pull-triggers

| Document | Zone / track | Pull this when... |
|---|---|---|
| oauth-mission | Start / floor | Any agent's approval must bind durably to the tokens it later uses. The floor; start here. |
| mission-architecture | Start / preface | Before adopting anything: the Mission model, invariants, and assurance levels the rest cite. |
| mission-substrate | Start / floor | Runtime implementers consume its commitment construction and kernel contract; binding authors profile it. |
| oauth-mission-status | Start / floor | You must observe or change Mission state beyond token expiry (revoke, suspend, complete). |
| mission-runtime | Start / floor | Actions need a point-of-use check, not just issuance-time gating. |
| mission-runtime-evidence | Start / floor | Runtime enforcement is deployed and decisions need durable, verifiable records. |
| mission-authzen | Start / floor | The PDP speaks AuthZEN and needs the decision-contract wire mapping. |
| mission-harness | Start / add-on | A harness holds session state across restarts and must stop work when the Mission dies. |
| oauth-mission-consent-evidence | Start / add-on | You must prove what the Approver actually saw, not only what was approved. |
| mission-authority-server | Compose / bindings | The AS cannot change: run Mission governance as a standalone control plane. |
| oauth-mission-issuance-grant | Compose / bindings | A MAS-governed estate wants Mission-bound gated tokens without full intake at each AS. |
| mission-aauth | Compose / bindings | The substrate is AAuth: Mission context on its native propose/approve flow. |
| mission-aauth-management | Compose / bindings | Alongside the AAuth binding: status, termination, delegation-tree queries. |
| aauth-mission-expiry | Compose / bindings | A citable profile of AAuth's native `expires_at` member is needed (base AAuth enforces the member regardless; the profile's own conformance line is OPTIONAL). |
| oauth-mission-expansion | Compose / OAuth extensions | Approved authority will predictably need to widen mid-task via fresh approval. |
| oauth-mission-child-delegation | Compose / OAuth extensions | A sub-agent needs its own Mission outliving a call frame, with cascade termination. |
| oauth-mission-cross-domain | Compose / OAuth extensions | A Mission from one trust domain must be honored by an AS in another (also the floor's conditional dependency). |
| mission-audit | Compose / Mission components | A cross-domain party must verify evidence integrity without trusting issuer logs. |
| oauth-mission-signals | Compose / OAuth extensions | Consumers need push notice of state changes instead of polling per Mission. |
| oauth-mission-approval | Compose / OAuth extensions | Approval is asynchronous: a human review queue, not an immediate decision. |
| mission-mandate | Compose / Mission components | An outside party must verify what was approved without a token-exchange hop. |
| oauth-mission-management | Compose / OAuth extensions | An operator needs fleet enumeration and bulk lifecycle across many Missions. |
| mission-approval-governance | Compose / Mission components | Approval authority itself needs authenticated, policy-backed provenance. |
| mission-shaping | Compose / Mission components | You need a defined client-side path from user prompt to candidate Mission Intent. |
| mission-capability-binding | Compose / Mission components | Actions come from a discovered catalog where invoked identity can drift from approval. |
| mission-security-model | Compose / guide | Reviewing or auditing: the one consolidated trust and blast-radius view. |
| oauth-mission-containment | Lab / OAuth experimental (floor-referenced) | A live Mission must be narrowed, not ended, on a protected event. |
| mission-metering | Lab / Mission experimental (floor-referenced) | A Mission needs cumulative caps (budget, calls, duration, egress), not just scope. |
| mission-discovery | Lab / Mission experimental | An open-world agent meets resources its approval never named. |
| mission-orchestration | Lab / Mission experimental | In-flight work must unwind safely if the Mission ends mid-workflow. |
| oauth-mission-transaction-authorization | Lab / OAuth experimental | One action needs a fresh, portable, cross-org authorization with no live callback. |
| oauth-mission-approval-revision | Lab / OAuth experimental | Reviewers routinely narrow a proposed Mission rather than approve or deny. |
| oauth-mission-attenuation | Lab / OAuth experimental | Deep fan-out makes an AS round-trip per narrowing too costly; mint offline. |
| oauth-mission-continuation | Lab / OAuth experimental | Authorized work continues across hops or time without re-presented credentials. |
| oauth-mission-cross-org-delegation | Lab / OAuth experimental | An attenuation chain crosses organizational trust domains. |
| oauth-mission-progressive | Lab / OAuth experimental | Authority cannot be enumerated up front; policy-bounded drawdown beats over-provisioning. |
| oauth-mission-template | Lab / OAuth experimental | Machine-speed dispatch makes per-run approval infeasible; consent once to a ceiling. |
| oauth-mission-work-products | Lab / OAuth experimental | Artifacts cross into another Mission and must carry provenance, never authority. |
| mission-uma | Lab / sketch | Evaluating a UMA 2.0 deployment only. |
| mission-aam | Lab / sketch | Adopting Cloudflare's AAM vocabulary and mapping it onto existing mechanisms. |
| mission-gnap | Lab / sketch | Evaluating a GNAP deployment only. |

## Reader editions

True inlining is disqualified by measurement: two built HTML files alone share 242 element
ids, so a single concatenated page means owning a post-processor coupled to xml2rfc's exact
output. The single-kramdown merge is semantic surgery across 18,771 source lines. What works,
proven in a prototype: per-edition HTML copies with a navigation bar injected as a sibling
element beside the empty `external-metadata` div xml2rfc already emits, plus an ordered index
page, plus a concatenated **bundle text** (cover, edition manifest, form-feed separators) as
the literal single scrollable file. Copies, not canonical-file injection, so permalinks never
carry edition chrome; edition-prefixed flat filenames, because the gh-pages install rule
strips path components. The build fails unless exactly one insertion point exists per file.

Link handling has two branches by necessity, since floor documents cite outside the floor
(authzen cites harness and metering): in-edition citations are rewritten to edition-local
files (the rewrite target is narrow: bibliography entries whose href matches the family's own
gh-pages host); out-of-edition links are visibly marked, open in a new tab with
`rel="noopener"` so the edition tab stays intact, and every copied page carries a permanent
edition-index link; no query-parameter return mechanism. Front-matter external links stay
untouched, and the relative `.xml` alternate link is fixed or dropped once filenames are
edition-prefixed.

The editions build via an explicit `make reader-editions` workflow step on both pull_request
and push, explicit rather than folded into a default target so edition failures stay
distinguishable from draft failures (the ghpages target itself runs only on push, so PR
coverage requires this step). The edition job builds every member from source in a clean
checkout, runtime-evidence included; CI already publishes runtime-evidence's artifacts, and
the requirement is that the edition job rebuilds from source rather than reusing any prebuilt
artifact. The Bundler lockfile issue is a contributor-machine fix only. A second Governed
Agent edition (floor plus harness and consent-evidence) is the same machinery with a second
document list.

Both a moving `latest` edition and immutable versioned bundles are published, each carrying
the bundle manifest and source commit. Versioned bundles cannot ride `GHPAGES_EXTRA` on the
default branch (its directory rule exists only for non-default branches, `notdir` strips
subdirectory paths, and the cleanup step removes every listed path on each push); immutability
needs its own publish path to a directory the per-push overwrite never touches, and the
versioned publisher enforces three rules: it refuses to overwrite an existing version with
different bytes, serializes concurrent Pages publications, and verifies every published
artifact against the bundle manifest's digests.

## OAuth Mission Runtime Baseline v0

An implementation guide, not a 42nd I-D: a guide selects and pins existing normative text and
never invents requirements; it replaces reading six documents rather than adding a seventh.

**Pinning is one coherent snapshot.** The bundle manifest carries a single
`source_repository_commit` covering every in-repository document (per-document last-modified
commits are recorded as informational traceability only, never as assembly inputs, so the
bundle can never combine documents that never coexisted); external dependencies are pinned by
repository, commit, and file path with a content digest (a bare blob hash is
content-addressable but awkward to audit or recover); artifact digests and the
disabled-capability set complete the manifest. Immutable editions build only from that
snapshot. The external-pin work is asymmetric: ARAP already has a copyable pin in
SPEC_VERSIONS.md; the Obligations Profile has no pin anywhere in the repository and must be
established from scratch.

**The published levels take semantic names** (the tier numbering is retired): the **OAuth
Mission Issuance Baseline** and the **OAuth Mission Runtime-Enforced Baseline**, deliberately
parallel to the Mission Assurance Levels they realize. The Runtime-Enforced floor pins
today's runtime text verbatim; the transaction-assurance machinery stays a named extension,
and #238's re-cut is not executed out of sequence through this guide (if it lands, the guide
re-pins). The worked example stitches demo scenarios 1, 2, and 8; the revocation-denial leg
is required because prompt cutoff is the entire value of the Runtime-Enforced level over the
Issuance level.

**The publication gate covers all six normative floor documents, substrate included.**
Today's known aggregate is 13 tested, 5 partial, 35 todo, with runtime, authzen, and
substrate uninventoried; runtime-evidence's six tested rows do not themselves prove its
inventory complete. Inventory alone is not the gate; the coverage threshold is: zero
uninventoried baseline requirements; zero todo rows on authorization invariants or
fail-closed/refusal requirements; positive and negative tests for every baseline protocol
surface; every partial row naming exactly what remains unproved; and composition tests over
the selected bundle, not merely each document independently. Plus: applicability narrowed to
the selected baseline, exact external pins, the disabled-capability list, and one overall
coverage snapshot. An exploratory bundle may publish earlier, labeled as exploratory, never
marketed as conformance-ready.

## AAuth Mission Context Bundle v0

The AAuth-path counterpart to the OAuth bundle, named from the binding's own vocabulary
(Mission Context Binding) to avoid collision with AAM and the OAuth bundle's names. It reuses
the OAuth plan's machinery (bundle manifest, single-snapshot pinning, parametrized reader
editions) and cannot execute before execution items 4 and 5 land.

**The honest frame: coherence, not composition.** Derived from front matters, not the
manifest: the cluster's only in-family normative edge is mission-aauth to mission-substrate;
mission-aauth-management never cites mission-aauth at all, and aauth-mission-expiry has zero
family dependencies. Every cluster document's sole external normative dependency is
`draft-hardt-oauth-aauth-protocol`. Membership is therefore justified by a shared upstream
pin, which is exactly what an adopter needs from it. The closure never reaches oauth-mission,
status, runtime, or authzen (each roots normatively in the OAuth core), so their exclusion is
structural, not stylistic; a PDP-over-AAuth composition is conceivable but unspecified today
(no document defines the `mission_s256`-to-PDP join) and stays out until requested.

| Document | Role | Justification |
|---|---|---|
| mission-substrate | floor | the sole in-family normative dependency of the binding |
| mission-aauth | core | the binding; supplies Lifecycle-Gated Authorization and the Reliance Bound via AAuth's native `expires_at` |
| mission-aauth-management | core | the kill switch: revocation, status query, delegation-tree query; without it the bundle has completion and expiry but no revocation |
| aauth-mission-expiry | add-on | profiles an already-native, base-enforced member; informative register in the binding; its own conformance line is OPTIONAL; kept standalone so the bare-AAuth audience is not stranded |
| mission-architecture | preface | informative; situates the cluster |

**Pinning is the point.** Today's in-repo citation carries no revision pin at all (the
seriesinfo was removed in the #472 alignment; the front-matter target is the live editor's
copy), and datatracker's -10 is a divergent pre-person-token document, disclosed and never
cited as the pin. The bundle manifest's external pin is what makes
frozen-until-upstream-release mean something concrete:

```json
"external_pins": [{
  "id": "AAUTH",
  "repo": "dickhardt/AAuth",
  "ref": "PR #73 merged",
  "commit": "f1569261d0b9d179324f1665db1597f81cd0a851",
  "path": "draft-hardt-oauth-aauth-protocol.md",
  "digest": "sha256:computed-at-build",
  "note": "datatracker -10 is divergent (pre-person-token); disclosed, not the pin"
}]
```

Publication is exploratory only, re-issued on an upstream datatracker release reaching or
superseding the pinned commit, or on a deliberate re-pin under the never-implicit discipline
SPEC_VERSIONS.md already uses.

**Reader editions:** architecture, substrate, mission-aauth, mission-aauth-management as the
core list; a second optional list adds aauth-mission-expiry (the same add-on pattern as the
Governed Agent edition). Link rewriting is materially lighter than the OAuth editions: the
cluster's out-of-edition family citations are few and informative, and upstream AAuth
references resolve to a non-family host the rewrite rule leaves untouched automatically.

**Gates before this bundle is more than exploratory:** an upstream release reaching the
pinned commit (none exists; datatracker is at -10); a conformance inventory for all three
cluster documents (zero rows exist today) AND for mission-substrate, the bundle's normative
floor document, with tested coverage of the capabilities the AAuth Statement claims plus
AAuth-to-Substrate composition tests over the bundle (item 11 therefore depends on that
slice of item 6, not only on items 4 and 5); an actual AAuth implementation (none exists
anywhere in src/, so composition tests are unreachable, not merely undone); execution items
4 and 5 landed; and a documentation-precision fix: README and family-manifest language
saying the binding "requires" the expiry profile overstates its informative register and
OPTIONAL conformance line, and must be reconciled so this bundle's coherence-not-composition
framing does not contradict the family's public claims. The known manifest inconsistency is
scheduled, not merely recorded: item 3's PR reconciles mission-aauth-management's manifest
entry with its citations now, default direction align-manifest-to-citations (remove the
stale mission-aauth dependency; it returns if the #445-slated revision adds the citation),
author override open. One flagged author call remains: whether PDP-over-AAuth deserves a
named out-of-scope mention.

## Freeze policy

Machine-enumerated, human-enforced. The manifest carries a required `maintenance` enum; CI
detects any change to a frozen document; the semantic classification (text fix vs shape
change) stays human-reviewed. The check is an always-running **required** status check
(succeeds when no frozen document changed; fails when one changed without an exception),
re-running on `labeled`, `unlabeled`, `synchronize`, and ordinary PR events; the checkout
needs a deeper fetch to diff against the PR base. An exception requires BOTH the designated
label AND approval from an authorized maintainer or CODEOWNER, since a label alone can be
applied by anyone with triage permission. Branch protection prohibits direct pushes to main,
which is what makes advisory-only push behavior safe. One flagged tension for the author:
that protection collides with the repository's standing convention of committing PLAN.md log
entries directly to main; either the convention moves to PRs, or an explicit admin exemption
is named for that path.

| Class | Promise | Assigned to |
|---|---|---|
| `active` | Full peer-symmetry maintenance | Floor (substrate included), add-ons, advanced, authority-server, issuance-grant, approval, attenuation (on merits, with their unratified DTR and Attenuating-Agent-Tokens dependencies named) |
| `active-experimental` | Active maintenance while experimental, earned by implementation evidence | transaction-authorization, cross-org-delegation (qualified on current evidence: 14/6/1 and 9-of-9 tested respectively; promotion is always a human decision informed by a named maintenance owner, an active implementation, a complete conformance inventory for the implemented surface, meaningful tested coverage, and a scheduled review horizon, never automatic because one tested row exists) |
| `frozen-until-upstream-release` | Text fixes only; shape changes wait on the upstream; CI-flagged, human-excepted | The AAuth cluster (wholly derivative of AAuth's unratified wire shape) |
| `lab-floor-referenced` | Lab maturity; active-tier responsiveness for the property floor text points at | containment, metering |
| `lab-best-effort` | Best effort, no cadence; four-condition gate out of the Lab | uma, aam, gnap, remaining Lab documents without implementation evidence |

The gate out of the Lab: a Mission Substrate Statement where a new substrate is bound; the
draft's own abstract drops deferred/sketch language; a named adopter or implementer
commitment on record as an issue; and category, maturity, and rung updated together in one PR.

## Consolidation and retirement

No consolidation before WG adoption, recorded as policy: reader editions are the chosen
remedy now, and the lifecycle and runtime/evidence boundaries are reconsidered only at WG
adoption or publication planning, when names, ownership, and publication shape get recut
anyway. Decision-grade numbers from the analysis: the approval pair has a hard
maturity-mixing toolchain blocker; the only citation-viable pair (runtime + runtime-evidence,
53 mutual citations) would create the family's largest document and a 29-file retarget
dominated by authzen's 89 citations; the lifecycle group's natural reader edition is the
manifest's own 9-document group. `aauth-mission-expiry` retirement goes upstream-first:
contribute the RFC 3339 precision and prompt-transition requirements to AAuth itself, and
retire the standalone profile only if upstream absorbs its distinctive semantics; folding it
into the Mission AAuth binding stays rejected (it would strand the bare-AAuth audience).

## Execution order

| # | Work item | Disposition |
|---|---|---|
| 1 | Rename the bundle and zone/track vocabulary (incl. the OAuth Implementation Floor track name) | Approved |
| 2 | Substrate into the OAuth Implementation Floor; define the normative/conditional dependency closure | Approved |
| 3 | README adoption-map overlay plus zone/track validation (required `presentation_zone` AND `presentation_track`; table-membership check; Architectural-group column now, `verbs` array after the spine vocabulary is reconciled; compatibility metadata shape for Mission components; the management-to-aauth manifest-dep reconciliation; the verb-spine catalog sections stay untouched) | Approved; one PR with 1-2, 9, 10 |
| 4 | Hardened `latest` reader editions: author the edition-build target (none exists today); explicit `make reader-editions` step on PR and push; edition job builds every member from source | Approved; needs the build target |
| 5 | Machine-readable versioned bundle manifest (single snapshot; establish the Obligations pin) and the dedicated immutable publish path with refuse-overwrite, serialized-publication, and verify-against-manifest rules | Hold lifted on confirming this plan's snapshot and publisher rules; after 4 |
| 6 | Inventory all six floor documents, substrate included, and meet the coverage threshold (with #238's ledger discipline) | Prerequisite for 7 |
| 7 | Publish v0: the OAuth Mission Issuance Baseline and Runtime-Enforced Baseline | Held on 6 |
| 8 | RAR-free mode stays behind #220 (normative landing in core or a Standards-Track profile) | Deferred by ruling |
| 9 | Maintenance enum with the human-reviewed frozen-change gate (required check; label-AND-CODEOWNER bypass; branch protection) | Hold lifted on confirming the gate design and the PLAN.md convention decision; rides 3 |
| 10 | Record "no consolidation before WG adoption"; aauth-mission-expiry goes upstream-first | Approved; rides 3 |
| 11 | AAuth Mission Context Bundle v0: pin the upstream commit, bundle manifest entry, aauth reader editions, exploratory publication; the expiry-framing precision fix rides item 3's PR | Directed; after 4 and 5; beyond exploratory only after item 6's substrate-plus-cluster slice with AAuth composition tests |

## Provenance

v1 explored the packaging track, the reader-edition build (with a working prototype of the
navigation injection), the baseline scope against #220/#238/#253, and consolidation
measurements. v2 applied the author's first review (dependency closure, the OAuth product
naming, the RAR-free exclusion, bundle-level conformance, zones over shelves, edition
hardening, the human-enforced freeze gate, consolidation softened to a publication-time
decision) and was verified by independent fidelity and executability passes. v3 applied the
author's second review (single-snapshot pinning and publisher immutability rules; the
six-document conformance gate with a coverage threshold; the explicit PR edition-build step;
track validation and the OAuth Implementation Floor rename; the resolved freeze gate; retired
tier numbering; concrete out-of-edition navigation; the orthogonality statement). v3.1
applied the verb-taxonomy preservation ruling: the verb spine is the family's semantic
signature and is not replaced; zones become a manifest-validated adoption-map overlay, the
catalog's group-keyed (verb-spine) sections stay untouched, and the adoption map carries a
Verb column so the two axes stay joined. v3.2 added the AAuth Mission Context Bundle per the
author's directive, scoped from derived dependency closure: coherence-not-composition
membership, the upstream commit pin as the substance of frozen-until-upstream-release,
exploratory-only publication behind five gates, and the third presentation-track exception
case it surfaced. v3.3 corrected the Compose and Lab tracks to the composition axis. v3.4
applied the third review: the Mission-components track replaces the substrate-neutral claim
(portability is conditional and derived per document from its Substrate declaration, with
explicit compatibility metadata); `presentation_track` is required now, the deterministic
derivation having been falsified by the AAuth cluster; the Verb column ships as
Architectural group until the spine vocabulary is reconciled (diagram vs architecture:
contain and dispatch) and a validated per-document `verbs` array lands; the AAuth
non-exploratory gate gains substrate's inventory, claimed-capability coverage, and
composition tests; and the management-to-aauth manifest inconsistency is scheduled into
item 3 rather than left as a recorded call. Where this document and any earlier version
disagree, this document governs.
