# Mission Adoption Plan (v4, plan of record)

Status: plan of record, 2026-08-18. The plan states decisions as fact; all revision history
lives in the Provenance section at the end. Refs #220, #238, #253.

**The problem.** The repository has a storefront problem, not a document-count problem. The
product inside the 41-document family is a small normative floor plus a preface, and a
newcomer currently meets all 41 as one flat surface.

**Success is measured from the adopter's side:** a first-time reader can name the six floor
documents and pick a track from the README's first screen, unaided. Checked by handing the
README to one outside reader and timing it; every other signal in this plan (fields,
validators, gates) is means, not ends.

Two manifests appear below and are always named in full: the **family manifest**
(`family-manifest.json`, the catalog's machine source of truth) and the **bundle manifest**
(a per-publication artifact defined in the Baseline section).

## Decisions

- **The bundle is seven documents: six normative plus a preface.** The OAuth Implementation
  Floor is substrate, core (oauth-mission), status, runtime, runtime-evidence, and authzen,
  with architecture as the informative reader preface. Substrate is a normative dependency
  of runtime, runtime-evidence, and authzen; runtime implementers consume its commitment
  construction and kernel contract. Cross-Domain is a conditional normative dependency the
  baseline disables. External normative dependencies (including AuthZEN's ARAP and
  Obligations profiles) are pinned alongside the family documents.
- **The bundle is an OAuth product:** working name **OAuth Mission Runtime Baseline v0**
  (alternative: Mission OAuth Adoption Bundle v0). "Mission Core Profile" is retired (it
  collided with the OAuth core draft and the Mission Deployment Profile, and implied the
  family as a whole is OAuth-shaped, which it is not). Its two published levels are the
  **OAuth Mission Issuance Baseline** and the **OAuth Mission Runtime-Enforced Baseline**,
  deliberately parallel to the Mission Assurance Levels they realize.
- **The RAR-free mode is excluded from v0.** It is protocol design, not packaging: it would
  override mandatory `authorization_details` carriage, define a new conformance mode, and
  create negotiation and downgrade requirements. It is an alternate projection mode, framed
  as `oauth-rar` and `oauth-scope-reference` modes with explicit discovery and no silent
  downgrade, and it waits for #220 to land normatively in core or a separate Standards-Track
  profile. Facts on record: template mode already derives an Authority Set without a
  submitted proposal; core introspection already returns audience-filtered
  `authorization_details`; Mission Status already returns the current audience-scoped set;
  the remaining gaps are mode negotiation, carriage overrides, reference-resolution
  behavior, failure semantics, privacy, and conformance. The PAR-ubiquity premise is not
  decision-grade; any wire-tier survey must test custom pushed parameters, Request Object
  preservation, approval rendering and policy hooks, JWT access-token claim customization,
  state-gated refresh, and extended introspection. The MAS entry ramp remains the answer for
  the immutable-IdP estate.
- **The verb taxonomy is the family's semantic signature and is never replaced.** The verb
  spine is carried by the README architecture diagram, the architecture document's spine,
  and the catalog's group-keyed sections (the spine's noun form). Zones answer "what do I
  adopt, and when"; verbs answer "what does this document do in the Mission's life". Zones
  land only as an overlay. One vocabulary decision is open and owned by the author: the
  README diagram carries contain and dispatch as rows while the architecture document's
  spine folds Containment into Govern and has no Dispatch heading; the canonical set is
  picked (update architecture, or shrink the diagram's list) before any per-document verb
  metadata is declared canonical.
- **Conformance disclosure is bundle-level and honest** (the gate is in the Baseline
  section).

## Zones and tracks

Three zones, with tracks along the composition axis. `oauth-mission-*` documents extend the
OAuth AS's wire surfaces and apply only to the OAuth path. **Mission components**
(`mission-*`) live outside the OAuth AS, which is all the naming rule promises: portability
is conditional, never implied by the prefix. A component composes with a binding only where
its Mission Substrate declaration is satisfied by that binding's supplied capabilities
(approval-governance imports OAuth-core approval objects and anchors; capability-binding
normatively depends on core, runtime, and authzen; neither is portable to the AAuth path
today). An AAuth adopter reads Compose as: pick your binding, take the Mission components
whose declarations your binding satisfies (checkable per document), skip the OAuth
extensions.

| Zone | Tracks | Contents |
|---|---|---|
| **Start** | Reader preface; OAuth Implementation Floor; Governed Agent Add-ons | architecture (preface); substrate, oauth-mission, status, runtime, runtime-evidence, authzen (floor); harness, consent-evidence (add-ons) |
| **Compose** | Bindings; OAuth extensions; Mission components; Security guide | authority-server, issuance-grant, the aauth cluster (bindings); expansion, child-delegation, cross-domain, signals, approval, management (OAuth extensions); audit, mandate, approval-governance, shaping, capability-binding (Mission components, compatibility per declaration); security-model (guide) |
| **Lab** | OAuth experimental; Mission experimental; Sketches | attenuation, containment, continuation, cross-org-delegation, progressive, template, transaction-authorization, approval-revision, work-products (OAuth experimental); discovery, metering, orchestration (Mission experimental); uma, aam, gnap (sketches) |

Two Lab documents are **floor-referenced**: containment and metering are named by property
in floor-document conditional text, so they receive active-tier responsiveness for exactly
that property while staying experimental (this is also a freeze class below).

**The adoption map is an overlay, never a regrouping.** The README's catalog keeps its
group-keyed sections; the map is a compact table near the top of the README (zone, track,
architectural group, documents, one-line trigger) carrying the five-minute path and linking
into the verb-organized catalog. The map first ships hand-written, straight from the
per-document table below, with no new metadata; the machine-validated form is a retrofit
(execution wave 2) once the map has stabilized. In the retrofit: `presentation_zone` and
`presentation_track` are both required family-manifest fields (track derivation from prefix
and group is not deterministic; the AAuth cluster falsifies it: management carries the
`mission-*` prefix and the lifecycle group, expiry carries neither recognized prefix and the
same group, both belong to Bindings), validated by table membership, with prefix/group kept
only as a cross-check that flags surprising assignments. The map's semantic column is
**Architectural group** (from the family manifest's `group`, which deliberately aggregates
verbs); a per-document `verbs` array validated against the canonical vocabulary is the
target once the spine decision above is made. Compatibility metadata for Mission components
(`applicable_bindings` or `required_substrate_capabilities`) is designed as its own spike
before it is populated; naming two candidates is not a schema. The existing README
"Adoption order" section remains alongside the map for now; whether the map supersedes it is
decided at retrofit time. Four family-manifest fields are orthogonal by convention:
`maturity` (specification stability), `maintenance` (repository responsiveness),
`presentation_zone`/`presentation_track` (adoption placement), `group` (architectural
grouping); none implies any of the others.

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
| aauth-mission-expiry | Compose / bindings | A citable profile of AAuth's native `expires_at` is needed (base AAuth enforces it regardless; the profile's own conformance line is OPTIONAL). |
| oauth-mission-expansion | Compose / OAuth extensions | Approved authority will predictably need to widen mid-task via fresh approval. |
| oauth-mission-child-delegation | Compose / OAuth extensions | A sub-agent needs its own Mission outliving a call frame, with cascade termination. |
| oauth-mission-cross-domain | Compose / OAuth extensions | A Mission from one trust domain must be honored by an AS in another (also the floor's conditional dependency). |
| oauth-mission-signals | Compose / OAuth extensions | Consumers need push notice of state changes instead of polling per Mission. |
| oauth-mission-approval | Compose / OAuth extensions | Approval is asynchronous: a human review queue, not an immediate decision. |
| oauth-mission-management | Compose / OAuth extensions | An operator needs fleet enumeration and bulk lifecycle across many Missions. |
| mission-audit | Compose / Mission components | A cross-domain party must verify evidence integrity without trusting issuer logs. |
| mission-mandate | Compose / Mission components | An outside party must verify what was approved without a token-exchange hop. |
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

Per-edition HTML copies with a navigation bar injected as a sibling element beside the empty
`external-metadata` div xml2rfc already emits, an ordered index page, and a concatenated
**bundle text** (cover, edition manifest, form-feed separators). Copies, never
canonical-file injection; edition-prefixed flat filenames (the gh-pages install rule strips
path components); the build fails unless exactly one insertion point exists per file. True
inlining stays rejected (two built files alone share 242 element ids), as does a
single-kramdown merge (semantic surgery across 18,771 source lines).

Links take two branches by necessity, since floor documents cite outside the floor (authzen
cites harness and metering): in-edition citations are rewritten to edition-local files (the
target is narrow: bibliography entries whose href matches the family's own gh-pages host);
out-of-edition links are visibly marked, open in a new tab with `rel="noopener"` leaving the
edition tab intact, and every copied page carries a permanent edition-index link; no
query-parameter return mechanism. Front-matter external links stay untouched; the relative
`.xml` alternate link is fixed or dropped once filenames are edition-prefixed.

Editions build via an explicit `make reader-editions` step on both pull_request and push
(explicit so edition failures stay distinguishable from draft failures; the ghpages target
runs only on push, so PR coverage requires the step). The edition job builds every member
from source in a clean checkout, runtime-evidence included; it never reuses prebuilt
artifacts. The Bundler lockfile issue is a contributor-machine fix, not a repo change. A
second Governed Agent edition (floor plus harness and consent-evidence) is the same
machinery with a second document list. A moving `latest` edition publishes now; immutable
versioned bundles are part of the retrofit wave and need a dedicated publish path (verified:
`GHPAGES_EXTRA` cannot carry them on the default branch), whose publisher refuses to
overwrite an existing version with different bytes, serializes concurrent Pages
publications, and verifies every artifact against the bundle manifest's digests.

## OAuth Mission Runtime Baseline v0

An implementation guide, not a 42nd I-D: it selects and pins existing normative text and
never invents requirements; it replaces reading six documents rather than adding a seventh.

**Pinning is one coherent snapshot.** The bundle manifest carries a single
`source_repository_commit` covering every in-repository document (per-document last-modified
commits are informational traceability only, never assembly inputs); external dependencies
are pinned by repository, commit, and file path with a content digest; artifact digests and
the disabled-capability set complete it. Immutable editions build only from that snapshot.
External-pin work is asymmetric: ARAP has a copyable pin in SPEC_VERSIONS.md; the
Obligations Profile has no pin anywhere and is established from scratch.

**Two publications, honestly labeled.**
- **Exploratory v0 ships in the first execution wave**, on today's coverage, labeled
  exploratory and never marketed as conformance-ready. Today's known aggregate for the floor:
  13 tested, 5 partial, 35 todo, with runtime, authzen, and substrate uninventoried
  (runtime-evidence's six tested rows do not prove its inventory complete).
- **The marketed v0** waits on the completeness gate: every normative requirement in all six
  floor documents inventoried; zero uninventoried baseline requirements; zero todo rows on
  authorization invariants or fail-closed/refusal requirements; positive and negative tests
  for every baseline protocol surface; every partial row naming exactly what remains
  unproved; composition tests over the selected bundle; applicability narrowed to the
  baseline; exact external pins; the disabled-capability list; one overall coverage
  snapshot. #238's ledger discipline is a prerequisite; the Runtime-Enforced floor pins
  today's runtime text verbatim and re-pins if #238's re-cut lands.

The worked example stitches demo scenarios 1, 2, and 8; the revocation-denial leg is
required because prompt cutoff is the entire value of the Runtime-Enforced level over the
Issuance level.

## AAuth Mission Context Bundle

The AAuth-path counterpart, named from the binding's own Mission Context vocabulary. **The
near-term action is the pin, not the apparatus:** today's upstream citation carries no
revision pin at all (the seriesinfo was removed in the #472 alignment; the front-matter
target is the live editor's copy), and datatracker's -10 is a divergent pre-person-token
document. The pin record (repo `dickhardt/AAuth`, PR #73 merged, commit `f156926...`, file
path, content digest) is committed now; the bundle apparatus (manifest entry, aauth reader
editions, exploratory publication) is built when a first AAuth implementation exists, and it
reuses the OAuth bundle's machinery.

**Membership (coherence, not composition).** Derived from front matters: the cluster's only
in-family normative edge is mission-aauth to substrate; management never cites mission-aauth;
expiry has zero family dependencies. Members: substrate (floor), mission-aauth and
mission-aauth-management (core; management is the kill switch, without it the bundle has
completion and expiry but no revocation or status query), aauth-mission-expiry as add-on
(informative register, OPTIONAL by its own conformance line, base-enforced natively),
architecture as preface. Status, runtime, and authzen are structurally excluded (each roots
normatively in the OAuth core); PDP-over-AAuth is unspecified and stays out until requested
(flagged author call: whether it gets a named out-of-scope mention).

**Gates beyond exploratory:** an upstream release reaching the pinned commit; a conformance
inventory for the three cluster documents AND substrate, with tested coverage of the
capabilities the AAuth Statement claims plus AAuth-to-Substrate composition tests; an actual
AAuth implementation (none exists in src today); and the documentation-precision fix (README
and family-manifest language saying the binding "requires" the expiry profile overstates its
informative register; reconciled in the first execution wave). The management-to-aauth
family-manifest dependency is reconciled in the first wave too, default
align-manifest-to-citations (remove the stale dependency; it returns if the #445-slated
revision adds the citation), author override open.

## Freeze policy

Five maintenance classes, machine-enumerated and human-enforced (`maturity` is spec
stability; `maintenance` is repository responsiveness; neither implies the other):

| Class | Promise | Assigned to |
|---|---|---|
| `active` | Full peer-symmetry maintenance | Floor and add-on tracks, OAuth extensions, Mission components, authority-server, issuance-grant, approval, attenuation (the last two on merits, with their unratified DTR and Attenuating-Agent-Tokens dependencies named) |
| `active-experimental` | Active maintenance while experimental, earned by implementation evidence | transaction-authorization (14/6/1), cross-org-delegation (9 of 9 tested); promotion is always a human decision informed by a named maintenance owner, an active implementation, a complete conformance inventory for the implemented surface, meaningful tested coverage, and a scheduled review horizon |
| `frozen-until-upstream-release` | Text fixes only; shape changes wait on the upstream | The AAuth cluster (wholly derivative of AAuth's unratified wire shape) |
| `lab-floor-referenced` | Lab maturity; active-tier responsiveness for the property floor text points at | containment, metering |
| `lab-best-effort` | Best effort, no cadence; the gate out of the Lab: a Mission Substrate Statement where a new substrate is bound, the abstract drops deferred/sketch language, a named adopter or implementer commitment on record, and category/maturity/rung updated together in one PR | uma, aam, gnap, remaining Lab documents |

**Enforcement is staged by an explicit trigger.** Immediately: the `maintenance` enum lands
as family-manifest data with a one-line assertion in the existing validator (value in the
enum). The full gate, whose design is settled and waits only on its trigger (the first
second contributor or external adopter): an always-running required PR status check that
fails when a frozen document changed without an exception, re-running on `labeled`,
`unlabeled`, `synchronize`, and ordinary PR events, with a deeper checkout fetch for base
diffs; an exception requires BOTH the designated label AND approval from an authorized
maintainer or CODEOWNER; branch protection prohibits direct pushes to main. The rationale
for staging: the apparatus defends against concurrent-editor drift, which cannot occur with
one committer, and main has no branch protection today. One decision rides the trigger: the
branch-protection rule collides with the repository's convention of committing PLAN.md log
entries directly to main; either the convention moves to PRs or that path gets a named
exemption.

## Consolidation and retirement

No consolidation before WG adoption, recorded as policy: reader editions are the chosen
remedy now, and the lifecycle and runtime/evidence boundaries are reconsidered only at WG
adoption or publication planning. The measured basis: the approval pair has a hard
maturity-mixing toolchain blocker; the only citation-viable pair (runtime plus
runtime-evidence, 53 mutual citations) would create the family's largest document and a
29-file retarget dominated by authzen's 89 citations; the lifecycle group's natural reader
edition is the family manifest's own 9-document group. `aauth-mission-expiry` retirement
goes upstream-first: contribute the RFC 3339 precision and prompt-transition requirements to
AAuth itself, and retire the standalone profile only if upstream absorbs them; folding it
into the Mission AAuth binding stays rejected (it would strand the bare-AAuth audience).

## Execution order

Value first; metadata retrofits after the map stabilizes; heavy governance waits on its
trigger.

| Wave | Work | Contents |
|---|---|---|
| Ship 1 | Rename + hand-written adoption map (one small PR) | Bundle and zone/track vocabulary; the adoption map as a plain README table built from the per-document table above, no new metadata; substrate-into-floor and dependency-closure prose; the no-consolidation policy record; the expiry-framing precision fix; the management-to-aauth dependency reconciliation; the AAuth pin record committed |
| Ship 2 | Reader editions | The `make reader-editions` target and script, `latest` editions for the floor and Governed Agent lists, per the hardening rules above |
| Ship 3 | Exploratory v0 | The guide body on today's coverage, labeled exploratory, with the pin snapshot and the honest ledger; owner: the author's next session |
| Retrofit | Manifest and validation | `presentation_zone` + `presentation_track` (required), table-membership validation, Architectural-group column, `maintenance` enum + one-line validator assertion; the compatibility-metadata spike; the verb-spine vocabulary decision and then the `verbs` array; the Adoption-order supersession decision; the bundle manifest and the immutable publish path |
| Gated | Marketed v0 | The six-document completeness gate above; then the marketed Issuance and Runtime-Enforced Baselines |
| Deferred | RAR-free mode | Behind #220 landing normatively |
| Trigger | Freeze gate; AAuth apparatus | The full freeze gate on the first second contributor or external adopter (with the PLAN.md convention decision); the AAuth bundle apparatus on the first AAuth implementation |

## Provenance

v1 explored packaging, the reader-edition build (working prototype of the nav injection),
baseline scope against #220/#238/#253, and consolidation measurements. v2 applied the
author's first review (dependency closure, OAuth product naming, RAR-free exclusion,
bundle-level conformance, zones over shelves, edition hardening, human-enforced freeze,
consolidation as a publication-time decision) and was verified by independent fidelity and
executability passes. v3 applied the second review (single-snapshot pinning and publisher
immutability, the six-document conformance gate and coverage threshold, the explicit PR
edition-build step, track validation, retired tier numbering, concrete out-of-edition
navigation, orthogonality). v3.1 preserved the verb taxonomy as the semantic signature and
made zones an overlay. v3.2 added the AAuth Mission Context Bundle from derived dependency
closure. v3.3 aligned tracks to the composition axis. v3.4 applied the third review
(Mission-components portability made conditional and checkable, `presentation_track`
required, the Architectural-group column, substrate added to the AAuth gate, the manifest
reconciliation scheduled). v4 is a fresh-eyes rewrite: same decisions, plan-as-fact register,
history confined to this section, the adopter-side success measure added, the first-wave PR
right-sized, the exploratory v0 given an execution line and owner, and two resequencings
flagged for the author's confirmation in the PR: the freeze gate's settled design now waits
on an explicit trigger rather than riding the first wave, and the AAuth bundle's near-term
action reduces to the committed pin. Where this document and any earlier version disagree,
this document governs.
