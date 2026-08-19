# Mission Adoption Plan (v5, plan of record)

Status: plan of record, 2026-08-18. The plan states decisions as fact; all revision history
lives in the Provenance section at the end. Refs #220, #238, #253.

**The problem.** The repository has a storefront problem, not a document-count problem. The
product inside the 41-document family is a small normative floor plus a preface, and a
newcomer currently meets all 41 as one flat surface.

**Success is measured from the adopter's side.** Pass rubric, written before the test:
unfamiliar readers select the correct documents for three scenarios (issuance-only OAuth;
Runtime-Enforced OAuth; an AAuth estate), scored on correct inclusion, correct exclusion,
and recognition of unsupported composition (a Mission component whose declaration their
binding does not satisfy), working from the README's first screen, unaided, within five
minutes per scenario. Run asynchronously with two or three readers; the result is logged as
a PLAN.md entry, pass or fail. Every other signal in this plan (fields, validators, gates)
is means, not ends.

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
- **The bundle is an OAuth product: the OAuth Mission Baseline Bundle** ("Runtime Baseline"
  is retired as the product name, since the product also publishes an issuance-only level;
  "Mission Core Profile" was retired earlier for its collisions). Its two published levels
  are the **OAuth Mission Issuance Baseline** and the **OAuth Mission Runtime-Enforced
  Baseline**, deliberately parallel to the Mission Assurance Levels they realize.
  **Bundle contents and minimum conformance profile are never synonymous**: the
  seven-document bundle is the reader edition's union; each level's exact normative slice is
  defined in the profile matrix (Baseline section). An issuance-only adopter is never told
  the runtime documents are mandatory, and the Issuance Baseline is never blocked on their
  conformance inventories.
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

**Reader-facing layer: the order menu.** The map's first reader test (the author, reading
the shipped compact track table cold) failed it: zone/track rows answer "where does this
document live", not "what do I order". The top layer is therefore a ten-pick menu sorted
into two levels. Level 1 lays down the necessary pieces of Mission-based authorization:
read the architecture; pick your binding (OAuth, AAuth, standalone authority server, or a
sketch); pick your runtime; pick your evidence. Level 2 grows breadth and depth across
use cases: shape your Mission and pick your approval complexity (each a table of named options ordered by growing capability, the two lanes
every end-to-end deployment decides; rank adjectives are never used as option labels);
pick your delegation (a complexity progression); run your agent (the agent-side stop and
unwind); adjust authority in flight (a named-direction table: widen, meet the unknown,
narrow, draw down, cap); operate the fleet (push notice and bulk lifecycle); a closing
shelf holds portable proof, the guide, and the remaining Lab items; the assurance menu closes
as the enforcement counterpart (the conformance baselines as cumulative levels). Maturity
on the menu is one vocabulary, mapped one-to-one from the family manifest's maturity field:
stable is unmarked, experimental and sketch mark readiness, and informational displays as
"guide" so document category is never mistaken for a readiness rung; no menu-local
readiness words are invented, and Compose bindings therefore read as stable peers of the
OAuth extensions. A fresh-eyes critique round hardened the menu: Level 1 concedes the
issuance exit up front (pick 2 alone is the floor); Level 2 and pick 3 carry explicit
OAuth-path scoping with the AAuth reading rule inline (per-document binding-compatibility
tags remain the Retrofit-wave spike); the approval-provenance option avoids colliding with
the Governed Agent baseline name; the baseline table is scoped to document-set baselines,
names its sets by document rather than pick number, and points to High-Assurance Agent as
condition-based; the shelf dissolved (proof pair to the evidence pick, the guide to pick 1,
a small evaluations list remains); and the validator gains menu-layer checks (slug
coverage, maturity-display agreement, pick-reference resolution, floor-referenced pairing)
so the menu's own claims are machine-checked, not just the matrix. The two-layer principle is unchanged: the menu is presentation, the
collapsed 41-row matrix remains the machine-validated layer carrying zone, track, group,
and per-document triggers, and the validator's placement checks bind to the matrix. Zones
and tracks stay authoritative in the manifest; the menu never regroups the catalog or the
verb spine.

**The adoption map is an overlay, never a regrouping.** The README's catalog keeps its
group-keyed sections; the map is a compact table near the top of the README (zone, track,
architectural group, documents, one-line trigger) carrying the five-minute path and linking
into the verb-organized catalog. The map first ships hand-written, straight from the
per-document table below, placed immediately after the README's at-a-glance opening block
and before "The architecture" (displacing nothing; the "Start with the Architecture" pointer
folds into the map's first row). To avoid a third unvalidated source of catalog truth, the map's PLACEMENT is
manifest-backed from day one: Ship 1 adds `presentation_zone` and `presentation_track` to
the family manifest and extends the existing validator to check that the map lists all 41
slugs exactly once, each under the zone and track the manifest declares. Only the map's
prose (the pull-triggers) is hand-authored. Two executor warnings: the README edit must not
alter the two exact headings the validator extracts ("The documents", "Adoption order"),
and the family manifest's `deps` arrays are inert to the validator (that edit is
informational). The richer metadata (compatibility fields, `verbs`) waits for the Retrofit
wave, whose entry condition is observable: the map has survived one success-rubric run
without structural rework. `presentation_zone` and `presentation_track` are required family-manifest fields, landing
in Ship 1 as stated above (track derivation from prefix
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
publications, and verifies every artifact against the bundle manifest's digests. An
immutable bundle's index and bibliography also expose the pinned normative-dependency URL
alongside the live editor's copy, so the reading path is as reproducible as the bytes.

## OAuth Mission Runtime Baseline v0

An implementation guide, not a 42nd I-D: it selects and pins existing normative text and
never invents requirements; it replaces discovering, ordering, and reconciling six documents
rather than adding a seventh.

**The profile matrix** (bundle contents are the reader edition's union; profiles are the
conformance slices):

| | Normative documents | Disabled conditionals |
|---|---|---|
| Bundle contents | substrate, core, status, runtime, runtime-evidence, authzen (+ architecture, informative preface) | listed per profile below |
| OAuth Mission Issuance Baseline | core (self-contained by design) | core's OPTIONAL capabilities as elected; Cross-Domain disabled |
| OAuth Mission Runtime-Enforced Baseline | the issuance slice plus substrate, status, runtime, runtime-evidence, authzen | Cross-Domain disabled; the transaction-assurance tier a named extension |

**Pinning is one coherent snapshot.** The bundle manifest carries a single
`source_repository_commit` covering every in-repository document (per-document last-modified
commits are informational traceability only, never assembly inputs); external dependencies
are pinned by repository, commit, and file path with a content digest; artifact digests and
the disabled-capability set complete it. Immutable editions build only from that snapshot.
External-pin work is asymmetric: ARAP has a copyable pin in SPEC_VERSIONS.md; the
Obligations Profile has no pin anywhere and is established from scratch.

**Two publications, honestly labeled.**
- **The preview ships in wave Ship 3** as `notes/oauth-mission-baseline-bundle-preview.md`,
  versioned `v0-preview.1` (never `v0`: a preview and the gated publication cannot share one
  version identity when bundles promise digest-verified immutability), tracked by a
  dedicated issue opened when Ship 2 completes. A publication claiming a coherent pin
  snapshot carries the machine-readable **bundle manifest with it**, so the manifest ships
  in Ship 3 too (only the immutable historical publisher waits for Retrofit). The preview
  carries the pin table (full SHAs and digests, the ARAP pin copied, the Obligations pin
  established), the reading order, and the two level definitions, and it carries NO
  conformance-coverage claims: today's numbers have an unknown denominator (13 tested, 5
  partial, 35 todo across an inventory that omits runtime, authzen, and substrate entirely,
  and runtime-evidence's six tested rows do not prove its inventory complete), and a partial
  number reads worse than none. Labeled preview, never marketed.
- **v0 proper** (the marketed publication; the identifier is reserved for it) adds the
  coverage ledger and waits on the completeness gate: every normative requirement in all six
  floor documents inventoried; zero uninventoried baseline requirements; zero todo rows on
  authorization invariants or fail-closed/refusal requirements; positive and negative tests
  for every baseline protocol surface; every partial row naming exactly what remains
  unproved; composition tests over the selected bundle; applicability narrowed to the
  baseline and expressed by machine, never manual judgment: each conformance-manifest
  requirement gains a `profiles` field enumerating which published baseline(s) it applies
  to (a separate bundle-conformance manifest was the alternative; the per-requirement field
  is the single source); exact external pins; the disabled-capability list; one overall
  coverage snapshot. #238's ledger discipline is a prerequisite; the Runtime-Enforced floor pins
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
path, content digest) is committed now, in a new `notes/external-pins.md` (a planning-pin registry, deliberately not
SPEC_VERSIONS.md, which describes implemented surfaces; one table: id, repo, ref, full
commit SHA, path, content digest, note, never abbreviated; the bundle manifest consumes it
at Ship 3); the bundle apparatus (manifest entry, aauth reader
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
inventory for the CORE bundle documents (substrate, the binding, and management; the expiry
profile's inventory and tests gate only the optional add-on edition), with tested coverage of the
capabilities the AAuth Statement claims plus AAuth-to-Substrate composition tests; an actual
AAuth implementation (none exists in src today); and the documentation-precision fix (README
and family-manifest language saying the binding "requires" the expiry profile overstates its
informative register; reconciled in the first execution wave). The management-to-aauth
family-manifest dependency is reconciled in the first wave too, default
align-manifest-to-citations (remove the stale dependency; it returns if the #445-slated
revision adds the citation); the override window closes when Ship 1c lands.

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

**Enforcement is staged by an explicit trigger.** In wave Ship 1: the `maintenance` enum
lands as family-manifest data with a one-line assertion in the existing validator (value in
the enum). The full gate, whose design is settled and waits only on its trigger: an
always-running required PR status check that fails when a frozen document changed without an
exception, re-running on `labeled`, `unlabeled`, `synchronize`, and ordinary PR events, with
a deeper checkout fetch for base diffs; an exception requires BOTH the designated label AND
approval from an authorized maintainer or CODEOWNER; branch protection prohibits direct
pushes to main. The rationale for staging: the apparatus defends against concurrent-editor
drift, which cannot occur with one committer, and main has no branch protection today.
**Triggers are operational repository events, recorded when they fire** (a labeled issue
plus a PLAN.md entry): the freeze trigger fires BEFORE merging the first PR authored by
anyone outside the maintainer set, or before granting additional write or triage access,
whichever comes first; "external adopter" fires on an issue identifying an adopter; the
AAuth trigger (below) fires on AAuth code landing in src, which is self-evident. Firing the
freeze trigger also extends CODEOWNERS, which today assigns owners to exactly one file and
none to the AAuth documents, so the gate's authorized-maintainer source exists before the
gate does. A trigger firing also ends this plan's implicit serial-execution
assumption. One decision rides the freeze trigger: the branch-protection rule collides with
the repository's convention of committing PLAN.md log entries directly to main; either the
convention moves to PRs or that path gets a named exemption.

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
| Ship 1 | Three small PRs, in order | 1a, append-only records: the AAuth pin record in `notes/external-pins.md`; the no-consolidation policy record. 1b, the storefront: bundle and zone/track vocabulary; the adoption map as a README table from the per-document table above, placed after the at-a-glance block, with `presentation_zone` and `presentation_track` landing in the family manifest and exact-membership validation (all 41 slugs once, each under its declared zone and track), the Architectural-group column, and the two executor warnings honored. 1c, precision and data: the expiry-framing fix; the management-to-aauth dependency reconciliation (default align-to-citations; the override window closes when 1c lands); the `maintenance` enum plus its one-line validator assertion |
| Ship 2 | Reader editions | The `make reader-editions` target and script, `latest` editions for the floor and Governed Agent lists, per the hardening rules above |
| Ship 3 | Preview (`v0-preview.1`) | `notes/oauth-mission-baseline-bundle-preview.md` plus the machine-readable bundle manifest (consuming `notes/external-pins.md`): the pin table with full SHAs and digests, reading order, level definitions per the profile matrix; NO coverage claims (the ledger joins v0 proper); tracked by a dedicated issue opened when Ship 2 completes |
| Ledger | Conformance inventories and tests (four tracked issues, each with an owner and acceptance criteria) | Inventory runtime, authzen, and substrate; prove runtime-evidence's inventory complete; add the missing positive, negative, and composition tests; add the per-requirement `profiles` field expressing Issuance vs Runtime-Enforced applicability |
| Retrofit | Richer metadata and publishing (entry condition: the map has survived one success-rubric run without structural rework) | The compatibility-metadata spike; the verb-spine vocabulary decision and then the `verbs` array; the Adoption-order supersession decision; the immutable publish path with the pinned-URL bibliography exposure; gh-pages publication of the preview |
| Gated | v0 proper | The completeness gate above, consuming the Ledger wave; then the marketed Issuance and Runtime-Enforced Baselines with the coverage ledger |
| Deferred | RAR-free mode | Behind #220 landing normatively |
| Trigger | Freeze gate; AAuth apparatus | The full freeze gate fires before merging the first PR authored outside the maintainer set or before granting additional write/triage access, and its firing extends CODEOWNERS (today one file, no AAuth owners) so the authorized-maintainer source exists before the gate; the AAuth bundle apparatus fires on AAuth code landing in src; every firing is recorded as a labeled issue plus a PLAN.md entry; the PLAN.md convention decision rides the freeze trigger |

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
action reduces to the committed pin. v4.1 applied the v4 critique (a ruling-fidelity audit,
a cold read, and an adversarial pass): it surfaces and flags a THIRD resequencing awaiting
the author's confirmation, that the third review ruled `presentation_zone`/
`presentation_track`, the compatibility-metadata shape, and the verb-spine decision into the
near-term PR while this plan places them in Retrofit; it repaired three table-prose
contradictions (the exploratory v0's wave, the maintenance enum's wave, the Ship 3 pin
source, now an inline guide table with the machine-readable bundle manifest at Retrofit); it
made Ship 3 startable (named file, tracked issue, no coverage claims until the denominator
exists); split Ship 1 into three PRs with the map-membership guard, the two executor
warnings, the pin record's named home, and the dependency-reconciliation override window
closed at 1c; gave the triggers tripwires; made the Retrofit entry condition observable; and
turned the success measure into a pre-written rubric with a logged result. v5 applied the
fourth author review, which settled the three outstanding resequencing flags: the third flag
resolved by ruling (the presentation fields and exact-membership validation return to Ship
1; the richer compatibility metadata and `verbs` are sanctioned to wait), and the first two
were accepted as refined (the freeze trigger became an operational repository event with a
CODEOWNERS extension; the pin registry was confirmed as `notes/external-pins.md` with full
SHAs and digests). Its five blocking corrections: the profile matrix separating bundle
contents from the two conformance slices (and the product renamed OAuth Mission Baseline
Bundle, since a Runtime name over an issuance-only level misled); the preview/v0 version
split with the bundle manifest moved into Ship 3; the Ship 1 metadata reversal above; the
restored Ledger execution wave for the conformance inventories, tests, and per-requirement
`profiles` field; and the AAuth gate split so the optional expiry add-on no longer gates
the core bundle. Its additional corrections: pinned bundles expose the pinned
normative-dependency URL beside the live copy; the success rubric became three scored
scenarios; and the guide replaces discovering, ordering, and reconciling, never reading.
Where this document and any earlier version disagree, this document governs.
