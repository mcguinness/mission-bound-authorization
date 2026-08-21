<!-- regenerate: off (edited by hand; set to on to let i-d-template regenerate) -->

# Mission-Bound Authorization

An OAuth token says what a client may access. It does not say why,
for what approved task, under whose approval, or until when in terms
of the task itself. That gap is survivable when a human clicks every
consent screen; it is not survivable when autonomous agents hold
delegated authority for hours across many resources.

A **Mission** closes the gap: a durable, integrity-bound record of
the approved task — the intent, the derived Authority Set, the
Approver, and a lifecycle — recorded and retained by the Mission
control point. In the OAuth binding, a client proposes a **Mission
Intent**, the Mission Issuer derives an **Authority Set**, and the approval event
commits both as `intent_hash` and `authority_hash`. Issuance and
every derivation of authority are gated on the Mission's current
state, so revoking the Mission is a kill switch at the issuance
layer; runtime enforcement is the targeted overlay for the actions
that cannot wait for token expiry.

Read as one system, the drafts define a **delegated-authority
layer**: authentication says who is acting, and entitlement
governance says what a principal may hold; this layer governs the
approved task itself. The Mission Issuer is the control plane,
holding the approved task and distributing bounded authority; tokens
with the PEP/PDP boundary are its data plane.

The essential boundary: a Mission records the approved task and its
lifecycle. It does not replace OAuth authority syntax. RAR describes
requested and issued authority; the Mission explains why that
authority exists and gates its continued derivation and use.

## The standardization ask

The ask is not adoption of the suite. It is: adopt the Mission model
and the OAuth issuance profile as the stable substrate for task-bound
delegated authorization. Runtime, lifecycle, evidence, and
cross-domain profiles proceed as companion drafts on their own
timelines.

The suite takes its name from the model; the core's title,
"Mission-Bound Authorization for OAuth 2.0", names the binding the
core defines. The companions refer to the core as the **issuance
profile** (it governs issuance and derivation).

## Start here

| You want to… | Start with |
|---|---|
| Understand the model | [Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html) |
| Implement OAuth issuance | [The core](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) ([datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/)) |
| Build a PEP or PDP | [Runtime](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html), then its [AuthZEN binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html) |
| Review threats and trust | [Security Model](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-security-model.html) |

The rest of this page is the orientation; the links above are depth,
not prerequisites. For the story told in prose rather than protocol,
the **[Mission Handbook](https://notes.karlmcguinness.com/mission-handbook/)**
is the published narrative companion: the why before the wire.

## The architecture, in verbs

The family organizes along a verb spine: each verb answers one
question and is owned by named documents. The
[Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)
is the citable form of this view.

| Verb | The question | Main mechanisms |
|---|---|---|
| **Propose** | What task is being requested? | [Intent Shaping](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaping.html) (client-side, untrusted proposal) |
| **Approve and Record** | Who approved what, at which control point, under what governance? | [The core](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) and the other bindings (below); [Deferred Approval](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval.html); [Approval Governance](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-approval-governance.html); [Template](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-template.html) (consent once to a ceiling, instantiate at machine speed); [Substrate Requirements](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.html) for new bindings |
| **Govern** | How does the Mission change or end? | [Status](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-status.html) (pull), [Signals](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-signals.html) (push), [Expansion](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-expansion.html) (widen via a successor), [Containment](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-containment.html) (issuer-held monotonic narrowing), [Progressive Drawdown](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-progressive.html), [Metering](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-metering.html), [Discovery](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-discovery.html), [Management](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-management.html) |
| **Enforce Each Action** | May this exact action run now? | [Runtime contract](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html), [AuthZEN binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html), [Transaction Authorization](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-transaction-authorization.html), [Capability Binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-capability-binding.html) |
| **Run and Wind Down** | What happens across sessions, queues, and restarts? | [Harness](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-harness.html), [Orchestration](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-orchestration.html) |
| **Delegate** | Is new subordinate authority created? | [Child Delegation](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-child-delegation.html), [Offline Attenuation](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-attenuation.html), [Cross-Organizational Delegation](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-org-delegation.html) |
| **Project** | How is existing authority honored elsewhere? | [Cross-Domain Projection](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-domain.html), [Cross-Organizational Delegation](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-cross-org-delegation.html) |
| **Continue** | How does authorization survive a hop or a pause? | [Continuation](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-continuation.html) |
| **Prove** | What was approved, decided, and executed? | [Consent Evidence](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-consent-evidence.html), [Runtime Evidence](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-evidence.html), [Mandate](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-mandate.html), [Audit](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-audit.html) |
| **Analyze** | What is trusted, and what breaks if it fails? | [Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html), [Security Model](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-security-model.html) |

Two of these are easy to conflate and the spine keeps them apart:
**delegate** creates new subordinate authority (a Child Mission, an
attenuated token); **project** honors authority that already exists
in another trust domain, creating none. A document may live under
more than one verb: Cross-Organizational Delegation both delegates
(the attenuation chain narrows authority) and projects (a relying
party in another organization honors it).

## Choose a binding

The binding decides where the Mission control point lives.

| Binding | Use it when | The boundary to know |
|---|---|---|
| [**OAuth AS**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) (the core) | Your Authorization Server can issue Mission-bound tokens | Portable structured authority on the token; this is the issuance profile |
| [**Standalone MAS**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.html) | Existing Authorization Servers cannot host Mission approval | Ordinary credentials are *joined* to Missions; high-consequence paths require Mission-bound issuance (the [Issuance Grant](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-issuance-grant.html)) |
| [**AAuth**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth.html) | The Person Server owns contextual governance | Native AAuth access semantics, not the OAuth Authority Set |
| [**UMA**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-uma.html) / [**GNAP**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-gnap.html) | Protocol research and evaluation | Experimental sketches, authored against the substrate contract |

## Choose an assurance outcome

The [Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)
defines four Mission Assurance Levels, each with its proof
obligations; a deployment claims the level it has earned.

| Level | What it gives |
|---|---|
| **Baseline Issuance** | Approved, integrity-bound Missions and state-gated issuance: the kill switch is the issuance gate, and outstanding tokens run to their own expiry |
| **Runtime-Enforced** | A point-of-use permit before each consequential action, with durable decision and execution evidence |
| **Governed Agent** | Adds session-continuity stop (the harness) and proof of what the Approver saw (consent evidence) |
| **High-Assurance Agent** | Adds the named custody and containment claims: compromise-resistant custody and trifecta containment |

Deployments compose along the Architecture's four cumulative
reference stacks, from the protocol core alone to the high-assurance
agent architecture; the manifest transcribes them as
`reference_stacks` in
[`family-manifest.json`](family-manifest.json), with the issuer
binding and the freshness source modeled as explicit alternatives.
Binding properties and assurance claims remain per path; a stack
name never upgrades weaker paths. The transcription is validated in
CI and provisional until v0 proper passes its publication gate. (The
Architecture's five *packages* are its own orthogonal decomposition;
the manifest does not restate them.)

## The minimal implementation

The first useful piece is one profile, not the suite. A minimal
conforming deployment implements the core alone: Mission Intent
submission, Authority Set derivation, the committed Mission record
with its integrity anchors, the `mission` claim, and state-gated
issuance with revocation by Mission. The authoritative checklist,
including the distinct client and resource-server obligations, is
the core's
[Conformance section](https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html#name-conformance);
this page does not duplicate it.

What the core alone does **not** protect, by design:
already-issued tokens run to expiry (prompt cutoff needs
introspection, Status, or the runtime layer); completed actions are
not undone; off-path execution by a compromised agent is the runtime
and harness profiles' territory; prompt injection is constrained
(inert intent text, fixed authority), not prevented; and
information-flow leakage within approved authority is out of scope.

## Add capabilities by verb

Every optional companion composes independently under its verb in
the table above: pick the mechanisms the deployment needs and check
each document's maturity before adopting it. For adoption closure,
follow the manifest's typed `requires` edges — each document's
normative in-family dependencies, extracted from the drafts' own
reference sections and drift-checked in CI; the wider citation graph
is recorded separately as `references` and pulls in nothing. The
complete catalog with per-document summaries, maturity, and adoption
triggers is [`DRAFTS.md`](DRAFTS.md).

## Status

Maturity words are the family manifest's own: **stable**,
**experimental**, **sketch**, with informational documents shown as
**guide**. The core is the published editor's draft
([datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/));
companions are editor's copies on their own timelines.

- [`DRAFTS.md`](DRAFTS.md) — the complete document catalog (all 41)
- [`DEPENDENCIES.md`](DEPENDENCIES.md) — dependency status, inside and outside the family
- [`conformance-manifest.json`](conformance-manifest.json) — requirement-level conformance coverage
- [`family-manifest.json`](family-manifest.json) — the exhaustive machine-readable inventory

## Repository use

Drafts build with the IETF
[i-d-template](https://github.com/martinthomson/i-d-template):

```sh
make draft-mcguinness-oauth-mission.txt   # one draft
make                                       # everything
```

Validation:

```sh
node scripts/check-family-manifest.mjs        # inventory, catalog, metadata (chains the Statement check)
node scripts/check-conformance-manifest.mjs   # requirement rows against the spec texts
node scripts/generate-drafts-index.mjs --check # DRAFTS.md index freshness
```

Each manifest entry carries `verbs` (the spine position), a
one-sentence `summary`, a `pull_when` adoption trigger, `maturity`,
`maintenance`, and two typed edge sets: `requires` (the draft's
normative in-family references — the only edges that close
transitively for adoption) and `references` (the full in-family
citation graph, never used for closure). The Architecture's
reference stacks are transcribed in the top-level `reference_stacks`
object. The checker validates all of it, including that every
`requires` edge matches the draft's own normative reference list,
regenerates nothing silently (the DRAFTS.md index is checked for
freshness, never rewritten in CI), and holds this README to three
rules: it links the catalog and dependency reports, every backticked
draft token is a real manifest slug, and every editor's-copy link
targets one.

The reference implementation lives under [`src/`](src/) (a pnpm
monorepo; see [`src/DEMO.md`](src/DEMO.md) and
[`src/SPEC_VERSIONS.md`](src/SPEC_VERSIONS.md) for the spec-to-code
matrix). Contributions: see [`CONTRIBUTING.md`](CONTRIBUTING.md);
substantive design changes go issue-first.
