<!-- regenerate: off (edited by hand; set to on to let i-d-template regenerate) -->

# Mission-Bound Authorization

An OAuth token says what a client may access. It does not say why,
for what approved task, under whose approval, or until when in terms
of the task itself. A conventional access token can establish what
access it authorizes; the token alone cannot establish whether the
task it serves is still approved.
That gap is survivable when a human clicks every consent screen. It
is not survivable when autonomous agents hold delegated authority
for hours across many resources, and the moment it bites is always
the same one: something looks wrong, and there is no object to ask
what this task is still allowed to do, or how to wind it down.

A **Mission** is that object: a durable, integrity-bound record of
the approved task (the intent, the derived Authority Set, the
Approver, and a lifecycle), recorded and retained by the Mission
control point. In the OAuth binding, a client proposes a **Mission
Intent**, the Mission Issuer derives an **Authority Set**, and the
approval event commits both as `intent_hash` and `authority_hash`,
making later alteration detectable to a verifier that retains or can
independently establish those commitments. Authority is
derived from the approved task, never asserted by a client or
inferred by a model. Issuance and issuer-mediated derivation are
gated on the Mission's current state: revocation stops the Mission
Issuer from minting or deriving further authority, while already
materialized credentials and downstream grants run only to their own
lifetimes unless state-aware runtime enforcement cuts off their use
sooner.

On the wire, one small claim rides every derived token:

```json
{ "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://as.example.com",
    "authority_hash": "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ" } }
```

It joins issuance, enforcement, and audit to one approved task, and
it is deliberately small: the record stays at the issuer, and the
token's `authorization_details` still carry the authority itself.

Read as one system, the drafts define a **delegated-authority
layer**. Authentication says who is acting; entitlement governance
says what a principal may hold; this layer answers the remaining
question: what work was approved, and is it still in force. The
Mission Issuer is the control plane, holding the approved task and
distributing bounded authority. Tokens, and the policy enforcement
and decision boundary (PEP/PDP) that checks them, are its data
plane.

The essential boundary: a Mission records the approved task and its
lifecycle, and replaces none of the systems around it. RAR (Rich
Authorization Requests, RFC 9396) still describes requested and
issued authority; the Mission explains why that authority exists and
gates its continued derivation. Agent identity still says who is
acting; the Mission says what for. Policy engines still decide each
action; the Mission supplies the task, authority, and lifecycle
context a Mission-aware decision consumes.

## The standardization ask

The ask is not adoption of the suite. It is: adopt the Mission model
and the OAuth issuance profile as the stable substrate for task-bound
delegated authorization. Runtime, lifecycle, evidence, and
cross-domain profiles proceed as companion drafts on their own
timelines. The suite's size is evidence of thinking, not the ask:
everything beyond that chartering surface enters scope only as the
community pulls it.

The suite takes its name from the model; the core's title,
"Mission-Bound Authorization for OAuth 2.0", names the binding the
core defines. The companions refer to the core as the **issuance
profile** (it governs issuance and derivation).

## Composes with what you already run

| You already run | The relationship |
|---|---|
| RAR (RFC 9396) | The Authority Set's wire syntax; the Mission adds the approved task it is derived from |
| Token Exchange and `act` (RFC 8693) | The rail AS-mediated delegation and continuation ride; offline attenuation deliberately works without it |
| Cross-App Access (XAA), via ID-JAG | The cross-domain rail the projection profile binds Missions to |
| Transaction Tokens | A different-layer neighbor: call-chain context within a domain, while the Mission is the durable task record above it |
| AuthZEN | The decision wire the runtime contract binds to |
| Security Event Tokens (RFC 8417) / OpenID Shared Signals Framework | The rail lifecycle Signals ride |

Every row composes; none competes.

## Start here

| You want to… | Start with |
|---|---|
| Understand the model | [Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html) |
| Implement OAuth issuance | [The core](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) ([datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/)) |
| Build a PEP or PDP | [Runtime](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html), then its [AuthZEN binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html) |
| Run agents under a Mission | [Harness](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-harness.html), then [Runtime](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html) |
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
| **Approve and Record** | Who approved what, at which control point, under what governance? | [The core](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) and the other bindings (below); [Deferred Approval](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval.html); [Approval Governance](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-approval-governance.html); [Template](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-template.html) (consent once to a ceiling, instantiate at machine speed) |
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
| [**Standalone MAS**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.html) (Mission Authority Server) | Existing Authorization Servers cannot host Mission approval | Ordinary credentials are *joined* to Missions; high-consequence paths require Mission-bound issuance (the [Issuance Grant](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-issuance-grant.html)) |
| [**AAuth**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth.html) | AAuth's Person Server (the user-held control point) owns contextual governance | Native AAuth access semantics, not the OAuth Authority Set |
| [**UMA**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-uma.html) / [**GNAP**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-gnap.html) | Protocol research and evaluation | Experimental sketches, authored against the substrate contract |

New bindings are authored against
[Substrate Requirements](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.html)
and claim their capabilities through a Mission Substrate Statement.

## Choose an assurance outcome

The [Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)
defines four Mission Assurance Levels, each with its proof
obligations; a deployment claims the level it has earned.

| Level | What it gives |
|---|---|
| **Baseline Issuance** | Approved, integrity-bound Missions and state-gated issuance: where the binding issues Mission-bound credentials, the kill switch is the issuance gate, and outstanding tokens run to their own expiry |
| **Runtime-Enforced** | A point-of-use permit before each consequential action, with durable decision and execution evidence |
| **Governed Agent** | Adds session-continuity stop (the harness) and proof of what the Approver saw (consent evidence) |
| **High-Assurance Agent** | Adds the level's two named claims: agent-compromise-resistant enforcement and trifecta containment |

Deployments compose along the Architecture's four cumulative
reference stacks, from the protocol core alone (Baseline Issuance)
to the high-assurance architecture (High-Assurance Agent). The
stacks are the Architecture's OAuth realization; the binding
decision stays in the table above, and the other bindings realize
the levels per their own documents (standalone MAS reaches an
issuance gate only by composing the Issuance Grant; AAuth reports
native capabilities, with the Person Server's contextual gate as its
per-action analogue). Binding properties and assurance claims remain
per path; a stack name never upgrades weaker paths.

## The minimal implementation

The first useful piece is one profile, not the suite. A minimal
conforming deployment implements the core alone: Mission Intent
submission, Authority Set derivation, the committed Mission record
with its integrity anchors, the `mission` claim, and issuance
bounded by the subset rule and gated on Mission state (revocation by
Mission is the kill switch). The authoritative checklist,
including the distinct client and resource-server obligations, is
the core's
[Conformance section](https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html#name-conformance);
this page does not duplicate it.

What the core alone does **not** protect, by design:
already-issued tokens run to expiry (prompt cutoff needs
introspection, Status, or the runtime layer); completed actions are
not undone; off-path execution by a compromised agent is the runtime
layer's territory; prompt injection is constrained
(inert intent text, fixed authority), not prevented; and
information-flow leakage within approved authority is out of scope.

## Add capabilities by verb

Every optional companion composes independently under its verb in
the table above: pick the mechanisms the deployment needs, check
each document's maturity before adopting it, and follow the
manifest's `adoption_requires` edges for what a draft cannot be
deployed without. The complete catalog with per-document summaries,
maturity, and adoption triggers is [`DRAFTS.md`](DRAFTS.md).

## Running code

The reference implementation under [`src/`](src/) (a pnpm monorepo)
implements the core and the runtime, lifecycle, delegation, and
transaction surfaces tracked row-by-row in
[`src/SPEC_VERSIONS.md`](src/SPEC_VERSIONS.md);
[`src/DEMO.md`](src/DEMO.md) runs the flow end to end.
[`conformance-manifest.json`](conformance-manifest.json) maps each
inventoried requirement in its audited specification set to tested,
partial, or todo coverage.

## Status

The core is a published Internet-Draft on the IETF
[Datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/);
the companions are editor's copies in this repository, on their own
timelines. Maturity words (**stable**, **experimental**, **sketch**,
with informational documents shown as **guide**) are this
repository's own labels, not IETF statuses.

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
`maintenance`, and typed edges in two layers: the extracted citation
graph (`normative_references` and `references`, drift-checked both
ways against each draft's own front matter) and the authored
adoption graph (`adoption_requires`, the unconditional deployment
dependencies that alone close transitively, validated as a subset of
the normative references; and `requires_when`, conditional edges
naming what activates them; a normative reference is not a
deployment dependency). The Architecture's OAuth reference stacks
are transcribed in the top-level `reference_stacks` object, with the
freshness source modeled as explicit alternatives; the transcription
is structurally validated in CI (fidelity to the Architecture's
prose is an editorial obligation) and provisional until v0 proper
passes its publication gate, and the Architecture's five *packages*,
its own orthogonal decomposition, are not restated here.
The checker validates the structure of all of it, regenerates
nothing silently (the DRAFTS.md index is checked for freshness,
never rewritten in CI), and holds this README to three rules: it
links the catalog and dependency reports, every backticked draft
token is a real manifest slug, and every editor's-copy link targets
one.

Contributions: see [`CONTRIBUTING.md`](CONTRIBUTING.md);
substantive design changes go issue-first.
