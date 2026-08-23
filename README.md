<!-- regenerate: off (edited by hand; set to on to let i-d-template regenerate) -->

# Mission-Bound Authorization

An access token carries authority for a resource request. It
does not, by itself, establish the approved task that caused the
authority to exist, or whether that task remains approved. The gap
matters little while a human clicks every consent screen. It becomes
material when autonomous agents hold delegated authority for hours
across many resources, and the moment it bites is always the same
one: something looks wrong, and there is no object to ask what this
task is still allowed to do, or how to wind it down.

A **Mission** is that object: a durable, integrity-bound record of
the approved task (the intent, the derived Authority Set, the
Approver, and a lifecycle), recorded and retained by the Mission
control point. Identity answers who is acting. Entitlements answer
what a principal may hold. A Mission answers the remaining question:
what work was approved, and is it still in force. It replaces
neither of the first two, and it sits above grants and tokens rather
than replacing them.

The model is four objects, with lifecycle cutting vertically through
the last three:

- **Intent**: the proposed work, submitted by a client and inert
  until approved.
- **Mission**: the approved, governed work, the record everything
  below derives from.
- **Authority**: the approved, bounded Authority Set for the work;
  tokens, grants, projections, and delegations carry or derive
  subsets of it.
- **Action**: one concrete use of that authority at a resource or
  through a decision point.

A client or a model may propose the Intent and candidate authority;
no proposal is authoritative. The Mission control point (in the
OAuth binding, the Mission Issuer) derives and bounds the Authority
Set under policy, and the approval event commits the intent and the
derived set as `intent_hash` and `authority_hash` (and the submitted
proposal, where one was made, as `proposal_hash`, keeping
what-was-asked distinct from what-was-granted), making later
alteration detectable to a verifier that retains or can
independently establish those commitments. Issuance and
issuer-mediated derivation take Mission state as authoritative
input: revocation stops the Mission Issuer from minting or deriving
further authority, while already materialized credentials and
downstream grants run only to their own lifetimes unless state-aware
runtime enforcement cuts off their use sooner.

Read as one system, the drafts define a **delegated-authority
layer**: the Mission Issuer is the control plane, holding the
approved task and distributing bounded authority; tokens, and the
policy enforcement and decision boundary (PEP/PDP) that checks them,
are its data plane.

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

## One Mission, end to end

> "Reconcile the Q3 payables and pay approved vendors, up to 500 USD
> per invoice, by Friday."

1. The agent proposes that as a **Mission Intent**, with candidate
   `authorization_details` for the accounting and payments APIs.
2. The Mission Issuer derives a bounded Authority Set; the user
   approves; Mission `M1` is `active`, all three anchors committed
   (`intent_hash` over the task, `proposal_hash` over what the agent
   asked for, `authority_hash` over what was granted).
3. The agent obtains tokens for the accounting API and the payments
   API; each carries the `mission` claim naming `M1`.
4. It delegates invoice classification to a sub-agent under a
   narrower Child Mission with `M1` as parent.
5. Fraud monitoring suspends `M1`. New issuance and refresh stop at
   the issuer for the whole tree; a Runtime-Enforced deployment also
   denies the next payment action at the decision point.
6. The audit question has an answer: which approved undertaking
   caused this payment, who approved it, and what exactly did they
   approve?

OAuth already handles each credential issuance in that story. The
Mission is the object that connects them into one governed
undertaking. The walkthrough is the OAuth realization; the peer
bindings realize the same kernel on their own substrates, each
declaring its lifecycle capabilities in its Mission Substrate
Statement.

## What a Mission is not

Not merely an OAuth grant with metadata. A grant, a consent record,
a refresh family, or a PDP record can be durable and
lifecycle-bearing within one Authorization Server's administrative
domain; durability is not the difference. What none of them
standardizes is the approved-task object: the Mission joins many
grants, credentials, actors, and evidence producers (and, through
projection, trust domains) to one committed, integrity-anchored
undertaking that can create subordinate authority and be ended as
one object at its control point, with the already-materialized
credentials running to their own lifetimes unless state-aware
enforcement cuts them off sooner (a residual the drafts document
rather than hide).

Nor is it the neighbors it composes with. RAR (Rich Authorization
Requests, RFC 9396) still describes requested and issued authority;
the Mission is the approved task that authority derives from, and
Mission state is authoritative input to the gates on its continued
derivation. A workflow, job, or session identifier names execution
state and carries no approved authority; a Mission is an
authorization object with an Approver and a lifecycle. A Transaction
Token carries call-chain context within a domain for one request;
the Mission is the durable task record above it. Agent identity
still says who is acting; the Mission says what for. Policy engines
still decide each action; the Mission supplies the task, authority,
and lifecycle context a Mission-aware decision consumes.

## The standards proposal

The proposed standardization surface is three layers: the
informative **Architecture** (the model), the normative **Mission
Substrate Requirements** (the binding-neutral kernel contract, which
publishes before or with any binding claiming conformance to it),
and one complete binding for the substrate with the most deployed
infrastructure: the **OAuth issuance binding**. The choice of first
binding is infrastructure, never maturity; no production Mission
deployment is known today on any binding. The remaining
documents are design exploration and independently selectable
companion work with declared dependencies (runtime, lifecycle,
evidence, and cross-domain profiles on their own timelines), not a
request to standardize a 41-document suite. Anything beyond that
chartering surface enters
scope only as the community pulls it.

The suite takes its name from the model; the OAuth binding's title,
"Mission-Bound Authorization for OAuth 2.0", names what it is: one
binding of the model. Its OAuth companions refer to it as the
**issuance profile** (it governs issuance and derivation on that
substrate).

## The minimal implementation

The first useful piece is one binding, not the suite. A minimal
conforming OAuth deployment implements the OAuth binding alone:
Mission Intent
submission, Authority Set derivation, the committed Mission record
with its integrity anchors, the `mission` claim, and issuance
bounded by the subset rule and gated on Mission state (revocation by
Mission is the kill switch). The authoritative checklist,
including the distinct client and resource-server obligations, is
the binding's
[Conformance section](https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html#name-conformance);
this page does not duplicate it.

What that binding alone does **not** protect, by design:
already-issued tokens run to expiry (prompt cutoff needs
introspection, Status, or the runtime layer); completed actions are
not undone; off-path execution by a compromised agent is the runtime
layer's territory; prompt injection is constrained
(inert intent text, fixed authority), not prevented; and
information-flow leakage within approved authority is out of scope.

## Start here

Three rings, smallest first; each ring is complete without the next:

- **The model and a binding**: [Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html) (the
  informative model), plus one binding's dependency-closed adoption
  set from the peer table below (the manifest's `adoption_requires`
  edges name each binding's floor). The
  [Substrate Requirements](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.html)
  (the binding-neutral kernel contract) are for binding authors and
  for reviewers validating a mapping; whether an adopter also needs
  them is each binding's own declared adoption closure (the
  `adoption_requires` edges): the OAuth binding is self-contained
  and never requires them, while several peer bindings and the
  runtime documents pull the substrate in as a dependency. For an OAuth estate that is
  [the OAuth binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html)
  alone: one self-contained document, and a useful deployment by
  itself. The peer bindings declare their own floors.
- **Runtime-enforced profile** (shown on the OAuth binding): add
  [Substrate Requirements](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-substrate.html)
  (the kernel contract the runtime documents consume),
  [Status](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-status.html)
  (or another freshness source), the
  [Runtime contract](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html),
  [Runtime Evidence](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime-evidence.html), and the
  [AuthZEN binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html) for a point-of-use
  permit before each consequential action.
- **Optional capabilities**: approval workflows, delegation,
  cross-domain projection, agent harnessing, evidence, and fleet
  management, each selectable on its own with its declared
  dependencies; [`DRAFTS.md`](DRAFTS.md) is the complete catalog. Two
  easy-to-miss pieces earn an early look: the work-product
  commitment model (results carry integrity, not only actions: the
  OAuth binding's Integrity and Commitments section) and the swarm
  ladder
  (one agent to a fleet without new machinery: the Architecture's
  scaling treatment).

The runtime ring in one breath: a gateway (the PEP) sits where the
agent's actions leave its boundary; before a consequential action it
asks a decision service (the PDP) whether this action, with these
concrete parameters, may run under this Mission right now; the
answer is grounded in the Mission's current authority and lifecycle
state, and it expires in minutes. Everything in the runtime
documents elaborates that sentence: what counts as consequential,
where the gate sits, how fresh "right now" must be, and what
evidence a permit or refusal leaves behind.

| You want to… | Start with |
|---|---|
| Understand the model | [Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html) |
| Implement OAuth issuance | [The OAuth binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) ([datatracker](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/)) |
| Build a PEP or PDP | [Runtime](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html), then its [AuthZEN binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authzen.html) |
| Run agents under a Mission | [Harness](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-harness.html), then [Runtime](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-runtime.html) |
| Review threats and trust | [Security Model](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-security-model.html) |

The rest of this page is the reference layer; the links above are
depth, not prerequisites. For the story told in prose rather than
protocol, the
**[Mission Handbook](https://notes.karlmcguinness.com/mission-handbook/)**
is the published narrative companion: the why before the wire.

## Composes with what you already run

| You already run | The relationship |
|---|---|
| RAR (RFC 9396) | The Authority Set's wire syntax; the Mission adds the approved task it is derived from |
| Token Exchange and `act` (RFC 8693) | The AS-mediated delegation rail; the Mission binding preserves the governed task across derived authority (offline attenuation deliberately works without it) |
| Cross-App Access (XAA), via ID-JAG | The cross-domain rail the projection profile binds Missions to |
| Transaction Tokens | A different-layer neighbor: call-chain context within a domain, while the Mission is the durable task record above it |
| AuthZEN | The decision wire the runtime contract binds to |
| Security Event Tokens (RFC 8417) / OpenID Shared Signals Framework | The rail lifecycle Signals ride |

These mechanisms occupy adjacent layers: Mission-Bound Authorization
is designed to compose with them, not to replace them.

## The architecture, in verbs

The family organizes along a verb spine: each verb answers one
question and is owned by named documents. The verbs are a table of
contents, not new machinery: each names a question an adopter
already has and points at the documents that answer it. The
[Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)
is the citable form of this view.

| Verb | The question | Main mechanisms |
|---|---|---|
| **Propose** | What task is being requested? | [Intent Shaping](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-shaping.html) (client-side, untrusted proposal) |
| **Approve and Record** | Who approved what, at which control point, under what governance? | [The OAuth binding](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) and its peers (below); [Deferred Approval](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-approval.html); [Template](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-template.html) (consent once to a ceiling, instantiate at machine speed); one more |
| **Govern** | How does the Mission change or end? | [Status](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-status.html) (pull), [Signals](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-signals.html) (push), [Containment](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-containment.html) (issuer-held monotonic narrowing); five more |
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
party in another organization honors it). This table headlines the
main mechanisms; the full verb-to-document map is
[`DRAFTS.md`](DRAFTS.md)'s Verbs column.

## Choose a binding

The binding decides where the Mission control point lives. The
bindings are peers: no production Mission deployment is known
today, OAuth brings the most deployed substrate infrastructure, and
Missions on it still require the changes its binding defines.
Maturity labels are document design maturity, never deployment
history.

| Binding | Use it when | The boundary to know |
|---|---|---|
| [**OAuth AS**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission.html) (the published Internet-Draft) | Your Authorization Server can issue Mission-bound tokens | Portable structured authority on the token; the issuance profile to its OAuth companions |
| [**Standalone MAS**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-authority-server.html) (Mission Authority Server) | Existing Authorization Servers cannot host Mission approval | Ordinary credentials are *joined* to Missions; high-consequence paths require Mission-bound issuance (the [Issuance Grant](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-oauth-mission-issuance-grant.html)) |
| [**AAuth**](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-aauth.html) | AAuth's Person Server (the user-held control point) owns contextual governance | Native AAuth access semantics; authority expressed in AAuth's own access model |
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
| **High-Assurance Agent** | Adds the level's two named claims: agent-compromise-resistant enforcement (mediated credential custody, a declared and audited path scope, action-bound approval, active freshness, and approval rendering isolated from the agent) and trifecta containment (least exposure; the mandatory harness taint rule, with pre-consented egress to Approver-named destinations as its one carve-out; and full mediation of external communication and commitment over enumerated egress channels) |

Both names are claims with proof obligations: the parentheses give
their shape, and the Architecture's declared per-condition evidence
and appraisal contract is what establishes them, never the wire
alone.

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

## Add capabilities by verb

Every optional companion composes independently under its verb in
the table above: pick the mechanisms the deployment needs, check
each document's maturity before adopting it (a repository
design-maturity label, never an IETF status; see Status below), and
follow the
manifest's `adoption_requires` edges for what a draft cannot be
deployed without. The complete catalog with per-document summaries,
maturity, and adoption triggers is [`DRAFTS.md`](DRAFTS.md).

## Running code

The reference implementation under [`src/`](src/) (a pnpm monorepo)
builds on the OAuth binding and implements its runtime, lifecycle,
delegation, and
transaction surfaces tracked row-by-row in
[`src/SPEC_VERSIONS.md`](src/SPEC_VERSIONS.md);
[`src/DEMO.md`](src/DEMO.md) runs the flow end to end.
[`conformance-manifest.json`](conformance-manifest.json) maps each
inventoried requirement in its audited specification set to tested,
partial, or todo coverage.

## Status

The OAuth binding is a published Internet-Draft on the IETF
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
