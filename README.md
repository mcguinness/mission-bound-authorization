<!-- regenerate: off (edited by hand; set to on to let i-d-template regenerate) -->

# Mission-Bound Authorization

An OAuth token says what a client may access. It does not say why,
for what approved task, under whose approval, or until when in terms
of the task itself. That gap is survivable when a human clicks every
consent screen; it is not survivable when autonomous agents hold
delegated authority for hours across many resources.

A **Mission** closes the gap: a durable, integrity-bound record of
the approved task — the intent, the derived Authority Set, the
Approver, and a lifecycle — held by the party that approved it.
Issuance and every derivation of authority are gated on the Mission's
current state, so revoking the Mission is a kill switch at the
issuance layer; runtime enforcement is the targeted overlay for the
actions that cannot wait for token expiry.

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
not prerequisites.

## The architecture, in verbs

The family organizes along a verb spine: each verb answers one
question and is owned by named documents. The
[Architecture](https://mcguinness.github.io/mission-bound-authorization/#go.draft-mcguinness-mission-architecture.html)
is the citable form of this view.

| Verb | The question | Main mechanisms |
|---|---|---|
| **Propose** | What task is being requested? | Intent Shaping (client-side, untrusted proposal) |
| **Approve and Record** | Who approved what, at which control point, under what governance? | The core and the other bindings (below); Deferred Approval; Approval Governance; Template (consent once to a ceiling, instantiate at machine speed); Substrate Requirements for new bindings |
| **Govern** | How does the Mission change or end? | Status (pull), Signals (push), Expansion (widen via a successor), Containment (issuer-held monotonic narrowing), Progressive Drawdown, Metering, Discovery, Management |
| **Enforce Each Action** | May this exact action run now? | Runtime contract, AuthZEN binding, Transaction Authorization, Capability Binding |
| **Run and Wind Down** | What happens across sessions, queues, and restarts? | Harness, Orchestration |
| **Delegate** | Is new subordinate authority created? | Child Delegation, Offline Attenuation |
| **Project** | How is existing authority honored elsewhere? | Cross-Domain Projection, Cross-Organizational Delegation |
| **Continue** | How does authorization survive a hop or a pause? | Continuation |
| **Prove** | What was approved, decided, and executed? | Consent Evidence, Runtime Evidence, Mandate, Audit |
| **Analyze** | What is trusted, and what breaks if it fails? | Architecture, Security Model |

Two of these are easy to conflate and the spine keeps them apart:
**delegate** creates new subordinate authority (a Child Mission, an
attenuated token); **project** honors authority that already exists
in another trust domain, creating none.

## Choose a binding

The binding decides where the Mission control point lives.

| Binding | Use it when | The boundary to know |
|---|---|---|
| **OAuth AS** (the core) | Your Authorization Server can issue Mission-bound tokens | Portable structured authority on the token; this is the issuance profile |
| **Standalone MAS** | Existing Authorization Servers cannot host Mission approval | Ordinary credentials are *joined* to Missions; high-consequence paths require Mission-bound issuance (the Issuance Grant) |
| **AAuth** | The Person Server owns contextual governance | Native AAuth access semantics, not the OAuth Authority Set |
| **UMA / GNAP** | Protocol research and evaluation | Experimental sketches, authored against the substrate contract |

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

Packages say what is deployed. Binding properties and assurance
claims remain per path; a deployment name never upgrades weaker
paths. The named deployment packages live in
[`family-manifest.json`](family-manifest.json) and are validated in
CI.

## Add capabilities by verb

Every optional companion composes independently under its verb in
the table above: pick the mechanisms the deployment needs, check
each document's maturity before adopting it, and let the manifest's
recorded dependencies pull in what a companion builds on. The
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
`maintenance`, and recorded `deps`; named deployment packages live in
the top-level `packages` object. The checker validates all of it,
regenerates nothing silently (the DRAFTS.md index is checked for
freshness, never rewritten in CI), and holds this README to exactly
two rules: it links the catalog and dependency reports, and every
backticked draft token is a real manifest slug.

The reference implementation lives under [`src/`](src/) (a pnpm
monorepo; see [`src/DEMO.md`](src/DEMO.md) and
[`src/SPEC_VERSIONS.md`](src/SPEC_VERSIONS.md) for the spec-to-code
matrix). Contributions: see [`CONTRIBUTING.md`](CONTRIBUTING.md);
substantive design changes go issue-first.
