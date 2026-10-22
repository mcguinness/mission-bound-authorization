# OAuth Binding Layering: Plan for Review

Status: proposal for review, prepared 2026-10-22. Nothing has been
filed or edited. Every proposal here becomes a GitHub issue only after
the owner says go.

## 0. Instructions for the reviewing model

You are reviewing a restructuring plan for one Internet-Draft in a
family of about 50 drafts. Read Sections 1 to 3 for context, then judge
Sections 4 to 7, then answer Section 9.

- **Base commit:** `origin/main` at `5344f4ed6`. The OAuth binding,
  the substrate and Discharge are byte-identical to `d7ab66ff9`, where
  the analysis began; only the ledger changed in between, and its
  counts below were re-measured on `5344f4ed6`.
- **Line numbers** refer to `draft-mcguinness-oauth-mission.md` at the
  base commit unless another file is named.
- **Reproduce the counts** from the repository root:
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/measure.py`
    (standard library only);
  - `python3 notes/audits/2026-10-22-oauth-binding-layering/companion_cites.py`.
- **What we want from you:**
  - a verdict per proposal: adopt, revise (say how), or reject (say
    why);
  - any factual error, with the line or quote that shows it;
  - any blast radius we missed: drafts, ledger rows, implementation;
  - any conflict with the constraints and rulings in Section 3;
  - whether each proposal matches OAuth RFC conventions.
- **Do not** recommend merging existing drafts (Section 3, C2) or
  moving any family companion into the binding's normative references
  (C1). Those are settled.

## 1. The question

The owner asked about `draft-mcguinness-oauth-mission.md` (the "OAuth
binding"):

1. It is doing a lot of jobs. Does it make sense to split the
   "binding" out from a core spec that does issuance?
2. Why does it need to reference so much of the family?
3. Why does it define parameters and implementation detail that it
   does not use itself but later specifications do?
4. What layering best fits OAuth best practices and conventions?

## 2. Context

- **The family.** About 50 drafts. `DRAFTS.md` gives each a role.
  - **core:** the substrate kernel (`draft-mcguinness-mission-substrate`).
  - **adapter-binding:** a binding of the Mission model to a wire
    protocol. The OAuth binding is one, beside MAS, AAuth, UMA and
    GNAP.
  - **companion:** a profile or extension built on a binding or on
    the kernel.
  - **guide:** an informational explainer.

  Issue #1089 retired "core" as a name for the OAuth binding. The
  owner still says "core spec" in conversation; this plan says "the
  binding" or "the base".
- **Publication state.** The binding's `-01` is on the datatracker
  (2026-10-21, D644). The file is the editor's draft: findings are
  filed as issues first, and the draft changes only through a
  reviewable PR on the owner's go. Resource Access `-00` is also
  published (D645). By this repository's submission tags, no other
  family draft has a datatracker revision.
- **Dependency direction.** Companions depend on the binding
  normatively. The binding depends on no companion normatively, and
  the substrate is an informative reference to it (D140, #708).
- **Ledger.** `conformance-manifest.json` holds one row per
  requirement, keyed by `spec` and `anchor`. Each row has a coverage
  (`tested`, `partial`, `todo`) and an applicability, either
  `unconditional` or gated on a capability id. The reference
  implementation lives in `src/`. Capability ids are declared in
  `src/services/authorization-server/src/adapters/capabilities.ts`.

## 3. Constraints and prior rulings

Every proposal must respect these. "Effect" says how each one shapes
this plan.

| Id | Ruling | Effect |
|---|---|---|
| C1 | The binding stands alone. It never takes a family companion as a normative reference, and it states a capability's property bar in its own terms with the companion informative (#169, Option 2). | A moved capability leaves an informative pointer behind, as Approved-Set Verification did (#882). |
| C2 | No consolidation: existing drafts are never merged. A new draft is allowed if it passes the New Draft Admission test (`CONTRIBUTING.md`, "New Draft Admission"). | P1 must answer that test, and must first assess an existing-document home. |
| C3 | #880 (2026-10-01) kept the generalized `approval_basis` in the binding. Its reasons: the members are vocabulary read by many drafts; `approval_basis` is REQUIRED on every record; making the direct-case members optional breaks the record; a hub draft would split one object across two documents. | P2 keeps the record shape and moves no member. |
| C4 | #1483 / D610 (2026-10-21) consolidated standing consent into one section after Delegation, keeping the unknown-type rule in the record's common definitions. | P2 edits that section in place. |
| C5 | #882 moved the optional Approved-Set Verification capability to a companion. The binding kept the commitment and a pointer. | The precedent for P1. |
| C6 | #1412 / D559 (2026-10-20) kept Instance Context in Delegated Tokens and its normative `client-instance-id` reference, until a concrete publication plan exists. Before proposing a new draft, assess an existing-document home. | P1 revisits D559 because its premise changed (Section 4.3). It is a `decide` item. |
| C7 | #1503 finding 9 / D625 (2026-10-21) made the Actor Profile and rar-metadata-remediation normative references. The owner rejected keeping them informative. | No proposal makes a reference informative. P1 moves the text that needs the references instead. |
| C8 | #207 (open, parked): the "Mission Model split". Its triggers: an OAuth WG adoption conversation (ask the WG's document-architecture preference first); a second non-OAuth binding with real implementer commitment; or MAS control-plane evolution that forces binding revisions at a felt cadence. | P5 keeps it parked. |
| C9 | #704 / D140: the initial OAuth WG submission set is the binding plus Resource Access. The substrate is withheld. | Resource Access's dependencies on the binding matter more than other companions' (P1). |
| C10 | D427 / PR #1231 left "Option A on family editor's-copy citations" unruled: submit Resource Access `-00`, and keep the other family drafts as informative editor's-copy references. | P3 pairs with it. |
| C11 | Working style: prefer existing OAuth and JOSE surfaces over new ones; make minimal changes that preserve capability; an editorial change preserves every obligation; use timeless spec prose. | Applies to every proposal. |

## 4. Findings

### 4.1 Jobs the binding does

Measured over the middle matter (34,747 words, 261 BCP 14 keywords,
133 sections). Each section's count excludes its subsections. The
bucketing is a judgment call, and `measure.py` lists every anchor in
its bucket.

| Job | Words | BCP 14 | Sections |
|---|---|---|---|
| 1. Issuance protocol, including approval: Intent via PAR, derivation, direct approval, record, anchors, grant binding, gating, `mission` claim, token response, scope projection, RS enforcement, errors, introspection, metadata, IANA | 21,872 | 193 | 79 |
| 2. RFC 8693 delegation profile: Section "Delegation Within a Mission" and Optional Capabilities | 2,708 | 17 | 8 |
| 3. Hooks for companions and the extension framework (detail in 4.4) | 5,036 | 51 | 14 |
| 4. Tutorial and examples in the middle matter | 947 | 0 | 4 |
| 5. Security, privacy, i18n, applicability | 4,184 | 0 | 28 |

Appendices (7,321 words, no BCP 14 keywords):
- End-to-End Example: 1,588;
- Design Context and Boundaries: 1,609;
- Role Mapping: 477;
- Derivation Policy: 938;
- Integrity Anchor Test Vectors: 543;
- OAuth Binding Mapping Assessment: 1,157;
- Document History: 981.

The Mapping Assessment (line 7006) and Role Mapping (line 6546) are the
substrate-binding content proper: they map the binding onto the
substrate kernel, informatively.

### 4.2 Family citations

- 140 citations of 30 family drafts; 111 sit in the middle matter.
- The most-cited drafts: Resource Access 25, Cross-Domain 20, Approval
  Governance 9, then Consent Evidence, Expansion, Child Delegation and
  Runtime with 7 each.
- The middle-matter sections with the most citations:
  - Grant Bindings and Related Mechanisms (line 2322): 6;
  - Composition and the Effective Ceiling (line 5428): 6;
  - Standing-Consent Bases (line 3881): 4;
  - Principals and Approval Basis (line 4128): 4.
- `measure.py` prints the full table by section.
- 29 of the 30 cited drafts have no datatracker revision, so their
  reference targets are github.io editor's copies (C10).

### 4.3 Normative Internet-Draft references

The binding's `normative:` block holds three Internet-Drafts:

| Reference | Kind | Cited from (body) |
|---|---|---|
| `draft-mcguinness-oauth-client-instance-id` | individual | Instance Context in Delegated Tokens (8 citations); one Error and Challenge Mapping row |
| `draft-mcguinness-oauth-actor-profile` | individual | Delegation Within a Mission (lead), Delegated Exchange, Instance Context |
| `draft-ietf-oauth-rar-metadata-remediation` | WG | Denial Responses, Remediation Grains, Authorization Server Metadata |

- At `6a7c616e` (2026-10-20), the basis of #1412, only
  `client-instance-id` was normative.
- Commits `e6f6c911a` ("the OAuth Actor Profile is a normative
  reference, scoped to the optional Delegation capability", D625) and
  `2e7c08608` (#1503 finding 9) added the other two on 2026-10-21.
- So D559 weighed one individual-draft dependency, in one subsection.
  Today there are two, and both are cited only from the optional
  Delegation capability (plus one error row).
- A Standards Track RFC is not published before its normative
  references. The RFC Editor queue state name was not verified in this
  session; reviewer, please confirm.
- Side finding: `notes/oauth-wg-submission-set.md` lines 56-60 say
  `DEPENDENCIES.md` has no external-normative-ids entry for
  `oauth-mission`. That predates `2e7c08608`: `DEPENDENCIES.md` line
  20 now lists rar-metadata-remediation for it.

### 4.4 Definitions the binding does not use itself

1. **`approval_basis` under `direct`** (lines 4128-4240). Every member
   can be derived from members the record already has:
   - `consent_principal` is the Approver;
   - `activation.approval_event_id` mirrors the record's own
     `approval_event_id`;
   - `activation_actor` equals `consent_principal`;
   - `root_commitment` is the record's `authority_hash`;
   - where `adjudication` is present, its `kind` MUST be `human` (line
     4223).

   The structure exists for the four standing-consent bases that
   companions define. Uses in other drafts:

   | Member | Drafts | Mentions |
   |---|---|---|
   | `consent_principal` | 12 | 69 |
   | `approved_at` | 10 | 58 |
   | `root_commitment` | 5 | 29 |
   | `activation_actor` | 6 | 19 |

   C3 explains why the structure stays.
2. **Standing consent** (lines 3881-4005): Standing-Consent Bases,
   Instances, Activation Policy Commitment and Recency.
   - About 850 words and 16 BCP 14 keywords.
   - 7 ledger rows (4 tested, 3 partial), gated on
     `core.standing-consent` or `core.standing-consent-recency`.
   - None of it applies to an AS whose only basis is `direct`.
   - Line 3888 onward names four companion-defined `type` values with
     their documents:
     - `template` (Template);
     - `policy_drawdown` (Child Delegation);
     - `ceiling_drawdown` (Progressive);
     - `governed_policy` (Approval Governance).
   - Three sentences put MUSTs on companion specifications rather than
     on implementations: line 3913 ("A companion profile defining a
     standing-consent `type` MUST make its ..."), line 3935 (`kind` MUST
     be `policy`), and line 3937 (MUST NOT flatten). A fourth is at line
     4193 (a companion MUST NOT define a `kind` value that names a
     record...).
3. **Commitment Mechanisms** (line 4593) defines three hash species:
   envelope anchor, canonical-object digest, and raw-octet digest.
   - Every anchor the binding defines is an envelope anchor (line 4654).
   - The substrate's Default Commitment Construction already defines
     all three species (`draft-mcguinness-mission-substrate.md` line
     534 onward); line 4616 says this section instantiates it. That
     reference is informative, so "instantiates" creates no normative
     dependency on the substrate (C1, D140).
   - Only Discharge cites the binding's section for the other two
     species (`draft-mcguinness-oauth-mission-discharge.md` lines 682
     and 849).
   - Discharge has no substrate reference today.
4. **`mission.expires_at`** (line 2825). Its MUST binds only "a
   profile that mints a further credential downstream of this one, or
   that verifies a Mission's remaining lifetime from retained state":
   in practice, Cross-Domain.
5. **Termination transition reading** (line 2175). A consumer MAY read
   the legacy state values `revoked`, `expired`, `completed`,
   `superseded` and `cascaded` as `terminated` with a reason. Three of
   them are older companion state values.
6. **Contrast case.** The Intent members (line 906 onward) are lean,
   and the base's own flow uses every one.

### 4.5 Why this happens (root causes)

1. **The binding is the only normative home left.**
   - The substrate is informative to the binding (D140).
   - No companion may become a normative reference of the binding
     (C1).
   - So vocabulary that two companions share at MUST strength has
     nowhere else to go. It lands in the binding, and the binding then
     names who uses it. #880 (C3) is the explicit case.
2. **The relationship prose runs backwards.** Normative sections
   explain how companions relate to the base:
   - Grant Bindings and Related Mechanisms has bullets for
     Cross-Domain, Child Missions and successors, Continuation, and the
     MAS join (lines 2322-2373);
   - Composition and the Effective Ceiling covers Child Delegation,
     Cross-Domain, Derivation Limits and Metering (line 5428).

   In OAuth the extension states how it relates to the base: RFC 6749
   never mentions PKCE or DPoP.
3. **The examples borrow Resource Access's type.** The binding defines
   no `authorization_details` type, so `mission_resource_access`
   appears in 16 binding sections. This is defensible, because the
   binding and Resource Access form the submission set (C9). The cost
   is citations, not structure.
4. **Some citations exist by ruling.** The Cross-Domain capability bar
   is self-contained in the binding with the companion informative
   (C1, #169). Its citations are the pointer that ruling chose.

## 5. OAuth conventions applied

These were verified against the RFC text in this session, except where
marked.

- **Extensions register their own values.**
  - RFC 6749 Section 11 creates the OAuth Access Token Types,
    Parameters, Authorization Endpoint Response Types and Extensions
    Error registries, each Specification Required.
  - RFC 7519 Section 10.1 creates the JSON Web Token Claims registry.
  - RFC 9396 creates no registry for `type` values: "The AS controls
    the interpretation of the value of the `type` parameter" (Section
    2.1).
  - A base specification defines and registers the values its own flow
    uses, and nothing else.
- **Rules on future extensions go in the registry instructions.** The
  binding already does this: its Lifecycle States registry tells the
  Designated Expert to reject a registration whose specification
  redefines the only-`active` rule (line 5780).
- **Optional features with their own dependencies get their own
  documents.** RFC 7009, RFC 7662, RFC 8693 and RFC 8414 all sit
  outside RFC 6749. GNAP's resource server connections (RFC 9767) are
  separate from GNAP core (RFC 9635). Both were verified.
- **A base specification names no later extension in normative
  text.** This one follows from the first convention and from RFC 6749
  practice; it is not a quoted rule.
- **Normative references gate publication** (Section 4.3; the RFC
  Editor state name is unverified).

## 6. Proposals

Every proposal is `-02` scope and issue-first. None changes a wire
member, endpoint, parameter, claim or error code.

### P1. Move the Token Exchange delegation mechanics into a companion (`decide`; revisits D559)

**Proposal (variant B, recommended).**
- *Moves* to a new companion, working title "Mission Delegation for
  OAuth 2.0", docname `draft-mcguinness-oauth-mission-delegation`,
  intended category `std`:
  - Designation (lines 3533-3576);
  - Delegated Exchange (lines 3577-3651);
  - Instance Context in Delegated Tokens (lines 3652-3717);
  - Delegated Token Example (lines 3819-3880);
  - the Actor Profile framing in the Section "Delegation Within a
    Mission" lead (lines 3496-3532), together with the two-step
    figure.
- *Stays* in the binding:
  - the "Delegation Within a Mission" heading and anchor, holding the
    delegate model: a delegated token's outermost `act` names the
    delegate, and `client_id` names the presenting client;
  - Delegation Constraints (lines 3739-3818): depth, depth accounting,
    per-entry type policy, the empty-result refusal, and "the resource
    server enforces none of this";
  - Self-Exchange Down-Scoping (lines 3718-3738).

**Why this cut.** The shared rules live in Delegation Constraints, and
every act-bearing issuance path depends on them:
- Resource Access's Delegate Eligibility rests on the binding for depth
  `d`: "That document's Delegation Constraints section defines `d`"
  (`draft-mcguinness-oauth-mission-resource-access.md` line 1101).
  Resource Access `-00` is published and is in the submission set (C9).
- Continuation discharges the depth-accounting duty for its own
  transport (D202; `continuation.md` line 393).
- Cross-Domain cites the depth reset (lines 411, 814 and 858).
- Derivation Limits cites the constraints (line 593).

The mechanics, by contrast, are used almost only by the binding:
"designation" appears 37 times in the binding and once in Transaction
Authorization.

Self-Exchange stays because it is a no-actor narrowing exchange, not
delegation. Two of its three ledger rows are `unconditional`, and it
needs neither the Actor Profile nor the optional capability.

**Variants considered.**

| Variant | What moves | Assessment |
|---|---|---|
| A. Status quo (D559) | nothing | The base keeps two individual-draft normative references for an optional capability. |
| B. Mechanics only (recommended) | Designation, Delegated Exchange, Instance Context, the example, the Actor Profile framing | Both individual-draft references leave; Resource Access, Continuation and Cross-Domain citations stay valid. |
| C. All of the Section "Delegation Within a Mission" | B plus Delegation Constraints and Self-Exchange | Resource Access `-00` (submission set), Continuation, Cross-Domain and Derivation Limits gain a dependency on an unsubmitted companion; the base loses its type-agnostic delegation discipline, which Extensibility lists as a stable interface (line 4679). |
| D. Host the mechanics in Child Delegation (existing draft) | as B, into Child Delegation | Different contract: Child Delegation creates new Missions with lineage, while designation and delegated exchange issue `act` tokens under the same Mission. Child Delegation does not use designations. |
| E. Keep the text but fence it as a separate part of the binding | nothing | The normative references stay, so the publication gate does not change. |

**What the base keeps or rewrites (touch points outside the moved
sections):**
- Implementation Map table rows (lines 527 and 531): point the
  delegation cases to the companion.
- The no-`mission_intent` exception (lines 1215-1216): keep
  self-exchange; mention designation as an example of a profile
  exchange.
- Principal Model (line 1989): delegates are carried in the `act`
  chain; keep it, with a pointer.
- Grant resolution on Token Exchange (lines 2286-2294) and the Token
  Exchange bullet of Grant Bindings and Related Mechanisms (lines
  2326-2333): keep. They are already generic; Issuance Gating covers
  "every derivation, refresh and Token Exchange".
- Token Claims (lines 2496-2518):
  - keep the generic `aud` exception for "a token the AS issues only
    for presentation back to itself at a Token Exchange", with
    designation as an example;
  - keep "MAY carry an `act` claim";
  - move the sentence that sender-constrains a delegated token to the
    delegate's key.
- Enforcement Requirements item 4 (lines 2929-2933, no inference of the
  approved agent from `client_id`): keep. RS "can also require an `act`
  chain" (line 2955): keep.
- Mission-Unaware Resource Servers routing MUST (lines 2966-2969): keep
  in the base. It applies to any delegated token, whichever profile
  issued it. Reviewer, please check.
- Error and Challenge Mapping rows (lines 3192-3197):
  - keep 3192 (self-exchange) and 3195 (empty result, Delegation
    Constraints);
  - move 3193, 3194, 3196 and 3197 (designation and Instance Context).
- Introspection (lines 3318-3320), "the AS MUST return `active: false`"
  for a designation: move, since the designation is the companion's
  artifact.
- Extensibility stable interface (line 4679), "the `act` delegation
  chain": keep, pointing at the base's delegate model.
- Optional Capabilities (lines 4971-4975): the Delegation capability
  becomes the companion's conformance. The base keeps an informative
  pointer, as for Approved-Set Verification.
- Security considerations:
  - Token Theft's designation sentences (lines 5309-5312): move;
  - Delegation and Chain Compromise (lines 5316-5355): split, with the
    designation and exchange parts moving;
  - Client Attribution and Delegation Lineage (lines 5356-5372): stays;
  - the Appendix "Client Identification in Delegated Tokens" (line
    6523): stays.
- References: `draft-mcguinness-oauth-actor-profile` and
  `draft-mcguinness-oauth-client-instance-id` leave the binding's
  `normative:` block. `draft-mcguinness-oauth-client-attesters`
  (informative) moves too.

**Blast radius (variant B).**
- **Ledger.** 14 rows re-anchor to the companion (10 tested, 4 todo):
  - the 8 `core.designation.*` rows;
  - `core.delegation.designation-only-subject-token` and
    `core.delegation.redemption-evaluated-afresh` (anchor
    `delegated-exchange`);
  - the 3 `core.instance-context.*` rows (all `todo`);
  - `core.self-exchange.designation-not-self-exchange` (anchor
    `self-exchange`, but about designations).

  Staying: the 4 `core.delegation-constraints.*` rows and the 2
  unconditional self-exchange rows. Three of the delegation-constraints
  rows are gated on `core.delegation`, and `cross-domain-carriage` is
  gated on `cross-domain.projection`. Once the base no longer defines
  the Delegation capability, the `core.delegation` gate needs a new
  name or an applicability that covers any profile issuing delegated
  tokens.
- **Implementation.** `capabilities.ts` declares `core.delegation` and
  `core.instance-context`, so ids are renamed or added there. No
  behavior changes.
- **Companion citations.** The 3 citations of Section "Delegation
  Within a Mission" (Cross-Domain line 821, Derivation Limits line 365,
  Transaction Authorization line 650) concern the delegate model and
  `act` structure, so they stay valid if that heading stays. The 5
  citations of Delegation Constraints stay valid. Transaction
  Authorization already cites the Actor Profile itself.
- **Uncited dependence (checked, none found).** No other draft uses the
  phrase "delegated exchange".
  - `actor_token` appears in Child Delegation (8 times) and Expansion
    (10). Each defines its own RFC 8693 exchange "per RFC 8693":
    - Child Delegation lines 452-461, 790 and 2301;
    - Expansion lines 450-458, 684 and 2354.
  - Neither relies on the binding's Delegated Exchange rules.
- **Pending finding.** #1503 finding 11 (a delegated token's lifetime
  and "that credential's grant"; Sections 12.2 and 8.1.2 in that
  issue's numbering) touches the delegation sections. Rule it before
  the move, or move it with the text.
- **Size.** About 1.5k words and 11 BCP 14 keywords leave the base:
  Designation 321 words and 3 keywords, Delegated Exchange 534 and 4,
  Instance Context 418 and 4, the example 251 and 0, plus part of the
  lead. Exact figures come from the normative-sentence record when the
  move is built.

**New Draft Admission answers (draft).**
- *Contract:* the Token Exchange protocol that lets an agent designate
  a delegate and lets the delegate redeem the designation for a
  Mission-bound token carrying an `act` chain, plus instance context
  for that token.
- *Why a separate document:* it is an optional capability with two
  normative individual-draft dependencies the base does not otherwise
  need. Of the existing drafts, Child Delegation has a different
  contract (variant D) and Continuation is an identity-continuity
  transport.
- *Parties:* the delegating client, the delegate client, and the AS.
- *What crosses the boundary:* the designation, a Token Exchange
  request and response, and the delegated token.
- *Existing mechanism tried:* plain RFC 8693 with `actor_token` cannot
  bind redemption to a named delegate without the designation step;
  this is the binding's current design, unchanged.
- *Property:* authority (delegated authority narrows, and it is bound
  to a named delegate); lifecycle is inherited from the Mission.

### P2. Replace the standing-consent list with an Approval Basis Types registry

**Proposal.**
- Create a "Mission Approval Basis Types" registry, Specification
  Required, seeded with `direct` only.
- Move the four companion-directed sentences (lines 3913, 3935, 3937
  and 4193) into the Designated Expert criteria. A registration's
  specification must:
  - make `consent_principal` and `root_commitment` trace to an
    accountable human's approval of the named standing consent, with
    no fresh human approval per instance;
  - carry that approval's instant as `approved_at`;
  - state what `approval_event_id` holds for an instance it activates;
  - when it populates `adjudication`, use `kind` `policy`;
  - not flatten a policy's or an Approval Governance Record's assertion
    set into one principal member.
- Replace the named list at line 3888 onward with a pointer to the
  registry.
- Each of the four companions registers its value in its own IANA
  section.

**Unchanged.**
- The record shape (C3): no member moves and no member changes
  presence.
- The unknown-type rule in the record's common definitions (C4).
- Every obligation on the activating issuer: `approved_at` verification
  (line 3928), Activation Policy Commitment, and Recency.
- The 7 ledger rows. They test issuer obligations, not specification
  obligations.

**Namespace Taxonomy amendment.** Line 4768 says: "A namespace whose
values determine fail-closed behavior and span multiple documents is
backed by an IANA registry". An unknown `approval_basis.type` is not
fail-closed: it is preserved as opaque provenance and refuses only an
operation that needs it.

The Termination Reasons registry already departs from that criterion.
An unknown reason changes nothing about availability, since the state
is still `terminated`. Proposed amendment: "A namespace whose values
determine fail-closed behavior, or whose registrants owe this document
stated obligations, and that spans multiple documents ...".

**Blast radius.**
- 4 companions add an IANA registration: Template, Child Delegation,
  Progressive and Approval Governance.
- No citation needs repointing; the 16 citations of standing-consent
  sections in 7 drafts stay valid.
- In the normative diff, 4 BCP 14 sentences move from the body into the
  IANA instructions. Treat that as a relocation and record it.

**Open.**
- Should `adjudication.kind` get a registry too? Only `human` and
  `policy` exist, and line 4193 already constrains companion values.
- Is a Specification Required registry the right weight for four
  family values?

### P3. Move "relationship to companion X" prose into the companions

**Rule.** A normative section of the base cites a companion only:
- to name a mechanism the base defers to (one sentence); or
- in one informative routing table, the Implementation Map.

Paragraphs that explain a companion's behavior move to that companion.

**Candidates** (line, current citations):
- Grant Bindings and Related Mechanisms (line 2322, 6): keep the Token
  Exchange bullet. Move the Cross-Domain, Child Missions and
  successors, and Continuation bullets, and the MAS join paragraph, to
  their companions. Leave one sentence: a profile that creates another
  grant lineage or another Mission states its relation to the grant
  binding.
- Composition and the Effective Ceiling (line 5428, 6) and Authority
  Materialized Before Containment (line 5464, 2): move the composition
  analysis to the Security Model guide. Keep a short statement of the
  base's own residual.
- Remediation Grains (line 3090, 3): keep `mission_denial` and the
  RAR-remediation grain, which uses the normative reference. Move the
  AuthZEN requestable-denial grain to the AuthZEN profile.
- Principals and Approval Basis (line 4128, 4): move the paragraph on
  which profiles commit `approval_basis` (Audit Transparency, Approval
  Governance) to those documents.
- Consent Binding (line 5053, 3): the same treatment.
- Policy-Language Types (line 1648, 2): informative example. Keep it,
  or trim it to one sentence and the example.
- Keep as they are: the pointers in runtime-boundary,
  downgrade-by-omission, prompt-injection and information-propagation.
  They are security considerations that name where a mitigation lives,
  which is ordinary RFC style.

**Pairs with C10.** Fewer family citations in the base also shrinks the
editor's-copy reference list a reviewer sees.

**Effect.** This plan sets no target count. Each paragraph gets a
disposition (kept, moved to X, or cut as duplicate) in the issue.

### P4. Point to the substrate for the two hash species the base never uses

**Proposal.**
- Commitment Mechanisms (line 4593) keeps the envelope anchor, the
  prefix and agility rules, and the I-JSON rules. Its two tested
  unconditional rows bind the base's own anchors.
- Its description of the canonical-object and raw-octet species
  becomes an informative pointer to the substrate's Default Commitment
  Construction.

**Blast radius.**
- Discharge lines 682 and 849 repoint to the substrate.
- Discharge gains its first substrate reference, which would be
  normative, as the bindings' substrate references already are.
- No ledger rows move.

**Open.**
- Check that no other companion relies on the base's "imports this
  section normatively" sentence (line 4654) for a non-envelope species.
  The sweep found citations only from Discharge, but companions may
  cite the base without naming the section.
- The reference runs both ways. The substrate says the binding
  instantiates its construction (`draft-mcguinness-mission-substrate.md`
  line 541), and the binding says it instantiates the substrate's (line
  4616). Both references are informative since #708, so pointing the
  binding at the substrate for the two species creates no normative
  cycle. Reviewer, please confirm the base would still state every rule
  its own anchors need.

### P5. Keep #207 (the Mission Model split) parked

#207 is the literal "split the binding from a core": a binding-neutral
Mission Model draft beneath the OAuth binding, which keeps only the
OAuth deltas. Recommendation: no change.

- **Convention.** OAuth specifications own their data model: RFC 7519
  defines its claims, RFC 8693 defines `act`, and RFC 9396 defines
  `authorization_details`. Putting a normative non-OAuth model
  underneath would give the WG a two-document normative stack before
  it asks for one.
- **The trigger.** #207's own first trigger is to ask the WG's
  document-architecture preference first.
- **Placement.** The real binding content, the Mapping Assessment and
  Role Mapping, is already in informative appendices, which is where
  convention puts it.
- **Cost.** Executing #207 is a large relocation round. Move-on-touch
  already migrates ownership one change at a time.

### Not proposed

- **Making rar-metadata-remediation informative.** Rejected at #1503
  finding 9 (C7). It is a WG draft, and Remediation Grains and
  Authorization Server Metadata use it.
- **Making the `direct`-case `approval_basis` members optional.** C3:
  it is a breaking record change.
- **Moving standing consent to a hub draft.** C3.
- **Any merge of existing drafts.** C2.

## 7. Sequencing and verification

**Order.**
1. P4, then P2: small and independent of the others.
2. P3: per-paragraph dispositions, coordinated with C10.
3. P1, after its `decide` ruling.

Each is one issue under the repository's Issue Convention.

**Verification per PR.**
- Record every BCP 14 sentence before and after, and classify each
  removal: moved (to where), rewritten, or relocated to IANA
  instructions.
- Check that no condition falls off a moved MUST.
- Run the family manifest check and the ledger checker; re-anchor
  moved rows to their new spec and anchor, keeping coverage, tests and
  pins.
- Build every touched draft. Re-pin the binding in the companions that
  cite it.
- P1 only: rename or declare the capability ids in `capabilities.ts`.
  A test run proves no behavior change.

## 8. Corrections to the chat summary

The owner first saw a chat summary of this analysis. This plan corrects
it in these places:

| Chat summary | Corrected |
|---|---|
| Delegation moves 20 ledger rows (16 tested) | 20 is variant C: the whole Section "Delegation Within a Mission", Self-Exchange included. Self-Exchange should stay, because 2 of its rows are unconditional; without it, C moves 18 (14 tested, 4 todo). The recommended variant B moves 14 (10 tested, 4 todo). |
| 10 companion citations in 6 drafts repoint | 2 of those 10 cite Self-Exchange, which stays. Under variant B, the other 8 (in 4 drafts) stay valid too, because the heading and Delegation Constraints stay. |
| "The base keeps one rule" for Token Exchange | The base also keeps the delegate model, Delegation Constraints and Self-Exchange (variant B). |
| Approval Basis Types registry presented as already convention-aligned | It needs the Namespace Taxonomy amendment in P2. |

## 9. Review questions

1. Is variant B the right cut, or does keeping Delegation Constraints
   in the base leave too much "defined for later specs" behind? Does
   anything else in the base still need the Actor Profile once the
   mechanics move? Check lines 3496-3532 and 3739-3818.
2. Can the Mission-Unaware Resource Servers routing MUST (lines
   2966-2969) stay in the base when the base no longer issues delegated
   tokens itself?
3. Does moving the introspection rule for designations (lines
   3318-3320) to the companion conflict with the base's Strengthening
   of RFC 7662 Section 4 (line 3314 onward)? A companion would be adding
   an `active: false` case to the base's rule.
4. P2: are DE criteria an acceptable home for MUSTs on future
   specifications in an OAuth document? Is there an RFC precedent
   stronger than the binding's own Lifecycle States rule (line 5780)?
5. P2: does the taxonomy amendment weaken the registry criterion so
   that Mission Record members or `mission` claim members would also
   need registries?
6. P3: which "relationship" paragraphs carry requirements a companion
   cannot restate without "Updates:" on the base? For example, the
   Token Claims `aud` exception constrains a base MUST.
7. P4: does any companion depend on the base's I-JSON or prefix rules
   for a non-envelope digest without citing the section by name?
8. P5: is there an OAuth WG precedent for a normative abstract model
   beneath an OAuth protocol document (in the style of RFC 7521 and
   RFC 7522/7523) that changes the recommendation?
9. Is the job bucketing in 4.1 fair? `record-principal-members` holds
   base members (`subject`, `client_id`) alongside the generalized
   `approval_basis`, and it is counted under job 3.
10. What did this plan miss that a WG reviewer of `-02` would raise
    about the layering?
