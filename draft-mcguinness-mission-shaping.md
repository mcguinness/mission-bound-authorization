---
title: "Mission Intent Shaping"
abbrev: "Mission Shaping"
category: info

docname: draft-mcguinness-mission-shaping-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - shaping
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-shaping.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC8259:
  RFC8785:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC6749:
  RFC7515:
  RFC9126:
  RFC9396:
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval-revision:
    title: "Mission Approval Revision for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval-revision.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-resource-access:
    title: "Mission Resource Access Profile for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-resource-access.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-template:
    title: "Mission Template for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-template.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-derivation-limits:
    title: "Mission Derivation Limits for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-derivation-limits.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-submission-evidence:
    title: "Mission Intent Submission Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-submission-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 (the "issuance profile")
defines the Mission Intent a client submits and the Authority Set an
Authorization Server derives from it, but not how an open-ended task
request becomes a Mission Intent. This document describes the Mission
Shaper, a client-side component that turns a user request or upstream
trigger into a candidate Mission Intent and, optionally, an Authority
Proposal: its trust boundary; recommended capability resolution,
ambiguity handling, and refusal; Shaping Evidence, an audit record of
how a proposal was produced; and re-shaping after a refusal, denial,
or required revision. It defines no protocol. The shaper only
proposes; authority is created by the issuance profile's validation
and approval.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") makes a
Mission a first-class authorization artifact. A client submits a
Mission Intent, and optionally an Authority Proposal, in a Pushed
Authorization Request {{RFC9126}}. The Authorization Server, acting as
Mission Issuer, derives an Authority Set, obtains the Approver's
consent, and binds issued tokens to the approved Mission. The issuance
profile does not specify how a deployment turns an open-ended task
request, such as "resolve this billing dispute", into a Mission Intent
with a goal, target resources, task bounds, success criteria, purpose,
and expiry.

This document describes that step, performed by a client-side Mission
Shaper. The shaper can be a rules engine, a form, a workflow, or a
function that uses a language model; whatever its implementation, its
output is untrusted input to the Mission Issuer ({{proposes-only}}).

The practices in this document make shaping auditable and fail closed.
An ambiguous request is narrowed, clarified, or refused
({{ambiguity}}); an unresolved capability is recorded, not treated as
authority to create it ({{capability-resolution}}); Shaping Evidence
records how each proposal was produced ({{shaping-evidence}}); and
after a refusal, denial, or required revision, the shaper constructs
a narrower next proposal ({{re-shaping}}). Every later guarantee (the
derived Authority Set, the approval, per-action decisions, and the
evidence trail) operates on what the shaper proposed.

## Scope {#scope}

This document is Informational. Deployments differ in how they process
prompts, which language models they use, and what their products
require, so no two transform a request into a Mission Intent the same
way. The interoperable surface is the result, the Mission Intent and
Authority Proposal, which the issuance profile defines and validates.
This document therefore describes the shaper's role in the trust model
and recommended shaper behavior. It defines no shaping protocol, media
type, claim name, conformance class, grant type, token format, policy
language, runtime decision API, or required endpoint; the approved
Mission and its tokens remain those of the issuance profile.

This document is optional. A deployment that accepts only
hand-authored Mission Intents conforms to the issuance profile and is
unaffected by this document.

## Mission Substrate {#mission-substrate}

This document is written against the Mission model, not OAuth 2.0
mechanics. A shaper produces a structured Mission Intent and,
optionally, a proposal of concrete authority, for a submission that
the receiving issuer treats as untrusted input. Shaping Evidence
commitments use the Default Commitment Construction of
{{I-D.draft-mcguinness-mission-substrate}}. The issuance profile
carries the submission in a Pushed Authorization Request; the Mission
Authority Server {{I-D.draft-mcguinness-mission-authority-server}}
accepts the same Mission Intent at its mission submission endpoint.
The AAuth binding {{I-D.draft-mcguinness-mission-aauth}} defines no
Mission Intent: its mission proposal is a natural-language
description, so the construction guidance in this document does not
apply to it. Another authorization substrate that accepts a
structured, untrusted task proposal and commits it at approval can
host these practices unchanged.

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

The BCP 14 keywords in this document state recommended behavior for
three parties:

- the shaper, expressed where possible on the observable shaping
  artifacts (the Mission Intent proposal and Shaping Evidence);
- a deployment that operates a shaper, including its client; and
- any party that receives shaper output or Shaping Evidence,
  including the Mission Issuer, which never treats either as
  authority.

None of these is a conformance obligation. The Mission Issuer's
processing of a submission is specified by the issuance profile; this
document cites it and does not restate it as its own requirement.

JSON {{RFC8259}} is the data model for the illustrative objects in
this document; the surrounding prose is authoritative. Digests over
Shaping Evidence use the JSON Canonicalization Scheme (JCS)
{{RFC8785}} ({{shaping-evidence}}).

This document uses the following terms defined by the issuance
profile: Mission, Mission Intent, Mission Intent Submission (Submission
envelope), Authority Proposal, Authority Set, Mission Issuer, Approver,
and Agent (Client). "Client" and "client-side" refer to that Agent
(Client), the OAuth client that submits the Mission Intent. The
issuance profile's Mission Issuer is an Authorization Server
{{RFC6749}}; this document calls it the Mission Issuer throughout.
"The issuance profile"
without a section reference means that document as a whole.

This document defines the following terms:

Mission Shaper (or "shaper"):
: A client-side component that produces a candidate Mission Intent,
  and optionally an Authority Proposal, from a task request and
  supporting context. A Mission Shaper does not grant authority.

Mission Intent proposal:
: The candidate Mission Intent the shaper emits for validation and
  approval under the issuance profile. The client submits it as the
  `intent` member of the Submission envelope.

Shaped proposal:
: A Mission Intent proposal together with any Authority Proposal the
  shaper produces for the same submission. "Proposal" alone means a
  shaped proposal.

Shaping ceiling:
: A bound on a shaped proposal, expressed as an `authorization_details`
  array and supplied by the deployment or by the caller of the shaper
  ({{authority-ceiling}}). It is distinct from the
  consented `authority_ceiling` Mission member of
  {{I-D.draft-mcguinness-oauth-mission-progressive}} and from the
  pre-consented Template Ceiling on Missions dispatched from a template
  ({{I-D.draft-mcguinness-oauth-mission-template}}).

Partial proposal:
: A shaped proposal that omits authority the task needs. It is emitted
  only with the disclosures that {{authority-ceiling}} and
  {{ambiguity}} require.

Resolution basis:
: The ground on which the shaper admits a resource or action into a
  proposal ({{capability-resolution}}).

Shaping Evidence:
: The record of inputs, inferences, policy decisions, unresolved
  ambiguities, and capability-resolution facts that produced a shaped
  proposal ({{shaping-evidence}}). Audit material, not authority.

The roles Mission requester and capability source are defined in
{{roles}}.

# Shaper Role and Trust Boundary {#role-and-trust-boundary}

The trust boundary separates the client, where the shaper runs, from
the Mission Issuer, where the Mission Intent is validated and the
Authority Set is created. This section defines the shaper's role on the
client side of that boundary; it is the stable core of this document.

## Client-Side Placement {#client-side}

The shaper runs in the same trust domain as the client that submits
the Mission Intent. The client consumes the shaper's output and submits
it to the Mission Issuer ({{oauth-composition}}).

The shaper is not a separate principal. It has no identity of its own
to the Mission Issuer, which sees only the client. A deployment MAY
factor the shaper into its own process or network service for
engineering reasons ({{exposing-shaping-as-a-service}}), but doing so
does not make the shaper a principal to the Mission Issuer and does not
move it across the trust boundary: it remains client-side machinery
that produces an untrusted proposal.

## The Shaper Proposes; It Does Not Issue {#proposes-only}

The Mission Shaper MUST NOT issue, derive, or certify authority of any
kind. It produces a shaped proposal, which is untrusted client input
under the issuance profile until the Mission Issuer validates and
narrows it and binds authority at the approval event
({{I-D.draft-mcguinness-oauth-mission}}, Section "Submission via PAR").
Nothing in this document changes that treatment, and a shaper
SHOULD NOT structure its output to imply otherwise.

Three consequences follow:

1. It does not act as a credential issuer. A shaper that signs its
   output as a statement of authority, attaches an authority
   assertion, emits a credential, or otherwise behaves as a credential
   issuer is acting outside this role and is NOT RECOMMENDED. A
   deployment MAY integrity-protect shaper output for client-internal
   reasons, for example to detect tampering between the shaper and the
   submission step in a multi-process client ({{multi-process}}). Such
   protection has no authority semantics at the Mission Issuer and
   MUST NOT be relied upon beyond the client.

2. It does not mimic Mission Issuer output. The Mission Intent proposal
   MUST NOT carry `mission.id`, `intent_hash`, `authority_hash`, an
   Authority Set, a lifecycle state, or approving-principal evidence.
   The Mission Issuer produces those values on the Mission record at
   and after the approval event ({{I-D.draft-mcguinness-oauth-mission}},
   Section "Mission Record"). The issuance profile rejects a Mission
   Intent that carries an unrecognized top-level member, including any
   such issuer-output member, with the `invalid_request` error code
   ({{I-D.draft-mcguinness-oauth-mission}}, Section "Submission via
   PAR").

3. It does not cross the trust boundary. Admitting input across the
   boundary is a Mission Issuer action. The shaper does not initiate
   the submission, call the pushed authorization request endpoint or
   the authorization endpoint, handle the authorization response,
   select the recipient Mission Issuer on its own authority, or attest
   to the submission on the Mission Issuer's behalf. It produces an
   input; the client transmits it; the Mission Issuer decides what to
   do with it.

## Deployment Roles {#roles}

This document separates four roles that implementations often
collapse:

Mission requester:
: The user or component that supplies the task request to be shaped.

Mission Shaper:
: Produces a shaped proposal and Shaping Evidence. Not authoritative
  for policy or consent.

Mission Issuer:
: The Authorization Server that validates the proposal, derives the
  Authority Set, records the approval event, and issues Mission-bound
  credentials under the issuance profile.

Capability source:
: A resource-owning catalog, metadata endpoint, policy service, or
  other source the shaper consults to resolve candidate resources and
  actions.

A deployment MAY co-locate these roles, but it SHOULD preserve the
authority boundary: shaping produces a proposal, issuance creates an
approved Mission, and runtime enforcement permits or denies actions.

# Processing Model {#processing-model}

A shaper processes a request in the following order, which the
remaining sections follow:

1. Normalize and classify the task input.
2. Separate facts the requester supplied, facts trusted context
   supplied, and facts the shaper inferred.
3. Resolve candidate resources and actions against capability sources
   ({{capability-resolution}}).
4. Apply deployment shaping policy, including any shaping ceiling and
   risk classification, while constructing the proposal
   ({{mission-intent-proposal}}).
5. Detect material ambiguity ({{ambiguity}}).
6. Produce one outcome: a shaped proposal, a request for
   clarification, or a refusal.
7. Record Shaping Evidence and, for a proposal, optionally compute a
   `shaping_evidence_hash` ({{shaping-evidence}}).

# Capability and Resource Resolution {#capability-resolution}

The shaper SHOULD NOT skip capability resolution merely because a task
is plausible in natural language. A request such as "email the
customer" does not identify which mailbox, sender, recipient, template,
or data source is allowed unless the deployment's capability sources or
policy resolve those details.

Before proposing a resource, the shaper SHOULD establish its
resolution basis, which is one of the following:

`catalog`:
: Resolved from a catalog, metadata endpoint, API description, tool
  catalog, or equivalent source.

`policy`:
: Selected by a deployment policy rule.

`user_supplied_exact`:
: The requester supplied a concrete resource identifier, and the
  shaper verified that it is admissible for shaping.

`capability_projection`:
: A resource-owning system or Authorization Server supplied an allowed
  resource and action projection for this task.

A model-generated capability name with none of these bases is
unresolved ({{refusal}}).

For each resolved capability, Shaping Evidence SHOULD record the
following, as a `capability_resolutions` entry ({{shaping-evidence}}):

- what was requested (`requested`);
- what it resolved to (`resolved`);
- the basis (`basis`);
- the source consulted, for `catalog` and `capability_projection`
  (`source_uri`); and
- where available, a digest over the source representation
  (`source_digest`), so that approval and runtime enforcement can
  detect drift.

A confidence value, if recorded, is audit evidence only, and a party
that receives it MUST NOT treat it as authority.

# Mission Intent Construction {#mission-intent-proposal}

A shaped proposal has two parts: a Mission Intent proposal, which
describes the task, and an optional Authority Proposal, which proposes
concrete authority for it ({{authority-proposal}}). The Mission Intent
proposal MUST satisfy the syntactic requirements of the issuance
profile's Mission Intent object ({{I-D.draft-mcguinness-oauth-mission}},
Section "Mission Intent"); {{construction-guidance}} covers each member.
The proposal MUST be bounded enough for the Mission Issuer to derive an
Authority Set without interpreting natural language as authority.

The shaper SHOULD NOT include a resource merely because the task text
implies it might be useful: each resource has a resolution basis
({{capability-resolution}}), or the shaper produces a clarification
request or a refusal.

## Mission Intent Members {#construction-guidance}

The following guidance maps a request or trigger onto each Mission
Intent member. It is guidance, not an algorithm. Concrete authority
(actions, structured constraints, and delegation facts) does not
appear in the Intent; it belongs in the Authority Proposal
({{authority-proposal}}).

`goal`:
: A concise summary in the form the Approver sees at consent. It
  preserves the requester's framing, so that the disclosure matches
  the requester's understanding. The shaper SHOULD NOT quote verbatim
  prompt text that contains instructions or commands
  ({{prompt-injection}}).

`goal_lang`:
: The language tag of the Intent's human-readable members (`goal`,
  `task_bounds`, and `success_criteria`), when the shaper knows it.

`target_resources`:
: The resources, datasets, tools, or domains the request referenced,
  each as an absolute URI. A human-readable label belongs in Shaping
  Evidence as an audit annotation, not in `target_resources`. Every
  `resource` value in the Authority Proposal appears here; the
  issuance profile refuses a proposed entry whose `resource` is not
  among `target_resources` with the `invalid_request` error code
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Authority
  Proposal"). The shaper SHOULD NOT widen `target_resources` beyond
  what the request referenced: a resource added "for convenience"
  enlarges approved authority.

`task_bounds`:
: Free-text bounds the requester expressed, plus the deployment-policy
  bounds always applied, so that the Approver sees the full set of
  bounds. Where a bound is machine-enforceable, the shaper also emits
  it as a structured constraint in the Authority Proposal; the Mission
  Issuer never parses the prose ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Mission Authority"). The shaper SHOULD NOT silently drop a
  user-expressed bound; it records the bound in `task_bounds` or in
  Shaping Evidence, or it requests clarification or refuses.

`success_criteria`:
: Free-text observable outcomes that show the task is complete,
  phrased for the Approver. They are disclosure and audit material
  only. The shaper SHOULD NOT encode authority in `success_criteria`,
  which carries no machine semantics in the issuance profile.

`purpose`:
: If the client has registered purposes, the registered purpose URI
  that matches the task. If none matches, the shaper omits `purpose`
  or requests clarification instead of choosing the nearest one:
  `purpose` can key the Mission Issuer's configured mapping
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission
  Authority"), so a wrong choice changes the derived authority
  ({{prompt-injection}}). The shaper SHOULD NOT invent a new `purpose`
  URI.

`expires_at`:
: The earliest expiry that lets the task complete; if the request names
  no bound, a conservative deployment default. The shaper does not
  request the maximum the Mission Issuer allows, and the Mission Issuer
  can narrow the value further.

`requested_derivation_limit`:
: Proposed only where the Mission Issuer implements
  {{I-D.draft-mcguinness-oauth-mission-derivation-limits}}; a Mission
  Issuer without it refuses the member as an unknown Intent member.
  Where the task implies a natural issuance count (a one-shot read, a
  fixed number of scheduled runs), the shaper proposes that count.
  Otherwise it omits the member, which leaves the limit to deployment
  policy alone, and that policy can impose none
  ({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}, Section
  "Effective Limit"). A proposed count can only lower the effective
  limit. The shaper does not propose a large round number "to be
  safe": a high guess adds no bound that policy does not already set,
  and it misleads the Approver about what was requested.

Other companion members:
: A companion profile can define further top-level Mission Intent
  members (for example, the consumption bounds of
  {{I-D.draft-mcguinness-mission-metering}}). The shaper emits the ones
  the deployment's adopted companions recognize. It SHOULD NOT emit a
  member the deployment does not recognize, since the issuance profile
  rejects an Intent that carries one.

## Authority Proposal {#authority-proposal}

The Mission Intent carries no authority members. Where a task calls for
concrete authority (actions, structured constraints such as
`max_amount`, or delegation facts), the shaper produces an Authority
Proposal: an `authorization_details` array {{RFC9396}} that the client
submits alongside the Intent ({{I-D.draft-mcguinness-oauth-mission}},
Section "Authority Proposal"). The Mission Issuer treats it as
untrusted input and derives each Authority Set entry as a narrowing of
a proposed entry.

Where cross-vendor interoperability matters, the shaper SHOULD carry
the concrete candidate authority it proposes (the resources, actions,
and constraints) in an Authority Proposal, and record the same
Authority Proposal in Shaping Evidence. The Mission Issuer then
derives the Authority Set in narrowing mode, each derived entry a
subset of a proposed entry, rather than from a configured mapping
keyed on the Intent ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission Authority"). Narrowing is the portable derivation path. The
proposal format and the narrowing rule are interoperable, so the
resulting Authority Set is enforceable and auditable across domains;
only the Mission Issuer's policy choice of what to narrow to stays
local.

The proposal MUST NOT present issuer outputs as approved authority: the
derived Authority Set is the Mission Issuer's product
({{proposes-only}}). A shaper that has resolved concrete facts (for
example, the actions a resource supports, or that the task implies
delegated execution) proposes them in the Authority Proposal and
records the same facts in Shaping Evidence for audit only. Shaping
Evidence is never an input to derivation.

## Shaping Ceiling and Default Deny {#authority-ceiling}

The shaper SHOULD apply a default-deny posture: its proposal contains
only resources that have a positive basis in the request, context,
capability sources, and shaping policy, and only the `task_bounds` and
`success_criteria` the shaper can defend. It does not include a broad
resource class as a fallback for unresolved detail.

When the concrete objects of an open-ended task are not known at
shaping time, the shaper SHOULD express the bound as invariants over
those objects (the owning customer, the tenant, an amount ceiling,
read-only except named writes, a time window), instead of reaching for
a broad resource class to anticipate them. Each invariant is a
structured constraint in the Authority Proposal, which bounds the
derived authority, and is restated in `task_bounds` for the Approver.
The Mission Issuer derives the same Authority Set whatever
`task_bounds` says ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Mission Authority"), and runtime enforcement applies the constraints
per object at the point of use.

The shaper SHOULD propose a Mission Intent scoped to one concrete task,
not to an agent's whole session or standing role. When a request spans
several distinct tasks, it proposes several task-scoped Mission
Intents instead of one broad proposal, so that each resulting Mission
stays narrow and is approved and revoked separately.

When a deployment or caller supplies a shaping ceiling, the proposal
MUST be a subset of it: each Authority Proposal entry is a subset of
a ceiling entry of the same type under that type's subset rule
({{I-D.draft-mcguinness-oauth-mission}}, Section "Subset Rule"), and
each `target_resources` value is among the resources the ceiling's
entries name. An Intent submitted without an Authority Proposal can be
derived through the Mission Issuer's configured mapping, which can
grant more actions on the same resources than the ceiling allows.
When the ceiling must constrain authority, the shaper MUST therefore
produce an Authority Proposal. If the task cannot be completed within
that ceiling, the shaper MUST request clarification, refuse, or emit a
partial proposal. It MUST NOT silently drop necessary authority: it
emits a partial proposal only when both of the following hold:

- Shaping Evidence records the excluded authority; and
- the outcome clearly indicates that the proposal may not satisfy the
  task.

The Mission Issuer enforces its own ceiling whether or not a shaping
ceiling is present.

## Delegation and Child Missions {#delegation}

The shaper does not author the `delegation` member of an Authority Set
entry ({{I-D.draft-mcguinness-oauth-mission-resource-access}}). If the
task implies sub-agents, background workers, or other delegated
execution, the shaper SHOULD propose that fact in the Authority
Proposal, recording the same fact in Shaping Evidence for audit only;
the Mission Issuer narrows it when deriving `delegation`, or refuses.
The shaper MAY also describe the desired delegation bound in
`task_bounds` or `success_criteria`. The shaper SHOULD NOT infer
delegated execution from the existence of a task graph or an agent
harness: a child actor needs explicit authority derived by the Mission
Issuer, not session ancestry.

Where a deployment creates Child Missions
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), turning a
sub-task into the proposed Child Mission Intent is a shaping act, and
this document applies to it unchanged. The Parent Mission's Authority
Set is the shaping ceiling. The child-delegation profile refuses a
child that is not a strict subset of its parent, so a proposal that
exceeds the parent cannot be approved; the shaper instead requests
clarification, refuses, or emits a partial proposal
({{authority-ceiling}}). Shaping Evidence for a child proposal SHOULD
record the parent Mission identifier (`parent_mission`) and the
parent-derived ceiling it shaped under (`shaping_ceiling`).

# Ambiguity Handling {#ambiguity}

The shaper SHOULD classify material ambiguity. Ambiguity is material
when choosing one interpretation over another would change the
Authority Set, the action class, the actor allowed to exercise it, the
expiry, or the risk posture.

For material ambiguity, the shaper SHOULD do one of the following:

1. request clarification ({{clarifications}});
2. emit a narrower proposal that excludes the ambiguous authority and
   record the exclusion in Shaping Evidence; or
3. refuse with a reason ({{refusal}}).

When the excluded authority is necessary for the task, the narrower
proposal is a partial proposal: Shaping Evidence MUST record the
excluded authority, and the outcome MUST indicate that the proposal
may not satisfy the task, as under a shaping ceiling
({{authority-ceiling}}).

When a shaper resolves an ambiguity in the broadening direction,
Shaping Evidence MUST record the resolution and, where deployment
policy permits that default resolution, the policy rule that
authorized it. The requirement is stated on the observable artifact
because the Mission Issuer cannot observe the shaper's internal
reasoning. A proposal that broadens authority on an ambiguity without
a corresponding Shaping Evidence record does not follow this document.
The Mission Issuer enforces its own ceiling and consent regardless of
what the shaper recorded.

Requesting clarification is not approval. The requester's answer is
incorporated into the Mission Intent, and the Mission Issuer still
validates, narrows, and renders the consent disclosure for binding
approval. A shaper MUST NOT treat answered clarifications as a reason
to skip the Mission Issuer's consent step: the shaper is not the
Approver's agent for consent.

## Clarifications {#clarifications}

A clarification SHOULD be phrased so that the requester can understand
the authority consequence of each answer. "Need more scope?" is not
sufficient; "May this Mission read invoices for customer 5678 in
addition to customer 1234?" is. A clarification SHOULD identify the
authority consequence of each offered choice. It SHOULD state what the
shaper will do if it is left unanswered (refuse, narrow, or wait).

Clarification runs from the shaper to the requester and resolves task
ambiguity before a proposal exists. The reverse channel, in which the
Approver questions the proposal at the consent surface, is Disclosure
Interrogation ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}});
Shaping Evidence, in particular `entry_rationales`, is its grounding
material ({{shaping-evidence}}).

## Refusal {#refusal}

Refusal is a shaper-internal decision. It requires no Mission Issuer
involvement, and this document defines no wire-level refusal error. A
shaper SHOULD refuse to shape when one of the following conditions
holds. Each label is a recommended value for Shaping Evidence and for
reporting the refusal to the client:

`unsupported_task`:
: The shaper cannot produce a Mission Intent for the task class.

`unresolved_resource`, `unresolved_action`:
: A requested resource or action cannot be resolved to a capability
  source ({{capability-resolution}}).

`outside_authority_ceiling`:
: The task requires authority outside the deployment or caller
  shaping ceiling ({{authority-ceiling}}).

`policy_prohibited`:
: Deployment policy prohibits shaping the task.

`material_ambiguity`:
: Material ambiguity remains, and policy requires refusal instead of
  clarification.

`unsafe_to_shape`:
: The request includes adversarial, conflicting, or untrusted content
  that prevents a defensible proposal ({{prompt-injection}}).

A deployment MAY define additional labels. It SHOULD NOT reuse these
labels with a different meaning.

A shaper SHOULD NOT refuse merely because the requested authority is
broad, or because the Authority Set the Mission Issuer would derive
looks expensive. Breadth is the decision of the Mission Issuer and the
Approver, and cost is a runtime concern; refusing on those grounds
substitutes the shaper's judgment for the Approver's.

# Shaping Evidence {#shaping-evidence}

Shaping Evidence records how a proposal was produced. It is audit
material: it does not grant authority and MUST NOT be used by a
Resource Server or Policy Decision Point (PDP) to permit an action. It
keeps the intent generator a distinct, attributable role: a record of
what the shaper emitted, separate from the requester who asked, the
Approver who consented, and the agent that executes
({{I-D.draft-mcguinness-mission-architecture}}). This document defines
no required schema, media type, or transport for Shaping Evidence. The
digests in this section are canonical-object digests and envelope
anchors under the substrate's Default Commitment Construction, which
this document imports normatively
({{I-D.draft-mcguinness-mission-substrate}}, Section "Default
Commitment Construction").

The following members are RECOMMENDED content. They are not a required
schema: a deployment can omit a member that does not apply and can add
members of its own. Unless its entry says otherwise, a member applies
to every outcome.

`shaper_id`:
: String. Identifies the shaper.

`shaper_version`:
: String. Identifies the shaper implementation, model, policy bundle,
  or workflow version.

`outcome`:
: String. The outcome of this shaping pass: `proposal`,
  `partial_proposal`, `clarification`, or `refusal`
  ({{processing-model}}).

`refusal_reason`:
: String. A refusal label ({{refusal}}). Present when `outcome` is
  `refusal`.

`proposed_intent`:
: Object. The Mission Intent proposal exactly as emitted, which ties
  the evidence to the proposal it describes. Present when `outcome` is
  `proposal` or `partial_proposal`.

`proposed_authorization_details`:
: Array. The Authority Proposal exactly as emitted. Present when the
  shaper produced one.

`shaping_ceiling`:
: Array. The shaping ceiling applied ({{authority-ceiling}}),
  including one derived from a Parent Mission. Present when a ceiling
  was supplied.

`parent_mission`:
: String. The Parent Mission identifier. Present for a Child Mission
  proposal ({{delegation}}).

`input_digest`:
: String. A digest over the shaping request, in the integrity-anchor
  form of the issuance profile ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Integrity Anchors"), computed over the JCS canonical bytes
  of the request after removing the fields that the named exclusion
  ruleset marks as not retained. To make the digest recomputable by a
  later auditor, the evidence MUST also record
  `input_exclusion_ruleset`. A digest whose exclusion ruleset is not
  recorded cannot be reproduced.

`input_exclusion_ruleset`:
: String. An identifier, with version, of the exclusion ruleset
  applied to `input_digest`. An auditor recomputes the digest over the
  retained canonical input under that ruleset.

`user_supplied_facts`:
: Array of strings. Facts copied from the request.

`inferred_facts`:
: Array of objects, one per fact the shaper inferred, with the members
  `fact` (string), `evidence` (string, the supporting evidence), and
  `confirmation_required` (boolean, whether a human must confirm it).

`policy_decisions`:
: Array of strings. Identifiers of the policy rules applied during
  shaping.

`capability_resolutions`:
: Array of objects, one per resource or action, with the members
  `requested` (string), `resolved` (string), `basis` (string, a
  resolution basis of {{capability-resolution}}), `source_uri`
  (string, the source consulted, for `catalog` and
  `capability_projection`), `source_digest` (string, defined below),
  and optionally `confidence` (number, audit evidence only).

`entry_rationales`:
: Array of objects, one per proposed resource or action, with the
  members `applies_to` (object naming the `resource` and `action`) and
  `basis` (string, the user-supplied or inferred fact that motivated
  its inclusion). A consent surface draws on this record to answer why
  the task needs an entry (Disclosure Interrogation,
  {{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

`ambiguities`:
: Array of objects, one per material ambiguity, with the members
  `description` (string) and `handling` (string: `clarified`,
  `narrowed`, `refused`, or `resolved_by_policy`), plus `policy_rule`
  (string) when `handling` is `resolved_by_policy` ({{ambiguity}}).

`excluded_authority`:
: Array of objects in the form of Authority Proposal entries.
  Plausible authority the shaper deliberately excluded.

`refusal_input`:
: Object. For a re-proposal, the refusal signal that motivated it
  ({{re-shaping}}): the `error` code and any `error_description`, or
  the `mission_rejected_scope` and
  `mission_rejected_authorization_details` values of a required
  revision.

`predecessor_evidence`:
: String. For a re-proposal, the `shaping_evidence_hash` of the
  predecessor proposal's evidence, or a deployment identifier for that
  evidence when no hash was computed.

`model_trace`:
: Deployment-defined. Model prompts, outputs, or tool calls used
  during shaping. When retained, it MUST be treated as sensitive audit
  data ({{privacy-considerations}}). It MUST NOT be rendered as
  authority.

A `source_digest` is computed over the source representation the
shaper consulted: the JCS {{RFC8785}} canonical bytes when that
representation is a JSON document, and otherwise the bytes as
retrieved (for an HTTP retrieval, the response content after any
content coding is removed). It is encoded as an integrity anchor is:
`sha-256:` followed by the base64url encoding, without padding, of the
SHA-256 digest ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Integrity Anchors"). Approval and runtime enforcement detect drift by
comparing it with a digest of the current representation.

{{example}} shows Shaping Evidence for a complete example.

## Integrity and the Evidence Hash {#evidence-hash}

A deployment MAY bind a proposal to its evidence so that the Mission
record can cite how the proposal was produced. When it does,
`shaping_evidence_hash` is a string in the integrity-anchor form of the
issuance profile, computed as follows:

1. Place the Shaping Evidence object in the issuance profile's
   domain-separated `{typ, iss, value}` envelope, with `typ` set to
   `mission-shaping-evidence`, `iss` set to the Mission Issuer's
   `issuer` identifier, and `value` set to the Shaping Evidence object.
2. Compute the prefixed digest of the JCS {{RFC8785}} canonical bytes
   of that envelope.

The envelope supplies the `typ` domain separation and the `iss`
binding that a digest of the bare object would omit. The hash is an
audit commitment only.

Because the shaper is client-side and MAY build a proposal before the
target Mission Issuer is selected, the hash can be computed only once
the Mission Issuer's `issuer` is fixed. A proposal re-submitted to a
different Mission Issuer needs a `shaping_evidence_hash` recomputed
under that issuer's `issuer`.

A deployment MAY instead, or in addition, carry an integrity envelope
over the Shaping Evidence, for example a JWS {{RFC7515}} Compact
Serialization over the JCS canonical bytes of the evidence. When the
JWS is embedded in the evidence, the signing input omits the member
that carries it.

Where the deployment records Consent Evidence, the client conveys the
hash in the `mission_shaping_evidence_hash` request parameter, and the
Mission Issuer records it in the OPTIONAL `shaping_evidence_hash`
member of the consent-disclosure object
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

Neither the hash nor the envelope confers authority. A Resource Server
or PDP MUST NOT treat a shaping evidence hash as proof of authority.

When a Mission record cites a `shaping_evidence_hash`, the deployment
SHOULD retain the Shaping Evidence and its `input_exclusion_ruleset`
for as long as it retains the Mission record (the audit horizon of
{{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Record"), so
that the cited evidence stays reproducible. Retained Shaping Evidence
is not rewritten, for example to update a label: any change breaks the
commitment the Mission record cites.

# Submitting a Shaped Proposal {#composition}

## Entering the Issuance Flow {#oauth-composition}

The issuance profile defines a `mission_intent` parameter carried in a
Pushed Authorization Request (PAR) {{RFC9126}}, whose value is the
Submission envelope ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Submission via PAR"). The Mission Intent proposal is the envelope's
`intent` member. An Authority Proposal is the value of the
`authorization_details` parameter in the same request. The
Authorization Server {{RFC6749}}, acting as Mission Issuer, validates
and narrows the submission, renders the consent disclosure, records
the approval event, and derives the Authority Set.

Intent-bound evidence in the envelope's `evidence` array names the
exact `intent_hash` of the submitted Intent. Intent-bound evidence
obtained for an earlier candidate does not admit a re-shaped Intent
unless its evidence type explicitly authorizes that transformation and
defines how its lineage is verified. Otherwise, a shaping pass that
changes the Intent needs intent-bound evidence for the Intent it
actually submits
({{I-D.draft-mcguinness-oauth-mission-submission-evidence}}, Section
"Evidence Binds One Exact Intent").

The shaper hands its output to the client, which performs the OAuth
flow ({{proposes-only}}) and MAY also convey a `shaping_evidence_hash`
so that the Mission record can cite the evidence ({{evidence-hash}}).
Because the issuance profile rejects an unrecognized top-level member
of both the Submission envelope and the Mission Intent, the hash is
not carried inside `mission_intent`. The client conveys it in the
`mission_shaping_evidence_hash` request parameter of the same pushed
authorization request, which Consent Evidence defines
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}, Section
"Shaping Evidence Hash Parameter"). A Mission Issuer that does not
implement Consent Evidence ignores the parameter, as it does any
unrecognized request parameter. Conveying it does not require the
Mission Issuer to trust the shaper: the value is a client-supplied
audit commitment, not verified provenance.

## Mission Issuer Handling {#issuer-handling}

A Mission Issuer MAY use a `shaping_evidence_hash`, and any Shaping
Evidence available to it, as input to the consent disclosure and to
audit, never to derivation ({{authority-proposal}}). Whatever a shaper
produced, the Mission Issuer, under the issuance profile:

- validates the Mission Intent independently;
- does not approve a Mission solely because a shaper produced it;
- derives the Authority Set under its own policy; and
- refuses, narrows, or requires approval as that profile requires.

A `shaping_evidence_hash` that the Mission Issuer records on the
Mission record is an audit commitment only.

Runtime enforcement does not consume shaper output either. Mission-Bound
Runtime Enforcement {{I-D.draft-mcguinness-mission-runtime}} consumes
the Mission Intent and the Authority Set on the Mission record, both
produced by the Mission Issuer, not by the shaper. A runtime that reads
Shaping Evidence for an authorization decision is misusing it.

# Re-Shaping {#re-shaping}

A proposal is not always approved as submitted, so shaping is a loop:
propose, learn what was refused, and propose again. Three refusal
signals feed the loop:

Derivation refusal:
: When its policy will not grant a well-formed request, the Mission
  Issuer refuses it with the `access_denied` error code. This covers a
  bare Intent that matches no configured mapping or whose mapped
  candidates policy narrows to nothing; the same code also reports an
  Approver who declines ({{I-D.draft-mcguinness-oauth-mission}},
  Section "Error and Challenge Mapping"). An Authority Proposal entry
  of an unsupported type, or one that fails its type's definition, is
  refused with the `invalid_authorization_details` error code. That is
  a construction error to correct, not a signal to narrow. Narrowing or
  omitting a valid proposed entry is not a refusal; the granted
  `authorization_details` reports it
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Authority
  Proposal").

Deferred denial:
: Under deferred approval, a reviewer that will grant only a narrowed
  subset of the proposal resolves the deferral to `access_denied`, and
  the client submits a fresh, narrower Mission Intent, which the
  shaper constructs ({{I-D.draft-mcguinness-oauth-mission-approval}}).

Required revision:
: Under approval revision, the `mission_rejected_scope` and
  `mission_rejected_authorization_details` members identify the
  refused dimensions in machine-readable form. The shaper uses them to
  plan the narrowed revision
  ({{I-D.draft-mcguinness-oauth-mission-approval-revision}}).

Re-shaping is shaping. A re-proposal passes through the full
processing model ({{processing-model}}) and is a fresh proposal with
fresh Shaping Evidence. Evidence for a re-proposal SHOULD record the
refusal input that motivated it (`refusal_input`: the error, the
resolution, or the rejected dimensions) and MAY reference the
predecessor proposal's evidence (`predecessor_evidence`), so that an
auditor can read the narrowing chain end to end.

A re-proposal after an authority refusal (a policy `access_denied`, a
deferred denial, or a required revision) narrows. A refusal is a
signal to propose less, not to propose the same authority under
different names. A shaper SHOULD NOT re-encode refused authority in
new vocabulary. It MUST NOT use iterative resubmission to probe the
Mission Issuer's policy boundary ({{silent-broadening}}). When a
narrower proposal can no longer complete the task, the shaper requests
clarification, refuses, or emits a partial proposal
({{authority-ceiling}}). A task that needs more than was refused is a
new proposal through the normal flow, not a widened retry.

A re-proposal after a construction error (`invalid_request` or
`invalid_authorization_details`) corrects the encoding instead. It
carries the same intended authority and does not broaden it; an entry
that failed validation has no subset relation to narrow against.

# Deployment Considerations {#deployment-considerations}

## Exposing Shaping as a Service {#exposing-shaping-as-a-service}

This document requires no shaping endpoint. A deployment that factors
shaping into a network service for engineering reasons MAY expose it
over HTTPS. The request and response formats of such a service are a
local implementation detail, not an interoperability contract, and
their description here is non-normative; the authentication
requirement below is normative.

A request typically conveys the task (free text, structured fields, or
both), the subject and agent on whose behalf the Mission would run,
deployment context, an optional shaping ceiling, and the capability
sources the shaper may consult. A response typically conveys an
outcome (a shaped proposal, a set of clarifications, or a refusal),
Shaping Evidence, and, for a proposal, an optional
`shaping_evidence_hash`. A deployment that advertises such an endpoint
in its metadata might use fields such as `mission_shaping_endpoint`
and `mission_shaping_profiles_supported`.

Such an endpoint MUST be authenticated when it can reveal sensitive
task, tenant, or resource information; an anonymous shaping endpoint is
appropriate only for public, non-sensitive tasks. The service remains
client-side machinery that produces an untrusted proposal, and it is
not a principal to the Mission Issuer ({{client-side}}).

## Declaring the Shaping Posture {#adds-and-does-not}

A deployment that runs a shaper can declare the following in its
Mission Deployment Profile, the deployment-level manifest defined by
{{I-D.draft-mcguinness-mission-architecture}}:

- whether shaping is in the submission path;
- the shaper version policy;
- whether Shaping Evidence is retained, and for how long; and
- whether Mission records cite `shaping_evidence_hash`.

The shaping posture then appears in the same artifact as the
deployment's other claims, and its absence is visible.

Shaping is not part of any Mission Assurance Level, and no level
requires it: the levels are built from issuer-side and runtime-side
guarantees, and the shaper is client-side
({{I-D.draft-mcguinness-mission-architecture}}). What shaping improves
at every level is the input: better proposals yield narrower Missions,
clearer consent disclosures, and a reviewable trail from request to
authority.

# Security Considerations {#security-considerations}

The Security Considerations of the issuance profile apply. The shaper
sits at the boundary where a prompt becomes a Mission Intent, and its
security properties follow from its role ({{proposes-only}}).

## Model Output Is Not Authority {#model-output}

A model-based shaper can draft a Mission Intent, but a deployment
MUST NOT let model output grant or widen access ({{proposes-only}}).
A deployment that lets a model's proposal become active without
validation and approval is not following this document. A model-based
shaper inherits its model's failure modes (hallucinated resources,
fabricated constraints, inconsistent paraphrase, and sensitivity to
small input perturbations), and SHOULD record the model identifier and
version in Shaping Evidence so that failures can be attributed.

## Shaper Compromise Does Not Directly Grant Authority {#shaper-compromise}

A compromised shaper can produce an arbitrary Mission Intent and
suppress ambiguity, but it cannot, by itself, cause the Mission Issuer
to approve that Intent. A compromised shaper can:

- cause spurious proposals to be submitted;
- mis-shape an Intent so that the Approver approves a task different
  from the one intended; or
- leak prompts through shaper-local logging.

It cannot:

- issue credentials;
- set or change Mission lifecycle state;
- bypass the approval event; or
- cause a Resource Server to act without authority issued by the
  Mission Issuer.

The Mission Issuer remains the enforcement point for approval: the
issuance profile requires it to validate the proposal and derive
authority under its own policy ({{I-D.draft-mcguinness-oauth-mission}},
Section "Mission Authority"). Deployments SHOULD monitor shaper
versions and evidence for anomalous broadening.

## Prompt Injection and Untrusted Content {#prompt-injection}

The shaper's input is, by assumption, partly or wholly
attacker-influenceable. Prompts can contain pasted content, content the
user was tricked into typing, or content arriving through a non-prompt
trigger such as an inbound email or webhook. Task text, tickets,
documents, tool descriptions, and catalog metadata can all carry
instructions aimed at the shaper. Concrete threats include attempts
to:

- expand `target_resources` beyond what the user requested;
- push `expires_at` past deployment policy;
- suppress a stated constraint; or
- select a `purpose` the user did not choose.

Mitigations the shaper SHOULD apply:

1. Treat all prompt and attachment content as untrusted data, not as
   instructions to the shaper. Do not let it alter shaper policy or
   override deployment defaults.
2. Apply the refusal behavior of {{refusal}} when the input exhibits
   injection patterns.
3. Do not echo verbatim prompt-derived instruction text into `goal` or
   `task_bounds` that the Approver will read. Paraphrase, or quote with
   clear attribution, but do not present injected content as if it
   came from the user.
4. Use the resolved vocabulary of the capability sources as a hard
   allowlist ({{capability-resolution}}); do not infer new authority
   types from the prompt.
5. Record the prompt, the parsed intent, and the chosen defaults in
   Shaping Evidence so that an auditor can reconstruct what the shaper
   saw.

Injection cannot be fully eliminated at the shaper. The defense in
depth is that the Approver sees the Mission Intent in a consent
disclosure rendered by the Mission Issuer, not by the shaper, before
authority is bound. A shaper that builds the Intent truthfully and a
Mission Issuer that renders the disclosure truthfully together make
injection visible at the approval step.

## Silent Broadening and Stale Capability Sources {#silent-broadening}

The primary failure mode is silent broadening: a vague goal becomes a
wide Authority Set. The ambiguity rules of {{ambiguity}} fail closed by
requiring clarification, narrowing, or refusal. A proposal shaped
against an outdated catalog can also resolve the wrong capability.
Capability resolutions SHOULD record source digests
({{capability-resolution}}) so that approval and runtime enforcement
can detect drift. A shaped proposal can also go stale. When a
proposal's freshness bound (for example, an expiry, or a source digest
that no longer matches) shows that it was built against a capability
catalog or policy version that has since changed, the client SHOULD
re-shape it instead of submitting it. Deployments SHOULD re-shape when
catalog data is volatile.

Re-shaping adds a loop variant of the same failure: widening by retry,
in which refused authority is resubmitted in different words until
something passes, or successive proposals walk the Mission Issuer's
policy boundary ({{re-shaping}}). A deployment SHOULD monitor for a
requester whose successive proposals for one task broaden; Shaping
Evidence chained across re-proposals is the record that makes such a
pattern visible.

## Shaper-to-Client Integrity in a Multi-Process Client {#multi-process}

In a client where the shaper runs in a different process or on a
different machine from the OAuth submission code, the step from shaper
to submission is an in-client boundary. An attacker between the two
could alter the Mission Intent before submission. The Mission Issuer
still validates the altered Intent and renders its consent disclosure,
so the Approver remains the final line of defense, but the altered
Intent will not match what the shaper produced. A deployment MAY apply
client-internal integrity protection between shaper output and the
submission code (a client-local signature, a process-isolated
channel). Such protection has no semantics at the Mission Issuer and
MUST NOT be carried into the Mission Intent as if it did
({{proposes-only}}).

# Privacy Considerations {#privacy-considerations}

The shaper turns a natural-language prompt, which can carry personal
data, business-confidential content, or free-form expression, into
structured artifacts. Its privacy considerations follow from where that
content flows.

The shaper copies or paraphrases prompt content into `goal`,
`target_resources`, and `task_bounds`. The Mission Issuer renders these
in the consent disclosure the Approver reads, and the Mission record
can retain them. A shaper SHOULD carry into these members only the
content needed to describe the task. It SHOULD NOT widen
`target_resources` or echo unrelated prompt content
({{construction-guidance}}). It SHOULD avoid copying third-party
personal data into `goal` where a non-identifying description
suffices.

Shaping Evidence gathers the prompt, applied defaults, inferences, and
model outputs into one artifact, so it concentrates sensitive content.
The shaper SHOULD apply the client's data-handling policy to prompt
content, including Shaping Evidence. Evidence sent outside the client's
trust domain (for example, to a centralized audit store) SHOULD carry
the same controls the client applies to any other prompt or
user-content log. Deployments SHOULD:

- minimize retained raw task text;
- prefer digests where full content is not required for audit;
- apply access controls equivalent to those used for Mission records;
  and
- be able to produce a redacted evidence record for audiences that need
  the provenance of the transformation but not the raw prompt.

The shaper introduces no identifier of its own and is not a separate
principal to the Mission Issuer ({{client-side}}). It therefore adds no
cross-party correlation surface beyond the prompt content it processes
and the client identity the Mission Issuer already sees.

# IANA Considerations {#iana}

This document has no IANA actions. The `mission_shaping_evidence_hash`
request parameter is registered by
{{I-D.draft-mcguinness-oauth-mission-consent-evidence}}; the metadata
names in {{exposing-shaping-as-a-service}} are examples and are not
registered.

--- back

# Worked Example {#example}

A user asks an agent: "Reconcile the Q3 invoices in the acme-corp
tenant and post any adjustments up to $500." The shaper scopes the
proposal to that one
task, bounds the work by invariants instead of enumerating invoices it
cannot yet know, and proposes only authority it can defend from the
request.

The following example shows the Mission Intent proposal, which the
client sends as the `intent` member of the Submission envelope:

~~~ json
{
  "goal":
    "Reconcile acme-corp Q3 invoices; post adjustments up to $500.",
  "target_resources": ["https://erp.example.com"],
  "task_bounds": [
    "Read only invoices in fiscal period 2026-Q3.",
    "Post journal entries of no more than $500.",
    "Tenant scope: acme-corp only."
  ],
  "success_criteria": ["All Q3 invoices for acme-corp reconciled."],
  "purpose": "urn:example:purpose:reconcile",
  "expires_at": "2026-11-05T00:00:00Z"
}
~~~

The following example shows the Authority Proposal, which the client
sends as the `authorization_details` parameter of the same pushed
authorization request. It uses the `mission_resource_access` type and
its Common Constraints
({{I-D.draft-mcguinness-oauth-mission-resource-access}}):

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"],
    "constraints": {
      "tenant": "acme-corp",
      "resource_issued_after": "2026-07-01T00:00:00Z",
      "resource_issued_before": "2026-09-30T23:59:59Z"
    } },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "tenant": "acme-corp",
      "max_amount": { "amount": "500.00", "currency": "USD" }
    } }
]
~~~

The following example shows the Shaping Evidence the shaper records
for this proposal. For brevity, it omits `proposed_intent` and
`proposed_authorization_details`, which repeat the two objects above:

~~~ json
{
  "shaper_id": "mission-shaper.example.com",
  "shaper_version": "policy-bundle-2026-06-30",
  "outcome": "proposal",
  "input_digest":
    "sha-256:InP9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4aB7cDe",
  "input_exclusion_ruleset": "standard-2026-06",
  "user_supplied_facts": [
    "tenant acme-corp",
    "fiscal quarter Q3",
    "adjustments up to $500"
  ],
  "inferred_facts": [
    {
      "fact": "Q3 means fiscal period 2026-Q3",
      "evidence": "the current fiscal year is 2026",
      "confirmation_required": false
    }
  ],
  "capability_resolutions": [
    {
      "requested": "read invoices",
      "resolved": "invoices.read",
      "basis": "catalog",
      "source_uri": "https://erp.example.com/.well-known/tools",
      "source_digest":
        "sha-256:rK6XgVWUx2qYxH37rHShEle6e_sRJcIkdrlaEMoNs_I"
    },
    {
      "requested": "post adjustments",
      "resolved": "journal-entries.write",
      "basis": "catalog",
      "source_uri": "https://erp.example.com/.well-known/tools",
      "source_digest":
        "sha-256:rK6XgVWUx2qYxH37rHShEle6e_sRJcIkdrlaEMoNs_I"
    }
  ],
  "entry_rationales": [
    {
      "applies_to": {
        "resource": "https://erp.example.com",
        "action": "invoices.read"
      },
      "basis": "the request asks to reconcile acme-corp Q3 invoices"
    },
    {
      "applies_to": {
        "resource": "https://erp.example.com",
        "action": "journal-entries.write"
      },
      "basis": "the request asks to post adjustments up to $500"
    }
  ]
}
~~~

This is only a proposal. The Mission Issuer, not the shaper, validates
it, narrows it to policy, and derives the Authority Set the agent is
bound to; each derived entry narrows an entry the shaper proposed. The
free-text `task_bounds` disclose the same bounds to the Approver and
grant nothing; the Mission Issuer never parses them. The invariants
(period, tenant, and amount) bound an open-ended task whose individual
invoices were unknown when the request was made. Had the request not
named the tenant, the shaper would have asked the requester instead of
guessing ({{clarifications}}).

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Restructured for readability without changing any requirement.
  Sections follow the processing model, and the shaper's role and the
  Authority Proposal each have one home. The construction table became
  a per-member list, the two examples became one end-to-end appendix
  showing the Intent, the Authority Proposal, and Shaping Evidence,
  and the Conformance section and "What Shaping Adds and Does Not"
  were folded into Conventions, Deployment Considerations, and the
  Introduction.

- Corrected statements against their sources: the derivation-refusal
  codes in Re-Shaping, the AAuth binding's intake (a natural-language
  proposal, not a Mission Intent), the narrowing mode that replaced
  the reproducibility rule, and open-ended invariants, which are
  Authority Proposal constraints rather than `task_bounds`.

- Reconciled the shaping-ceiling outcomes with Ambiguity Handling and
  defined a partial proposal; fixed the condition on the broadening
  record; named the parties the keywords bind; limited Shaping
  Evidence to consent disclosure and audit at the Mission Issuer;
  made signing and integrity envelopes consistent; and moved
  staleness to one client-side rule.

- Replaced the "sound shaper" idiom with BCP 14 keywords. Member
  guidance covers `goal_lang` and the `target_resources` containment
  rule, and `purpose` is chosen only when the request supports it.

- Only a re-proposal after an authority refusal narrows; a
  construction error is corrected without broadening. The
  derivation-limit and intent-bound-evidence guidance follow their
  owning drafts, and an ambiguity narrowing that drops necessary
  authority is a partial proposal.

- Renamed the `authority_source` resolution basis to
  `capability_projection`; retained evidence is not rewritten. The
  recommended evidence members are typed, with their applicability,
  new members for the outcome, the emitted proposal, the ceiling, the
  parent Mission, and the re-proposal chain, and a defined
  `source_digest`. A shaping ceiling is an `authorization_details`
  array, and one that must constrain authority requires an Authority
  Proposal.

- The evidence hash travels in the `mission_shaping_evidence_hash`
  pushed authorization request parameter that Consent Evidence
  defines.

# Acknowledgments
{:numbered="false"}

This document builds on Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} and complements Mission-Bound
Runtime Enforcement {{I-D.draft-mcguinness-mission-runtime}}.
