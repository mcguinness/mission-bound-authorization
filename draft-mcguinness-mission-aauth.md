---
title: "Mission-Bound Authorization for AAuth"
abbrev: "Mission AAuth"
category: std

docname: draft-mcguinness-mission-aauth-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - aauth
 - person server
 - governance
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC9421:
  I-D.draft-hardt-oauth-aauth-protocol:
    title: "AAuth Protocol"
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026
    seriesinfo:
      Internet-Draft: draft-hardt-oauth-aauth-protocol-08
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-hardt-aauth-r3:
    title: "AAuth Rich Resource Requests (R3)"
    target: https://dickhardt.github.io/AAuth/draft-hardt-aauth-r3.html
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-discovery:
    title: "Mission Open-World Discovery"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-discovery.html
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
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
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
  I-D.draft-mcguinness-mission-shaping:
    title: "Mission Shaping"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-shaping.html
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
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-security-model:
    title: "Mission Security Model"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html
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
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

The AAuth protocol gives agents their own identity and routes their
authorization through a Person Server, with a native mission concept:
an approved mission referenced by an approver URL and a hash,
signature-covered on every request and echoed in resource and auth
tokens. AAuth leaves the mission's structure implementation-defined,
gives it two states, and leaves governance evaluation to unspecified
Person Server policy. This document supplies those pieces from the
Mission model of Mission-Bound Authorization for OAuth 2.0, in
AAuth's own idiom: the blob's native members carry the Mission record
under a fixed equivalence, three flat members complete it, the
integrity anchors are a deterministic projection of the
s256-committed blob rather than stored fields, the approval
interaction is the approval event, the full Mission lifecycle rides
the mission log with revocation and expiry, and, because no
auth token is issued under a Mission without passing the Person Server,
the Person Server gates auth-token issuance on Mission state. In the
PS-asserted mode, and in the federated mode where the Access Server
carries the family mission members, the auth token is a Mission-bound
credential and the family's governance, enforcement, and evidence
profiles compose credential-carried; otherwise the binding is
Reference-only and consumers resolve Mission facts through the Person
Server. This is the third binding of the Mission model and the first to
a non-OAuth substrate.

--- middle

# Introduction

The AAuth protocol {{I-D.draft-hardt-oauth-aauth-protocol}} defines
agent-to-resource authorization in which an agent holds its own
cryptographic identity and a Person Server (PS) brokers user consent.
AAuth includes a native mission concept: the agent proposes a mission
at the PS, the PS and user clarify and approve it, and the approved
mission is referenced by the pair of the `approver` URL and `s256`,
the hash of the mission JSON. The reference travels in the
`AAuth-Mission` header, covered by the HTTP Message Signature
{{RFC9421}} on every request, and is echoed in the `mission` claim of
resource and auth tokens. The PS keeps a mission log and evaluates
every subsequent request against the mission's intent.

AAuth deliberately leaves three things open. The mission JSON's
structure beyond four required members is implementation-defined. The
mission has exactly two states, active and terminated, with
"transitions beyond completion", including revocation, deferred to a
companion specification. And how the PS evaluates a request against
the mission is unspecified PS policy. This document supplies exactly
those pieces from the Mission model of
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile"), and
it supplies them natively: AAuth's own blob members carry the Mission
record under a fixed equivalence (the `description` is the goal, the
`approved_tools` are the Authority Set, the `agent` is the
`client_id`), three flat members complete what the natives cannot
carry, the integrity anchors are computed as a deterministic
projection of the s256-committed blob rather than embedded beside
the members they commit, the propose-clarify-approve interaction is
profiled as the approval event, the full Mission lifecycle rides the
mission log with `revoked` and
`expired` added and the only-`active` rule gating every PS surface,
and the family's governance, enforcement, and evidence profiles
compose against the result.

The headline property is issuance gating. In AAuth's PS-asserted mode
the PS issues the auth token itself; in the federated mode the PS is
the mandatory gate through which the resource's Access Server is
reached. Either way, no auth token exists under a Mission without
passing the PS, so this binding gates credential issuance on Mission
state exactly as the issuance profile gates derivation ({{gating}}).
That is the
property the family's standalone OAuth binding, the Mission Authority
Server {{I-D.draft-mcguinness-mission-authority-server}}, structurally
forgoes.

This is the third binding of the Mission model and the first to a
non-OAuth substrate: the issuance profile binds the model to the OAuth
Authorization Server, the Mission Authority Server binds it to a
standalone service beside an unchanged Authorization Server, and this
document binds it to the AAuth Person Server.

## Applicability

This profile targets AAuth deployments that operate a Person Server
and use AAuth missions. Mission governance in AAuth is orthogonal to
the resource access modes: the governance surfaces are PS endpoints,
so any agent with a PS can operate under a Mission regardless of
which mode a resource supports. A deployment without a PS has no
party to fill the Mission Issuer role and cannot implement this
profile. This document tracks draft-hardt-oauth-aauth-protocol-08, an
individual Internet-Draft ({{limitations}}).

# Conventions and Terminology

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

This document uses Mission, Mission Intent, Mission Issuer, Authority
Set, Approver, Subject, `mission_id`, the integrity anchors
(`intent_hash` and `authority_hash`), the subset rule, the
only-`active` rule, and the audit horizon as defined by
{{I-D.draft-mcguinness-oauth-mission}}. It uses Person Server (PS),
Agent Provider, Access Server, agent token, resource token, auth
token, mission blob, mission log, the `AAuth-Mission` header, and the
resource access modes as defined by
{{I-D.draft-hardt-oauth-aauth-protocol}}. It additionally uses:

Mission-Bound Person Server:
: A Person Server conforming to this profile: it implements the
  Mission Issuer role over AAuth's mission surfaces ({{conformance}}).

Mission-Bound Agent:
: An AAuth agent that proposes structured intent, carries the Mission
  reference, and respects the Mission lifecycle ({{conformance}}).

# Mission Roles {#roles}

| AAuth role | Mission model role |
|---|---|
| Person Server | Mission Issuer: holds the Mission record, runs the approval interaction, gates auth-token issuance, serves Mission state |
| Person | Subject, and typically the Approver |
| Agent | Agent: the agent identifier is the Mission's `client_id`; the agent-token `cnf.jwk` key signs its requests |
| Resource | Resource Server |
| Access Server | Resource-side token issuer behind the PS gate; a PDP analog for resource policy |
| Agent Provider | Out of scope: the agent identity substrate |

The AAuth `approver` URL is the Mission `issuer`: AAuth fixes the
approver as the PS, so the Mission's `issuer` is the PS's issuer URL.
The Approver is the person the PS represents, or a principal the PS's
policy authorizes to approve on that person's behalf. The Agent
Provider is out of scope as agent identity is throughout the family:
it supplies the acting identity the Mission's `client_id` records,
and this profile adds no requirement to it.

# Mission Record {#mission-record}

AAuth's mission blob is the JSON object the PS returns at approval,
held only by the agent and the PS, and committed by `s256` over its
exact bytes ({{I-D.draft-hardt-oauth-aauth-protocol}}). This binding
makes the blob the wire carrier of the Mission record without
restating it: the blob's native members carry the record's facts
under a fixed equivalence, and three flat members carry what the
natives cannot. No nested record object is embedded, and no fact is
spelled twice.

A Mission-Bound Person Server MUST maintain a Mission record, as the
issuance profile's Mission Record section defines it, for every
mission it approves, with `issuer` equal to the `approver` URL. The
record's equivalence with the blob is fixed as follows:

- `intent.goal` **is** the blob's `description`; `created_at` **is**
  `approved_at`; `client_id` **is** `agent`; `issuer` **is**
  `approver`.
- The Authority Set **is** the `approved_tools` array under the
  projection of {{two-commitments}}: each tool entry is one
  `mission_resource_access` entry, its `resource` the entry's
  `resource`, its `name` the entry's single action, its
  `constraints` the entry's constraints. A tool with no `resource`
  projects to the PS's own issuer URL, PS-governed local action
  whose point-of-use evaluation belongs to the runtime layer. This
  equivalence is definitional, so the AAuth-native tool list and the
  committed authority cannot diverge: they are one structure.
- The approved Mission Intent is the canonical projection of
  {{two-commitments}} (`goal` from `description`, `resources` from
  the tool providers in order of first appearance, `expires_at`);
  when the approved Intent carries members the projection cannot
  express (structured `controls`, `proposed_authority` context), the
  blob carries the approved Intent verbatim in a flat
  `mission_intent` member, which then supersedes the canonical
  projection.

Three flat members complete the record, in AAuth's own style:

`mission_id`:
: REQUIRED. The Mission Identifier ({{reference}}).

`expires_at`:
: REQUIRED ({{lifecycle}}). RFC 3339 {{RFC3339}} date-time.

`policy_version`:
: REQUIRED. The derivation policy correlator, per the issuance
  profile.

What deliberately does not appear in the blob:

- the record's `state`: the blob is immutable under `s256`, and
  state is served by the lifecycle surfaces ({{lifecycle}});
- the integrity anchors: they are computed from the blob
  ({{two-commitments}}); and
- the `subject` and `approver` principals with their
  `approval_event_id`: the PS establishes the principals at approval
  as `{iss, sub}` objects whose `iss` is its own issuer URL and
  records them PS-side, where evidence and the status surfaces join
  them.

Keeping the person out of the portable artifact is AAuth's own
directed-identity posture, and this binding follows it.

The AAuth-native blob members are otherwise unchanged, and the blob
MAY carry additional session members per AAuth. Additional members
are committed by `s256` and, apart from `mission_intent`, not by
the integrity anchors.

## The Anchor Projection {#two-commitments}

The blob stores no anchors; the anchors are computed from it. AAuth's
`s256` is the unpadded base64url SHA-256 of the exact blob bytes as
returned, and the agent stores those bytes without re-serialization
({{I-D.draft-hardt-oauth-aauth-protocol}}). The family's anchors are
a deterministic projection of those committed bytes:

- **Authority projection**: for each `approved_tools` entry, in
  array order, one object `{ "type": "mission_resource_access",
  "resource": <tool resource, or the PS's issuer URL when absent>,
  "actions": [<tool name>], "constraints": <tool constraints, when
  present> }`. The resulting array is the Authority Set.
- **Intent projection**: `{ "goal": <description>, "resources":
  <the distinct tool resource values, in order of first appearance>,
  "expires_at": <expires_at> }`, unless the blob carries
  `mission_intent`, which is then the approved Intent verbatim
  ({{mission-record}}).

`intent_hash` and `authority_hash` are computed over these projected
objects per the issuance profile's envelope and canonicalization
rules, with the PS's issuer URL as the envelope `iss`; the core's
test vectors verify the pipeline, and {{record-example}} gives a
computed pair for the projection itself. Any holder of the blob
recomputes the anchors; no party needs them stored. The anchors
travel where family consumers live: the `mission` claim
({{mission-claim}}), consent and runtime evidence, Mandates, and
audit statements.

The two commitments answer different questions and neither
substitutes for the other ({{security-two-commitments}}): `s256`
answers "is this the blob the reference names", byte-exact and
session-inclusive; the anchors answer "what task and authority were
approved", domain-separated, issuer-bound, and comparable across the
family.

## Mission Reference and Resolution {#reference}

The (`approver`, `s256`) pair is the AAuth-native Mission reference.
The `AAuth-Mission` header is unchanged by this binding: no new
parameters are defined, and this document gives its existing
parameters family semantics (`approver` names the `issuer`, `s256`
locates the record).

A Mission-Bound Person Server MUST resolve `s256` to the Mission
record at every PS endpoint that takes a mission reference. Per
AAuth, a Resource or Access Server never dereferences the reference;
it consumes mission semantics through token claims and PS
evaluation.

`mission_id`, carried as the blob's flat `mission_id`
member ({{mission-record}}), is the family-surface identifier: the
Mission Status operation, lifecycle signals, consent evidence, runtime
evidence, and audit key on it
({{I-D.draft-mcguinness-oauth-mission-status}},
{{I-D.draft-mcguinness-mission-audit}}). The two names identify the
same Mission, and the record binds them.

## Worked Example {#record-example}

The approved mission blob for a reconciliation Mission at
`https://erp.example.com`, approved by `alice` at
`https://ps.example.com` for the agent
`aauth:reconciler@agent.example`:

~~~ json
{
  "approver": "https://ps.example.com",
  "agent": "aauth:reconciler@agent.example",
  "approved_at": "2026-10-15T14:32:11Z",
  "description":
    "Reconcile Q3 invoices and post adjustments under $500.",
  "approved_tools": [
    { "name": "invoices.read",
      "description": "Read invoices",
      "resource": "https://erp.example.com",
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      } },
    { "name": "journal-entries.write",
      "description": "Post journal entries",
      "resource": "https://erp.example.com",
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" }
      } }
  ],
  "capabilities": ["interaction"],
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "expires_at": "2026-12-31T23:59:59Z",
  "policy_version": "ps-policy:v4"
}
~~~

Every Mission fact rides a native member or one of the three flat
members; nothing is spelled twice. The projection of
{{two-commitments}} over this blob yields the two-entry Authority Set
(the two tools, with their constraints) and the canonical Intent
(`goal` from `description`, `resources`
`["https://erp.example.com"]`, `expires_at`), and the anchors
computed over those projections with the issuance profile's JCS
pipeline and `iss` `https://ps.example.com` are, reproducibly:

~~~ text
intent_hash    = sha-256:kYYJtTdI2RDrObFOdRDGonB7eRmiB65xwxqnw5Nikbk
authority_hash = sha-256:mdRUVZfU1BG_Bgla4mrLp6Q9NPVTJ-udnn88F1oXqFc
~~~

On the wire, `s256` is computed over the exact response body bytes;
for the compact (whitespace-free) serialization of the blob shown, in
the member order shown, it is:

~~~ text
AAuth-Mission: approver="https://ps.example.com";
    s256="w7zuCFWNcWtDb10bawnuQrMcVRGm9B8PKFpJUMoUzbs"
~~~

# Mission Intent {#mission-intent}

The agent's proposal to the PS's `mission_endpoint` is the Mission
Intent proposal. AAuth defines the proposal as a JSON object with a
Markdown `description` and an optional `tools` array
({{I-D.draft-hardt-oauth-aauth-protocol}}). This binding adds two
OPTIONAL proposal members:

`mission_intent`:
: A Mission Intent object as the issuance profile defines it. The
  issuance profile's syntactic rules apply unchanged: the object is
  closed at the top level, and it is untrusted client input, never
  authority. The PS MUST bound its size and array lengths.

`resource` (on each `tools` entry):
: An absolute URI naming the tool's provider.

`constraints` (on each `tools` entry):
: An object of machine-actionable bounds on the tool, in the
  issuance profile's `constraints` shape: Common Constraint names
  with their shared semantics, other names deployment-defined.

A Mission-Bound Agent SHOULD include `mission_intent`. With a
structured Intent the PS derives the Authority Set by narrowing, which
the issuance profile makes reproducible and auditable; from
`description` and `tools` alone the derivation is generative, under
that profile's disclosure and recording rules for generative
derivation.

In either case the approved Intent is carried by the canonical
projection where it fits, and verbatim in the blob's
`mission_intent` member where it does not ({{mission-record}}). When
the proposal's Intent carries no `expires_at`, the PS MUST set one
by policy, since the record requires it.

Derivation lands in the `approved_tools` shape, consistent with the
issuance profile's Modeling Tools and Function Calls section: each
derived Authority Set entry is one tool entry, its provider the
entry's `resource`, its name the entry's action, its bounds the
entry's `constraints`. The tools are the Authority Set by definition
under the projection of {{two-commitments}}, so the AAuth-native
tool list and the committed authority cannot diverge: they are one
structure. For a tool with no `resource` (a local tool with no
remote provider), the projection sets the entry's `resource` to the
PS's own issuer URL: the authority is PS-governed local action, and
its point-of-use evaluation belongs to the runtime layer, not to
issuance.

AAuth's permission endpoint remains the per-call path for actions
outside the Authority Set: each grant there is an individually
approved action recorded in the mission log, and it does not widen the
committed set. The proposal is exactly the shaping profile's Mission
Intent proposal; a deployment that shapes free-text instructions into
structured Intents composes here unchanged
({{I-D.draft-mcguinness-mission-shaping}}).

# Mission Approval {#approval}

AAuth's propose, clarify, approve interaction is the approval event.
It is natively asynchronous: the PS returns a 202 deferred response
while review runs, so no approval blocks a front-channel redirect,
exactly as at a Mission Authority Server
({{I-D.draft-mcguinness-mission-authority-server}}). It executes the
issuance profile's approval steps, mapped onto the interaction:

1. Authenticate the Approver: the person the PS represents, or a
   principal the PS's policy authorizes to approve for that person.
   When a structured Intent carries `controls.acr`, the authentication
   MUST be one the deployment's policy maps as satisfying the named
   class.
2. Establish the Subject: the PS MUST itself establish the Subject's
   (`iss`, `sub`), with `iss` its own issuer URL. The PS MUST NOT
   take the Subject from unauthenticated client input.
3. Derive the Authority Set from the proposal ({{mission-intent}})
   and render it for consent under the issuance profile's rendering
   rules. The Markdown `description` and the agent's clarification
   messages are attacker-influenceable text: the PS MUST render them
   inert and sanitized, mitigate direction-override and confusable
   presentation, and visually distinguish the derived Authority Set
   from client-supplied text ({{security-rendering}}).
4. Compute the integrity anchors with the PS's issuer URL as the
   envelope `iss`.
5. Create the Mission record in the `active` state atomically with
   the approval decision, construct the blob from the approved
   native members and the flat members ({{mission-record}}), and
   compute `s256` over the response bytes; the anchors of step 4 are
   thereafter recomputable from those bytes ({{two-commitments}}).
   The PS MUST NOT return the
   approved (`approver`, `s256`) reference before the record is
   `active`.

Per AAuth, the PS or user MAY refine the description and tools during
clarification, and the approved mission MAY differ from the proposal.
The recorded Intent and Authority Set are the refined ones. If the
derived Authority Set changes between rendering and consent, the PS
MUST recompute and re-obtain consent per the issuance profile.

Mission Consent Evidence composes unchanged, with the PS as the
committing issuer
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

AAuth's clarification chat is the shaping profile's clarification
step ({{I-D.draft-mcguinness-mission-shaping}}). When the user
questions the proposal rather than the task ("why does this need
write access to my finance folder?"), the chat is also the
consent-evidence profile's Disclosure Interrogation: an answer the
PS presents in its own voice is grounded in recorded shaping or
provenance material, the agent's chat replies stay
attacker-influenceable text under {{security-rendering}}, and the
chat the mission log retains ({{security-mission-log}}) is the
interrogation record.

# Mission Lifecycle {#lifecycle}

AAuth gives a mission two states, active and terminated, and defers
transitions beyond completion to a companion specification. This
binding supplies them: the Mission lifecycle is the issuance profile's
state space, extended by the status profile where the deployment
adopts it ({{I-D.draft-mcguinness-oauth-mission-status}}), and the
only-`active` rule governs, with unrecognized states fail-safe
non-active. Transitions live in AAuth's own idiom: each is a
mission-log event, the log is the authoritative transition history,
and AAuth's endpoints surface the current state through the existing
mission status machinery.

| Family state | AAuth surface |
|---|---|
| `active` | active: PS endpoints serve the mission |
| `completed` | terminated (`mission_terminated`) |
| `revoked` | terminated (`mission_terminated`) |
| `expired` | terminated (`mission_terminated`) |
| `suspended` | deferred: 202 pending at PS endpoints |

AAuth's two states are a projection of this space: only `active` maps
to active, and every terminal state surfaces on AAuth endpoints as the
`mission_terminated` error with `mission_status` `terminated`, which
already instructs the agent to stop. The family surfaces
({{state-surfaces}}) report the distinct state. This binding adds to
AAuth's model:

- **Revocation.** The PS MUST provide an authenticated means for the
  Subject, the Approver, or an administrator to revoke a Mission by
  `mission_id`, independent of any token, per the issuance profile.
  AAuth's revocation scenario in which "the PS revokes a mission" is
  this transition to `revoked`. On revocation the PS SHOULD revoke
  outstanding auth tokens issued under the Mission at the resources'
  revocation endpoints, as AAuth provides.
- **Expiry.** `expires_at` is REQUIRED on the record. When it
  passes, the Mission transitions to `expired` without a request.
- **Completion.** AAuth's propose-completion interaction is the
  completion transition: when the user accepts the summary, the PS
  commits the Mission to `completed`, with the semantics of the
  status profile's `complete` operation. The status profile's
  `terminal_when` completion constraint composes unchanged
  ({{I-D.draft-mcguinness-oauth-mission-status}}, Completion
  section).
- **Suspension.** A PS that adopts the status profile's `suspended`
  state MUST NOT report `mission_terminated` for a suspended Mission,
  since termination is permanent to the agent. It defers processing
  instead, using AAuth's 202 deferred mechanism, which AAuth's design
  rationale names as the waiting path for short pauses. For long
  pauses the PS SHOULD terminate and let a new proposal re-scope the
  work, per that rationale.

## Issuance Gating {#gating}

This gate rests on an AAuth structural precondition: no auth token
exists under a Mission without passing the Person Server, in either
mode. On that precondition, under a Mission that is not `active`,
the PS MUST NOT:

- process a token request;
- federate with an Access Server;
- grant a permission; or
- otherwise extend authority.

The `active` check MUST be atomic with issuance.

This gate extends AAuth's rule that any PS endpoint referencing a
non-active mission returns the mission status error, and it is the
issuance profile's derivation gate: in the PS-asserted mode the PS
refuses to issue the auth token, and in the federated mode it
refuses to federate, so no credential is derived under a non-active
Mission in any mode.

Each auth-token issuance and each federation event counts as one
derivation under the Mission. The PS maintains the derivation count
and, where the Intent's `controls.max_derivations` is present, MUST
refuse the issuance or federation that would exceed it, per the
issuance profile's count-and-gate rule.

An auth token issued under a Mission MUST NOT have an `exp` later
than the Mission's `expires_at`, so no credential outlives the
Mission. AAuth
already caps auth-token lifetime at one hour, so every issuance is a
fresh evaluation point and revocation latency is bounded by the
auth-token lifetime; the state surfaces below give a tighter cutoff
where a deployment needs one.

## Mission State Surfaces {#state-surfaces}

The mission log is the native state substrate, and the family
surfaces are views over it: a status read reports the log's latest
lifecycle event, and a signal transmits one.

A Mission-Bound Person Server SHOULD serve the Mission Status
operation of {{I-D.draft-mcguinness-oauth-mission-status}}, with its
signed responses, authentication, anti-oracle property, and caching
rules. It MAY serve the operation at its existing mission endpoint,
keyed by the native reference, rather than at a distinct endpoint.
It MAY serve that profile's Mission Lifecycle endpoint as its
management surface. It MAY emit Mission Lifecycle Signals, with the
PS as the transmitting Mission Issuer
({{I-D.draft-mcguinness-oauth-mission-signals}}).

A PS whose deployment claims runtime enforcement of the
high-consequence classes MUST serve signed Mission Status as an
active freshness source with a published staleness bound: this is
the runtime profile's active-freshness requirement for those classes
({{I-D.draft-mcguinness-mission-runtime}}), and auth-token-lifetime
expiry alone does not meet it.

A PS that serves these surfaces at distinct endpoints publishes the
corresponding members
(`mission_status_endpoint`,
`mission_status_signing_alg_values_supported`,
`mission_lifecycle_endpoint`, `mission_event_stream_endpoint`,
`mission_max_stale_seconds`) in its AAuth PS metadata document, with
the semantics those profiles define. The PS's existing `jwks_uri` is
the published key material for its signed artifacts.

# Mission-Bound Credential {#credential}

The AAuth auth token is this binding's Mission-bound credential.

## The Mission Claim {#mission-claim}

An auth token a Mission-Bound Person Server issues under a Mission
MUST carry, in its `mission` claim, the family members `id`,
`issuer`, and `authority_hash` as the issuance profile defines them,
alongside AAuth's native members `approver` and `s256`. The claim
SHOULD also carry the `expires_at` member as the issuance-grant
profile defines it
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}): a bounding
commitment with no liveness. One object carries all five; `issuer`
equals `approver` in this binding, and both appear because each
specification's consumers read their own members.

AAuth parties ignore members they do not recognize. A family
consumer MUST NOT use any `mission` member to grant or widen
authority, per the issuance profile.

In the federated mode the Access Server mints the auth token and
copies the AAuth-native reference per AAuth. The family members
appear only when the Access Server supports this profile; when it
does not, the credential still names the Mission by (`approver`,
`s256`), the PS's gate still holds ({{gating}}), and a consumer that
needs the family members resolves them through the Mission Status
operation or a Mission Mandate
({{I-D.draft-mcguinness-mission-mandate}}).

## Authority Subset {#subset}

The authority an auth token grants MUST be a subset of the Mission's
Authority Set. The granted `scope` is a coarse projection under the
issuance profile's scope rule: every scope value MUST correspond to
authority present in the Authority Set, and no scope value conveys
authority, or relaxation of a constraint, that the set does not
grant.

In the federated mode this subset, and the Mission's lifetime, are
the PS's federation and delivery checks:

- the PS MUST NOT federate a request whose requested authority
  exceeds this subset;
- the PS MUST NOT deliver to the agent an Access Server-issued token
  whose granted scope exceeds this subset;
- the PS MUST NOT deliver an Access Server-issued token whose `exp`
  is later than the Mission's `expires_at`, so no federated
  credential outlives the Mission ({{gating}}); and
- the PS MUST NOT initiate federation when the Mission's remaining
  lifetime is too short to yield a deliverable token.

An auth token MAY additionally carry Mission-derived authorization
details entries as the issuance profile defines them. Each carried
entry MUST be a subset of a Mission entry under the subset rule, and
a Resource Server that consumes them enforces per the issuance
profile's Resource Server enforcement rules, including failing
closed on constraints it cannot enforce.

The subset rule binds the issuer PS's own derivations to the recorded
Authority Set. It does not impose cross-hop attenuation in AAuth call
chaining, where AAuth deliberately does not require a downstream grant
to be a subset of the upstream scope: a downstream hop is governed at
that hop's own decision point, under its own Mission or per-call
permission, not by algebra over this Mission's set.

This is a boundary on the family's only-narrows invariant, not an
exception to it. The invariant governs derivation: a credential
derived from a Mission only narrows that Mission's authority. A
chained hop derives no credential from this Mission; it is a fresh
decision at a new decision point, evaluated against its own
authority source, so it falls outside the invariant rather than
violating it. Attenuation within any one Mission's own derivations
stays strict ({{gating}}, {{credential}}).

## Subject Directedness {#subject-directedness}

The issuance profile sets a derived token's `sub` to the Mission
Subject's `sub`. AAuth directs `sub` per resource for privacy. This
binding follows AAuth on the wire: the auth token's `sub` MAY be the
directed identifier for its audience. The PS MUST maintain the
mapping from each directed identifier to the Mission's `subject` so
that evidence, audit, and the status surfaces resolve the same
principal.

## Per-Request Mission Binding {#request-binding}

The auth token is proof-of-possession: its `cnf.jwk` is the agent's
signing key, and every request carries an HTTP Message Signature
{{RFC9421}} whose covered components include the `aauth-mission`
component whenever the mission context rides the header. Key
possession and the signature-covered reference together give
per-request, sender-constrained Mission binding: this satisfies the
credential-carried mode of the runtime profile's Mission binding
establishment ({{I-D.draft-mcguinness-mission-runtime}}), so the
runtime profile and its AuthZEN binding
({{I-D.draft-mcguinness-mission-authzen}}) compose credential-carried,
with no join step. A mission-aware Resource copies the reference into
the resource token unchanged, per AAuth, so the PS receives the
mission context on every token request.

The PS's evaluation of each token and permission request against the
mission context and log history is a PDP-shaped decision point. A
runtime-enforced AAuth deployment implements the runtime profile's
decision contract ({{I-D.draft-mcguinness-mission-runtime}}) at these
endpoints with the PS as the PDP, rather than restating that contract
here: the decision inputs, parameter binding, denial reasons, and
freshness rules are the runtime profile's, and the mission log is the
PS's runtime evidence trail ({{security-mission-log}}). This binding
adds only the AAuth-specific mapping: the token or permission request
is the decision request, the `aauth-mission` reference resolves the
established Mission, and each logged decision is a runtime decision
record.

## Worked Example {#credential-example}

An auth token for the Mission of {{record-example}}, issued by the PS
in the PS-asserted mode, narrowed to read-only authority:

~~~ json
{
  "iss": "https://ps.example.com",
  "dwk": "aauth-person.json",
  "aud": "https://erp.example.com",
  "sub": "alice",
  "agent": "aauth:reconciler@agent.example",
  "cnf": { "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." } },
  "scope": "invoices.read",
  "jti": "at_9Kp2vN7sR1tY8mZ3qX5b",
  "iat": 1793606400,
  "exp": 1793610000,
  "mission": {
    "approver": "https://ps.example.com",
    "s256": "w7zuCFWNcWtDb10bawnuQrMcVRGm9B8PKFpJUMoUzbs",
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://ps.example.com",
    "authority_hash":
      "sha-256:mdRUVZfU1BG_Bgla4mrLp6Q9NPVTJ-udnn88F1oXqFc"
  }
}
~~~

The `scope` is a subset projection of the read entry; `sub` is shown
undirected for readability. The AAuth claims (`iss`, `dwk`, `aud`,
`agent`, `cnf`) are unchanged by this binding.

# Mission Substrate {#mission-substrate}

The companion profiles of the Mission suite are defined against the
Mission model's substrate primitives rather than against OAuth
mechanics. In the PS-asserted mode this binding is full provision in
the substrate's terms ({{I-D.draft-mcguinness-mission-substrate}}):
it provides every primitive, including the Mission-bound credential
and issuance gating, the two the standalone binding forgoes. In the
federated mode full provision holds only when the Access Server
carries the family `mission` members ({{mission-claim}}); a federated
deployment whose Access Servers do not is Reference-only
({{verification-modes}}). Against the substrate's requirements:

1. **Identifier and issuer**: `mission_id`, a flat blob member;
   `issuer` the `approver` URL; the (`approver`, `s256`) pair is the
   wire-native reference to the same Mission ({{reference}}).
2. **Lifecycle state space**: the issuance profile's states with the
   only-`active` rule and fail-safe unrecognized states, extended by
   the status profile where adopted; freshness through the status
   operation, signals, and the one-hour auth-token lifetime, with a
   PS-declared staleness bound ({{lifecycle}}).
3. **Authority Set representation**: the issuance profile's, with its
   subset rule and Common Constraints, carried as the profiled
   `approved_tools`, which are the Authority Set by definition under
   the projection ({{mission-record}}, {{two-commitments}}).
4. **Integrity anchors**: the family envelope and canonicalization,
   `iss` the PS's issuer URL, computed as a deterministic projection
   of the s256-committed blob rather than stored
   ({{two-commitments}}).
5. **Mission-bound credential**: the auth token with the `mission`
   claim and signature-covered reference, issued only while the
   Mission is `active` ({{credential}}, {{gating}}).
6. **Published key material**: the PS's keys, resolvable through
   AAuth's discovery ({{state-surfaces}}).
7. **Audit horizon**: PS-declared; the record and the mission log are
   retained for it.
8. **Approval fidelity**: the propose, clarify, approve interaction
   produces the record, the anchors, and the consent disclosure with
   the required fidelity ({{approval}}).

The composition consequences:

- The runtime profile and its AuthZEN binding compose
  credential-carried ({{request-binding}}); no join is needed.
- Status and signals are PS-served; the PS is the transmitting
  Mission Issuer ({{state-surfaces}}).
- Shaping, consent evidence, the status profile's completion
  machinery, the Mandate, and audit transparency compose unchanged: the PS is the Mission Issuer those
  profiles name, the committing issuer for consent evidence, the
  minter of Mandates, and the producer of audit statements.
- Child delegation maps naturally to AAuth's `parent_agent` sub-agent
  model: sub-agents are individually identified, authorization is
  parent-mediated, and the PS is the control point. The family
  profile's request wire is OAuth-bound
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), so
  AAuth-native Child Mission creation is deferred work; today a
  sub-agent operates under its parent's Mission per AAuth.
- Offline attenuation does not apply: AAuth has no offline-mint
  substrate; every credential is issuer-minted and
  proof-of-possession bound
  ({{I-D.draft-mcguinness-oauth-mission-attenuation}}).
- Cross-domain projection does not apply: AAuth's federated mode is
  its own cross-party mechanism, federating per request at the trust
  layer between the PS and the Access Server rather than projecting a
  Mission into a foreign issuer
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

# Limitations {#limitations}

**Substrate maturity.** AAuth is an individual Internet-Draft, and
this binding pins its wire behavior to
draft-hardt-oauth-aauth-protocol-08. A change to AAuth's mission
surfaces revises this document; a deployment tracks both.

**Blob visibility.** Only the agent and the PS hold the mission blob,
and AAuth forbids a Resource or Access Server to dereference the
reference. A Resource therefore verifies from token claims and the
signature-covered reference, not by recomputing the anchors: it holds
no Authority Set unless a token carries authorization details. A
deployment that needs Resource-side `authority_hash` verification
uses a Mission Mandate, minted by the PS as the Mission `issuer`,
carrying the committed facts under the PS's signature
({{I-D.draft-mcguinness-mission-mandate}}).

**The PS as trusted component.** The PS concentrates approval,
issuance, and state in one service, so its compromise is Mission
Issuer compromise in the security model's terms: forged approvals,
arbitrary minting, and false state
({{I-D.draft-mcguinness-mission-security-model}}). Consent evidence
and audit transparency make forgery detectable after the fact; they do
not prevent it ({{security-ps-compromise}}).

# Mission Verification Modes {#verification-modes}

AAuth's default keeps the mission blob with the agent and the PS, so
a Resource verifies from the reference and token claims, not by
recomputing the anchors ({{limitations}}). That makes resource-side
verifiability an explicit axis this binding must name, one the OAuth
binding does not have because its tokens always carry the authority
payload. A deployment declares which of three modes it serves; the
modes are cumulative in what a Resource or auditor can check without
trusting PS-private state.

**Reference-only** (the default):
: the credential names the Mission by (`approver`, `s256`) and carries
  the granted scope. The PS gate holds ({{gating}}), but a Resource
  cannot independently verify the Mission's authority; it trusts the
  PS's evaluation. Federated mode ({{mission-claim}}) is at most this
  when the Access Server does not carry the family members.

**Credential-carried**:
: the auth token additionally carries the `mission` claim family
  members (`id`, `issuer`, `authority_hash`), so a Resource can bind
  the token to a named Mission and its consent anchor, though it still
  holds no Authority Set to check a specific action against.

**Resource-verifiable**:
: the PS additionally provides either token-carried
  `authorization_details` or a signed Mission Mandate
  ({{I-D.draft-mcguinness-mission-mandate}}) carrying the committed
  facts, so a Resource or an auditor can verify that a given
  token or request is within the approved Mission's authority without
  trusting opaque PS policy or private blob state. A deployment that
  needs independent resource-side or third-party authority
  verification MUST serve this mode.

These modes are the AAuth-specific verification axis; the family's
Mission Assurance Levels ({{I-D.draft-mcguinness-mission-architecture}})
layer on top, and a runtime-enforced or agent-compromise-resistant AAuth
deployment claims the corresponding level there rather than a
binding-specific name. Full-provision Mission governance, which the
PS gate already provides ({{gating}}), reaches the Runtime-Enforced
level only in the Resource-verifiable mode with the runtime decision
contract in force ({{request-binding}}).

# Resource-Declared Semantics {#resource-declared}

This section is informative. AAuth's exploratory Rich Resource
Requests companion ({{I-D.draft-hardt-aauth-r3}}) inverts the
authority ontology this family inherits from OAuth: instead of the
client proposing authority, the resource publishes an R3 document
declaring its operations, their human meaning, and their
consequences, content-addressed by `r3_s256`, and the agent carries
the hash of a declaration it cannot read. That is the descriptive
half of open-world discovery, and it composes with this binding's
governance half without new mechanism:

- **Encounter-time adjudication at the gate that already exists.**
  The Person Server issues or gates every auth token ({{gating}}),
  so the moment an agent requests a token for a newly encountered
  resource is the adjudication point: the PS evaluates the
  resource's declared operations against the Mission's Authority
  Set, or against a pre-consented ceiling where the progressive
  companion is deployed
  ({{I-D.draft-mcguinness-oauth-mission-progressive}}), binding
  in-envelope encounters by policy and routing everything else to
  the Approver.
- **Consent composes the resource's own words.** The R3 `display`
  section is resource-authored consent material; a PS that renders
  it into a Mission's approval or expansion disclosure gives the
  Approver the resource's stated meaning and consequences, and
  Consent Evidence then commits what was shown
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).
- **A third commitment.** `r3_s256` commits what the resource
  declared, beside `intent_hash` (what the client asked) and
  `authority_hash` (what was consented). Recorded with binding and
  decision evidence (the progressive companion's
  `resource_declaration_digest` carries it), it makes the encounter
  reproducible in audit: what the resource claimed to be at the
  moment authority bound to it.

R3 is an exploratory draft; this section describes composition, not
a normative dependency, and nothing in this binding's conformance
requires it. The discovery companion
({{I-D.draft-mcguinness-mission-discovery}}) defines the encounter
contract, the identity pinning, and the floors the Person Server
applies at that gate.

# Conformance {#conformance}

An implementation conforms in one of two roles.

A **Mission-Bound Person Server**:

- maintains a Mission record for every approved mission, carried by
  the blob's native and flat members under the fixed equivalence of
  {{mission-record}}, and computes the integrity anchors as the
  projection of {{two-commitments}} with its issuer URL;
- resolves the (`approver`, `s256`) reference to the record at every
  PS endpoint that takes one ({{reference}});
- executes the approval event of {{approval}}, creating the record
  `active` atomically with the approval decision;
- operates the lifecycle of {{lifecycle}}: authenticated revocation,
  `expires_at` enforcement, completion, and the only-`active`
  gate at every PS surface, atomic with issuance ({{gating}});
- issues auth tokens as Mission-bound credentials ({{mission-claim}},
  {{subset}}), with `exp` bounded by the Mission's `expires_at`;
- serves Mission state per {{state-surfaces}} and retains the record
  and mission log for the audit horizon; and
- declares which verification mode of {{verification-modes}} the
  deployment serves.

A **Mission-Bound Agent**:

- SHOULD propose a structured Mission Intent ({{mission-intent}});
- treats every proposal as a proposal, never as authority;
- stores the blob bytes exactly as received, carries the Mission
  reference on resource requests, and covers `aauth-mission` in its
  request signatures, per AAuth;
- respects the only-`active` rule: it stops on `mission_terminated`,
  treats an unrecognized `mission_status` as non-active, and proposes
  completion when the task is done; and
- treats `mission_id` and the Mission reference as references, never
  as credentials.

# Security Considerations

## Rendering the Mission Description {#security-rendering}

The Markdown `description`, the proposal, and every `justification`
are attacker-influenceable text that the PS renders to the person at
the consent surface. The issuance profile's rendering rules apply
unchanged, as the approval event applies them ({{approval}}); their
point is that crafted text cannot pass as derived authority. AAuth's
own Markdown-sanitization requirement is necessary but not
sufficient. The consent surface MUST also make clear which rendered
content is authority and which is the agent's narrative.

## Two Commitments, Neither Substitutes {#security-two-commitments}

`s256` commits the session-specific blob bytes, including members the
anchors do not cover, but it has no domain separation and no issuer
binding: it is a content hash, and a party holding only `s256` learns
nothing about what was approved. The anchors commit the approved
Intent and Authority Set under the issuance profile's
domain-separated, issuer-bound envelope, reproducible from the blob
alone through the projection of {{two-commitments}}, but they do not
commit `approved_at`, `capabilities`, or any
other session member. A verifier holding the blob MUST check the
commitment relevant to its question: `s256` for "is this the blob the
reference names", the anchors for "is this the authority and task
that were approved". A party without the blob relies on the signed
status surfaces or a Mandate.

Because the anchors are computed rather than stored, the projection
is in the trust path: an implementation error in the projection is
an anchor error. The core's test vectors verify the envelope and
canonicalization pipeline, and the computed pair of
{{record-example}} verifies the projection itself; an implementation
MUST reproduce both before interoperating.

## Person Server Compromise {#security-ps-compromise}

A compromised PS is a compromised Mission Issuer: it can forge
approvals, alter records before activation, issue credentials against
missions no one approved, and report false state
({{I-D.draft-mcguinness-mission-security-model}}). Because the blob is
held by the agent as exact bytes under `s256`, after-the-fact
alteration of an approved mission is detectable by any holder of the
original bytes; consent evidence commitments and audit transparency
extend that detectability to the approval itself. Signing-key custody
and the status profile's key-retention rules keep archived state
evidence verifiable.

## The Mission Log as Evidence {#security-mission-log}

The mission log is the PS's evidence trail: token requests with their
justifications, permission requests and outcomes, audit records, and
clarification chats, in order. Where the PS implements the runtime
decision contract ({{request-binding}}), the log is its decision
evidence, and the runtime profile's record-integrity expectations
apply: tamper-evident storage, retention for the audit horizon, and a
grant recorded before the authority it grants is used
({{I-D.draft-mcguinness-mission-runtime}}).

For a runtime-enforced deployment the log MUST record, in commit
order, at least:

- the Mission Intent proposal;
- any clarification exchange;
- the approval rendering and the approval decision with the
  committed `authority_hash`;
- each auth-token request and the token issued;
- each permission request and its decision (permit or the denial
  reason); and
- each lifecycle transition (revocation, completion, or expiry).

Ordering MUST place a grant before any use of the authority it
grants, so the log reconstructs what was authorized, by what
decision, under what Mission state, and to what outcome. A
deployment MAY map these to the runtime profile's decision and
execution evidence records, which is the interoperable form.

# Privacy Considerations

**The blob stays with the agent and the PS.** Task text, constraints,
and the full Authority Set do not travel in credentials unless a
deployment opts to carry authorization details; by default a Resource
sees only the reference and the granted scope. The Subject's
identity does not appear in the blob at all ({{mission-record}}),
extending AAuth's directed-identity posture to the Mission artifact
itself. This is a minimization
property the OAuth binding does not have, where the token carries the
authority payload; the trade is Resource-side enforcement, which here
requires opting into token-carried authority or a Mandate
({{limitations}}).

**Reference correlation.** The (`approver`, `s256`) pair rides every
mission-context request and token, so Resources observing it can
correlate the Mission's activity within and across services, and
`approver` identifies the person's PS. This is the deliberate
property of the issuance profile's Mission Identifier correlation,
and that profile's guidance applies: the stable anchor is what audit
and governance key on. A deployment SHOULD document the correlation
it implies. AAuth's directed `sub` limits subject correlation; the
Mission reference is not directed, because it is the anchor.

Directed Mission references, in which the PS presents a distinct
per-audience reference that still verifies back to the same Mission
through PS-signed evidence, would limit this cross-resource
correlation in the same way. They are future work here, parallel to
the audience-pairwise references the issuance profile defers
({{I-D.draft-mcguinness-oauth-mission}}): both trade the stable audit
anchor for unlinkability, and neither is a v1 property.

# IANA Considerations {#iana}

This document has no IANA actions. The registries AAuth establishes
belong to that specification, and this binding defines no new AAuth
requirement, capability, or platform values. The members this
document adds ride inside structures whose extensibility their
defining specifications state: the flat `mission_id`, `expires_at`,
and `policy_version` members (and the conditional `mission_intent`)
in the PS-produced blob, and `id`, `issuer`, and `authority_hash`
inside the `mission`
claim AAuth registers, whose unrecognized members AAuth consumers
ignore. Should AAuth establish registries for those members, the
members this document defines would be registered there.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization work. It
binds the Mission model to the AAuth protocol's Person Server and
native mission concept, and builds on the Mission Status and
Lifecycle, Mission-Bound Runtime Enforcement, and Mission Authority
Server companions.
