---
title: "Mission Intent Shaping for OAuth 2.0"
abbrev: "OAuth Mission Shaping"
category: info

docname: draft-mcguinness-oauth-mission-shaping-latest
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
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-shaping.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC8259:
  RFC8785:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest

informative:
  RFC6749:
  RFC7515:
  RFC9126:
  I-D.draft-mcguinness-oauth-mission-runtime:
    title: "Mission-Bound Runtime Enforcement for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-runtime-latest

--- abstract

Mission-Bound Authorization for OAuth 2.0 defines a Mission Intent and
the Authority Set an Authorization Server derives from it, but leaves
the step that turns an open-ended task request into a candidate Mission
Intent to deployment policy. This document is an OPTIONAL, Informational
profile describing the Mission Shaper: a client-side component that
turns a user prompt or upstream trigger into a candidate Mission Intent
for submission to the issuance profile. It defines the shaper's role and
trust boundary, recommended behavior for ambiguity, capability
resolution, and refusal, and an audit artifact (Shaping Evidence). It
deliberately defines no portable shaping wire protocol and claims no
cross-vendor conformance: the shaper proposes only. It never grants
authority, never widens authority, and never activates a Mission. A
model-based shaper is no exception. Authority is created only by the
issuance profile's validation and approval, never by the shaper.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") makes a
Mission a first-class authorization artifact. It defines how a Mission
Intent is submitted, how an Authorization Server derives an Authority
Set, how an Approver consents, and how issued tokens are bound to the
approved Mission. It does not standardize how a deployment turns an
open-ended task request, such as "resolve this billing dispute," into a
Mission Intent with a goal, resources, free-text constraints, success
criteria, purpose, context, and expiry.

This document describes that missing shaping step. A **Mission Shaper**
is a client-side component that produces a candidate Mission Intent
before the issuance profile's approval flow begins. The shaper can be a
deterministic rules engine, a form, an LLM-assisted function, or a
workflow. Whatever its implementation, its output is only a proposal:
the Authorization Server validates and narrows it, the Approver or
governing policy approves it, and only the resulting approved Mission
carries authority.

The purpose of this profile is to make shaping auditable and fail
closed. When a task request is ambiguous, the shaper does not silently
invent authority: it narrows to a defensible candidate, asks for
clarification, or refuses to shape. When a capability or resource is
unknown, the shaper records that fact rather than treating natural
language as authority to create it. When the shaper uses model output,
that output is evidence for review, not an entitlement decision.

## Why This Profile Is Informational {#why-informational}

This document is Informational by deliberate choice, not by omission.
Client-side prompt processing is loosely shaped by deployment policy,
language-model choice, and product ergonomics; no two deployments will
agree on the transformation from a request to a Mission Intent. A
Standards Track wire protocol for that transformation would overclaim,
because the interoperable surface is not the transformation but its
result: the Mission Intent, which the issuance profile already defines
and validates on the wire.

What is stable, and what this profile records, is the shaper's role
inside the trust model and the behaviors a sound implementation follows.
This profile therefore defines role boundaries, trust posture, and
recommended behavior; it does not define a portable shaping protocol,
register a media type or claim name, or define a conformance test suite.
A deployment that exposes shaping as a network service MAY do so
({{exposing-shaping-as-a-service}}), but that surface is a local
implementation detail, not an interoperability contract.

# Relationship to the Issuance Profile {#relationship}

This document is OPTIONAL and layered on
{{I-D.draft-mcguinness-oauth-mission}}. A deployment that accepts only
hand-authored Mission Intent values is fully conformant to the issuance
profile and is unaffected by this document.

This document describes:

- the shaper's role and trust boundary ({{role-and-trust-boundary}});
- a processing model and recommended Mission Intent construction
  ({{processing-model}}, {{mission-intent-proposal}});
- recommended ambiguity, refusal, and capability-resolution behavior
  ({{ambiguity}}, {{capability-resolution}});
- Shaping Evidence, an audit artifact ({{shaping-evidence}}); and
- how a shaped proposal enters the issuance flow
  ({{composition}}).

This document does not define a new OAuth grant type, a new access token
format, a policy language, a runtime authorization decision API, or a
required shaping endpoint. The approved Mission and its tokens remain
those of the issuance profile.

It uses the terms Mission, Mission Intent, Authority Set, Mission
Issuer, Approver, and Authorization Server as defined by
{{I-D.draft-mcguinness-oauth-mission}}. Where this document refers to
"the issuance profile" without a section, it means that document as a
whole.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

The normative keywords in this document describe recommended shaper and
Mission Issuer behavior. They do not establish a conformance class:
this profile is Informational ({{why-informational}}).

All JSON shown in this document is non-normative and illustrative; the
member descriptions in the surrounding text are authoritative. This
document uses JSON {{RFC8259}} as the data model for the illustrative
objects, and JCS {{RFC8785}} where a hash is computed over Shaping
Evidence ({{shaping-evidence}}).

This document additionally uses:

Mission Shaper (or "shaper"):
: A client-side component that produces a candidate Mission Intent from
  a task request and supporting context. A Mission Shaper does not grant
  authority.

Mission requester:
: The component or user that supplies the task request to be shaped.

Mission Intent proposal:
: The candidate `mission_intent` object the shaper emits for validation
  and approval under the issuance profile.

Capability source:
: A resource-owning catalog, metadata endpoint, policy service, or other
  source the shaper consults to resolve candidate resources and actions.

Shaping Evidence:
: The record of inputs, inferences, policy decisions, unresolved
  ambiguities, and capability-resolution facts that produced the Mission
  Intent proposal. Audit material, not authority.

# Shaper Role and Trust Boundary {#role-and-trust-boundary}

The Mission Shaper occupies a single, narrow role. This section defines
that role and the trust boundary the shaper does not cross. It is the
stable core of this profile.

## Client-Side Placement {#client-side}

The shaper executes on the client side of the Mission-Bound
Authorization trust boundary: in the same trust domain as the requesting
client that will submit the Mission Intent. Its output is consumed by
that client and submitted to the Mission Issuer through the issuance
profile's `mission_intent` submission ({{composition}}).

The shaper is not a separate principal. It has no identity of its own to
the Mission Issuer; the Mission Issuer sees the requesting client. A
deployment MAY factor the shaper into its own process or network service
for engineering reasons ({{exposing-shaping-as-a-service}}), but doing
so does not make the shaper a principal to the Authorization Server and
does not move it across the trust boundary: it remains client-side
machinery that produces an untrusted proposal.

## The Shaper Does Not Issue Authority {#proposes-only}

The Mission Shaper MUST NOT issue, derive, or certify authority of any
kind. It produces a Mission Intent proposal. That proposal is, by the
issuance profile's definition, untrusted client input until the Mission
Issuer validates and narrows it and binds authority at the approval
event. The shaper's output therefore has no authority implications until
the Mission Issuer approves a Mission from it and derives an Authority
Set.

A shaper that signs its output, attaches an authority assertion, emits a
credential, or otherwise behaves as a credential issuer is acting
outside the role this profile describes and is NOT RECOMMENDED. A
deployment MAY integrity-protect shaper output for client-internal
reasons (for example, to detect tampering between the shaper and the
submission step in a multi-process client, {{multi-process}}), but that
protection has no authority semantics at the Mission Issuer and MUST NOT
be relied upon by anything beyond the client.

## Untrusted Output Principle {#untrusted-output}

A Mission Issuer that receives a Mission Intent MUST treat it as
untrusted input under the issuance profile's validation rules. Nothing
in this profile changes that, and a shaper SHOULD NOT structure its
output to imply otherwise.

In particular, a shaper MUST NOT emit, in the Mission Intent proposal,
members that mimic Mission Issuer outputs. The proposal MUST NOT carry
`mission.id`, `intent_hash`, `authority_hash`, an Authority Set, a
lifecycle state, or approving-principal evidence. Those values are
produced by the Mission Issuer on the Mission record at and after the
approval event, never by the client ({{I-D.draft-mcguinness-oauth-mission}}).
A shaper that emits them is either confused about its role or attempting
to mislead an auditor, and a Mission Issuer MUST ignore any such member
presented in a Mission Intent.

## The Shaper Never Crosses the Trust Boundary {#never-crosses}

The trust boundary separates the client, where the shaper lives, from
the Mission Issuer, where the Mission Intent is validated and the
Authority Set is created. Crossing that boundary is a Mission Issuer
action. The shaper produces an input; the client transmits the input;
the Mission Issuer decides what to do with it. The shaper does not
initiate the submission, does not invoke the OAuth Pushed Authorization
Request or Authorization Endpoint, does not select the recipient Mission
Issuer on its own authority, and does not attest to the submission's
correctness on the Mission Issuer's behalf.

## Deployment Roles {#roles}

This profile separates four roles that implementations often collapse:

Mission requester:
: Supplies the task request to be shaped.

Mission Shaper:
: Produces a Mission Intent proposal and Shaping Evidence. Not
  authoritative for policy or consent.

Mission Issuer:
: The Authorization Server that validates the proposal, derives the
  Authority Set, records the approval event, and issues Mission-bound
  credentials under {{I-D.draft-mcguinness-oauth-mission}}.

Capability source:
: A catalog, metadata endpoint, or policy service the shaper consults to
  resolve candidate resources and actions.

A deployment MAY co-locate these roles, but it SHOULD preserve the
authority boundary: shaping produces a proposal, issuance creates an
approved Mission, and runtime enforcement permits or denies actions.

# Processing Model {#processing-model}

A sound shaper processes a request in this order:

1. Normalize and classify the caller-supplied task input.
2. Distinguish facts supplied by the requester, facts supplied by
   trusted context, and facts inferred by the shaper.
3. Resolve candidate resources and actions against capability sources
   ({{capability-resolution}}).
4. Apply deployment shaping policy, including authority ceilings and
   risk classification.
5. Detect material ambiguity ({{ambiguity}}).
6. Produce an outcome: a proposal, a request for clarification, or a
   refusal.
7. Record Shaping Evidence and, for a proposal, optionally a
   `shaping_evidence_hash` ({{shaping-evidence}}).

The shaper SHOULD NOT skip capability resolution merely because a task
is natural-language plausible. A request such as "email the customer"
does not identify which mailbox, sender, recipient, template, or data
source is allowed unless the deployment's capability sources or policy
resolve those details.

# Mission Intent Construction {#mission-intent-proposal}

A Mission Intent proposal MUST satisfy the syntactic requirements of the
issuance profile's `mission_intent` object
({{I-D.draft-mcguinness-oauth-mission}}): a `goal`, `resources` (each an
absolute URI), optional free-text `constraints`, optional
`success_criteria`, an optional `purpose`, a `mission_expiry`, and an
optional `context` object. The shaper proposes the resources and
describes the desired bounds in free-text `constraints` and
`success_criteria`; it does not author actions, structured constraints,
or delegation. The Mission Issuer derives the actions, structured
(object) constraints, and delegation as members of the Authority Set it
computes ({{I-D.draft-mcguinness-oauth-mission}}). The proposal MUST be
bounded enough for the Mission Issuer to derive an Authority Set without
interpreting natural language as authority.

The proposal MUST NOT carry an Authority Set or its derived members:
`actions`, structured (object) constraints such as `max_amount_usd`, or
`delegation`. Those are products of the Mission Issuer's derivation, not
inputs from the shaper. A shaper that has resolved such facts (for
example, the actions a resource supports, or that the task implies
delegated execution) records them in Shaping Evidence
({{shaping-evidence}}), where the Mission Issuer MAY consult them, rather
than placing them in the proposal.

A sound shaper does not include a resource in the proposal merely because
the task text implies it might be useful. The shaper should have a
resolution basis under {{capability-resolution}}, or it should produce a
clarification request or a refusal.

## Authority Ceiling and Default Deny {#authority-ceiling}

A sound shaper applies a default-deny posture. The Mission Intent
proposal should contain only resources that have a positive basis in the
request, context, capability source, and shaping policy, and free-text
`constraints` and `success_criteria` that describe the bounds the shaper
can defend. The shaper should not include a broad resource class as a
convenience fallback for unresolved detail.

When a deployment or caller supplies an authority ceiling, the proposal
MUST be a subset of it. If the task cannot be completed within that
ceiling, the shaper MUST request clarification or refuse; it MUST NOT
silently drop necessary authority while emitting a proposal that appears
complete, unless Shaping Evidence records the excluded authority and the
outcome clearly indicates the proposal may not satisfy the task. The
Mission Issuer remains responsible for enforcing its own ceiling even
when no caller ceiling is present.

## Delegation and Child Work {#delegation}

The shaper does not author a delegation entry: `delegation` is a member
of the Authority Set the Mission Issuer derives
({{I-D.draft-mcguinness-oauth-mission}}), not of the Mission Intent
proposal. If the task implies use of sub-agents, background workers, or
delegated execution, the shaper SHOULD record that fact in Shaping
Evidence ({{shaping-evidence}}) so the Mission Issuer can derive
`delegation` on the relevant Authority Set entry or refuse. The shaper
MAY also describe the desired delegation bound in free-text
`constraints` or `success_criteria`. A sound shaper does not infer
delegated execution from the mere existence of a task graph or an agent
harness: a child actor needs explicit authority derived by the Mission
Issuer, not session ancestry.

## Construction Guidance {#construction-guidance}

The following maps a prompt or trigger onto the Mission Intent fields.
It is guidance, not a normative algorithm; the SHOULD/MUST points are
called out. Resolved actions, structured constraints, and delegation
facts do not appear here: they belong in Shaping Evidence, where the
Mission Issuer derives the Authority Set from them.

| Field | Guidance | Avoid |
|---|---|---|
| `goal` | Concise user-readable summary in the form the Approver sees at consent; preserve the user's framing so the disclosure matches their understanding. | SHOULD NOT quote verbatim prompt text that contains instructions or commands ({{prompt-injection}}). |
| `resources` | Enumerate, as absolute URIs, the resources, datasets, tools, or domains the prompt referenced; record any human-readable label as an audit annotation in Shaping Evidence, not as the `resources` value. | SHOULD NOT widen beyond what the prompt referenced; "for convenience" enlarges approved authority. |
| `constraints` | Free-text bounds the user expressed plus deployment-policy bounds always applied, so the Approver sees the full bound set. The Mission Issuer derives any structured constraint from these. | SHOULD NOT silently drop a user-expressed bound; record it in `constraints` or in Shaping Evidence, or clarify or refuse instead. |
| `success_criteria` | Free-text observable outcomes that indicate the task is complete, phrased for the Approver. Disclosure and audit material only. | SHOULD NOT encode authority here; `success_criteria` carries no machine semantics in the issuance profile. |
| `mission_expiry` | The smallest ceiling that lets the task complete; if the prompt names no bound, apply a conservative deployment default. | Don't request the maximum the Mission Issuer allows; the Issuer MAY narrow further. |
| `purpose` | If the client has registered purposes, select the closest registered URI. | SHOULD NOT invent a new `purpose` URI. |
| `context` | Emit `context` keys the deployment recognizes; a deployment MAY add further keys it defines. | SHOULD NOT emit a key the specific deployment does not recognize; an unrecognized key risks rejection of the Intent. |

# Ambiguity Handling {#ambiguity}

A sound shaper classifies material ambiguity. Ambiguity is material when
choosing one interpretation over another would change the Authority Set,
the action class, the actor allowed to exercise it, the expiry, or the
risk posture.

For material ambiguity, a sound shaper does one of:

1. request clarification;
2. emit a narrower proposal that excludes the ambiguous authority and
   records the exclusion in Shaping Evidence; or
3. refuse with a reason.

Because a shaper is a client-side component whose internal reasoning the
Mission Issuer cannot observe, this profile expresses the requirement
through the observable artifact rather than the internal choice: when a
shaper resolves an ambiguity in the broadening direction, Shaping
Evidence MUST record the resolution and, where a deployment permits
policy-based default narrowing, the policy rule that authorized it. A
proposal that broadens authority on an ambiguity without a corresponding
Shaping Evidence record is non-conforming. The Mission Issuer enforces
its own ceiling and consent regardless of what the shaper recorded.

Requesting clarification is not approval. The user's response is
incorporated into the Mission Intent; the Mission Issuer still
validates, narrows, and renders the consent disclosure for binding
approval. A shaper MUST NOT treat answered clarifications as a reason to
skip the Mission Issuer consent step: the shaper is not the Approver's
agent for consent.

## Clarifications {#clarifications}

A clarification SHOULD be phrased so the requester can understand the
authority consequence of each answer. "Need more scope?" is not
sufficient; "May this Mission read invoices for customer 5678 in
addition to customer 1234?" is. A clarification SHOULD identify the
authority consequence of each offered choice and SHOULD state what the
shaper will do if it is left unanswered (refuse, narrow, or wait).

## Refusal {#refusal}

There are inputs a shaper SHOULD refuse to shape. Refusal is a
shaper-internal decision; it requires no Mission Issuer involvement, and
this profile defines no wire-level refusal error. A shaper SHOULD refuse
when:

- it cannot produce a Mission Intent for the task class
  (`unsupported_task`);
- a requested resource or action cannot be resolved to a capability
  source (`unresolved_resource`, `unresolved_action`);
- the task requires authority outside the deployment or caller authority
  ceiling (`outside_authority_ceiling`);
- deployment policy prohibits shaping the task (`policy_prohibited`);
- material ambiguity remains and policy requires refusal rather than
  clarification (`material_ambiguity`); or
- the request includes adversarial, conflicting, or untrusted content
  that prevents a defensible proposal (`unsafe_to_shape`).

The reason strings above are recommended labels for Shaping Evidence and
for surfacing a refusal to the requesting client; a deployment MAY
define additional labels but SHOULD NOT reuse these with different
meaning.

A shaper SHOULD NOT refuse merely because the requested authority is
broad, or because the Authority Set the Mission Issuer would derive
looks expensive. Breadth is the Mission Issuer's decision and the
Approver's; cost is a runtime concern. Refusing on those grounds
substitutes the shaper's judgment for the Approver's.

# Capability and Resource Resolution {#capability-resolution}

Before proposing a resource, a sound shaper establishes a resolution
basis. The basis is one of:

`catalog`:
: Resolved from a catalog, metadata endpoint, OpenAPI description, MCP
  tool catalog, or equivalent source.

`policy`:
: Selected by a deployment policy rule.

`user_supplied_exact`:
: The requester supplied a concrete resource identifier and the shaper
  verified it is admissible for shaping.

`authority_source`:
: A resource-owning system or Authorization Server supplied an allowed
  resource/action projection for this task.

A sound shaper records the resolution basis in Shaping Evidence. A
model-generated capability name with none of these bases is not
resolved, and a sound shaper treats it as unresolved ({{refusal}}).

For each resolved capability, Shaping Evidence SHOULD record what was
requested, what it resolved to, the basis, the source consulted (for
`catalog` and `authority_source`), and, where available, a digest over
the source representation so later approval and runtime enforcement can
detect drift. A confidence value, if recorded, is audit evidence only
and MUST NOT be treated as authority.

# Shaping Evidence {#shaping-evidence}

Shaping Evidence records how a proposal was produced. It is audit
material: it does not grant authority and MUST NOT be used by a Resource
Server or Policy Decision Point to permit an action. This profile
defines no required schema, media type, or transport for it; the
following members are RECOMMENDED content.

`shaper_id`:
: A string identifying the shaper.

`shaper_version`:
: A string identifying the shaper implementation, model, policy bundle,
  or workflow version.

`input_digest`:
: A digest over the shaping request, in the integrity-anchor encoded
  form of {{I-D.draft-mcguinness-oauth-mission}}, computed over the JCS
  {{RFC8785}} canonical bytes of the request after removing the fields
  the named exclusion ruleset marks as non-retained. To make the digest
  recomputable by a later auditor, the evidence MUST also record
  `input_exclusion_ruleset`, an identifier (and version) of the
  exclusion ruleset applied, and the auditor recomputes the digest over
  the retained canonical input under that ruleset. A digest whose
  exclusion set is not recorded cannot be reproduced and so is not a
  conforming `input_digest`.

`user_supplied_facts`:
: Facts copied from the request.

`inferred_facts`:
: Facts the shaper inferred, each with its supporting evidence and
  whether human confirmation is required.

`policy_decisions`:
: Policy rules applied during shaping.

`capability_resolutions`:
: Each resource or action and its resolution basis
  ({{capability-resolution}}).

`ambiguities`:
: Material ambiguities and how each was handled.

`excluded_authority`:
: Plausible authority the shaper deliberately excluded.

`model_trace`:
: Model prompts, outputs, or tool calls used during shaping. When
  retained it MUST be treated as sensitive audit data
  ({{privacy-considerations}}) and MUST NOT be rendered as authority.

## Integrity and the Evidence Hash {#evidence-hash}

A deployment MAY bind a proposal to its evidence so the Mission record
can cite how the proposal was produced. When it does:

- `shaping_evidence_hash` is a string in the integrity-anchor form of
  {{I-D.draft-mcguinness-oauth-mission}}. Like every other committed
  object in this suite, the Shaping Evidence object is committed inside
  that profile's domain-separated `{typ, iss, value}` envelope, with
  `typ` of `mission-shaping-evidence`, `iss` the Mission Issuer
  `origin`, and `value` the Shaping Evidence object; the anchor is the
  prefixed digest of the JCS {{RFC8785}} canonical bytes of that
  envelope. Hashing the bare object would omit the `typ` domain
  separation and `iss` binding the integrity-anchor construction exists
  to provide. It is an audit commitment only.
- A deployment MAY instead, or in addition, carry an integrity envelope
  over the Shaping Evidence, for example a JWS {{RFC7515}} Compact
  Serialization over the JCS canonical bytes of the evidence with the
  envelope member removed.

Neither the hash nor the envelope confers authority. A Resource Server
or PDP MUST NOT treat a shaping evidence hash as proof of authority.

## Illustrative Evidence (Non-Normative)

~~~ json
{
  "shaper_id": "mission-shaper.example.com",
  "shaper_version": "policy-bundle-2026-06-30",
  "input_digest":
    "sha-256:InP9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4aB7cDe",
  "user_supplied_facts": [
    "support ticket 456",
    "customer 1234"
  ],
  "capability_resolutions": [
    {
      "requested": "invoice.read",
      "resolved": "invoice.read",
      "basis": "catalog",
      "source_uri":
        "https://billing.example.com/.well-known/tools"
    }
  ]
}
~~~

# Mission Issuer Handling {#issuer-handling}

A Mission Issuer that receives a shaped Mission Intent MAY use a
`shaping_evidence_hash` and Shaping Evidence as input to approval and
audit, but MUST independently validate the Mission Intent under
{{I-D.draft-mcguinness-oauth-mission}}.

The Mission Issuer MUST NOT approve a Mission solely because a shaper
produced it. It MUST derive an Authority Set under issuer policy and
MUST refuse, narrow, or require approval as the issuance profile
requires. If the Mission Issuer records a `shaping_evidence_hash` on the
Mission record, it MUST treat that value as an audit commitment only.

A Mission Issuer SHOULD refuse a stale shaped proposal: a deployment
that conveys a freshness bound with the proposal (for example, an
expiry, or an evidence source digest that no longer matches) SHOULD
re-shape rather than submit a proposal built against a capability
catalog or policy version that has since changed.

# Composition {#composition}

## Entering the Issuance Flow {#oauth-composition}

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} defines a `mission_intent`
parameter carried inside a Pushed Authorization Request (PAR)
{{RFC9126}}. The Mission Intent the shaper produced is the value of that
parameter. The Authorization Server {{RFC6749}} acts as the Mission
Issuer: it validates, narrows, renders the consent disclosure, records
the approval event, and derives an Authority Set
({{I-D.draft-mcguinness-oauth-mission}}).

The shaper does not invoke the PAR endpoint or the Authorization
Endpoint and does not handle the authorization response. Those are
requesting-client responsibilities ({{never-crosses}}). The shaper hands
its output to the requesting client, which performs the OAuth flow and
MAY also convey a `shaping_evidence_hash` as deployment extension data
so the Mission record can cite the evidence. Conveying it does not
require the Mission Issuer to trust the shaper.

## Runtime Enforcement {#runtime-composition}

Mission-Bound Runtime Enforcement for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission-runtime}} defines the per-action
PDP and PEP contract. The runtime does not consume shaper output. It
consumes the Mission Intent and the Authority Set on the Mission record,
both produced by the Mission Issuer, not by the shaper. A runtime that
reads Shaping Evidence for an authorization decision is misusing it.

# Exposing Shaping as a Service {#exposing-shaping-as-a-service}

This profile requires no shaping endpoint, and a shaper is a client-side
function ({{client-side}}). A deployment that nevertheless factors
shaping into a network service for engineering reasons MAY expose it over
HTTPS. The request and response shapes such a service uses are a local
implementation detail, not an interoperability contract, and this
section is non-normative.

A request typically conveys the task (free text and/or structured
fields), the subject and agent on whose behalf the Mission would run,
deployment context, an optional authority ceiling, and the capability
sources the shaper may consult. A response typically conveys an
outcome (a Mission Intent proposal, a set of clarifications, or a
refusal) together with Shaping Evidence and, for a proposal, an
optional `shaping_evidence_hash`. A deployment that publishes such an
endpoint through its metadata might use fields such as
`mission_shaping_endpoint` and `mission_shaping_profiles_supported`.

Such an endpoint MUST be authenticated when it can reveal sensitive
task, tenant, or resource information; an anonymous shaping endpoint is
appropriate only for public, non-sensitive tasks. Exposing the shaper
this way does not change its role: it remains client-side machinery that
produces an untrusted proposal ({{role-and-trust-boundary}}), and it is
not a principal to the Authorization Server.

# Security Considerations {#security-considerations}

The shaper sits at the prompt-to-Intent boundary. Its security
properties follow from the role contract: the shaper proposes, and
authority is created only at the Mission Issuer's approval event.

## Model Output Is Not Authority {#model-output}

A model-based shaper can draft a Mission Intent, but the model MUST NOT
be the authority that grants or widens access. The approved Mission is
created only through the issuance profile's validation and approval. A
deployment that lets a model's proposal become active without validation
and approval is not following this profile. A model-based shaper
inherits its model's failure modes (hallucinated resources, fabricated
constraints, inconsistent paraphrase, sensitivity to small input
perturbations) and SHOULD record the model identifier and version in
Shaping Evidence so failures can be attributed.

## Shaper Compromise Does Not Directly Grant Authority {#shaper-compromise}

A compromised shaper can produce arbitrary Mission Intent and can
suppress ambiguity, but it cannot, by itself, cause the Mission Issuer
to approve that Intent. A compromised shaper can cause spurious
proposals to be submitted, mis-shape Intent so the Approver approves a
task different from the one intended, or leak prompts through
shaper-local logging. It cannot issue credentials, set or change Mission
lifecycle state, bypass the approval event, or cause a Resource Server
to act without Mission Issuer-issued authority. The Mission Issuer
remains the enforcement point for approval and MUST validate and narrow
the proposal; deployments SHOULD monitor shaper versions and evidence
for anomalous broadening.

## Prompt Injection and Untrusted Content {#prompt-injection}

The shaper's input is, by assumption, partially or wholly
attacker-influenceable: prompts may contain pasted content, content the
user was tricked into typing, or content arriving through a non-prompt
trigger such as an inbound email or webhook. Task text, tickets,
documents, tool descriptions, and catalog metadata can all carry
instructions aimed at the shaper. Concrete threats include attempts to
expand `resources` beyond what the user requested, to push
`mission_expiry` past deployment policy, to suppress a stated
constraint, or to select a `purpose` the user did not choose.

Mitigations the shaper SHOULD apply:

1. Treat all prompt and attachment content as untrusted data, not as
   instructions to the shaper. Do not let it alter shaper policy or
   override deployment defaults.
2. Apply the refusal behavior of {{refusal}} when the input exhibits
   injection patterns.
3. Do not echo verbatim prompt-derived instruction text into `goal` or
   `constraints` the Approver will read; paraphrase, or quote with clear
   attribution, but do not present injected content as if it came from
   the user.
4. Use the capability sources' resolved vocabulary as a hard allowlist
   ({{capability-resolution}}); do not infer new authority types from
   the prompt.
5. Record the prompt, the parsed intent, and the chosen defaults in
   Shaping Evidence so an auditor can reconstruct what the shaper saw.

Injection cannot be fully eliminated at the shaper. The defense in depth
is the Approver seeing the Mission Intent in a consent disclosure
rendered by the Mission Issuer, not by the shaper, before authority is
bound. A shaper that builds Intent truthfully and a Mission Issuer that
renders disclosure truthfully together make injection visible at the
approval step.

## Silent Broadening and Stale Capability Sources {#silent-broadening}

The primary failure mode is silent broadening: a vague goal becomes a
wide Authority Set. The ambiguity rules of {{ambiguity}} are intended to
fail closed by requiring clarification, narrowing, or refusal. A
proposal shaped against an old catalog can also resolve the wrong
capability; capability resolutions SHOULD record source digests
({{capability-resolution}}) and deployments SHOULD re-shape when catalog
data is volatile, so approval and runtime enforcement can detect drift.

## Shaper-to-Client Integrity in a Multi-Process Client {#multi-process}

In a client where the shaper runs in a different process or machine from
the OAuth submission code, the shaper-to-submission step is an in-client
boundary. An attacker between the two could alter the Mission Intent
before submission. The Mission Issuer will still validate the altered
Intent and render its consent disclosure, so the Approver remains the
final line of defense, but the altered Intent will not match what the
shaper actually produced. A deployment MAY apply client-internal
integrity protection between shaper output and the submission code (a
client-local signature, a process-isolated channel). Such protection has
no semantics at the Mission Issuer and MUST NOT be carried into the
Mission Intent as if it did ({{proposes-only}}).

## Confidentiality of Prompt Content {#confidentiality}

Prompts may carry sensitive content (personal data, business data,
free-form expression). The shaper SHOULD apply the requesting client's
data-handling policy to prompt content, including Shaping Evidence.
Evidence transmitted outside the client's trust domain (for example,
shipped to a centralized audit store) SHOULD carry the same controls the
client applies to any other prompt or user-content log.

# Privacy Considerations {#privacy-considerations}

The shaper sits where a user's natural-language prompt, which may carry
personal data, business-confidential content, or free-form expression,
becomes structured artifacts. The privacy surface follows
from where that content flows.

The shaper copies or paraphrases prompt content into `goal`,
`resources`, `constraints`, and `context`, which the Mission Issuer
renders in a consent disclosure the Approver reads and which may be
retained in the Mission record. A shaper SHOULD carry into these fields
only the content needed to describe the task, SHOULD NOT widen
`resources` or echo unrelated prompt content
({{mission-intent-proposal}}), and SHOULD avoid copying third-party
personal data into `goal` where a non-identifying description suffices.

Shaping Evidence aggregates the prompt, applied defaults, inferences,
and model outputs into one artifact and is therefore a concentrated sink
of sensitive content. Deployments SHOULD minimize retained raw task
text, prefer digests where full content is not required for audit, apply
access controls equivalent to those used for Mission records, and be
able to produce a redacted evidence record for audiences that need the
transformation provenance but not the raw prompt.

The shaper introduces no identifier of its own and is not a separate
principal to the Mission Issuer ({{role-and-trust-boundary}}). It
therefore adds no cross-party correlation surface beyond the prompt
content it processes and the requesting-client identity the Mission
Issuer already sees.

# IANA Considerations {#iana}

This document has no IANA actions. The Mission Intent Shaping profile is
Informational; it registers no media type, claim name, endpoint name,
parameter name, error code, metadata field, or namespace URI. A future
portable shaping protocol, if specified, would be a separate document
and would carry its own registrations there.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
set and describes the shaping layer that precedes Mission issuance. It
builds on Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} and complements Mission-Bound
Runtime Enforcement for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission-runtime}}.
