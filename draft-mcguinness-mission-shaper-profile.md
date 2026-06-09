---
title: "Mission Shaper Profile"
abbrev: "Mission Shaper Profile"
category: info

docname: draft-mcguinness-mission-shaper-profile-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - shaper
 - intent
 - authorization
 - agent
 - delegation
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-shaper-profile.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  I-D.draft-mcguinness-mission-framework:

informative:
  RFC3339:
  RFC6749:
  RFC9396:
  I-D.draft-mcguinness-mission-oauth-profile:
  I-D.draft-mcguinness-mission-runtime-profile:
  I-D.draft-mcguinness-oauth-actor-profile:
  I-D.draft-mcguinness-oauth-client-instance-assertion:

--- abstract

This document is an Informational profile describing the Mission
Shaper, a client-side component that transforms a user prompt or
upstream trigger into a structured Mission Intent for submission to
a Mission state authority per the Mission Framework. This profile
defines role boundaries, trust-boundary placement, and recommended
behavior for Shaper implementations. It does not define a portable
wire protocol, register media types or claim names, or claim
cross-vendor conformance. A future portable Shaper protocol, if
warranted, would be a separate Standards Track specification with
its own discovery surface and conformance requirements.

--- middle

# Introduction

The Mission Framework {{I-D.draft-mcguinness-mission-framework}}
defines the Mission Intent as the structured task proposal a client
submits to a state authority (an OAuth Authorization Server, an
AAuth Person Server, or a Mission Authority Server). The Framework
specifies the schema, validation, narrowing, and approval semantics
of Mission Intent. It does not specify how a client produces the
Mission Intent in the first place.

In practice, agentic clients produce Mission Intent from one of two
sources:

1. A natural-language prompt from a human user.
2. An upstream trigger such as an event, a schedule, an API call,
   or an inbound message.

The component inside the client that performs this transformation is
called the **Mission Shaper**. The Shaper is a client-side
function. It is not a credential issuer, not a Resource Server, not
a state authority, and not a Policy Decision Point. The Shaper does
not approve Missions, does not issue authority, and does not certify
its own output. Its output is a proposal that the requesting client
submits to the state authority, which is the only party authorized
to validate it, narrow it, and bind authority to it.

This document is an Informational profile. It describes role
boundaries, recommended behavior, and an audit artifact (the Shaper
Trace) for Shaper implementations. It is deliberately non-portable:
the Framework defines the wire shape for Submitted Mission Intent
through its substrate profiles, and the Shaper merely produces a
value of that shape. Different client implementations may construct
Mission Intent differently, may use different language models or
heuristics, and may make different ambiguity-resolution choices.
This profile defines only the role contract the Shaper occupies
inside the trust model and the behaviors a sound implementation
follows.

This document does not define:

- A wire format for invoking a Shaper.
- A discovery endpoint for Shaper-as-a-service.
- A media type or claim name.
- A conformance test suite.
- A normative algorithm for prompt-to-Intent transformation.

The reason this profile is Informational is recorded in the
architecture decision log: client-side prompt processing is loosely
shaped by deployment policy, language-model choice, and product
ergonomics. A Standards Track document would overclaim, because no
two deployments will agree on the transformation. The role
boundaries and trust posture, however, are stable and worth
documenting.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms defined in the Mission Framework
{{I-D.draft-mcguinness-mission-framework}} are inherited here,
including Mission Intent, Submitted Mission Intent, Validated
Mission Intent, Mission Proposal, Mission, Authority Set, state
authority, requesting client, and approving principal.

This document additionally uses:

**Mission Shaper** (or "Shaper"):
: A client-side component that transforms a user prompt or upstream
trigger into a Submitted Mission Intent. Defined informally in the
Framework's terminology and given a role contract here.

**Prompt**:
: The natural-language or structured input the Shaper consumes. A
prompt may be a free-text user utterance, a templated user
interaction, or an upstream event payload.

**Trigger**:
: A non-prompt input that initiates Shaper invocation. Examples:
inbound webhook, scheduled job, message arrival, prior Mission
completion.

**Discovery snapshot**:
: A captured-at-construction record of the state-authority discovery
metadata the Shaper consulted while constructing the Submitted
Mission Intent. Used for audit reproducibility, not for wire
exchange.

**Derivation hint**:
: A non-authoritative suggestion the Shaper attaches to its output
to assist downstream tooling (e.g., a list of objects the prompt
appeared to mention). A derivation hint is advisory; it MUST NOT be
treated as authority by any downstream party.

**Shaper Trace**:
: An audit artifact recording the inputs the Shaper consumed, the
discovery snapshot used, the Mission Intent produced, and any
ambiguity decisions or refusal flags. Non-normative.

# Shaper Role and Trust Boundary

The Mission Shaper occupies a single, narrow role inside the
client. This section defines that role and the trust boundary the
Shaper does not cross.

## Client-side placement

The Shaper executes inside the requesting client (per Framework
terminology). It runs in the same trust domain as the rest of the
client. Its output is consumed by the client and submitted to the
state authority through the substrate's Mission Intent submission
contract (the OAuth Profile, AAuth Profile, or MAS profile).

The Shaper is not a separate principal. It has no identity of its
own to the state authority; the state authority sees the requesting
client.

## The Shaper does not issue authority

The Mission Shaper MUST NOT issue, derive, or certify authority of
any kind.

The Shaper produces Submitted Mission Intent. Submitted Mission
Intent is, by Framework definition, untrusted until the state
authority validates it and produces Validated Mission Intent on a
Mission Proposal. The Shaper's output therefore has no authority
implications until the state authority approves a Mission from it
and derives an Authority Set.

A Shaper that signs its output, attaches an authority assertion,
emits a credential, or otherwise behaves as a credential issuer is
acting outside the role this profile defines and is NOT RECOMMENDED.
Implementations that wish to integrity-bind Shaper output for
client-side reasons (e.g., to prevent tampering between Shaper and
the submission step inside a multi-process client) MAY do so, but
that binding has no authority semantics at the state authority and
MUST NOT be relied upon by anything beyond the client process.

## Untrusted output principle

A state authority that receives Submitted Mission Intent MUST treat
that input as untrusted under the Framework's validation rules.
Nothing in this profile changes that. A Shaper SHOULD NOT structure
its output to imply otherwise. In particular, the Shaper SHOULD NOT
include fields that look like state-authority outputs (`mission.id`,
`proposal_hash`, `authority_hash`, `consent_disclosure_hash`,
`authority_set`, lifecycle state, approving-principal evidence).
Those fields are produced by the state authority on the Mission
Proposal and Mission records, not by the client. A Shaper that
emits them is either confused about its role or attempting to
mislead an auditor.

## The Shaper never crosses the trust boundary

The trust boundary in the Mission-Bound Authorization architecture
separates the client (where the Shaper lives) from the state
authority (where Validated Mission Intent and Authority Set are
created). Crossing that boundary is a state-authority action. The
Shaper produces an input; the client transmits the input; the state
authority decides what to do with it. The Shaper does not initiate
the submission, does not select the recipient state authority on
its own authority, and does not attest to the submission's
correctness on behalf of the state authority.

# Discovery Snapshot

A Shaper needs information about the state authority it is shaping
Intent for. At minimum, this includes the Mission Intent schema the
state authority will validate against, the Authority Set entry
types the state authority supports, and any deployment-specific
policy bounds the deployment exposes through metadata.

The Framework defines a discovery metadata document at
`{mission.origin}/.well-known/mission-authority`
{{I-D.draft-mcguinness-mission-framework}} containing fields
including `mission_intent_schema_uri`,
`authority_set_types_supported`, and
`mission_framework_versions_supported`. The OAuth Profile,
AAuth Profile, and MAS profile each add their substrate-specific
fields.

## What the Shaper consumes

A Shaper SHOULD consult the following sources when constructing a
Submitted Mission Intent:

1. The state-authority discovery document for the target state
   authority, retrieved at the URL the requesting client is
   configured to use.
2. The Mission Intent schema referenced by
   `mission_intent_schema_uri` in that document.
3. The list of Authority Set entry types the state authority
   advertises in `authority_set_types_supported`, so the Shaper can
   express objects, actions, and constraints in a vocabulary the
   state authority will accept.
4. Any deployment-specific narrowing-profile URIs or constraint
   registries referenced from the state-authority discovery
   document.
5. Client-local configuration, including the client's registered
   `purpose` URIs (if used), default `mission_expiry` ceilings, and
   product-level deployment policy.

A Shaper that does not consult discovery before constructing
Mission Intent is more likely to produce input the state authority
will reject. There is no wire penalty for skipping discovery; the
penalty is functional.

## Snapshot versioning for audit reproducibility

A Shaper SHOULD record a discovery snapshot describing exactly
which discovery sources, at exactly which versions, it relied upon
when constructing a particular Submitted Mission Intent. The
purpose of the snapshot is to allow an auditor to reproduce, after
the fact, the inputs the Shaper had available.

A discovery snapshot SHOULD include, for each discovery source
consulted:

- The URL retrieved.
- A content hash of the retrieved document, computed by the Shaper.
- The timestamp of retrieval, in RFC 3339 {{RFC3339}} format.
- Any version identifier the document itself exposed (e.g.,
  `mission_framework_versions_supported`).

The snapshot is a Shaper-internal artifact. It is not transmitted
on the wire to the state authority, and the state authority does
not validate it. This profile does not define a snapshot schema or
file format. The snapshot is recorded inside the Shaper Trace
(below) when an implementation supports tracing.

A Shaper MAY cache discovery documents for performance; if it does,
the cached version's content hash and original retrieval timestamp
are the values recorded in the snapshot, not a refreshed timestamp.
Misrepresenting the snapshot would defeat the audit purpose.

# Mission Intent Construction Rules

The Framework defines the Mission Intent fields:

- `goal` (string, required).
- `objects` (array of string, required).
- `constraints` (array of string, required).
- `success_criteria` (array of string, required).
- `mission_expiry` (RFC 3339 timestamp, required).
- `purpose` (URI, optional).
- `context` (object, optional).
- Extension fields prefixed with `x_*` (optional).

This section gives recommended construction rules for mapping a
prompt or trigger onto these fields. These are guidance; they are
not a normative algorithm.

## `goal`

The `goal` SHOULD be a concise, user-readable summary of the task
in the form the approving principal will see at consent time. The
Shaper SHOULD preserve the user's own framing where possible
(rather than paraphrasing into Shaper vocabulary), so that the
consent disclosure presented by the state authority matches the
user's understanding of what they asked for.

The `goal` SHOULD NOT include verbatim quoted prompt text that
contains instructions or commands. Quoting an attacker-controlled
instruction into a field the approving principal will read invites
the approving principal to act on instructions that did not come
from them.

## `objects`

The `objects` array SHOULD enumerate the resources, datasets,
tools, or domains the prompt referenced. A Shaper SHOULD prefer
canonical identifiers (e.g., a resource URI the requesting client
recognizes) where the prompt can be resolved to one, and SHOULD
fall back to a user-readable label only when no canonical
identifier is available.

A Shaper SHOULD NOT widen `objects` beyond what the prompt
referenced. Adding objects "for convenience" enlarges the surface
the state authority will validate and, if approved, enlarges the
authority bound to the Mission.

## `constraints`

The `constraints` array SHOULD reflect bounds the user expressed
("read-only", "today only", "no more than three messages"). A
Shaper SHOULD also add deployment-policy constraints that the
requesting client always applies (e.g., a fixed maximum spend, a
fixed cohort restriction), so the approving principal sees the full
set of bounds at consent time.

A Shaper MUST NOT silently drop a constraint the user expressed
because the Shaper cannot map it to a known constraint type. If the
constraint cannot be expressed in a vocabulary the state authority
will accept, the Shaper SHOULD either ask the user to clarify (per
the ambiguity-surfacing behavior below) or refuse to produce the
Mission Intent (per the refusal behavior below).

## `success_criteria`

The `success_criteria` array SHOULD record what would make this
task complete from the user's perspective. The Shaper SHOULD avoid
encoding open-ended criteria ("until I tell you to stop") in a way
that disables the Framework's `mission_expiry` ceiling. The
state authority owns lifecycle; the Shaper proposes criteria the
state authority and runtime evaluate.

## `mission_expiry`

The `mission_expiry` SHOULD be the smallest ceiling that lets the
task complete. The Shaper SHOULD prefer a short, task-shaped
expiry over a long, calendar-shaped expiry (one hour for a
one-shot task; one work day for a follow-the-thread task; not one
year). The state authority MAY narrow `mission_expiry` further
under deployment policy; the Shaper's job is to start tight, not to
ask for the maximum the state authority allows.

If the prompt does not name a time bound, the Shaper SHOULD apply
a deployment default rather than asking the user for an expiry on
every prompt. Defaults SHOULD be conservative.

## `purpose`

The `purpose` URI is optional. If the requesting client has
registered purposes with the state authority or the deployment
ecosystem, the Shaper SHOULD select the purpose URI that most
closely matches the prompt, rather than omitting `purpose` or
inventing a new URI. Inventing URIs at Shaper time defeats the
purpose registry.

## `context`

The `context` object carries machine-actionable bounds keyed by
constraint type. The Shaper SHOULD only emit `context` keys the
state-authority discovery snapshot advertised as supported
constraint types. Emitting unknown keys gives the state authority
no choice but to reject the Mission Intent.

## Extensions (`x_*`)

A Shaper MAY emit `x_*` extension fields the requesting client and
state authority have agreed on. The Shaper SHOULD NOT invent
`x_*` fields opportunistically: per the Framework, an extension
field that claims authority-relevant semantics will be rejected by
the state authority unless registered.

# Recommended Ambiguity-Surfacing Behavior

A prompt is often underspecified relative to what the Mission
Intent schema requires. The Shaper has two ways to resolve
underspecification: ask the user a clarifying question, or apply a
deployment default. This section gives guidance on the choice.

## When to ask for clarification

The Shaper SHOULD ask the user a clarifying question when:

1. The prompt names a class of objects but not a specific instance,
   and the choice of instance is consequential (e.g., "send the
   report" when there are several reports).
2. The prompt requests an action whose impact varies sharply
   depending on a bound the user did not state (e.g., "spend up to
   X" when X is missing).
3. The prompt could plausibly mean either a small task or a large
   task, and the difference matters for what authority will be
   approved.
4. The deployment policy requires user confirmation of a parameter
   (e.g., the cohort of users a broadcast will reach).

## When to apply a default

The Shaper MAY apply a deployment default, rather than asking,
when:

1. The missing field has a conservative default the user would
   reasonably expect (e.g., applying a one-hour `mission_expiry`
   when no time bound was stated).
2. Asking would impose more friction than the disambiguation is
   worth, and the consent step at the state authority will surface
   the default to the approving principal anyway.
3. The deployment policy explicitly designates this case as
   default-applicable.

## What ambiguity surfacing is not

Asking the user a clarifying question is not approval. The user's
response is incorporated into the Submitted Mission Intent. The
state authority still validates, narrows, and presents the consent
disclosure for binding approval. A Shaper SHOULD NOT skip the
state-authority consent step on the grounds that the user already
"answered enough questions". The Shaper is not the approving
principal's agent for consent.

# Recommended Non-Authoritative Derivation-Hint Content

Some deployments find it useful for the Shaper to attach
non-authoritative hints to its output, to help downstream
orchestration tools render the Mission Intent for user review, log
the Shaper's reasoning, or prefetch resources. These are
derivation hints. They are advisory.

A derivation hint:

- SHOULD be carried in a Shaper-local data structure (or, if
  transmitted over a substrate, in a field the substrate clearly
  marks as advisory).
- MUST NOT be carried in fields the state authority interprets as
  authoritative (the Validated Mission Intent fields, the Authority
  Set, integrity-anchor inputs, approving-principal evidence).
- SHOULD NOT be transmitted to a Resource Server, a Policy Decision
  Point, or a Policy Enforcement Point as a basis for an
  authorization decision. A PDP that consults Shaper-emitted hints
  for authorization is conflating the Shaper with a credential
  issuer, which this profile explicitly disclaims.

Examples of reasonable derivation-hint content:

- A list of objects the Shaper inferred from the prompt, with a
  confidence label per item, for client-side UI.
- A list of candidate Authority Set entry types the Shaper expects
  the state authority will derive (for prefetch of policy
  documents, not for authorization).
- The provenance of each Mission Intent field (prompt text, user
  clarification, deployment default).
- The language-model identifier and version that produced the
  field, when the Shaper used a model.

A downstream party that wants to rely on any of these hints SHOULD
verify them against authoritative artifacts: the Validated Mission
Intent on the Mission Proposal, the Authority Set on the Mission,
or the runtime PDP decision. Derivation hints are inputs to user
experience and audit, not to authorization.

# Recommended Refusal Behavior

There are inputs the Shaper SHOULD refuse to produce Mission Intent
from. Refusal is a Shaper-internal decision; it does not require
state-authority involvement, and this profile does not define a
wire-level refusal error.

## When the Shaper SHOULD refuse

The Shaper SHOULD refuse to produce Mission Intent when:

1. The prompt contains instructions evidently designed to enlarge
   authority beyond what the user has stated (prompt-injection
   patterns directed at the Shaper).
2. The prompt requests action against an object the deployment
   policy categorically forbids (e.g., a domain the requesting
   client is configured to never touch).
3. The Shaper cannot map the requested action to any Authority Set
   entry type the discovery snapshot advertises, and no fallback
   constraint vocabulary applies. Submitting such an Intent only
   wastes a state-authority validation cycle.
4. The requested `mission_expiry`, if honored, would exceed any
   deployment ceiling the Shaper is aware of, and the Shaper has
   no policy basis for narrowing it on the user's behalf.
5. The prompt contains content that, if echoed into the consent
   disclosure, would mislead the approving principal (e.g., a
   crafted string disguised as a system instruction).

## When the Shaper SHOULD NOT refuse

The Shaper SHOULD NOT refuse merely because the requested authority
is broad. Breadth is the state authority's decision, not the
Shaper's. The state authority will narrow under deployment policy
and surface the result to the approving principal. The Shaper
refusing on breadth grounds substitutes its own judgment for the
approving principal's.

The Shaper SHOULD NOT refuse on the grounds that the Authority Set
the state authority would derive looks expensive. That is a
runtime concern, not a Shaper concern.

## How refusal is surfaced

When the Shaper refuses, it SHOULD return a structured refusal to
the requesting client, including:

- A category label (e.g., "prompt-injection", "out-of-policy",
  "unmappable").
- A short user-readable explanation suitable for the client to
  display.
- The Shaper Trace artifact (below), so the client and any
  downstream auditor can review the inputs.

The requesting client decides what to do with the refusal: prompt
the user for a different formulation, route to a different
workflow, log and discard, or escalate. The refusal itself is not
an authority decision; it is the Shaper declining to manufacture
input.

# Shaper Trace (non-normative example)

The Shaper Trace is an audit artifact recording the prompt-to-Intent
transformation. It is non-normative. This profile does not define
a schema for the Shaper Trace, does not register a media type for
it, and does not specify how it is transmitted. Implementations
that find a trace useful may shape it as they wish.

A Shaper Trace might record fields such as:

- `prompt`: the prompt or trigger payload the Shaper consumed.
- `discovery_snapshot`: the discovery snapshot the Shaper relied
  on (URLs, content hashes, retrieval timestamps).
- `clarifications`: any clarifying questions the Shaper asked the
  user and the responses received.
- `defaults_applied`: deployment defaults the Shaper used to fill
  underspecified fields, with the rationale per field.
- `mission_intent`: the Submitted Mission Intent the Shaper
  produced (or the refusal record, if the Shaper refused).
- `derivation_hints`: any non-authoritative hints the Shaper
  attached.
- `model`: an identifier and version for the language model or
  ruleset the Shaper used, where applicable.
- `created_at`: an RFC 3339 {{RFC3339}} timestamp.

A non-normative sketch of a Shaper Trace record:

~~~ json
{
  "prompt": "schedule a follow-up with our top 5 customers this week",
  "discovery_snapshot": {
    "sources": [
      {
        "url": "https://as.example/.well-known/mission-authority",
        "content_hash": "sha-256:...",
        "retrieved_at": "2026-06-09T14:02:11Z"
      }
    ]
  },
  "defaults_applied": [
    {"field": "mission_expiry", "reason": "deployment-default-7d"}
  ],
  "mission_intent": {
    "goal": "schedule a follow-up with our top 5 customers this week",
    "objects": ["crm.customers", "calendar.primary"],
    "constraints": ["read-only access to CRM", "one event per customer"],
    "success_criteria": ["5 calendar events created"],
    "mission_expiry": "2026-06-16T14:02:11Z"
  },
  "derivation_hints": {
    "expected_authority_types": ["mission_resource_access"]
  },
  "model": "example-shaper/0.3",
  "created_at": "2026-06-09T14:02:11Z"
}
~~~

This example is illustrative. It is not a vector, not a schema, and
not a recommended on-the-wire shape. A deployment may use a
completely different structure or none at all.

# Composition with Substrate Profiles

The Mission Shaper produces Submitted Mission Intent. The
substrate profile defines how that Submitted Mission Intent enters
the state authority's submission contract. This profile does not
re-specify any of those contracts; it points at them.

## OAuth Profile

The Mission-Bound OAuth Profile
{{I-D.draft-mcguinness-mission-oauth-profile}} defines a
`mission_intent` parameter carried inside a Pushed Authorization
Request (PAR) {{RFC9396}}. The Submitted Mission Intent the Shaper
produced is the value of that parameter. The Authorization Server
acts as the state authority: it validates, narrows, and renders the
consent disclosure, then creates a Mission Proposal and, on
approval, a Mission with a derived Authority Set
({{I-D.draft-mcguinness-mission-oauth-profile}}).

The Shaper does not invoke the OAuth Authorization Endpoint, does
not call the PAR endpoint, and does not handle the authorization
response. Those are requesting-client responsibilities. The Shaper
hands its output to the requesting client, which performs the
OAuth flow.

## AAuth Profile

The Mission-Bound AAuth Composition Profile defines a native
Mission Intent submission shape on top of AAuth's two-state
lifecycle. The Submitted Mission Intent the Shaper produced is
carried into the AAuth submission as that profile specifies.

The relationship between the Shaper and the AAuth Person Server is
the same as between the Shaper and an OAuth AS: the Shaper does not
talk to the Person Server. The requesting client (the AAuth agent)
talks to the Person Server, carrying Shaper output.

## Mission Authority Server (MAS)

When the state authority is a Mission Authority Server holding a
substrate-neutral Mission record, the Mission Authority Server
profile defines the Submitted Mission Intent submission shape. The
Shaper's output enters that submission shape. The MAS validates,
narrows, and approves; downstream OAuth and AAuth substrates
project from the MAS-held Mission.

Across all three substrates, the Shaper role is identical: produce
a Submitted Mission Intent; let the state authority validate and
bind authority to it. The differences between substrates are in
the submission and projection wire shapes, not in what the Shaper
does.

## Runtime Enforcement Profile

The Mission-Bound Runtime Enforcement Profile
{{I-D.draft-mcguinness-mission-runtime-profile}} defines the PDP
and PEP contract for per-action enforcement. The runtime does not
consume Shaper output. It consumes Validated Mission Intent (on
the Mission record) and the Authority Set (also on the Mission
record), both produced by the state authority, not by the Shaper.
A runtime that reads Shaper derivation hints or Shaper Traces for
authorization is misusing them.

# Security Considerations

The Shaper sits at the prompt-to-Intent boundary. This section
identifies the security properties that follow from its role
contract and the threats that bear on its operation.

## Shaper compromise does not directly grant authority

A compromised Shaper can produce arbitrary Submitted Mission
Intent. It cannot, by itself, cause the state authority to approve
that Intent. The state authority validates the Intent against the
deployment's schema and policy, renders a consent disclosure to the
approving principal, and binds authority only at the approval
event.

A compromised Shaper can therefore:

- Cause spurious Mission Proposals to be submitted.
- Mis-shape Intent in ways that lead the approving principal to
  approve a task different from the one they intended.
- Leak prompts or context outward through Shaper-local logging.

A compromised Shaper cannot:

- Issue credentials.
- Set or change Mission lifecycle state.
- Bypass the approval event.
- Cause a Resource Server to act without state-authority-issued
  authority.

The trust posture is intentional. The Shaper's role is shaping, not
authorizing. Authority is created at the approval event by the
state authority.

## Untrusted Shaper output principle

State authorities, Resource Servers, PDPs, PEPs, and auditors MUST
treat Shaper output as untrusted client input. The Framework
already requires this for Submitted Mission Intent; this profile
reinforces it for any Shaper-emitted artifact, including
derivation hints, Shaper Traces, and structured refusals.

Implementations that grant authority on the basis of a
Shaper-emitted artifact (e.g., a Resource Server that lets a client
in because the client included a "trusted Shaper attestation")
have constructed a side channel around the Framework's authority
model. This profile does not endorse such constructions. If a
deployment finds itself building one, the right response is to push
the authority creation back to the state authority, not to harden
the side channel.

## Prompt injection at the Shaper boundary

The Shaper's input is, by assumption, partially or wholly
attacker-influenceable. Prompts come from users, but prompts may
contain content the user pasted, content the user was tricked into
typing, or content arriving through a non-prompt trigger such as
an inbound email or webhook. Prompt injection at the Shaper
boundary is a realistic threat.

Concrete prompt-injection threats include:

- An attacker-crafted document attempts to instruct the Shaper to
  expand the `objects` array beyond what the user requested.
- A crafted string in a triggered email body attempts to set
  `mission_expiry` further into the future than deployment policy
  allows.
- An instruction disguised as a system message attempts to suppress
  one of the user's stated constraints.
- A request attempts to specify a `purpose` URI that maps to a
  task class the user did not select.

Mitigations the Shaper SHOULD apply:

1. Treat all prompt content as untrusted data, not as
   instructions to the Shaper itself. Do not let prompt content
   alter Shaper policy or override deployment defaults.
2. Apply the recommended refusal behavior (above) when the prompt
   exhibits patterns characteristic of injection.
3. Do not echo verbatim prompt-derived instruction text into
   `goal` or `constraints` fields the approving principal will
   read. Paraphrase, or quote with clear attribution to the prompt
   source, but do not present injected content as if it came from
   the user.
4. Use the discovery snapshot's `authority_set_types_supported`
   and constraint vocabulary as a hard whitelist. Do not infer new
   authority types from the prompt.
5. Record the prompt, the parsed intent, and the chosen defaults
   in the Shaper Trace so an auditor can reconstruct what the
   Shaper saw.

Even with these mitigations, prompt injection cannot be fully
eliminated at the Shaper. The Framework's defense in depth is the
approving principal seeing the Validated Mission Intent in a
consent disclosure rendered by the state authority, not by the
Shaper, before authority is bound. A Shaper that builds Intent
truthfully from the prompt, and a state authority that renders
disclosure truthfully from the Validated Mission Intent, together
make injection visible at the approval step.

## Confidentiality of prompt content

Prompts may carry sensitive content (PII, business data, free-form
user expression). The Shaper SHOULD apply the requesting client's
data-handling policy to prompt content, including the Shaper Trace.
A Shaper Trace transmitted outside the client's trust domain (e.g.,
shipped to a centralized audit store) SHOULD apply the same
controls the client applies to any other prompt or user-content
log.

## Shaper-to-client integrity inside a multi-process client

In a client where the Shaper runs in a different process or
machine from the OAuth or AAuth submission code, the
Shaper-to-submission step is an in-client boundary. An attacker
sitting between the two could alter the Submitted Mission Intent
before submission. The state authority will still validate the
altered Intent and present its consent disclosure, so the
approving principal remains the final line of defense, but the
altered Intent will not match the prompt the Shaper actually
shaped.

Implementations MAY apply client-internal integrity protection
between the Shaper output and the submission code (e.g., a
client-local signature, a process-isolated channel). Such
integrity protection has no semantics at the state authority and
MUST NOT be carried into the Submitted Mission Intent as if it
did.

## Reliance on language-model behavior

A Shaper that uses a language model to construct Mission Intent
inherits that model's failure modes: hallucinated objects,
fabricated constraints, inconsistent paraphrase, sensitivity to
small input perturbations. The model is not part of the trust
boundary; its output is a client-side proposal subject to
state-authority validation. Implementations SHOULD nonetheless
record the model identifier and version in the Shaper Trace so
that failures can be attributed.

# IANA Considerations

This document has no IANA actions. The Mission Shaper Profile is
Informational. It does not register media types, claim names,
endpoint names, parameter names, error codes, metadata fields, or
namespace URIs. A future portable Shaper protocol, if specified,
would be a separate Standards Track document and would carry its
own IANA registrations there.

--- back

# Acknowledgments
{:numbered="false"}

This profile builds on the Mission Framework
{{I-D.draft-mcguinness-mission-framework}} and complements the
Mission-Bound OAuth Profile
{{I-D.draft-mcguinness-mission-oauth-profile}}, the AAuth
Composition Profile, the Mission Authority Server profile, and the
Mission-Bound Runtime Enforcement Profile
{{I-D.draft-mcguinness-mission-runtime-profile}}. The placement of
the Shaper as a non-authority-issuing client-side role, and the
explicit untrusted-output principle, draw on the architecture
discussion captured in the Mission-Bound Authorization spec
breakdown. Related delegation and instance-identity work referenced
informatively includes the OAuth Actor Profile for Delegation
{{I-D.draft-mcguinness-oauth-actor-profile}} and the OAuth Client
Instance Assertion
{{I-D.draft-mcguinness-oauth-client-instance-assertion}}.
