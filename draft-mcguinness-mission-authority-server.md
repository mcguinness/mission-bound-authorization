---
title: "Mission Authority Server"
abbrev: "Mission Authority Server"
category: std

docname: draft-mcguinness-mission-authority-server-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - governance
 - approval
 - enforcement
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC6838:
  RFC7519:
  RFC7638:
  RFC7662:
  RFC8259:
  RFC8615:
  RFC9110:
  RFC9421:
  RFC9651:
  MCP-META:
    title: "Model Context Protocol: Base Protocol"
    target: https://modelcontextprotocol.io/specification/2025-11-25/basic/index
    author:
      - org: Model Context Protocol Project
    date: 2025
  RFC9068:
  RFC9325:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
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
  I-D.draft-mcguinness-mission-approval-governance:
    title: "Mission Approval Governance"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-approval-governance.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8725:
  I-D.draft-mcguinness-oauth-mission-issuance-grant:
    title: "Mission Issuance Grant for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-issuance-grant.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC6749:
  RFC8126:
  RFC8414:
  RFC8693:
  RFC9635:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
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
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
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
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
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
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html
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
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
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

--- abstract

Mission-Bound Authorization for OAuth 2.0 defines the Mission, a
durable, human-approved, integrity-bound authorization artifact, and
binds it to OAuth issuance: the Authorization Server derives tokens
under the Mission and gates them on its state. Many deployments cannot
change their Authorization Server. This document defines the Mission
Authority Server, a standalone service that implements the Mission
Issuer role without being an OAuth Authorization Server: it validates
Mission Intents, runs approval events, records Missions, operates the
Mission lifecycle, and serves Mission state. It derives no tokens.
Access tokens remain ordinary OAuth tokens; a Policy Decision Point
joins each presented credential to its Mission at the point of use and
enforces through the Mission-Bound Runtime Enforcement profile. This
is the standalone binding, the AS-optional
deployment mode: Mission governance and per-action enforcement with no
change to the deployment's Authorization Server, forgoing the
Mission-bound credentials and issuance gating that only the issuance
profile provides (the issuance-grant companion restores both at
Authorization Servers that redeem its grants). Beyond a single-AS workaround, the Mission
Authority Server is the standalone Mission Issuer for an estate whose
task governance must span many Authorization Servers, SaaS systems,
APIs, local tools, and agent runtimes at once: a control plane for
approved-task authority over an unchanged OAuth estate. This document
defines a deployable conformance floor and, above it, an Enterprise
Mission Authority Profile for that role.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") binds
issued authority to a durable, human-approved Mission. Its Mission
Issuer role is played by the OAuth Authorization Server (AS)
{{RFC6749}}: the AS validates the Mission Intent, runs the approval
event, records the Mission, derives Mission-bound tokens, and gates
issuance on Mission state. That binding is the strongest deployment of
the Mission model, and it requires changing the AS.

Many deployments cannot make that change: the AS is a shared or
third-party service, while the need to govern agent tasks is
immediate. This document defines the **Mission Authority Server
(MAS)** for those deployments: a standalone service that implements
the Mission Issuer role of the issuance profile without being an OAuth
Authorization Server. A MAS validates Mission Intents, runs approval
events, records Missions, operates the Mission lifecycle, and serves
Mission state. It derives no tokens, and it requires no change to the
deployment's existing AS.

Because tokens remain ordinary OAuth tokens with no `mission` claim,
the credential-to-Mission association is established at the point of
use instead of traveling in the credential: the Policy Enforcement
Point (PEP) presents the Mission reference explicitly, and the Policy
Decision Point (PDP) joins the credential to the Mission before
evaluating the action ({{mission-join}}). Per-action enforcement then
proceeds under the runtime profile
{{I-D.draft-mcguinness-mission-runtime}} unchanged.

A deployment that changes its AS gets Mission-bound credentials and
issuance gating, which the MAS mode does not provide
({{limitations}}). The MAS is nonetheless a peer binding, not a
staging area: decoupling governance from token issuance is an
architectural choice some deployments make deliberately and keep.
Lacking a Mission-bound credential is not the same as lacking
strategic value. An enterprise governing agent tasks across many
Authorization Servers, SaaS tenants, APIs, and tool gateways needs
one place that holds the approved task, its lifecycle, and its
authority, independent of which system issued a given token; a
central MAS can be that place, and can remain the long-term
architecture even after some Authorization Servers become
Mission-aware. For deployments that want Mission-bound tokens on a
particular AS later, the path is smooth: the record, anchors, and
lifecycle a MAS operates are the issuance profile's own, so moving
issuance into that AS carries them over unchanged, while the MAS
continues to govern the rest of the estate.

## Applicability

This profile targets deployments that need governed, approvable,
revocable agent tasks but cannot extend their Authorization Server,
and that can route consequential actions through the runtime profile's
enforcement. It is also a deliberate architectural choice in its own
right: a deployment MAY prefer a standalone Mission Issuer even where
it controls its AS, to keep governance decoupled from token issuance
or to govern with one Mission Issuer across many Authorization
Servers, accepting the enforcement posture of {{limitations}}. A
deployment that wants Mission-bound tokens and issuance gating
implements the issuance profile; a deployment that cannot deploy runtime
enforcement over its consequential action paths obtains records but no
enforcement from this profile and SHOULD NOT claim it
({{limitations}}).

The Mission Join ({{mission-join}}) is the newest mechanism in the
family and not yet exercised in deployment; a deployment that can
implement the issuance profile obtains the stronger, stable binding.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

This document uses Mission, Mission Intent, Mission Issuer, Authority
Set, Approver, Subject, `mission_id`, the integrity anchors, and the
audit horizon as defined by {{I-D.draft-mcguinness-oauth-mission}};
the Mission Status operation and Mission Lifecycle endpoint as defined
by {{I-D.draft-mcguinness-oauth-mission-status}}; and PEP, PDP,
consequential action, Mission state source, and enforcement scope as
defined by {{I-D.draft-mcguinness-mission-runtime}}. It additionally
uses:

Mission Authority Server (MAS):
: A service that implements the Mission Issuer role of the issuance
  profile without being an OAuth Authorization Server. It is the
  `issuer` of the Missions it records, and it derives no tokens.

Mission-joining PDP:
: A PDP that resolves Missions at a MAS and verifies the join between
  a presented credential and the referenced Mission before evaluating
  an action ({{mission-join}}).

Standalone binding:
: This document's deployment mode: the Mission Issuer role implemented
  by a MAS, with the deployment's tokens unchanged. The rest of the
  Mission family cites this mode by this name; "AS-optional" is its
  informal gloss.

# Mission Substrate Statement {#mission-substrate}

This Statement applies to the standalone MAS binding defined by this
revision and declares conformance to
{{I-D.draft-mcguinness-mission-substrate}}.

The contextual-governance kernel maps as follows:

1. **Mission Reference**: the tuple (`issuer`, `mission_id`) names one
   Mission. The MAS issuer URL is the uniqueness namespace;
   `mission_id` follows the issuance profile's comparison, retention,
   entropy, and non-reassignment rules.
2. **Controller**: the MAS controls approval, Mission state, and the
   governance record. Consumers establish its identity and keys from
   the MAS discovery document ({{discovery}}).
3. **Actor binding**: the authenticated submitting client is the
   Actor and is recorded as `client_id`; the MAS separately establishes
   the Subject during approval. Later action decisions establish the
   Actor and Subject through the Mission Join, including the mapping
   assurance and ambiguity declared by the deployment
   ({{mission-approval}}, {{mission-join}}).
4. **Approved Context**: the Mission Intent, the recorded authority
   proposal where one was submitted, and the derived Authority Set
   in the immutable Mission record are the Approved Context. The
   issuance profile's `intent_hash` and `authority_hash`, computed
   with the MAS issuer URL, plus `proposal_hash` where a proposal
   was submitted, are this binding's chosen commitments;
   they are not substrate-kernel requirements.
5. **Approval ceremony**: the asynchronous MAS approval surface
   authenticates the Approver, establishes the Subject and Actor,
   renders the derived authority, computes the commitments, and
   creates the record `active` atomically with approval
   ({{mission-approval}}).
6. **Governance gate**: only `active` permits a positive MAS decision;
   every other or unrecognized state fails closed. The lifecycle
   endpoint supplies authenticated transitions, including revocation
   by the authorized parties ({{lifecycle-and-state}}).
7. **Reliance bound**: a positive MAS decision requires current
   `active` state at decision time. Standing artifacts carry their own
   bounds: a signed Mission Status is relied on within its declared
   freshness window ({{lifecycle-and-state}}), and a Join Assertion
   within the introspected token's lifetime ({{join-assertion}}).
   Tokens of the unchanged Authorization Server are not represented as
   Mission-governed artifacts.
8. **Context propagation**: submission status and signed Mission
   Status responses carry the Mission Reference. A Mission-joining PDP
   verifies the reference against the acting credential before using
   Mission authority. That join establishes correlation, not that the
   unchanged Authorization Server issued the credential under the
   Mission ({{mission-reference}}, {{mission-join}}).
9. **Governance record**: the MAS audit log is the ordered governance
   record. The MAS MUST append approval, positive and negative
   Mission-dependent decisions, join decisions it makes, and lifecycle
   transitions in per-Mission append order; MUST protect the log under
   the same integrity and access controls as the Mission record; and
   MUST retain both for the declared audit horizon.

The Statement's capability table follows, one row per capability;
every supplied row states its activation conditions, and its temporal
and failure elements in its cells or by express inheritance of the
Bounded Reliance floor ({{I-D.draft-mcguinness-mission-substrate}}):

| Capability | Claim | Activation | Scope and defining sections | Limitations |
| --- | --- | --- | --- | --- |
| Lifecycle-Gated Authorization | supplied | a Mission-joining PDP deployment | MAS-native authority operations and joined action decisions check current state ({{lifecycle-and-state}}, {{mission-join}}) | The unchanged Authorization Server does not gate token issuance or refresh; the token-layer residual runs to credential expiry |
| State-Observable | supplied | always | Signed Mission Status responses with the `mission_max_stale_seconds` freshness bound ({{lifecycle-and-state}}, {{discovery}}) | Consumers fail closed when the declared freshness bound is exceeded |
| Structured Authority | supplied | always | The issuance profile's Authority Set and Common Constraints are held at the MAS and evaluated at the joining PDP | Semantics apply only to the declared authority-detail types and mappings |
| Monotonic Derivation | supplied | native child creation ({{native-child}}) | The defined no-broader-than relation at the native child-creation derivation point | PDP action evaluation is enforcement, never derivation; a separately approved expansion is a new approval; unchanged AS tokens are outside the claim |
| Credential-Bound | supplied | the Join Assertion endpoint ({{join-assertion}}) | A signed assertion binds one introspected token digest and `cnf` thumbprint to the Mission; fact semantics: verified party correlation, with the assertion's `exp` bounded by the token's remaining lifetime | Neither the assertion nor the mapping join proves the Authorization Server issued the token under the Mission; a mapping-join-only deployment is outside this row |
| Authorized Context Correlation | supplied | always | The mapping join and the Join Assertion ({{mission-join}}, {{join-assertion}}): the MAS and its joining PDPs are the joining authority under the enterprise mapping contract, joining the introspected credential, the subject and client mappings, and the Mission; a failed join denies `mission_mismatch`, never falling back | The association proves the credential belongs to the Mission's parties, never that it was issued for the Mission; the bare mapping join carries the (`subject`, `client`) equivalence-class ambiguity, and substitution protection requires the `cnf`-bound assertion ({{join-spoofing}}) |
| Independently Verifiable | supplied | signed Mission Status ({{lifecycle-and-state}}) | Record and state properties as of the response's freshness window; Join Assertions add token-specific correlation where used | Does not prove AS issuance under the Mission or current state after the observation window |
| Portable Evidence | supplied | Consent Evidence, a Mission Mandate, or Audit Transparency adopted | The adopted profile's artifact and verification procedure | The base MAS audit log is Controller-local and is not portable evidence |
{: title="Standalone MAS Mission substrate capabilities"}

The Portable Evidence condition is supplied only when the deployment
adopts Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), a Mission
Mandate ({{I-D.draft-mcguinness-mission-mandate}}), or Audit
Transparency ({{I-D.draft-mcguinness-mission-audit}}); the referenced
profile defines the portable artifact and verification procedure.

The composition consequences follow from those claims:

- Shaping, consent evidence, audit transparency, the security model,
  status, and signals compose with the capabilities they name. Where
  such a profile names the Mission Issuer or issuer AS, the MAS is that
  party.
- The runtime profile and its AuthZEN binding, the harness, and
  orchestration compose through the runtime profile's externally
  established binding mode
  ({{I-D.draft-mcguinness-mission-runtime}}), profiled here as the
  Mission Join ({{mission-join}}).
- Offline attenuation does not apply in MAS-only mode because no
  Mission-bound credential or offline-minting chain exists
  ({{I-D.draft-mcguinness-oauth-mission-attenuation}}). The
  token-carriage aspects of delegation likewise have no carrier.
- Mission Expansion ({{I-D.draft-mcguinness-oauth-mission-expansion}})
  and Mission Child Delegation
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) bind their
  request, on the OAuth wire, to an {{RFC8693}} token exchange whose
  `subject_token` is the predecessor or parent Mission-bound access
  token; their MAS-native wire is defined by {{native-surfaces}}, which
  carries both operations on the mission submission endpoint with an
  authenticated-client binding in place of that token-exchange
  possession proof. Their models (supersession, lineage, cascade) apply
  to MAS-held Missions unchanged.

# Mission Submission {#mission-submission}

A client proposes a Mission by submitting a Mission Intent to the
MAS's mission submission endpoint, published as
`mission_submission_endpoint` ({{discovery}}). The endpoint MUST be
served over TLS 1.2 or later (TLS 1.3 RECOMMENDED), following the
recommendations of {{RFC9325}}. The endpoint MUST authenticate the
client using the authentication mechanisms of the Mission Status
endpoint ({{I-D.draft-mcguinness-oauth-mission-status}}): mTLS,
DPoP-bound bearer, or private-key JWT. How clients register with a
MAS is deployment-defined; the identifier the MAS authenticates is
recorded as the Mission's `client_id`.

The endpoint serves two operations, dispatched by request media type:

- **Intent submission**: an HTTPS POST whose `application/json` body
  is the Mission Intent Submission envelope ({{intent-submission}}).
- **Submission status**: an HTTPS POST with an
  `application/x-www-form-urlencoded` body containing a `submission`
  parameter ({{submission-status}}).

## Intent Submission {#intent-submission}

The request body is a Mission Intent Submission envelope as the
issuance profile defines it, `intent` plus OPTIONAL `evidence`, and
the issuance profile's validation and Intent Submission Evidence
rules apply unchanged ({{I-D.draft-mcguinness-oauth-mission}}): the
submission is untrusted client input and never authority; the MAS
MUST bound its total size, array lengths, evidence entry count, and
evidence verification cost; and the envelope and the Intent are both
closed at the top level. The issuance profile's OAuth error outcomes
map to this endpoint's error codes ({{submission-errors}}):

- A body that cannot be parsed as a JSON {{RFC8259}} object, is
  structurally invalid, exceeds the deployment's size bounds, or
  contains a top-level member the issuance profile does not define
  MUST be refused with `invalid_mission_intent` (the MAS equivalent of
  the issuance profile's `invalid_request` rejections, including
  reject-unknown-top-level-member).
- A well-formed Intent from which the MAS cannot derive a valid
  Authority Set under policy MUST be refused with `invalid_authority`
  (the MAS equivalent of `invalid_authorization_details`), so a client
  can distinguish a syntax error from an authority-derivation failure.
- An Intent Submission Evidence entry of an unsupported type, an
  entry that fails its type's verification, or a policy-required
  evidence type absent from the submission MUST be refused with
  `invalid_intent_evidence` (the MAS equivalent of the issuance
  profile's `invalid_mission_intent_evidence`); presented evidence is
  never silently ignored.

The request body MAY additionally carry an `authorization_details`
member: the client's authority proposal, an array of
`authorization_details` objects. This member is this binding's
proposal carriage, replacing the issuance profile's PAR-only
carriage rule; that profile's validation, derivation, recording, and
hashing semantics apply unchanged
({{I-D.draft-mcguinness-oauth-mission}}). It is a proposal, never
authority, and it is a submission member, not a Submission-envelope
member ({{native-carriage}}): the MAS MUST remove it before applying
the envelope validation above. The issuance profile's intake refusals for a
proposed entry map to `invalid_authority` here. A Mission created
from a submission carrying a proposal records `proposed_authority`
and `proposal_hash` as the issuance profile's Mission record defines
them.

A MAS has no derivation event: no token is issued under the Mission,
so `controls.max_derivations` binds nothing here (a MAS
implementing the issuance-grant companion has one, each grant
minted, and applies that profile's counting rule,
{{I-D.draft-mcguinness-oauth-mission-issuance-grant}}). A MAS SHOULD refuse
an Intent that carries it, or record it and ensure the approval
rendering marks it non-binding, per the issuance profile's rule that
consent is not given to a limit that binds nowhere. The same
treatment applies to any future control scoped to an issuance event.

On acceptance the MAS derives the Authority Set from the Intent, and
from the authority proposal where one was submitted, under
the issuance profile's derivation rules
({{I-D.draft-mcguinness-oauth-mission}}) and returns HTTP 202 with a
pending-submission reference:

`submission_id`:
: REQUIRED. A string. An opaque URL-safe ASCII string of
  `[A-Za-z0-9_-]` characters with at least 128 bits of entropy,
  carrying no semantic content. It MUST NOT be reused. It is a
  reference, never a capability.

`status`:
: REQUIRED. A string. `pending` on acceptance.

`expires_at`:
: REQUIRED. A string. An RFC 3339 {{RFC3339}} date-time after which an
  undecided submission lapses to `expired`.

Example:

~~~ http-message
POST /mas/mission/submit HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments under $500.",
    "resources": ["https://erp.example.com"],
    "expires_at": "2026-12-31T23:59:59Z"
  }
}
~~~

~~~ http-message
HTTP/1.1 202 Accepted
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_4qV9rL3tY6sB1zN0eF7jB8K2nP",
  "status": "pending",
  "expires_at": "2026-10-16T14:32:11Z"
}
~~~

## Submission Status {#submission-status}

The client polls the outcome with a form-urlencoded POST carrying:

`submission`:
: REQUIRED. A string. The `submission_id`.

A submission is in one of four states:

| `status` | Meaning |
|---|---|
| `pending` | Awaiting an approval decision. |
| `approved` | Approved; a Mission exists ({{mission-reference}}). |
| `denied` | Declined by the Approver or refused by policy. Terminal. |
| `expired` | `expires_at` passed undecided. Terminal. |

Only `approved` delivers a Mission: a consumer MUST treat every other
`status` value, recognized or not, as not approved, mirroring the
issuance profile's only-`active` rule. A resolved submission MUST
remain resolvable for a deployment-defined window; the reference is
never reused.

The MAS MUST return submission status only to the authenticated client
that submitted the Intent. For any other caller, and for an unknown
`submission_id`, the MAS MUST return the `not_found` error with an
identical status code, body, and headers, preserving the anti-oracle
property of {{I-D.draft-mcguinness-oauth-mission-status}}.

## Error Responses {#submission-errors}

A hard failure returns the matching HTTP status with a JSON object
body:

`error`:
: REQUIRED. A string. A code from the table below.

`error_description`:
: OPTIONAL. A string. Human-readable detail.

`error_reason`:
: OPTIONAL. A string. A machine-readable refinement of `error`: for
  `invalid_mission_intent`, the name of the offending top-level
  member; for `invalid_authority`, the `resources` entry no authority
  could be derived for. It reflects the client's own input and MUST
  NOT disclose policy internals.

A consumer MUST ignore members it does not recognize.

| `error` | HTTP | Description |
|---|---|---|
| `invalid_mission_intent` | 400 | Unparseable, structurally invalid, oversized, or containing an undefined top-level member. |
| `invalid_authority` | 400 | Well-formed Intent, but no valid Authority Set is derivable under policy. |
| `invalid_intent_evidence` | 400 | An evidence entry of unsupported type or failing its type's verification, or a policy-required evidence type absent from the submission. |
| `unauthorized` | 401 | Request not authenticated. |
| `not_found` | 404 | A referenced submission or Mission does not exist OR is not visible to the caller. |
| `rate_limited` | 429 | Caller is rate-limited. |
| `unavailable` | 503 | MAS temporarily cannot serve the request. |

This aligns with the OAuth-shaped surfaces' shared error idiom
{{I-D.draft-mcguinness-oauth-mission-status}}: an `error`/
`error_description` JSON object body, `application/json` with
`Cache-Control: no-store`, and `error_description` diagnostic and
never authorization input. This surface's own requiredness stays as
above: `error_description` and `error_reason` are OPTIONAL, and
`error_reason` is MAS-specific. The MAS does not carry `nonce`; that
member's requiredness on the status and lifecycle surfaces
({{I-D.draft-mcguinness-oauth-mission-status}}) and on Mission
Management does not extend here, a deliberate, frozen divergence.

# Mission Approval {#mission-approval}

Approval at a MAS is natively asynchronous: there is no authorization
code ceremony, so no approval blocks a front-channel redirect. The MAS
routes each pending submission to its approval surface (a review
application, queue, or policy engine) and resolves it when the
decision is made.

The approval event executes steps 1 through 4 of the issuance
profile's approval event unchanged
({{I-D.draft-mcguinness-oauth-mission}}):

1. Authenticate the Approver; when the Intent's `controls.acr` is
   present, the authentication MUST be one the deployment's policy
   maps as satisfying the named class (the issuance profile's `acr`
   mapping rule).
2. Establish the Subject under the issuance profile's rules: the MAS
   MUST itself establish the Subject's (`iss`, `sub`) and MUST NOT
   take it from unauthenticated client input.
3. Render the derived Authority Set for consent with the issuance
   profile's rendering rules applied unchanged: client-supplied
   strings inert, direction-override and confusable presentation
   mitigated, derived authority visually distinguished from client
   text.
4. Compute the integrity anchors, `authority_hash`, `intent_hash`,
   and, where an authority proposal was submitted, `proposal_hash`,
   using the issuance profile's envelope with the MAS's issuer URL as
   `iss`.

Step 5 becomes: create the Mission record in the `active` state
atomically with the approval decision. The record is the issuance
profile's Mission Record, member for member; its `issuer` is the MAS's
issuer URL and its `approval_event_id` is the approval idempotency
key. There is no authorization code to bind, so the deferred-approval
profile's re-sequencing of this step
({{I-D.draft-mcguinness-oauth-mission-approval}}) is not needed:
deferral is the MAS's native shape.

A declined submission resolves to `denied`. Mission Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) composes
unchanged: the MAS is the committing issuer for any
consent-disclosure commitment.

# Mission Reference Delivery {#mission-reference}

The client learns its `mission_id` from the submission-status response
after approval. When `status` is `approved`, the response additionally
carries:

`mission_id`:
: REQUIRED. A string. The Mission's identifier.

`mission_expires_at`:
: REQUIRED. A string. The Mission's effective `expires_at`, the
  issuance profile's common Mission-creating response member
  ({{I-D.draft-mcguinness-oauth-mission}}): this response is the
  success response that first delivers the newly created Mission's
  identifier, and no OAuth credential accompanies it here.

`authorization_details`:
: REQUIRED. An array. The consented Authority Set, so the client
  learns its granted authority here; this response is the MAS
  counterpart of the issuance profile's token-response
  `authorization_details` echo.

Example:

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_4qV9rL3tY6sB1zN0eF7jB8K2nP",
  "status": "approved",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "mission_expires_at": "2026-12-31T23:59:59Z",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read", "journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" }
      } }
  ]
}
~~~

`mission_id` remains a reference, never a credential
({{I-D.draft-mcguinness-oauth-mission}}): presenting it authorizes
nothing, and no MAS surface derives authority from possession of it.

# Mission Lifecycle and State {#lifecycle-and-state}

In MAS mode there are no Mission-bound tokens and no token
introspection, so the Mission Status profile's surfaces are the only
way a consumer observes or changes Mission state. A MAS therefore
implements them as its state surface, by reference:

- The MAS MUST serve the Mission Status operation of
  {{I-D.draft-mcguinness-oauth-mission-status}}, including its signed
  responses, authentication, anti-oracle property, and caching rules.
- The MAS MUST serve the Mission Lifecycle endpoint of that profile
  with its full operation set (`revoke`, `suspend`, `resume`, and
  `complete`), following that profile's state machine unchanged. A MAS
  owns its state store, so partial support is not permitted.
- The MAS MAY emit Mission Lifecycle Signals
  ({{I-D.draft-mcguinness-oauth-mission-signals}}), which compose
  unchanged, with the MAS as the transmitting Mission Issuer.

The issuance profile's token-introspection projection does not apply:
there is no token to introspect.

The MAS publishes the corresponding metadata members
(`mission_status_endpoint`,
`mission_status_signing_alg_values_supported`,
`mission_lifecycle_endpoint`, `mission_max_stale_seconds`, and, when
signals are supported, `mission_event_stream_endpoint`) in its
discovery document ({{discovery}}) with the semantics those profiles
define for the members of the same names.

# Mission Expansion and Child Creation {#native-surfaces}

Mission Expansion ({{I-D.draft-mcguinness-oauth-mission-expansion}})
and Mission Child Delegation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) each rest on
one abstract requirement, stated normatively by each of those profiles:
that the requester prove possession of the predecessor or parent
Mission's authority through a sender-constrained proof rather than a
reusable bearer refresh credential. Those profiles bind that
requirement on the OAuth wire to an {{RFC8693}} token exchange whose
`subject_token` is the predecessor or parent Mission-bound access token,
with possession proven against that token's own confirmation key. A MAS
issues no tokens, so that token-exchange binding has no carrier here.
This section defines the peer MAS binding of the same requirement, an
authenticated-client submission on the mission submission endpoint, and
names it as the other binding of that requirement without restating the
requirement itself.

This section defines the MAS-native wire for both operations: carriage
on the mission submission endpoint ({{native-carriage}}) and the
authenticated-client binding in place of the token-exchange possession
proof ({{native-binding}}). It defines carriage and binding only; every
mechanism (supersession, reconciliation, lineage, strict subset,
fan-out, cascade, and the closed code sets) remains owned by its profile
and applies here by reference ({{native-expansion}}, {{native-child}}).
The capability is OPTIONAL ({{conformance}}).

## Submission Carriage {#native-carriage}

The mission submission endpoint carries both operations as intent
submissions ({{intent-submission}}) with additional top-level members
of the request body:

`predecessor`:
: A string. The `mission_id` of the predecessor Mission this
  submission expands; semantics per the expansion profile. Its
  presence marks the submission as an expansion request.

`parent`:
: A string. The `mission_id` of the Parent Mission; semantics per the
  child-delegation profile.

`child_actor`:
: An object identifying the child actor, in the form the
  child-delegation profile defines. The presence of `parent` and
  `child_actor` together marks the submission as a child-creation
  request.

These are submission members, not Mission Intent members: a MAS that
implements this capability MUST remove them before applying the
issuance profile's Intent validation, and the remainder of the body
is the Mission Intent Submission envelope, validated unchanged
({{intent-submission}}). On a
MAS that does not implement this capability they are undefined
top-level members and the submission is refused with
`invalid_mission_intent`, the correct refusal for an unsupported
operation.

A submission carrying both `predecessor` and either child member MUST
be refused with `invalid_mission_intent`: the operations do not
combine. A submission carrying `parent` without `child_actor`, or
`child_actor` without `parent`, MUST be refused the same way.

The OAuth wire's token-exchange possession proof, the predecessor or
parent Mission-bound access token presented as `subject_token`, does
not exist on this surface; the binding of {{native-binding}} replaces
it.

The referenced profiles' OAuth error outcomes map onto this endpoint's
error surface as the issuance profile's do ({{intent-submission}}):
`invalid_request` outcomes map to `invalid_mission_intent`, and
authority-derivation failures to `invalid_authority`. Two rules cover
the outcomes those profiles express as `invalid_grant`:

- A `predecessor` or `parent` the binding does not resolve, whether
  the Mission does not exist or is recorded under another client, MUST
  be refused with `not_found`, with a response identical in both
  cases, preserving the anti-oracle property of {{submission-status}}.
- A reference the binding resolves whose state or serialization
  refuses the operation (the expansion profile's predecessor-active
  and reconciliation rules; the child-delegation profile's
  parent-active rule) MUST be refused with `conflict`, returned with
  HTTP 409. `conflict` extends the error code set of
  {{submission-errors}} and is used only by this section's operations.

The profile-defined machine-readable code rides the MAS error surface
in the member its profile defines: a reconciliation status in
`mission_expansion_status`
({{I-D.draft-mcguinness-oauth-mission-expansion}}) and an adjudication
denial reason, for expansion and child creation alike, in the shared
`mission_denial_reason` member that profile defines
({{I-D.draft-mcguinness-oauth-mission-expansion}},
{{I-D.draft-mcguinness-oauth-mission-child-delegation}}), carried as
a member of the error response body ({{submission-errors}}) or, for a
denial at adjudication, of the `denied` submission-status response
({{submission-status}}).

## Request Binding {#native-binding}

The OAuth wire resolves the predecessor or parent from the Mission-bound
access token presented as the token exchange's `subject_token`, proving
possession against that token's confirmation key, and treats any named
identifier only as a cross-check. A MAS holds no such tokens, so the
named identifier is itself the reference, and the MAS binds the request
to it as follows:

- The MAS MUST verify that the authenticated submitting client is the
  client recorded as the predecessor Mission's `client_id` (for
  expansion) or the Parent Mission's `client_id` (for child creation).
  Both identifiers live in the MAS's own client namespace
  ({{mission-submission}}), so the comparison is ordinarily
  byte-equality; where a deployment maps client identities it MUST
  document the mapping, exactly as the client join requires
  ({{mission-join}}).
- For an expansion, the MAS MUST verify at the approval event that the
  Subject it establishes ({{mission-approval}}) equals the predecessor
  Mission's `subject`; a successor MUST NOT be created for a different
  Subject.

This is an authentication-based binding, not a possession-based one:
it proves the requester is the same registered client the predecessor
or parent was recorded for, not that it holds and can prove possession
of that Mission's access token. The delta from the OAuth wire is
exactly that: a party able to authenticate as the registered client can
request these operations for any of that client's Missions, where the
token-exchange possession proof would limit it to the Missions whose
Mission-bound access token it holds and can prove control of
({{sec-native-binding}}).

Where the deployment authenticates client instances
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}), the MAS
SHOULD bind at instance granularity rather than at the bare
`client_id`, and a Mission Join Assertion for the predecessor or
parent ({{join-assertion}}), presented with the submission,
strengthens the proof to a named runtime instance holding a
sender-constrained credential that verifiably joins to that Mission.

## Expansion Semantics {#native-expansion}

An expansion submission is adjudicated under the expansion profile's
rules ({{I-D.draft-mcguinness-oauth-mission-expansion}}), applied by
reference:

- **Predecessor active.** The predecessor MUST be `active` when the
  submission is accepted, per that profile's predecessor-active rule.
- **Reconciliation.** Concurrent expansions against the same
  predecessor are serialized under that profile's compare-and-set
  reconciliation, and its closed reconciliation-status set applies: a
  refusal at submission carries the code per {{native-carriage}}, and
  a pending submission overtaken by a concurrent expansion resolves to
  `denied` with the code in the status response.
- **Supersession atomicity.** In one atomic operation on the MAS's
  records, the successor activates with its `predecessor` member set,
  and the predecessor transitions to `superseded` with its `successor`
  member set. The `successor` and `related_to` members carry that
  profile's semantics and surface through the MAS's Mission Status
  responses; `superseded` enters the state space the MAS reports
  ({{lifecycle-and-state}}).
- **Denial reasons.** That profile's closed denial-reason set applies;
  the code rides in `mission_denial_reason` per
  {{native-carriage}}.

Approval of the successor is this document's native asynchronous
approval event ({{mission-approval}}): fresh consent for the
successor's derived Authority Set, with no authorization-code leg to
re-sequence. On approval the client's poll delivers the successor's
`mission_id` and consented authority ({{mission-reference}}). The
successor-expiry rule and every other expansion rule that does not
name the OAuth wire apply unchanged. Progressive authorization is out
of scope here exactly as it is out of the expansion profile's base:
every expansion on this surface is adjudicated by a fresh approval,
and the policy-adjudicated variant remains the experimental
companion's ({{I-D.draft-mcguinness-oauth-mission-progressive}}).

## Child-Creation Semantics {#native-child}

A child-creation submission is adjudicated under the child-delegation
profile's rules
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}), applied by
reference:

- **On-switch.** Child creation is permitted only where the applicable
  Parent Mission Authority Set entry's `delegation` member carries a
  `children` object; an entry without one permits no child.
- **Strict subset.** The child Authority Set MUST satisfy that
  profile's strict-subset evaluation against the parent, with no
  relaxation.
- **Fan-out.** Fan-out accounting and its serialization apply
  unchanged: the MAS counts non-terminal Child Missions against
  `max_children` and serializes creation against the same parent entry
  and fan-out bucket.
- **Parent member.** The Child Mission record carries the `parent`
  object constructed per that profile, including `depth`; with no
  token carrier, it surfaces through the record and the MAS's Mission
  Status responses.
- **Cascade.** Cascade applies with one simplification: the MAS owns
  its state store, so cascade transitions are native lifecycle
  transitions on its own records. The MAS implements that profile's
  `immediate` mode, and the `cascaded` state surfaces through Mission
  Status ({{lifecycle-and-state}}).
- **Denial reasons.** That profile's closed denial-reason set applies;
  the code rides in `mission_denial_reason` per {{native-carriage}}.
  The `parent_mismatch` reason has no analog on this surface: with no
  `subject_token` to resolve the parent against a cross-check, a binding
  failure is refused per {{native-carriage}}.

The child client identity rules hold unchanged: the child actor is the
Child Mission's client, recorded as its `client_id`; it authenticates
itself to the MAS for its own submissions, status, and lifecycle
operations; and child credentials MUST NOT transit the parent. The
creating client learns the Child Mission's `mission_id` from its own
submission status; `mission_id` is a reference, never a capability, so
conveying it to the child actor moves no authority. At the point of
use, the Mission Join ({{mission-join}}) binds the child's ordinary
OAuth credentials to the Child Mission through the child's own
`client_id`, never the parent's.

## Expansion Example {#native-example}

Mid-task, the agent behind the Q3 reconciliation Mission finds a
$1,200 adjustment, outside its approved $500 cap. It submits an
expansion: a Mission Intent for the broadened task whose body names
the predecessor:

~~~ http-message
POST /mas/mission/submit HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments under $2,000.",
    "resources": ["https://erp.example.com"],
    "expires_at": "2026-12-31T23:59:59Z"
  },
  "predecessor": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-"
}
~~~

The MAS authenticates the client, verifies it is the predecessor's
recorded `client_id`, verifies the predecessor is `active`, strips
`predecessor`, validates the remaining Submission envelope, derives
the successor's Authority Set, and accepts:

~~~ http-message
HTTP/1.1 202 Accepted
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_7bD1eF4jB0K9wT2xM5nQ8rL3vZ",
  "status": "pending",
  "expires_at": "2026-10-16T15:07:42Z"
}
~~~

Adjudication proceeds per {{mission-approval}}: the Approver consents
to the widened cap, the MAS verifies the established Subject equals
the predecessor's `subject`, and one atomic operation creates the
successor `active` and supersedes the predecessor. The client's next
poll returns `approved` with the successor's `mission_id`
({{mission-reference}}).

# Mission Authority Server Metadata {#discovery}

A MAS publishes a metadata document at the well-known URI {{RFC8615}}
path `/.well-known/mission-authority-server`, registered in {{iana}}:
a JSON object served over TLS as `application/json`. The document's
location is constructed from the `issuer`, following the
metadata-location rule of {{RFC8414}}:

1. For an `issuer` with no path component, the document is served at
   the well-known path under the issuer's host.
2. For an `issuer` that bears a path component, the
   `mission-authority-server` well-known segment is inserted between
   the host and the issuer's path (for `issuer`
   `https://host/tenant`, the document is at
   `https://host/.well-known/mission-authority-server/tenant`).

Its members
mirror the Mission suite's Authorization Server metadata members where
applicable, so a consumer reads the same member names it would read
from AS metadata {{RFC8414}}, resolved from this document instead:

`issuer`:
: REQUIRED. A string. The MAS's issuer URL. It equals the `issuer` of
  every Mission the MAS records and the `iss` of its integrity-anchor
  envelopes and signed status responses. A consumer MUST verify that
  applying the location-construction steps above to this `issuer`
  yields the URL the metadata was resolved from.

`mission_submission_endpoint`:
: REQUIRED. A string containing a URL. The mission submission endpoint
  ({{mission-submission}}).

`mission_status_endpoint`:
: REQUIRED. A string containing a URL. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_status_signing_alg_values_supported`:
: REQUIRED. A JSON array of strings. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_lifecycle_endpoint`:
: REQUIRED. A string containing a URL. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`mission_auth_methods_supported`:
: REQUIRED. A JSON array of strings. The caller authentication
  mechanisms the MAS accepts at the submission, status, and lifecycle
  endpoints, from the mechanism set of
  {{I-D.draft-mcguinness-oauth-mission-status}}. A value naming a
  client authentication method is an entry of the IANA "OAuth Token
  Endpoint Authentication Methods" registry (`tls_client_auth` for
  mTLS, `private_key_jwt`), following the discovery pattern of the
  {{RFC8414}} `*_endpoint_auth_methods_supported` members. The
  DPoP-bound access token mechanism is token presentation rather than
  client authentication, so no registry entry names it; this document
  uses `dpop_bound_token`.

`mission_join_assertion_endpoint`:
: OPTIONAL. A string containing a URL. The join-assertion endpoint
  ({{join-assertion}}). Present when the MAS mints Mission Join
  Assertions.

`mission_event_stream_endpoint`:
: OPTIONAL. A string containing a URL. Present when the MAS supports
  Mission Lifecycle Signals; semantics per
  {{I-D.draft-mcguinness-oauth-mission-signals}}.

`mission_max_stale_seconds`:
: OPTIONAL. An integer. Semantics per
  {{I-D.draft-mcguinness-oauth-mission-status}}.

`jwks_uri`:
: REQUIRED. A string containing a URL. The MAS's JSON Web Key Set:
  the issuer's signing keys, from which consumers resolve the keys
  for Mission Status responses, consent evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), Mission
  Mandates ({{I-D.draft-mcguinness-mission-mandate}}), and other
  issuer-signed artifacts, with the signing-key retention rules of
  {{I-D.draft-mcguinness-oauth-mission-status}}.

Example:

~~~ json
{
  "issuer": "https://mas.example.com",
  "mission_submission_endpoint":
    "https://mas.example.com/mas/mission/submit",
  "mission_status_endpoint":
    "https://mas.example.com/mas/mission/status",
  "mission_status_signing_alg_values_supported": ["ES256"],
  "mission_lifecycle_endpoint":
    "https://mas.example.com/mas/mission/lifecycle",
  "mission_auth_methods_supported":
    ["dpop_bound_token", "private_key_jwt"],
  "mission_join_assertion_endpoint":
    "https://mas.example.com/mas/mission/join-assertion",
  "mission_max_stale_seconds": 60,
  "jwks_uri": "https://mas.example.com/.well-known/jwks.json"
}
~~~

A consumer holding a Mission reference resolves this document from the
reference's `issuer`; whether a given `issuer` is a MAS or an OAuth AS
is deployment configuration. The submission and lifecycle surfaces
follow a reference-plus-continuation shape (a request yields an opaque
reference the client continues against) that parallels the grant
continuation pattern of GNAP {{RFC9635}}.

# Mission Join {#mission-join}

In MAS mode the acting access token is an ordinary OAuth token from
the deployment's unchanged AS: it carries no `mission` claim and no
Mission-derived `authorization_details`, so it cannot identify its
Mission. The PEP names the Mission explicitly, and the PDP joins the
credential to it before evaluating the action. The join is this
profile's load-bearing mechanism: it is what a permit "under this
Mission" rests on when no cryptographic binding exists. This section
defines the baseline mapping join; the Mission Join Assertion
({{join-assertion}}) is the enterprise-mode join built on it. The
Enterprise profile runs two modes: Mission-bound credentials carry
the high-consequence classes, and Join Assertions carry the
externally joined governed paths outside those classes
({{enterprise-profile}}).

The join also has a ceiling no assertion raises: it proves the
credential belongs to the Mission's parties, never that it was
issued for the Mission ({{limitations}}). For the high-consequence
classes, association is therefore not the terminal architecture. The
issuance join ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}})
or native Mission-bound issuance restores cryptographic derivation.
A path claiming the Enterprise profile's high-consequence credential
property MUST use Mission-bound issuance: an acting credential
satisfying the mission-credential-bound composition of the Mission
Binding Properties ({{I-D.draft-mcguinness-mission-architecture}}).
A deployment without it still claims the runtime and join
capabilities its paths actually have, and states the difference in
its Mission Deployment Profile; no `residual_risks` entry buys the
stronger claim, and a Join Assertion cannot satisfy it.

A Mission-joining PDP and its PEPs MUST observe the following:

1. **The PEP supplies the Mission reference.** For governed work the
   PEP MUST supply the `mission_id` and `issuer` of the Mission the
   work is bound to, taken from its Mission binding (a Mission-aware
   harness records exactly this,
   {{I-D.draft-mcguinness-mission-harness}}) or from deployment
   configuration. In the AuthZEN binding
   ({{I-D.draft-mcguinness-mission-authzen}}) this is
   `context.mission`; the PEP populates `authority_hash` and `state`
   from the MAS's signed Mission Status response.
2. **The PDP resolves the Mission at the MAS.** The PDP MUST resolve
   the referenced Mission through the MAS's Mission Status operation
   and MUST treat the MAS as the Mission state source under the
   runtime profile's state and freshness rules
   ({{I-D.draft-mcguinness-mission-runtime}}): fail closed when state
   cannot be established within the published staleness bound, and use
   an active freshness mechanism for the high-consequence classes.
3. **Subject join.** The PDP MUST verify that the presented
   credential's authenticated subject equals the Mission's
   `subject.sub` under the deployment's account mapping. Where the
   credential's issuer and the Mission's `subject.iss` name the same
   namespace, equality is byte-equality; otherwise the deployment MUST
   document the mapping, and a subject the mapping does not cover
   fails the join.
4. **Client join.** The PDP MUST verify that the presented
   credential's authenticated client identifier equals the Mission's
   `client_id`, or names a delegate that deployment policy explicitly
   authorizes to act under that Mission's client. Delegate
   authorization MUST be explicit, an enumerated policy, never a
   default. Where the AS and MAS client namespaces differ, the
   deployment MUST record the client mapping in its mapping contract
   ({{mapping-contract}}), exactly as for subjects.
5. **Delegate narrowing.** When the joined party is a delegate rather
   than the Mission's `client_id`, the PDP MUST narrow the effective
   Authority Set to the delegable subset under the issuance profile's
   per-entry `delegation` rules
   ({{I-D.draft-mcguinness-oauth-mission}}): entries without a
   `delegation` member are excluded, `allowed_delegates` is applied,
   and `max_depth` is evaluated from the deployment's actor records
   rather than from a Mission-bound token's `act` chain.
6. **Join failure is a deny.** A failure of the subject or client join
   MUST be denied with the `mission_mismatch` denial reason: the
   presented credential does not join to the referenced Mission
   because its authenticated subject or client identifier does not
   match the Mission's `subject.sub` or `client_id` under the
   deployment's documented mapping and delegate policy. The PDP MUST
   NOT fall back to evaluating the action against the referenced
   Mission's authority when the join fails.
7. **Authority comes from the Mission.** On a successful join, the PDP
   evaluates the action under the runtime profile's decision contract,
   drawing the Authority Set from the Mission (the audience-scoped
   Mission Status response or a materialized policy view), since the
   credential carries none. All other decision inputs and invariants
   of {{I-D.draft-mcguinness-mission-runtime}} apply unchanged.
8. **The permit intersects three bounds.** A permit under a join never
   exceeds any of three independently evaluated bounds: the authority
   the acting credential itself carries (the token as issued, enforced
   at the Resource Server or gateway), the Mission's approved
   authority, and current Resource policy. The join adds the Mission
   bound; it MUST NOT widen either of the other two, and a PEP MUST
   NOT treat a Mission permit as overriding what the credential or
   the resource would refuse.

In the baseline mapping join the PDP compares the authenticated subject
and client the PEP attests in the decision request, not the acting
credential itself: the PEP authenticates the credential at the
enforcement boundary and populates the decision request from it, and
the PDP neither receives nor inspects the credential. Baseline join
integrity therefore rests wholly within the PEP trust base, and a PEP
that misattests the subject or client widens the join. The
credential-bound join, where the acting token itself is inspected, is
the Mission Join Assertion ({{join-assertion}}), where the MAS resolves
the token centrally and binds its assertion to that token's digest and
key.

The join binds identity, not possession, so the acting credential's
own sender binding is what keeps a joined permit from being a bearer
property. Acting credentials for governed work SHOULD be
sender-constrained, with DPoP or mutual TLS at the unchanged AS. For
the high-consequence action classes they MUST be. With a pure bearer
token, any holder inside the (subject, client) equivalence class
joins ({{join-spoofing}}).

A successful join, in the AuthZEN binding: the PEP supplies
`context.mission` populated from its Mission binding, with
`authority_hash` and `state` taken from the MAS's signed Mission
Status response, and the other decision inputs per
{{I-D.draft-mcguinness-mission-authzen}}:

~~~ json
{
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR",
    "properties": { "iss": "https://idp.example.com" }
  },
  "resource": { "type": "invoice", "id": "inv_2026Q3_842" },
  "action": { "name": "invoices.read" },
  "context": {
    "mission": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://mas.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "state": "active"
    }
  }
}
~~~

The credential's authenticated subject and client match the Mission's
`subject.sub` and `client_id`, so the join holds; the PDP evaluates
the action under the Mission's Authority Set and permits:

~~~ json
{
  "decision": true,
  "context": {
    "decision_id": "dec_7mQ2sV5rL9tY3sB8zN1eF4jB0K",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
    "action_class": "irreversible_action",
    "class_source": "resource_floor",
    "permit_expires_at": "2026-11-02T08:15:30Z"
  }
}
~~~

The AuthZEN profile's denial-reason extensibility rule permits a
companion profile to extend the denial-reason set by specification,
and requires a consumer to treat an unrecognized reason as a deny
({{I-D.draft-mcguinness-mission-authzen}}). `mission_mismatch` and
`mission_reference_conflict` ({{reference-verification}}) are such
extensions: where this profile is implemented, they are members of
that denial-reason set, and neither requires IANA action under the
AuthZEN profile's extension-by-specification model. A consumer that
does not implement this profile treats them as that rule requires:
the action stays refused.

Example AuthZEN denial for a credential whose `client_id` does not
match the referenced Mission:

~~~ json
{
  "decision": false,
  "context": {
    "decision_id": "dec_2nP4qV9rL3tY6sB1zN0eF7jB8K",
    "denial_reason": "mission_mismatch",
    "action_class": "irreversible_action",
    "class_source": "resource_floor",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t"
  }
}
~~~

The join proves that the credential belongs to the same subject and
client the Mission names. It does not prove the credential was derived
under the Mission; no MAS-mode mechanism can, because the AS issues
tokens with no knowledge of Missions ({{limitations}},
{{join-spoofing}}).

A deployment MAY move the join's verification from each PDP to the
MAS with the Mission Join Assertion ({{join-assertion}}). That
upgrade strengthens who verifies the join, not what the join can
prove.

Where the deployment's Authorization Server issues tokens under the
client-instance-assertion profile
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}), the acting
credential identifies a concrete runtime instance: the token's `act`
entry carries the instance `sub` and an instance-specific `cnf` key.
The PDP SHOULD include that instance in the join, so the client join
binds (subject, client, instance) rather than (subject, client). This
restores per-instance granularity behind a shared gateway `client_id`:
the validated instance joins, not every workload in the `client_id`
equivalence class.

# Mission Reference Propagation {#reference-propagation}

The Mission Join consumes a Mission reference the PEP supplies, and
join rule 1 names two sources: the PEP's own recorded Mission binding
and deployment configuration ({{mission-join}}). When the gateway PEP
is not the process that holds the binding (an MCP gateway, an egress
proxy), neither source exists at the enforcement boundary, and
nothing has said how the requesting side names the Mission a given
request runs under. This section defines that channel.

The carried value is an untrusted **Mission-selection assertion**: it
routes the request to a Mission for the join to verify. The Mission
Join verifies the referenced Mission and its subject and client
relationship and supplies the authoritative state and anchors; in the
baseline same-party case neither the carriage nor the join proves
that this particular request was created under that Mission. Who
attached the value is what strengthens attribution: a trusted harness
attaching it from its recorded Mission binding
({{I-D.draft-mcguinness-mission-harness}}) attests more than the
agent naming its own Mission, the deployment's Enforcement Scope
Statement records which party attaches it, and grading what an
established join proves is the join-assurance concern, not this
channel's.

## The Reference Tuple {#reference-tuple}

The propagated value is exactly the Mission reference tuple:
`mission_id` and `issuer`, compared as the canonical (`issuer`,
`mission_id`) pair under the issuance profile's comparison rules
({{I-D.draft-mcguinness-oauth-mission}}). The channel carries nothing
else: state, integrity anchors, authority, and policy data always
come from the MAS's signed Mission Status response
({{submission-status}}), and a request carrying any of them in this
channel MUST be refused, never silently ignored, so ambiguity is
detectable rather than absorbed. The tuple is single-homed: each
carriage below maps this one tuple, and a new carrier profiles it
rather than defining a second.

## HTTP Carriage: Mission-Reference {#mission-reference-field}

`Mission-Reference` is an HTTP request field {{RFC9110}} whose value
is a Structured Fields Dictionary {{RFC9651}} (shown wrapped for
layout; the field is one line):

~~~ http-message
POST /call HTTP/1.1
Host: gateway.example.com
Authorization: Bearer 2YotnFZFEjr1zCsicMWpAA
Mission-Reference: id="msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  issuer="https://mas.example.com"
~~~

- The field is a request header field and MUST NOT be sent as a
  trailer field.
- The value is a Dictionary carrying exactly two members, both
  REQUIRED: `id`, a String carrying the Mission identifier, and
  `issuer`, a String carrying the exact issuer identifier the MAS
  publishes in its metadata ({{discovery}}). A MAS participating in
  this profile MUST publish an ASCII issuer identifier (Structured
  Field Strings are ASCII); the sender copies that published string
  with no URI normalization of any kind, and equality is byte
  equality of the exact string.
- A sender MUST NOT emit an `id` longer than 256 characters or an
  `issuer` longer than 512 characters; a receiver MUST treat a longer
  value as malformed.
- {{RFC9651}} parsing keeps the last of duplicate Dictionary keys, so
  parse success alone is not enough. A receiver MUST reject as
  malformed, before map collapse: a duplicate `id` or `issuer`
  occurrence, a parameter on either member, an Inner List or any
  non-String value, and any member other than the two defined here.
  A profile the deployment adopts MAY define an additional member by
  specification; a receiver MUST NOT act on a member it does not
  implement.
- A sender MUST send exactly one field line. Field lines that do not
  combine into exactly one Dictionary satisfying every rule above, or
  any parse failure, make the reference malformed.
- A malformed, missing, or stripped reference fails closed wherever
  Mission governance is required: governed work with no establishable
  Mission reference is refused before evaluation, per the runtime
  profile's preconditions
  ({{I-D.draft-mcguinness-mission-runtime}}).

## MCP Carriage {#mcp-reference}

For a tool call governed through MCP, the reference rides the
request's `params._meta` object on each `tools/call`, never tool
arguments and never session state, under the key
`com.karlmcguinness.mission/reference`, a reverse-DNS-prefixed key in
a namespace this family's author controls, per the pinned MCP
revision's `_meta` rules ({{MCP-META}}; MCP reserves its own `_meta`
prefixes):

~~~ json
{
  "method": "tools/call",
  "params": {
    "name": "post_journal_entry",
    "arguments": { "amount": "500.00", "currency": "USD" },
    "_meta": {
      "com.karlmcguinness.mission/reference": {
        "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
        "issuer": "https://mas.example.com"
      }
    }
  }
}
~~~

The value carries exactly `mission_id` and `issuer`, with the tuple
semantics of {{reference-tuple}} unchanged. The value object is
closed the same way as the HTTP field: a receiver MUST reject
duplicate JSON member names at parse time, a member other than
`mission_id` and `issuer`, a non-string member value, and the
propagation key appearing more than once in `_meta`. Unknown `_meta` keys are
extensible metadata an ordinary MCP server may ignore; a server that
silently ignores this key is not a conforming Mission PEP. Where a
tool is governed as Mission-required, absent negotiated or configured
propagation support the call MUST be refused, never run as ordinary
ungoverned execution. A future MCP extension or capability mechanism
may supersede this carriage; the tuple's semantics stay this
section's.

## Verification and Conflict {#reference-verification}

- The value is a selection assertion, never authority: its presence
  or content grants nothing, the Mission is established only through
  the Mission Join ({{mission-join}}), and an unverified reference
  MUST NOT establish the Mission, the runtime profile's
  externally-established rule
  ({{I-D.draft-mcguinness-mission-runtime}}).
- Where the acting credential carries a `mission` claim, the
  credential-carried reference governs, and a propagated reference
  naming a different Mission is a deny.
- Where the PEP's own binding source (a harness-recorded binding,
  deployment configuration) names a different Mission than the
  propagated reference, the conflict is a deny, never a silent
  pick-one.
- An attribution conflict, or a malformed reference where governance
  requires one, is denied with the `mission_reference_conflict`
  denial reason, a member this profile adds to the AuthZEN
  denial-reason set under its extensibility rule beside
  `mission_mismatch` ({{mission-join}}): `mission_mismatch` stays the
  subject-or-client join failure, and `mission_reference_conflict` is
  reference sources naming different Missions or an unusable
  reference.
- The selection assertion applies only to the request it accompanies:
  it selects the Mission the join is evaluated against, and does not
  by itself establish request provenance or attribution.
  Session-scoped stickiness is a deployment choice recorded in the
  Enforcement Scope Statement, and per-request carriage is required
  wherever the runtime profile requires per-action evaluation.
- The field rides the deployment's TLS, which authenticates the
  channel endpoint, never which component attached the value:
  transport protection does not upgrade self-asserted attribution.
  Where HTTP Message Signatures {{RFC9421}} are deployed on the
  request, the signature MUST cover `Mission-Reference`.

Example denial for a propagated reference conflicting with the PEP's
recorded binding:

~~~ json
{
  "decision": false,
  "context": {
    "decision_id": "dec_2nP4qV9rL3tY6sB1zN0eF7jB8K",
    "denial_reason": "mission_reference_conflict"
  }
}
~~~

## Forwarding and Privacy {#reference-forwarding}

The tuple is a stable correlator and lands in gateway logs. An
intermediary MUST NOT copy the field or the `_meta` key onto a
request to an unrelated authority domain, and a terminating PEP
SHOULD remove it before forwarding unless the downstream recipient
participates in the same verified binding. The issuance profile's
Mission Identifier correlation considerations apply to logged
values.

# Mission Join Assertion {#join-assertion}

The Mission Join of {{mission-join}} rests on subject and client
mapping tables that every PDP operates and keeps correct. This section
defines an OPTIONAL upgrade from mapping-table equality to a
credential-bound proof: the MAS verifies the join centrally and mints
a signed assertion of it, so the PDP verifies one signature and one
token binding instead of operating a mapping table. A MAS that
supports the upgrade publishes its join-assertion endpoint as
`mission_join_assertion_endpoint` ({{discovery}}). The endpoint MUST
meet the TLS and caller-authentication requirements of the mission
submission endpoint ({{mission-submission}}).

## Assertion Request {#join-assertion-request}

The PEP, or the client acting for it, POSTs a JSON object:

`mission_id`:
: REQUIRED. A string. The Mission the join is asserted against; its
  `issuer` is the MAS.

`access_token`:
: A string. The acting access token. REQUIRED unless the digest pair
  is present.

`token_sha256`:
: A string. The unpadded base64url SHA-256 digest of the access
  token's ASCII bytes. This is a member-named digest construction
  outside the default prefixed form: the member name fixes the
  algorithm, and a successor algorithm enters as a new member, never
  by reinterpreting this one.

`token_jkt`:
: A string. The JWK thumbprint {{RFC7638}}, using SHA-256, of the
  token's `cnf` public key.

The caller presents `access_token`, or `token_sha256` together with
`token_jkt`. The digest pair keeps the credential itself off this
wire, but it is usable only where the deployment's introspection
surface can resolve a token by digest; `access_token` is the
interoperable form.

The acting token MUST be sender-constrained. The MAS MUST NOT mint an
assertion for a token without a `cnf` key: such a token gives the
assertion nothing to bind.

The MAS verifies the join centrally:

1. It establishes the acting token's validity, subject, and client.
   Where the AS offers token introspection {{RFC7662}}, the MAS
   introspects the token under introspection credentials it holds
   there, and a token the AS reports inactive fails the request. Where
   the AS offers no third-party introspection but issues JWT access
   tokens, the MAS MAY instead validate the token locally under RFC
   9068 {{RFC9068}} semantics, resolving the AS's signing keys from its
   published metadata and taking the subject and client from the
   validated claims; a token that fails signature, `exp`, or `aud`
   validation fails the request. An opaque token that no introspection
   surface will resolve cannot be verified, and the request fails.
   Calling the AS is permitted in MAS mode; changing it is not.
2. It verifies the subject and client joins of {{mission-join}}
   against the introspection response or the validated token claims,
   under its own documented account and client mappings and delegate
   policy.

A token that does not join is refused with the `join_failed` error
(HTTP 403), in the error format of {{submission-errors}}; like
`conflict`, it extends that section's error code set. An unknown
or not-visible `mission_id` returns `not_found`, preserving the
anti-oracle property.

Visibility on this endpoint is bounded: a Mission is visible to its
`client_id`, its recorded delegates, and the PEPs and PDPs enrolled
for the Mission's enforcement scope. Any other caller MUST receive
`not_found`, so the `join_failed` (403) and `not_found` (404) split
never acts as a mapping oracle for callers outside that set.

Assertion lifetime is capped by the token's, so short token lifetimes
put minting on the rotation path: each rotation needs a fresh
assertion and its introspection call, per Mission and per workload. A
deployment amortizes deliberately: it sizes agent token lifetimes to
the runtime layer's revocation cutoff rather than treating expiry as
the kill switch (the token-lifetime trade of
{{I-D.draft-mcguinness-mission-runtime}}). The MAS MAY reuse an
introspection result across mintings of the same token within the
deployment's staleness bound, so re-minting for an unchanged token
does not repeat the AS round trip.

That same position makes minting a denial-of-service surface: it is a
hot, per-action-adjacent path, invoked on every rotation for every
Mission and workload the MAS serves. The MAS MUST rate-limit
assertion requests per caller. The MAS SHOULD serve repeated requests
for the same (token digest, audience) pair from cache within the
assertion's lifetime, so a burst of re-mints for an unchanged token
costs one evaluation rather than many.

## The Assertion {#join-assertion-artifact}

On success the MAS mints a Mission Join Assertion: a signed JWT
{{RFC7519}} whose protected header carries the `typ`
`mission-join+jwt` and a `kid` resolvable in the MAS's `jwks_uri`;
exact validation of that `typ`, with mutually exclusive validation
rules for the artifact profiles, implements the substitution defense
of {{RFC8725}}, Sections 3.11 and 3.12. Its
claims:

`iss`:
: REQUIRED. The MAS's issuer URL.

`mission`:
: REQUIRED. An object containing `id`, `issuer`, and
  `authority_hash`.

`token`:
: REQUIRED. An object containing `sha256`, the token digest as in
  {{join-assertion-request}}, and `jkt`, the thumbprint of the token's
  `cnf` public key {{RFC7638}}.

`iat`:
: REQUIRED. Issuance time.

`exp`:
: REQUIRED. Expiry. It MUST NOT exceed the access token's remaining
  lifetime.

`aud`:
: RECOMMENDED. The PDP or PDPs the assertion is minted for; audience
  scoping prevents replay of an assertion to a consumer it was not
  minted for.

`mapping_version`:
: OPTIONAL. A string. The mapping contract version
  ({{mapping-contract}}) under which the subject and client joins
  were evaluated. RECOMMENDED where the MAS publishes a mapping
  contract, so each join is attributable to the mapping that
  produced it.

When the introspected token carries instance identity
({{I-D.draft-mcguinness-oauth-client-instance-assertion}}), the MAS
SHOULD include the instance identifier in the `token` object: the
`act` entry's `sub`, and the `agent_instance_id` where the agent
profile ({{I-D.draft-mcguinness-oauth-ai-agent-instance}}) is in use.
Under that profile the `cnf` key the `jkt` thumbprint binds is
instance-specific, never shared across a client's instances, so the
assertion's token binding is materially stronger: it names one runtime
instance, not any holder of a client-shared key.

The endpoint returns HTTP 200 with a JSON object whose `assertion`
member carries the JWT. Each minting is a join evidence event: the MAS
records the Mission reference, the token digest and thumbprint, the
authenticated caller, the mapping version where one is published
({{mapping-contract}}), and the validity window, retained for the
audit horizon.

Example claims:

~~~ json
{
  "iss": "https://mas.example.com",
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "issuer": "https://mas.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ"
  },
  "token": {
    "sha256": "rN2kQ4mZ7tP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2n",
    "jkt": "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
  },
  "iat": 1793606400,
  "exp": 1793608200
}
~~~

## PDP Consumption {#join-assertion-pdp}

A PDP presented with a Join Assertion verifies, in place of the
mapping checks of {{mission-join}} steps 3 and 4:

- the signature, under a key from the MAS's `jwks_uri`, and the
  `mission-join+jwt` header `typ`;
- that `iss` and the `mission` claim match the referenced Mission's
  `issuer`, `id`, and `authority_hash`;
- that `exp` has not passed and any `aud` names this PDP; and
- the token binding: the presented credential's digest equals
  `token.sha256` and its `cnf` key's thumbprint equals `token.jkt`.

Every other join rule holds unchanged: the PDP resolves Mission state
at the MAS under the runtime profile's freshness rules, denies with
`mission_mismatch` when any check above fails, and draws authority
from the Mission.

For the high-consequence action classes
({{I-D.draft-mcguinness-mission-runtime}}) in MAS mode, the
Enterprise profile requires Mission-bound issuance for the acting
credential ({{enterprise-profile}}); a Join Assertion strengthens
every joined path outside those classes and remains required there
under that profile. The mapping join of {{mission-join}} remains
the conformance floor: a deployment without the endpoint still joins,
and a PDP MUST NOT treat possession of an assertion as authority,
per the family rule that references and binding proofs grant nothing.

# Limitations {#limitations}

This section states what MAS-only deployment does not provide. These
are structural properties of the mode, not implementation quality
issues, and a deployment claiming this profile MUST NOT overstate
them. The mode provides the contextual-governance kernel,
State-Observable, and Structured Authority capabilities, but it does
not claim that an unchanged Authorization Server's credential was
issued under the Mission or that its issuance was lifecycle-gated.
Credential-Bound correlation and action-time lifecycle gating compose
through the runtime join and PEP coverage, within the conditional scope
declared by {{mission-substrate}}. Among the Mission Assurance Levels
this is the Runtime-Enforced level reached
through the MAS binding, which provides no Mission-bound credential
and no issuance gating
({{I-D.draft-mcguinness-mission-architecture}}).

A deployment claiming this profile MUST state, alongside its
Enforcement Scope Statement:

- what the join proves (that the credential belongs to the Mission's
  subject and client) and what it does not (that the credential was
  issued under the Mission);
- the subject and client mapping granularity, and whether instance
  identity is included in the join
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}});
- whether Mission Join Assertions are required, which the Enterprise
  profile requires on joined, PDP-gated paths outside the
  irreversible, external-commitment, and privileged-administration
  classes, the classes it reserves for Mission-bound issuance
  ({{join-assertion}}, {{enterprise-profile}}); and
- which action paths are covered by runtime enforcement, since nothing
  at the token layer covers the rest.

An enterprise deployment carries this statement inside its mapping
contract ({{mapping-contract}}) rather than beside it, so the join's
facts have one home.

**No Mission-bound credentials.** Tokens carry no `mission` claim and
no Mission-derived `authorization_details`. Nothing cryptographically
binds a token to the approval event, and no audit anchor travels in
credentials: `authority_hash` reaches consumers only through the MAS's
signed status responses and the PDP's evidence, never in the
credential a resource actually accepted. Resource Servers cannot
enforce Mission authority statelessly from the token.

**No issuance gating.** The AS issues and refreshes tokens with no
knowledge of Mission state. Revoking a Mission stops nothing at the
token layer: every outstanding token, and every token the AS issues
after revocation, remains valid OAuth. The Mission kill switch acts
only through the runtime layer's state re-check.

A MAS deployment MUST deploy the runtime profile's enforcement
({{I-D.draft-mcguinness-mission-runtime}}) over every consequential
action path within the scope it claims Mission governance for.
Because both properties are absent, enforcement rests entirely on PEP
coverage: the no-unmediated-path condition consolidated by the
security model ({{I-D.draft-mcguinness-mission-security-model}}) is
load-bearing for all of this profile's guarantees, not only for the
runtime profile's agent-compromise-resistant enforcement claim. A
token exercised outside PEP coverage is ungoverned: its use is
bounded by ordinary OAuth alone, and no Mission property applies to
it.

**Weaker expansion and child-creation binding.** Mission Expansion
and Child Delegation are carried natively in this mode
({{native-surfaces}}), so a standalone deployment can widen authority
and delegate to sub-agents; what the mode does not provide is the
OAuth wire's token-exchange possession proof. Requests are bound to the
predecessor or parent by authenticated client identity
({{native-binding}}), which proves the same registered client, not
possession of a held Mission-bound access token
({{sec-native-binding}}). Offline attenuation remains inapplicable in
this mode because it requires the Mission-bound credential
({{mission-substrate}}).

**Upgrade path.** Implementing the issuance profile at the AS restores
what this mode lacks: Mission-bound credentials and issuance gating.
The MAS then serves as the AS's Mission store, or merges into the AS.
The Mission record, the integrity anchors, and the lifecycle carry
over unchanged, because a MAS operates the issuance profile's own
definitions of all three; the enforcement join becomes unnecessary for
newly issued tokens, which carry the `mission` claim.

These are the limitations of MAS-only deployment. The Mission
Issuance Grant companion
({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) defines the
issuance join: a grant this MAS mints for an active Mission and an
estate Authorization Server redeems at its token endpoint for
Mission-bound tokens, state-gated at minting and at refresh. Where
deployed, it removes the credential and issuance-gating limitations
for the resources of each consuming Authorization Server, while
approval, the record, and the lifecycle remain here.

# The Enterprise Mission Authority Profile {#enterprise-profile}

The conformance floor ({{conformance}}) makes a MAS deployable. This
profile is the operating profile for a MAS used as an estate's
Mission control plane: it turns the floor's SHOULDs and OPTIONALs
into the guarantees an enterprise deployment needs. A deployment
claims the Enterprise Mission Authority Profile over a declared
coverage set: the Authorization Server, resource, and action-class
paths the claim names. The estate-level obligations below hold
deployment-wide; the per-path credential, join, and runtime
obligations hold for every path in the set; a path outside the set
is explicitly unclaimed, and never inherits the profile from the
deployment's name. The profile is the Runtime-Enforced level of the
Mission Assurance Levels under the MAS binding, with the obligations
below ({{I-D.draft-mcguinness-mission-architecture}}).

- **Status and lifecycle.** The MAS MUST serve the Mission Status
  operation and the Mission Lifecycle endpoint with signed responses
  ({{lifecycle-and-state}}), so state and the kill switch are
  available estate-wide.
- **Active freshness.** For the high-consequence action classes, the
  MAS-served state MUST be an active freshness source with a published
  staleness bound, meeting the runtime profile's requirement for those
  classes ({{I-D.draft-mcguinness-mission-runtime}}); token-lifetime
  expiry alone does not qualify. Where per-class bounds differ, the
  metadata's single `mission_max_stale_seconds` ({{discovery}})
  advertises the tightest bound in force, the value a consumer may
  assume without knowing an action's class; the per-class bounds are
  published in the Enforcement Scope Statement.
- **Join Assertion.** The MAS MUST offer the Mission Join Assertion
  ({{join-assertion}}). For every joined, PDP-gated governed path not
  classified as irreversible, external commitment, or privileged
  administration ({{I-D.draft-mcguinness-mission-runtime}}), the PDP
  MUST require one.
- **Mission-bound issuance for the high-consequence classes.** For
  the high-consequence action classes
  ({{I-D.draft-mcguinness-mission-runtime}}) the PDP MUST require an
  acting credential satisfying the mission-credential-bound
  composition of the Mission Binding Properties
  ({{I-D.draft-mcguinness-mission-architecture}}): the
  credential-mission-bound equivalence plus presenter-key-bound
  possession, end to end; a Join Assertion does not satisfy it, and
  absence denies rather than falling back to a mapping or asserted
  join. Where the Mission Issuance Grant
  ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}) is the
  issuance path for such a class, the grant MUST carry `cnf` and
  redemption MUST produce an access token sender-constrained to that
  same key: the issuance upgrade opens no bearer interval between
  grant and action, and this profile defines no rotation exception. Mission-bound issuance restores the
  issuance gate; it does not replace this profile's runtime
  active-freshness check for these classes. Issuance also does not
  prove that a particular work item was supposed to run under the
  selected Mission when a client legitimately holds credentials for
  several Missions: work-item attribution stays with the reference
  propagation channel and the `work-item-bound` property. The
  Enterprise claim is made per covered Authorization Server,
  resource, and action path; a mixed estate's weaker paths never
  inherit it from the deployment's name.
- **Instance-bound joins.** Where the acting credential carries a
  client-instance identity
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}}), a
  high-consequence join MUST bind (`subject`, `client`, `instance`),
  not (`subject`, `client`), so a single workload joins rather than
  every workload sharing a gateway `client_id`. Client-instance
  identity rests on an unratified individual draft
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}}); where a
  deployment has no instance-identity substrate, the high-consequence
  join binds only (`subject`, `client`), and the shared-`client_id`
  residual of {{join-spoofing}} remains, stated in the Mission
  Deployment Profile's `residual_risks`.
- **Runtime enforcement.** Consequential actions MUST be enforced
  under the runtime profile and its AuthZEN binding
  ({{I-D.draft-mcguinness-mission-authzen}}), with documented PEP
  coverage published in the runtime profile's Enforcement Scope
  Statement.
- **Audit evidence.** Joins and decisions MUST produce runtime
  evidence retained for the audit horizon
  ({{I-D.draft-mcguinness-mission-runtime}}).
- **Approval governance.** Where a recording trigger of Mission
  Approval Governance holds for an approval event (the Approver
  differs from the Subject, more than one principal contributes, a
  non-human assertion contributes, a threshold, veto, or
  separation-of-duty rule is evaluated, or validating an assertion
  requires authority standing outside the Mission record), the MAS
  MUST record the Approval Governance Record
  ({{I-D.draft-mcguinness-mission-approval-governance}}), committed
  atomically with the Mission's creation and retained for its audit
  horizon. The Mission record still carries exactly one accountable
  `approver`, the only principal any projection or enforcement
  consumes; direct self-approval by one authenticated human stays the
  degenerate case the Mission record represents completely.

The Join Assertion obligation is what separates the modes: the
mapping join ({{mission-join}}) is the baseline compatibility mode,
and the Join Assertion is the enterprise mode, because it centralizes
subject and client mapping at the MAS, binds the proof to one token
digest and key thumbprint, and produces audit evidence rather than
leaving each PDP to maintain mapping tables.

A deployment claiming this profile SHOULD publish its claims,
coverage, and residual risks as a Mission Deployment Profile
({{I-D.draft-mcguinness-mission-architecture}}).

## High-Consequence Binding {#high-consequence-binding}

The two binding-establishment modes are mutually exclusive per
action, as the runtime profile fixes
({{I-D.draft-mcguinness-mission-runtime}}), and a high-consequence
path switches modes rather than layering them: the join algorithm of
{{mission-join}} assumes a credential that cannot identify its
Mission, and it never runs against one that can. For each action the
PDP:

1. classifies the action under the runtime profile's classes;
2. for a high-consequence path in the declared coverage set, requires
   and validates a Mission-bound acting credential per the issuance
   obligation above; a mapping or asserted join never substitutes;
3. establishes the Mission from that credential's authenticated
   `mission` claim, never from an external selection;
4. where a propagated Mission-Reference is also present, requires
   exact equality of its issuer and Mission identifier with the
   credential's `mission` claim and a consistent `authority_hash`,
   and denies on any mismatch;
5. applies current Mission state, current authority, the subject,
   client, and actor checks, and the sender proof, as elsewhere in
   this profile; and
6. never uses a Join Assertion or a mapping join to select a
   different Mission than the credential's own: with concurrent
   Missions for one subject and client, the credential's `mission`
   claim is the binding, and nothing re-points it.

## Estate Prerequisites {#enterprise-prerequisites}

The profile's mandatory path runs through the deployment's unchanged
Authorization Server, and it assumes capabilities there:
configuration rather than code, but gating nonetheless. Before
claiming the profile a deployment confirms its estate AS provides:

- **Token introspection.** {{RFC7662}} introspection reachable by the
  MAS, under credentials the deployment protects
  ({{sec-join-assertion}}); the MAS cannot mint a Join Assertion
  without it ({{join-assertion-request}}).
- **Sender-constrained issuance.** DPoP-bound or mutual-TLS-bound
  access tokens for the agent clients acting in the high-consequence
  classes: the join requires sender-constraint for those classes
  ({{mission-join}}), and the MAS MUST NOT mint an assertion for a
  token without a `cnf` key ({{join-assertion-request}}).
- **`cnf` in introspection.** Introspection responses that report the
  token's `cnf` confirmation, since the assertion binds the key
  thumbprint that response reports.

An estate whose Authorization Server cannot provide these still
joins under the mapping join at the conformance floor
({{mission-join}}, {{conformance}}); it does not claim this profile.
The digest pair of {{join-assertion-request}} further assumes an
introspection surface that resolves a token by digest, which
mainstream Authorization Servers do not provide; a deployment plans
for the `access_token` form.

## The Enterprise Mapping Contract {#mapping-contract}

The dominant MAS risk is a coarse or drifting join: shared
`client_id` values, many-to-one directory mappings, and workload
identity that the join collapses ({{join-spoofing}}). An enterprise
MAS MUST publish a mapping contract stating, for the joins it
performs:

- the subject namespace mapping (how a credential's authenticated
  subject maps to the Mission's `subject`);
- the client namespace mapping (how a credential's client maps to the
  Mission's `client_id`);
- the delegate policy applied to `act`-chain actors, which MUST state
  how the issuance profile's per-entry `delegation` rules are
  evaluated at the join;
- whether client-instance identity is supported and required;
- a mapping version identifier, so a mapping change is detectable;
- an audit record for each mapping decision; and
- the failure semantics, which MUST fail closed with `mission_mismatch`
  on any unresolved or ambiguous mapping.

A MAS that mints Join Assertions SHOULD carry the version in each
assertion's `mapping_version` claim ({{join-assertion-artifact}}), so
a mapping change is attributable in join evidence, not only
detectable in documents.

## Policy View Distribution {#policy-distribution}

An enterprise MAS MAY serve audience-scoped Authority Set views, or
the runtime profile's materialized policy view
({{I-D.draft-mcguinness-mission-runtime}}), to the PDPs that enforce
for each audience, rather than each PDP resolving full Mission state
per action. This is what makes the MAS the estate's approved-task
authority distribution point: it distributes bounded, audience-scoped
authority derived from the Mission, not tokens. The view is served
under the Mission Status operation's authentication and anti-oracle
rules, carries the Mission's `authority_hash` as its consent anchor,
and does not widen authority beyond the Authority Set.

# Deployment {#deployment}

This section is non-normative. It shows where a MAS lands in a real
estate and how a deployment adopts it incrementally.

## Topology {#deployment-topology}

A typical MAS deployment runs the MAS beside the existing identity
provider and Authorization Server, changing neither:

- the MAS records Missions, runs approvals, operates the lifecycle,
  and signs Mission Status;
- a PEP at the enforcement boundary (an API gateway, a service-mesh
  sidecar, an MCP or tool gateway, a SaaS connector, a workflow
  orchestrator, or a legacy-API wrapper) presents the Mission
  reference and calls a PDP before each consequential action;
- the PDP runs the runtime profile's decision contract and its
  AuthZEN binding, drawing authority from the MAS-served Authority Set
  or a materialized policy view ({{policy-distribution}});
- the MAS mints a Join Assertion after introspecting the presented
  token, so the PDP verifies one signed proof rather than a mapping
  table; and
- runtime decision and execution evidence flows to the deployment's
  audit sink.

Which Mission Issuer governs a given resource is deployment
configuration the estate makes explicit: where more than one Mission
Issuer operates, the deployment documents the resource-to-issuer
mapping alongside its mapping contract, and a PEP treats a resource
with no mapped issuer as outside this profile's governance rather
than inventing one.

## Connector Patterns {#deployment-connectors}

The PEP is wherever consequential effects can be refused before they
happen. Common placements, all non-normative:

- **API gateway PEP**: refuses at the gateway in front of a protected
  API.
- **Service-mesh sidecar PEP**: refuses at the sidecar for
  service-to-service calls.
- **SaaS connector PEP**: refuses in the connector mediating a SaaS
  API.
- **MCP or tool-server PEP**: refuses at the tool boundary an agent
  invokes.
- **Workflow or orchestrator PEP**: refuses at the step boundary of a
  governed workflow.
- **Legacy-API wrapper PEP**: refuses in a wrapper fronting a system
  that cannot itself enforce.

Each is credible only to the extent it has no unmediated bypass; the
runtime profile's Enforcement Scope Statement is where that coverage
is stated ({{I-D.draft-mcguinness-mission-runtime}}).

## Progressive Adoption {#deployment-adoption}

A MAS is adopted level by level across the Mission Assurance Levels
({{I-D.draft-mcguinness-mission-architecture}}), each phase
independently useful. The six phases group into three modes, and a
deployment's claim is bounded by its mode: **records mode** (phases
1 and 2) is inventory, approval, lifecycle, and audit, with no
prevention claim of any kind; **enforced-paths mode** (phases 3 and
4) prevents on exactly the paths the Enforcement Scope Statement
enumerates and is records mode everywhere else; **issuance mode**
(phases 5 and 6) restores the token-layer gate. "No AS code change"
holds in every mode; what changes is the claim, and a
high-consequence enforcement claim requires issuance mode's
machinery or the Estate Prerequisites' AS features
({{enterprise-prerequisites}}), never records alone:

1. The MAS records Missions and approvals: governance and audit of
   what tasks were approved, with no enforcement change yet
   (Baseline Issuance under the MAS binding: governance and audit,
   without the level's issuance-gate kill switch; phase 2 supplies
   the state-based cutoff).
2. Mission Status and lifecycle become the estate-wide kill switch:
   consumers fail safe on non-`active` state (the state-aware
   half-step).
3. PEP/PDP runtime enforcement gates consequential actions per the
   runtime profile (the Runtime-Enforced level).
4. Join Assertions and instance-bound joins harden the join for the
   high-consequence classes (the Enterprise profile,
   {{enterprise-profile}}).
5. Estate Authorization Servers adopt the issuance join
   ({{I-D.draft-mcguinness-oauth-mission-issuance-grant}}), redeeming
   MAS-minted grants for Mission-bound, state-gated tokens: the
   token-layer kill switch returns without moving approval into the
   AS.
6. Where a particular AS later becomes natively Mission-aware, it
   adds the core's own issuance for its resources, while the MAS
   record, lifecycle, and authority model continue to govern the
   rest of the estate.

A deployment stops at the phase its risk warrants; nothing above the
floor is required to begin, and the MAS remains the enduring control
plane of the family's delegated-authority layer
({{I-D.draft-mcguinness-mission-architecture}}) even as individual
Authorization Servers become Mission-aware.

The common starting estate runs bots on standing service accounts
with broad, durable entitlements. The migration is per task, not per
account: each recurring job becomes a durable Mission whose Authority
Set is derived from the entitlements the job actually exercises, with
the deployment's entitlement catalog as the derivation policy's
input; the service account retains only what no Mission yet governs,
and that shrinking residue is the adoption metric.

# Conformance {#conformance}

An implementation conforms in one of two roles.

A **Mission Authority Server**:

- serves the mission submission endpoint with the validation,
  media-type dispatch, error, and anti-oracle rules of
  {{mission-submission}};
- executes the approval event of {{mission-approval}}, creating the
  Mission record `active` atomically with the approval decision;
- records Missions per the issuance profile's Mission Record section
  and retains each record for the audit horizon;
- serves the Mission Status operation and the Mission Lifecycle
  endpoint with its full operation set (`revoke`, `suspend`, `resume`,
  `complete`) per {{lifecycle-and-state}};
- publishes the discovery document of {{discovery}} with every
  REQUIRED member; and
- issues no token and no artifact that grants access by possession:
  `submission_id` and `mission_id` are references.

**Expansion and Child Creation** ({{native-surfaces}}) is a named
OPTIONAL capability of the Mission Authority Server role. A MAS
claiming it additionally:

- accepts the `predecessor`, `parent`, and `child_actor` submission
  members, with the dispatch and refusal rules of {{native-carriage}};
- verifies the binding of {{native-binding}} before adjudicating: the
  authenticated submitting client equals the predecessor's or parent's
  recorded `client_id`, and, for expansion, the established Subject
  equals the predecessor's `subject`;
- applies the expansion profile's rules by reference: predecessor
  active, reconciliation serialization, supersession atomicity, and
  the lineage members ({{native-expansion}});
- applies the child-delegation profile's rules by reference: the
  `children` on-switch, strict subset, fan-out accounting, `parent`
  construction, cascade, and child client identity ({{native-child}});
  and
- carries the profiles' closed code sets, reconciliation statuses in
  `mission_expansion_status` and adjudication denial reasons in the
  shared `mission_denial_reason` member, on its error and
  submission-status surfaces ({{native-carriage}}).

A **Mission-joining PDP**:

- resolves referenced Missions at the MAS through the Mission Status
  operation and treats the MAS as its Mission state source under the
  runtime profile's freshness rules ({{mission-join}});
- verifies the subject join and the client join before evaluating
  authority, and denies with `mission_mismatch` on any join failure;
- for a high-consequence path under the Enterprise profile, requires
  the mission-credential-bound acting credential and denies on its
  absence, never falling back to a mapping or asserted join
  ({{enterprise-profile}});
- evaluates joined actions under the runtime profile's decision
  contract, drawing authority from the Mission; and
- when the AuthZEN binding is in use, emits Decision Evidence per
  {{I-D.draft-mcguinness-mission-runtime-evidence}}, recording the
  Mission reference the join was verified against.

# Security Considerations

## Join Spoofing {#join-spoofing}

A client cannot gain authority by asserting another party's
`mission_id`: the join requires the subject and client the PEP
authenticates from the credential to match values the MAS recorded at
approval, which the client cannot alter, so a reference to someone
else's Mission fails with `mission_mismatch`. Three residuals remain:

- **Mapping coarseness.** Where the deployment's account mapping is
  many-to-one (several AS accounts map to one directory subject), any
  credential in the equivalence class joins; a deployment SHOULD keep
  the mapping one-to-one for subjects that hold Missions, with the
  granularity recorded in its mapping contract ({{mapping-contract}}).
  The client join is coarse the same way where several workloads share
  one `client_id`: any of them joins. Client instance assertions
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}}) are the
  standard fix: the join then binds the validated instance
  ({{mission-join}}), and this residual remains only for deployments
  without instance identity.
- **Same-party misattribution.** Two Missions held by the same subject
  and client are distinguished only by the PEP-supplied reference, so
  a faulty or compromised PEP can attribute work to the wrong
  same-party Mission, bounded by that Mission's authority and visible
  in evidence.
- **Bearer possession.** With a pure bearer token, possession alone
  presents the credential, so any holder inside the (subject, client)
  equivalence class joins, which is why {{mission-join}} requires
  sender-constraint for the high-consequence classes.
- **Same-party self-selection.** The propagation channel
  ({{reference-propagation}}) lets the requesting side name the
  Mission, so an agent whose subject and client join more than one
  active Mission chooses which one a request runs under: a
  confused-deputy shape (least-restrictive-Mission selection), not
  merely spoofing. The join bounds the choice to Missions whose
  parties match, each chosen Mission's own authority bounds what the
  choice yields, and who attaches the reference bounds it further: a
  trusted harness attaching from its recorded binding, or a Mission
  Join Assertion presented alongside, is the strong form, and the
  Enforcement Scope Statement records the attachment provenance.

The Mission Join Assertion ({{join-assertion}}) is the mitigation for
the coarse-mapping and shared-client residuals: the MAS evaluates the
mapping once, centrally, under its documented policy, and binds the
result to one introspected token by digest and key thumbprint, so the
join stops being a standing property of every credential in an
equivalence class and becomes a minted, audited, token-bound event.

## Join Assertion Trust {#sec-join-assertion}

A captured Join Assertion moves no authority: it names one token by
digest and key thumbprint, so a replay without that token and its
sender-constraint key proves nothing, and `exp`, capped at the token's
remaining lifetime, bounds the window in which the proof is live. The
introspection call names a trust relationship specific to this
upgrade: the MAS relies on the deployment's AS, through RFC 7662
introspection or, for JWT access tokens, local RFC 9068 validation of
the AS-issued token, for the token's validity, subject, and client, and
the deployment documents that reliance and protects the MAS's
introspection credentials accordingly. The structural gain is
concentration: the subject and client mappings are evaluated at one
audited point under one documented policy, instead of configured
independently at N PDPs, where one drifted table is a silent join
widening.

## Expansion and Child-Creation Binding {#sec-native-binding}

The native surfaces of {{native-surfaces}} bind a request to its
predecessor or parent by authenticated client identity, not by the
token-exchange possession proof of the OAuth wire, and the residual is
exactly that difference: a compromised or impersonated registered
client can request expansion or child creation for any Mission recorded
under its `client_id`, where proving possession of the Mission-bound
access token would have limited it to the Missions whose token it holds
and can prove control of. The mitigations:

- Instance-grade binding
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}}) shrinks
  the `client_id` equivalence class to one runtime instance, and a
  Mission Join Assertion presented with the submission makes that
  instance a verified, token-bound party ({{native-binding}}).
- The expansion profile's fresh-approval requirement means no widening
  activates without the Approver, so a forged expansion request yields
  an approval prompt, not authority.
- The child-delegation profile's fan-out controls bound what child
  creation can amplify.
- The binding failure surface is anti-oracle ({{native-carriage}}), so
  a request against a Mission the client is not bound to is
  indistinguishable from one against a Mission that does not exist.

## Ambient Authority of Ungated Tokens

The central residual of this mode: tokens are ordinary OAuth tokens,
so within their lifetime and scope they work wherever PEP coverage is
absent, and Mission revocation does not touch them. Mitigations are
short token lifetimes at the AS, narrow scope hygiene for agent
clients, and complete PEP coverage of consequential paths; none
eliminates the residual, which only the issuance profile's gating
removes ({{limitations}}).

## MAS Availability

The runtime layer fails closed when Mission state cannot be
established within the staleness bound, so a MAS outage converts into
work stoppage for governed actions, not into loosened enforcement
(the availability trade the security model states,
{{I-D.draft-mcguinness-mission-security-model}}). A deployment
provisions MAS availability accordingly and sizes
`mission_max_stale_seconds` to the caching it can tolerate.

## Signing-Key Custody

The MAS's signing key is the estate's Mission root of trust: it signs
status and lifecycle responses, Join Assertions, and the issuer-signed
artifacts of the companions. A MAS SHOULD hold it in a non-exportable
keystore (an HSM or equivalent KMS-grade custody) with dual-controlled
generation. A MAS SHOULD sign high-volume surfaces (status, Join
Assertions) and long-lived artifacts (Mandates, Issuance Grants) under
distinct `kid`s in one `jwks_uri`, so custody can differ by blast
radius. The introspection credential the MAS holds at the estate AS
({{join-assertion-request}}) is secret material of the same tier: its
compromise forges joins
({{I-D.draft-mcguinness-mission-security-model}}).

## MAS Compromise

Compromise of a MAS is equivalent to Mission Issuer compromise: it can
forge approvals, alter records, and report false state. One
consequence is specific to this mode: the PDP join is the only
credential-to-Mission binding, so a compromised MAS combined with the
PDP's trust in it yields arbitrary attribution of authority to any
credential the join accepts. Consent Evidence commitments
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) and audit
transparency ({{I-D.draft-mcguinness-mission-audit}}) make forgery
detectable after the fact; signing-key custody and the status
profile's key-retention rules keep archived state evidence verifiable.

## Approval Surface Authentication

The MAS's review surface is the approval event surface, and the
issuance profile's approval rules apply to it unchanged: the Approver
is authenticated to the `acr` mapping, the Subject is never taken from
client input, client text is rendered inert, and derived authority is
visually distinguished from it ({{mission-approval}}). The submission,
status, and lifecycle endpoints reject unauthenticated callers and
preserve the anti-oracle property
({{I-D.draft-mcguinness-oauth-mission-status}}).

# Privacy Considerations

A MAS holds task data centrally: every governed Mission Intent (goals,
constraints, purposes) and every Mission record, outside the AS that
holds the deployment's identity data. The issuance profile's
minimization guidance applies: collect only the Intent members the
task needs, audience-filter every disclosure surface per the status
profile's rules, and treat submission, status, and lifecycle logs as
PII sinks. Retention is anchored on the issuance profile's audit
horizon: records are retained at least that long, and SHOULD NOT be
retained materially longer without a documented basis.

# IANA Considerations {#iana}

## HTTP Field Name Registration

This document registers the following in the "Hypertext Transfer
Protocol (HTTP) Field Name" registry ({{RFC9110}}):

- Field Name: Mission-Reference
- Status: permanent
- Structured Type: Dictionary
- Reference: this document, {{mission-reference-field}}
- Comments: none

## Well-Known URI Registration

IANA is requested to register the following in the "Well-Known URIs"
registry {{RFC8615}}:

- URI Suffix: `mission-authority-server`
- Change Controller: IETF
- Specification Document: this document, {{discovery}}
- Status: permanent
- Related Information: none

## Mission Authority Server Metadata Registry

IANA is requested to create the "Mission Authority Server Metadata"
registry. The registration policy is
Specification Required {{RFC8126}}. A Designated Expert reviews a
submission for: a Member Name following the metadata naming
conventions of {{discovery}} and not already registered; a definition
precise enough that a client can consume the member from its
specification alone; and no overlap with an existing member's
semantics (a refinement belongs in the defining specification, not a
parallel member). Registration does not require IETF review or a
Standards Track document. Each entry has: Member Name, Change
Controller, and Reference. The registry is seeded with the members of
{{discovery}};
for each, Change Controller IETF and Reference this document:

- `issuer`
- `mission_submission_endpoint`
- `mission_status_endpoint`
- `mission_status_signing_alg_values_supported`
- `mission_lifecycle_endpoint`
- `mission_auth_methods_supported`
- `mission_join_assertion_endpoint`
- `mission_event_stream_endpoint`
- `mission_max_stale_seconds`
- `jwks_uri`

## Media Type Registration

This document registers one media type per {{RFC6838}}.

### Mission Join Assertion Media Type

- Type name: application
- Subtype name: mission-join+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{sec-join-assertion}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission Authority Server
  deployments and PDPs consuming Mission Join Assertions
- Fragment identifier considerations: not applicable
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): none
  - Macintosh file type code(s): none
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

## Runtime Denial Reason

`mission_mismatch` extends the denial-reason set of
{{I-D.draft-mcguinness-mission-authzen}} under that profile's
denial-reason extensibility rule
({{mission-join}}). That profile's denial reasons are AuthZEN
extension data and are not registered in an IETF registry, so this
document requests no IANA action for it.

--- back

# MAS-Mode End-to-End Example {#e2e-example}

This appendix is non-normative. It stages the standalone binding end
to end on one Mission; the architecture's MAS-mode sequence diagram
shows the same stages in temporal order
({{I-D.draft-mcguinness-mission-architecture}}).

## Submit

The client proposes the Mission by POSTing its Mission Intent to the
submission endpoint; the MAS validates it, derives the Authority Set
under policy, and returns a pending-submission reference
({{mission-submission}}).

~~~ http-message
POST /mas/mission/submit HTTP/1.1
Host: mas.example.com
Content-Type: application/json
Authorization: DPoP eyJhbGciOiJFUzI1NiIsImtpZCI6...
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments under $500.",
    "resources": ["https://erp.example.com"],
    "expires_at": "2026-12-31T23:59:59Z"
  }
}
~~~

~~~ http-message
HTTP/1.1 202 Accepted
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_4qV9rL3tY6sB1zN0eF7jB8K2nP",
  "status": "pending",
  "expires_at": "2026-10-16T14:32:11Z"
}
~~~

## Poll to Approved

The MAS routes the submission to its approval surface; the Approver
authenticates, reviews the rendered Authority Set, and approves, and
the MAS creates the Mission `active` atomically with the decision
({{mission-approval}}). The client's next poll returns the Mission
reference and its consented authority ({{mission-reference}}).

~~~ http-message
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "submission_id": "sub_4qV9rL3tY6sB1zN0eF7jB8K2nP",
  "status": "approved",
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
  "mission_expires_at": "2026-12-31T23:59:59Z",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read", "journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" }
      } }
  ]
}
~~~

## Join

The agent works under an ordinary OAuth token from the unchanged AS,
which carries no Mission signal. For the first consequential action,
the PEP supplies the Mission reference, with `authority_hash` and
`state` from the MAS's signed Mission Status response, and the PDP
verifies the subject and client joins ({{mission-join}}).

~~~ json
{
  "subject": {
    "type": "user",
    "id": "user_3p2q8mN1a0kV7tR",
    "properties": { "iss": "https://idp.example.com" }
  },
  "resource": { "type": "invoice", "id": "inv_2026Q3_842" },
  "action": { "name": "invoices.read" },
  "context": {
    "mission": {
      "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
      "issuer": "https://mas.example.com",
      "authority_hash":
        "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ",
      "state": "active"
    }
  }
}
~~~

## Permit

The join holds and the action is within the Mission's Authority Set,
so the PDP permits; the PEP executes the call to
`https://erp.example.com`, and both record their evidence
({{I-D.draft-mcguinness-mission-runtime-evidence}}). A revocation at
the MAS
stops the next such action at this step, through the runtime state
re-check.

~~~ json
{
  "decision": true,
  "context": {
    "decision_id": "dec_7mQ2sV5rL9tY3sB8zN1eF4jB0K",
    "policy_view_id":
      "sha-256:kP3xR9sQ7nM2vL4tY6bD1eF8jC5wH0pV2nR3kQ4mZ7t",
    "action_class": "irreversible_action",
    "class_source": "resource_floor",
    "permit_expires_at": "2026-11-02T08:15:30Z"
  }
}
~~~

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work. It profiles the Mission Issuer role for deployments whose
Authorization Server cannot change, and builds on the Mission Status
and Lifecycle, Mission-Bound Runtime Enforcement, and AuthZEN profile
companions.
