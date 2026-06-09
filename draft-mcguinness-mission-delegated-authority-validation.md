---
title: "Delegated Authority Validation"
abbrev: "Delegated Authority Validation"
category: std

docname: draft-mcguinness-mission-delegated-authority-validation-latest
submissiontype: independent
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - authorization
 - oauth
 - resource-as
 - delegation
 - ontology
venue:
  group: "Independent Submission"
  type: "Independent"
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-delegated-authority-validation.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC2119:
  RFC8174:
  I-D.draft-mcguinness-mission-framework:
  I-D.draft-mcguinness-mission-expansion:

informative:
  RFC8693:
  RFC9396:
  RFC6838:
  I-D.draft-mcguinness-mission-oauth-profile:
  I-D.draft-mcguinness-mission-runtime-profile:

--- abstract

This document defines a narrow server-to-server protocol by which an
originating Authorization Server delegates authority validation to a
Resource Authorization Server (Resource AS) at the moment the
originating AS lacks the Resource AS's action ontology. The Resource
AS examines a minimized requested authority together with an
audience-filtered Mission projection and returns one of three
classification outcomes: in-bounds, out-of-bounds, or out-of-bounds
but eligible for governed expansion. The protocol composes with the
Mission Framework and with Mission Expansion. Scope is intentionally
narrow: this document defines the AS-to-Resource-AS handoff at
issuance or expansion time only. Runtime per-action authority
evaluation between a Policy Enforcement Point and a Policy Decision
Point is defined by the Mission-Bound Runtime Enforcement Profile and
is out of scope here.

--- middle

# Introduction

The Mission Framework {{I-D.draft-mcguinness-mission-framework}}
defines the Mission record, the typed Authority Set, integrity
anchors, and the Mission Status interface. The Mission-Bound OAuth
Profile {{I-D.draft-mcguinness-mission-oauth-profile}} binds those
elements to OAuth, including the `mission_resource_access` Rich
Authorization Request {{RFC9396}} type. Mission Expansion
{{I-D.draft-mcguinness-mission-expansion}} defines how an
out-of-bounds request becomes a governed authority addition.

In some deployments the originating Authorization Server that holds
the Mission record does not own the action ontology of the Resource
Server it is issuing credentials for. The Resource Server is fronted
by a Resource AS {{RFC8693}}, and only the Resource AS knows whether
a proposed `mission_resource_access` entry, action set, or constraint
set is meaningful against its local resource and policy model. Token
Exchange topologies, cross-vendor tool catalogs, and open-world
MCP-style integrations all produce this gap.

This document defines the narrow wire protocol the originating AS
uses to ask the Resource AS to classify a proposed authority entry
against the Resource AS's local ontology at issuance time or at
Mission Expansion time. The protocol returns one of three outcomes:
`in_bounds`, `out_of_bounds`, or `out_of_bounds_eligible`. The
originating AS uses the result to issue, refuse, or refuse with an
expansion eligibility signal carried back to its client per
{{I-D.draft-mcguinness-mission-expansion}}.

## Trigger condition

This protocol fires only when the originating AS lacks the Resource
AS's action ontology and cannot classify the proposed authority on
its own. An originating AS that holds enough of the Resource AS's
ontology to classify the proposed authority MUST classify locally
and MUST NOT delegate. Delegation is the fallback path for ontology
gaps, not a general validation surface.

## Relationship to other Mission-Bound specs

This document does not define the Mission Expansion workflow; that
lives in {{I-D.draft-mcguinness-mission-expansion}}. This document
signals expansion eligibility using the field names that Mission
Expansion already defines (`access_request_uri`, `ticket`,
`requested_authority`).

This document and the Mission-Bound Runtime Enforcement Profile
{{I-D.draft-mcguinness-mission-runtime-profile}} both classify
requests against Mission authority but fire at different times
between different actors. The boundary is normative and is restated
in {{boundary-with-runtime-enforcement}}.

## Scope and non-scope

This document defines: the AS-to-Resource-AS validation request and
response messages; disclosure minimization rules for the request;
the classification outcomes and their consequences for the
originating AS; trust establishment; composition with Mission
Expansion eligibility signaling; and failure modes when the Resource
AS is unreachable, classification times out, or ontology versions
mismatch.

This document does NOT define: the Mission record, Mission Intent,
or Authority Set shapes (see
{{I-D.draft-mcguinness-mission-framework}}); the OAuth wire binding
of `mission_resource_access` (see
{{I-D.draft-mcguinness-mission-oauth-profile}}); the Mission
Expansion workflow, replacement and branch semantics, or
reconciliation rules (see
{{I-D.draft-mcguinness-mission-expansion}}); runtime per-action
authority evaluation (see
{{I-D.draft-mcguinness-mission-runtime-profile}}); disclosure of the
full Mission Intent to a Resource AS (business purpose, unrelated
objects, and authority for other resources are excluded by default);
or negotiation by which a Resource AS demonstrates a policy need for
additional Mission fields (deployment policy, out of scope).

# Conventions and Definitions

{::boilerplate bcp14-tagged}

Terms from {{I-D.draft-mcguinness-mission-framework}} are inherited.
Additional definitions:

**Originating AS**:
: The Authorization Server that holds the Mission record and is
issuing or expanding authority. The state authority for the Mission.

**Resource AS**:
: The Authorization Server adjacent to the target Resource Server.
Authoritative for the Resource Server's action ontology, local
constraint semantics, and Resource policy.

**Action ontology**:
: The local vocabulary, schema, and semantics by which a Resource AS
interprets actions, resources, and constraints. The Resource AS is
authoritative for its action ontology.

**Audience-filtered Mission projection**:
: A minimal projection of the Mission record bounded to the Resource
AS's audience, carrying Mission state and the integrity anchors
needed to bind the classification, with all Authority Set entries
other than those addressed to the Resource AS's audience removed.

**Proposed authority entry**:
: A single typed Authority Set entry the originating AS proposes to
issue or add. A validation request carries one or more proposed
entries.

**Classification outcome**:
: The Resource AS's determination for a proposed authority entry:
`in_bounds`, `out_of_bounds`, or `out_of_bounds_eligible`.

# The AS-to-Resource-AS Validation Request and Response

This section defines the two messages exchanged between the
originating AS and the Resource AS. The protocol fires only under
the trigger condition stated in {{introduction}}: the originating AS
lacks the Resource AS's action ontology for the proposed authority
entries. The originating AS MUST NOT use this protocol for entries
it can classify locally.

## Transport

The validation request is an HTTPS POST from the originating AS to
the Resource AS. The validation endpoint URL is advertised by the
Resource AS as `mission_authority_validation_endpoint` in its OAuth
Authorization Server metadata.

The deployment selects a mutual-authentication mechanism. Acceptable
mechanisms include mutual TLS or signed JWT request authentication.
The chosen mechanism MUST bind the response to the request. The
authentication requirements are normative and are stated in
{{trust-establishment}}.

## Validation request

The validation request is a JSON document with media type
`application/mission-authority-validation-request+json` and the
following members:

- `originating_as` (string, required): the issuer URL of the
  originating AS.
- `mission` (object, required): the audience-filtered Mission
  projection per {{audience-filtered-mission-projection}}.
- `requested_authority` (array of object, required): one or more
  proposed authority entries to classify. Each element is a typed
  Authority Set entry per {{I-D.draft-mcguinness-mission-framework}}.
- `request_id` (string, required): a unique, unpredictable identifier
  used to bind the response.
- `request_time` (RFC 3339 timestamp, required).
- `ontology_version_hint` (string, optional): the schema version of
  the Resource AS's action ontology the originating AS believes
  applies. Used to detect skew per
  {{mismatched-ontology-versions}}.

The originating AS MUST NOT include Mission Intent fields,
principal-model fields, or Authority Set entries beyond what
{{disclosure-minimization}} permits.

### Audience-filtered Mission projection

The `mission` member carries: `id` or `ref` (exactly one, per
{{I-D.draft-mcguinness-mission-framework}}); `origin` (state
authority issuer URL); `authority_hash` (integrity anchor committed
at the approval event); `policy_version` (the derivation
`policy_version` recorded on the Mission record); `state` (lifecycle
state, MUST be `active` for any request sent through this protocol);
`audience` (the Resource AS audience identifier the projection is
bounded to); and `expires_at` (the Mission's `mission_expiry`
ceiling).

The Resource AS MAY verify the Mission projection by an out-of-band
Mission Status query against the `origin` state authority per
{{I-D.draft-mcguinness-mission-framework}}; it is not required to
take the projection on its face.

## Validation response

The validation response is a JSON document with media type
`application/mission-authority-validation-response+json` and the
following members:

- `request_id` (string, required): MUST match the request's
  `request_id`.
- `resource_as` (string, required): issuer URL of the Resource AS
  producing the classification.
- `evaluated_at` (RFC 3339 timestamp, required).
- `ontology_version` (string, required): schema version of the
  Resource AS's action ontology used in evaluation.
- `classifications` (array of object, required): per-entry results,
  positionally corresponding to `requested_authority` in the
  request. Each element carries `result` (one of `in_bounds`,
  `out_of_bounds`, `out_of_bounds_eligible`, `version_mismatch`,
  `unknown_resource`, `unknown_action`); optional `reason`
  (machine-readable identifier); and conditional `expansion` object
  carrying the Mission Expansion eligibility-signaling fields per
  {{I-D.draft-mcguinness-mission-expansion}} (`access_request_uri`,
  `ticket`, `requested_authority`) when `result` is
  `out_of_bounds_eligible`.

The originating AS MUST verify the response's `request_id`, that it
was produced by the expected Resource AS audience, and that its
mutual-authentication binding is valid before acting on any
classification.

## Resource AS responsibilities

The Resource AS:

1. MUST examine only the minimized `requested_authority` entries and
   the audience-filtered Mission projection. The Resource AS MUST NOT
   require, and the originating AS MUST NOT send by default, Mission
   Intent fields, principal-model fields, or unrelated Authority Set
   entries.
2. MAY consult Mission Status at the `origin` state authority to
   verify the projection's `state`, `authority_hash`, and
   `policy_version`.
3. MUST evaluate each `requested_authority` entry against its local
   ontology under its current `ontology_version`.
4. MUST return one classification per `requested_authority` entry in
   positional order.
5. MUST return `out_of_bounds_eligible` only when the Resource AS's
   local policy declares the requested authority eligible for
   governed Mission Expansion per
   {{I-D.draft-mcguinness-mission-expansion}}.
6. MUST NOT issue any credentials, mint any tokens, or alter any
   Mission state in response to this protocol. The Resource AS
   classifies only.
7. MUST return `version_mismatch` when an `ontology_version_hint`
   in the request does not match the Resource AS's current
   ontology version and the Resource AS cannot evaluate against the
   hinted version.

## Single example

The following example shows a validation request for one
`mission_resource_access` entry that the Resource AS classifies as
`out_of_bounds_eligible`. The originating AS would surface the
expansion eligibility to its client per
{{I-D.draft-mcguinness-mission-expansion}}.

Request:

~~~
POST /mission-authority-validation HTTP/1.1
Host: docs-as.example.com
Content-Type: application/mission-authority-validation-request+json

{
  "originating_as": "https://as.example.com",
  "mission": {
    "id": "msn_01J9Z2P8BQ4Y3F0V0K9D6Z7M1",
    "origin": "https://as.example.com",
    "authority_hash": "sha-256:rA3...",
    "policy_version": "as.example.com:standard@2026-06-01",
    "state": "active",
    "audience": "https://docs.example.com",
    "expires_at": "2026-06-09T18:00:00Z"
  },
  "requested_authority": [
    {
      "type": "mission_resource_access",
      "specification_uri":
        "https://mcguinness.github.io/mission-bound-authorization/specs/mission_resource_access-v1",
      "schema_version": "1",
      "authority": {
        "resource": "https://docs.example.com",
        "actions": ["documents.share_external"],
        "constraints": {
          "folder": "board-materials"
        }
      },
      "narrowing_profile": "urn:mbo:narrowing:default-v1"
    }
  ],
  "request_id": "req_7Q2x...",
  "request_time": "2026-06-09T17:32:01Z",
  "ontology_version_hint": "docs-as.example.com:ontology@2026-05-15"
}
~~~

Response:

~~~
HTTP/1.1 200 OK
Content-Type: application/mission-authority-validation-response+json

{
  "request_id": "req_7Q2x...",
  "resource_as": "https://docs-as.example.com",
  "evaluated_at": "2026-06-09T17:32:01Z",
  "ontology_version": "docs-as.example.com:ontology@2026-05-15",
  "classifications": [
    {
      "result": "out_of_bounds_eligible",
      "reason": "external_sharing_requires_expansion",
      "expansion": {
        "access_request_uri":
          "https://docs-as.example.com/expansion-request",
        "ticket": "exp_tkt_K8m...",
        "requested_authority": {
          "type": "mission_resource_access",
          "authority": {
            "resource": "https://docs.example.com",
            "actions": ["documents.share_external"]
          }
        }
      }
    }
  ]
}
~~~

# Disclosure Minimization

The validation request is bounded to the smallest set of fields the
Resource AS needs to classify against its local ontology. This
section enumerates that bound normatively.

The originating AS MUST send: the audience-filtered Mission
projection per {{audience-filtered-mission-projection}}, bounded to
the Resource AS's audience; the proposed `requested_authority`
entries that target the Resource AS's audience; and the
`request_id`, `request_time`, and `originating_as` identifier.

The originating AS MUST NOT send by default:

- Mission Intent `goal`, `purpose`, `context`, `success_criteria`,
  or any descriptive narrative.
- Mission Intent `objects` entries unrelated to the Resource AS's
  audience.
- Authority Set entries for resources other than the Resource AS's
  audience.
- Principal-model fields. The standard request does not carry
  `subject`, `approving_principal`, or `requesting_client`
  identifiers.
- `proposal_hash` or `consent_disclosure_hash` integrity anchors.
  The `authority_hash` is the only anchor the Resource AS needs to
  bind the classification to the Mission's authority commitment.
- Identifiers of unrelated Missions, other tenants, or other
  Resource ASes.

A Resource AS MAY require additional Mission fields only when its
local policy declares a registered need. The mechanism by which a
Resource AS demonstrates such a need, and by which the originating
AS authorizes the additional disclosure, is out of scope of this
document and is governed by deployment policy. In the absence of a
registered need, the originating AS MUST NOT enlarge the disclosure.

The Mission projection's `audience` member binds the projection to
the Resource AS. The originating AS MUST set `audience` to the
Resource AS's audience identifier and MUST NOT send the same
projection bytes to a different Resource AS. A Resource AS MUST
refuse a projection whose `audience` does not match its own.

# Classification Outcomes

The Resource AS returns one classification per `requested_authority`
entry. The outcomes and their consequences for the originating AS
are normative.

**`in_bounds`**: the proposed authority is meaningful under the
Resource AS's ontology and acceptable for the projected Mission.
The originating AS MAY issue or expand authority for this entry,
subject to its own derivation policy and the Framework's narrowing
rules.

**`out_of_bounds`**: the proposed authority is meaningful but not
acceptable. The Resource AS declares no expansion eligibility. The
originating AS MUST NOT issue or expand authority for this entry
and surfaces the refusal to its client per the substrate profile
in use.

**`out_of_bounds_eligible`**: the proposed authority is meaningful,
not within current bounds, but eligible for governed Mission
Expansion per {{I-D.draft-mcguinness-mission-expansion}}. The
response's `expansion` object carries the eligibility-signaling
fields. The originating AS MUST NOT issue or expand authority on
this classification alone; it surfaces the eligibility signal to
its client per the Mission Expansion substrate binding. The client
follows the Mission Expansion workflow to obtain a successor
Mission, after which a fresh validation request reflects the
post-expansion state.

`version_mismatch`, `unknown_resource`, and `unknown_action` are
classification failures rather than authority decisions; they are
addressed in {{failure-modes}}.

# Trust Establishment

Trust between the originating AS and the Resource AS is two-way and
asymmetric.

The originating AS trusts the Resource AS's classification because
the Resource AS owns the action ontology of its Resource Server and
is authoritative for what its actions, constraints, and Resource
policy mean. No other party is better positioned to classify. The
originating AS MUST authenticate the Resource AS's response and MUST
verify it was produced by the expected Resource AS audience.

The Resource AS trusts the originating AS's Mission projection
because the originating AS is the state authority and is
authoritative for the Mission record, the `authority_hash`, the
lifecycle state, and the derivation `policy_version`. The Resource
AS MUST authenticate the originating AS and MAY independently verify
the projection against the state authority's Mission Status
interface per {{I-D.draft-mcguinness-mission-framework}} before
classifying.

The validation request and response MUST be exchanged over a
mutually authenticated channel. The chosen mechanism MUST bind the
response to the request such that the originating AS can verify that
the response is the Resource AS's response to this specific request.

The Resource AS is NOT delegated to mint Mission-bound credentials.
It classifies a proposed authority entry; it does not issue or
expand authority. Credential issuance and Mission Expansion remain
with the originating AS or the appropriate state authority per the
Framework's role definitions.

# Composition with Mission Expansion

The `out_of_bounds_eligible` classification outcome composes
directly with the Mission Expansion eligibility contract defined in
{{I-D.draft-mcguinness-mission-expansion}}.

When the Resource AS returns `out_of_bounds_eligible`, the response's
`expansion` object carries the same eligibility-signaling members
that Mission Expansion defines for substrate denial:
`access_request_uri` (the URL at which the client submits an
AuthZEN Access Request), `ticket` (an opaque, single-use,
time-limited bearer token bound to this eligibility signal), and
`requested_authority` (the proposed authority entry that prompted
the eligibility classification). This document does not redefine
these fields; it uses the field names and semantics defined by
{{I-D.draft-mcguinness-mission-expansion}}.

The originating AS surfaces the eligibility signal to its client per
the substrate profile in use. For OAuth, this is the binding defined
in {{I-D.draft-mcguinness-mission-oauth-profile}}. The originating AS
MUST NOT alter the `ticket`, MUST NOT extend its validity, and MUST
NOT bind it to a different audience.

After Mission Expansion produces a successor Mission per
{{I-D.draft-mcguinness-mission-expansion}}, the originating AS MAY
issue authority that was previously classified
`out_of_bounds_eligible` only after a fresh delegated validation
request against the successor Mission's projection returns
`in_bounds`. The originating AS MUST NOT carry forward a prior
`out_of_bounds_eligible` classification across a Mission Expansion
event.

# Failure Modes

The originating AS MUST fail closed when delegated validation cannot
complete. Failing closed means refusing issuance or expansion for
the proposed authority entries. The originating AS MUST NOT
default-permit on any failure mode in this section.

## Resource AS unreachable

When the originating AS cannot reach the Resource AS's validation
endpoint within the deployment's bounded request timeout, the
originating AS MUST refuse the affected `requested_authority`
entries. It MAY surface a transient-failure indication to its
client. It MUST NOT cache prior classifications across an
unreachable interval beyond the cache validity declared by the
Resource AS's response.

## Classification timeout

When the originating AS reaches the Resource AS but does not receive
a response within the deployment's bounded classification timeout,
the originating AS MUST refuse the affected entries and SHOULD log
the timeout. The Resource AS SHOULD advertise its expected maximum
response time in its metadata so the originating AS can set a
compatible timeout.

## Mismatched ontology versions

When the request's `ontology_version_hint` does not match the
Resource AS's current ontology version and the Resource AS cannot
evaluate against the hinted version, the Resource AS MUST return
`version_mismatch` for each affected entry and MUST include its
current `ontology_version` in the response. On receiving
`version_mismatch`, the originating AS MUST NOT issue or expand
authority for the affected entries; it MAY re-issue the request
with the Resource AS's current ontology version after consulting
the Resource AS's metadata.

## Unknown resource or action

`unknown_resource` and `unknown_action` indicate that the proposed
authority entry references a resource or action the Resource AS does
not recognize. The originating AS MUST refuse the affected entries.
These results MUST NOT be conflated with `out_of_bounds`: an unknown
identifier is an ontology classification failure, not an authority
decision.

## Replay and binding

The response's `request_id` binds it to a specific validation
request. The originating AS MUST refuse to act on a response whose
`request_id` does not match an outstanding request.

# Boundary with Runtime Enforcement {#boundary-with-runtime-enforcement}

This document and the Mission-Bound Runtime Enforcement Profile
{{I-D.draft-mcguinness-mission-runtime-profile}} both classify
requests against Mission authority. The boundary is normative.

| Property | This document | Runtime Enforcement Profile |
|---|---|---|
| When | Issuance or Mission Expansion time | Per consequential action at runtime |
| Between | Originating AS and Resource AS | PEP and PDP |
| Subject | A proposed Authority Set entry | A specific action request |
| Output | `in_bounds` / `out_of_bounds` / `out_of_bounds_eligible` per entry | `permit` / `deny` / `expandable_deny` per request |
| Trigger | Originating AS lacks Resource AS's ontology | Every action in the deployment's enforcement-scope manifest |
| Side effects | None | Authoritative counters (e.g., `max_invocations`), Decision Evidence, Execution Evidence |

A deployment MUST NOT use this protocol as a substitute for runtime
enforcement. A `in_bounds` classification at issuance does not
permit any specific runtime action; the Runtime Enforcement Profile
evaluates per-action decisions on its own inputs.

A deployment MAY use the same ontology, the same `mission_resource_access`
schema, and the same denial vocabulary across both protocols. The
two operations remain separate because they fire at different times
between different actors.

If implementer experience shows the boundary between this document
and the Runtime Enforcement Profile to be unstable, this document
folds into the Runtime Enforcement Profile in a future revision.

# Security Considerations

## Disclosure minimization

The Resource AS receives the smallest subset of the Mission record
needed to classify. Enlarging the disclosure to include Mission
Intent fields, principal-model fields, or unrelated Authority Set
entries creates an information surface the Resource AS does not
need and increases the impact of a Resource AS compromise. The
originating AS MUST treat the disclosure floor in
{{disclosure-minimization}} as a maximum, not a minimum. Any
enlargement requires deployment-policy authorization that is out of
scope of this document.

## False positives and false negatives

A Resource AS that returns `in_bounds` for an entry the Resource
Server will later refuse at runtime creates an authority mismatch
detectable only at runtime. A Resource AS that returns
`out_of_bounds` for an entry the Resource Server would have accepted
creates an availability impact on the Mission. Both classes of
error are local to the Resource AS's ontology and policy. The
Resource AS is authoritative for both and is responsible for keeping
issuance-time classification consistent with runtime enforcement.

## Resource AS compromise

A compromised Resource AS can return arbitrary classifications.
Worst-case impact is bounded: the originating AS does not issue
credentials beyond the Mission's Authority Set narrowing rules
regardless of the classification (the originating AS MUST apply its
own narrowing per {{I-D.draft-mcguinness-mission-framework}}); a
compromised Resource AS cannot mint credentials (issuance remains
at the originating AS); and a compromised Resource AS can deny
legitimate issuance (availability) or falsely declare expansion
eligibility (governance). Deployments SHOULD audit Resource AS
classifications against runtime denial patterns to detect
divergence.

## Request and response binding

A response not bound to its specific request can be replayed against
a different request to misrepresent a classification. The
`request_id` binding and the mutual-authentication mechanism's
response-to-request binding mitigate this. The originating AS MUST
refuse responses that do not bind to an outstanding request and MUST
refuse responses whose mutual-authentication binding fails to
verify.

## Audience confusion

A Mission projection sent to the wrong Resource AS audience could
be acted on by the wrong party. The projection's `audience` member,
the mutual-authentication channel, and the originating AS's
audience-filtering requirements together prevent audience confusion.
A Resource AS MUST refuse a projection whose `audience` does not
match its own.

## Fail-closed default

Every failure mode in {{failure-modes}} requires the originating AS
to refuse issuance or expansion. A deployment that default-permits
on classification failure produces silent privilege enlargement and
is non-conformant.

## Expansion ticket handling

The `ticket` member of the `expansion` object is an opaque,
single-use, time-limited bearer token. The originating AS, in
forwarding it to its client, MUST NOT extend its validity, MUST NOT
rebind it to a different audience, and MUST NOT log it in a form
that survives the eligibility window. Ticket semantics are defined
by {{I-D.draft-mcguinness-mission-expansion}}.

## Ontology version skew

A Resource AS that updates its ontology without coordinating with
its originating ASes can return `version_mismatch` for previously
working requests. Deployments SHOULD coordinate ontology updates
across consuming originating ASes. The Resource AS MUST advertise
its current `ontology_version` in metadata so originating ASes can
refresh their hints.

# IANA Considerations

This document creates the following IANA registrations.

## Media Types

This document registers two media types per {{RFC6838}}:

`application/mission-authority-validation-request+json`. Type
name: application. Subtype: mission-authority-validation-request+json.
Required parameters: none. Encoding considerations: binary; JSON
over HTTPS. Security considerations: see Security Considerations of
this document. Published specification: this document. Applications:
Authorization Servers and Resource Authorization Servers
implementing Mission-Bound Delegated Authority Validation. Change
controller: IETF. Provisional registration: yes.

`application/mission-authority-validation-response+json`. All fields
as above except subtype, which is
mission-authority-validation-response+json.

## Mission Authority Validation Classification Result Codes

This document creates a new IANA registry, "Mission Authority
Validation Classification Result Codes", tracking the result codes
returned in a validation response's `classifications` array.

- **Registration Policy**: Specification Required.
- **Required fields per entry**: `result`, defining specification,
  consequence for the originating AS, change controller.
- **Initial entries**:
  - `in_bounds`: this document. The proposed authority is meaningful
    and acceptable for the projected Mission. The originating AS MAY
    proceed.
  - `out_of_bounds`: this document. The proposed authority is
    meaningful but not acceptable. The originating AS MUST refuse.
  - `out_of_bounds_eligible`: this document. The proposed authority
    is meaningful, out of bounds, and eligible for governed Mission
    Expansion. The originating AS MUST NOT issue on this
    classification alone and surfaces expansion eligibility.
  - `version_mismatch`: this document. The Resource AS's ontology
    version does not match the request. The originating AS MUST
    refuse and MAY retry.
  - `unknown_resource`: this document. The Resource AS does not
    recognize the requested resource. The originating AS MUST
    refuse.
  - `unknown_action`: this document. The Resource AS does not
    recognize the requested action. The originating AS MUST refuse.

## Mission Capability-Advertisement Metadata

This document registers the following entry in the Mission
Capability-Advertisement Metadata registry created by
{{I-D.draft-mcguinness-mission-framework}}:

- `mission_authority_validation_endpoint`: URL at which a Resource
  AS accepts delegated authority validation requests per this
  document. Advertised in Authorization Server metadata.

# Acknowledgments
{:numbered="false"}

The author thanks the Mission-Bound Authorization implementer
community for feedback that shaped the narrow scope of this
specification.

--- back
