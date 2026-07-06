---
title: "Mission Deferred Approval for OAuth 2.0"
abbrev: "OAuth Mission Deferred Approval"
category: std

docname: draft-mcguinness-oauth-mission-approval-latest
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
 - approval
 - deferred
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-approval.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC9126:
  I-D.draft-gerber-oauth-deferred-token-response:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-latest

informative:
  I-D.draft-mcguinness-oauth-mission-approval-revision:
    title: "Mission Approval Revision for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-approval-revision.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-approval-revision-latest
  I-D.draft-mcguinness-mission-shaping:
    title: "Mission Intent Shaping"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-shaping.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-shaping-latest
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-authority-server-latest
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-consent-evidence-latest
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest

--- abstract

Mission-Bound Authorization for OAuth 2.0 (the "issuance profile")
records an approval event at which an Approver consents to a Mission's
derived Authority Set, but it treats that event as immediate. A human
review of an agent's proposed Mission is often asynchronous. This
document defines an optional Mission Deferred Approval profile. It
profiles OAuth Deferred Token Response so a Mission approval can be
deferred and polled. Deferral explicitly overrides the issuance
profile's approval-event sequencing: the approval event moves to the
asynchronous review surface, and the Mission record is created
atomically with that decision rather than with the authorization code.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") derives
an Authority Set from a submitted Mission
Intent and records an approval event at which an Approver consents to
that authority. It specifies what the approval commits, not how the
approval is obtained over time. One fact about agent approval is left
unspecified: a human Approver review is asynchronous. The agent submits
a proposed Mission and must wait, sometimes for a long time, for a
decision.

This document supplies that. It profiles OAuth Deferred Token Response
{{I-D.draft-gerber-oauth-deferred-token-response}} (the "deferred
substrate") so a Mission approval can be deferred and polled.

A reviewer that will grant only a narrowed subset of the proposed
Mission resolves the deferral to `access_denied`, and the client submits
a fresh, narrower Mission Intent; an experimental companion defines an
in-place narrowing-revision handshake over this profile
({{I-D.draft-mcguinness-oauth-mission-approval-revision}}). Widening an
approved Mission is a different operation with its own fresh approval
({{I-D.draft-mcguinness-oauth-mission-expansion}}).

# Status: An OPTIONAL Extension {#optional-status}

This document is OPTIONAL. A deployment that obtains Mission approvals
synchronously is fully conformant to the issuance profile and is
unaffected by this document. It places no new requirement on the
issuance profile.

A deployment claims this profile only when it defers Mission approvals
under the deferred substrate. The approval event, the Authority Set,
the subset rule, and the integrity anchors are unchanged; this document
governs only how the approval is reached over time.

This profile is specific to the OAuth binding's authorization-code
ceremony. Under the standalone Mission Authority Server binding
({{I-D.draft-mcguinness-mission-authority-server}}), approval is
natively asynchronous and this re-sequencing is not needed.

This profile tracks an in-progress substrate. It depends normatively on
OAuth Deferred Token Response
({{I-D.draft-gerber-oauth-deferred-token-response}}), an early
Internet-Draft that is not ratified and whose details may change, so
this profile is not yet a stable interface and will track the substrate
as it evolves. Synchronous Mission approval, which needs only the
issuance profile, is the stable path; deploy deferred approval for
evaluation rather than as a stable interface.

# Relationship to the Issuance Profile {#issuance-relationship}

This document depends normatively on the issuance profile and on the
deferred substrate, and is not implementable alone. It reuses, without
restating, the issuance profile's Mission Intent, submission via PAR
{{RFC9126}}, authority derivation, approval event, subset rule, and
integrity anchors, and the deferred substrate's deferral response,
continuation polling, cancellation, and sender-constraint rules. It uses
the terms Agent (Client), Approver, Mission Issuer, Mission Intent, and
Authority Set as the issuance profile defines them, and `completion_mode`,
`deferral_code`, and the deferred grant type as the deferred substrate
defines them.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

Proposed Mission:
: The Mission Intent and the Authority Set the Mission Issuer derived
  from it, pending an approval decision.

# Deferred Mission Approval {#deferred-approval}

A Mission approval MAY be deferred. The client submits the Mission
Intent through PAR as the issuance profile requires, and includes
`deferred` among the `completion_mode` values on the resulting token
request, opting in to the deferred substrate
({{I-D.draft-gerber-oauth-deferred-token-response}}). When the Mission
Issuer cannot decide the approval immediately, for example because it
routes the proposed Mission to a human reviewer, it returns the
substrate's deferred response (`authorization_pending` with a
`deferral_code`) instead of a token, and the client polls with the
deferred grant type until the approval resolves to a Mission-bound token
response, `access_denied`, or `expired_token`.

## Sequencing the Approval Event {#deferred-sequencing}

The issuance profile treats the approval event as immediate: the
Approver consents and the Mission record is created atomically with
issuance of the authorization code
({{I-D.draft-mcguinness-oauth-mission}}). This profile is an explicit
override of that sequencing for a deferred approval, and it moves the
approval event without weakening it:

1. The client submits the proposed Mission via PAR {{RFC9126}} and the
   authorization request completes into a deferred state per the
   deferred substrate ({{I-D.draft-gerber-oauth-deferred-token-response}}).
2. Before approval only the pending request exists. The authorization
   artifact represents a pending authorization, never authority, and no
   Mission exists. A `deferral_code` and any PAR `request_uri` are
   pending-request state, not a grant.
3. The approval event executes on the asynchronous review surface. That
   surface MUST authenticate the Approver and MUST satisfy the Mission
   Intent's `controls.acr`, exactly as the synchronous approval event
   requires ({{I-D.draft-mcguinness-oauth-mission}}).
4. The Mission record is created in the `active` state atomically with
   the approval decision, preserving the issuance profile's atomicity at
   the moved point.
5. Issuance then completes per the deferred substrate: the next poll
   resolves to a Mission-bound token response.

Deferral changes only the timing of the approval event. The Authority
Set the token is issued against, its `authority_hash`, and the recorded
consent are exactly as in a synchronous approval.

## Deferred Approval State Machine {#state-machine}

A deferred approval is in one of three states: `pending`, `approved`,
or `denied`. The Mission Issuer starts a deferred approval in `pending`
and MAY move it to `approved` or `denied`; both are terminal.

~~~ text
       submit (PAR + deferred)
                |
                v
           +---------+
           | pending |
           +---------+
             |     |
   approve   |     +-------------> denied  (terminal)
             v
          approved  (terminal; Mission created active)
~~~

An experimental companion extends this state machine with a
`revision_required` state and a narrowing-revision handshake
({{I-D.draft-mcguinness-oauth-mission-approval-revision}}). Without it,
a proposal the reviewer will grant only in narrowed form resolves to
`access_denied`, and the client submits a fresh, narrower Mission
Intent via PAR {{RFC9126}}.

## Pending Lifetime and Staleness {#pending-staleness}

A deferred approval MUST carry a deployment-set maximum pending lifetime,
after which it resolves to `expired_token` per the deferred substrate. A
decision made after a change to the derivation `policy_version`, or to
the applicable capability catalog, MUST be made over a proposal that has
been re-derived and re-rendered under the current policy and catalog; the
Mission Issuer MUST NOT commit an approval over a proposal derived under
superseded policy.

# Integration with the Mission Suite {#integration}

Consent evidence:
: Where a deployment records Consent Evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), a deferred
  approval produces evidence exactly as a synchronous one: an approval
  yields evidence with decision `approved` bound to the created
  Mission's anchors, and a denial yields evidence with decision
  `declined` over the proposal's anchors. The rendering the reviewer
  approved on the asynchronous surface is the disclosure the evidence
  commits.

Shaping:
: A client-side shaper ({{I-D.draft-mcguinness-mission-shaping}})
  narrows a proposal before submission, which reduces the chance a
  deferred review is refused. After an `access_denied` resolution, the
  shaper constructs the fresh, narrower Mission Intent the client
  resubmits.

Integrity anchors:
: The approval commits the proposal actually approved. The
  `intent_hash` and `authority_hash` are computed over the Mission
  Intent and Authority Set the Approver decided on.

# Worked Example {#example}

Agent `s6BhdRkqt3`, acting for `alice`, proposes a Mission to reconcile
Q3 invoices with read access to the ERP. It submits the Mission Intent
through PAR and opts in to deferral on the token request:

~~~ http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&
client_id=s6BhdRkqt3&
completion_mode=deferred
~~~

The Mission Issuer routes the proposed Mission to `alice` for review and
defers:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{ "error": "authorization_pending",
  "deferral_code": "dfc_7M2R4kP9sT1x",
  "expires_in": 600, "interval": 5 }
~~~

The agent polls with the deferred grant type. On review `alice`
approves the proposal. The Mission record is created `active`
atomically with her decision, and the next poll resolves to a
Mission-bound token:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{ "access_token": "eyJ...",
  "token_type": "DPoP",
  "expires_in": 300,
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": { "period": "2026-Q3" } } ],
  "mission_id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-" }
~~~

The token carries the `mission` claim and its `authority_hash` as the
issuance profile defines; the response also surfaces the optional
`mission_id` parameter ({{I-D.draft-mcguinness-oauth-mission}}) for
correlation. Had `alice` approved only a subset, the deferral would
resolve to `access_denied` and the agent would submit a fresh, narrower
Mission Intent, unless the deployment runs the experimental revision
companion ({{I-D.draft-mcguinness-oauth-mission-approval-revision}}).

# Conformance {#conformance}

A Mission Issuer conforming to this profile MUST:

- support the deferred substrate for Mission approvals it defers;
- execute the approval event on the asynchronous review surface with
  the authentication the issuance profile requires
  ({{deferred-sequencing}});
- create the Mission record `active` atomically with the approval
  decision; and
- enforce the pending lifetime and staleness rules of
  {{pending-staleness}}.

A client conforming to this profile MUST treat every pending response
as unapproved and poll the `deferral_code` per the deferred substrate.

# Security Considerations {#security-considerations}

The deferred substrate's security considerations apply in full,
including deferral-code entropy, sender-constraint continuity,
cancellation, and oracle resistance.

The asynchronous review surface is part of the consent path. It MUST
meet the approval event's authentication requirements, authenticating
the Approver and satisfying the Mission Intent's `controls.acr`
({{deferred-sequencing}}); deferring an approval does not lower the bar
the synchronous event sets. Approver routing and notification, how a
proposed Mission reaches a reviewer and how the reviewer is alerted, are
deployment matters and are named as such here rather than specified.

# Privacy Considerations {#privacy-considerations}

A pending proposed Mission reveals what authority an agent sought
before any approval exists. A Mission Issuer SHOULD treat pending
proposals and their resolutions as sensitive and retain them under the
same controls as other approval-event records.

# IANA Considerations {#iana}

This document has no IANA actions. The `deferred` completion mode and
the deferred grant type are registered by the deferred substrate
({{I-D.draft-gerber-oauth-deferred-token-response}}).

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and profiles OAuth Deferred Token Response for asynchronous
Mission approval.
