---
title: "Mission Deferred Approval for OAuth 2.0"
abbrev: "OAuth Mission Deferred Approval"
category: std

docname: draft-mcguinness-oauth-mission-approval-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
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
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html"

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
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-oauth-mission-approval-revision:
    title: "Mission Approval Revision for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval-revision.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-shaping:
    title: "Mission Intent Shaping"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-shaping.html
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
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
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

--- abstract

Mission-Bound Authorization for OAuth 2.0 (the "issuance profile")
records an approval event at which an Approver consents to a Mission's
derived Authority Set, but it treats that event as immediate. A human
review of an agent's proposed Mission is often asynchronous. This
document defines an optional Mission Deferred Approval profile. It
profiles OAuth Deferred Token Response so a Mission approval can be
deferred and polled. Deferral relocates the issuance profile's
approval event to the asynchronous review surface and creates the
Mission record atomically with that decision rather than with the
authorization code. It relies on a core extensibility seam for
approval sequencing.

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
evaluation rather than as a stable interface. This document is
Standards Track despite that posture because it tracks its substrate
and stabilizes with it.

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
({{I-D.draft-mcguinness-oauth-mission}}). For a deferred approval this
profile relocates that approval event without weakening it, moving it
to the asynchronous review surface:

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

This relocation relies on a core extensibility seam for approval
sequencing, under discussion upstream. The core specifies the approval
event and authorization-code issuance as one atomic step, so a
deployment claims conformance to this profile's relocated sequencing
rather than unqualified conformance to that original step; what the
approval commits is unchanged.

Deferral changes only the timing of the approval event. The Authority
Set the token is issued against, its `authority_hash`, and the recorded
consent are exactly as in a synchronous approval. A Mission revoked
between the approval decision and the resolving poll yields no token:
issuance gating derives only from an `active` Mission
({{I-D.draft-mcguinness-oauth-mission}}). Carrying the issuance
profile's unredeemed-code rule, when the client never polls and the
`deferral_code` is never redeemed, the AS SHOULD revoke the orphaned
`active` Mission or allow it to expire
({{I-D.draft-mcguinness-oauth-mission}}).

## The Residual Front-Channel Ceremony {#front-channel}

The issuance profile runs the approval event as the OAuth
authorization-code flow initiated from the PAR-issued `request_uri`,
in ordered steps: authenticate the Approver, establish the Subject,
render the derived Authority Set for consent, compute the integrity
anchors, and create the Mission record atomically with issuance of the
authorization code ({{I-D.draft-mcguinness-oauth-mission}}). Under
deferral those steps divide between the front channel and the review
surface:

- Authenticating the Approver, establishing the Subject, rendering for
  consent, and computing the integrity anchors all move to the
  asynchronous review surface and execute at the approval event
  ({{deferred-sequencing}}).
- The front channel establishes only the pending request. No Approver
  need be present at the authorization endpoint, and the endpoint MAY
  complete the authorization request into the deferred state and issue
  the authorization code without user interaction, because that code
  represents a pending authorization, not authority (step 2 of
  {{deferred-sequencing}}). The AS MUST still bind the code to the
  requesting client with PKCE (`S256`) or issue a DPoP-bound code, as
  the issuance profile requires for a front-channel code
  ({{I-D.draft-mcguinness-oauth-mission}}).
- Subject establishment occurs on the review surface, at the approval
  event, together with Approver authentication, not at the front
  channel; the AS MUST NOT take the Subject from unauthenticated client
  input ({{I-D.draft-mcguinness-oauth-mission}}).
- Creating the Mission record, the final step, executes atomically with
  the approval decision rather than with the code
  ({{deferred-sequencing}}).

## Deferred Approval State Machine {#state-machine}

A deferred approval is in one of these states: `pending`, `approved`,
`denied`, `expired`, or `cancelled`. The Mission Issuer starts a
deferred approval in `pending` and MAY move it to `approved` or
`denied`. The pending lifetime elapsing moves it to `expired`
({{pending-staleness}}), and client cancellation under the deferred
substrate moves it to `cancelled`
({{I-D.draft-gerber-oauth-deferred-token-response}}). `approved`,
`denied`, `expired`, and `cancelled` are terminal.

~~~ text
       submit (PAR + deferred)
                |
                v
           +---------+  deny             --> denied     (terminal)
           | pending |  lifetime elapsed --> expired    (terminal)
           +---------+  client cancels   --> cancelled  (terminal)
             |
   approve   |
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

## The Approval Decision Set {#decision-set}

This section is OPTIONAL and experimental. The issuance profile
records exactly one accountable Approver and defers approval-authority
provenance to a governance layer
({{I-D.draft-mcguinness-oauth-mission}}). An enterprise review
surface often is that governance layer: the decision may involve
several principals, a threshold rule, and a delegation-of-authority
policy, and an auditor later needs to prove not only who approved but
under which authority the approval was valid.

A Mission Issuer MAY record an **approval decision set** alongside
the approval event, retained with the Mission record for its audit
horizon and joined by `approval_event_id`:

- `approval_policy`: an identifier and version for the policy
  governing who may approve this proposal (the deployment's
  delegation-of-authority matrix);
- `threshold`: the rule the recorded assertions satisfied; and
- `assertions`: one or more decision assertions, each carrying the
  asserting principal as an (`iss`, `sub`) pair, a `kind` of `human`,
  `service`, or `policy`, the decision, the decision time, and
  optionally the provenance under which that principal was authorized
  to decide and a reason.

The set is governance evidence, not a wire artifact. It never appears
on tokens or in any protocol message; the Mission record still
carries exactly one accountable `approver`, the principal the
`approval_policy` designates as accountable for the committed
decision, and every downstream projection is unchanged. An approval
whose recorded assertions do not satisfy the declared
`approval_policy` threshold MUST NOT commit, and a committed set is
immutable. The ordinary one-person approval is the degenerate case, a
single human assertion, and need not be recorded at all. Where
consent evidence is claimed, each human assertion's disclosure is
committed as the consent-evidence profile requires
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}); a `policy`
assertion carries its policy identifier and version, which is the
family's provenance chain for non-human approval (policy approves the
instance because a human approved the policy). Consent evidence's
`co_approvals` and `approval_authority` members
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}) are this
record's consent-evidence projection; where both are recorded they
MUST agree, and the decision set governs.

~~~ json
{
  "approval_event_id": "ape_7Kq2mR9tW4xY",
  "approval_policy": { "id": "dlg-matrix", "version": "v7" },
  "threshold": "2-of-2",
  "assertions": [
    { "approver": { "iss": "https://login.example.com",
        "sub": "manager@example.com" },
      "kind": "human", "decision": "approve",
      "decided_at": "2026-09-30T16:58:11Z",
      "provenance": "role:finance-manager" },
    { "approver": { "iss": "https://as.example.com",
        "sub": "policy:finance-charter" },
      "kind": "policy", "decision": "approve",
      "decided_at": "2026-09-30T16:58:12Z",
      "provenance": "dlg-matrix:v7#agent-charters" }
  ]
}
~~~

## Queue Pressure {#queue-pressure}

Deferral turns the review surface into a queue a client can flood. The
Mission Issuer MUST bound the number of concurrent pending proposals
per (client, Approver) pair, refusing further submissions until the
queue drains. It SHOULD collapse pending proposals carrying an
identical `intent_hash` into a single review item, SHOULD rate-limit
reviewer notifications, and SHOULD log a queue flood as a security
event, alongside the decline-suppression detection the consent
evidence profile describes
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

Collapsing identical proposals is a review-surface convenience and does
not merge their outcomes: one approval decision MUST resolve exactly
one pending approval, and the Mission Issuer MUST re-queue or deny the
others rather than mint a Mission for each. A single consent therefore
mints at most one Mission.

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
  "mission_id": "msn_7Wq3nR8tV2xK5pL9yD4sB6zE1mC0fJ-" }
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
  {{pending-staleness}} and the queue bounds of {{queue-pressure}}.

A Mission Issuer that records approval decision sets additionally
commits only approvals whose assertions satisfy the declared
`approval_policy` threshold, and retains each committed set,
immutable, for the Mission's audit horizon ({{decision-set}}).

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

An approval decision set ({{decision-set}}) is evidence about the
approval, never a second authorization surface: the accountable
`approver` on the Mission record remains the principal every
downstream check and projection uses, and a forged or padded
assertion set changes nothing an enforcement point consumes. Its
threat is to auditability, not authority, and its integrity rests on
the issuer's record retention like the approval event itself.

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
