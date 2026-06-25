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
  RFC9396:
  I-D.draft-gerber-oauth-deferred-token-response:
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
  I-D.draft-mcguinness-oauth-mission-shaping:
    title: "Mission Intent Shaping for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-shaping-latest
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-consent-evidence-latest
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-expansion-latest

--- abstract

The Mission-Bound Authorization for OAuth 2.0 profile records an
approval event at which an Approver consents to a Mission's derived
Authority Set, but it treats that event as immediate. A human review of
an agent's proposed Mission is often asynchronous and frequently
results in approval of a narrowed subset rather than an all-or-nothing
decision. This document defines an OPTIONAL Mission Deferred Approval
profile. It profiles OAuth Deferred Token Response so a Mission approval
can be deferred and polled, and adds a revisable approval mode in which
the Authorization Server, when it can grant only a narrowed version of
the proposed Mission, invites the client to push a narrowing revision
and continue the same deferred approval rather than abandon it and start
over. Revisions can only narrow the proposed Mission.

--- middle

# Introduction

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} (the
"issuance profile") derives an Authority Set from a submitted Mission
Intent and records an approval event at which an Approver consents to
that authority. It specifies what the approval commits, not how the
approval is obtained over time. Two facts about agent approval are left
unspecified:

- A human Approver review is asynchronous: the agent submits a proposed
  Mission and must wait, sometimes for a long time, for a decision.
- A reviewer commonly approves a narrowed subset of the proposed
  Mission, not an all-or-nothing outcome. With no way to revise in
  place, the agent must abandon the proposal and submit a new one,
  losing the approval state and any preceding work.

This document supplies both. It profiles OAuth Deferred Token Response
{{I-D.draft-gerber-oauth-deferred-token-response}} (the "deferred
substrate") so a Mission approval can be deferred and polled, and it
defines a **revisable** approval mode: when the Authorization Server can
grant only a narrowed version of the proposed Mission, it signals which
dimensions it refused and invites the client to push a narrowing
revision, then continues the same deferred approval. The client keeps
its place; the approval resolves over the narrowed proposal.

This is narrowing only. A revision can reduce the proposed Mission; it
can never broaden it. Widening an approved Mission is a different
operation with its own fresh approval ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

# Status: An OPTIONAL Extension {#optional-status}

This document is OPTIONAL. A deployment that obtains Mission approvals
synchronously, or that abandons and resubmits when a reviewer narrows a
proposal, is fully conformant to the issuance profile and is unaffected
by this document. It places no new requirement on the issuance profile.

A deployment claims this profile only when it defers Mission approvals
under the deferred substrate or accepts revisable approvals. The
approval event, the Authority Set, the subset rule, and the integrity
anchors are unchanged; this document governs only how the approval is
reached over time.

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

Revision:
: A narrowing of the proposed Mission, submitted by the client while the
  approval is deferred, that replaces the proposed Mission's Authority
  Set with a subset of it.

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

Deferral changes only the timing of the approval event. The Authority
Set the token is issued against, its `authority_hash`, and the recorded
consent are exactly as in a synchronous approval.

# Revisable Approval {#revisable}

A client signals that it accepts a narrowing revision by including
`revisable` among its `completion_mode` values alongside `deferred`:

~~~ text
completion_mode=deferred revisable
~~~

`revisable` is a completion-mode value registered in the deferred
substrate's OAuth Completion Mode Values registry ({{iana}}). It
authorizes only the revision handshake defined here. A Mission Issuer
MUST NOT invite a revision unless the client offered `revisable`.

## The Revision Required signal {#revision-required}

When the Mission Issuer determines that it cannot approve the proposed
Mission as stated, but could approve a sufficiently narrowed version,
and the client offered `revisable`, it returns the deferred substrate's
`authorization_pending` response extended with revision parameters
rather than resolving to `access_denied`. Using the substrate's existing
pending response, as the substrate permits a profile to do, keeps a
client that does not implement this profile polling normally; only a
revisable-aware client acts on the added parameters.

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "authorization_pending",
  "deferral_code": "dc_9P2K7zT1mX8b3N",
  "revision_required": true,
  "clarification_handle": "ch_4QFJ3P9",
  "rejected_scope": "crm:write",
  "rejected_authorization_details": [
    { "type": "payment", "limit": "10000" }
  ],
  "expires_in": 420,
  "interval": 5
}
~~~

`revision_required` (boolean) and `clarification_handle` (string) are
REQUIRED on this response. `rejected_scope` and
`rejected_authorization_details` are OPTIONAL; they tell the agent which
dimensions of the proposed Mission were refused so it can plan a
narrowed revision without further out-of-band interaction. A Mission
Issuer MAY omit them when disclosure would reveal sensitive policy
state.

The `clarification_handle` is bound to the deferred approval and
authorizes one revision submission. It is not a token, grant, or
continuation handle, and it is sender-constrained to the same key as the
`deferral_code` ({{I-D.draft-gerber-oauth-deferred-token-response}}). A
client MUST NOT treat `revision_required`, the rejected dimensions, or
the handle as evidence of any granted authority; the proposed Mission
remains unapproved.

## Submitting a revision {#revision-submission}

The client submits the narrowed Mission Intent to the PAR endpoint
{{RFC9126}} with the `clarification_handle` as an additional parameter,
sender-constrained as the deferred substrate requires. The Mission
Issuer:

1. verifies the `clarification_handle` is bound to a deferred approval
   in the revision-required condition, is unexpired and single-use, and
   matches the client and sender-constraint of the deferred approval;
2. derives the Authority Set for the revised Intent and verifies it is a
   subset of the proposed Mission's Authority Set under the issuance
   profile's subset rule ({{I-D.draft-mcguinness-oauth-mission}}), with
   `authorization_details` narrowing per the inclusion semantics of
   {{RFC9396}}; the revision MUST narrow at least the refused dimensions
   and MUST NOT broaden any dimension;
3. invalidates the `clarification_handle`;
4. replaces the proposed Mission's Authority Set with the revised one
   and re-reviews it.

The client continues polling the existing `deferral_code`; the revision
does not start a new approval. If the Mission Issuer returns a PAR
`request_uri`, it is an artifact of PAR and MUST NOT be used to start a
separate authorization transaction.

If the revision is not a subset, or otherwise fails validation, the PAR
endpoint returns an error and the deferred approval stays in the
revision-required condition. Because the handle is single-use, the
client obtains a new `clarification_handle` from a subsequent
`authorization_pending` response before retrying. A Mission Issuer
SHOULD bound the number of revision cycles per deferred approval and
SHOULD resolve to `access_denied` when no acceptable narrowing remains.

# Integration with the Mission Suite {#integration}

Consent evidence:
: A revised proposed Mission is a different disclosure. Where a
  deployment records Consent Evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), the
  re-reviewed revision MUST get a fresh `consent_rendering_hash`; prior
  consent does not transfer to the narrowed proposal.

Shaping:
: The `rejected_scope` and `rejected_authorization_details` parameters
  are the machine-readable input a client-side shaper
  ({{I-D.draft-mcguinness-oauth-mission-shaping}}) uses to plan the
  narrowed revision. Shaping narrows a proposal before submission; this
  profile narrows it during review. Together they let an orchestrator
  propose, learn what was refused, and re-propose without losing state.

Integrity anchors:
: The approval commits the final, narrowed Authority Set. The
  `intent_hash` and `authority_hash` are computed over the revised
  Mission Intent and Authority Set actually approved, not the originating
  proposal.

This profile narrows only, and only while an approval is deferred. It is
distinct from widening an approved Mission, which requires a fresh
approval ({{I-D.draft-mcguinness-oauth-mission-expansion}}), and from
drawing authority from a pre-consented ceiling without a per-step human
(progressive authorization,
{{I-D.draft-mcguinness-oauth-mission-expansion}}).

# Worked Example {#example}

Agent `s6BhdRkqt3`, acting for `alice`, proposes a Mission to reconcile
Q3 invoices that asks for both read and write on the ERP. It submits the
Mission Intent through PAR and opts in to both deferral and revision on
the token request:

~~~ http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=SplxlOBeZQQYbYS6WxSbIA&
client_id=s6BhdRkqt3&
completion_mode=deferred%20revisable
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

The agent polls with the deferred grant type. On review `alice` approves
read but not write. Rather than deny, the Mission Issuer narrows and
invites a revision, extending the pending response:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{ "error": "authorization_pending",
  "deferral_code": "dfc_7M2R4kP9sT1x",
  "revision_required": true,
  "clarification_handle": "clh_4QFJ3P9wZ2",
  "rejected_authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"] } ],
  "expires_in": 540, "interval": 5 }
~~~

The agent pushes a narrowed Mission Intent, dropping the write, to PAR
with the clarification handle:

~~~ http
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

mission_intent=%7B...read-only%20Q3%20invoices...%7D&
client_id=s6BhdRkqt3&
clarification_handle=clh_4QFJ3P9wZ2
~~~

The Mission Issuer verifies the handle, confirms the revised Authority
Set is a subset of the proposed one, updates the deferred approval, and
re-reviews (here, policy auto-approves the now-narrower read-only
Mission). The agent keeps polling the same `deferral_code`, which now
resolves to a Mission-bound token over the final, narrowed authority:

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
  "mission": {
    "id": "msn_8RfX2Lqv9TqMv4z7sA2bN1k0YpEdHc9-",
    "origin": "https://as.example.com",
    "authority_hash":
      "sha-256:l3KvZ4mP5x0wQrR6tY2nD9bM7sX1cF8gH2vJ4kE5pNQ" } }
~~~

The agent never abandoned its request; the approval resolved over the
narrowed proposal, and the committed `authority_hash` is over the
read-only Authority Set actually approved.

# Conformance {#conformance}

A Mission Issuer conforming to this profile MUST:

- support the deferred substrate for Mission approvals it defers;
- offer a revision only when the client signaled `revisable`;
- enforce that a revision is a subset of the proposed Mission under the
  issuance profile's subset rule, never a broadening;
- treat each `clarification_handle` as single-use and
  sender-constrained to the deferred approval; and
- commit the approval over the final narrowed Authority Set.

A client conforming to this profile MUST treat a revision-required
response as unapproved, submit only narrowing revisions, and continue
polling the existing `deferral_code`.

# Security Considerations {#security-considerations}

The deferred substrate's security considerations apply in full,
including deferral-code entropy, sender-constraint continuity,
cancellation, and oracle resistance. This section adds only what the
revision handshake introduces.

- Narrowing only. A revision MUST NOT broaden the proposed Mission on
  any dimension. The Mission Issuer enforces the subset relation per
  parameter (scope, resource, audience, `authorization_details`) before
  re-review.
- Single-use handle. A `clarification_handle` MUST be invalidated after
  one submission, success or failure. A new handle is issued on a
  subsequent revision-required response.
- Sender-constraint continuity. The handle MUST be sender-constrained to
  the same key as the `deferral_code`. An attacker holding the handle
  without the key cannot push a revision.
- Handle lifetime. The handle lifetime MUST NOT exceed the remaining
  lifetime of the `deferral_code`, and SHOULD be shorter when the handle
  is exposed to orchestration layers outside the OAuth client.
- Stale consent. A re-reviewed revision MUST be presented to the
  reviewer as a new disclosure with a fresh consent commitment
  ({{integration}}); prior consent does not transfer.
- Policy disclosure. `rejected_scope` and `rejected_authorization_details`
  can reveal policy boundaries; a Mission Issuer SHOULD disclose only the
  minimum needed to narrow and MAY omit them.
- Revision bounding. A Mission Issuer SHOULD bound revision cycles per
  deferred approval and log excessive cycles as a security event.

# Privacy Considerations {#privacy-considerations}

The rejected-dimension parameters and the revision history reveal what
authority an agent sought and was refused. A Mission Issuer SHOULD treat
them as sensitive, minimize what it discloses, and retain revision
history under the same controls as other approval-event records.

# IANA Considerations {#iana}

This document registers one value in the OAuth Completion Mode Values
registry established by the deferred substrate
({{I-D.draft-gerber-oauth-deferred-token-response}}):

- `revisable`: Change Controller IETF; Reference this document,
  {{revisable}}.

This document registers the following in the "OAuth Parameters"
registry. For each: Change Controller IETF; Reference this document,
{{revision-required}}.

- `revision_required` (token endpoint response)
- `clarification_handle` (token endpoint response, PAR request)
- `rejected_scope` (token endpoint response)
- `rejected_authorization_details` (token endpoint response)

PAR {{RFC9126}} carries the revision as authorization-request parameters
without a distinct usage location, so the pushed submission of the
narrowed Intent and `clarification_handle` needs no separate
registration.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and profiles OAuth Deferred Token Response for asynchronous,
revisable Mission approval.
