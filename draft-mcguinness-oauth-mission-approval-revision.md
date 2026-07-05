---
title: "Mission Approval Revision for OAuth 2.0"
abbrev: "OAuth Mission Approval Revision"
category: std

docname: draft-mcguinness-oauth-mission-approval-revision-latest
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
 - revision
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-approval-revision.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6749:
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
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-approval-latest

informative:
  I-D.draft-mcguinness-mission-shaping:
    title: "Mission Intent Shaping"
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-shaping-latest
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

Mission Deferred Approval for OAuth 2.0 defers a Mission approval and
lets a client poll for the decision. A reviewer commonly approves a
narrowed subset of a proposed Mission rather than an all-or-nothing
outcome. This document defines an experimental revisable approval mode
on top of the deferred approval profile: when the Authorization Server
can grant only a narrowed version of the proposed Mission, it invites
the client to push a narrowing revision and continue the same deferred
approval rather than abandon it and start over. Revisions can only
narrow the proposed Mission.

--- middle

# Introduction

Mission Deferred Approval
{{I-D.draft-mcguinness-oauth-mission-approval}} (the "deferred approval
profile") moves the issuance profile's approval event
({{I-D.draft-mcguinness-oauth-mission}}) to an asynchronous review
surface: the client submits a proposed Mission, receives the deferred
substrate's pending response
({{I-D.draft-gerber-oauth-deferred-token-response}}), and polls until
the approval resolves. When a reviewer will grant only a narrowed subset
of the proposal, that profile resolves to `access_denied` and the client
submits a fresh, narrower Mission Intent.

This document defines a **revisable** approval mode that keeps the
deferred approval open instead: the Mission Issuer signals which
dimensions it refused and invites the client to push a narrowing
revision, then continues the same deferred approval. The client keeps
its place; the approval resolves over the narrowed proposal.

This is narrowing only. A revision can reduce the proposed Mission; it
can never broaden it. Widening an approved Mission is a different
operation with its own fresh approval
({{I-D.draft-mcguinness-oauth-mission-expansion}}).

# Status: An EXPERIMENTAL Extension {#optional-status}

This document is OPTIONAL and **experimental**: adopt it for
evaluation, not as a stable interface. The stable path needs no
revision mechanism at all. A deferred approval that cannot be granted
as proposed resolves to `access_denied`, and the client submits a
fresh, narrower Mission Intent via PAR {{RFC9126}}; the deferred
approval profile and the issuance profile fully specify that path. What
this document adds over deny-and-resubmit is continuity of a single
deferred approval and machine-readable refusal hints, at the cost of a
revision artifact and a per-dimension narrowing verification.

A deployment claims this profile only when it offers or consumes the
revision handshake. A Mission Issuer or client that does not implement
it remains fully conformant to the deferred approval profile: a
revisable-unaware client polling a deferred approval observes only the
substrate's ordinary pending responses ({{revision-required}}).

Like the deferred approval profile, this document tracks the
in-progress deferred substrate
({{I-D.draft-gerber-oauth-deferred-token-response}}) and will track it
as it evolves.

# Relationship to the Deferred Approval Profile {#issuance-relationship}

This document depends normatively on the deferred approval profile
{{I-D.draft-mcguinness-oauth-mission-approval}}, on the issuance
profile {{I-D.draft-mcguinness-oauth-mission}}, and on the deferred
substrate {{I-D.draft-gerber-oauth-deferred-token-response}}, and is
not implementable alone. It reuses, without restating, the deferred
approval profile's sequencing of the approval event and its state
machine, the issuance profile's Mission Intent, authority derivation,
subset rule, and integrity anchors, and the deferred substrate's
deferral response, continuation polling, cancellation, and
sender-constraint rules. It uses Proposed Mission as the deferred
approval profile defines it.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

Revision:
: A narrowing of the proposed Mission, submitted by the client while the
  approval is deferred, that replaces the proposed Mission's Authority
  Set with a subset of it.

# The Revision-Required State {#state-machine}

This profile extends the deferred approval profile's state machine
({{I-D.draft-mcguinness-oauth-mission-approval}}) with one state,
`revision_required`. The Mission Issuer:

- MAY move `pending` to `revision_required` instead of `denied` when
  the client offered `revisable` ({{revisable}});
- returns `revision_required` to `pending` on an accepted revision
  ({{revision-submission}}); and
- accepts a revision only while in `revision_required`.

`approved` and `denied` remain the terminal states. Resolving a
deferred approval and replacing its proposed Mission with a revision
are atomic with respect to each other: a concurrent approval of a
proposal that a revision has superseded cannot commit, and a revision
accepted after the approval resolved cannot reopen it.

~~~ text
       submit (PAR + deferred)
                |
                v
           +---------+   accept revision   +------------------+
           | pending |<--------------------| revision_required|
           +---------+                     +------------------+
             |  |  |                              ^
   approve   |  |  | needs narrowing              |
             |  |  +------------------------------+
             |  |
             |  +----------------> denied  (terminal)
             v
          approved  (terminal; Mission created active)
~~~

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
`revisable` has effect only together with `deferred`; a Mission Issuer
that receives `revisable` without `deferred` MUST ignore it, because
there is no deferred approval to revise.

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
  "revision_handle": "rvh_4QFJ3P9",
  "rejected_scope": "crm:write",
  "rejected_authorization_details": [
    { "type": "payment", "limit": "10000" }
  ],
  "expires_in": 420,
  "interval": 5
}
~~~

`revision_required` (boolean) and `revision_handle` (string) are
REQUIRED on this response. `rejected_scope` and
`rejected_authorization_details` are OPTIONAL; they name the dimensions
of the proposed Mission that were refused so the agent can plan a
narrowed revision without further out-of-band interaction. A Mission
Issuer MAY omit them when disclosure would reveal sensitive policy
state.

`rejected_scope` is a space-delimited list of scope tokens, using the
`scope` syntax of {{RFC6749}}. `rejected_authorization_details` is an
array of authorization-details-shaped subtrees that the re-derived
Authority Set MUST exclude or narrow: each subtree names a `type` and
the members within it that must not survive re-derivation unchanged. The
Mission Issuer verifies per-dimension narrowing after it re-derives the
Authority Set from the revised Intent ({{revision-submission}}); the
client cannot author the Authority Set, so its obligation is scoped to
the Intent members it does author (the `resources`, the
`mission_expiry`, and the free-text `constraints`), which it revises to
drive that narrowing.

The `revision_handle` is bound to the deferred approval and
authorizes one revision submission. It is not a token, grant, or
continuation handle, and it is sender-constrained to the same key as the
`deferral_code` ({{I-D.draft-gerber-oauth-deferred-token-response}}). A
client MUST NOT treat `revision_required`, the rejected dimensions, or
the handle as evidence of any granted authority; the proposed Mission
remains unapproved. Like the `deferral_code`, the `revision_handle` is
pending-request state, not a grant
({{I-D.draft-mcguinness-oauth-mission-approval}}).

## Submitting a revision {#revision-submission}

The client submits the narrowed Mission Intent to the PAR endpoint
{{RFC9126}} with the `revision_handle` as an additional parameter,
sender-constrained as the deferred substrate requires. The Mission
Issuer:

1. verifies the `revision_handle` is bound to a deferred approval
   in the revision-required condition, is unexpired and single-use, and
   matches the client and sender-constraint of the deferred approval;
2. re-derives the Authority Set for the revised Intent, under the same
   `policy_version` that governed the proposed Mission, and verifies it
   is a subset of the proposed Mission's Authority Set under the issuance
   profile's subset rule ({{I-D.draft-mcguinness-oauth-mission}}), with
   `authorization_details` narrowing per the inclusion semantics of
   {{RFC9396}}. The re-derived Authority Set MUST exclude or narrow every
   dimension named in `rejected_scope` or
   `rejected_authorization_details` ({{revision-required}}), verified per
   dimension, and MUST NOT broaden any dimension. Deriving under the
   proposed Mission's `policy_version` keeps the subset comparison
   reproducible; if policy has changed since the proposal, the Mission
   Issuer re-derives the proposed Authority Set under the current policy
   to re-establish the baseline before comparing, or refuses the
   revision;
3. invalidates the `revision_handle`;
4. replaces the proposed Mission's Authority Set with the revised one
   and re-reviews it.

The client continues polling the existing `deferral_code`; the revision
does not start a new approval. If the Mission Issuer returns a PAR
`request_uri`, it is an artifact of PAR and MUST NOT be used to start a
separate authorization transaction.

## Revision Errors {#revision-errors}

The PAR endpoint reports a failed revision with a specific error:

- An expired or already-consumed `revision_handle` yields
  `invalid_grant`.
- A malformed revision (unparseable, or structurally invalid against the
  Mission Intent member definitions) yields `invalid_request`.
- A revision whose re-derived Authority Set does not narrow every
  dimension named in `rejected_scope` or `rejected_authorization_details`
  yields `revision_not_narrowing` ({{iana}}).
- When the deferral resolved (to `access_denied`, `expired_token`, or an
  approval) while the revision was in flight, the endpoint yields
  `invalid_grant` and the resolution is conveyed on the next poll of the
  `deferral_code`.

For example, a revision that keeps a refused write action yields:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "revision_not_narrowing",
  "error_description":
    "The re-derived Authority Set retains journal-entries.write"
}
~~~

A malformed revision leaves the `revision_handle` reissuable: because the
submission never advanced the approval, the client obtains a new handle
from a subsequent `authorization_pending` response and retries. A
consumed handle, and a handle whose deferral has resolved, are not
reissuable.

A Mission Issuer MUST bound the number of revision cycles per deferred
approval and MUST resolve to `access_denied` once the bound is reached or
no acceptable narrowing remains, so a client cannot drive an unbounded
revision loop.

A revised proposal remains subject to the deferred approval profile's
pending lifetime and staleness rules
({{I-D.draft-mcguinness-oauth-mission-approval}}): a decision after a
`policy_version` or capability-catalog change is made over a re-derived,
re-rendered proposal.

# Integration with the Mission Suite {#integration}

Consent evidence:
: A revised proposed Mission is a different disclosure. Where a
  deployment records Consent Evidence
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), the
  re-reviewed revision MUST get a fresh `consent_rendering_hash`; prior
  consent does not transfer to the narrowed proposal. Each
  revision-required outcome produces Consent Evidence with decision
  `narrowed`, carrying the reviewed disclosure's `consent_rendering_hash`
  and the refused dimensions. The final evidence for the resulting
  approval MAY carry `predecessor_intent_hashes` committing the revision
  chain.

Shaping:
: The `rejected_scope` and `rejected_authorization_details` parameters
  are the machine-readable input a client-side shaper
  ({{I-D.draft-mcguinness-mission-shaping}}) uses to plan the
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
approval ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

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
defers. The agent polls with the deferred grant type. On review `alice`
approves read but not write. Rather than deny, the Mission Issuer
narrows and invites a revision, extending the pending response:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{ "error": "authorization_pending",
  "deferral_code": "dfc_7M2R4kP9sT1x",
  "revision_required": true,
  "revision_handle": "rvh_4QFJ3P9wZ2",
  "rejected_authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"] } ],
  "expires_in": 540, "interval": 5 }
~~~

Where the deployment records Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), this
revision-required outcome is recorded with `decision` `narrowed`,
carrying the reviewed disclosure's `consent_rendering_hash` and the
refused dimensions; the anchor values are those of that profile's
worked disclosure and test vector:

~~~ json
{
  "evidence_id": "cns_5tN8wQ2rD6",
  "mission": {
    "origin": "https://as.example.com",
    "intent_hash":
      "sha-256:P38IRTmTaUESJ5RpCw1WXmIqfsQmYek7zxiQWERcq-E",
    "authority_hash":
      "sha-256:H3xcKuSglGecACyY2qGQYunTGqIalyeXS1Qr0dCcgjs"
  },
  "approver": {
    "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR"
  },
  "narrowed_at": "2026-06-30T18:02:00Z",
  "decision": "narrowed",
  "refused_dimensions": {
    "rejected_authorization_details": [
      { "type": "mission_resource_access",
        "resource": "https://erp.example.com",
        "actions": ["journal-entries.write"] }
    ]
  },
  "policy_version": "approval-policy:v12",
  "sequence": 88126,
  "disclosure": {
    "uri": "https://as.example.com/consent-evidence/disc_4pQ9z",
    "consent_rendering_hash":
      "sha-256:UadIff2z6aIb50BR8aytdoi3odBdWvLsRzyLFIC4wwM"
  },
  "evidence_envelope": {
    "format": "jws-compact",
    "value": "eyJhbGciOiJFUzI1NiIsImtpZCI6ImNvbnNlbnQt..."
  }
}
~~~

No Mission exists yet, so the `mission` descriptor carries the
proposal's anchors and no `id`.

The agent pushes a narrowed Mission Intent, dropping the write, to PAR
with the revision handle:

~~~ http
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

mission_intent=%7B...read-only%20Q3%20invoices...%7D&
client_id=s6BhdRkqt3&
revision_handle=rvh_4QFJ3P9wZ2
~~~

The Mission Issuer verifies the handle, confirms the revised Authority
Set is a subset of the proposed one, updates the deferred approval, and
returns it to `pending`. `alice` reviews the narrowed read-only proposal
and approves it. Every revision resolution requires a fresh approval
event with its own rendering; prior consent does not transfer, and the
recorded `approver` is the principal who approved the final set. The
agent keeps polling the same `deferral_code`, which now resolves to a
Mission-bound token over the final, narrowed authority:

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
issuance profile defines. The agent never abandoned its request; the
approval resolved over the narrowed proposal, and the committed
`authority_hash` is over the read-only Authority Set actually approved.

# Conformance {#conformance}

A Mission Issuer conforming to this profile is a conforming Mission
Issuer of the deferred approval profile
({{I-D.draft-mcguinness-oauth-mission-approval}}) and MUST additionally:

- offer a revision only when the client signaled `revisable`;
- enforce that a revision is a subset of the proposed Mission under the
  issuance profile's subset rule, never a broadening;
- treat each `revision_handle` as single-use and
  sender-constrained to the deferred approval; and
- commit the approval over the final narrowed Authority Set.

A client conforming to this profile MUST treat a revision-required
response as unapproved, submit only narrowing revisions, and continue
polling the existing `deferral_code`.

# Security Considerations {#security-considerations}

The deferred substrate's and the deferred approval profile's security
considerations apply in full, including deferral-code entropy,
sender-constraint continuity, cancellation, oracle resistance, and the
approval-event authentication requirements on the asynchronous review
surface. This section adds only what the revision handshake introduces.

- Narrowing only. A revision MUST NOT broaden the proposed Mission on
  any dimension. The Mission Issuer enforces the subset relation per
  parameter (scope, resource, audience, `authorization_details`) before
  re-review.
- Single-use handle. A `revision_handle` MUST be invalidated after
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
- Revision bounding. A Mission Issuer MUST bound revision cycles per
  deferred approval and resolve to `access_denied` at the bound
  ({{revision-submission}}), and SHOULD log excessive cycles as a
  security event, so a client cannot drive an unbounded reshape-and-retry
  loop to wear down a reviewer.

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

- `revision_required` (token response)
- `revision_handle` (token response)
- `rejected_scope` (token response)
- `rejected_authorization_details` (token response)

PAR {{RFC9126}} carries authorization-request parameters without a
distinct usage location, so the pushed submission of the narrowed Intent
and `revision_handle` needs no separate registration, as the issuance
profile states ({{I-D.draft-mcguinness-oauth-mission}}).

This document registers the following in the "OAuth Extensions Error"
registry:

- Name: `revision_not_narrowing`
- Usage Location: token error response
- Protocol Extension: Mission Approval Revision (this document)
- Change Controller: IETF
- Reference: this document, {{revision-errors}}

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and extends Mission Deferred Approval with an experimental
narrowing-revision handshake.
