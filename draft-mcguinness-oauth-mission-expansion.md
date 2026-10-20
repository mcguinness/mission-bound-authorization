---
title: "Mission Expansion for OAuth 2.0"
abbrev: "OAuth Mission Expansion"
category: std

docname: draft-mcguinness-oauth-mission-expansion-latest
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
 - expansion
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6749:
  RFC9126:
  RFC9396:
  RFC8693:
  RFC8705:
  RFC8785:
  RFC9449:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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

informative:
  RFC8126:
  RFC9470:
  RFC9562:
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
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
  I-D.draft-gerber-oauth-deferred-token-response:
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-containment:
    title: "Mission Containment for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-containment.html
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
  I-D.draft-mcguinness-oauth-mission-child-delegation:
    title: "Mission Child Delegation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-child-delegation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-continuation:
    title: "Mission Continuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-continuation.html
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
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
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
  I-D.draft-mcguinness-oauth-mission-template:
    title: "Mission Template for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-template.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-discharge:
    title: "Mission Entry Discharge for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-discharge.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 commits a Mission's
authority at a single approval event. Enlarging that authority
requires a new approval, recorded as a successor Mission. This
document defines Mission Expansion, the optional extension that
obtains that approval.

A client requests expansion with an OAuth 2.0 Token Exchange that
presents the predecessor Mission's sender-constrained access token. A
fresh approval creates the successor, whose authority comes only from
that approval and which carries a `predecessor` member linking it to
the Mission it replaces. When the successor activates, the
predecessor is terminated with reason `superseded`; an expansion that
never completes leaves the predecessor active. A deployment that never
expands a Mission is unaffected by this document.

--- middle

# Introduction

Mission-Bound Authorization for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission}} (the "issuance profile") makes
a Mission a first-class OAuth artifact: a structured, human-approved,
integrity-bound task whose authority bounds and outlives every token
an agent derives. The issuance profile commits the Authority Set once,
at the approval event, and defines no mid-stream authorization
upgrade. Widening authority requires a new approval and a successor
Mission, as this document specifies.

An agent's task does not always stay within the authority approved
for it. The agent can meet an action that the approved Authority Set
does not cover but that the deployment's governance policy would
permit under a fresh consent. Expansion is the governed path from that
shortfall to a new approval. It does not modify or widen the existing Mission. It creates a new Mission through the issuance profile's own
approval event, with its own integrity anchors and Mission record,
linked to the Mission it replaces. The successor's authority comes
only from that approval.

The mechanism rests on three additions to the issuance profile:

- an expansion request, an {{RFC8693}} token exchange bound to the
  predecessor by possession of the predecessor's Mission-bound access
  token ({{expansion-request}});
- a `predecessor` lineage member on the resulting Mission
  ({{predecessor-member}}); and
- the `superseded` termination reason for the predecessor
  ({{superseded-state}}), with the reconciliation rules that keep
  concurrent expansions consistent ({{reconciliation}}).

## Relationship to the Issuance Profile {#relationship}

This document depends normatively on the issuance profile and is not
implementable alone. It reuses the following from that profile
without restating them:

- the Mission Intent and its submission via PAR;
- authority derivation and the subset rule;
- the approval event and its integrity anchors;
- the Mission record and the `mission` claim; and
- the lifecycle and issuance gating.

It uses the terms Agent (Client), Subject, Approver, Mission Issuer,
Mission Intent, Authority Set, Mission, and derived token as defined
there. "The issuance profile" without a section reference means
{{I-D.draft-mcguinness-oauth-mission}} as a whole.

This document is an optional, layered extension and changes nothing
in the issuance profile. A deployment that implements the issuance
profile and never expands a Mission is fully conformant to that
profile and unaffected by this document: it issues no expansion
request, records no `predecessor` member, and never terminates a
Mission with reason `superseded`. The issuance profile's lifecycle
(`active`, and `terminated` with reason `revoked` or `expired`) is
complete without expansion. A Mission Issuer claims conformance to
this document only under one of the targets of {{conformance}}.

## Scope {#scope}

This document defines:

- the expansion request and its binding to the predecessor
  ({{expansion-request}});
- adjudication, completion, and successor activation
  ({{adjudication}});
- the `predecessor`, `related_to`, and `successor` lineage members
  ({{predecessor-member}});
- the predecessor's transition to `terminated` with reason
  `superseded` ({{superseded-state}});
- replacement expansion, the only expansion mode ({{replacement}});
- concurrent-expansion reconciliation, with a closed set of
  reconciliation status codes ({{reconciliation}});
- creation idempotency for Mission-creation exchanges
  ({{creation-idempotency}}); and
- the expansion denial reasons and the Mission Denial Reasons
  registry ({{denial-reasons}}).

This document does not define:

- a way to widen an existing Mission in place; expansion always
  creates a new Mission;
- runtime per-action enforcement, or how a denial is classified as
  expansion-eligible ({{eligibility}},
  {{I-D.draft-mcguinness-mission-runtime}});
- branch expansion, in which predecessor and successor both remain
  active ({{replacement}});
- multi-hop or cross-domain expansion: the predecessor's Mission
  Issuer (its `issuer`) adjudicates every expansion; or
- policy-adjudicated expansion within a pre-consented authority
  ceiling, which the experimental progressive authorization companion
  defines ({{I-D.draft-mcguinness-oauth-mission-progressive}}). Under
  this document alone, every expansion is adjudicated by a fresh human
  approval.

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

All JSON shown in this document is non-normative and illustrative; the
member definitions in the surrounding text are authoritative.

The following terms apply in addition to those inherited from the
issuance profile ({{relationship}}).

Predecessor Mission:
: The active Mission an expansion enlarges. It is the baseline for the
  successor and is referenced by the successor's `mission.predecessor`
  member ({{predecessor-member}}).

Successor Mission:
: The Mission a replacement expansion creates through a fresh approval
  event. It carries its own Authority Set, integrity anchors, and
  `mission_id`, and a `predecessor` member linking it to the
  predecessor ({{predecessor-member}}).

Expansion request:
: An {{RFC8693}} token exchange that carries a Mission Intent and
  presents the predecessor Mission's Mission-bound access token as the
  `subject_token`, asking the Mission Issuer to adjudicate a successor
  ({{expansion-request}}).

Successor activation:
: The single atomic step in which the successor Mission becomes
  `active` and the predecessor becomes `terminated` with reason
  `superseded` ({{successor-activation}}).

# Protocol Overview {#overview}

~~~
 Agent (client)               Mission Issuer (AS)
     |                            |
     | denied: action outside     |
     | active Mission's authority |
     |                            |
     | 1. token exchange -------> | resolve predecessor from
     |    subject_token =         | subject_token; verify
     |    predecessor's Mission-  | possession (subject_token
     |    bound access token;     | cnf); gate predecessor
     |    mission_intent          | active
     |                            |
     |                            | 2. complete, one of:
     |                            |
     |    <-- deferral ---------- | (a) deferred: fresh async
     |    ---- poll ------------> |     approval; token on
     |    <-- access token ------ |     approval
     |                            |
     |    <-- interaction req. -- | (b) interactive: the
     |    ---- PAR + handle ----> |     client pushes the
     |    <-- (front channel) --> |     continuation; approval;
     |    ---- code ------------> |     code redemption
     |    <-- access token ------ |
     |                            |
     |         at activation: successor active,
     |         predecessor superseded (atomic)
     v
~~~
{: #fig-flow title="Expansion Protocol Flow"}

{{fig-flow}} shows the protocol:

1. An action is denied because the requested authority is outside the
   active Mission's Authority Set ({{eligibility}}).
2. The client sends an expansion request: an {{RFC8693}} token
   exchange that presents the predecessor's Mission-bound access token
   and carries the successor's Mission Intent ({{expansion-request}}).
   Possession of that token binds the request to one predecessor, so
   the Mission Issuer adjudicates a successor of that predecessor
   rather than an unrelated new Mission.
3. The Mission Issuer verifies the request and derives the successor's
   Authority Set ({{verification-order}}). A request that widens
   nothing is refused.
4. An expansion always widens authority, so a fresh consent supplies
   the broader authority, obtained through the deferred token response
   ({{I-D.draft-gerber-oauth-deferred-token-response}}) or the
   deployment's interactive approval ({{completion-modes}}). The
   successor's authority comes only from that consent.
5. When the successor's authority is issued, the successor activates
   and the predecessor becomes `terminated` with reason `superseded`,
   atomically ({{successor-activation}}). An expansion that never
   completes leaves the predecessor `active`.

## Eligibility {#eligibility}

A client initiates expansion after an action is denied because the
requested authority is outside the active Mission's Authority Set and
the deployment's governance policy permits widening it. The component
that denies the action classifies the denial as expansion-eligible;
this document does not define that classification.

Denials come from different sources:

- A Mission-aware resource server enforces the token's authority
  statelessly and refuses an out-of-bounds action with its usual
  insufficient-authority error ({{I-D.draft-mcguinness-oauth-mission}}).
- Under the runtime enforcement profile
  ({{I-D.draft-mcguinness-mission-runtime}}), a deny is terminal for
  the attempted action, and a request that would broaden the Mission's
  authority is refused, with expansion out of that profile's scope.
  This document defines that expansion.

This document does not require any particular denial source: a client
that knows, by any means, that an action needs authority the active
Mission lacks MAY initiate expansion. An eligible denial is not an
authorization in favor of expansion; whether the Mission Issuer
adjudicates a successor remains its decision ({{adjudication}}).

## Expansion Is Not Step-Up {#not-step-up}

Expansion is distinct from authentication step-up {{RFC9470}}:

- A request denied because an `acr` or `amr` constraint requires fresh
  authentication is satisfied by step-up. The Authority Set does not
  change.
- A request denied because the requested authority is not in the
  active Mission's Authority Set requires expansion. The Authority Set
  is enlarged only through a new approval event.

{{step-up-distinction}} describes the consequence of conflating the
two.

# The Expansion Request {#expansion-request}

To expand a predecessor Mission, the requester MUST prove possession of
the predecessor Mission's authority through a sender-constrained proof,
and a reusable bearer refresh credential MUST NOT be the carrier of
that proof.

This document binds that requirement to an {{RFC8693}} token exchange
at the token endpoint ({{submission}}): the predecessor's own
sender-constrained Mission-bound access token is the `subject_token`,
and possession is proven against that token's confirmation key
({{request-binding}}). The Mission Authority Server profile
({{I-D.draft-mcguinness-mission-authority-server}}) binds the same
requirement to an authenticated-client submission on its token-less
surface; the two are peer bindings of one requirement.

## Token Exchange Request {#submission}

The client sends an {{RFC8693}} token exchange request to the token
endpoint with the following parameters:

`grant_type`:
: REQUIRED. `urn:ietf:params:oauth:grant-type:token-exchange`.

`requested_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:access_token`. This value
  selects expansion: the Mission Issuer returns the successor's
  Mission-bound access token. Child creation, the peer operation on the
  same grant, is selected by the JWT token type
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

`subject_token`:
: REQUIRED. The predecessor Mission's sender-constrained Mission-bound
  access token. This token, not any identifier, selects the predecessor
  authoritatively ({{request-binding}}).

`subject_token_type`:
: REQUIRED. `urn:ietf:params:oauth:token-type:access_token`. The
  Mission Issuer MUST reject any other value with `invalid_request`. A
  refresh token MUST NOT be accepted as the `subject_token` for an
  expansion: the possession proof is a sender-constrained access token,
  never a reusable bearer refresh credential.

`actor_token`:
: OPTIONAL. A token identifying the acting agent, per {{RFC8693}}.
  Where it is absent, the request's client authentication identifies
  the acting agent. This document does not restructure any act chain:
  a successor Mission begins its own act chain afresh under its own
  approval.

`actor_token_type`:
: REQUIRED when `actor_token` is present, per {{RFC8693}}.

`mission_intent`:
: REQUIRED. The successor's Mission Intent Submission envelope, per
  {{I-D.draft-mcguinness-oauth-mission}}. Its `intent` is the
  successor's Mission Intent and describes the broadened task: the
  `goal`, `target_resources`, `task_bounds`, and any other Mission
  Intent member the successor needs, including the authority the
  denied action required. Its OPTIONAL `evidence` array carries Intent
  Submission Evidence under that profile's dispatch, refusal, and
  never-authority rules and those of
  {{I-D.draft-mcguinness-oauth-mission-submission-evidence}}. The
  Mission Issuer derives the successor's Authority Set from this
  Intent and bounds it by policy exactly as for any Mission; this
  document adds no authority-derivation rule.

`authorization_details`:
: OPTIONAL. The successor's authority proposal, an ordinary
  {{RFC9396}} token request parameter. It is this exchange's proposal
  carriage and replaces the issuance profile's PAR-only carriage rule;
  that profile's validation, derivation, recording, and hashing
  semantics apply unchanged ({{I-D.draft-mcguinness-oauth-mission}}).
  It is a proposal, never authority: the Mission Issuer derives and
  bounds the successor's Authority Set by policy regardless of what was
  proposed. A successor created from an exchange carrying one records
  `proposed_authority` and `proposal_hash`.

`predecessor`:
: OPTIONAL. A string: the `mission_id` of the predecessor, a
  non-authoritative cross-check and audit value only. The Mission
  Issuer resolves and selects the predecessor from `subject_token`
  ({{request-binding}}); when `predecessor` is present the Mission
  Issuer MUST verify it names that same resolved Mission and refuse a
  mismatch with `invalid_grant`. The `predecessor` parameter does not
  select or authorize a predecessor: a client MUST NOT be able to
  expand a Mission merely by naming its `mission_id`.

`creation_request_id`:
: REQUIRED. The creation idempotency identifier
  ({{creation-idempotency}}): an ASCII string of at most 255 octets,
  opaque to the Mission Issuer beyond equality, that identifies this
  one Mission-creation operation across every completion mode. At
  least 128 bits of client-generated randomness is RECOMMENDED; a UUID
  {{RFC9562}} satisfies this. The Mission Issuer MUST refuse an
  exchange missing it with `invalid_request`.

A `mission_intent` on a token exchange marks it as a Mission-creation
exchange, and its `requested_token_type` selects the operation: the
access-token type selects expansion, and the JWT type selects child
creation ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).
The Mission Issuer MUST refuse with `invalid_request` a token exchange
that carries both a `predecessor` cross-check and the child-delegation
profile's `child_actor`, and an expansion exchange that carries
`child_actor`: the operations do not combine.

The possession proof of {{request-binding}} is presented only on the
token endpoint's authenticated back channel and MUST NOT appear on any
front channel. The token exchange establishes the predecessor binding
and the possession proof in every completion mode; an interactive
completion's front-channel approval ceremony carries only the consent
decision ({{interactive-handoff}}).

The following is an example of an expansion request in the scenario of
{{example}}, with client authentication omitted (line breaks for
display purposes only). The client also opts in to deferred completion
with the deferred token response's `completion_mode` parameter
({{Section 4.1 of I-D.draft-gerber-oauth-deferred-token-response}}):

~~~ http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&requested_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3A
  access_token
&subject_token=eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...
&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3A
  access_token
&mission_intent=%7B%22intent%22%3A%7B%22goal%22%3A%22Reconcile...
&predecessor=msn_QBZj5JSIV6tkkb93ZTvbiz_9dOMMXfJS
&creation_request_id=7c9e6679-7425-40de-944b-e07fc1f90ae7
&completion_mode=deferred
&client_id=s6BhdRkqt3
~~~
{: #fig-request title="Expansion Request"}

The following is an example of the decoded `mission_intent` value. It
raises the journal-entry cap from USD 500 to USD 2,000 and keeps the
rest of the predecessor's task:

~~~ json
=============== NOTE: '\' line wrapping per RFC 8792 ===============

{
  "intent": {
    "goal": "Reconcile Q3 invoices and post adjustments of at most \
      USD 2,000 per journal entry.",
    "target_resources": ["https://erp.example.com"],
    "task_bounds": [
      "Read only invoices issued in 2026-Q3.",
      "Post journal entries of at most USD 2,000 each."
    ],
    "purpose": "urn:example:purpose:reconcile",
    "expires_at": "2026-12-31T23:59:59Z"
  }
}
~~~
{: #fig-intent title="Decoded Successor Mission Intent"}

## Proving Possession of the Predecessor {#request-binding}

The issuance profile resolves a Mission from the credential the client
presents, never from a client-supplied `mission_id`
({{I-D.draft-mcguinness-oauth-mission}}, Section "Binding the Mission
to the Grant"). An expansion resolves the predecessor from the
`subject_token` the client presents and proves possession against
that token's own confirmation:

1. The Mission Issuer MUST resolve the predecessor Mission from
   `subject_token`, applying the issuance profile's token-to-Mission
   resolution for a Mission-bound access token.
2. The Mission Issuer MUST verify that the presenter controls the
   `subject_token`'s own confirmation key: a {{RFC9449}} DPoP proof
   whose key matches the token's `cnf` `jkt`, or the {{RFC8705}}
   mutual-TLS certificate whose thumbprint matches the token's `cnf`
   `x5t#S256`. Possession is proven against the token's confirmation, a
   sender-constrained proof; it is not read from any Mission-record
   field. A `subject_token` that is not sender-constrained cannot carry
   this proof, so the Mission Issuer MUST refuse it with
   `invalid_request`.
3. Where the proof is a DPoP proof, its `jti` is single-use per
   {{RFC9449}}: the Mission Issuer MUST reject a replayed proof.
4. When `predecessor` is present, the Mission Issuer MUST verify the
   resolved Mission is the one it names ({{submission}}).

The confirmation key, not the identifier, authorizes the expansion. A
client that does not hold the predecessor's Mission-bound access token
and its sender-constraint key cannot present a valid `subject_token`,
so it cannot expand the predecessor. No expansion ticket or other new
bearer credential is needed: the client proves possession of a
credential it already holds.

These checks run at the token exchange, before any approval, so the
Mission Issuer confirms that the predecessor is real, active, and
possessed before it prompts an Approver; expansion cannot drive
approval prompts against another party's Mission. The proof gates the
proposal channel (who may put an expansion of this predecessor in
front of the Approver, and who may trigger the atomic supersession),
never the authority: no proof failure can widen anything.

The Mission Issuer MUST record each expansion presentation and count it
toward the deployment's anomaly detection, and the per-predecessor rate
limit ({{policy-probing}}) applies unconditionally. The `subject_token`
is consumed only to resolve and bind the predecessor, never to
refresh, so presenting it has no interaction with refresh token
rotation or replay detection.

Expansion therefore requires a sender-constrained Mission-bound access
token. A deployment that issues only bearer tokens for a Mission, or
none, forgoes expansion of that Mission, and nothing else:

- the work can continue under a freshly approved Mission whose
  disclosure references the work it continues, since a successor's
  authority comes only from fresh consent in any case
  ({{independent-continuation}}); and
- the Subject or an administrator acts on the predecessor at the
  management plane, whose standing is the authenticated principal,
  never a token's possession
  ({{I-D.draft-mcguinness-oauth-mission-status}}).

## Predecessor Must Be Active {#predecessor-active}

The Mission Issuer MUST resolve the predecessor from `subject_token`
and verify it is in the `active` state before adjudicating, and MUST
re-verify it at completion when adjudication is deferred or interactive
({{deferred-window}}). An expansion request against a predecessor that
is not `active` MUST be refused with `invalid_request`
({{Section 2.2.2 of RFC8693}}) and a reconciliation status
({{reconciliation}}):

- if the predecessor made a terminal exit from `active` (it is
  `terminated`, with reason `revoked`, `expired`, already `superseded`
  ({{superseded-state}}), or another), the status is one of the two
  terminal-exit codes, chosen by the attribution rule of
  {{reconciliation}};
- if the predecessor is in a non-terminal non-active state, for example
  `suspended` where the Mission Status profile
  {{I-D.draft-mcguinness-oauth-mission-status}} is deployed, the status
  is `predecessor_not_active`.

This rule extends the issuance profile's issuance gating, which
refuses to derive from a non-active Mission, to adjudicating an
expansion of one.

# Adjudication {#adjudication}

The Mission Issuer derives the successor's Authority Set from the
submitted Mission Intent and bounds it by policy, exactly as for any
Mission. The successor's authority is what that derivation and the
completion yield, not the predecessor's authority plus a delta;
authority the successor keeps from the predecessor is expressed in
the expansion Mission Intent ({{replacement}}).

The Mission Issuer evaluates an expansion in the order of
{{verification-order}}, completes it in one of the modes of
{{completion-modes}}, and activates the successor as
{{successor-activation}} describes.

## Verification Order {#verification-order}

The Mission Issuer MUST evaluate an expansion token exchange in this
order, refusing on the first failure:

1. Parse the exchange, require `subject_token` with
   `subject_token_type` = `urn:ietf:params:oauth:token-type:access_token`,
   rejecting a refresh token, and require `creation_request_id`
   ({{submission}}).
2. Resolve the predecessor Mission from `subject_token`
   ({{request-binding}}).
3. Verify possession: the presenter controls the `subject_token`'s own
   confirmation key ({{RFC9449}} DPoP proof `jkt`, or {{RFC8705}} mTLS
   `x5t#S256`), and, for a DPoP proof, the proof `jti` is single-use
   ({{request-binding}}).
4. Verify the acting agent (`actor_token`, or the request's client
   authentication) is authorized to request expansion of this
   predecessor.
5. Look up the `(client, creation_request_id)` reservation and, where
   one exists, recover the recorded operation instead of proceeding
   ({{creation-idempotency}}). The lookup follows client
   authentication and possession verification and precedes the
   predecessor lifecycle gate of step 6 ({{creation-revalidation}}).
6. Verify the predecessor is `active` ({{predecessor-active}}) and,
   when `predecessor` is present, that it names the resolved Mission.
7. Derive the successor's Authority Set under policy from the
   submitted Mission Intent ({{adjudication}}) and verify that it
   widens the predecessor: when the derived requested authority is a
   subset of the predecessor's own Effective Authority Set, refuse the
   exchange with the `nothing_to_expand` denial reason, as there is
   nothing to expand ({{denial-reasons}}).
8. Complete per {{completion-modes}}; at a deferred or interactive
   completion, re-verify the predecessor's Mission state before issuing
   ({{deferred-window}}).

On any failure the Mission Issuer MUST refuse and MUST NOT create a
successor. A failure to which this document assigns a code, such as a
`predecessor` mismatch or a denial reason ({{denial-reasons}}), uses
that code. Otherwise:

- a `subject_token` or `actor_token` that is invalid, whose sender
  constraint is not proven, or that is unacceptable for the exchange is
  refused with `invalid_request` ({{Section 2.2.2 of RFC8693}});
- a required DPoP proof that is missing, or a DPoP proof that fails its
  own validation, is refused with `invalid_dpop_proof`
  ({{Section 5 of RFC9449}}); and
- any other failure is refused with `invalid_request`,
  `invalid_grant`, or `invalid_token` as appropriate.

An authorization server that requires a DPoP nonce answers a proof
lacking its current nonce with `use_dpop_nonce` and a `DPoP-Nonce`
header ({{Section 8 of RFC9449}}), not `invalid_dpop_proof`.

Step 7 compares against the predecessor's Effective Authority Set as
{{I-D.draft-mcguinness-oauth-mission-status}} defines it: the approved
Authority Set after applying every issuer-held narrowing mechanism the
deployment runs, including the containment profile's overlay where
deployed ({{I-D.draft-mcguinness-oauth-mission-containment}}).

Authority the predecessor once held but containment or discharge has
removed is therefore never `nothing_to_expand`: a request for it
widens the effective set and is expansion-eligible. Such authority
returns only through a fresh-consent successor, never by re-deriving
under the predecessor. The expansion consent disclosure
({{completion-modes}}) surfaces the predecessor's containment history
and the chain's outstanding containment restrictions
({{I-D.draft-mcguinness-oauth-mission-containment}}). An expansion that
restores authority under a discharge restriction of the chain MUST
authorize that authority explicitly, and its consent disclosure MUST
name the discharged entry and the condition that discharged it
({{I-D.draft-mcguinness-oauth-mission-discharge}}).

## Completion Modes {#completion-modes}

An expansion completes in one of two modes. Both obtain the fresh
approval the successor's authority requires, and both rest on the same
possession-proven token exchange ({{expansion-request}}).

Deferred:
: When approval is asynchronous and the exchange opts in, the Mission
  Issuer returns the deferred token response
  ({{I-D.draft-gerber-oauth-deferred-token-response}}, profiled for
  Missions by {{I-D.draft-mcguinness-oauth-mission-approval}}):
  `authorization_pending` with a `deferral_code`, its `expires_in`, and
  a polling `interval`. The Approver acts on the deployment's
  asynchronous review surface. The client polls with the substrate's
  deferred grant type and the `deferral_code`; the poll resolves to the
  successor's access token on approval, or to `access_denied` or
  `expired_token`. This document references that substrate and does
  not redefine it.

Interactive:
: When approval is interactive, the Mission Issuer answers the token
  exchange with the interaction-required response of
  {{interactive-handoff}}. The client pushes an authorization request
  carrying the continuation, the user agent completes the issuance
  profile's own approval ceremony
  ({{I-D.draft-mcguinness-oauth-mission}}), and the client redeems the
    resulting authorization code for the successor's authority.

An exchange opts in to deferred completion when its `completion_mode`
includes `deferred`, the deferred token response's opt-in. The Mission
Issuer MUST NOT return the deferred response to an exchange that does
not opt in. It answers such an exchange with the interactive handoff
({{interactive-handoff}}) or, where it offers no interactive
completion, refuses it with `invalid_request`.

This document defines no synchronous completion for an expansion that
takes fresh consent. An expansion response is a successor or a
refusal, never a token derived under the predecessor: a request whose
derived authority is a subset of the predecessor's own Effective
Authority Set is refused with `nothing_to_expand`
({{verification-order}}, {{denial-reasons}}).

Policy-adjudicated expansion within a pre-consented authority ceiling
belongs to the experimental progressive authorization companion
({{I-D.draft-mcguinness-oauth-mission-progressive}}). An in-ceiling
drawdown that passes that companion's policy-adjudication guards
completes synchronously in the token-exchange response, which returns
the successor's access token. One that falls back to a fresh human
approval completes in one of the two modes above.

In either mode, obtaining the fresh approval follows the issuance
profile's approval event. The Mission Issuer:

- authenticates the Approver against the published
  approval-authentication floor;
- obtains fresh consent for the derived Authority Set;
- satisfies any requested `acr_values` or `max_age` strength; and
- renders the Subject when the Approver is not the Subject.

The consent disclosure MUST reflect the successor's authority being
adjudicated. If the Approver declines, no successor is created and the
predecessor is untouched ({{denial-reasons}}).

In either mode, the exchange's `creation_request_id` reservation
({{creation-idempotency}}) makes completion recoverable: a client that
loses the response recovers the one committed operation, never a
second creation.

The following is an example of a deferred response to the request in
{{fig-request}}:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "authorization_pending",
  "deferral_code": "dfc_DK-IqhQDOOy21T3Wu7mQYt",
  "expires_in": 600,
  "interval": 5
}
~~~
{: #fig-deferred title="Deferred Response"}

The following is an example of the client's poll with the deferred
grant type ({{Section 5.5 of I-D.draft-gerber-oauth-deferred-token-response}})
and a DPoP proof, with client authentication omitted (line breaks for
display purposes only):

~~~ http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adeferred
&deferral_code=dfc_DK-IqhQDOOy21T3Wu7mQYt
&client_id=s6BhdRkqt3
~~~
{: #fig-poll title="Deferred Poll"}

The following is an example of the response to the first poll after
the Approver approves, which activates the successor
({{successor-activation}}). In this example, the response carries the
token exchange's `issued_token_type` ({{Section 2.2.1 of RFC8693}}),
the successor's `mission_id`, the effective expiry in
`mission_expires_at` ({{successor-expiry}}), and the granted
`authorization_details`:

~~~ http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store

{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "issued_token_type":
    "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "DPoP",
  "expires_in": 300,
  "mission_id": "msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX",
  "mission_expires_at": "2026-12-31T23:59:59Z",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
                "resource_issued_before": "2026-09-30T23:59:59Z"
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "2000.00", "currency": "USD" }
      } }
  ]
}
~~~
{: #fig-success title="Successful Completion"}

## Interactive Handoff {#interactive-handoff}

An {{RFC8693}} success carries an issued token
({{Section 2.2.1 of RFC8693}}), so interactive completion cannot use
one. The Mission Issuer MUST answer the token exchange with an OAuth
error response ({{Section 5.2 of RFC6749}}), HTTP status 400, carrying:

`error`:
: `mission_interaction_required`.

`mission_continuation`:
: A string: an opaque, unguessable handle naming the pending creation
  operation ({{creation-idempotency}}), bound to the authenticated
  client and the operation fingerprint ({{creation-fingerprint}}).

`expires_in`:
: A number: the handle's remaining lifetime in seconds, the approval
  window of the operation.

The client tells the outcomes apart from the response alone:

- an issued token is the {{RFC8693}} success;
- `authorization_pending` is deferred completion ({{completion-modes}});
  and
- `mission_interaction_required` is this handoff.

The following is an example of the interaction-required response:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "mission_interaction_required",
  "mission_continuation": "e8GpKnzx1X8-SzJQ3aVRj7",
  "expires_in": 600
}
~~~
{: #fig-handoff title="Interaction-Required Response"}

The client then sends a pushed authorization request
({{Section 2 of RFC9126}}) carrying:

- `mission_continuation`;
- `response_type=code`, its `redirect_uri`, and `state`;
- the PKCE `S256` challenge or DPoP binding the issuance profile
  requires for an authorization code
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Authorization Code
  Protection"); and
- optionally, the `predecessor` cross-check ({{submission}}), which
  names the recorded predecessor.

It carries no `mission_intent` and no `authorization_details`: the
token exchange is this operation's carriage ({{submission}}). Client authentication at the pushed authorization request endpoint
binds the handle to the client, so the handle alone does not give its
holder the operation.

The following is an example of the pushed authorization request, with
client authentication omitted (line breaks for display purposes
only):

~~~ http
POST /par HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded

response_type=code
&client_id=s6BhdRkqt3
&redirect_uri=https%3A%2F%2Fagent.example.com%2Fcb
&state=af0ifjsldkj
&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
&code_challenge_method=S256
&mission_continuation=e8GpKnzx1X8-SzJQ3aVRj7
~~~
{: #fig-par title="Pushed Authorization Request Carrying the Continuation"}

The Mission Issuer:

- MUST refuse a pushed request whose `mission_continuation` is unknown,
  expired, or bound to another client, with `invalid_request`;
- MUST take the predecessor, Intent, proposal, submission evidence,
  presenter confirmation, and actor context only from the recorded
  operation, and MUST refuse a pushed request that supplies any of
  them with a different value, accepting an equal `predecessor` as a
  cross-check; and
- validates the other authorization request parameters as for any
  pushed request.

The `request_uri` is a temporary front-channel reference; the
continuation names the durable operation, which has one approval
ceremony and one outcome. The Mission Issuer MUST serialize
adjudication per operation and record at most one approval outcome
for it: the first ceremony to conclude records approval or denial, and
every other ceremony or pushed request for the continuation resumes
from that recorded outcome instead of adjudicating again.

When a `request_uri` expires, the user agent consumes it, or the
authorization response is lost, the client pushes again with the same
`mission_continuation`:

- before an outcome is recorded, the push starts no second
  adjudication; it continues the operation's one ceremony;
- after approval, the Mission Issuer issues a fresh authorization code
  for the recorded approval, bound to that push's PKCE or DPoP input,
  without prompting again; and
- after denial, the operation has failed: the Mission Issuer MUST
  refuse the push with `access_denied`, and a `creation_request_id`
  retry receives `access_denied`.

Redemption of an authorization code for the operation:

1. verifies the PKCE or DPoP binding;
2. verifies, in the same atomic step as activation, that the
   continuation has not expired and the recorded outcome is approval;
   and
3. activates the successor under the checks of {{reconciliation}},
   atomically with the predecessor's supersession
   ({{successor-activation}}).

The continuation's expiry is the operation's deadline, a clock
separate from the authorization code's own lifetime
({{Section 4.1.2 of RFC6749}}): the Mission Issuer MUST refuse
redemption at or after it with `invalid_grant`, and nothing activates.
`subject_token` expiry during the window does not gate redemption
({{deferred-window}}).

After activation the Mission Issuer MUST refuse a further pushed
request for the continuation with `invalid_request`, and MUST refuse
redemption of any other code issued for the operation with
`invalid_grant`. A lost redemption
response is recovered by repeating the token exchange with the same
`creation_request_id` ({{creation-recovery}}); an operation whose
continuation expired before activation answers that retry with
`expired_token`.

## Successor Activation {#successor-activation}

A successor activates at the point its authority is issued:

- the resolving poll, for a deferred completion;
- the code redemption, for an interactive completion; or
- the token-exchange response, for a policy-adjudicated drawdown
  under the progressive authorization companion
  ({{I-D.draft-mcguinness-oauth-mission-progressive}}).

At completion the Mission Issuer computes the successor's integrity
anchors: `intent_hash`, `authority_hash`, and, where the exchange
carried an authority proposal, `proposal_hash`. At activation it
creates the successor Mission record in the `active` state, with its
`predecessor` member set ({{predecessor-member}}), atomically with the
predecessor's transition to `terminated` with reason `superseded`
({{superseded-state}}). The same atomic step applies:

- the compare-and-set checks of {{reconciliation}};
- the Subject and authority-source checks of {{successor-source}};
- the effective-expiry check of {{successor-expiry}}; and
- where Child Mission Carryover is approved, the carryover rules of
  {{predecessor-children}}.

Until the successor activates, the predecessor remains `active`. An
expansion that never completes, whose deferred approval lapses, or
whose authorization code is never redeemed or expires, creates no
successor and leaves the predecessor `active`. It therefore never leaves the task without authority or cascade-terminates the predecessor's
Child Missions.

## The Deferred Window {#deferred-window}

A completion can occur later than the request, across a deferred or
interactive approval window. Two rules govern that window:

- The predecessor's Mission state MUST be re-verified at issuance
  (completion), not only at request time. A predecessor that was
  terminated during the window, or whose containment or discharge since
  adjudication restricts authority the successor carries, MUST fail
  completion, per the compare-and-set of {{reconciliation}}. This preserves the
  halt on new derivation that a terminal predecessor state effects: a
  deferred approval MUST NOT become a bypass of it.
- Expiry of the `subject_token` during the window MUST NOT gate
  completion. The predecessor binding and the possession proof are
  evaluated and recorded at request time ({{request-binding}}); the
  short-lived `subject_token` expiring while approval is pending does
  not invalidate the pending exchange. The re-verification above is of
  the predecessor's Mission state, not of the expired token.

## Successor Expiry {#successor-expiry}

The successor's effective `expires_at` follows the issuance profile's
requested-versus-effective rule
({{I-D.draft-mcguinness-oauth-mission}}), with two bounds:

- It MUST NOT be later than the expansion submission's
  `intent.expires_at`, the requested ceiling.
- It MUST NOT exceed the predecessor's `expires_at` unless the Mission
  Issuer's policy explicitly permits extension and the extension is
  disclosed to the Approver at the expansion consent event, which
  records the exact approved extension ceiling.

Expansion adds authority; it does not silently extend lifetime. The
issuance profile caps every derived credential's `exp` at the
Mission's `expires_at`, so a successor that silently outlived its
predecessor would carry a longer-lived Mission past the originally
approved horizon.

The completing success response, the resolving poll or the code
redemption, MUST carry the effective value in the issuance profile's
`mission_expires_at` response member. Completion inherits the
issuance profile's atomic creation-time check: where the
submission's `intent.expires_at` passes while the expansion is
pending, completion creates no successor Mission. A deferred poll then
answers `access_denied`, a code redemption `invalid_grant`, and a
completion in the token-exchange response `invalid_request`.

An auditor verifies the successor record by inequalities, never by
matching a recomputed minimum:

- in every case, the effective value is no later than the submission's
  `intent.expires_at`;
- without an approved extension, it is also no later than the
  predecessor's `expires_at`; and
- with one, it MAY be later than the predecessor's `expires_at` only
  when the Mission Issuer's policy permits the extension and the exact
  effective value was rendered and approved at the expansion consent
  event.

Any further shortening is justified by recorded policy.

An approved successor extension MUST NOT extend a carried child's expiry:
carryover remains bounded by the old child and its new parent's effective
expiry ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

## Successor Subject and Authority Source {#successor-source}

A successor's `subject` and `authority_source` MUST equal the
predecessor's, whichever completion mode or approval basis creates it;
an approval that would establish another Subject or source creates no
successor. Work for another Subject or source continues under a
separately approved Mission, outside succession
({{independent-continuation}}).

In the commit that activates the successor, the Mission Issuer MUST
verify that the source still applies to the Subject and that the
successor Authority Set lies within the source's ceiling as it stands
at that commit. On failure it creates no successor and leaves the
predecessor `active`. The same commit rechecks the effective expiry
({{successor-expiry}}).

# Lineage Members {#predecessor-member}

This document defines three lineage members. The issuance profile's
`mission` claim is an open object whose additional members are each
defined by the profile that introduces them, are ignored by a consumer
that does not understand them, and never grant or widen authority
({{I-D.draft-mcguinness-oauth-mission}}); `predecessor` is one such
member.

`predecessor`:
: REQUIRED on a successor Mission; absent otherwise. A string: the
  `mission_id` of the Mission this Mission succeeded by expansion. It
  is carried on the successor's `mission` claim and recorded on the
  successor's immutable Mission record, so the lineage is durable
  independently of any derived token and the expansion chain is
  observable in audit.

`related_to`:
: OPTIONAL. A string: the `mission_id` of a Mission this Mission is
  related to by lineage without superseding it, used for a
  non-superseding link such as a branch ({{replacement}}) or an
  independent continuation ({{independent-continuation}}). Unlike
    `predecessor`, its presence does not imply that the referenced
  Mission was superseded, and it carries no lifecycle consequence. It
  is a member of the Mission Record and is not carried on the
  `mission` claim.

`successor`:
: REQUIRED in the `termination` of a Mission terminated with reason
  `superseded` ({{superseded-state}}); absent otherwise. A string: the
  `mission_id` of the successor that superseded this Mission by
  expansion, issued by the same Mission Issuer and written into the
  predecessor's `termination` at supersession. It appears only inside
  `termination`. It is the reverse of the successor's `predecessor`
  link, so a consumer that holds a superseded predecessor discovers its
  successor directly. The Status profile surfaces it in the status
  response ({{I-D.draft-mcguinness-oauth-mission-status}}) and the
  Signals profile in the supersession's lifecycle event
  ({{I-D.draft-mcguinness-oauth-mission-signals}}), each inside
  `termination`.

All three members are lineage and audit context only. Consistent with the issuance profile's
open-`mission`-claim rule, each of them MUST NOT grant or widen
authority, and a consumer that does not understand one MUST ignore it.
The successor's authority comes only from its own `authority_hash`,
never from its predecessor.

Each is a bare Mission Identifier string, not an object like the
`parent` member of a Child Mission
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}): same-issuer
succession needs only the identifier to resolve the linked Mission at
the shared `issuer`, whereas parentage carries cascade semantics and
cross-object integrity that require a structured member.

The lineage members have these properties:

- **Cardinality.** A successor has at most one `predecessor`. An
  expansion chain is expressed by walking `predecessor` links from a
  successor back toward the original Mission.
- **Immutability.** The `predecessor` member is set at the
  successor's approval event and MUST NOT change thereafter. The Mission record is immutable
  except for its `state` and its `termination`, which a supersession
  writes once on the predecessor with the `successor` link
  ({{superseded-state}}).
- **Origin.** The predecessor and successor share an `issuer`: an
  expansion is adjudicated by the predecessor's Mission Issuer. A
  consumer correlating a chain resolves each link at that issuer.

The following is an example of a successor's `mission` claim (other
token claims omitted):

~~~ json
{
  "mission": {
    "id": "msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX",
    "issuer": "https://as.example.com",
    "predecessor": "msn_QBZj5JSIV6tkkb93ZTvbiz_9dOMMXfJS"
  }
}
~~~
{: #fig-claim title="Successor Mission Claim"}

# The Superseded Termination Reason {#superseded-state}

This document adds one termination reason to the issuance profile's
Mission Termination Reasons registry
({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission Termination
Reasons Registry"), used only by expansion:

`superseded`:
: The reason a predecessor Mission is `terminated` when a successor
  replaces it through a replacement expansion. The predecessor is
  non-active, and its `termination`
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Mission
  Termination") carries the `successor` member
  ({{predecessor-member}}).

A deployment that never expands a Mission never produces this reason;
the issuance profile's lifecycle is unchanged for it. The transition
is:

| From | Event | To | Reason |
|---|---|---|---|
| `active` | successor activates when its authority is issued | `terminated` | `superseded` |
{: title="The supersession transition"}

The transition has these properties:

- **Atomic with successor activation.** The predecessor becomes
  `terminated` with reason `superseded` only in the successor's
  activation step ({{successor-activation}}), at the point the
  successor's authority is issued, not at the approval decision that
  precedes it. In that step the Mission Issuer writes the predecessor's
  `termination`, once, with `successor` set to the successor's
  `mission_id` ({{predecessor-member}}). If the atomic operation fails,
  the predecessor remains `active` and no successor record exists. The
  Mission Issuer MUST NOT produce a partial successor or a predecessor
  left in an indeterminate state.
- **No further derivation.** A superseded Mission is not
  `active`, so the issuance profile's issuance gating refuses to derive
  any new token, refresh, token exchange, or cross-domain grant under
  it: derivation proceeds only from an `active` Mission
  ({{I-D.draft-mcguinness-oauth-mission}}). The refusal's
  `mission_error` value is `superseded`
  ({{I-D.draft-mcguinness-oauth-mission}}, Section "Issuance Gating").
  New authority for the task flows through the successor.
- **Already-issued predecessor tokens.** Tokens already derived under
  the predecessor before it was superseded remain valid until their own
  `exp`, exactly as in the issuance profile's revocation model:
  superseding a Mission stops new derivation; it does not retroactively
  invalidate access tokens already issued.
  - These tokens MUST NOT be silently rebound to the successor.
    Authority under the successor is obtained only by deriving from
    the successor's grant, which is a new derivation governed by the
    successor's Authority Set.
  - A deployment that needs a lower cutoff latency on the
    predecessor's outstanding tokens SHOULD use short token lifetimes.
    It MAY additionally revoke the predecessor's refresh token where
    the issuance profile's optional revocation composition is in use.
- **Reported as non-active.** A superseded predecessor is reported
  through the same mechanisms that report a revoked or expired
  Mission:

  - where the issuance profile's optional token introspection is
    offered, the composite `active` is `false` and, from the issuer,
    `mission.state` is `terminated` and `mission.termination.reason`
    is `superseded`; and
  - where the Mission Status profile
    ({{I-D.draft-mcguinness-oauth-mission-status}}) is deployed, the
    Status Response `mission.state` is `terminated` and its
    `mission.termination` carries reason `superseded` and the
    `successor`.

  A deployment that offers either surface and this document MUST
  include `superseded` among the termination reasons its issuer may
  report. Consumers rely on the issuance profile's forward-compatibility
  rule: a `terminated` Mission, whatever its reason, is non-deriving.

The following is an example of the predecessor's `state` and
`termination` after supersession (other Mission record members
omitted):

~~~ json
{
  "state": "terminated",
  "termination": {
    "reason": "superseded",
    "terminated_at": "2026-11-02T09:40:00Z",
    "successor": "msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX"
  }
}
~~~
{: #fig-termination title="Superseded Predecessor"}

The following is an example of a later refresh under the predecessor,
refused with the issuance profile's `mission_error` diagnostic:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_grant",
  "mission_error": "superseded"
}
~~~
{: #fig-superseded-refusal title="Refused Derivation under a Superseded Mission"}

## Child Missions of the Predecessor {#predecessor-children}

Supersession is a terminal exit from `active`, so it is a terminal
cascade trigger for the predecessor's entire delegation tree under the
child delegation profile
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Cascade
applies to every non-terminal Child Mission, regardless of whether that
child's own Authority Set would still satisfy strict-subset validation
against the successor: the successor's Authority Set is freshly
derived, not inherited by reference, so a child's creation-time subset
check does not carry forward
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
"Cascade Revocation").

A child still needed after the expansion is re-created under the
successor through ordinary child creation, in generation order. Each
re-creation costs
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}, Section
"Cascade Failure"):

- a fresh assertion conveyed to the child actor that held the
  terminated child; and
- an interval, while the replacement is delivered, in which that child
  actor's outstanding tokens under the terminated child run to the
  earlier of their own `exp` and, where the runtime enforcement layer
  is deployed, the runtime staleness bound.

When the predecessor has non-terminal Child Missions, the expansion
consent disclosure SHOULD surface that fact as a material notice: at
minimum the count of live Child Missions and that supersession
terminates them. Where a deployment provides this notice, the
expansion consent event renders the cost above; that consent event is the only point in this document at which a human can witness the
cascade before it happens. A deployment MAY additionally support an
expansion-request parameter by which the client asks the Mission
Issuer to refuse the expansion while live Child Missions exist.

Where explicitly approved Child Mission Carryover is selected, the Mission
Issuer MUST render and commit its complete manifest and exclusion policy,
and recheck that snapshot at completion under the child profile's Carryover
rules ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Otherwise
the ordinary cascade notice and per-child re-creation above remain the minimum.

Carryover completes in the successor's activation step
({{successor-activation}}). When the approved operation includes Child
Mission Carryover, the Mission Issuer MUST include replacement records, required old-child
cascades, the committed outcome map, and durable recovery work in the
same atomic operation. Publication follows commit and is repairable;
constructing replacements first does not guarantee external event order
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).

## No Implicit Rollback {#no-rollback}

The Mission Issuer MUST NOT implicitly resurrect a superseded
predecessor when its successor is later revoked, expired, or itself
superseded; `terminated` is terminal, whatever its reason. A
deployment that needs to revert to the predecessor's authority
expresses that as a new approval event creating a new Mission that
carries the relevant authority, and MAY record its `related_to` member
naming the superseded predecessor to preserve the lineage
({{independent-continuation}}). A rollback is a new governed Mission,
not a state reversal.

# Replacement Expansion {#replacement}

A successful expansion is a replacement: the successor replaces the
predecessor, which becomes `terminated` with reason `superseded`
({{superseded-state}}). Replacement is the only mode this document
defines. Under replacement:

- exactly one successor is created per predecessor, and the
  predecessor is no longer `active` once the successor activates; and
- the successor carries its own complete Authority Set as derived and
  consented at the expansion approval event; it does not inherit the
  predecessor's authority by reference.

A deployment that wants the successor to retain the predecessor's
authority alongside the new authority expresses the combined authority
in the expansion Mission Intent, so the successor's `authority_hash`
commits exactly the authority the Approver saw and approved
({{adjudication}}).

A branch mode, in which the predecessor and the successor both remain
`active` after expansion (for example, a separately scoped child task
running alongside the original), is OPTIONAL and is not defined here.
A deployment that needs a separately scoped task alongside a
still-active Mission creates an ordinary new Mission under the
issuance profile and MAY set that Mission's `related_to` member
({{predecessor-member}}) to the original Mission's `mission_id` to
preserve lineage. It does not set `predecessor`, which would imply a
supersession, so the original remains `active`. An atomic, grant-bound
branch expansion that creates such a child within a single expansion
approval event is deferred to a future revision of this document.

# Continuing Under an Independently Approved Mission {#independent-continuation}

A deployment can end one Mission and continue the work under another
without this document's expansion protocol: it approves an ordinary
new Mission under the issuance profile and explicitly revokes the
prior Mission. This is independent continuation, an operational
pattern. It is not expansion, succession, or replacement in the
protocol sense, and none of this document's `predecessor`,
`successor`, or `superseded` semantics apply.

The two commits are independent, with these consequences:

- both Missions are normally `active` for an interval; revoking first
  instead opens an availability gap if the new approval fails;
- revocation can fail or be omitted, leaving both active until the
  prior Mission's own lifecycle ends it;
- the prior Mission's outstanding tokens retain their ordinary
  residual lifetime, and no credential is rebound: authority under
  the new Mission is obtained only by fresh derivation from it;
- revoking the prior Mission terminal-cascades its Child Missions,
  and continuing child work requires fresh Child Mission creation
  under the new Mission
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}});
- a harness applies its ordinary stop behavior to the revoked
  Mission; the supersession continuation handoff does not apply
  ({{I-D.draft-mcguinness-mission-harness}}); and
- nothing serializes concurrent continuations, no exactly-one
  guarantee exists, and the new approval is not grant-bound to the
  prior Mission.

A deployment MAY record the relationship as `related_to` on the new
Mission ({{predecessor-member}}). The `related_to` member is
issuer-recorded correlation metadata, not client-asserted authority:

- this document defines no client request parameter for it, and
  `mission_intent` carries the task and its submission evidence, never
  a relationship member; and
- the input that causes it to be recorded is authenticated and
  authorized under the Mission Issuer's management or local policy.

The Mission Issuer:

- MUST authorize and resolve the reference, in its own namespace,
  before the new Mission's approval completes (a cross-issuer
  relationship requires a structured extension);
- MUST set `related_to` atomically when the Mission record is created;
  and
- MUST NOT add or change it afterward.

An unresolved or unauthorized reference is never recorded: deployment
policy either rejects the creation uniformly or proceeds without the
relationship, applied consistently across requests, and neither
behavior discloses whether the referenced Mission exists. The member
asserts related work only, neither mutual recognition nor replacement.

A Mission created this way MUST NOT carry the `predecessor` member,
which asserts the supersession semantics only replacement expansion
provides. Independent continuation does not satisfy any profile that
requires a successor: containment restoration in particular requires
the `predecessor` link and the disclosed history that expansion's
approval renders.

# Concurrent Expansion Reconciliation {#reconciliation}

More than one expansion request MAY be in flight against the same
predecessor at once, and more than one MAY be adjudicated and awaiting
its completion. Because replacement produces exactly one successor per
predecessor ({{replacement}}) and supersession is deferred to
activation ({{successor-activation}}), the Mission Issuer MUST
serialize the completions that would activate a successor of the same
predecessor, so that concurrent expansions cannot each activate one.

The Mission Issuer MUST apply compare-and-set semantics at successor
activation ({{successor-activation}}). This is the completion-side
re-verification of the deferred window ({{deferred-window}}). In the
same atomic step that would activate the successor and supersede the
predecessor, the Mission Issuer MUST verify:

1. the predecessor is still in the `active` state;
2. no other replacement expansion has already activated a successor for
   this predecessor (equivalently, the predecessor has not already
   been terminated with reason `superseded`); and
3. the successor's complete Authority Set, including authority carried forward from the predecessor, overlaps no authority under a
   current containment or discharge restriction of the chain
   ({{I-D.draft-mcguinness-oauth-mission-containment}},
   {{I-D.draft-mcguinness-oauth-mission-discharge}}) that the
   successor's approval did not explicitly restore with that
   restriction disclosed.

If any check fails, the Mission Issuer MUST refuse the completion
with the applicable reconciliation status from the closed set below,
alongside the error code of the step that completes it:

- a deferred poll answers `access_denied`, the deferred token
  response's outcome for a request that resolved with an error;
- an authorization code redemption answers `invalid_grant`; and
- where the token-exchange response completes the expansion, a failed
  first or second check, a predecessor no longer `active`, answers
  `invalid_request` ({{predecessor-active}}), and a failed third check
  answers `invalid_grant`.

The losing or otherwise stale expansion is rejected at completion; it
activates no successor.

The third check catches narrowing that occurs between adjudication and
activation: authority contained or discharged after the approval
returns only through a new expansion, adjudicated against the current
restrictions, which require fresh human approval with the restriction
disclosed.

The reconciliation status codes are:

`superseded_by_concurrent_expansion`:
: A concurrent replacement expansion has already produced a successor;
  the predecessor is `terminated` with reason `superseded` rather than
  `active`. The client
  SHOULD discover the existing successor and re-evaluate whether a
  further expansion is still required (an expansion of the successor is
  a new expansion against the successor as predecessor).

`predecessor_state_changed`:
: The predecessor made a terminal exit from `active` (to `terminated`,
  with reason `revoked`, `expired`, `superseded`, or another) before
  this expansion could complete,
  whether caught at request binding ({{predecessor-active}}) or at the
  compare-and-set on successor activation. The
  client MUST NOT retry the same expansion against this predecessor.

`predecessor_not_active`:
: The predecessor is in a non-terminal non-active state (for example
  `suspended` under the Mission Status profile
  {{I-D.draft-mcguinness-oauth-mission-status}}) and cannot be expanded
  until it returns to `active`. The client MAY retry the expansion after
  the predecessor is `active` again.

`authority_restricted_since_approval`:
: The successor's Authority Set overlaps authority that came under a
  containment or discharge restriction of the chain after the
  successor's approval was adjudicated (check 3 above). The client MAY
  submit a new expansion, which is adjudicated against the current
  restrictions.

The two terminal-exit codes overlap in the `superseded` case:
`superseded_by_concurrent_expansion` is the specific reconciliation
outcome when the cause is a concurrent expansion that has already
activated a successor,
and `predecessor_state_changed` is the general outcome for any other
terminal exit from `active`. A Mission Issuer SHOULD return the
specific code when it can attribute the change to a concurrent
expansion. The `predecessor_not_active` code reports a reversible,
non-terminal state, so it invites the retry the terminal codes forbid.

The Mission Issuer conveys the reconciliation status in an OAuth error
response member:

`mission_expansion_status`:
: A string carrying one reconciliation status from the closed set
  above, returned by the step that failed. At the token endpoint (the
  token exchange response, a deferred token response poll, and an
  authorization code redemption), it is a member of the JSON error
  response body, alongside the OAuth `error` member. On the interactive path's
  front-channel authorization error response, which carries error
  parameters rather than a JSON body, it is an error response
  parameter of the same name. Adjudication denial reasons use the
  separate `mission_denial_reason` member ({{denial-reasons}}).

The following is an example of a resolving poll refused because a
concurrent expansion of the same predecessor activated first:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "access_denied",
  "mission_expansion_status": "superseded_by_concurrent_expansion"
}
~~~
{: #fig-reconciliation title="Reconciliation Refusal"}

# Creation Idempotency {#creation-idempotency}

A `creation_request_id` identifies one Mission-creation operation
across every completion mode. The Mission Issuer MUST durably bind
the authenticated client, the identifier, the operation fingerprint
({{creation-fingerprint}}), and the resulting continuation or
successor Mission, atomically with the creation decision. Repetition
of the exchange recovers that operation ({{creation-recovery}}); it
MUST NOT repeat Mission creation or any creation-side effect:
creation accounting, creation lifecycle events, evidence emission.

The identifier is REQUIRED in every completion mode for two reasons:

- the client cannot know in advance which mode the Mission Issuer will
  select; and
- the existing single-use artifacts do not stop a retry from creating
  twice. DPoP proof `jti` single-use ({{request-binding}}) prevents
  replay of one captured proof, but a client that loses the response
  retries with a fresh, valid proof. The interactive path's single-use
  artifacts prevent only duplicate redemption within one ceremony.

The reservation made at initiation, and the single recorded approval
outcome of {{interactive-handoff}}, prevent a retry or a repeated
pushed request from starting a second ceremony ({{creation-recovery}}).

A creation exchange that its adopter explicitly profiles, whether or
not it mints a Mission, adopts these definitions by reference, under
its own domain-separating `op` value and its own binding of the
fingerprint's `source` and other members to what that exchange
actually creates ({{creation-fingerprint}}):

- the child delegation profile's child-creation exchange carries the
  same parameter with the same semantics
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}});
- the continuation profile's async-delegation exchange adopts it for a
  delegated refresh-token family, which is not a Mission
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}); and
- the template profile's Dispatch adopts it for a dispatched Mission
  ({{I-D.draft-mcguinness-oauth-mission-template}}).

## The Operation Fingerprint {#creation-fingerprint}

The operation fingerprint commits what the operation is, so the
Mission Issuer can tell a repeated identifier from a reused one. It is
an issuance-profile integrity anchor
({{I-D.draft-mcguinness-oauth-mission}}) with:

- `typ` `mission-creation-fingerprint`, under that profile's
  collision-resistant `typ` convention; and
- the fingerprint object below as its committed value.

The anchor envelope is canonicalized with JCS {{RFC8785}}, hashed with
SHA-256, and encoded as `sha-256:` followed by the base64url,
no-padding, encoding of the digest, exactly as for the profile's other
anchors. It is an envelope anchor under the issuance profile's
commitment mechanisms, which this document imports normatively. As a
JCS commitment-envelope `typ`, `mission-creation-fingerprint` names a
hash domain, not a representation crossing a protocol boundary, and is
not a media type ({{I-D.draft-mcguinness-oauth-mission}}, Section
"Namespace Taxonomy").

The fingerprint object carries exactly these members:

`op`:
: `expansion` for this document's exchange; `child-creation` for the
  child delegation profile's; `dispatch` for the template profile's
  Dispatch ({{I-D.draft-mcguinness-oauth-mission-template}}). This
  member domain-separates the operations that share a creation
  exchange. An adopting profile ({{creation-idempotency}}) declares its
  own value the same way, as the continuation profile's
  async-delegation exchange declares `async-delegation`
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}).

`iss`:
: The Mission Issuer's issuer identifier.

`client`:
: The authenticated client identifier.

`source`:
: The `mission_id` of the source Mission resolved from
  `subject_token` ({{request-binding}}): the predecessor here, the
  parent under child delegation, and the base Mission under the
  continuation profile's async-delegation exchange
  ({{I-D.draft-mcguinness-oauth-mission-continuation}}). The resolved
  identifier is the member, never the raw `subject_token`, since a
  legitimate retry may carry a newly issued token for the same
  Mission, and never the optional cross-check alone, which is
  non-authoritative. An adopting profile whose exchange has no source
  Mission or `subject_token` to resolve binds `source` to its own
  profiled source authority instead, stated in its own adoption
  clause: the template profile's Dispatch binds it to the dispatched
  Mission Template's `id`
  ({{I-D.draft-mcguinness-oauth-mission-template}}), never pretending
  that identifier is a Mission ID.

`cnf`:
: The verified presenter confirmation, as a JSON object with one
  member as in a `cnf` claim: `jkt`, the DPoP proof key's thumbprint,
  or `x5t#S256`, the mTLS certificate's thumbprint
  ({{request-binding}}).

`actor`:
: The verified acting-agent identity where the exchange carries an
  `actor_token`: a JSON object with that token's `iss` and `sub`, and
  any further actor context the Mission Issuer's authorization of the
  acting agent relies on. Absent where client authentication alone
  identifies the acting agent.

`intent`:
: The semantic `intent` object of the parsed `mission_intent`
  Submission envelope ({{I-D.draft-mcguinness-oauth-mission}}).

`evidence`:
: The parsed `evidence` array of the Submission envelope, when
  present. Presented evidence affects admission, derivation,
  approval, and side effects, so a retry presenting different
  evidence is a different operation, refused on the fingerprint
  mismatch below.

`proposal`:
: The parsed `authorization_details` array, when present.

`child_actor`:
: The parsed `child_actor` object; child creation only, absent on an
  expansion.

`requested_token_type`:
: The exchange's `requested_token_type` value.

`cross_check`:
: The supplied `predecessor` value (under child delegation, the
  supplied `parent` value), when present.

An extension that defines a new parameter affecting the
authorization, derivation, approval, output, or side effects of the
creation MUST extend the fingerprint object with it. Attempt-specific
material is excluded: the DPoP proof serialization and its `jti`, the
client-authentication assertion serialization, the raw
`subject_token` serialization, `completion_mode`, and
`creation_request_id` itself. The completion mode recorded at
initiation governs recovery ({{creation-recovery}}).

## The Durable Reservation {#creation-reservation}

A reservation is the durable record binding the authenticated client,
the `creation_request_id`, and the fingerprint. It is created in a
`reserved` state, which covers a pending completion, and moves to
`completed` when the successor activates or to `failed` when the
operation is denied, its deadline passes, or its activation is
refused. The
`(client, creation_request_id)` pair is unique, and the store MUST
enforce that uniqueness as a constraint; a read-before-insert check
without one does not withstand concurrent retries.

The reservation and the created Mission's identifier MUST be
committed atomically with Mission creation; credential generation MAY
follow the commit. When the Mission commits and the Mission Issuer fails before
responding, the retry
finds the committed operation and resumes delivery
({{creation-recovery}}), never creating again.

A repeated presentation of the same `(client, creation_request_id)`
resolves by fingerprint:

- same fingerprint, operation completed: recover it
  ({{creation-recovery}});
- same fingerprint, operation reserved: return the same continuation
  or deferral, or a retryable in-progress result;
- same fingerprint, operation failed: return the recorded failure,
  directly or through the same deferral's next poll (`access_denied`
  after a denial or a refused activation, `expired_token` after the
  deadline); and
- different fingerprint: refuse with `invalid_request`, since the
  identifier was reused for a different operation.

## Recovery Is Delivery {#creation-recovery}

The Mission Issuer stores the operation's stable outcome, never its
serialized response: the completion mode with its continuation
handle, or the created Mission's identifier with its
delivery-artifact metadata. A revalidated retry
({{creation-revalidation}}) recovers that outcome:

- A pending deferred completion returns the same deferral: the same
  `(client, creation_request_id)` resolves to the same deferred
  continuation, scoped to the authenticated client, never to a
  second deferral.
- A pending interactive completion returns the same
  `mission_continuation` ({{interactive-handoff}}). The reservation is
  made at initiation, so a retry cannot start a second approval
  ceremony.
- A completed operation whose delivery credential is still valid
  returns that credential.
- A completed operation whose delivery credential has expired is
  recovered by minting a fresh delivery credential for the
  already-created successor, provided that successor remains
  `active` and the requester re-establishes the recorded
  authorization context ({{creation-revalidation}}). The fresh
  credential is a delivery event with ordinary issuance accounting;
  it MUST NOT repeat creation accounting: no second creation
  lifecycle event, no second evidence emission, no second count
  against any creation budget.

Recovery never re-creates. Whatever the outcome tier, a recovered
operation yields the Mission the operation already created, or the
continuation it already opened, and nothing else.

## Revalidation and Lookup Order {#creation-revalidation}

A matching `creation_request_id` never bypasses authentication or
possession. Before recovering anything, the Mission Issuer MUST
establish:

- the same authenticated client;
- the recorded source Mission;
- the same authorized acting agent;
- possession of the recorded sender-constraint identity, the stored
  `cnf` of {{creation-fingerprint}}; and
- fingerprint compatibility ({{creation-reservation}}).

No key-rotation recovery path is defined: a requester that can no
longer prove possession of the recorded `cnf` does not recover the
operation.

The idempotency lookup occurs after client authentication and
possession verification and before the predecessor lifecycle gate
({{verification-order}}). The order matters: the retry worth
recovering is exactly the one whose predecessor was terminated with
reason `superseded` when the first attempt succeeded
({{superseded-state}}), so re-running the predecessor-active gate
first would refuse the very recovery this mechanism exists to serve.

## Tombstone Retention {#creation-retention}

Retention has two tiers:

- The full delivery-artifact record MAY be retained briefly.
- The idempotency tombstone, the `(client, creation_request_id)`
  binding with its fingerprint and its Mission or continuation
  reference, MUST survive at least the deployment's published retry
  horizon, and retention to the source or created Mission's lifetime,
  or to the deployment's audit horizon, is RECOMMENDED.

The retry horizon is a published deployment bound, like the
deployment's other operational bounds. A client MUST NOT retry a
creation past the published horizon: reuse of an identifier after its
tombstone expires is outside the contract and is processed as a new
operation.

# Expansion Denial Reasons {#denial-reasons}

An adjudication that completes with the Approver declining, or with
the Mission Issuer refusing on policy grounds, denies the expansion:
no successor is created, and the predecessor remains `active` and
untouched. The denial surfaces according to the completion mode
({{completion-modes}}):

- on the token exchange response, as an OAuth error (typically
  `invalid_request` for a request the Mission Issuer will not derive a
  valid Authority Set from);
- on a deferred poll, as the deferred substrate's `access_denied`
  resolution; or
- on the interactive path, through the approval's own decline path.

A denial MAY additionally carry one machine-readable reason code from
the Mission Denial Reasons registry ({{iana-denial-reasons}}). This
document defines four:

`out_of_policy`:
: The Mission Issuer's governance policy refuses the requested
  authority class for this Mission, independent of who approves.

`approver_rejected`:
: The Approver declined the expansion at the consent step.

`out_of_scope_for_purpose`:
: The requested authority is incompatible with the Mission's recorded
  `purpose`; a different Mission, not an expansion of this one, is the
  appropriate vehicle.

`nothing_to_expand`:
: The derived requested authority is a subset of the predecessor's own
  Effective Authority Set, so there is nothing to expand: ordinary
  token derivation under the predecessor already serves the request
  ({{verification-order}}). This refusal surfaces on the token exchange
  response itself, as `invalid_request`, and MUST carry this reason
  code; it is never answered with a token derived under the
  predecessor, so an expansion response is never ambiguously a
  non-successor.

Companion profiles register further values in the Mission Denial
Reasons registry ({{iana-denial-reasons}}). For example, the experimental progressive authorization companion
registers `out_of_ceiling`
({{I-D.draft-mcguinness-oauth-mission-progressive}}), and the
experimental template profile registers
`out_of_template_ceiling` and `dispatch_prohibited_class`
({{I-D.draft-mcguinness-oauth-mission-template}}). A consumer MUST
treat an unrecognized reason code as a denial with no further
semantics.

A Mission Issuer MUST NOT use a reason code to disclose policy
boundaries beyond the adjudicated request ({{policy-probing}}).
Omitting the reason code is always permitted, except on a
`nothing_to_expand` refusal, which always carries it (see its
definition above). That code reveals only that the requester already
holds the requested authority, which the requester can observe from
its own token, so the policy-probing rationale for omission does not
apply; carrying it keeps a non-widening refusal distinguishable from a
policy denial.

When present, a reason code is carried in a `mission_denial_reason`
member:

- at the token endpoint (the token exchange response and a deferred
  token response poll), as a member of the JSON error response body
  alongside the OAuth `error` member; and
- on the interactive path's front-channel authorization error
  response, as an error response parameter of the same name.

The following is an example of the refusal of an expansion request
that widens nothing:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_request",
  "mission_denial_reason": "nothing_to_expand"
}
~~~
{: #fig-denial title="Denial with nothing_to_expand"}

The `mission_denial_reason` member is the shared carrier for
adjudication denial
reasons across the profiles that mint a Mission related to an existing
one: the child delegation profile
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) carries its
own closed denial-reason set in the same member, and further such
profiles do likewise. Each profile defines its values by
specification; the unrecognized-code rule above applies to the member
wherever it appears.

Two failure classes are not denial reasons and use the issuance
profile's error vocabulary directly:

- a `predecessor` cross-check that does not match the
  `subject_token`-resolved Mission fails with `invalid_grant`
  ({{request-binding}}), or with `invalid_request` where the
  predecessor is not `active` ({{predecessor-active}}); and
- an expansion Mission Intent the Mission Issuer cannot parse fails
  with `invalid_request`, and one it can parse but cannot derive a
  valid Authority Set from fails with `invalid_authorization_details`
  ({{RFC9396}}) where the client submitted a proposal alongside it, or
  `access_denied` where it did not, exactly as for any Mission
  creation.

# Conformance {#conformance}

An implementation claims conformance to this document only in the
Mission Issuer role, under one of two targets: as an
expansion-capable Mission Issuer when it adjudicates expansion, or
under the optional `related_to` correlation target below.

A Mission Issuer that records `related_to` without adjudicating
expansion conforms to the **`related_to` correlation** target when it
meets every rule of {{independent-continuation}}: authenticated and
authorized input, pre-approval resolution, creation-time atomic
recording, immutability, consistent non-disclosing failure behavior,
and no `predecessor` member. Nothing else in this section applies to
that target.

A conforming **expansion-capable Mission Issuer** MUST:

- accept an {{RFC8693}} token exchange whose `subject_token` is the
  predecessor's Mission-bound access token, with `subject_token_type`
  of `access_token`, treating it as an expansion ({{submission}}), and
  reject a refresh token as the `subject_token`;
- resolve the predecessor from `subject_token`, verify possession
  against the token's own confirmation key, refuse a `predecessor`
  cross-check that does not match the resolved Mission with
  `invalid_grant` and a predecessor that is not `active` with
  `invalid_request`, and evaluate the request in the verification
  order of {{verification-order}}
  ({{request-binding}}, {{predecessor-active}});
- require a `creation_request_id` on every expansion exchange,
  refusing a missing one with `invalid_request`, and recover a
  repeated one under the reservation, recovery, revalidation, and
  retention rules of {{creation-idempotency}};
- refuse an exchange whose derived requested authority is a subset of
  the predecessor's own Effective Authority Set, carrying the
  `nothing_to_expand` denial reason ({{verification-order}},
  {{denial-reasons}});
- complete the expansion in one of the modes of {{completion-modes}},
  obtaining new consent for the successor's authority through the
  deferred token response or the interactive handoff
    ({{completion-modes}}, {{interactive-handoff}}) and enforcing the
  successor-expiry rule ({{successor-expiry}});
- keep the predecessor's `subject` and `authority_source` on the
  successor and verify that source in the activating commit
  ({{successor-source}});
- record the `predecessor` member on the successor's `mission` claim
  and Mission record ({{predecessor-member}});
- activate the successor and transition the predecessor to
  `terminated` with reason `superseded`, its `termination` carrying
    `successor`, atomically when the successor's authority is issued
  ({{successor-activation}}), leaving the predecessor `active` until
  then, re-verifying predecessor state at
  completion ({{deferred-window}}), and refuse further derivation under
  a superseded Mission ({{superseded-state}}); and
- serialize concurrent expansions against the same predecessor with the
  reconciliation semantics of {{reconciliation}}.

An expansion-capable Mission Issuer is also a conforming issuance-profile
Mission Issuer ({{I-D.draft-mcguinness-oauth-mission}}); this document
adds the expansion surface to that role. A resource server requires no
new behavior: it enforces a successor's tokens exactly as it enforces
any Mission-bound token, and treats the `predecessor` member, if it
reads it at all, as audit context it MUST NOT use to grant authority
({{predecessor-member}}).

Every expansion this document defines is adjudicated as a fresh
approval event ({{adjudication}}). The experimental progressive
authorization companion defines a further OPTIONAL capability,
**Expansion with Progressive Authorization**, with its own conformance
requirements ({{I-D.draft-mcguinness-oauth-mission-progressive}}).

# Security Considerations {#security-considerations}

The security considerations of the issuance profile
({{I-D.draft-mcguinness-oauth-mission}}) apply, including its general
OAuth guidance for the underlying credentials. Expansion's central
guarantee is the issuance profile's, applied to the successor: a
user's fresh approval bounds every token derived for the broadened
task. The risks specific to expansion are in the predecessor binding,
the predecessor-to-successor handoff, and the lineage link.

## Predecessor Confusion {#predecessor-confusion}

A client could attempt to expand a Mission it does not control, for
example by naming another tenant's or subject's `mission_id` in the
`predecessor` parameter.

Mitigations:

- The predecessor is resolved from the `subject_token` the client
  presents, not from the `predecessor` value, and possession is proven
  against that token's own confirmation key; the Mission Issuer verifies
  that the resolved Mission matches the named one and refuses a mismatch
  with `invalid_grant` ({{request-binding}}). A client that does not
  hold the predecessor's Mission-bound access token and its
  sender-constraint key cannot expand it.
- The issuance profile's integrity anchors are issuer-bound, so a
  Mission's governance state cannot be transplanted across Mission
  Issuers; an expansion is adjudicated only at the predecessor's own
  `issuer`.

## Possession Proof {#possession-proof}

A stolen or exfiltrated predecessor credential could be replayed to
request an expansion.

Mitigations:

- The `subject_token` is a sender-constrained access token, not a
  reusable bearer refresh credential, and possession is proven against
  the token's own confirmation key ({{request-binding}}): a bearer copy
  of the token, without its DPoP key or mTLS certificate, cannot carry
  the proof. A refresh token is never accepted as the
  `subject_token` ({{submission}}).
- The DPoP proof `jti` is single-use ({{RFC9449}}), so a captured proof
  cannot be replayed ({{verification-order}}).
- The short-lived `subject_token` bounds the window in which even a
  key-holding attacker could act, and the possession proof is bound and
  recorded at request time, so a legitimate deferred completion is not
  gated on that lifetime ({{deferred-window}}).

## Authority Comes Only from New Consent {#new-consent}

An expansion could be misused to widen authority without the Approver
re-consenting, if a successor were allowed to inherit or extend
authority without a fresh approval.

Mitigations:

- The successor's authority comes only from the Authority Set derived
  and consented at the expansion approval event; the `authority_hash`
  commits exactly that set ({{adjudication}}). The `predecessor` member
  carries no authority and cannot widen the successor
  ({{predecessor-member}}).
- The successor-expiry rule ({{successor-expiry}}) keeps the
  successor's `expires_at` from silently exceeding the predecessor's,
  so expansion cannot carry a longer lifetime past the originally
  approved horizon.

## Race against the Predecessor Lifecycle {#lifecycle-race}

Between the moment a client decides to expand and the moment the
successor activates, the predecessor may be revoked, expire, or be
superseded by a concurrent expansion. A deferred or interactive
completion widens this window. Without serialization an expansion could
appear to succeed against a predecessor that is no longer authoritative,
or two successors could be created.

Mitigations:

- The Mission Issuer verifies predecessor state and the
  no-existing-successor condition in the same atomic step that would
  activate the successor ({{deferred-window}}), and serializes the
  completions that activate a successor of the same predecessor
  ({{reconciliation}}).
- A failed check refuses with a reconciliation status
  ({{reconciliation}}) that tells the client whether to discover an
  existing successor or stop, without leaking the predecessor's new
  internal state beyond that.

## Duplicate Creation {#duplicate-creation}

To a client, a lost response is indistinguishable from a failed
creation. Without idempotency the natural retry after a network
fault creates a second Mission: live authority nobody intended and,
under the child delegation profile, a consumed fan-out budget
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). Proof
`jti` single-use does not close this fault: the retry carries a
fresh, valid proof.

Mitigations:

- The required `creation_request_id`, with its durable reservation
  and uniqueness constraint, makes the retry recover the one
  committed operation, concurrent retries included
  ({{creation-idempotency}}, {{creation-reservation}}).
- The identifier is a deduplication handle, not a secret and not a
  credential: recovery re-establishes client authentication,
  possession of the recorded confirmation key, and the recorded
  authorization context, so the recovery path never weakens the
  possession requirements of {{request-binding}}
  ({{creation-revalidation}}).
- Reservations are scoped to the authenticated client, so one
  client's identifiers cannot interfere with, or replay, another's.
- Storage is bounded: the tombstone is small, its horizon is
  published ({{creation-retention}}), and a Mission Issuer MAY cap
  outstanding reservations per client.

## Expansion versus Step-Up {#step-up-distinction}

Conflating expansion with authentication step-up {{RFC9470}} would
route an authentication shortfall through an approval event the
Approver did not need to perform, surfacing irrelevant consent and
risking approval fatigue, or conversely would treat a genuine
authority shortfall as a mere re-authentication and silently widen
nothing.

Mitigation: a denial that is an authentication shortfall (`acr`,
`amr`) is satisfied by step-up and MUST NOT be routed to expansion; a
denial that is an authority shortfall is the one expansion addresses
({{not-step-up}}). The component that classifies the denial
({{eligibility}}) makes this distinction.

## Policy Probing {#policy-probing}

A client could submit many expansion requests for the same predecessor
to map the Mission Issuer's policy boundary from the denial reasons.

Mitigations:

- The Mission Issuer MUST rate-limit expansion requests per predecessor
  per client. The bound is unconditional: it caps both policy probing
  and the approval prompts a client can drive against an Approver
  (prompt fatigue). Every expansion presentation is recorded and
  counted toward anomaly detection ({{request-binding}}).
- A denial reason discloses no policy boundary beyond the adjudicated
  request ({{denial-reasons}}): a denial reports whether the requested
  authority was approved, not the full surface of what would have
  been.

## Audit Linkage {#audit-linkage}

The `predecessor` member makes the expansion chain observable: an
authorized auditor can trace a successor back through its predecessors
to the original Mission. This is a core governance property of
expansion. An implementation that omits the member breaks the chain
and defeats it; the member is therefore mandatory on a successor
({{predecessor-member}}).

# Privacy Considerations {#privacy-considerations}

The privacy considerations of the issuance profile
({{I-D.draft-mcguinness-oauth-mission}}) apply. The privacy surface
expansion adds is the lineage link and the authority detail disclosed
when a task is broadened.

## Predecessor-Chain Correlation {#chain-correlation}

The `predecessor` member that gives audit linkage ({{audit-linkage}})
is also a correlation surface. It links a successor to its predecessor
across distinct approval events, so a party that can read the chain
can correlate the evolving task over time, which is more than any
single Mission discloses. Deployments SHOULD scope read access to the
`predecessor` member, and to any Mission-state surface that exposes it,
to parties with a governance need, rather than exposing the chain to
every credential audience. The issuance profile's Mission Identifier
correlation considerations apply to each Mission in the chain.

## Related-Work Correlation {#related-to-correlation}

`related_to` correlates independently approved tasks the way the
`predecessor` chain correlates a succession, without the authority
linkage. The same scoping applies: deployments SHOULD disclose the
member only to audiences that require the governance relationship,
and the issuance profile's Mission Identifier correlation
considerations apply to both Missions it names.

## Disclosure of the Broadened Task {#broadened-task}

The expansion Mission Intent and the consent disclosure rendered at the
expansion approval event reveal how the approved task is evolving. The
Mission Issuer SHOULD render that disclosure only to the Approver and
authorized governance consumers, consistent with the issuance profile's
treatment of consent disclosure.

# IANA Considerations {#iana}

The `predecessor` member of the `mission` claim ({{predecessor-member}})
is not registered in a dedicated registry: it is carried inside the
already-registered `mission` claim, an open object for which the
issuance profile establishes no member registry. No new claim,
parameter, or token-introspection registration is required for the
lineage link.

This document defines two sets of symbolic codes: the expansion
reconciliation status codes ({{reconciliation}}), a closed set conveyed
in `mission_expansion_status`, and the expansion denial reasons
({{denial-reasons}}), conveyed in the shared `mission_denial_reason`
member. As members of the OAuth error response JSON body at the token
endpoint, both are namespaced to their error responses and require no
registration; their authorization error response parameter forms, used
on the interactive path, are registered in {{iana-parameters}}.

The reconciliation status codes remain specification-defined: the
closed set is small and fully specified in {{reconciliation}}. A future
revision MAY establish a "Mission Expansion Reconciliation Status"
registry for it with a Specification Required {{RFC8126}} policy; until
then this document is the value space.

The denial reasons are registry-backed: this document establishes the
Mission Denial Reasons registry ({{iana-denial-reasons}}) and seeds it
with the four values it defines. Each further document that defines a
value on the carrier requests its own registration in it.

## Mission Termination Reasons Registration {#iana-lifecycle-registration}

This document requests registration of one reason in the issuance
profile's Mission Termination Reasons registry
({{I-D.draft-mcguinness-oauth-mission}}), under that registry's
Specification Required policy:

| Value | Semantics | Members | Change Controller | Reference |
|---|---|---|---|---|
| `superseded` | A successor Mission replaced the predecessor through a replacement expansion. | `successor` (REQUIRED) | IETF | this document, {{superseded-state}} |

## Mission Denial Reasons Registry {#iana-denial-reasons}

IANA is requested to create the "Mission Denial Reasons" registry. The
registration policy is Specification Required {{RFC8126}}.
Registration does not require IETF review or a Standards Track
document; a Specification Required reference that a Designated Expert
can review against the criteria below suffices.

A Designated Expert reviews a submission for the discipline
{{denial-reasons}} requires:

- a `Value` matching `^[a-z][a-z0-9_]*$` not already registered;
- a `Semantics` sentence precise enough that a consumer can tell the
  denial from every other registered value; and
- a `Reference` that fixes which specification defines it.

The registry covers values of the `mission_denial_reason` parameter
only ({{denial-reasons}}). The resource server `WWW-Authenticate`
`mission_denial` attribute ({{I-D.draft-mcguinness-oauth-mission}},
Section "Resource Server Enforcement") and AuthZEN decision-context
denial reasons ({{I-D.draft-mcguinness-mission-authzen}}) are separate
specification-defined value spaces, outside this registry's scope. A
companion that adds a denial value states whether it adds a row to
this carrier's registry or defines a value in a separate space. A
shared spelling across carriers is a coincidence, never shared
semantics, unless the defining documents state the mapping.

Consumers treat an unrecognized value as a denial with no further
semantics ({{denial-reasons}}). A Designated Expert MUST reject a
registration whose governing specification attempts to redefine this
interaction rather than adding a value bound by it.

Each registration records:

- **Value**: the `mission_denial_reason` symbolic string.
- **Semantics**: one sentence stating what the denial means.
- **Change Controller**: IETF, or the registrant for any other
  registration.
- **Reference**: the specification defining the value.

This document seeds the registry with the values it defines
({{denial-reasons}}):

| Value | Semantics | Change Controller | Reference |
|---|---|---|---|
| `out_of_policy` | The Mission Issuer's governance policy refuses the requested authority class for this Mission, independent of who approves. | IETF | this document, {{denial-reasons}} |
| `approver_rejected` | The Approver declined the expansion at the consent step. | IETF | this document, {{denial-reasons}} |
| `out_of_scope_for_purpose` | The requested authority is incompatible with the Mission's recorded `purpose`. | IETF | this document, {{denial-reasons}} |
| `nothing_to_expand` | The derived requested authority is a subset of the predecessor's own Effective Authority Set, so there is nothing to expand. | IETF | this document, {{denial-reasons}} |

Each further document that defines a value on this carrier requests
that value's registration in its own IANA considerations, carrying its
Internet-Draft reference as a publication dependency under this
registry's policy until it is published.

## OAuth Parameters Registration {#iana-parameters}

The expansion request is an {{RFC8693}} token exchange carrying the
already-registered `mission_intent` request parameter and the
already-registered token-exchange parameters `subject_token`,
`subject_token_type`, `requested_token_type`, `actor_token`, and
`actor_token_type`; none of these needs registration by this document.
The deferred completion mode uses the deferred token response
({{I-D.draft-gerber-oauth-deferred-token-response}}) and registers
nothing here.

The `predecessor` cross-check is carried in the token exchange request
at the token endpoint and, on the interactive path, in the
authorization request. The reconciliation status and denial reason are
carried in the token error response and, on the interactive path, in
the authorization error response. The `creation_request_id` identifier
is carried in the token exchange request in every completion mode and
never appears on a front channel.

This document requests registration of the following parameters in
the "OAuth Parameters" registry ({{Section 11.2 of RFC6749}}):

- Parameter name: `predecessor`
- Parameter usage location: token request, authorization request
- Change controller: IETF
- Specification document(s): this document, {{submission}}

- Parameter name: `mission_expansion_status`
- Parameter usage location: token response, authorization response
- Change controller: IETF
- Specification document(s): this document, {{reconciliation}}

- Parameter name: `mission_denial_reason`
- Parameter usage location: token response, authorization response
- Change controller: IETF
- Specification document(s): this document, {{denial-reasons}}; also
  carried by the child delegation profile
  ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})

- Parameter name: `mission_continuation`
- Parameter usage location: token response, authorization request
- Change controller: IETF
- Specification document(s): this document, {{interactive-handoff}}

- Parameter name: `creation_request_id`
- Parameter usage location: token request
- Change controller: IETF
- Specification document(s): this document, {{submission}},
  {{creation-idempotency}}; also carried by the child delegation
  profile ({{I-D.draft-mcguinness-oauth-mission-child-delegation}})

## OAuth Extensions Error Registration {#iana-error-registration}

This document registers the following value in the "OAuth Extensions
Error Registry" ({{Section 11.4 of RFC6749}}):

- Error name: `mission_interaction_required`
- Error usage location: token error response
- Related protocol extension: Mission Expansion
- Change controller: IETF
- Specification document(s): this document, {{interactive-handoff}}

--- back

# End-to-End Example {#example}

This appendix follows one expansion through deferred completion. A Q3
reconciliation Mission `msn_QBZj5JSIV6tkkb93ZTvbiz_9dOMMXfJS`, issued
by `https://as.example.com` to the client `s6BhdRkqt3` acting for
`alice`, authorizes reading Q3 invoices and posting journal entries of
at most USD 500 each. Mid-task the agent finds an adjustment of
USD 1,200, outside the active Mission's authority. It cannot widen the
Mission in place.

1. The agent sends an expansion request ({{fig-request}}). It presents
   the predecessor's Mission-bound access token as the
   `subject_token`, proves possession with a DPoP proof over that
   token's confirmation key, and carries a Mission Intent that raises
   the cap to USD 2,000 ({{fig-intent}}).
2. The Mission Issuer resolves the predecessor from `subject_token`,
   verifies possession, confirms that the `predecessor` cross-check
   names that Mission and that it is `active`, and derives the
   successor's Authority Set, which widens the predecessor's
   ({{verification-order}}).
3. The widening requires fresh consent, and the deployment approves
   asynchronously, so the Mission Issuer defers ({{fig-deferred}}) and
   the client polls ({{fig-poll}}).
4. `alice` approves the widened cap on the review surface. At 09:40:00
   UTC on 2026-11-02 the next poll activates the successor
   `msn_2Yt7Qv9LqMv4z7sA2bN1k0YpEdHc9RfX` and supersedes the
   predecessor in one atomic step, and the response delivers the
   successor's access token ({{fig-success}}). Until then the
   predecessor stays `active`.
5. The successor's tokens carry the `predecessor` member
   ({{fig-claim}}), and the predecessor's record names the successor
   ({{fig-termination}}).
6. The predecessor derives no new tokens ({{fig-superseded-refusal}}).
   Its already-issued access tokens run out their short lifetimes, and
   the task continues under the successor.

The widening came only from `alice`'s fresh consent: the successor's
`authority_hash` commits the complete widened Authority Set she
approved, not the predecessor's authority plus a delta.

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

- Editorial restructure, with no change to any requirement: sections
  reordered and titled in Title Case; Successor Activation and Child
  Missions of the Predecessor collect the activation and child-cascade
  rules previously spread across several sections; dense paragraphs
  become lists; restatements in the Lineage, Security and IANA text
  point to the rule's home instead of repeating the keyword; the main
  messages have examples, and Appendix A walks one expansion end to
  end; the OAuth Parameters
  registrations use the RFC 6749 template.

- No `predecessor_token` parameter is registered: the predecessor is
  resolved from `subject_token`.

- A failed expansion exchange uses the code this document assigns to
  the failure; otherwise an invalid, unproven or unacceptable
  `subject_token` or `actor_token` is `invalid_request`, as Section
  2.2.2 of RFC 8693 requires; a required DPoP proof that is missing, or
  one that fails validation, is `invalid_dpop_proof`, and a proof
  lacking a required nonce keeps `use_dpop_nonce` (#1178).

- A predecessor that is not `active` refuses the expansion exchange
  with `invalid_request`, following the issuance profile's Token
  Exchange rule; a predecessor cross-check mismatch, and a completion
  by code redemption or deferred poll, keep `invalid_grant` (#1154).

- Supersession terminates the predecessor: it becomes `terminated` with
  reason `superseded`, registered in the Mission Termination Reasons
  registry, and its `termination` carries the REQUIRED `successor`; the
  record's mutable members are `state` and `termination`, and a
  refused derivation's `mission_error` is `superseded` (#705).
- Successor Subject and authority source: every successor keeps the
  predecessor's `subject` and `authority_source`, whatever approval
  basis creates it; another Subject or source needs a separately
  approved Mission outside succession, and the activating commit
  verifies that the source applies and that its current ceiling covers
  the successor (#1118).
- Interactive completion has a defined handoff: the token exchange
  answers `mission_interaction_required` with a `mission_continuation`
  handle, the client pushes an RFC 9126 request carrying it, and code
  redemption activates the successor; the handle names the durable
  operation and each `request_uri` is a temporary reference.
- An in-ceiling drawdown under the progressive authorization companion
  completes synchronously in the token-exchange response, a third
  issuance point; fresh-consent expansion still completes deferred or
  interactively.
- Successor activation's compare-and-set also rechecks the complete
  successor Authority Set against current containment and discharge
  restrictions, refusing with `authority_restricted_since_approval`
  when narrowing landed after adjudication.
- A fresh-consent restoration of authority under a discharge
  restriction authorizes that authority explicitly and discloses the
  discharged entry and its condition; the consent also surfaces the
  chain's outstanding containment restrictions.
- Added explicitly approved carryover hooks for disclosure, atomic completion,
  and the carried child's unchanged expiry ceiling (#576).

# Acknowledgments {#acknowledgments}
{:numbered="false"}

The author thanks the reviewers of the Mission-Bound Authorization for
OAuth 2.0 profile for feedback on the expansion model and its
composition with the issuance flow.
