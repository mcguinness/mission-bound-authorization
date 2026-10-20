---
title: "Mission Progressive Authorization for OAuth 2.0"
abbrev: "OAuth Mission Progressive Authorization"
category: exp

docname: draft-mcguinness-oauth-mission-progressive-latest
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
 - progressive
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-derivation-limits:
    title: "Mission Derivation Limits for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-derivation-limits.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  RFC8693:
  RFC9449:
  I-D.draft-mcguinness-mission-discovery:
    title: "Mission Open-World Discovery"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-discovery.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
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
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
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
  I-D.draft-mcguinness-mission-metering:
    title: "Mission Consumption Metering"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-metering.html
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
  I-D.draft-mcguinness-mission-approval-governance:
    title: "Mission Approval Governance"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-approval-governance.html
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
  I-D.draft-mcguinness-oauth-mission-template:
    title: "Mission Template for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-template.html
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

--- abstract

Mission Expansion for OAuth 2.0 widens an agent's authority only
through a fresh human approval that creates a successor Mission. An
open-ended agentic task often cannot have its full authority
enumerated at the initial approval, which leaves a deployment choosing
between over-provisioning a broad standing Mission and interrupting
the user for a fresh approval at every step.

This document defines progressive authorization, an experimental third
option. At the initial approval, the Approver additionally consents to
a bounded authority ceiling and a drawdown policy. The Mission Issuer
may then adjudicate an expansion that stays within that ceiling by
policy rather than by a fresh human approval. Authority grows within
the ceiling at runtime while the active authority any single Mission
yields stays narrow, and each drawdown is bounded incrementally,
never activating the whole ceiling at once. Authority
classes named by the runtime profile's high-consequence
classification, and the external-communication exfiltration leg,
always require a fresh human approval, even within the ceiling.

--- middle

# Introduction

Mission Expansion for OAuth 2.0
{{I-D.draft-mcguinness-oauth-mission-expansion}} (the "expansion
profile") defines the governed path from an authority shortfall to a
new approval: a successor Mission, freshly consented, that supersedes
its predecessor. Every expansion under that profile is adjudicated by a
fresh human approval.

For a task whose growth is anticipated, that discipline has a human
cost. Each expansion is another approval moment, and an Approver asked
too often stops reading what is asked (the consent-fatigue residual of
{{I-D.draft-mcguinness-mission-security-model}}). A deployment that
avoids the prompts over-provisions a broad standing Mission instead.

Progressive authorization is a third option. The Approver consents
once to a bounded envelope, the authority ceiling, and to a rule for
drawing authority from it, the drawdown policy. Authority then grows
within the envelope at runtime without a fresh human approval each
time, while the active authority any single Mission yields stays
narrow. The envelope can name a class of resources the agent will only
meet during execution: the Approver consents once to the family, and
every concrete binding stays inside it ({{ceiling-test}}). One
considered consent to a ceiling replaces many hurried consents to
increments.

This document is optional and experimental: adopt it for
evaluation, not as a stable interface. It removes the per-expansion
human from a consented envelope, which is the highest-consequence
capability in the expansion family. This document therefore
conditions the capability on the rate bounds, prohibited-class
rules, and audit linkage it requires, and plain expansion remains
the better fit where task authority can be anticipated per step.

A Mission Issuer that does not implement this document adjudicates
every expansion as a fresh human approval and is a fully conforming
expansion-capable Mission Issuer
({{I-D.draft-mcguinness-oauth-mission-expansion}}). Nothing here places
a new requirement back on the expansion profile or the issuance
profile.

## Relationship to Other Specifications {#relationship}

This document depends normatively on the expansion profile
{{I-D.draft-mcguinness-oauth-mission-expansion}} and on the issuance
profile {{I-D.draft-mcguinness-oauth-mission}}, and is not
implementable alone. It reuses, without restating:

- the expansion profile's expansion request, adjudication,
  `predecessor` member, `superseded` termination reason, and
  reconciliation; and
- the issuance profile's approval event, integrity-anchor envelope,
  and subset rule.

Other companions interact with a drawdown as follows:

| Companion | Effect on a drawdown | Section |
|---|---|---|
| Mission Derivation Limits | Carries the derivation count and limit forward | {{drawdown-derivation-limits}} |
| Mission Child Delegation | Live Child Missions require a fresh approval | {{fresh-approval}} |
| Mission Entry Discharge | Discharged authority is not restored by policy | {{fresh-approval}} |
| Mission Containment | Contained capability is not restored by policy | {{fresh-approval}} |
| Mission Consumption Metering | Grants no new capacity | {{ceiling-drawdown-basis}} |
| Mission Approval Governance | The basis meets the accountable-approver rule; a consumption-bound drawdown needs a class-named exception | {{ceiling-drawdown-basis}} |
| Mission Consent Evidence | Commits the ceiling and review disclosures | {{progressive-authorization}}, {{ceiling-review}} |
| Mission Open-World Discovery | Defines the encounter adjudication contract for a self-declared resource | {{audit-linkage}} |
{: title="Companion Interactions"}

## Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

This document uses Predecessor Mission, Successor Mission, and
Expansion request as the expansion profile defines them.

Authority ceiling:
: The pre-consented maximum authority any expansion of a Mission may
  reach without a further human approval ({{progressive-authorization}}).
  This bound is distinct from the template profile's Template Ceiling
  on Missions dispatched from a template and from the shaping
  companion's caller-supplied shaping ceiling on a proposal
  ({{I-D.draft-mcguinness-oauth-mission-template}},
  {{I-D.draft-mcguinness-mission-shaping}}).

Drawdown policy:
: The policy under which the Mission Issuer may adjudicate an
  in-ceiling expansion by policy rather than by a fresh human approval
  ({{progressive-authorization}}).

Mission Deployment Profile:
: The deployment-level manifest the architecture defines
  ({{I-D.draft-mcguinness-mission-architecture}}). The bounds,
  mappings, and cadence this document requires a deployment to
  publish are published there.

# Protocol Overview {#overview}

A progressive Mission begins with an ordinary approval and grows
through a chain of successor Missions:

1. At the initial approval, the Approver consents to the Mission, an
   authority ceiling, and a drawdown policy. The Mission Issuer records
   the ceiling and the policy on the Mission and commits them with
   `ceiling_hash` ({{progressive-authorization}}).
2. When the agent needs authority its Mission lacks, the client sends
   an expansion request: a token exchange presenting the Mission's
   access token ({{I-D.draft-mcguinness-oauth-mission-expansion}}).
3. A request outside the ceiling is never policy-adjudicated: it falls
   back to an ordinary, freshly approved expansion, subject to the
   Mission Issuer's policy ({{ceiling-test}}).
4. A request within the ceiling falls back to an ordinary, freshly
   approved expansion when it meets a fresh-approval condition
   ({{fresh-approval}}), when it exceeds a drawdown bound or would
   activate the entire remaining ceiling ({{drawdown-bounds}}), when
   the chain is past its ceiling review cadence ({{ceiling-review}}),
   or when the drawdown policy does not authorize it
   ({{policy-adjudication}}).
5. Otherwise the drawdown policy adjudicates the request. If the
   expansion profile's activation checks and any derivation limit
   admit it, the Mission Issuer creates the successor, supersedes the
   predecessor, and returns the successor's access token in the
   token-exchange response ({{drawdown-successor}}).
6. A review approval re-consents to or narrows the ceiling, which
   restarts the review cadence ({{ceiling-review}}).

~~~ ascii-art
   Approver consents to Mission M0, ceiling C, drawdown policy P
                                |
                                v
      +------+  drawdown  +------+  drawdown  +------+
      |  M0  |----------->|  M1  |----------->|  M2  |---> ...
      +------+  under P   +------+  under P   +------+
     terminated          terminated            active
    (superseded)        (superseded)
~~~
{: #fig-chain title="A Drawdown Chain"}

Every successor drawn under P stays within C, and each such drawdown
is bounded incrementally.

## Example Scenario {#example-scenario}

The examples in this document follow one scenario, the
`ceiling-drawdown` variant of the family's Q3 reconciliation baseline.
At `2026-11-02T08:00:00Z`, `alice` (`user_3p2q8mN1a0kV7tR` at
`https://idp.example.com`) approves Mission
`msn_pasG9An7Ivj9cOdd3RqWWonuaLAbDHtM` at `https://as.example.com` for
the reconciliation agent, the client `s6BhdRkqt3`. Its Authority Set
allows only reading Q3 invoices at `https://erp.example.com`. `alice`
also consents to an authority ceiling that adds posting journal
entries of at most USD 500 and correcting Q3 invoices, under the
drawdown policy `q3-reconcile-drawdown` version `1`.

The deployment's Mission Deployment Profile publishes a per-drawdown
bound of one added action, a chain rate bound of two drawdowns per
hour, and a 30-day ceiling review cadence. It maps `invoices.read` to
the consequential read class, and `journal-entries.write` and
`invoices.write` to the reversible consequential write class, so no
ceiling action requires a fresh approval by class
({{fresh-approval}}). The Mission has no Child Missions and its chain
has no discharge or containment restrictions.

# Progressive Authorization {#progressive-authorization}

At the initial approval event ({{I-D.draft-mcguinness-oauth-mission}}),
the Approver MAY additionally consent to an authority ceiling and a
drawdown policy, recorded as these Mission members:

`authority_ceiling`:
: An array of authorization-details-shaped entries, each the shape of
  an Authority Set entry ({{I-D.draft-mcguinness-oauth-mission}}). It
  is the pre-consented maximum any expansion of this Mission may reach
  without a further human approval, and every in-ceiling successor
  MUST be within it ({{in-ceiling-expansion}}).

`drawdown_policy`:
: An activation policy reference, an object of `id`, `version`, and
  `digest` ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Standing-Consent Bases"). It identifies the policy under which the
  Mission Issuer MAY adjudicate an in-ceiling expansion by policy
  rather than by a fresh human approval, and commits its content. The
  policy's content is deployment-defined.

Where present, `authority_ceiling` and `drawdown_policy` are recorded
on the Mission and committed by a `ceiling_hash`. Because
`ceiling_hash` covers `drawdown_policy`, the ceiling commits the exact
policy the human consented to, and the Mission Issuer verifies its
`digest` before each policy-adjudicated drawdown under the issuance
profile's activation policy commitment rule
({{I-D.draft-mcguinness-oauth-mission}}, Section "Standing-Consent
Bases").

The `ceiling_hash` is computed with the issuance profile's
integrity-anchor envelope ({{I-D.draft-mcguinness-oauth-mission}}):

- `typ`: `mission-authority-ceiling`;
- hashed object: a JSON object with exactly two members,
  `authority_ceiling` (the ceiling array) and `drawdown_policy` (the
  activation policy reference object), canonicalized as the
  integrity-anchor envelope requires, so member order follows that
  canonicalization;
- omission rule: when the Mission carries no `drawdown_policy`, the
  `drawdown_policy` member is omitted from the hashed object, never
  included as null or an empty object.

`ceiling_hash` is an envelope anchor under the issuance profile's
commitment mechanisms, which this document imports normatively.

Neither member is committed under `authority_hash`: `authority_hash`
commits only the consented Authority Set
({{I-D.draft-mcguinness-oauth-mission}}), and the ceiling is a bound
on future expansions, not present authority.

The consent disclosure MUST render the ceiling and the fact that
in-ceiling expansion is policy-adjudicated
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

A Mission that carries no `authority_ceiling` has no progressive
authorization: every expansion of it is an ordinary, freshly approved
expansion ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

The following is an example of the ceiling members the Mission Issuer
records for the scenario's Mission at the initial approval
({{example-scenario}}), other members omitted:

~~~ json
{
  "authority_ceiling": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      },
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" } } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.write"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      } }
  ],
  "drawdown_policy": {
    "id": "q3-reconcile-drawdown",
    "version": "1",
    "digest":
      "sha-256:HS89ur28PoDZuYR2YEAPKaqYTIawABGKnIyjTWDQNGc"
  },
  "ceiling_hash":
    "sha-256:8PkE9J8vIWBKyPTG21yYer3W3BPP8opLI2moZr3S-kw"
}
~~~

The Mission's Authority Set is the first ceiling entry alone. The
policy snapshot that `digest` commits has `content_type`
`application/json` and consists of exactly the following bytes, which
state the per-drawdown bound and the ceiling review cadence in seconds
({{ceiling-review}}):

~~~
{"ceiling_review_cadence":2592000,"max_added_actions":1}
~~~

## In-Ceiling Expansion {#in-ceiling-expansion}

An **in-ceiling expansion** is an expansion, adjudicated per the
expansion profile ({{I-D.draft-mcguinness-oauth-mission-expansion}}),
whose successor Authority Set is within the predecessor's consented
`authority_ceiling`.

### Ceiling Test {#ceiling-test}

A requested successor Authority Set is in-ceiling when every one of
its entries is a subset of some `authority_ceiling` entry under the
issuance profile's subset rule ({{I-D.draft-mcguinness-oauth-mission}}).
A `constraints`-bounded ceiling uses the same subset semantics.

A ceiling entry MAY name a resource family rather than a single
resource, under the same resource-narrowing semantics the subset rule
fixes: a successor entry's `resource` is in-ceiling when it narrows
the ceiling entry's.

The Mission Issuer MUST NOT policy-adjudicate a requested authority
that is not within the consented `authority_ceiling`. Such a request
falls back to an ordinary, freshly human-approved expansion
({{policy-adjudication}}), subject to the Mission Issuer's policy,
which can refuse it as it can refuse any expansion. A refusal MAY
carry `out_of_ceiling` ({{denial-reason}}); a response that starts the
human approval never carries it. Approving that authority does not
raise the ceiling ({{ceiling-reconsent}}).

In the example scenario ({{example-scenario}}), the agent finds an
adjustment of USD 1,200 at 09:18:00. The client presents the access
token issued at 09:15:00 and requests a successor whose journal-write
entry allows USD 2,000, which is within no ceiling entry. The request
falls back to a fresh human approval. The following is an example of
the response, the expansion profile's deferred response with no
denial reason; no Mission is created yet, and
`msn_uG1kkHwXSlzUs4OKztGGk5FOmBnkpTOb` stays `active`:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "authorization_pending",
  "deferral_code": "dfc_mgumqI7ZWFKY71J9GLLeo7",
  "expires_in": 600,
  "interval": 5
}
~~~

If `alice` approves the USD 2,000 entry without re-consenting the
ceiling, the successor carries the ceiling unchanged, and the USD
2,000 entry stays outside it ({{ceiling-reconsent}}).

### Policy Adjudication {#policy-adjudication}

When the predecessor consented to a drawdown policy that authorizes
the requested widening, the Mission Issuer MAY satisfy the
adjudication's approval event by policy rather than by a fresh human
approval, exactly as a parent Mission's Authority Set may permit
policy-approved child creation
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}). This is
an explicit override of the expansion profile's consent step for the
in-ceiling case only.

This does not widen authority without consent
({{I-D.draft-mcguinness-oauth-mission-expansion}}). The consent is the
human consent given at the initial approval to the ceiling and the
drawdown policy; policy adjudication only draws within that pre-given
consent and can never exceed the ceiling.

An in-ceiling request the drawdown policy does not authorize is not
refused with `out_of_ceiling`; it falls back to an ordinary, freshly
human-approved expansion. A drawdown policy snapshot that does not
match `drawdown_policy.digest` authorizes nothing, so a request under
it falls back the same way. A drawdown that falls back to a fresh
human approval completes deferred or interactively, as any expansion
does.

### Conditions That Require a Fresh Approval {#fresh-approval}

**Prohibited classes.** Some authority classes always require a fresh
human approval even within the ceiling. To make that testable, a
deployment MUST publish in the Mission Deployment Profile a mapping
from its action identifiers to the runtime profile's action classes
({{I-D.draft-mcguinness-mission-runtime}}), or an equivalent declared
classification.

A drawdown MUST be adjudicated by a fresh human approval when it:

- grants authority in the irreversible, external-commitment, or
  privileged-administration class;
- satisfies the runtime profile's external-communication predicate
  (the exfiltration leg, {{I-D.draft-mcguinness-mission-runtime}});
  or
- grants cross-domain authority.

The drawdown policy MUST NOT permit policy-only adjudication of such
a drawdown.

**Live Child Missions.** Policy adjudication skips the interactive
prompt, and with it the expansion profile's child-cascade consent
notice ({{I-D.draft-mcguinness-oauth-mission-expansion}}), while
supersession terminally cascades to the predecessor's non-terminal
Child Missions ({{I-D.draft-mcguinness-oauth-mission-child-delegation}}).
The Mission Issuer therefore MUST NOT policy-adjudicate an in-ceiling
drawdown while the predecessor has non-terminal Child Missions: such
a request falls back to a fresh human approval, at which that notice
can be rendered.

**Discharged authority.** The drawdown policy MUST NOT
policy-adjudicate a successor whose complete Authority Set, including
authority carried forward from its predecessor, overlaps in authority
the authority a discharge restriction of its expansion chain covers
({{I-D.draft-mcguinness-oauth-mission-discharge}}). The test is overlap
in authority, not structural equality or entry identity. Such a
request falls back to a fresh human approval whose consent disclosure
names the discharged entry and the condition that discharged it.

The Mission Issuer MUST apply this test to every drawdown in the chain
after the discharge, not only to one from the Mission that holds the
discharged entry, and neither an approval of unrelated authority nor a
ceiling review clears the restriction ({{ceiling-review}}).
Completion-discharged authority therefore cannot be resurrected by
policy.

**Contained authority.** The drawdown policy MUST NOT
policy-adjudicate a successor whose complete Authority Set, including
authority carried forward from its predecessor, overlaps in authority
capability under a containment restriction of its expansion chain
({{I-D.draft-mcguinness-oauth-mission-containment}}). Such a request
falls back to a fresh human approval whose consent disclosure names
the contained capability and the event class that caused its
containment.

The Mission Issuer MUST apply this test to every drawdown in the chain
after the containment, not only to one from the Mission that holds the
overlay, and neither an approval of unrelated authority nor a ceiling
review clears the restriction ({{ceiling-review}}). A drawdown whose
authority overlaps no restricted capability remains eligible for
policy adjudication under the other guards of {{in-ceiling-expansion}}.
Contained authority therefore cannot be restored by policy.

Both tests are re-applied at successor activation, so a containment
or discharge that lands after adjudication is caught there
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Concurrent
Expansion Reconciliation").

**Review cadence.** A drawdown for a chain past its ceiling review
cadence also falls back to a fresh human approval ({{ceiling-review}}).

### Drawdown Bounds {#drawdown-bounds}

Policy adjudication is bounded per drawdown and across the chain, so
a pre-consented ceiling cannot become a standing grant that a
compromised agent reaches through unattended drawdowns.

A single policy-adjudicated in-ceiling drawdown MUST NOT activate the
entire remaining ceiling. A drawdown activates the entire remaining
ceiling when its successor's Authority Set holds all the authority the
ceiling grants: every `authority_ceiling` entry, taken one action at a
time, is a subset of some entry of the successor's Authority Set under
the issuance profile's subset rule, constraints and resource narrowing
included ({{I-D.draft-mcguinness-oauth-mission}}). A comparison the
subset rule cannot decide counts as activating it. Policy adjudication
therefore never reaches the entire ceiling: the final increment always
takes a fresh human approval.

The drawdown policy MUST bound each drawdown incrementally, by one or
both of:

- a per-drawdown delta bound; or
- narrowing the successor's Authority Set to what the triggering
  action needs.

The concrete per-drawdown bound MUST be published in the Mission
Deployment Profile.

Each in-ceiling drawdown creates a successor Mission, so a
per-Mission bound would reset at every step. A deployment:

- MUST rate-bound policy-adjudicated expansions per expansion chain,
  keyed by the chain's root Mission and counted across `predecessor`
  links per unit time;
- MUST publish the concrete rate bound in the Mission Deployment
  Profile; and
- MUST record each policy-adjudicated expansion as an approval event
  whose decision mechanism is the drawdown policy that authorized it
  ({{audit-linkage}}).

A drawdown that would activate the entire remaining ceiling, or that
exceeds the per-drawdown bound or the chain rate bound, falls back to
a fresh human approval, exactly as a request the drawdown policy does
not authorize does ({{policy-adjudication}}).

### The Successor Mission {#drawdown-successor}

The successor is created as the expansion profile requires: its
Authority Set freshly derived and bound by the ceiling, its
`predecessor` member set, the predecessor superseded. The successor's
`subject` and `authority_source` are the predecessor's, and the commit
that activates it checks that source's ceiling
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Successor
Subject and Authority Source").

An in-ceiling successor MUST carry the predecessor's
`authority_ceiling` and `drawdown_policy` unchanged or narrowed,
committed under the same or, when narrowed, a recomputed
`ceiling_hash`. Any change to either beyond narrowing requires a fresh
human approval, never policy adjudication.

A drawdown that passes every policy-adjudication guard of
{{in-ceiling-expansion}} completes synchronously in the
token-exchange response ({{I-D.draft-mcguinness-oauth-mission-expansion}},
Section "The Expansion Request"), which returns the successor's
access token. The successor is still created through the full
approval-event machinery of the expansion profile, under the
`ceiling_drawdown` basis ({{ceiling-drawdown-basis}}); only the
interactive prompt is skipped. The Mission Issuer MUST commit the
successor's activation, the predecessor's supersession, and the
creation reservation, applying the expansion profile's activation
checks in that same atomic step, before it delivers the response. A
lost response is recovered through `creation_request_id`
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Creation
Idempotency").

In the example scenario ({{example-scenario}}), the agent finds an
adjustment of USD 180 to post at 09:15:00. Its Mission lacks
`journal-entries.write`, so the client requests an expansion as an
{{RFC8693}} token exchange, proving possession of the Mission's access
token with a DPoP proof {{RFC9449}}. The `mission_intent` carries the
baseline Q3 Intent. The following is an example of the request; client
authentication is omitted, and extra line breaks are for display only:

~~~ http
POST /token HTTP/1.1
Host: as.example.com
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2Iiwi...

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange&
requested_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&
subject_token=<the%20Mission%27s%20access%20token>&
subject_token_type=
  urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token&
mission_intent=%7B%22intent%22%3A%7B...%7D%7D&
predecessor=msn_pasG9An7Ivj9cOdd3RqWWonuaLAbDHtM&
creation_request_id=787d127f-df08-5d87-bf49-ed64a323194a
~~~

The derived successor Authority Set is the baseline's: the read entry
and the journal-write entry, each a ceiling entry. It adds one action,
within the per-drawdown bound, and leaves `invoices.write` undrawn.
No condition of {{fresh-approval}} applies, the drawdown is the
chain's first, the ceiling consent is 75 minutes old against a 30-day
review cadence, and the policy snapshot matches its `digest` and
authorizes the widening. The drawdown policy therefore adjudicates the
request. The following is an example of the response, which carries
the successor's access token and its granted `authorization_details`:

~~~ json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6ImF0K2p3dCJ9...",
  "issued_token_type":
    "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "DPoP",
  "expires_in": 300,
  "mission_id": "msn_uG1kkHwXSlzUs4OKztGGk5FOmBnkpTOb",
  "mission_expires_at": "2026-12-31T23:59:59Z",
  "authorization_details": [
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["invoices.read"],
      "constraints": {
        "resource_issued_after": "2026-07-01T00:00:00Z",
        "resource_issued_before": "2026-09-30T23:59:59Z"
      },
      "delegation": {
        "max_depth": 2,
        "allowed_delegates": [{ "sub_profile": "ai_agent" }]
      } },
    { "type": "mission_resource_access",
      "resource": "https://erp.example.com",
      "actions": ["journal-entries.write"],
      "constraints": {
        "max_amount": { "amount": "500.00", "currency": "USD" } } }
  ]
}
~~~

### Ceiling Re-Consent {#ceiling-reconsent}

A fresh human approval in a chain that carries a ceiling, whether the
request fell back from policy adjudication or lay outside the ceiling,
makes two separate decisions: the Approver approves the successor's
authority and can, separately, re-consent the ceiling.

Without an explicit re-consent, the successor MUST carry the
predecessor's `authority_ceiling`, `drawdown_policy` and
`ceiling_hash` unchanged, together with the instant and the Approver
of the ceiling consent they commit, and the ceiling review cadence
does not restart. Authority approved beyond the ceiling stays outside
it: a later expansion whose Authority Set retains that authority is
outside the ceiling ({{ceiling-test}}).

Where the Approver explicitly re-consents a ceiling and drawdown
policy at that approval, the successor MUST record the re-consented
`authority_ceiling` and the selected `drawdown_policy` under a
recomputed `ceiling_hash`, with the re-consent's instant and Approver
as those of the ceiling consent. The ceiling review cadence restarts
from that instant ({{ceiling-review}}). The consent disclosure MUST
render the re-consented ceiling and policy as at the initial approval
({{progressive-authorization}}).

Either way the expansion chain continues: its root, `predecessor`
links, rate-bound window, cumulative drawdown count, and every
discharge and containment restriction carry forward, and a re-consent
clears none of them.

### The ceiling_drawdown Approval Basis {#ceiling-drawdown-basis}

A policy-adjudicated in-ceiling successor is rooted in a
standing-consent `approval_basis`, under the issuance profile's open
`type` set ({{I-D.draft-mcguinness-oauth-mission}}), with `type`
`ceiling_drawdown`, defined and owned by this profile. Its members
are:

- `consent_principal`: the Approver who consented the ceiling;
- `activation`: an object with exactly two members, `policy_id` (the
  Mission's `drawdown_policy.id`) and `policy_version` (its
  `drawdown_policy.version`, the version whose content
  `drawdown_policy.digest` commits and this adjudication evaluated);
- `activation_actor`: the requesting client;
- `root_commitment`: the `ceiling_hash`; and
- `approved_at` (the issuance profile's standing-consent
  requirement): the instant the Approver consented the ceiling that
  `ceiling_hash` commits, read from the Mission Issuer's retained
  record of that consent, never from the drawdown request.

The successor record's `approval_event_id` identifies this drawdown,
never the ceiling consent: a unique value the Mission Issuer allocates
when it creates the exchange's `(client, creation_request_id)`
reservation and retains with the committed successor
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Creation
Idempotency"). A retry recovers it; a reservation created after that
key's tombstone expires receives a new one.

The following is an example of the scenario's successor record
({{example-scenario}}), other members omitted:

~~~ json
{
  "id": "msn_uG1kkHwXSlzUs4OKztGGk5FOmBnkpTOb",
  "issuer": "https://as.example.com",
  "predecessor": "msn_pasG9An7Ivj9cOdd3RqWWonuaLAbDHtM",
  "subject": { "iss": "https://idp.example.com",
    "sub": "user_3p2q8mN1a0kV7tR" },
  "approval_basis": {
    "type": "ceiling_drawdown",
    "consent_principal": { "iss": "https://idp.example.com",
      "sub": "user_3p2q8mN1a0kV7tR" },
    "activation": { "policy_id": "q3-reconcile-drawdown",
      "policy_version": "1" },
    "activation_actor": { "iss": "https://as.example.com",
      "sub": "s6BhdRkqt3" },
    "root_commitment":
      "sha-256:8PkE9J8vIWBKyPTG21yYer3W3BPP8opLI2moZr3S-kw",
    "approved_at": "2026-11-02T08:00:00Z"
  },
  "approval_event_id": "ape_1hJEKlr4vhnTLqwrYhpX",
  "ceiling_hash":
    "sha-256:8PkE9J8vIWBKyPTG21yYer3W3BPP8opLI2moZr3S-kw",
  "created_at": "2026-11-02T09:15:00Z"
}
~~~

`approved_at` is the instant of the ceiling consent, not of the
drawdown. The successor carries the predecessor's `authority_ceiling`
and `drawdown_policy` unchanged, so its `ceiling_hash` is the
predecessor's.

The child delegation profile's `policy_drawdown` basis
({{I-D.draft-mcguinness-oauth-mission-child-delegation}}) is not
reused: that value names policy-approved child creation, not a
ceiling drawdown.

The issuance profile's fourth high-risk class, a consumption bound
({{I-D.draft-mcguinness-oauth-mission}}, Section "Approver
Authentication Strength"), is not held back here. A successor
continues its predecessor's consumption counters, and a
policy-adjudicated successor cannot raise a bound
({{I-D.draft-mcguinness-mission-metering}}), so a drawdown widens
authority within the ceiling without granting new capacity.

The `ceiling_drawdown` `approval_basis` already carries the trace the
issuance profile's approval-authentication floor requires for a
consumption bound, through the `consent_principal` and `approved_at`
fields this section defines. A deployment recording Consent Evidence
renders the bound at the same surface under the metering profile's
consent-integrity rule ({{I-D.draft-mcguinness-mission-metering}}).

Where a deployment adopts Approval Governance
({{I-D.draft-mcguinness-mission-approval-governance}}) and records a
Governance Record for a policy-adjudicated drawdown, the
`ceiling_drawdown` `approval_basis` satisfies that profile's
accountable-approver rule directly, through the same
`consent_principal`, `root_commitment`, and `approved_at` this
document already requires. No assertion is fabricated in the name of
the requesting client or the drawdown policy to stand in for a fresh
human decision that did not occur. Approval Governance's own
high-risk-class default still binds that record: a policy-adjudicated
drawdown carrying a consumption bound
activates only where a committed, class-named exception admits it;
absent the exception, the Mission fails to activate under that
profile's atomic-commitment rule.

### Derivation Limits {#drawdown-derivation-limits}

This section binds only a deployment that also adopts Mission
Derivation Limits
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}). A
policy-adjudicated drawdown continues its predecessor's undertaking,
so it cannot replenish the predecessor's allowance of counted
derivations:

- The successor MUST carry forward the predecessor's committed
  derivation count. Where the predecessor has a `derivation_limit`,
  the successor's `derivation_limit` MUST NOT exceed it: a stricter
  authorization-server policy ceiling or `requested_derivation_limit`
  narrows it further, and omitting or raising the request neither
  removes nor raises it. A predecessor without a `derivation_limit`
  has no finite limit to pass on, and the successor's is established
  as Mission Derivation Limits states
  ({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}, Section
  "Effective Limit").
- The Mission Issuer MUST read the predecessor's committed count and
  transfer it in the atomic step above that activates the successor,
  supersedes the predecessor, and commits the creation reservation,
  after any predecessor derivation that commits first. Concurrent
  derivation under the predecessor and competing or duplicate
  drawdowns MUST NOT fork or replenish the remaining allowance.
- The successor access token the drawdown response returns is one
  derivation, charged to the successor in that same atomic step and
  never again to the predecessor. Where the carried-forward count plus
  that derivation would exceed the successor's `derivation_limit`,
  the Mission Issuer MUST refuse the drawdown as Mission Derivation
  Limits refuses a derivation
  ({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}, Section
  "Enforcement at Issuance"), with `invalid_grant` and its
  `mission_error` diagnostic, creating no successor, superseding no
  predecessor, and counting nothing.
- An exact creation retry MUST return the recorded result without
  repeating its accounting; returning the existing access token adds
  no derivation. A fresh delivery token minted on recovery is ordinary
  issuance ({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section
  "Recovery Is Delivery"), counted against and gated by the
  successor's `derivation_limit`.

The ceiling consent's disclosure ({{progressive-authorization}}) MUST
state this inheritance, as Mission Derivation Limits requires of a
standing consent
({{I-D.draft-mcguinness-oauth-mission-derivation-limits}}, Section
"Approval Rendering"): policy-adjudicated
successors carry forward the Mission's derivation count and never
exceed its rendered `derivation_limit`, or, where the Mission has
none, no finite limit is guaranteed for them.

A successor created by a fresh human approval establishes its limit
afresh, as Mission Derivation Limits states. This bounds counted
derivations through the drawdown succession only, not a Mission's
descendants, other tokens, or resource effects.

## What It Bounds, and What It Does Not {#progressive-limits}

The ceiling is broad by construction, since it must cover the
open-ended task. What stays narrow is the active authority any single
Mission in the chain yields: each in-ceiling successor is derived for
the authority actually needed at that step and is independently gated
and revocable.

A compromised agent cannot instantly wield the ceiling. It can
exercise only the current active authority and request in-ceiling
drawdown, which is policy-gated, bounded per drawdown and rate-limited
per chain ({{drawdown-bounds}}), recorded for audit
({{audit-linkage}}), and enforced per action by the runtime layer
({{I-D.draft-mcguinness-mission-runtime}}).

Progressive authorization bounds, and does not eliminate,
standing-authority exposure. A deployment SHOULD pair it with short
successor lifetimes, constraint-bounded ceilings, and runtime
enforcement.

## The Ceiling Review {#ceiling-review}

A pre-consented ceiling is standing consent, and standing consent
decays: a chain renewed indefinitely on policy alone is a standing
grant. This profile therefore bounds the chain in time, not only per
drawdown and per unit time ({{drawdown-bounds}}).

A deployment MUST publish a **ceiling review cadence** in its
Mission Deployment Profile. The Mission Issuer MUST NOT
policy-adjudicate an in-ceiling drawdown for a chain whose most
recent human approval of the ceiling is older than that cadence: the
request falls back to a fresh human approval, exactly as a request
the drawdown policy does not authorize does
({{policy-adjudication}}).

The cadence is a recency ceiling on the `ceiling_drawdown` approval
basis's `approved_at`, the kind of declared maximum standing-consent
age the issuance profile permits a deployment to declare
({{I-D.draft-mcguinness-oauth-mission}}); this profile makes
publishing one mandatory rather than optional.

The cadence is part of the drawdown policy's own versioned content: a
deployment's drawdown policy document MUST state the cadence effective
under a given version, identified by the `policy_id` and
`policy_version` the `ceiling_drawdown` activation carries
({{ceiling-drawdown-basis}}), per the issuance profile's own rule that
a mutable, unversioned value MUST NOT serve this role.

Because `ceiling_hash` commits that policy's `digest`, the cadence is
anchored with it. Changing the cadence changes the policy snapshot, so
a drawdown under the changed policy no longer matches the committed
`digest` and falls back to a fresh human approval until a review
approval re-consents the ceiling under the new policy. An auditor
recovers the cadence that governed a given drawdown from the retained
snapshot that `digest` names, exactly as it resolves the drawdown
logic itself.

The review approval is an ordinary expansion approval that
re-consents, or narrows, the ceiling ({{ceiling-reconsent}}). Its
consent disclosure MUST render the chain's record since the prior
review:

- the drawdown count and rate;
- the guard exceptions escalated to human approval;
- the `out_of_ceiling` refusals;
- the entries discharged under the Entry Discharge companion's
  completion machinery ({{I-D.draft-mcguinness-oauth-mission-discharge}}),
  and the chain's outstanding discharge restrictions, which
  re-consenting the ceiling does not clear;
- the chain's outstanding containment restrictions, each with its
  contained capability and the event class that caused it
  ({{I-D.draft-mcguinness-oauth-mission-containment}}), which
  re-consenting the ceiling does not clear; and
- where the metering profile runs, consumption against its bounds
  ({{I-D.draft-mcguinness-mission-metering}}).

Where consent evidence is claimed, that disclosure is committed like
any other ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}),
so the record shows the reviewer saw the cycle they renewed. The
review is where decay is caught; {{sec-consent-decay}} names the tells
a reviewer checks the records for.

## Realizing an Approved Access Request {#arap-feedback}

Progressive authorization grows authority that a deployment anticipated
well enough to express as a ceiling. The runtime enforcement layer
handles the unanticipated case: it can let an agent request authority
it discovers it needs at the point of use, through an access-request
and approval workflow ({{I-D.draft-mcguinness-mission-runtime}}). That
workflow yields a permit for the single re-evaluated action.

To persist the newly approved authority for the rest of the task,
rather than have the agent re-request it on every call, the Mission
Issuer MAY realize an approved access request as an expansion:

- a request whose authority is within the Mission's consented ceiling is
  realized as a policy-adjudicated in-ceiling expansion
  ({{in-ceiling-expansion}}); and
- a request whose authority exceeds the ceiling is realized only on the
  fresh human approval the request carries, as an ordinary expansion
  ({{ceiling-test}}); the ceiling rises only where the Approver also
  re-consents it ({{ceiling-reconsent}}).

Realizing a request as an expansion is subject to every rule of the
expansion profile: the successor's authority is freshly derived and
bound, the predecessor is superseded, and authority is never widened
without the consent the request carries
({{I-D.draft-mcguinness-oauth-mission-expansion}}). An access request
not realized as an expansion grants only the single runtime permit and
no durable Mission authority.

# The out_of_ceiling Denial Reason {#denial-reason}

This document extends the expansion profile's closed set of expansion
denial reasons ({{I-D.draft-mcguinness-oauth-mission-expansion}}) by
specification, as that profile's IANA considerations anticipate, with
one value, carried in `mission_denial_reason` exactly as that
profile's reasons are:

`out_of_ceiling`:
: The requested authority is not within the Mission's consented
  authority ceiling ({{progressive-authorization}}), and the Mission
  Issuer refused the expansion instead of taking it to a fresh human
  approval ({{ceiling-test}}).

A consumer that does not implement this document treats
`out_of_ceiling` as it treats any unrecognized reason code: the
expansion stays denied.

The expansion profile surfaces a denial on the token-exchange response
as an OAuth error with the reason code in `mission_denial_reason`
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Expansion
Denial Reasons"). Had the Mission Issuer's policy refused the
scenario's request at 09:18:00 ({{ceiling-test}}) instead of taking it
to `alice`, the following is an example of a refusal that carries the
code:

~~~ http
HTTP/1.1 400 Bad Request
Content-Type: application/json
Cache-Control: no-store

{
  "error": "invalid_request",
  "mission_denial_reason": "out_of_ceiling"
}
~~~

# Audit Linkage {#audit-linkage}

Each policy-adjudicated in-ceiling expansion is an approval event and
MUST be recorded as one, in which:

- the decision mechanism is the drawdown policy (its identifier and
  version) rather than a human;
- the Approver who consented the ceiling remains the accountable
  `consent_principal` ({{I-D.draft-mcguinness-oauth-mission}}, Section
  "Role Mapping"); and
- the successor's `predecessor` member links the drawdown chain for an
  authorized auditor exactly as for human-approved expansions
  ({{I-D.draft-mcguinness-oauth-mission-expansion}}).

The record MUST carry the chain's cumulative drawdown count, so the
rate bound of {{drawdown-bounds}} is auditable from the records
alone.

A deployment MUST retain the consented `authority_ceiling`,
`drawdown_policy`, and `ceiling_hash` with every Mission record in
the chain for the audit horizon. An auditor can then verify that every
drawdown was within the consented envelope and, by resolving the
retained drawdown policy document at the `policy_version` each
drawdown's `ceiling_drawdown` approval basis already records, that it
was adjudicated within the cadence that applied at the time
({{ceiling-review}}).

Where a drawdown is triggered by the agent encountering a resource
not named at approval, and the resource self-declares its operations
and consequences in a content-addressed form, the adjudication MUST
evaluate the declaration against the ceiling. The record of such a
drawdown MUST carry the declaration's digest as
`resource_declaration_digest`, so the encounter is reproducible in
audit: what the resource claimed to be when authority bound to it. An
AAuth deployment adopting Rich Resource Requests composes one such
self-declaring substrate ({{I-D.draft-mcguinness-mission-aauth}}).

The discovery companion ({{I-D.draft-mcguinness-mission-discovery}})
defines the encounter adjudication contract, the identity pinning,
and the floors this drawdown path carries.

# Conformance {#conformance}

A Mission Issuer that claims **Expansion with Progressive
Authorization** is a conforming expansion-capable Mission Issuer
({{I-D.draft-mcguinness-oauth-mission-expansion}}) and MUST:

- for a Mission whose Approver consented to a ceiling, record the
  consented `authority_ceiling` and `drawdown_policy` on the Mission
  and commit them with `ceiling_hash` ({{progressive-authorization}});
- evaluate a requested successor Authority Set as in-ceiling by the
  subset rule, and never policy-adjudicate an out-of-ceiling request
  ({{ceiling-test}});
- for a successor that a fresh human approval creates in a chain that
  carries a ceiling, carry the predecessor's ceiling members unchanged
  unless the Approver explicitly re-consents a ceiling and drawdown
  policy, record a re-consent under a recomputed `ceiling_hash` with
  its own instant and Approver, and preserve the chain's history and
  restrictions ({{ceiling-reconsent}});
- bound each policy-adjudicated drawdown incrementally, so a single
  drawdown never activates the entire remaining ceiling, and publish the
  concrete per-drawdown bound in the Mission Deployment Profile
  ({{drawdown-bounds}});
- fall back to a fresh human approval for a drawdown that would
  activate the entire remaining ceiling, or that exceeds the
  per-drawdown bound or the chain rate bound ({{drawdown-bounds}});
- enforce the prohibited-class rule, requiring a fresh human approval for
  a drawdown that grants irreversible, external-commitment, or
  privileged-administration authority, that satisfies the
  external-communication predicate, or that grants cross-domain
  authority, and publish the action-class mapping in the Mission
  Deployment Profile ({{fresh-approval}});
- require a fresh human approval for an in-ceiling drawdown while the
  predecessor has non-terminal Child Missions ({{fresh-approval}});
- require a fresh human approval for a drawdown whose complete
  Authority Set overlaps authority under a containment or discharge
  restriction of its chain, from any Mission in the chain
  ({{fresh-approval}});
- rate-bound policy-adjudicated drawdowns per expansion chain, keyed by
  the chain's root Mission and counted across `predecessor` links,
  publish the concrete rate bound in the Mission Deployment Profile, and
  record each as an approval event carrying the chain's cumulative
  drawdown count ({{drawdown-bounds}}, {{audit-linkage}});
- bound each chain by the published ceiling review cadence, refusing
  policy adjudication past it, rendering the chain's record since the
  prior review in the review approval's disclosure, and stating the
  cadence effective under each drawdown policy version in that
  policy's own versioned content ({{ceiling-review}}); and
- where the deployment also adopts Mission Derivation Limits, carry a
  policy-adjudicated drawdown's derivation count and limit forward,
  count its
  successor access token once, and refuse a drawdown that would
  exceed the limit without creating a successor or superseding the
  predecessor ({{drawdown-derivation-limits}}).

# Security Considerations {#security-considerations}

The expansion profile's security considerations apply in full
({{I-D.draft-mcguinness-oauth-mission-expansion}}). This document adds
the drawdown surface.

## Unattended Drawdown {#sec-unattended-drawdown}

The ceiling is consented once and drawn on many times. A compromised
agent can request in-ceiling drawdown unattended. The mitigations are
the rate bound ({{drawdown-bounds}}), the prohibited-class rule
({{fresh-approval}}), the fall-back to human approval for unauthorized
drawdowns ({{policy-adjudication}}), and per-action runtime
enforcement ({{I-D.draft-mcguinness-mission-runtime}}).

## The Drawdown Policy as Governance {#sec-drawdown-policy}

The drawdown policy is authority-bearing governance. A misconfigured
policy over-grants within the ceiling; it MUST be reviewed and
versioned like approval policy, and its identity and version are
recorded as the decision mechanism ({{audit-linkage}}).

## The Ceiling as a Consent Artifact {#sec-ceiling-consent}

The ceiling is a consent artifact. It MUST be rendered to the
Approver at the initial approval with the fact that in-ceiling
expansion is policy-adjudicated ({{progressive-authorization}}); a
ceiling the Approver did not knowingly consent to is standing
authority obtained by omission.

## Probing the Ceiling {#sec-ceiling-probing}

A refusal that carries `out_of_ceiling` tells the requester that its
request fell outside the ceiling, so repeated requests can map the
ceiling. Omitting the code keeps the ceiling undisclosed
({{ceiling-test}}). The expansion profile's per-predecessor rate limit
bounds such probing either way
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Policy
Probing").

## Consent Decay {#sec-consent-decay}

Consent decays even when nothing is misconfigured: the drawdown and
rate bounds cap rate, not duration, and the ceiling review
({{ceiling-review}}) is the temporal bound. The tells of decay are
checkable from the chain's own records:

- reviews that never narrow the ceiling;
- ceilings that only grow;
- guard exceptions trending toward zero because the policy was
  quietly widened; and
- discharge that never fires because no unit of work is scoped
  tightly enough to complete.

A review that cannot cite the evidence of the cycle it renews has not
reviewed it.

# Privacy Considerations {#privacy-considerations}

The ceiling discloses, at initial approval time, the full envelope a
task may grow into, which can reveal more about the anticipated task
than any single Mission's Authority Set.

The expansion profile's predecessor-chain correlation considerations
apply to the drawdown chain
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section
"Predecessor-Chain Correlation"). Access to the ceiling and drawdown
records SHOULD be scoped to parties with a governance need.

# IANA Considerations {#iana}

This document requests one registration ({{iana-denial-reason}}).
`authority_ceiling` and `drawdown_policy` are Mission record members
defined by this profile, and the `mission-authority-ceiling` anchor
`typ` follows the issuance profile's collision-resistant `typ`
convention; none of these requires registration.

## Mission Denial Reasons Registration {#iana-denial-reason}

This document requests registration of the following value in the
"Mission Denial Reasons" registry
({{I-D.draft-mcguinness-oauth-mission-expansion}}, Section "Mission
Denial Reasons Registry"):

- Value: `out_of_ceiling`
- Semantics: The requested authority is not within the Mission's
  consented authority ceiling, and the Mission Issuer refused the
  expansion.
- Change Controller: IETF
- Reference: this document, {{denial-reason}}

--- back

# Document History {#document-history}

\[\[ To be removed from the final specification ]]

-01

- Ceiling Test and new Ceiling Re-Consent: a request outside the
  ceiling is never policy-adjudicated and falls back to an ordinary,
  freshly approved expansion, subject to the Mission Issuer's policy; a
  refusal MAY carry `out_of_ceiling`, which a response starting the
  human approval never carries. A human-approved successor carries the
  ceiling members unchanged unless the Approver explicitly re-consents
  a ceiling and drawdown policy; the chain's history and restrictions
  continue either way (#1413, #1415, D555).
- Drawdown Bounds: a drawdown that would activate the entire remaining
  ceiling, or that exceeds the per-drawdown bound or the chain rate
  bound, falls back to a fresh human approval. The entire remaining
  ceiling is defined by the subset rule, one action at a time, so the
  final increment always takes a fresh human approval (#1414, D555).
- Editorial: In-Ceiling Expansion in subsections, Relationship and
  Terminology under the Introduction, a Protocol Overview, Title Case
  headings, Security Considerations in subsections, and the IANA
  request as a registration template. The Derivation Limits adoption
  condition covers its whole subsection, as the #1119 entry below
  describes. Examples on the baseline fixture's `ceiling-drawdown`
  variant: the ceiling members and policy snapshot, a drawdown request
  and response, the successor record, and an `out_of_ceiling` refusal.
  No requirement is added or removed.
- Relationship to the Expansion Profile: `superseded` is the
  expansion profile's termination reason, not a lifecycle state
  (#705).
- In-ceiling expansion: a `ceiling_drawdown` successor keeps its
  predecessor's `subject` and `authority_source`, and its activating
  commit checks that source's ceiling, as the expansion profile
  requires of every successor (#1118).
- In-ceiling expansion: where Mission Derivation Limits is also
  adopted, the ceiling consent's disclosure states that
  policy-adjudicated successors carry the Mission's derivation count
  and limit forward, or that no finite limit is guaranteed where the
  Mission has none (#1119).
- In-ceiling expansion: where Mission Derivation Limits is also
  adopted, a policy drawdown carries its predecessor's committed
  derivation count and limit forward (a stricter ceiling can narrow
  the limit; nothing raises or resets it), counts its successor access
  token once in the atomic creation step, and is refused under Mission
  Derivation Limits' enforcement rule, creating and superseding
  nothing, when
  the limit would be exceeded (#1079).
- Audit Linkage and In-Ceiling Expansion name the drawdown policy as
  the approval event's decision mechanism, not its approver; the
  Approver who consented the ceiling stays the `consent_principal`,
  matching the issuance profile's Role Mapping.
- In-ceiling expansion: a `ceiling_drawdown` successor's
  `approval_event_id` identifies the drawdown: a unique value allocated
  with the exchange's `(client, creation_request_id)` reservation and
  retained with the successor, so a retry recovers it and reuse of the
  key after its tombstone expires receives a new one; no new member
  (#1017).

- In-ceiling expansion: a drawdown that passes every policy-adjudication
  guard completes synchronously in the token-exchange response,
  committing activation, supersession and the creation reservation
  before the response; the undefined `request_uri` redemption is
  removed.
- In-ceiling expansion: the discharge guard tests the complete successor
  Authority Set against the chain's discharge restrictions, from any
  later Mission, and the ceiling review discloses outstanding discharge
  restrictions.
- In-ceiling expansion: a policy-adjudicated drawdown whose complete
  Authority Set overlaps capability under a containment restriction of
  its chain falls back to a fresh human approval naming the contained
  capability and its cause, from any later Mission in the chain; the
  ceiling review discloses outstanding restrictions and does not clear
  them.
- `drawdown_policy` is an activation policy reference (`id`,
  `version`, `digest`) under the issuance profile's Standing-Consent
  Bases, replacing the string or URI and the SHOULD to commit the
  policy body; `ceiling_hash` covers the object, and a snapshot that
  does not match falls back to a fresh human approval. The
  `ceiling_drawdown` activation maps to `drawdown_policy.id` and
  `.version`, and the review cadence, part of the policy content, is
  anchored with it.
- The consumption-bound rationale rests on the metering profile's
  successor rule: a successor continues its predecessor's counters, and
  a policy-adjudicated successor cannot raise a bound.
- Editorial: disambiguated `authority_ceiling` from the template
  profile's Template Ceiling and the shaping companion's shaping
  ceiling at its first definition ({{conventions-and-terminology}}), no
  normative change.
- Mirrored the OAuth binding's Mission Template uncommitted-policy-body
  pattern onto `drawdown_policy`: a SHOULD to additionally commit the
  policy body under an integrity anchor or disclose it under Consent
  Evidence ({{progressive-authorization}}). Reframed the ceiling
  review cadence as a recency ceiling on the `ceiling_drawdown`
  approval basis's `approved_at`, reproducible from the drawdown
  policy's own versioned content identified by the existing
  `policy_id`/`policy_version` rather than a new commitment or a new,
  separately versioned member ({{ceiling-review}}, {{audit-linkage}}).

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and extends Mission Expansion with an experimental pre-consented
drawdown mechanism.
