---
title: "Mission Completion for OAuth 2.0"
abbrev: "OAuth Mission Completion"
category: std

docname: draft-mcguinness-oauth-mission-completion-latest
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
 - completion
 - discharge
venue:
  github: "mcguinness/draft-mcguinness-oauth-mission"
  latest: "https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-completion.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  RFC7515:
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
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-mission-runtime-latest
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-status-latest
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/draft-mcguinness-oauth-mission/draft-mcguinness-oauth-mission-signals.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
    seriesinfo:
      Internet-Draft: draft-mcguinness-oauth-mission-signals-latest

--- abstract

Mission-Bound Authorization for OAuth 2.0 commits an approved Authority
Set and gates issuance on Mission state, but a Mission keeps deriving an
entry's authority until it is revoked or expires, even after the task
that entry was granted for is finished. The Intent's `success_criteria`
record when a task is done but are inert. This document defines an
OPTIONAL Mission Completion profile. It adds `terminal_when`, a
completion condition carried in a `mission_resource_access` entry's
`constraints` that, once met, **discharges** the Authority Set entry:
the Authorization Server stops deriving tokens carrying that entry. Discharge is monotonic, it can only remove an
entry's authority and never widen it, so it is safe against a
prompt-injected agent by construction; it composes with the subset rule
as a condition a derived entry can add but never drop; and it lets a
multi-resource Mission complete one entry at a time. It is the
enforceable counterpart of the inert `success_criteria`.

--- middle

# Introduction

The issuance profile {{I-D.draft-mcguinness-oauth-mission}} (the
"issuance profile") gates issuance on Mission state: an `active` Mission
derives tokens, a `revoked` or `expired` Mission does not. It has no
notion of an approved entry being **done**. A Mission granted authority
to release a record "for this enrollment" keeps deriving that authority
after the enrollment closes, until a clock or a revoke stops it. The
Intent's `success_criteria` describe when the task is complete, but the
issuance profile keeps them inert: they are rendered and committed, and
carry no machine effect ({{I-D.draft-mcguinness-oauth-mission}}).

This document supplies the enforceable counterpart. It defines
`terminal_when`, an OPTIONAL Common Constraint
({{I-D.draft-mcguinness-oauth-mission}}) on a `mission_resource_access`
entry that carries one or more completion conditions. When a condition
is met, the entry is **discharged**: the Authorization Server MUST NOT
thereafter derive a token carrying that entry, exactly as it refuses
derivation for a non-`active` Mission.

Three properties make this safe inside the Mission model and this
document requires all three:

- **Discharge is monotonic.** It only removes an entry's authority; it
  can never widen the entry or the Mission. A prompt-injected agent
  therefore cannot use it to gain anything: the worst it can do is spend
  its own authority sooner, which is not an attack.
- **Discharge composes with the subset rule.** A derived entry carries
  its parent's completion conditions unchanged and MAY add more, the same
  way constraints may be added or tightened but never dropped.
- **Discharge fails closed.** A consumer that does not understand
  `terminal_when` refuses the entry rather than ignoring the condition,
  and an Authorization Server that cannot determine a condition's status
  refuses to derive.

Discharge gates at the entry, not the Mission, so a multi-resource
Mission completes one entry at a time while the Mission remains `active`
for the rest. It also strengthens the kill switch: a task that finishes
stops issuing its own authority without waiting for a clock or a revoke.

# Status: An OPTIONAL Extension {#optional-status}

This document is OPTIONAL. A deployment that ends an entry's authority
only by Mission revocation or expiry is fully conformant to the issuance
profile and is unaffected by this document. It places no new requirement
on the issuance profile; it defines one OPTIONAL entry member and the
rules for handling it.

A deployment claims this profile only when it issues or consumes entries
carrying `terminal_when`.

This profile is newer and less exercised than the issuance core and the
runtime layer, and is not part of the recommended v1 deployment bundles.
Its entry-discharge details may change.

# Relationship to the Issuance Profile {#issuance-relationship}

This document depends normatively on the issuance profile and is not
implementable alone. It reuses, without restating, the issuance profile's
Mission, `mission_resource_access` entry, Authority Set, subset rule,
integrity anchors, lifecycle states, and issuance gating, and the inert
`success_criteria` member of the Mission Intent. It uses Mission, Mission
Issuer, Authority Set, and derivation as the issuance profile defines
them.

It extends the issuance profile in one narrow, additive way: it registers
`terminal_when`, an OPTIONAL Common Constraint on a
`mission_resource_access` entry ({{terminal-when}}), whose subset rule
the issuance profile's existing subset comparison applies
({{subset-extension}}). It changes no Mission state, the three-state
lifecycle, or the meaning of any existing member.

# Conventions and Terminology {#conventions}

{::boilerplate bcp14-tagged}

Discharge:
: The state of a `mission_resource_access` entry whose `terminal_when`
  has been met. A discharged entry's authority is spent: it is no longer
  derivable.

# Entry Completion Conditions {#terminal-when}

This document defines `terminal_when`, a Common Constraint
({{I-D.draft-mcguinness-oauth-mission}}) carried in the `constraints`
object of a `mission_resource_access` entry. It is a
specification-defined Common Constraint under the issuance profile's
naming convention ({{iana}}).

`terminal_when`:
: OPTIONAL. An array of completion conditions. When any condition is
  met, the entry is discharged ({{discharge}}). Each condition is an
  object with these members:

  `event_type`:
  : REQUIRED. A string identifying the completion event. Its semantics
    are deployment- or registry-defined and opaque to this document, as
    `purpose` is ({{I-D.draft-mcguinness-oauth-mission}}).

  `event_source`:
  : OPTIONAL. A string. A URI the Authorization Server consults to
    determine whether the event has occurred ({{determining}}).

  `max_staleness`:
  : OPTIONAL. A string. An ISO 8601 duration, matching the `duration`
    rule in Appendix A of {{RFC3339}}, bounding how stale the
    Authorization Server's view of the event MAY be when it gates
    issuance.

The `terminal_when` array is part of the entry's `constraints` and so of
the Authority Set: it is committed by `authority_hash` and reproducible
under derivation ({{I-D.draft-mcguinness-oauth-mission}}). Whether a
condition has fired is evaluated state, not part of `authority_hash`;
folding fired status into the anchor would make the committed authority
time-varying.

`terminal_when` is the enforceable counterpart of the inert
`success_criteria` ({{I-D.draft-mcguinness-oauth-mission}}), which
remains inert: `success_criteria` describe completion for the Approver,
`terminal_when` acts on it. It is distinct from a cumulative
consumption bound, which meters volume;
a `terminal_when` condition is a single external event.

# Discharge and Issuance Gating {#discharge}

When a condition in an entry's `terminal_when` has been met, the entry is
discharged. The Authorization Server MUST NOT derive a token carrying a
discharged entry, at the token endpoint, on refresh, or on Token
Exchange, exactly as issuance is refused for a non-`active` Mission
({{I-D.draft-mcguinness-oauth-mission}}). A derivation that would carry
only discharged entries MUST fail; a derivation that carries a mix MUST
omit the discharged entries.

Discharge gates at the entry, not the Mission. The Mission remains
`active` and continues to derive its other entries: a multi-resource
Mission therefore completes partially, one entry at a time, as each
entry's task finishes. The three Mission states are unchanged; a
deployment that also tracks Mission-level completion MAY transition a
Mission whose entries are all discharged to a `completed` state where a
lifecycle profile defines one ({{I-D.draft-mcguinness-oauth-mission-status}}),
but this document does not require it.

Discharge gates new derivations only. A token already issued for an entry
remains valid until it expires, as with revocation
({{I-D.draft-mcguinness-oauth-mission}}). A deployment that needs prompt
cutoff relies on short token lifetimes or on the runtime layer denying a
discharged entry at the point of use ({{runtime}}).

## Determining Discharge {#determining}

The Authorization Server determines whether a condition has been met from
the `event_source`, within `max_staleness` when present. The mechanism is
deployment-defined (a status query, a received signal, a recorded
administrative action). This document defines one interoperable
event-source profile a deployment MAY use: the `event_source` URI is
retrieved over authenticated HTTPS and returns a signed JSON status
document, a JWS {{RFC7515}}, with these members:

- `occurred`: REQUIRED. A boolean, true when the event has occurred.
- `observed_at`: REQUIRED. An RFC 3339 {{RFC3339}} date-time at which the
  status was observed.
- `event_type`: REQUIRED. A string, the `event_type` the document
  reports.
- `source`: REQUIRED. A URI identifying the reporting source.

Other source mechanisms remain deployment-defined. The Mission Issuer
MUST authenticate and integrity-verify any event source outside its own
trust domain before acting on its report.

Once the Authorization Server observes that a condition has been met, the
discharge is recorded as Authorization-Server-side state and MUST NOT
revert, regardless of any later report from the event source: a source
that afterward reports the event as not occurred does not restore the
entry's authority.

If the Authorization Server cannot determine whether a condition has been
met, for example because `event_source` is unreachable within
`max_staleness`, it MUST treat the entry as possibly discharged and
refuse to derive it, as it fails closed for stale Mission state. Discharge
removes authority, so the conservative action when status is unknown is
to withhold issuance, never to issue.

## Discharge Visibility {#visibility}

A discharged entry is no longer derivable, so the surfaces that report a
Mission's authority MUST reflect that. Where the Mission Status profile
{{I-D.draft-mcguinness-oauth-mission-status}} is deployed, the Status
operation and the token introspection projection MUST omit a discharged
entry from the `authorization_details` they return. This is consistent
with the audience filtering those surfaces already apply: a discharged
entry, like an entry addressed to another audience, is not authority the
caller may rely on.

A per-entry discharge lifecycle signal is future work for the Mission
Lifecycle Signals profile {{I-D.draft-mcguinness-oauth-mission-signals}};
this document defines no discharge event.

# Subset Rule {#subset-extension}

Because `terminal_when` is a Common Constraint, the issuance profile's
subset comparison ({{I-D.draft-mcguinness-oauth-mission}}) applies its
defined subset rule with no new clause: for a key present in the
reference entry's `constraints`, the same key MUST be present in the
candidate entry and its value MUST be no broader under the key's
defined rule. For `terminal_when`, a candidate value is no broader
than a reference value when the candidate's condition array contains
every condition of the reference, compared structurally after the
canonicalization of the issuance profile
({{I-D.draft-mcguinness-oauth-mission}}); the candidate MAY add further
conditions.

Conditions are compared structurally, not by event semantics. A child
cannot drop or alter a parent's completion condition, only add more, so
discharge composes monotonically: an added condition can only make an
entry discharge sooner, which is a narrowing. Modifying a parent
condition is forbidden because a verifier cannot decide whether the
change discharges earlier or later from opaque `event_type` values.

# Forward Compatibility {#forward-compat}

Because `terminal_when` is a `constraints` member, a consumer that does
not recognize it fails closed by the issuance profile's Resource Server
enforcement rule directly: a consumer MUST fail closed on any
`constraints` key it does not understand, or understands but cannot
enforce, refusing the request rather than granting access while ignoring
the key ({{I-D.draft-mcguinness-oauth-mission}}). Discharge is
load-bearing narrowing, so ignoring `terminal_when` would silently widen
the grant. That enforcement rule is the honest basis of discharge's
safety: an unrecognized `terminal_when` is refused, never dropped.

An Authorization Server that does not implement this profile simply does
not emit `terminal_when`, and is unaffected. The fail-closed rule binds a
consumer that encounters the constraint without implementing it.

# Derivation Guidance {#derivation-guidance}

This guidance is non-normative. When the Authorization Server derives an
entry from the Mission Intent, a reviewable rule governs what each
element of the Intent becomes:

- an `action` if removing it would leave the task undefined;
- an ordinary `constraints` member if removing it would merely make the
  task less restrictive; and
- a `terminal_when` completion condition, itself a `constraints` member,
  if it defines when the task is satisfied, retiring the entry's
  authority rather than widening or restricting it.

The third case is what this profile adds. A bound that holds throughout
the task is an ordinary constraint; an event that ends the task is a
`terminal_when` condition. For example, "only invoices under 500 USD" is
a `max_amount` constraint, while "until the Q3 close is finalized" is
a completion condition.

# Relationship to Runtime Enforcement {#runtime}

Discharge is an issuance-gating signal and is fully meaningful at the
issuance profile alone. It is also a natural input to the runtime layer
({{I-D.draft-mcguinness-mission-runtime}}): a runtime Policy
Enforcement Point that recognizes `terminal_when` SHOULD deny a
discharged entry at the point of use, closing the window between
discharge and token expiry the same way it denies a revoked Mission. A
Policy Enforcement Point learns that an entry is discharged from the
Mission Status operation or the token introspection projection
({{visibility}}), the same way it learns a Mission is revoked. A runtime
Policy Enforcement Point that does not recognize `terminal_when` fails
closed for the entry per {{forward-compat}}.

# Worked Example {#example}

A Mission for `alice` reconciles Q3 payables. Its Authority Set has two
entries: a read over the ledger, and a write to post journal entries,
bounded to under 500 USD and discharged when the Q3 close is finalized:

~~~ json
[
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["invoices.read"] },
  { "type": "mission_resource_access",
    "resource": "https://erp.example.com",
    "actions": ["journal-entries.write"],
    "constraints": {
      "max_amount": { "amount": "500.00", "currency": "USD" },
      "terminal_when": [
        { "event_type": "accounting-period-closed",
          "event_source": "https://erp.example.com/periods/2026-Q3",
          "max_staleness": "PT15M" } ] } }
]
~~~

While the period is open, the Authorization Server derives both entries.
When the finance team finalizes the Q3 close, the `event_source` reports
the period closed. From then on the Authorization Server refuses to
derive the write entry: a refresh returns a token carrying only the read
entry. The Mission stays `active`, so the agent can still read the
ledger to finish its reconciliation report, but it can no longer post
journal entries. No revoke and no clock was needed; the write authority
retired itself when the task it was granted for completed.

If the `event_source` were unreachable when the agent refreshed, the
Authorization Server would treat the write entry as possibly discharged
and omit it, rather than risk issuing authority for a task that may have
ended ({{determining}}).

# Conformance {#conformance}

An Authorization Server conforming to this profile MUST:

- treat an entry whose `terminal_when` has been met as discharged and
  refuse to derive it ({{discharge}});
- refuse to derive an entry whose discharge status it cannot determine
  ({{determining}});
- record an observed discharge as latched state that MUST NOT revert on a
  later source report ({{determining}});
- carry every parent completion condition into a derived entry when
  narrowing, permitting only added conditions ({{subset-extension}});
- where it offers the Mission Status operation or the token introspection
  projection, omit a discharged entry from the `authorization_details` it
  returns ({{visibility}}); and
- keep the `terminal_when` condition array committed by `authority_hash`
  and keep fired status out of it ({{terminal-when}}).

A consumer conforming to this profile MUST fail closed for an entry
carrying a `terminal_when` constraint it does not understand
({{forward-compat}}).

# Security Considerations {#security-considerations}

The security considerations of the issuance profile apply. This profile
adds:

- Monotonic by construction. Discharge only removes an entry's authority,
  so it is not a path to escalation; a compromised or injected agent
  cannot use `terminal_when` to widen authority, and the worst it can do
  is retire its own authority sooner.
- Fail closed on unknown constraint. A consumer that does not understand
  the `terminal_when` constraint MUST refuse the entry
  ({{forward-compat}}); ignoring the constraint would let a discharged
  entry continue to be narrowed, projected, or enforced, defeating
  discharge.
- Fail closed on unknown status. When discharge status is
  indeterminate the Authorization Server withholds issuance
  ({{determining}}); a deployment that fails open here defeats the
  control.
- Trusted event source. `event_source` is a trusted input to issuance: a
  party that can make the source report "not yet complete" can keep an
  entry derivable past its true completion. The Mission Issuer MUST
  authenticate and integrity-verify an event source outside its own trust
  domain ({{determining}}), and SHOULD prefer sources within it.
- Already-issued tokens. Discharge gates new derivations only; a token
  already issued runs to expiry. Prompt cutoff relies on short token
  lifetimes or runtime point-of-use denial ({{runtime}}), the same caveat
  revocation carries.

# Privacy Considerations {#privacy-considerations}

A `terminal_when` condition can reveal task structure: `event_type` and
`event_source` may name a business event, a case, or a record whose mere
existence is sensitive, and they ride the token where the entry is
carried. A deployment SHOULD treat them as it treats other authority
detail, and SHOULD avoid event identifiers that disclose more than the
consuming party needs. Consulting an `event_source` also reveals the
Authorization Server's interest in that event; a deployment SHOULD weigh
that exposure when the source is operated by another party.

# IANA Considerations {#iana}

This document has no IANA actions. It defines one Common Constraint by
specification, under the issuance profile's Common Constraint
convention ({{I-D.draft-mcguinness-oauth-mission}}), which requires a
definition to fix the name, value syntax, subset rule, and intersection
rule:

- Name: `terminal_when`
- Value syntax: a JSON array of completion-condition objects, each with a
  REQUIRED `event_type` (string), an OPTIONAL `event_source` (string, a
  URI), and an OPTIONAL `max_staleness` (string, an ISO 8601 duration)
  ({{terminal-when}}).
- Subset rule: a candidate value is no broader than a reference value
  when the candidate's condition array contains every condition of the
  reference, compared structurally after the issuance profile's
  canonicalization; the candidate MAY add further conditions
  ({{subset-extension}}).
- Intersection rule: the union of the two condition arrays.
- Change Controller: IETF
- Reference: this document, {{terminal-when}}

`terminal_when` is a `constraints` member of the `mission_resource_access`
authorization details type defined by the issuance profile
({{I-D.draft-mcguinness-oauth-mission}}). `event_type` values are
deployment- or registry-defined and opaque to this document, as
`purpose` is, so this profile establishes no registry of event types.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and gives the inert `success_criteria` of the issuance profile an
enforceable, monotonic counterpart.
