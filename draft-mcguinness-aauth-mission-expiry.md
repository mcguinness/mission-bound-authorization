---
title: "AAuth Mission Expiry"
abbrev: "AAuth Mission Expiry"
category: std

docname: draft-mcguinness-aauth-mission-expiry-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - aauth
 - mission
 - agent
 - expiry
 - lifetime
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-aauth-mission-expiry.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC3339:
  I-D.draft-hardt-oauth-aauth-protocol:
    title: "AAuth Protocol"
    target: https://datatracker.ietf.org/doc/draft-hardt-oauth-aauth-protocol/10/
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026
    seriesinfo:
      Internet-Draft: draft-hardt-oauth-aauth-protocol-10

informative:
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission Context Binding for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth-management:
    title: "AAuth Mission Management"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth-management.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

AAuth approves an immutable mission blob and gives a mission two
protocol states, `active` and `terminated`, with no bound on how long
an approval remains usable. This extension defines an OPTIONAL
`expires_at` member of the approved mission blob. The expiry is
proposed and approved with the mission, covered by the native `s256`
content address, and immutable thereafter. At or after the deadline
the Person Server terminates the mission on every decision path and
issues no auth token that outlives it.

--- middle

# Introduction

An AAuth mission is approved once and then relied on for as long as it
stays `active`. The base protocol bounds token lifetimes but not the
mission itself: absent explicit termination, an approval remains usable
indefinitely through a stream of fresh short-lived tokens.

This extension gives a mission a lifetime the approver sees and
consents to. Because `expires_at` sits inside the approved mission
blob, it is part of what the Person approves, it is covered by the
`s256` content address, and it cannot be changed in place. Expiry adds
no protocol state: a mission that reaches its deadline becomes
`terminated`.

The extension changes Person Server behavior only. Agents, Resources,
and Access Servers require no changes, and deployments that do not
adopt it retain base AAuth behavior.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses Person, Agent, Person Server (PS), Access Server
(AS), Resource, Auth Token, mission, approved mission blob, mission
proposal, and the `{approver, s256}` mission reference as defined by
{{I-D.draft-hardt-oauth-aauth-protocol}}.

# The expires_at Member {#member}

This specification defines an OPTIONAL `expires_at` member of the
approved mission blob. Its value is an RFC 3339 `date-time`
{{RFC3339}}, the internet profile of the ISO 8601 form AAuth uses for
`approved_at`, and MUST identify an instant later than the blob's
`approved_at`.

Because `expires_at` is in the approved mission blob, it is covered by
`s256` and cannot be changed in place. Changing an approved expiry
requires proposing and approving a new mission, which carries a new
`s256` and therefore a new mission reference.

A mission whose approved blob has no `expires_at` member has no expiry
under this extension.

Extending the blob is consistent with its definition: AAuth enumerates
members the blob MUST include and members it MAY include and states no
rule that closes the set, the blob is the PS's own approval response
body, and a conforming Agent stores that body byte-exact whether or
not it recognizes a member.
The existing `capabilities` member already places PS-determined,
session-specific information inside the committed bytes, and
`expires_at` follows the same pattern. If a future AAuth revision
defines `expires_at` or blob-member extensibility rules, that
definition governs and this document will align with it.

# Proposal and Approval {#approval}

A mission proposal MAY include `expires_at`. The PS or the Person MAY
add or change the value during clarification, before approval. The
approved value is the one in the approved mission blob, and the Agent
verifies and stores the approved response bytes exactly as AAuth
requires.

Support is discovered from the approved blob itself: an Agent or
deployment that requires a lifetime bound checks the approved blob and
treats the member's absence according to its policy. AAuth does not
specify how a PS that does not implement this extension handles an
unrecognized proposal member, so a proposal is not a guarantee that the
approved blob will carry the bound.

An Agent that does not implement this extension still preserves the
member unmodified, because AAuth requires exact-byte storage of the
approved blob. It simply gains no early warning of the deadline.

# Enforcement {#enforcement}

At or after `expires_at`, the PS MUST atomically transition an
`active` mission to `terminated` before it processes any further
request under that mission reference. A missed scheduler callback does
not extend authority: every PS decision path MUST compare the current
time with `expires_at` before treating the mission as `active`. A
request under an expired mission is rejected exactly as under any
terminated mission, with AAuth's `mission_terminated` error.

The PS SHOULD terminate promptly at the deadline so that status and
logging reflect the transition, rather than waiting for the next
request under the reference.

The PS MUST NOT issue an Auth Token whose `exp` is later than the
mission's `expires_at` when the PS controls that expiry. In
federation, the PS MUST enforce that bound: where the AS cannot
constrain the token's `exp` to the mission's `expires_at`, the PS
MUST NOT broker or approve the issuance.

# Relationship to Other Specifications {#relationships}

The Mission Context Binding for AAuth
{{I-D.draft-mcguinness-mission-aauth}} requires this extension and
approves no mission without `expires_at`. Base AAuth deployments can
adopt this extension independently of that binding.

A PS that also implements AAuth Mission Management
{{I-D.draft-mcguinness-mission-aauth-management}} records the
transition with termination reason `expired`, exposes the approved
expiry through the status operation, and serializes automatic expiry
with explicit termination as that document specifies.

# Security Considerations

Clock synchronization, comparison precision, and tolerated clock skew
MUST be documented by the deployment. An Agent SHOULD NOT schedule
work that depends on completing near the deadline.

Expiry bounds duration; it does not end a mission early. A compromise
discovered before the deadline still requires an explicit termination
mechanism.

Already-issued Auth Tokens are the residual after expiry. The
issuance bound in {{enforcement}} keeps that residual inside the
mission's lifetime: no token issued under the mission outlives
`expires_at`.

Immutability defeats lifetime extension. An attacker who controls an
Agent cannot stretch an approved mission's lifetime; a longer lifetime
requires a new proposal and a new approval by the Person.

# Privacy Considerations

`expires_at` is part of the private mission blob and is not disclosed
to Resources or Access Servers. It adds no correlation surface beyond
the blob itself.

# IANA Considerations

This document requests no IANA registrations. The AAuth Protocol does
not currently establish a registry for approved mission-blob members.
If AAuth creates one before publication, this document will request
registration of `expires_at`.

# Acknowledgments
{: numbered="false"}

The AAuth protocol and its extension points are the work of Dick
Hardt.
