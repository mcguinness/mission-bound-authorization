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
    target: https://dickhardt.github.io/AAuth/draft-hardt-oauth-aauth-protocol.html
    refcontent: "Editor's copy, commit fc5e972c"
    author:
      -
        ins: D. Hardt
        name: Dick Hardt
    date: 2026

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

AAuth's approved mission blob MAY carry `expires_at`: an immutable,
consent-bound lifetime the Person Server enforces on every decision
path, capping every token carrying `mission_s256`. This document
profiles that member: values are RFC 3339 date-times, deployments
document their clock-skew posture, and the Person Server terminates
promptly at the deadline.

--- middle

# Introduction

AAuth defines `expires_at` as an OPTIONAL member of the approved
mission blob: every Person Server (PS) decision path MUST compare the
current time to it and treat a mission past it as terminated, and no
token carrying `mission_s256` may outlive it
{{I-D.draft-hardt-oauth-aauth-protocol}}. This document profiles the
member with the deltas in {{member}} and {{enforcement}}.

An AAuth mission is approved once and then relied on for as long as it
stays `active`. Absent an expiry, an approval remains usable
indefinitely through a stream of fresh short-lived tokens. Because
`expires_at` sits inside the approved mission blob, it is part of what
the Person approves, it is covered by the `s256` content address, and
it cannot be changed in place.

# Status: An Optional Profile {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: frozen-until-upstream-release.
Implementation: not yet in the conformance ledger (conformance-manifest.json).
Adopt when: A citable profile of AAuth's native `expires_at` is needed (base AAuth enforces it regardless; the profile's own conformance line is OPTIONAL).
Requires: nothing beyond its listed references.
<!-- family-status: END -->

# Conventions and Terminology {#conventions-and-terminology}

{::boilerplate bcp14-tagged}

This document uses Person, Agent, Person Server (PS), Access Server
(AS), Resource, Auth Token, mission, approved mission blob, mission
proposal, and the `{approver, s256}` mission reference as defined by
{{I-D.draft-hardt-oauth-aauth-protocol}}.

# The expires_at Member {#member}

AAuth defines `expires_at` as an OPTIONAL member of the approved
mission blob {{I-D.draft-hardt-oauth-aauth-protocol}}. This
profile adds one requirement of its own: under this profile,
`expires_at` MUST be an RFC 3339 `date-time` {{RFC3339}}, the internet
profile of the ISO 8601 form AAuth's own text uses, and MUST identify
an instant later than the blob's `approved_at`.

Because `expires_at` is in the approved mission blob, it is covered by
`s256` and cannot be changed in place, as AAuth specifies for every
blob member. Changing an approved expiry requires proposing and
approving a new mission, which carries a new `s256` and therefore a new
mission reference.

A mission whose approved blob has no `expires_at` member has no
expiry.

# Enforcement {#enforcement}

AAuth requires every PS decision path to compare the current time to
`expires_at` and to treat a mission past it as terminated, and it caps
every token carrying `mission_s256` (person, resource, and auth) to
that deadline {{I-D.draft-hardt-oauth-aauth-protocol}}. This profile
adds only a promptness requirement: the PS SHOULD terminate at the
deadline itself, rather than waiting for the next request under the
reference, so that status and logging reflect the transition without
delay.

# Proposal and Approval {#approval}

A mission proposal MAY include `expires_at`. The PS or the Person MAY
add or change the value during clarification, before approval. The
approved value is the one in the approved mission blob, and the Agent
verifies and stores the decoded blob bytes exactly as AAuth requires.

Support is discovered from the approved blob itself: a deployment that
requires a lifetime bound checks the approved blob and treats the
member's absence according to its policy. A proposal is not a
guarantee that the approved blob will carry the bound.

# Relationship to Other Specifications {#relationships}

The Mission Context Binding for AAuth
{{I-D.draft-mcguinness-mission-aauth}} requires AAuth's native
`expires_at` member and approves no mission without it. Base AAuth
deployments get enforcement regardless of that binding: it is the
base protocol's.

A PS that also implements AAuth Mission Management
{{I-D.draft-mcguinness-mission-aauth-management}} records the
transition with termination reason `expired`, surfaced through
AAuth's `mission_terminated` error and the status operation, and
serializes automatic expiry with explicit termination as that document
specifies.

# Conformance {#conformance}

An **AAuth Person Server** conforms to this profile when it:

1. requires `expires_at`, once present in the approved mission blob,
   to be an RFC 3339 `date-time` naming an instant later than
   `approved_at` ({{member}}); and
2. documents its clock synchronization, comparison precision, and
   tolerated clock skew ({{security-considerations}}).

Prompt termination at the deadline itself, rather than at the next
request under the reference, remains a SHOULD ({{enforcement}}).
Support for `expires_at` remains OPTIONAL, following the approved
blob member it profiles.

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
