---
title: "Mission Continuation: Authorization Continuity for Mission-Bound Authorization"
abbrev: "Mission Continuation"
docname: draft-mcguinness-oauth-mission-continuation-00
category: std
submissiontype: IETF
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - continuity
 - delegation
author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

--- abstract

This document profiles authorization continuity for Mission-Bound
Authorization. A Mission is the durable, grant-anchored root of what
work remains authorized, under which constraints, on whose approval.
Mission Continuation binds that authorization to an identity-continuity
transport that re-establishes who is acting, so a Mission's work may
continue across hops and over time without re-presenting the original
credential and without widening authority. Identity Continuation
Assertions, async delegation, and cross-domain projection are the
transports; the Mission binds all of them under one invariant: a
continuation handle grants nothing.

--- middle

# Editorial Status (Outline)

THIS IS A STRUCTURAL OUTLINE FOR REVIEW. Section headings and the
load-bearing claims are fixed; normative language (RFC 2119 terms),
worked examples, references, and IANA text are to be completed once
the shape is agreed. Draft and RFC citations are written in plain text
here and become proper cross-references in the full draft.

# Introduction {#introduction}

Three things are continuously conflated when long-running or multi-hop
agentic work is authorized:

- identity continuity: WHO is acting, and how that identity legitimately
  continues (intra-domain across hops, or across a trust boundary);
- authorization continuity: WHAT work remains authorized, under WHICH
  constraints, on WHOSE approval; and
- execution-time evidence: WHAT was actually done at each continued hop.

Identity-continuity mechanisms (the Identity Continuation Assertion,
draft-mcguinness-oauth-id-continuation-assertion; async delegation,
draft-zhu-oauth-async-delegation; cross-domain projection,
draft-mcguinness-oauth-mission-cross-domain) answer only the first.
They carry no answer to "is this work still authorized, and within what
bounds" beyond whatever a token happens to embed. Mission-Bound
Authorization (draft-mcguinness-oauth-mission) answers the second: the
Mission is the approved, constrained, state-gated, revocable record of
the work. This profile is the binding between them, plus the evidence
that ties each continued action back to the Mission.

# The Three Continuities {#three-continuities}

Outline. Define each continuity precisely and name its owner:

- Identity continuity is owned by a transport (Section {#transports}),
  never by this profile. This profile is transport-agnostic and states
  the requirements a transport MUST meet to carry a Mission
  continuation.
- Authorization continuity is owned by the Mission (Section
  {#authorization-continuity}).
- Execution-time evidence is owned by the runtime and recorded against
  the Mission (Section {#evidence}).

State the anti-pattern this separation prevents: a transport that
embeds authorization detail and is then treated as self-authorizing,
so that possession of a continued credential substitutes for the
Mission's live state.

# Authorization Continuity and the Mission {#authorization-continuity}

Outline. The Mission is the durable, grant-anchored root a continuation
chains from. Normative content to specify:

- Rooting. A continuation is rooted in exactly one Mission; the rooting
  is grant-anchored (durable, MAY outlive a session) or session-anchored
  (MUST NOT outlive its session). Rooting from a bare access token is
  forbidden.
- Subset derivation. Every continued grant's authorization is derived
  as a subset of the Mission's Authority Set; a continuation MUST NOT
  widen (no new resource, no broadened scope, no relaxed constraint).
- State gating. Every continued grant is issued only while the Mission
  (and every ancestor in its lineage) is active; issuance is atomic with
  the state check.
- Lifetime. A continued credential's lifetime MUST NOT exceed the
  Mission's expiry; a transport's own maximum lifetime is clamped to it.
- Termination. A terminal Mission ends the continuation for future
  grants; it does not shorten an already-issued credential.
- Derivation accounting. Continuation participates in the Mission's
  max_derivations accounting; specify whether re-issuance is bounded.

# The Grants-Nothing Invariant {#invariant}

Outline. The single invariant the whole profile rests on, stated once
and referenced everywhere:

> A continuation handle grants nothing. It names an accepted hop. Every
> continued grant re-passes the Mission's active gate. Continuity is
> never authority.

Note the family precedents that already hold this line: the harness
binds session continuity to Mission state and never to authority
(draft-mcguinness-mission-harness); the UMA binding's PCT is a
continuation handle that "grants nothing" and every RPT re-passes fresh
assessment (draft-mcguinness-mission-uma). This profile generalizes the
same rule to the OAuth transports.

# Continuation Transports {#transports}

Outline. The transport-agnostic requirements, then one subsection per
transport describing how the Mission binds it. A transport MUST: name
an accepted hop with a handle that is not itself a credential; rebind
the acting identity to a confirmed key per hop; and carry no
authorization the Mission did not derive.

## Identity Continuation (intra-domain, connected) {#transport-ica}

Outline. draft-mcguinness-oauth-id-continuation-assertion. Short-lived
(<= 300s), DPoP-sender-constrained assertion presented as an RFC 8693
token-exchange subject token; the AS mints a continuation ID-JAG whose
authorization_details is a Mission-authority subset, audience-local
subject, actor rebound per hop. The `identity_continuation_handle`
resolves to the Mission. This is the connected, hop-by-hop case.
(Reference implementation exists: see the impl notes.)

## Async Delegation (intra-domain, disconnected) {#transport-async}

Outline. draft-zhu-oauth-async-delegation. Refresh-token family for
long-running, disconnected work (scheduled tasks, queues, multi-stage
orchestration). The delegated authorization state is a subset of the
Mission's authority; the "absolute maximum delegation lifetime" is the
Mission's expiry; the refresh-token family is revoked when the Mission
reaches a terminal state (the family-revocation rule already in that
draft, driven here by Mission lifecycle). This is the disconnected,
over-time case. This is precisely the "scheduled continuation MUST root
in durable RAS authorization" case ICA defers; the Mission is that
durable root.

## Cross-Domain Projection (across a trust boundary) {#transport-xdomain}

Outline. draft-mcguinness-oauth-mission-cross-domain. Single-hop
projection to a partner domain; a Resource AS mints a local token
bounded by the projected authority and resolves an audience-local
subject. This profile adds nothing to projection's wire; it states that
a projected Mission continued in the partner domain remains subject to
the grants-nothing invariant there. Projection stays single-hop
regardless of intra-domain continuation on either side.

# Execution-Time Evidence {#evidence}

Outline. Each action taken under a continued credential produces a
Mission Receipt / decision evidence (draft-mcguinness-mission-runtime,
draft-mcguinness-mission-authzen) recorded against the Mission. Open
design point (see Open Questions): whether the continuation hop
identity (the handle, or the credential's jti) MUST reach the receipt
so an action ties back to the specific hop that authorized it, or
whether generic per-Mission evidence suffices.

# Substrate Dispositions {#substrate}

Outline. This is an OAuth-wire profile, not a substrate requirement
(draft-mcguinness-mission-substrate restates no definition; the
continuity semantics are restatements of existing substrate
requirements). Non-OAuth bindings dispose of it as a composition
consequence:

- AAuth (draft-mcguinness-mission-aauth): over-time continuation is
  native (the (approver, s256) reference is a grants-nothing handle;
  the PS's state-gated one-hour issuance/federation is the continuation
  point). Cross-workload continuation has no AAuth transport and AAuth
  declines authority carry-forward by design; it is deferred work.
- UMA (draft-mcguinness-mission-uma): the PCT is the continuation
  handle and already realizes the grants-nothing invariant.

# Security Considerations {#security}

Outline. Handle theft yields no authority (the invariant). Revocation
latency equals the shortest of the transport lifetime and the
continued-credential lifetime; per-transport figures. Replay: ICA jti
single-use; async-delegation family-rotation and reuse detection.
Confused-deputy and audience-confinement across hops.

# Privacy Considerations {#privacy}

Outline. Audience-local subjects (no correlatable global subject across
audiences); the ICA transport carries no subject at all. Handle opacity.

# IANA Considerations {#iana}

Outline. No new registrations expected beyond those the transports
define; confirm whether a grant-profile URI or discovery metadata is
introduced here.

# Open Questions {#open-questions}

1. Cross-workload vs over-time scope for non-OAuth bindings (AAuth needs
   a new native mechanism only if cross-workload is in scope).
2. Whether execution-time evidence MUST carry the hop identity.
3. Whether continuation re-issuance is bounded by max_derivations or is
   an explicit continuity ceiling.
4. Federated-AAuth Reference-only mode: is an AS re-issuance a Mission
   continuation or an unattributed fresh mint.

--- back
