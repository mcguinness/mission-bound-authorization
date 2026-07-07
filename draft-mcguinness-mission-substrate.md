---
title: "Mission Substrate Requirements"
abbrev: "Mission Substrate"
category: std

docname: draft-mcguinness-mission-substrate-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - substrate
 - binding
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html"

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

informative:
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-aauth:
    title: "Mission-Bound Authorization for AAuth"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html
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
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
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

--- abstract

The Mission model is bound to three authorization substrates: the
OAuth 2.0 issuance profile that defines it, the standalone Mission
Authority Server, and the AAuth Person Server. Its substrate-neutral
companion profiles are written against Mission primitives rather than
against any one binding, so a further binding that provides the same
primitives hosts them unchanged. This document is for authors of such
further bindings: it consolidates the primitives a binding provides,
points at where each is normatively defined, and shows which profiles
consume each one, changing nothing for the existing bindings and
profiles.

--- middle

# Introduction

A Mission is a durable governance object created by an explicit
approval event: the approved task, with a lifecycle, that authority is
derived for, bound to, and gated on. Mission-Bound Authorization for
OAuth 2.0 {{I-D.draft-mcguinness-oauth-mission}} (the "issuance
profile", here "the core") defines the object and every primitive of
the model, bound to the OAuth 2.0 Authorization Server. Two further
bindings exist: the Mission Authority Server (MAS), a standalone
Mission Issuer beside an unchanged Authorization Server
({{I-D.draft-mcguinness-mission-authority-server}}), and the AAuth
binding, which gives that protocol's native mission concept the
model's structure ({{I-D.draft-mcguinness-mission-aauth}}). The core
provides every primitive by construction; the MAS provides all but the
Mission-bound credential and issuance gating, profiling the join for
that gap as its Mission Join; the AAuth binding provides all of them;
their substrate statements remain their own.

The family's substrate-neutral profiles (runtime enforcement and its
decision API bindings, the harness, orchestration, intent shaping,
consent evidence, the Mandate, audit transparency, and the security
model) are written against Mission primitives rather than against
OAuth mechanics; each names what it consumes in a Mission Substrate
section of its own, except consent evidence, whose consumption is
stated by its approval binding. The architecture document consolidates that
interface informationally, ending in a Binding Checklist
({{I-D.draft-mcguinness-mission-architecture}}). This document is the
checklist's normative home, written for the author of a new binding:
what a binding of the Mission model to another authorization substrate
provides so that the substrate-neutral profiles apply as written, with
the binding supplying the primitives their Mission Substrate sections
consume. It restates no definition: each requirement points at the
core section that owns it.

## Status: A Profile for New Bindings {#status}

This document changes nothing for the existing bindings and profiles.
The core remains self-contained and authoritative for every definition
this document names; the existing bindings' Mission Substrate
statements remain authoritative for those bindings, which predate this
document and claim no conformance to it. No existing family document
depends on this one, and none needs revision on its account. A
requirement stated here binds only a new binding that claims
conformance to this document ({{conformance}}). Where this document
and the core appear to differ, the core governs.

## Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses Mission, Mission Intent, Mission Issuer, Authority
Set, Approver, Subject, the Mission Identifier, `issuer`, the
`mission` claim, the integrity anchors (`intent_hash` and
`authority_hash`), the subset rule, Common Constraints, the
only-`active` rule, and the audit horizon as defined by the core. It uses Policy Enforcement Point
(PEP), Policy Decision Point (PDP), consequential action, and Mission
binding establishment as defined by
{{I-D.draft-mcguinness-mission-runtime}}. A **Mission Substrate
Binding** is a specification that binds the Mission model to an
authorization substrate and claims conformance to this document
({{conformance}}). It additionally uses:

Full provision:
: Providing every primitive of {{requirements}}, including the
  Mission-bound credential ({{credential}}).

Partial provision:
: Providing every primitive of {{requirements}} except the
  Mission-bound credential, with a defined join in its place
  ({{credential}}).

# Mission Substrate Requirements {#requirements}

Each subsection states the requirement on the binding, the home of the
normative definition (a section of the core), and the consuming
profiles; a summary here never overrides its home.

## Mission Identifier and Issuer {#identifier}

A binding MUST provide a Mission identifier that is opaque, carries no
semantic content, has at least 128 bits of entropy, and is never
reused, together with an `issuer`: an issuer identifier naming the
approving Mission Issuer, from which consumers resolve the binding's
state and key surfaces; together they name exactly one Mission.

A binding MAY define a substrate-native reference to the same Mission,
as the AAuth binding does with its (`approver`, `s256`) pair; the
Mission record MUST bind both names to the same Mission.

Home: the Mission Record and Mission Identifier Format sections of
{{I-D.draft-mcguinness-oauth-mission}}.

Consumers: every substrate-neutral profile keys on the pair, from
enforcement decisions and evidence through harness work-item bindings
to the audit statement subject and the Mandate.

## Mission Lifecycle States {#lifecycle}

A binding MUST provide the core's lifecycle state space: `active`,
`revoked`, and `expired` as the minimum, with only `active` permitting
issuance, derivation, or continued reliance. Every other state value,
including one a consumer does not recognize, is non-active and
non-deriving; a binding MUST NOT define a surface that fails open on
an unrecognized state. A binding that adopts an extension state MUST
surface its value verbatim and MUST NOT translate it into a core state
or a substrate-native vocabulary, because the fail-safe rule keys on
the exact value.

A binding MUST specify at least one state source from which consumers
learn a Mission's current state, with a stated staleness bound, so
deployments can meet the runtime profile's freshness rules.

Home: the Mission Lifecycle and Gating section of
{{I-D.draft-mcguinness-oauth-mission}}; the freshness rules are the
runtime profile's ({{I-D.draft-mcguinness-mission-runtime}}), and the
Mission Status profile defines a canonical observation surface
({{I-D.draft-mcguinness-oauth-mission-status}}).

Consumers: the runtime layer (per-class state re-check, fail closed on
staleness), the harness (pause, suppress, terminate), orchestration
(the unwind trigger), and the Mandate (state only as of minting).

## Mission Authority Representation {#authority}

A binding MUST represent the Authority Set as an array of entries in
the core's authorization-details shape: each entry names a resource,
its actions, and its constraints. The binding MUST apply the subset
rule at every narrowing it performs: no derivation, delegation, or
attenuation under a Mission yields authority broader than the
Mission's Authority Set. The binding MUST interpret Common Constraint
names per their definitions and compare their values in value space
under each definition's subset and intersection rules, so independent
implementations compute the same result for the same values.

Home: the Mission Authority section of
{{I-D.draft-mcguinness-oauth-mission}}, with its Subset Rule and
Common Constraints subsections.

Consumers: the runtime layer and its decision API bindings
(evaluation), consent evidence (rendering), and the Mandate (optional
carriage).

## Mission Integrity Anchors {#anchors}

A binding MUST compute `intent_hash` and `authority_hash` over the
core's domain-separated, issuer-bound envelope, with the binding's
issuer identifier as the envelope `iss`, under the core's
canonicalization rules. A verifier MUST reject an anchor whose
algorithm prefix it does not recognize and MUST NOT treat an
unrecognized prefix as `sha-256`. A new committed object uses the same
envelope with a new `typ` under the core's extension rule.

A binding MAY additionally commit to its native artifact with a
mechanism of its own, as the AAuth binding's `s256` commits the
mission blob. It MUST state that commitment's relationship to the
anchors, including whether either substitutes for the other.

Home: the Integrity Anchors and Canonicalization Rules sections of
{{I-D.draft-mcguinness-oauth-mission}}, with the `typ` extension rule
in its Extensibility section.

Consumers: consent evidence (`consent_rendering_hash`), intent shaping
(Shaping Evidence), the runtime layer (the materialized policy view),
orchestration (`unwind_plan_hash`), the Mandate (the encoded digest
form), and audit transparency (the committed evidence types).

## Mission-Bound Credential {#credential}

This primitive is OPTIONAL, and it is where provision levels split.

Under full provision, the binding issues a credential carrying the
`mission` claim (`id`, `issuer`, `authority_hash`) under its own
proof-of-possession discipline, and only while the referenced Mission
is `active`: credential issuance is gated on Mission state.

Under partial provision, the binding issues no such credential. It
MUST define a join per the externally established mode of the runtime
profile's Mission binding establishment step: how a PDP verifies a
supplied Mission reference against the acting credential before any
authority is evaluated. The definition MUST state what the join proves
and what it cannot prove; an unverified reference never establishes
the Mission. The MAS's Mission Join is the profiled example
({{I-D.draft-mcguinness-mission-authority-server}}).

Profiles that ride the credential itself (offline attenuation, and the
token-carriage aspects of delegation) apply only under full provision.
Of the substrate-neutral profiles, those that need a
credential-to-Mission association (the runtime layer and the harness)
route through the binding establishment step, which is what makes
partial provision possible; the rest consume no credential at all
(the composition table's credential column).

Home: the Mission-Bound Access Tokens and The Mission Claim sections
of {{I-D.draft-mcguinness-oauth-mission}}; the seam is the Mission
binding establishment section of the runtime profile
({{I-D.draft-mcguinness-mission-runtime}}).

## Mission Key Material {#keys}

A binding MUST publish the Mission Issuer's signing keys, resolvable
from the `issuer` by verifiers of its signed artifacts. Across a
rotation, the verification key for each key identifier SHOULD remain
resolvable while artifacts signed under it remain within the audit
horizon ({{audit-horizon}}).

Home: the Signing and Key Rotation section of
{{I-D.draft-mcguinness-oauth-mission}}; the discovery surface is the
binding's own metadata.

Consumers: verifiers of Mission-bound credentials under full
provision, the Mandate ({{I-D.draft-mcguinness-mission-mandate}}),
signed state surfaces ({{I-D.draft-mcguinness-oauth-mission-status}}),
and audit statements ({{I-D.draft-mcguinness-mission-audit}}).

## Mission Audit Horizon {#audit-horizon}

A binding MUST declare an audit horizon: the retention window for the
Mission record and its evidence, at least the Mission's lifetime plus
a declared post-terminal period. After a Mission reaches a terminal
state, its record MUST be retained for the audit horizon.

Home: the Mission Record section of
{{I-D.draft-mcguinness-oauth-mission}}.

Consumers: consent evidence, runtime enforcement evidence, and audit
transparency size their retention to it; the security model's
retention analysis assumes it.

## Mission Approval Fidelity {#approval-fidelity}

A binding's approval surface MUST realize the core's approval-event
steps, whatever its native ceremony:

1. authenticate the Approver, at the deployment's authentication floor
   and satisfying the Intent's `controls.acr` where present;
2. establish the Subject, never from unauthenticated client input;
3. derive the Authority Set and render the derived authority for
   consent, not the goal or the Intent, with the core's display
   hardening (inert client strings, direction-override and confusable
   mitigation, derived authority visually distinct from client text);
4. compute the integrity anchors over the consented Authority Set and
   the approved Intent ({{anchors}}); and
5. create the Mission record in the `active` state atomically with the
   approval decision.

Home: the Mission Approval section of
{{I-D.draft-mcguinness-oauth-mission}}. The MAS shows the steps
re-shaped for an asynchronous surface, approval bound to the
submission rather than an authorization code; the AAuth binding shows them
profiled onto a propose-clarify-approve interaction.

Consumers: consent evidence binds to this event; every downstream
guarantee (the anchors, the gating, the record) assumes it.

# Mission Composition {#composition}

The table shows which substrate-neutral profiles consume which
primitives, so a binding author reads off what a provision level
hosts; each row mirrors the profile's own Mission Substrate statement
(for consent evidence, its approval binding) and adds nothing. Marks:
`X` consumed; `B` consumed through the Mission binding establishment
step (the credential under full provision, the join under partial
provision); `.` not consumed. Notes follow the table.

| Profile | Id | State | Auth | Anchor | Cred | Keys | Horizon | Appr |
|---|---|---|---|---|---|---|---|---|
| Runtime and its decision API bindings | X | X | X | X | B | . | X | . |
| Harness | X | X | . | . | B | . | . | . |
| Orchestration | X | X | . | X | . | . | . | . |
| Intent Shaping | . | . | . | X | . | . | . | . |
| Consent Evidence | X | . | X | X | . | . | X | X |
| Mandate | X | X | X | X | . | X | . | . |
| Audit Transparency | X | . | . | X | . | X | X | . |
| Consumption Metering | X | . | X | X | . | . | . | . |
{: title="Primitives consumed per substrate-neutral profile"}

- The credential column is the split. Under partial provision, every
  `B` composes through the join and no other cell changes.
- Consumption Metering defines no binding of its own: its counters key
  on the identifier, its `call_class` draws on the Authority Set
  representation, and its bounds are committed through the anchor
  envelope; enforcement composes through the runtime row's binding.
- The security model is not a row: it is informational, analyzes every
  primitive, and applies to any binding
  ({{I-D.draft-mcguinness-mission-security-model}}).
- Some profiles name further inputs in their own Mission Substrate
  sections, which remain the authoritative per-consumer statements:
  intent shaping consumes the Mission Intent structure and a
  submission channel; audit transparency consumes the evidence types
  and their canonical bytes; the harness and orchestration import the
  runtime profile's evidence conventions.
- Profiles bound to OAuth wire mechanics (expansion, child delegation,
  offline attenuation, cross-domain projection) are not
  substrate-neutral and are not rows; a binding wanting those
  capabilities defines its own surfaces. The documents behind these
  profile names are mapped by the architecture
  ({{I-D.draft-mcguinness-mission-architecture}}).

# Mission Substrate Conformance {#conformance}

This document defines one conformance role, claimed by a
specification, not an implementation; implementations conform to the
binding's own conformance clauses.

A **Mission Substrate Binding**:

1. provides the Mission identifier and `issuer` ({{identifier}});
2. provides the lifecycle state space with the only-`active` rule,
   fail-safe treatment of unrecognized states, verbatim extension
   states, and a state source with a stated staleness bound
   ({{lifecycle}});
3. represents the Authority Set in the core's shape and applies the
   subset rule and Common Constraint value-space semantics at every
   narrowing ({{authority}});
4. computes the integrity anchors over the core's envelope and
   canonicalization, rejects unrecognized algorithm prefixes, and
   states the relationship of any native commitment to the anchors
   ({{anchors}});
5. either provides the Mission-bound credential with issuance gating,
   or defines a join stating what it proves and what it cannot prove
   ({{credential}});
6. publishes resolvable issuer key material with rotation retention
   ({{keys}});
7. declares an audit horizon over the record and its evidence
   ({{audit-horizon}}); and
8. realizes the approval-event steps on its approval surface
   ({{approval-fidelity}}).

A Mission Substrate Binding MUST state its provision level: full
provision, or partial provision with the section defining its join,
naming the profiles that consequently do not apply. It SHOULD publish
this as a Mission Substrate section following the existing bindings'
pattern, so each item is checkable against its text.

# Security Considerations

This document defines no mechanism; its security posture is the core's
plus the binding's own. Two considerations are specific to binding.

## The Binding as Trust Root

A Mission Substrate Binding implements the Mission Issuer, the root of
trust of the security model's trusted base: it derives authority, runs
the approval event, commits the anchors, and gates or joins. Mission
Issuer compromise semantics apply to any binding: a compromised issuer
mints or attributes arbitrary authority, forges approvals, and reports
false state; consent evidence and audit transparency make that
detectable after the fact, not preventable
({{I-D.draft-mcguinness-mission-security-model}}). A new binding
re-derives only the substrate-specific entries of that model.

## Mission Join Assurance

Partial provision moves the credential-to-Mission binding from
cryptographic carriage to the join, so the join's assurance bounds
every downstream guarantee that names "this credential under this
Mission". A binding MUST state that assurance honestly: what the join
proves, what it cannot prove, and the residuals that remain. The MAS's
Join Spoofing analysis is the pattern
({{I-D.draft-mcguinness-mission-authority-server}}): the join proves
the credential belongs to the subject and client the Mission names, no
mechanism in that mode proves the credential was derived under the
Mission, and mapping coarseness and same-party misattribution remain
as residuals.

# Privacy Considerations

This document introduces no data element. The core's privacy
considerations apply to any binding: the Mission identifier is a
correlation handle, and the Mission record concentrates task data at
the Mission Issuer; each hosted profile's own apply unchanged.

# IANA Considerations

This document has no IANA actions.

--- back

# Acknowledgments
{:numbered="false"}

This document gives a normative home to the substrate interface first
consolidated informationally by the architecture document. The author
thanks the Mission-Bound Authorization implementer community for
feedback.
