---
title: "Mission Deployment Profile"
abbrev: "Mission Deployment Profile"
category: std

docname: draft-mcguinness-mission-deployment-profile-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - mission
 - agent
 - authorization
 - deployment
 - assurance
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-deployment-profile.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC6838:
  RFC7515:
  RFC8259:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
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
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-mission-architecture:
    title: "An Architecture for Mission-Bound Authorization"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-architecture.html
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
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
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
  I-D.draft-mcguinness-oauth-mission-progressive:
    title: "Mission Progressive Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-progressive.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

The Mission-Bound Authorization family states what a deployment can
prove as named assurance claims, each with a proof obligation an
owning profile fixes. This document gives those claims their
machine-readable form: a stable identifier for each claim, and the
Mission Deployment Profile manifest, a JSON object in which a
deployment publishes the claims it makes, the per-layer statements
behind them, and the residual risks it does not cover. The manifest
is the surface a procurement, an auditor, or a relying party
compares; every proof obligation remains with the profile that owns
it.

--- middle

# Introduction

A Mission is a durable governance object created by an explicit
approval event: the approved task, with a lifecycle, that authority
is derived for, bound to, and gated on
({{I-D.draft-mcguinness-oauth-mission}}, "the core"). The family's
strongest properties are deployment properties, not protocol
properties: complete PEP placement, a trusted freshness source, and
credential custody are things a deployment does, not things a token
proves. The architecture therefore states those properties as named
assurance claims and is plain about the comparison surface: "the
claims, not the level, are what a relying party compares"
({{I-D.draft-mcguinness-mission-architecture}}). The Mission
Assurance Levels order adoption; a level name asserts nothing a
consumer can check.

What the architecture deferred is defined here. This document fixes
a stable identifier for each assurance claim ({{claims}}) and
defines the Mission Deployment Profile manifest ({{manifest}}): the
JSON object a deployment publishes so a procurement, a security
review, or a relying party compares deployments on claims rather
than labels.

The division of authority is deliberate and narrow. Each claim's
proof obligation lives in the profile that owns it, and the owning
profile keeps normative force over the obligation; this document
owns only the identifier and the manifest form. A manifest changes
no enforcement behavior: it is the assertion surface, and the owning
profile's conformance section is the verification surface.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

This document uses Mission, Mission Issuer, and `issuer` as defined
by the core. It uses action class, Enforcement Scope Statement, and
the named enforcement claims as defined by
{{I-D.draft-mcguinness-mission-runtime}} (the "runtime profile"),
and the rendering-assurance rungs as defined by
{{I-D.draft-mcguinness-oauth-mission-consent-evidence}} (the
"consent-evidence profile"). It additionally uses:

Publisher:
: The deployment operator that publishes a Mission Deployment
  Profile manifest for a deployment it operates.

Consumer:
: A party (a procurement, an auditor, a relying party, or software
  acting for one) that reads a manifest to evaluate or compare a
  deployment.

# Assurance Claim Identifiers {#claims}

Each assurance claim of the architecture's claims axis has one
stable identifier, listed below. Each entry
summarizes the claim in one paragraph and points at the owning
profile section that fixes its proof obligation; the summary never
overrides its home. A parameterized claim is not made without its
parameters: the parameters state what the claim covers, and a claim
entry missing a parameter its definition names asserts nothing
({{consumption}}).

`record-integrity`:
: The Mission's integrity anchors reproduce from the record alone.
  Home: the Integrity Anchors section of the core
  ({{I-D.draft-mcguinness-oauth-mission}}). No parameters.

`bounded-revocation-latency`:
: Revocation reaches enforcement within a stated bound per action
  class: the published staleness bound plus the permit window plus
  the class's execution bound. Home: the Mission State and Freshness
  section of the runtime profile
  ({{I-D.draft-mcguinness-mission-runtime}}). Parameters (REQUIRED):
  `seconds`, an object mapping each covered action class to its
  bound in seconds.

`action-time-enforcement`:
: PEP coverage for the Enforcement Scope Statement's mediated set,
  and nothing outside it: the runtime profile's core enforcement
  tier. Home: the Enforcement Scope and Conformance section of the
  runtime profile ({{I-D.draft-mcguinness-mission-runtime}}).
  Parameters (REQUIRED): `classes`, an array of the action classes
  claimed.

`parameter-bound-enforcement`:
: Permits bound to concrete normalized parameters for the classes
  claimed. Home: the Parameter Binding and Time-of-Check to
  Time-of-Use section of the runtime profile
  ({{I-D.draft-mcguinness-mission-runtime}}). Parameters (REQUIRED):
  `classes`, an array of the action classes claimed.

`transaction-grade-execution`:
: The transaction-assurance tier machinery for the classes claimed:
  single-use permits, execution leases, and outcome reconciliation.
  Home: the transaction-assurance tier of the runtime profile's
  Enforcement Scope and Conformance section
  ({{I-D.draft-mcguinness-mission-runtime}}). Parameters (REQUIRED):
  `classes`, an array of the action classes claimed.

`compromise-resistant-custody`:
: The runtime profile's agent-compromise-resistant enforcement
  claim: mediated credential custody, action-bound approval,
  agent-isolated approval rendering, active-state freshness, and the
  declared-and-audited path scope. Home: the
  Agent-Compromise-Resistant Enforcement section of the runtime
  profile ({{I-D.draft-mcguinness-mission-runtime}}). No parameters.

`trifecta-containment`:
: The runtime profile's trifecta-containment claim: least exposure,
  the enforced taint rule with its pre-consented egress carve-out,
  and full mediation of the external-communication and
  external-commitment classes. Home: the Trifecta Containment
  section of the runtime profile
  ({{I-D.draft-mcguinness-mission-runtime}}). No parameters.

`consent-rendering`:
: The rendering-assurance rung the deployment claims for its
  approval surface, Rung 0 through Rung 4. Home: the Rendering
  Assurance section of the consent-evidence profile
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), with
  the rungs above the floor in its appendix. Parameters (REQUIRED):
  `rung`, an integer from 0 to 4.

The action-class values in parameters are the runtime profile's
classification identifiers in JSON form (`consequential_read`,
`consequential_write`, `irreversible_action`, `external_commitment`,
`privileged_administration`); a deployment-declared class uses the
identifier its Enforcement Scope Statement declares.

# The Manifest {#manifest}

A Mission Deployment Profile manifest is a JSON object {{RFC8259}}
with the media type `application/mission-deployment-profile+json`
({{iana}}). Its members:

`issuer`:
: REQUIRED. The `issuer` identifier of the Mission Issuer whose
  Missions the deployment runs.

`bindings`:
: REQUIRED. An array naming each Mission Issuer binding the
  deployment runs, from the values `oauth-core`, `mas`, `aauth`, and
  `uma`: the four bindings the architecture surveys
  ({{I-D.draft-mcguinness-mission-architecture}}).

`claims`:
: REQUIRED. An array of claim entries. Each entry is an object with
  `claim`, one identifier of {{claims}}, and `parameters`, the
  claim's parameter object, REQUIRED where the claim's definition
  names parameters.

`statements`:
: OPTIONAL. An object composing the per-layer statements the
  family's profiles demand, each member present where its profile is
  run: `enforcement_scope_statement`, the runtime profile's
  Enforcement Scope Statement with its content items as JSON members
  ({{I-D.draft-mcguinness-mission-runtime}}); `mapping_contract`,
  the Mission Authority Server's mapping contract
  ({{I-D.draft-mcguinness-mission-authority-server}});
  `environment_statement`, the harness profile's
  execution-environment scope statement
  ({{I-D.draft-mcguinness-mission-harness}}); `transparency`, the
  audit-transparency service topology and registration schedule
  ({{I-D.draft-mcguinness-mission-audit}}); and `ceiling_review`,
  the progressive profile's bounds and ceiling-review cadence
  ({{I-D.draft-mcguinness-oauth-mission-progressive}}). Each
  statement's owning profile governs its meaning and normative
  force; the manifest fixes only the carrying shape.

`residual_risks`:
: REQUIRED. A non-empty array of strings, each naming a gap the
  listed claims do not cover. The manifest is not credible without
  it: the deployment states what it does not cover in the same
  object as its guarantees
  ({{I-D.draft-mcguinness-mission-architecture}}).

`profile_version`:
: OPTIONAL. A deployment-controlled string identifying this manifest
  revision, so a consumer can detect change.

## Worked Example {#example}

A deployment running the OAuth core binding with runtime
enforcement, a harness, audit transparency, and standing charters
publishes:

~~~ json
{
  "profile_version": "acme-agent-runtime-3",
  "issuer": "https://as.example.com",
  "bindings": ["oauth-core"],
  "claims": [
    { "claim": "record-integrity" },
    { "claim": "bounded-revocation-latency",
      "parameters": { "seconds": {
        "consequential_read": 45,
        "consequential_write": 45,
        "irreversible_action": 45,
        "external_commitment": 45,
        "privileged_administration": 45 } } },
    { "claim": "action-time-enforcement",
      "parameters": { "classes": [
        "consequential_read", "consequential_write",
        "irreversible_action", "external_commitment",
        "privileged_administration" ] } },
    { "claim": "parameter-bound-enforcement",
      "parameters": { "classes": [
        "consequential_write", "irreversible_action",
        "external_commitment",
        "privileged_administration" ] } },
    { "claim": "transaction-grade-execution",
      "parameters": { "classes": [
        "irreversible_action", "external_commitment",
        "privileged_administration" ] } },
    { "claim": "compromise-resistant-custody" },
    { "claim": "trifecta-containment" },
    { "claim": "consent-rendering",
      "parameters": { "rung": 1 } }
  ],
  "statements": {
    "enforcement_scope_statement": {
      "pdp": "authzen",
      "pep_locations": ["tool-gateway", "browser-action-proxy"],
      "mediated_action_classes": [
        "consequential_read", "consequential_write",
        "irreversible_action", "external_commitment",
        "privileged_administration" ],
      "action_bound_approval_classes": [
        "irreversible_action", "privileged_administration" ],
      "unmediated_exclusions": [
        "internal_reasoning", "local_cache_read" ],
      "credential_custody": {
        "held_by": "pep",
        "sender_constrained": true,
        "key_generated_in_pep": true,
        "agent_receives_bearer_token": false },
      "approval_rendering": {
        "rendered_by": "agent-isolated-component" },
      "state_sources": [
        { "type": "status_endpoint",
          "max_staleness_seconds": 30 } ],
      "resource_servers": {
        "authorization_details_enforcing": [
          "https://erp.example.com" ],
        "scope_projection_only": [
          "https://mail.example.com" ],
        "constraint_enforcement_for_scope_only": "runtime_pep" },
      "evidence": {
        "decision_evidence": true,
        "execution_evidence": true,
        "retention_days": 365,
        "field_classification": "evidence-schema-v2",
        "evidence_access_audited": true,
        "erasure_policy": "erasure-records" }
    },
    "environment_statement": {
      "subagent_inheritance": "explicit_delegation_only",
      "resume_requires_active_state": true,
      "cached_credentials_revalidated": true,
      "taint_rule": "enforced",
      "egress_channels_enumerated": true
    },
    "transparency": {
      "service_operator": "third_party",
      "monitor": "sec-ops",
      "registration_time_bound_seconds": 3600
    },
    "ceiling_review": {
      "cadence_days": 90,
      "per_drawdown_bound": "single_entry_delta",
      "drawdown_rate_bound_per_chain_per_hour": 60
    }
  },
  "residual_risks": [
    "unmediated local reasoning is outside enforcement",
    "revocation latency up to 45 seconds on mediated paths",
    "PEP compromise is not prevented",
    "scope-only resources are constrained only via the PEP",
    "long-term memory is not Mission-scoped"
  ]
}
~~~

The 45 second latency bound composes the state source's 30 second
staleness with the deployment's declared permit window and execution
bound. A smaller deployment lists fewer claims, fewer statements,
and more residuals; the manifest stays honest at any size.

# Validation and Consumption {#consumption}

Four rules are the whole processing model.

- A consumer MUST treat an unrecognized claim identifier as not
  proven, never as proven.
- A publisher MUST NOT list a claim whose owning-profile obligations
  the deployment does not meet; a parameterized claim without its
  parameters is not listed.
- A consumer MUST ignore a manifest member it does not recognize:
  unrecognized members are the manifest's extension point.
- A publisher MUST keep `residual_risks` current with the claims
  listed: a claim added or withdrawn changes what remains uncovered.

A claim entry asserts; it does not prove. Checking a claim is the
owning profile's conformance surface, from the Enforcement Scope
Statement's items to the runtime profile's negative tests, and a
consumer weighs an unverified manifest accordingly
({{security-considerations}}).

# Publication and Integrity {#integrity}

How a manifest is published is deployment-defined: a URL, a document
attached to a procurement, or an entry in a deployment registry.
This document deliberately defines no discovery endpoint and no
metadata extension: the manifest is a governance artifact between a
publisher and its consumers, not a protocol surface, and the family
adds no wire mechanism for it.

A publisher MAY publish the manifest as a JWS {{RFC7515}} whose
payload is the manifest object, with the protected header `typ` set
to `mission-deployment-profile+jwt` ({{iana}}), signed under keys
the publisher makes resolvable to its consumers. A consumer of the
signed form MUST reject a JWS whose `typ` carries any other value.
The signature adds origin and integrity to the assertion; it proves
no claim ({{security-considerations}}).

# Conformance {#conformance}

Two roles conform to this document.

A **Manifest Publisher**:

- publishes a manifest with the members of {{manifest}}, including a
  non-empty `residual_risks`;
- lists only claims whose owning-profile obligations its deployment
  meets, each with the parameters its definition names ({{claims}},
  {{consumption}}); and
- keeps the manifest current as claims and residuals change
  ({{consumption}}).

A **Manifest Consumer**:

- treats an unrecognized claim identifier as not proven and ignores
  unrecognized members ({{consumption}}); and
- rejects a signed manifest whose `typ` is not
  `mission-deployment-profile+jwt` ({{integrity}}).

# Security Considerations {#security-considerations}

## Overclaiming

The first threat is the artifact itself: a manifest is an assertion,
not a proof, and an overclaiming publisher produces a well-formed
manifest for guarantees its deployment does not hold. The mitigation
is the division of authority of {{claims}}: every claim points at an
owning profile whose conformance surface, scope statements, evidence,
and negative tests included, is where verification happens. A
consumer that treats a manifest as proof has moved trust from the
deployment to a document; sound practice weighs a manifest together
with the owning profiles' evidence.

## The Manifest as an Oracle

`residual_risks` states enforcement gaps, and a published gap list
reads as an attack surface to an adversary as it reads as honesty to
an auditor. This document resolves that tension with policy, not
mechanism: publication audience is deployment policy. A deployment
can hand the full manifest to contracted consumers and publish a
reduced surface openly; what no published form omits is
`residual_risks` itself ({{manifest}}).

## Signed Manifests

The JWS form of {{integrity}} authenticates the publisher and
protects the manifest in transit; it changes nothing about truth. A
compromised or dishonest publisher signs the same false assertion.

# Privacy Considerations

A manifest describes infrastructure, not people, and carries no
Mission data. It can still fingerprint a deployment: PEP locations,
staleness bounds, and residual risks together narrow which
deployment a manifest describes and what it runs. The publication
audience ({{security-considerations}}) is the control.

# IANA Considerations {#iana}

## Media Type Registration

IANA is requested to register two media types per {{RFC6838}}.

### application/mission-deployment-profile+json

- Type name: application
- Subtype name: mission-deployment-profile+json
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; UTF-8 encoded JSON
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-Bound Authorization
  deployments, procurement and audit tooling, and relying parties
- Fragment identifier considerations: not applicable
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): none
  - Macintosh file type code(s): none
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

### application/mission-deployment-profile+jwt

- Type name: application
- Subtype name: mission-deployment-profile+jwt
- Required parameters: none
- Optional parameters: none
- Encoding considerations: binary; JWS Compact Serialization
- Security considerations: see {{security-considerations}}
- Interoperability considerations: see this document
- Published specification: this document
- Applications that use this media type: Mission-Bound Authorization
  deployments, procurement and audit tooling, and relying parties
- Fragment identifier considerations: not applicable
- Additional information:
  - Deprecated alias names for this type: none
  - Magic number(s): none
  - File extension(s): none
  - Macintosh file type code(s): none
- Person & email address to contact for further information:
  Karl McGuinness <public@karlmcguinness.com>
- Intended usage: COMMON
- Restrictions on usage: none
- Author: IETF
- Change controller: IETF

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization work and
gives the family's assurance claims their machine-readable form. The
author thanks the Mission-Bound Authorization implementer community
for feedback.
