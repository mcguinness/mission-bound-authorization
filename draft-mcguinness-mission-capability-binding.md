---
title: "Mission Capability Binding"
abbrev: "Mission Capability Binding"
category: std

docname: draft-mcguinness-mission-capability-binding-latest
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
 - capability
 - catalog
 - mcp
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-capability-binding.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-mcguinness-mission-substrate:
    title: "Mission Substrate Requirements"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-substrate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  RFC6234:
  RFC7519:
  RFC8259:
  RFC8785:
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
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  AUTHZEN:
    target: https://openid.net/specs/authorization-api-1_0-final.html
    title: "OpenID AuthZEN Authorization API 1.0"
    author:
      -
        org: OpenID Foundation
    date: 2026

informative:
  MCP-REGISTRY:
    title: "The MCP Registry"
    target: https://modelcontextprotocol.io/registry/about
    author:
      - org: Model Context Protocol Project
    date: 2026
  COAZ:
    target: https://openid.github.io/authzen/authzen-mcp-profile-1_0.html
    title: "AuthZEN Profile for Model Context Protocol Tool Authorization - Draft 1"
    author:
      -
        org: OpenID Foundation
    date: 2026
  I-D.draft-mcguinness-mission-runtime-evidence:
    title: "Mission Runtime Evidence"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:

--- abstract

Mission-Bound Runtime Enforcement: AuthZEN Profile
{{I-D.draft-mcguinness-mission-authzen}} carries the decision request
that permits a consequential action against a Mission's approved
authority. For an action sourced from a discovered catalog (the MCP
Registry, {{MCP-REGISTRY}}, is one example catalog source; its
contents are discovery metadata, never authority for a server's
effective capabilities), an MCP tool, an OpenAPI operation, or an
equivalent capability source, the
invoked identity can drift from what the catalog served at approval.
This document defines the companion binding that ties an approved
catalog entry to the capability source it was derived from: the
`tool_id`, source, and content digest recorded at derivation and
verified at decision time, the per-capability extraction rule that
computes the digest, the `capability_drift` denial reason as a
coordinated extension of the AuthZEN binding's runtime denial
classification, and the mapping onto the OpenID AuthZEN Profile for
Model Context Protocol Tool Authorization (COAZ) for MCP
deployments.

--- middle

# Introduction

An agent's approved authority can name a capability, an MCP tool, an
OpenAPI operation, or a catalog entry, rather than a fixed action
name. The catalog a Mission was approved against is not immutable: a
tool's definition can change, a catalog can be revised, or an
invoked identity can drift from the one the approval bound. Without a
binding back to the capability source, a Policy Decision Point (PDP)
enforcing the runtime profile's decision contract
{{I-D.draft-mcguinness-mission-runtime}} has no way to tell a stable
capability from one that has silently mutated underneath the
approval.

This document is a companion to Mission-Bound Runtime Enforcement:
AuthZEN Profile {{I-D.draft-mcguinness-mission-authzen}} (the
"AuthZEN binding"). It defines the capability-source binding a
validating server records at derivation and a Policy Enforcement
Point (PEP) presents at decision time in `context.capability_source`
of the OpenID AuthZEN Authorization API {{AUTHZEN}} request the
AuthZEN binding shapes: a stable `tool_id`, the discovery
`source_uri`, a `source_digest` over the capability's extracted
definition, and an `operation_ref`. It defines the per-capability
extraction rule that computes `source_digest`, the decision-time
verification a PDP performs, the `capability_drift` denial reason
this document registers as a coordinated extension of the AuthZEN
binding's runtime denial classification, and the mapping onto the
AuthZEN Profile for Model Context Protocol Tool Authorization (COAZ)
{{COAZ}} for MCP deployments.

This document rides the AuthZEN binding's request as
`context.capability_source` and the runtime profile's capability
identity requirement; it defines no drift rule of its own, since that
requirement is the runtime profile's
({{I-D.draft-mcguinness-mission-runtime}}). A deployment that does
not claim this companion is unaffected: the AuthZEN binding's
decision contract consumes an already established action identity.

# Status: An Optional Profile {#doc-status}

<!-- family-status: BEGIN (generated from family-manifest.json; exact-matched by scripts/check-family-manifest.mjs) -->
Role: companion. Spec maturity: experimental. Maintenance: active.
Implementation: not yet in the conformance ledger (conformance-manifest.json).
Adopt when: Actions come from a discovered catalog where invoked identity can drift from approval.
Requires: Mission-Bound Runtime Enforcement: AuthZEN Profile; Mission-Bound Runtime Enforcement; Mission Substrate Requirements.
Also requires, conditionally: Mission-Bound Authorization for OAuth 2.0 (when the OAuth binding is the substrate).
<!-- family-status: END -->

# Conventions and Terminology {#conventions-and-definitions}

{::boilerplate bcp14-tagged}

This document uses JSON {{RFC8259}} as the data model for the
capability-source binding object. JCS canonicalization {{RFC8785}}
applies wherever this document computes a digest, under the
substrate's default commitment construction
({{I-D.draft-mcguinness-mission-substrate}});
this document does not define a second canonicalization.

"SHA-256" refers to {{RFC6234}}. A digest is encoded in the encoded
form of the substrate's default commitment construction
({{I-D.draft-mcguinness-mission-substrate}}): `sha-256:` followed by
the base64url, no-padding encoding of the digest. Under the substrate's
default commitment construction, which this document imports
normatively ({{I-D.draft-mcguinness-mission-substrate}}),
`source_digest` is a canonical-object digest and `catalog_digest` a
raw-octet digest over the exact retrieved representation.

The terms Policy Enforcement Point (PEP), Policy Decision Point
(PDP), consequential action, and Executor are used as defined in
{{I-D.draft-mcguinness-mission-runtime}}. The AuthZEN request and
response envelope, the `context` object, and the runtime denial
classification are used as defined in
{{I-D.draft-mcguinness-mission-authzen}}.

Validating server:
: The component that, at derivation, validates the Mission's
  authority and records the derivation-time facts a PDP later
  checks, such as a capability `source_digest`
  ({{capability-source-binding}}). In the issuance profile this is
  the Mission Issuer; this document uses the term where the
  recording role is what matters.

# Capability Source Context {#context-capability-source}

For catalog-sourced actions, the PEP supplies the capability-source
binding in `context.capability_source` using the object defined in
{{capability-source-binding}}. For non-catalog actions, this member
is absent.

# Capability Source Binding {#capability-source-binding}

Consequential actions an agent discovers at runtime, through a Model
Context Protocol tool catalog, an OpenAPI document, a Protected
Resource Metadata-linked catalog, or an equivalent capability source,
identify the source they came from, so a Mission's approved authority
stays bound to concrete tools rather than to bare action names a
later catalog revision could redefine. The runtime profile assigns
capability identity to the approved `actions` and refuses an invoked
identity outside them ({{I-D.draft-mcguinness-mission-runtime}});
this document gives the concrete binding an AuthZEN deployment
presents for catalog-sourced actions.

For MCP tools, this binding composes with the AuthZEN MCP profile's
COAZ mapping {{COAZ}}. COAZ maps MCP tool definitions and invocation
parameters into the AuthZEN Subject-Action-Resource-Context model;
this document adds Mission governance, source binding, Mission
evidence, and runtime metering. A Mission-governed MCP deployment MAY
use COAZ to construct the AuthZEN `subject`, `resource`, `action`,
and parameter-bearing `context` members, but the Mission-specific
`context.mission`, `context.actor`, freshness, permit binding, and
evidence requirements of the AuthZEN binding
({{I-D.draft-mcguinness-mission-authzen}}) still apply.

The minimum binding, committed by the validating server at derivation
and presented by the executing component at request time in
`context.capability_source`, is:

~~~ json
{
  "tool_id": "mcp://docs.example.com/tools/write_document",
  "source_uri": "https://docs.example.com/.well-known/mcp",
  "source_digest":
    "sha-256:OAbEIh2DTYUVP7DjRhHct4aapsT8PybZq2ILdut9UP0",
  "operation_ref": "tools/write_document"
}
~~~

`tool_id`:
: A string. A stable capability identifier the executing
  component asserts the action invokes.

`source_uri`:
: A string. The discovery source the capability was
  resolved from.

`source_digest`:
: A string. The integrity-anchor encoded form
  ({{I-D.draft-mcguinness-oauth-mission}}) over the capability's
  extracted definition ({{capability-extraction}}), recorded at
  derivation time. At request time it is computed over the current
  extracted definition, so the PDP's comparison detects a mutated
  definition.

`operation_ref`:
: A string. The source-format-specific operation
  reference (MCP tool name, OpenAPI `operationId`, or equivalent).

`catalog_digest`:
: OPTIONAL. A string. The integrity-anchor encoded form over the
  exact retrieved source representation, recorded at derivation
  time. Its semantics are strictly stricter than `source_digest`:
  when recorded, any change to the retrieved source refuses, whether
  or not it touches the capability. A deployment records it where
  the whole catalog is the trust unit.

`executor`:
: OPTIONAL. A string. An identifier for the executing component that
  serves the capability at request time (for example, an MCP server
  instance), asserted by the PEP that authenticates it. It is a
  request-time fact, not part of the derived authority recorded at
  derivation, and is recorded in Decision Evidence when present; it
  is never an input to the `source_digest` or `catalog_digest`
  comparison.
  Where the executing component authenticates under an
  attested-instance profile
  ({{I-D.draft-mcguinness-oauth-client-instance-assertion}},
  {{I-D.draft-mcguinness-oauth-ai-agent-instance}}), the deployment
  SHOULD carry the attested instance identifier here rather than a
  self-chosen label.

Rules:

- The validating server records `tool_id`, `source_uri`,
  `source_digest`, `operation_ref`, and any `catalog_digest` for
  every consequential action sourced from a discovered catalog.
  These values are part of the approved Mission's derived authority
  and are therefore covered by `authority_hash`
  ({{I-D.draft-mcguinness-oauth-mission}}).
- The PEP presents `tool_id` on consequential requests for
  catalog-sourced actions. The runtime profile owns the drift
  semantics ({{I-D.draft-mcguinness-mission-runtime}}); the PDP
  applies them through this document's decision-time verification
  ({{capability-verification}}), over the per-capability comparison
  scope of {{capability-extraction}}. This document adds only the
  wire representation and per-capability verification, carrying such
  a refusal as `capability_drift` ({{capability-drift-reason}}) with
  its boundary against `out_of_authority` fixed by the AuthZEN
  binding's runtime denial classification
  ({{I-D.draft-mcguinness-mission-authzen}}); it defines no drift
  rule of its own.
- Resource policy MAY refuse a catalog-sourced action whose
  `source_uri` or `executor` is outside the deployment's trusted
  set. Such a refusal is a Resource-policy condition, carried as
  `resource_policy` ({{I-D.draft-mcguinness-mission-authzen}}), not
  a drift refusal.
- Actions not sourced from a discovered catalog (deployment-registered
  `authorization_details` types, first-party operations with stable
  identity) do not require this binding.

## Decision-Time Verification {#capability-verification}

For a catalog-sourced action whose approved entry recorded a
capability source binding at derivation, the PDP MUST verify, as
part of its decision, that `context.capability_source` is present
and matches the approved binding: the presented `source_digest`,
computed over the capability's current extracted definition
({{capability-extraction}}), MUST equal the recorded value, and,
where a `catalog_digest` was recorded, the presented `catalog_digest`
MUST equal it likewise; otherwise the PDP returns `capability_drift`
({{capability-drift-reason}}). Whether an action is catalog-sourced,
and which digests were recorded, are determined from the
materialized policy view the AuthZEN binding defines
({{I-D.draft-mcguinness-mission-authzen}}), not from the PEP's
request; where no source binding was recorded, this check does not
apply.

## Per-Capability Extraction {#capability-extraction}

`source_digest` is computed over the extracted per-capability
definition, not the whole retrieved source, so a revision elsewhere
in a shared catalog does not invalidate a Mission's approved
capabilities, while any mutation of an approved capability's own
definition still refuses. The extraction rule is fixed per source
format:

- For an MCP tool catalog, the extracted definition is the single
  tool's definition object as retrieved (the member of the catalog's
  tool list whose name is the capability's), JCS-canonicalized
  {{RFC8785}}.
- For an OpenAPI document, the extracted definition is an object
  with two members: `operation`, the operation object
  `operation_ref` identifies, and `components`, an object carrying,
  under their component names, the components of the document the
  operation references by name, directly or transitively. The
  assembled object is JCS-canonicalized.
- For another source format, the binding profile in use defines the
  extraction rule. A capability whose format has no defined
  extraction rule cannot carry a `source_digest`; the whole-source
  `catalog_digest` remains available for it.

For the MCP tool of the minimum binding above, the extracted
definition is the tool's definition object:

~~~ json
{
  "name": "write_document",
  "description": "Create or update a document",
  "inputSchema": {
    "type": "object",
    "properties": {
      "path": { "type": "string" },
      "content": { "type": "string" }
    },
    "required": ["path", "content"]
  }
}
~~~

The JCS canonical bytes are a single line with sorted member names
and no whitespace, shown here wrapped for layout only; remove the
layout line breaks, adding no characters, to recover the canonical
form:

~~~ text
{"description":"Create or update a document","inputSchema":{"propert
ies":{"content":{"type":"string"},"path":{"type":"string"}},"require
d":["path","content"],"type":"object"},"name":"write_document"}
~~~

~~~ text
source_digest = sha-256:OAbEIh2DTYUVP7DjRhHct4aapsT8PybZq2ILdut9UP0
~~~

Adding, removing, or renaming another tool in the same catalog
leaves this value unchanged; any byte change to this definition
changes it.

Cross-format canonicalization, signed capability manifests, and
media-type negotiation across catalog formats are out of scope
({{I-D.draft-mcguinness-mission-runtime}}); this document requires
only the stable identifier plus source evidence above.

## Capability Drift Denial Reason {#capability-drift-reason}

This document registers `capability_drift` as a coordinated
extension to the runtime denial classification, under the AuthZEN
binding's extensibility rule
({{I-D.draft-mcguinness-mission-authzen}}): an extension value MUST
be either a collision-resistant name (following the
Collision-Resistant Name guidance of {{RFC7519}} Section 4.2) or a
name coordinated within the Mission-Bound Authorization document
family; `capability_drift` is the name this document reserves.

`capability_drift`:
: for a catalog-sourced action whose approved entry recorded a
  capability source binding ({{capability-source-binding}}), the
  digest of the action's current extracted capability definition
  differs from the `source_digest` committed at derivation, a
  recorded `catalog_digest` no longer matches the retrieved source,
  or the presented `tool_id` is outside the approved set.

`capability_drift` applies only when a source binding was recorded
and the digest comparison ran; an invoked identity outside the
approved set for which no source binding was recorded is
`out_of_authority` ({{I-D.draft-mcguinness-mission-authzen}}), not
`capability_drift`.

Capability or catalog drift, and an invoked identity outside the
approved set when a source binding was recorded, surface as a PDP
denial carrying `capability_drift`, under the carrier taxonomy of
the AuthZEN binding ({{I-D.draft-mcguinness-mission-authzen}}).

# Conformance {#conformance}

A deployment claims Mission Capability Binding only for the
catalog-sourced actions within the runtime enforcement scope it
documents ({{I-D.draft-mcguinness-mission-runtime}}), under the
AuthZEN decision-API binding
({{I-D.draft-mcguinness-mission-authzen}}).

A validating server conforming to this document MUST record
`tool_id`, `source_uri`, `source_digest`, `operation_ref`, and any
`catalog_digest` for every consequential action sourced from a
discovered catalog, at derivation ({{capability-source-binding}}).

A PEP conforming to this document MUST present
`context.capability_source` on a consequential request for a
catalog-sourced action ({{context-capability-source}}).

A PDP conforming to this document MUST verify the presented binding
against the recorded one and return `capability_drift` on a
mismatch ({{capability-verification}}, {{capability-drift-reason}}).

A deployment that does not claim this document is unaffected: the
AuthZEN binding's decision contract consumes an already established
action identity ({{I-D.draft-mcguinness-mission-authzen}}).

# Security Considerations {#security-considerations}

The runtime profile's Security Considerations
({{I-D.draft-mcguinness-mission-runtime}}) and the AuthZEN binding's
({{I-D.draft-mcguinness-mission-authzen}}) apply in full. This
section addresses only threats specific to capability-source
binding.

## Catalog compromise and stale digests

A validating server that records `source_digest` over stale or
attacker-influenced source data commits to the wrong capability from
the start; this document detects drift after derivation, not a
poisoned derivation. Where the catalog itself is not trusted, a
deployment SHOULD additionally record `catalog_digest` and constrain
`source_uri` to a trusted, authenticated origin.

## Executor identity is not a security boundary

The `executor` member is a request-time fact the PEP asserts after
authenticating the serving component; it is never an input to
`source_digest` or `catalog_digest`, so a spoofed executor cannot
mask or forge a drift check. Resource policy, not this document,
bounds which executors are trusted ({{capability-source-binding}}).

# Privacy Considerations {#privacy-considerations}

The runtime profile's evidence-privacy guidance
({{I-D.draft-mcguinness-mission-runtime}}) applies in full.
`source_uri`, `tool_id`, and `executor`, when recorded in Decision
Evidence ({{I-D.draft-mcguinness-mission-runtime-evidence}}), MAY
reveal internal catalog topology; this document defines no
additional record content and no exemption from that guidance.

# IANA Considerations {#iana}

This document requests no IANA actions. The `context.capability_source`
member this document adds to the AuthZEN request `context` object
({{I-D.draft-mcguinness-mission-authzen}}) is AuthZEN extension data
and is not registered in an IETF registry. The `capability_drift`
denial-reason value is a specification-coordinated extension of the
runtime denial classification
({{I-D.draft-mcguinness-mission-authzen}}), not an IANA-registered
value.

--- back

# Acknowledgments
{:numbered="false"}

This document extracts the capability-source binding from
Mission-Bound Runtime Enforcement: AuthZEN Profile and builds on the
OpenID AuthZEN Profile for Model Context Protocol Tool Authorization.
The author thanks the OpenID AuthZEN community and the Mission-Bound
Authorization implementer community for feedback.
