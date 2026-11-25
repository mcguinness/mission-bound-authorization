---
title: "OAuth 2.0 Mission Anchors"
abbrev: "Mission Anchors"
category: std

docname: draft-mcguinness-oauth-mission-anchors-latest
submissiontype: IETF
workgroup: Web Authorization Protocol
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - digest
 - commitment
 - JCS
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-anchors.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  RFC4648:
  RFC6234:
  RFC6920:
  RFC7493:
  RFC7519:
  RFC8785:

informative:
  MISSION-BASE:
    title: "OAuth 2.0 Mission"
    target: https://github.com/mcguinness/mission-bound-authorization/blob/main/notes/mission-base-sketch.md
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

This document defines one construction for an anchor: a digest of a
JSON value, separated by object type and bound to an issuer, so that
specifications that commit facts of an OAuth 2.0 Mission produce the
same bytes for the same inputs.

--- middle

# Introduction

Specifications layered on OAuth 2.0 Mission {{MISSION-BASE}} commit
facts of a Mission by digest, such as the description of the work or
the approved authority. This document defines the construction they
share, so that each computes the same anchor for the same inputs and
none depends on another or on the base. It defines no Mission
behavior: a specification that uses it states what it commits, under
which `typ`, and where the anchor is carried. The construction produces
the same bytes as the commitment construction of Mission-Bound
Authorization for OAuth 2.0 {{I-D.draft-mcguinness-oauth-mission}}.

## Conventions and Terminology

{::boilerplate bcp14-tagged}

# Anchors {#anchors}

A party implements this construction when a specification it
implements uses it.

An anchor over a JSON value is computed as follows:

1. Construct the envelope, where `typ` names the kind of object
   committed, `iss` is the issuer identifier of the party that makes
   the commitment, unless the specification using the construction
   names another, such as the issuer an object's own format defines,
   and `value` is the object:

   ~~~
   { "typ": "<object type>", "iss": "<issuer>", "value": <object> }
   ~~~

2. Canonicalize the envelope with JCS {{RFC8785}}.
3. Compute SHA-256 {{RFC6234}} over the canonical bytes.
4. Encode the result as `sha-256:` followed by the base64url encoding
   of the digest, without padding ({{RFC4648}}).

The `typ` value separates object types, so a digest of one kind of
object cannot stand for another. The `iss` binding keeps a committed
object from being transplanted from one authorization server to
another. A specification that commits an object defines its `typ`
value, which MUST be a collision-resistant name, for example a short
name prefixed within a namespace the defining specification controls,
following the Collision-Resistant Name guidance of
{{Section 2 of RFC7519}}. Values with the `mission-` prefix form a
namespace that this document lists ({{namespace}}); there is no IANA
registry of `typ` values.

## Canonicalization {#canonicalization}

JCS alone leaves gaps that two implementations could fill differently.
These rules close them, for computing an anchor and for comparing
committed values:

- The committed `value` is exactly the object the authorization server
  recorded, so an auditor reproduces the anchor from the record alone.
- JCS does not reorder arrays, and no sorting is defined, so array
  order is significant. The authorization server presents each
  committed array in its recorded order wherever it emits it.
- URI values are committed and compared byte for byte, with no
  normalization, unless a type defines a normalization for a
  comparison of its own; anchor computation is always byte-exact over
  the recorded values.

## Input and Algorithm {#algorithm}

Every committed value and its envelope are I-JSON {{RFC7493}} data, as
{{Section 3.1 of RFC8785}} requires. The party computing or verifying
an anchor MUST reject input that is not I-JSON rather than adapt it,
and MUST parse received JSON with a parser that rejects duplicate
member names. The anchor is over the parsed data, not the source text,
so a value that needs exact decimal or large-integer semantics is
carried as a string.

`sha-256` is mandatory to implement for a party that computes anchors,
and is the only algorithm defined. A new algorithm enters only through
a new prefix that a specification using this construction defines, named from the
Named Information Hash Algorithm Registry {{RFC6920}}, and there is no
negotiation. A verifier MUST reject an anchor whose prefix it does not
recognize, so a later algorithm cannot be used to downgrade. A
specification that introduces a new prefix defines where a parallel
anchor is carried, how the old and new values are shown to commit to
the same object, producer and verifier behavior while both are in use,
and the transition; it never changes an anchor already made, including
an implied value.

## The mission- Namespace {#namespace}

This document lists every value with the `mission-` prefix. Each entry
gives the exact value, the specification that defines it, and the
object it commits. A listed value never changes and is never reused
for another object, so anchors and test vectors computed under it
stay valid. OAuth 2.0 Mission Intent and OAuth 2.0 Mission Commitments
use `mission-intent`, `mission-authority-set`, and
`mission-authority-entry` for the same objects as the specification
that defines them.

| Value | Defined by | Committed object |
|---|---|---|
| `mission-activation-policy` | draft-mcguinness-mission-approval-governance | an activation policy snapshot: its media type and exact bytes |
| `mission-approval-context-v1` | draft-mcguinness-mission-approval-governance | the approval context manifest |
| `mission-approval-policy` | draft-mcguinness-mission-approval-governance | an approval policy snapshot: its media type and exact bytes |
| `mission-authority-ceiling` | draft-mcguinness-oauth-mission-progressive | an authority ceiling and its drawdown policy |
| `mission-authority-entry` | draft-mcguinness-oauth-mission | one entry of the approved authority, as recorded |
| `mission-authority-set` | draft-mcguinness-oauth-mission | the approved authority, as recorded |
| `mission-consent-disclosure` | draft-mcguinness-oauth-mission-consent-evidence | the consent disclosure object |
| `mission-creation-fingerprint` | draft-mcguinness-oauth-mission-expansion | a creation operation fingerprint |
| `mission-delegation-chain` | draft-mcguinness-oauth-mission-cross-org-delegation | an ordered chain of compact JWS delegation tokens |
| `mission-derivation-entries` | draft-mcguinness-mission-audit | the `authorization_details` of an issued token |
| `mission-intent` | draft-mcguinness-oauth-mission | the approved Mission Intent |
| `mission-intent-evidence` | draft-mcguinness-oauth-mission | one submission evidence entry, as presented |
| `mission-policy-view` | draft-mcguinness-mission-runtime | a materialized policy view manifest |
| `mission-proposed-authority` | draft-mcguinness-oauth-mission | the submitted `authorization_details`, as recorded |
| `mission-shaping-evidence` | draft-mcguinness-mission-shaping | a shaping evidence object |
| `mission-substrate-context` | draft-mcguinness-mission-substrate | the context object of that document's illustrative worked example |
| `mission-submission-evidence-v1` | draft-mcguinness-mission-approval-governance | the recorded `submission_evidence` array |
| `mission-submission-provenance` | draft-mcguinness-oauth-mission-consent-evidence | the recorded `submission_evidence` array |
| `mission-template` | draft-mcguinness-oauth-mission-template | a Mission Template |
| `mission-unwind-plan` | draft-mcguinness-mission-orchestration | a step's unwind plan |
| `mission-work-product-provenance` | draft-mcguinness-oauth-mission-work-products | a work product's provenance object |
{: title="Values with the mission- prefix"}

The change controller of this document, its author until a working
group adopts it, maintains this list. A specification adds a value by
asking in the public issue tracker of this document's repository,
giving the value, its defining specification, and the committed
object, and the next revision of this document lists it. A
specification that does not use this list names its `typ` values in a
namespace it controls ({{anchors}}).

# Security Considerations

The `typ` value separates object types, so a digest of one kind of
object cannot stand for another, and the `iss` value keeps a committed
object from being transplanted from one issuer to another
({{anchors}}). An anchor commits bytes, not meaning: a party relies on
an anchor only for an object whose canonical form it reproduces, and
treats an anchor with a prefix it does not recognize as unverifiable
({{algorithm}}).

# Privacy Considerations

An anchor over an object with little entropy, such as a short
description of a task, can be reversed by guessing the object and
recomputing the anchor. A specification that commits such an object
states who may see the anchor.

# IANA Considerations

This document has no IANA actions.

--- back

# Document History
{:numbered="false"}

\[\[ To be removed from the final specification ]]

-00

- Initial version: the anchor construction, separated from OAuth 2.0
  Mission so that the base defines no construction it does not use,
  and the list of values with the `mission-` prefix.
