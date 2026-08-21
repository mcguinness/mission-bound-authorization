# Mission-Bound Authorization dependency status

This file carries the dependency report for the family: where every
normative dependency outside the repository stands, and which of them
are not yet ratified. [README.md](README.md) keeps only the pointer;
the per-document catalog is in [DRAFTS.md](DRAFTS.md).

## Dependency stability

Bold shorthand below names the family's documents informally;
[DRAFTS.md](DRAFTS.md) maps every document to its full draft name.

Outside the family itself, every normative dependency is a ratified
RFC, a finalized OpenID specification, or (for the **uma** sketch) a
final Kantara Initiative Recommendation, with these tracked
exceptions: **oauth-mission** (the OAuth binding) has a normative dependency on an
unratified individual draft (OAuth 2.0 RAR Metadata and Error
Remediation): an AS that advertises Mission-bound authorization
support MUST advertise the authorization-details type-metadata
endpoint that draft defines, and its reference to the OAuth Actor
Profile is informative and confined to its optional Delegation
capability; **status** depends on the OAuth Status List (a
working-group document); **cross-domain** depends on OAuth
identity chaining (approved, in the RFC Editor queue) and ID-JAG (a
working-group document); **audit**'s COSE hash envelope is approved
and in the RFC Editor queue; **approval**, **attenuation**,
**cross-org-delegation**, **aauth**, **aauth-expiry**, and
**aauth-management** track unratified individual drafts (OAuth
Deferred Token Response, Attenuating Agent Tokens, and the AAuth
protocol); **authority-server** confines its Internet-Draft
references (client instance assertion and the AI agent instance
profile) to the
Enterprise Mission Authority Profile's instance-bound joins, an
optional hardening above the base conformance floor. For
**authzen**, the decision binding tracks the AuthZEN working group:
the core evaluation API, and normatively the Access Request and
Approval Profile (ARAP) and the Obligations Profile, both
working-group drafts. **capability-binding**'s Model Context Protocol
tool-authorization (COAZ) integration remains informative and
optional.

Family-internal normative dependencies are Internet-Drafts by
construction: the substrate contract anchors the **uma**, **gnap**,
**authority-server**, and **aauth** Statements; **aauth-expiry**
anchors the AAuth binding and its management companion; and **oauth-mission** anchors its OAuth companions. The family manifest tracks
these. The substrate contract publishes before or with any binding
that claims conformance to it.

In short: a stable adoption path on the OAuth binding (the binding
itself, Status, and the runtime enforcement documents) rests on
ratified dependencies and the tracked in-progress ones noted above;
the MAS and AAuth bindings are equally stable paths per their own
dependency notes, and everything experimental is additive and can
wait.
