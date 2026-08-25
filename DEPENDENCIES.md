# Mission-Bound Authorization dependency status

This file carries the dependency report for the family: where every
normative dependency outside the repository stands, and which of them
are not yet ratified. [README.md](README.md) keeps only the pointer;
the per-document catalog is in [DRAFTS.md](DRAFTS.md).

The author's proposed initial OAuth WG submission set is recorded
separately in [notes/oauth-wg-submission-set.md](notes/oauth-wg-submission-set.md).

## Dependency stability

<!-- external-normative-ids: BEGIN (generated; validated by scripts/check-family-manifest.mjs) -->
- I-D.draft-gerber-oauth-deferred-token-response (cited normatively by: oauth-mission-approval, oauth-mission-approval-revision)
- I-D.draft-hardt-oauth-aauth-protocol (cited normatively by: aauth-mission-expiry, mission-aauth, mission-aauth-management)
- I-D.draft-ietf-cose-hash-envelope (cited normatively by: mission-audit)
- I-D.draft-ietf-oauth-identity-assertion-authz-grant (cited normatively by: oauth-mission-cross-domain)
- I-D.draft-ietf-oauth-identity-chaining (cited normatively by: oauth-mission-cross-domain)
- I-D.draft-ietf-oauth-status-list (cited normatively by: oauth-mission-status)
- I-D.draft-niyikiza-oauth-attenuating-agent-tokens (cited normatively by: oauth-mission-attenuation, oauth-mission-cross-org-delegation)
- I-D.draft-rosomakho-oauth-txn-challenge (cited normatively by: oauth-mission-transaction-authorization)
- I-D.draft-zehavi-oauth-rar-metadata (cited normatively by: mission-authzen)
<!-- external-normative-ids: END -->

Bold shorthand below names the family's documents informally;
[DRAFTS.md](DRAFTS.md) maps every document to its full draft name.

Outside the family itself, every normative dependency is a ratified
RFC, a finalized OpenID specification, or (for the **uma** sketch) a
final Kantara Initiative Recommendation, with these tracked
exceptions: **oauth-mission** (the OAuth binding) cites the OAuth 2.0
RAR Metadata and Error Remediation individual draft informatively
only: an AS that implements that draft's type-metadata endpoint
SHOULD advertise it, conformance does not depend on it, and the
stable baseline is RFC 9396's `authorization_details_types_supported`
(a MUST for an advertising AS); its reference to the OAuth Actor
Profile is likewise informative and confined to its optional
Delegation capability; **status** depends on the OAuth Status List (a
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
