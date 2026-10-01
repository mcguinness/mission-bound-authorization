# Disposition ledger (non-KEEP rows)

Generated from CLASS-R1..R5.jsonl. `L` is the BASE.md line (PR #864 head 162b63e1). KEEP rows (203) are in ALL.json.

## DELETE-POINTER (84)

### DUPLICATE (63)

- **#3** L540 `conventions-and-terminology` MAY: Terminology entry carries a keyword that {{grant-binding}} states as its home.
  - Proposal: Delete the sentence 'A Mission MAY have zero or more grant bindings; a grant binding never resolves to more than one Mission.'; the definition already maps each lineage 'to exactly one Mission ({{grant-binding}})'.
  - Home: #138
- **#4** L576 `principal-model` OPTIONAL: Overview restates the adjudication member label (OPTIONAL) and its permission; one proposal covers #4 and #5.
  - Proposal: under a standing-consent basis a policy adjudicates the activation, which the basis's `adjudication` member can make explicit ({{mission-record}}), while the Approver remains the human whose consent roots it
  - Home: #177
- **#5** L576 `principal-model` MAY: Same sentence as #4; second keyword.
  - Proposal: Covered by the #4 proposal.
  - Home: #177
- **#7** L642 `protocol-flow` MAY: Overview keyword duplicates the Resource Server list (#316 require; #319 audit context). Overview should carry no keywords.
  - Proposal: the RS enforces the `authorization_details` statelessly and can check the `mission` claim ({{rs-enforcement}}), with no callback to the AS required.
  - Home: #316
- **#8** L642 `protocol-flow` MAY: Same permission as {{revocation}} #257; overview keyword.
  - Proposal: a deployment can also treat RFC 7009 {{RFC7009}} revocation of the refresh token as revoking the Mission ({{revocation}}).
  - Home: #257
- **#14** L768 `mission-intent` MUST NOT: Fourth statement of the prose boundary; one home at #83 (which adds `goal_lang`).
  - Proposal: It is disclosure metadata for rendering, committed by `intent_hash` like every Intent member, and carries no machine semantics ({{authorization-derivation}}).
  - Home: #83
- **#18** L789 `mission-intent` MUST NOT: Same rule as #83 for `task_bounds`.
  - Proposal: They are disclosure and audit context, rendered to the Approver beside the derived Authority Set ({{approval-event}}) and never parsed for machine semantics ({{authorization-derivation}}); a machine-enforceable bound enters as structure instead.
  - Home: #83
- **#20** L797 `mission-intent` MUST NOT: Same rule as #83 for `success_criteria`.
  - Proposal: These are disclosure and audit material only: they are rendered to the Approver and committed by `intent_hash` ({{integrity-anchors}}) and carry no machine semantics ({{authorization-derivation}}).
  - Home: #83
- **#26** L819 `mission-intent` MUST NOT: Third statement of the ceiling (#111 producer, #218 member definition). Passive MUST; party is the AS.
  - Proposal: The submitted Intent is recorded verbatim. The lifetime actually granted is the Mission Record's effective `expires_at`, which the AS establishes at Mission creation and which is never later than this value ({{approval-event}}, {{mission-record}}).
  - Home: #218
- **#27** L822 `mission-intent` MAY: Permission restates the approval-event establishment step; "longer requires fresh approval" restates #89.
  - Proposal: Cut: {{approval-event}} step 4 narrows the ceiling by policy (#111), and a longer lifetime is a widening the Subset Rule refuses (#89).
  - Home: #111
- **#35** L925 `submission-via-par` MUST: Restates the member type; AS refusal follows from #36. Rationale 'omission already expresses absence ...' is cut.
  - Proposal: `evidence`: OPTIONAL. A non-empty array of Intent Submission Evidence entries ({{intent-submission-evidence}}); the AS refuses an empty array with `invalid_request`.
  - Home: #34
- **#39** L965 `submission-via-par` SHOULD: SHOULD contradicts #55 MUST (unsupported type) and error-mapping (policy refusal = access_denied), which declares itself the one home.
  - Proposal: **Derivation failure is distinct from syntax.** A well-formed submission that yields no valid Authority Set is refused after validation, with the error code {{error-mapping}} assigns to the failing object, so a client can tell a syntax error from a derivation failure.
  - Home: #55
- **#45** L1007 `submission-via-par` MUST NOT: Record spans three bullets; #45 is the first keyword. Bound on derived authority is #77; token-level bound is #88.
  - Proposal: Absorbed by the #44 proposal.
  - Home: #77
- **#51** L1055 `authority-proposal` MUST NOT: Same clause as #45 verbatim ('MUST NOT grant authority beyond what the Mission Intent yields').
  - Proposal: The submitted `authorization_details` is a proposal, never authority ({{submission-via-par}}); the AS derives and bounds the Authority Set from it ({{authorization-derivation}}).
  - Home: #77
- **#58** L1075 `authority-proposal` MUST: Home is mission-bound-tokens #281, which itself restates RFC 9396 Section 7 (and removes its "MAY omit values").
  - Proposal: The granted `authorization_details` in the token response reflects every narrowing and omission ({{mission-bound-tokens}}).
  - Dependency: RFC9396 Section 7: 'In addition to the token response parameters as defined in [RFC6749], the AS MUST also return the authorization_details as granted by the resource owner and assigned to the respective access token.'
  - Home: #281
- **#74** L1293 `authorization-derivation` MUST: Verbatim duplicate of #59.
  - Proposal: Each derived entry is a same-type subset of a proposed entry ({{authority-proposal}}).
  - Home: #59
- **#79** L1329 `authorization-derivation` MUST: Record member is REQUIRED (#211); this restates it. Audit purpose.
  - Proposal: The Mission records the policy version in force as `policy_version` ({{mission-record}}), an opaque audit correlator; the policy itself does not travel.
  - Home: #211
- **#81** L1345 `authorization-derivation` MUST: Echo is per token (#281); comparing it with the proposal shows a shortfall only if the token carries the full set.
  - Proposal: The granted `authorization_details` in the token response ({{mission-bound-tokens}}) is the authoritative statement of what was granted; a client compares it against its proposal, which `proposal_hash` commits as submitted ({{integrity-anchors}}).
  - Dependency: RFC9396 Section 7: 'In addition to the token response parameters as defined in [RFC6749], the AS MUST also return the authorization_details as granted by the resource owner and assigned to the respective access token.'
  - Home: #281
- **#87** L1424 `authorization-derivation` MAY: Same permission as #90.
  - Proposal: `mission_resource_access` is defined by the Mission Resource Access Profile ({{I-D.draft-mcguinness-oauth-mission-resource-access}}); the Authority Set carries it on the same type-agnostic terms as any supported type ({{other-types}}).
  - Home: #90
- **#93** L1505 `other-types` MUST NOT: Second keyword of the #92 sentence.
  - Proposal: Delete ', and MUST NOT appear in a delegated token or in a cross-domain grant'; #91 already bars delegation and projection to a Resource AS.
  - Home: #91
- **#97** L1578 `other-types` MUST NOT: A MUST NOT inside a non-normative example restates #91.
  - Proposal: Because the Cedar profile defines no subset or delegation rule over policy sets, the AS carries the Cedar entry as approved, so it does not appear in a delegated token or cross-domain grant ({{other-types}}).
  - Home: #91
- **#111** L1661 `approval-event` MUST NOT: #218 is the tested home; #26 in mission-intent is a third copy (flag for R1).
  - Proposal: Replace 'The established value MUST NOT be later than the requested ceiling and MUST be in the future when established.' with 'The value is bounded as `expires_at` requires ({{mission-record}}) and is rechecked at the creation commit (step 7).'
  - Home: #218
- **#112** L1661 `approval-event` MUST: Record invariant #217 plus commit-time check #118 cover it; an establishment-time check adds nothing observable.
  - Proposal: Replace 'The established value MUST NOT be later than the requested ceiling and MUST be in the future when established.' with 'The value is bounded as `expires_at` requires ({{mission-record}}) and is rechecked at the creation commit (step 7).'
  - Home: #217
- **#119** L1717 `approval-event` MUST: Paragraph 1717-1725 restates the approval_basis rules at 2313-2318.
  - Proposal: Every Mission is rooted in an approved authorization basis (`approval_basis`, {{mission-record}}); the steps above define the `direct` basis, and {{mission-record}} states the rules for it and for a standing-consent basis a companion profile defines.
  - Home: #189
- **#121** L1719 `approval-event` MUST: #190 is the fuller home (it adds the approved_at carriage, #191).
  - Proposal: Every Mission is rooted in an approved authorization basis (`approval_basis`, {{mission-record}}); the steps above define the `direct` basis, and {{mission-record}} states the rules for it and for a standing-consent basis a companion profile defines.
  - Home: #190
- **#136** L1851 `approval-authentication` MUST NOT: A Mission Intent member is client input; #102 already forbids taking achieved authentication context from it.
  - Proposal: The authentication achieved for the approval event (`acr`, `amr`, and `auth_time`, in the sense {{RFC9470}} and {{OpenID.Core}} define them) is approval-time provenance established under step 1 of {{approval-event}}, never a Mission Intent member.
  - Home: #102
- **#204** L2368 `mission-record` MUST NOT: Step 6 under #101 and integrity-anchors (BASE.md 2595) fix each anchor's input, so approval_basis cannot enter either digest.
  - Proposal: `approval_basis` is provenance: neither anchor covers it ({{integrity-anchors}}); a profile that commits the Mission Record itself covers it under that profile's own anchor.
  - Home: #101
- **#205** L2370 `mission-record` MAY: #344 is the disclosure rule; #295 in mission-claim is another copy.
  - Proposal: Its disclosure through introspection follows {{caller-authorization-and-minimization}}.
  - Home: #344
- **#216** L2419 `mission-record` MUST NOT: Lifecycle #240 and gating #246/#247 own the no-derivation-after-expiry rule.
  - Proposal: An RFC 3339 date-time: the AS-established effective Mission expiry ({{lifecycle}}, {{issuance-gating}}).
  - Home: #240
- **#221** L2467 `role-mapping` OPTIONAL: Restates adjudication OPTIONAL; 'this revision imposes' is temporal.
  - Proposal: Where a profile or deployment does not populate `adjudication` ({{mission-record}}), the table shows the value it would carry.
  - Home: #177
- **#226** L2665 `canonicalization` MUST: Same rule restated at lines 2722-2725 under #230, which the tested ledger row anchors; keep that home.
  - Proposal: - Duplicate member names are rejected at parse time ({{commitment-mechanisms}}).
  - Home: #230
- **#227** L2665 `canonicalization` MUST: Rejection half of the same duplicated rule.
  - Proposal: (folded into the #226 pointer)
  - Home: #230
- **#245** L2829 `derivation-issuance-policy` MUST: Approval-event step 5 (line 1672), under #101's 'MUST, in order', already renders the established derivation_limit.
  - Proposal: The approval surface renders the established value ({{approval-event}}).
  - Home: #113
- **#256** L2925 `revocation` MUST: 'The MUST is satisfiable' is a keyword used as a noun about #255.
  - Proposal: A deployment-defined authenticated surface satisfies this; Mission Status ({{I-D.draft-mcguinness-oauth-mission-status}}) defines one interoperable `revoke` operation.
  - Home: #255
- **#259** L2934 `revocation` SHOULD: Third statement of short lifetimes (see also line 3124).
  - Proposal: Already-issued access tokens remain valid until they expire ({{issuance-gating}}).
  - Home: #254
- **#272** L2995 `mission-bound-tokens` MUST NOT: #88: 'The AS MUST refuse to derive an entry that is not a subset ... of some Mission Authority Set entry.'
  - Proposal: Every emitted `authorization_details` entry is a subset of a Mission Authority Set entry ({{subset}}).
  - Home: #88
- **#273** L2996 `mission-bound-tokens` MUST: Restates #88 for narrowed issuance.
  - Proposal: (folded into the #272 pointer)
  - Home: #88
- **#277** L3022 `mission-bound-tokens` SHOULD: Restates #270; the whole paragraph at line 3022 repeats three levels stated elsewhere.
  - Proposal: (delete the paragraph; point to {{delegation}} for the delegated-token MUST)
  - Home: #270
- **#278** L3023 `mission-bound-tokens` MUST: #359 is the delegated-token MUST.
  - Proposal: Delegated tokens are sender-constrained to the delegate's own key ({{delegation}}).
  - Home: #359
- **#280** L3027 `mission-bound-tokens` SHOULD: Third SHOULD for the same token in one section.
  - Proposal: (delete)
  - Home: #270
- **#287** L3111 `mission-bound-tokens` MAY: Second statement of the scope permission.
  - Proposal: `authorization_details` is the authoritative expression of a Mission-bound token's authority; a `scope` claim ({{scope-projection}}) is a compatibility projection that cannot carry per-entry `constraints`.
  - Home: #269
- **#305** L3256 `mission-claim` MAY: Future-revision meta. Also repeated at #156 (line 2108).
  - Proposal: (delete; {{namespace-taxonomy}} states the specification-defined posture)
  - Home: #390
- **#318** L3352 `rs-enforcement` MAY: Stated in PRM (#407), repeated at downgrade (#425) and line 3383.
  - Proposal: (delete; {{protected-resource-metadata}} defines the member)
  - Home: #407
- **#325** L3372 `rs-enforcement` MUST NOT: #436 is the SecCons MUST covering the same routing; keep one. Author call on which home.
  - Proposal: A deployment that delegates routes delegated Mission-bound tokens only to Mission-aware Resource Servers ({{client-id-misattribution}}).
  - Home: #436
- **#335** L3563 `introspection` OPTIONAL: BCP 14 qualifies behaviors, not sections; "This section is OPTIONAL" is not RFC idiom and repeats #338 and #413.
  - Proposal: Delete the sentence; #338 ("An AS MAY support OAuth 2.0 Token Introspection") and the conformance capability list state the optionality.
  - Home: #338
- **#336** L3564 `introspection` REQUIRED: Same rule also at #271 (mission-bound-tokens), #411 and #415; #349 is the one home with party and condition.
  - Proposal: Delete; {{introspected-consumption}} carries the rule.
  - Home: #349
- **#355** L3805 `delegation` OPTIONAL: Section-level OPTIONAL is not RFC idiom.
  - Proposal: Delete "This section is OPTIONAL."; the heading "(Optional)" and the conformance list carry it.
  - Home: #413
- **#358** L3850 `delegation` MUST NOT: Restates #357 in negative form; #89 already forbids widening after approval.
  - Proposal: Delete "Delegation MUST NOT add authority."
  - Home: #357
- **#360** L3860 `delegation` MUST: #246 already names Token Exchange: "The AS MUST refuse to derive a token, at the token endpoint, on refresh, and on Token Exchange".
  - Proposal: Issuing a delegated token is a derivation, refused unless the Mission is `active` ({{issuance-gating}}).
  - Home: #246
- **#373** L4158 `lasv-retrieval` MUST NOT: #372 already requires the subset check whatever the commitment result.
  - Proposal: Delete ", and MUST NOT treat commitment match alone as sufficient" from the second bullet.
  - Home: #372
- **#397** L4681 `discovery` MAY: other-types lines 50-58 already give the carrier order and "Deployment documentation is always a sufficient carrier".
  - Proposal: Delete the paragraph at 4679-4687; {{other-types}} states the declaration and its carriers.
  - Home: #95
- **#398** L4698 `discovery` OPTIONAL: The member's own OPTIONAL is the one home.
  - Proposal: Delete "Discovery is OPTIONAL:"; keep the #399 sentence.
  - Home: #393
- **#404** L4725 `discovery` MUST: Repeats #395 and the following sentence (4672-4675) almost word for word.
  - Proposal: Delete the sentence "The stable baseline is {{RFC9396}}: ... is its normative definition."
  - Home: #395
- **#411** L4795 `conformance` REQUIRED: Fourth statement of the opaque-token introspection rule.
  - Proposal: ... as the RFC 9068 JWT or as an opaque reference token under the introspected consumption mode ({{introspected-consumption}});
  - Home: #349
- **#414** L4835 `conformance` OPTIONAL: Repeats #413 and #338.
  - Proposal: Delete "OPTIONAL as a state overlay for JWT deployments;"
  - Home: #413
- **#415** L4836 `conformance` REQUIRED: Fifth statement of the opaque-token rule; lowercase pointer.
  - Proposal: Required where the AS issues opaque Mission-bound tokens ({{introspected-consumption}}).
  - Home: #349
- **#425** L5057 `downgrade-by-omission` MAY: Same permission as rs-enforcement #318.
  - Proposal: On the enforcement side, a Resource Server for such a resource rejects a token lacking the `mission` claim and can advertise that requirement ({{rs-enforcement}}, {{protected-resource-metadata}}).
  - Home: #318
- **#428** L5220 `token-theft` SHOULD: Restates the primary-token SHOULD of mission-bound-tokens.
  - Proposal: Derived tokens are sender-constrained (DPoP {{RFC9449}} or mTLS {{RFC8705}}) at the levels set in {{mission-bound-tokens}} and {{delegation}}.
  - Home: #270
- **#429** L5220 `token-theft` MUST: Restates the delegated-token MUST of delegation (also echoed at #278).
  - Proposal: Derived tokens are sender-constrained (DPoP {{RFC9449}} or mTLS {{RFC8705}}) at the levels set in {{mission-bound-tokens}} and {{delegation}}.
  - Home: #359
- **#430** L5220 `token-theft` MUST: Restates a companion's MUST, already echoed at #279; core Security text should not restate companion levels.
  - Proposal: Derived tokens are sender-constrained (DPoP {{RFC9449}} or mTLS {{RFC8705}}) at the levels set in {{mission-bound-tokens}} and {{delegation}}.
  - Home: #279
- **#433** L5247 `delegation-and-chain-compromise` SHOULD: #254 already makes all derived tokens, delegated included, short-lived.
  - Proposal: Short derived-token lifetimes ({{issuance-gating}}), and marking delegable only the entries that need delegation, keep this exposure small.
  - Home: #254
- **#435** L5280 `client-id-misattribution` MUST NOT: Same rule as #313 widened to 'component'; #325 already covers non-RS components.
  - Proposal: {{rs-enforcement}} forbids a Resource Server to infer the approved agent from `client_id`, and forbids routing a delegated token to a component that authorizes or logs on `client_id` without processing the `act` chain.
  - Home: #313
- **#450** L5543 `third-party-data-subjects` MAY: `submission_evidence` is already an OPTIONAL record member (#166).
  - Proposal: Mission approval and Mission authority are not the data subject's consent: a Mission record can retain a verified consent reference or facts as `submission_evidence` ({{mission-record}}), and those facts are provenance and policy input only, which the resource domain validates independently under its current disclosure policy.
  - Home: #166

### RESTATES (18)

- **#44** L1006 `submission-via-par` MAY: Base permissions; the proposal also absorbs #45.
  - Proposal: A client can also push `scope` and `resource` ({{RFC8707}}) values; the AS treats them as a requested subset of the authority the Mission Intent yields ({{authorization-derivation}}).
  - Dependency: RFC8707 Section 2: 'In requests to the authorization server, a client MAY indicate the protected resource (a.k.a. resource server, application, API, etc.) to which it is requesting access by including the following parameter in the request.'; RFC6749 Section 4.1.1: 'scope OPTIONAL. The scope of the access request as described by Section 3.3.'
- **#52** L1062 `authority-proposal` MUST: Supported-type requirement is RFC 9396 Section 5 validation.
  - Proposal: Replaced by the COMMIT 4 paragraph: "The AS validates each submitted entry per {{Section 5 of RFC9396}}: ...".
  - Dependency: RFC9396 Section 5: 'The AS MUST refuse to process any unknown authorization details type or authorization details not conforming to the respective type definition.'
- **#53** L1062 `authority-proposal` MUST: 'Validate against the documented definition' is RFC 9396 Section 5 'conforming to the respective type definition'.
  - Proposal: Replaced by the COMMIT 4 paragraph.
  - Dependency: RFC9396 Section 5: 'The AS MUST refuse to process any unknown authorization details type or authorization details not conforming to the respective type definition.'
- **#99** L1599 `approval-event` MUST: Once #98 makes the binding mandatory, both base specifications already require rejecting a mismatched verifier or key.
  - Proposal: Delete; end #98 with: 'Redemption is then verified as {{Section 4.6 of RFC7636}} or {{Section 10 of RFC9449}} specifies.'
  - Dependency: RFC7636 Section 4.6: "If the values are not equal, an error response indicating "invalid_grant" as described in Section 5.2 of [RFC6749] MUST be returned." RFC9449 Section 10: "If they do not match, it MUST reject the request."
- **#229** L2718 `commitment-mechanisms` MUST: The narrowing is reject-not-adapt (#230), which RFC 7493 Section 3 invites; the string and number bullets restate RFC 8785 Section 3.1.
  - Proposal: Every committed JSON value and its envelope are I-JSON data as {{Section 3.1 of RFC8785}} requires; the party computing or verifying a commitment MUST reject non-conformant input before canonicalization rather than adapt it:
  - Dependency: RFC8785 Section 3.1: Irrespective of the method used, the data to be serialized MUST be adapted for I-JSON [RFC7493] formatting, which implies the following:
- **#264** L2959 `mission-bound-tokens` MUST: Also duplicated by #306.
  - Proposal: Access tokens issued under a Mission are JWTs per {{RFC9068}}, which fixes the required claims (including `jti`), the `at+jwt` `typ` header parameter, and resource server validation ({{Section 2.1 of RFC9068}}, {{Section 2.2 of RFC9068}}, {{Section 4 of RFC9068}}).
  - Dependency: RFC9068 Section 4: The resource server MUST verify that the "typ" header value is "at+jwt" or "application/at+jwt" and reject tokens carrying any other value.
- **#270** L2965 `mission-bound-tokens` SHOULD: Same strength as the base, so no narrowing. Repeated at #277 and #280. Token-theft (5218) must then cite RFC 9700 Section 2.2.1 instead.
  - Proposal: - can be sender-constrained, as {{Section 2.2.1 of RFC9700}} recommends, via a `cnf` claim {{RFC7800}}: DPoP {{RFC9449}} (`cnf.jkt`) or mTLS {{RFC8705}} (`cnf.x5t#S256`).
  - Dependency: RFC9700 Section 2.2.1: Authorization and resource servers SHOULD use mechanisms for sender-constraining access tokens, such as mutual TLS for OAuth 2.0 [RFC8705] or OAuth 2.0 Demonstrating Proof of Possession (DPoP) [RFC9449] (see Section 4.10.1), to prevent misuse of stolen and leaked access tokens.
- **#274** L3000 `mission-bound-tokens` SHOULD: RFC 8707 Section 2 also permits mapping to 'a more general URI or abstract identifier'.
  - Proposal: The AS audience-restricts the token per {{Section 2 of RFC8707}} and {{Section 3 of RFC9068}}; `aud` names Resource Server(s), APIs, or security domains, not necessarily the entries' `resource` values.
  - Dependency: RFC8707 Section 2: The authorization server SHOULD audience-restrict issued access tokens to the resource(s) indicated by the "resource" parameter.
- **#275** L3012 `mission-bound-tokens` SHOULD: Keep the mechanics as prose; drop the cross-domain comparison sentence.
  - Proposal: Single-audience tokens ({{Section 2.3 of RFC9700}}) are obtained with the {{RFC8707}} `resource` parameter: the AS narrows the Authority Set under {{subset}} to the requested resource(s) and sets `aud` accordingly.
  - Dependency: RFC9700 Section 2.3: In particular, access tokens SHOULD be audience-restricted to a specific resource server or, if that is not feasible, to a small set of resource servers.
- **#306** L3314 `rs-enforcement` MUST: The cnf half restates RFC9449 Section 7.1 'a resource server MUST check that a DPoP proof was also received'.
  - Proposal: - validates the JWT per {{Section 4 of RFC9068}} and any sender-constraint per {{Section 7.1 of RFC9449}} or {{Section 3 of RFC8705}};
  - Dependency: RFC9068 Section 4: Resource servers receiving a JWT access token MUST validate it in the following manner.
- **#312** L3319 `rs-enforcement` MUST: Also restated in the token list (line 2971) and client-id-rebinding.
  - Proposal: - reads `client_id` as {{Section 4.3 of RFC8693}} defines it, on a delegated token or otherwise ({{client-id-rebinding}});
  - Dependency: RFC8693 Section 4.3: The "client_id" claim carries the client identifier of the OAuth 2.0 [RFC6749] client that requested the token.
- **#323** L3352 `rs-enforcement` MUST: The DPoP half is RFC9449 Section 7.1 'a resource server MUST check...'; composite-active line 3674 repeats it.
  - Proposal: (An introspecting Resource Server still verifies `cnf` locally: {{Section 6.2 of RFC9449}}, {{Section 3.2 of RFC8705}}, {{composite-active}}.)
  - Dependency: RFC8705 Section 3: The protected resource MUST obtain, from its TLS implementation layer, the client certificate used for mutual TLS and MUST verify that the certificate matches the certificate associated with the access token.
- **#324** L3352 `rs-enforcement` MUST NOT: Descriptive base text; composite-active (lines 3674-3678) already states it.
  - Proposal: (folded into the #323 pointer)
  - Dependency: RFC9449 Section 6.2: Note that the resource server does not send a DPoP proof with the introspection request, and the authorization server does not validate an access token's DPoP binding at the introspection endpoint.
- **#332** L3496 `remediation-grains` MAY: The base is SHOULD for its RSs; a MAY here understates it.
  - Proposal: A Resource Server can also return the `insufficient_authorization` error code with `authorization_remediation` ({{I-D.draft-ietf-oauth-rar-metadata-remediation}}).
  - Dependency: draft-ietf-oauth-rar-metadata-remediation-00 Section 4: Resource servers SHOULD return insufficient_authorization when access is denied due to missing or insufficient authorization details.
- **#333** L3499 `remediation-grains` OPTIONAL: MISSTATEMENT: the dependency says RECOMMENDED; the draft says OPTIONAL.
  - Proposal: (delete the member description; cite the draft)
  - Dependency: draft-ietf-oauth-rar-metadata-remediation-00 Section 4: authorization_reference: RECOMMENDED. An opaque string generated by the resource server to enable the client to select an existing access token associated with equivalent authorization details, without requiring the client to understand the semantics of the authorization details object:
- **#339** L3636 `caller-authorization-and-minimization` MUST ledger `core.introspection.caller-authentication` (retire): Tested row: retire or re-point to the kept pointer. RFC 7662 Section 2.1 also says "the endpoint MUST also require some form of authorization".
  - Proposal: Delete the bullet; keep the lead as "The introspection endpoint is protected per {{RFC7662}} Sections 2.1 and 4. In addition, the AS:"
  - Dependency: RFC7662 Section 4: "To prevent this, the authorization server MUST require authentication of protected resources that need to access the introspection endpoint and SHOULD require protected resources to be specifically authorized to call the introspection endpoint."
- **#356** L3843 `delegation` RECOMMENDED: Echoes the Actor Profile's own requirement level; the same bullet says "This document does not re-specify the `act` structure."
  - Proposal: Each actor object carries the members that profile defines (for example `sub`, `iss`, and the `sub_profile` actor-type classification, such as `ai_agent`).
  - Dependency: draft-mcguinness-oauth-actor-profile-00 Section 3.4: "In addition to the sub claim required by [RFC8693], a profile-conformant actor object MUST contain an iss claim and SHOULD contain a sub_profile claim."
- **#396** L4676 `discovery` MAY: Verbatim permission from the base; "understands" versus the base's "will use" also drifts.
  - Proposal: Delete; RFC 9396 Section 10 defines the client metadata.
  - Dependency: RFC9396 Section 10: "Clients MAY indicate the authorization details types they will use when requesting authorization with the client registration metadata parameter authorization_details_types, which is a JSON array."

### EXT-HOOK (2)

- **#31** L886 `mission-intent` MAY: Closure and its companion exception are the #37/#38 rule; {{extensibility}} owns how companions add members.
  - Proposal: The Mission Intent's top level is closed to the members above and to those a companion profile the AS implements defines ({{extensibility}}).
  - Home: #37
- **#391** L4638 `namespace-taxonomy` MAY: Governs other documents ("the audit profile's deferred evidence types"), framing the core as part of a family.
  - Proposal: Delete; family media-type registration policy belongs with {{I-D.draft-mcguinness-mission-architecture}} (owner decision).

### LOCAL-IMPL (1)

- **#319** L3352 `rs-enforcement` MAY: Permission to log is inherent.
  - Proposal: (delete; {{mission-claim}} says `id` and `issuer` carry no authority)

## MERGE (27)

### DUPLICATE (19)

- **#47** L1007 `submission-via-par` MUST NOT ledger `core.submission.pushed-parameters-authoritative` (reword): A value the AS ignores cannot widen authority; #47 adds no test beyond #46. Ledger row quotes both clauses.
  - Proposal: On the front-channel request that redeems the `request_uri`, the AS MUST ignore any `mission_intent`, `authorization_details`, `scope`, or `resource` presented.
  - Home: #46
- **#48** L1018 `submission-via-par` MUST: "Treat as a proposal" and "derive by policy" are one principle.
  - Proposal: Merged into the #49 proposal.
  - Home: #49
- **#57** L1075 `authority-proposal` MUST NOT: 'Keep such an entry silently' is unclear; the echo rule (#281) already forbids representing an unchanged entry as granted.
  - Proposal: Dropped; see COMMIT 4.
  - Home: #281
- **#63** L1180 `intent-submission-evidence` MUST NOT: Record spans two bullets; #63 is "MUST NOT be silently ignored", the converse of #62.
  - Proposal: Keep only: 'A submission is accepted only when every presented entry verifies.'
  - Home: #62
- **#67** L1197 `intent-submission-evidence` MUST NOT: Party unstated. If aimed at downstream consumers of a Mission, move to {{downgrade-by-omission}} instead.
  - Proposal: Dropped; #66 already refuses the submission.
  - Home: #66
- **#69** L1208 `intent-submission-evidence` MUST NOT: Record joins the next bullet; #69 is "MUST NOT be treated as evidence for the revised Intent".
  - Proposal: Merged into the #68 proposal.
  - Home: #68
- **#103** L1617 `approval-event` MUST: 'MUST itself establish' restates the step-2 lead plus #105; the testable negative suffices. See Part B COMMIT 1.
  - Proposal: When the Approver is a different principal (for example, an administrator approving on a user's behalf), the AS MUST NOT take the Subject from unauthenticated client input, and MUST authorize the Approver to approve for that Subject under local policy.
  - Home: #105
- **#113** L1667 `approval-event` MUST: Step 5 lead (under #101) already binds rendering the Authority Set; 1691-1693 is a third statement and becomes the because-clause.
  - Proposal: - The consent object is the **derived Authority Set**, what the agent may actually do, not the `goal` or Mission Intent: derivation is local policy, and nothing commits that the derived authority reflects the goal the Approver read. An approval surface that renders only the `goal`, `success_criteria`, or Mission Intent does not conform.
  - Home: #101
- **#116** L1684 `approval-event` MUST ledger `core.approval-event.authority-source-rerender` (reword): Three re-render rules (step 4 unkeyworded, this, #129); one change list. Ledger row (partial) re-quotes the merged list item.
  - Proposal: Delete the sentence; add 'the established authority source' to the change list of #129 (Part B COMMIT 2).
  - Home: #129
- **#232** L2749 `commitment-mechanisms` MUST NOT: Rejecting already excludes treating the prefix as sha-256; the ledger substring stays intact. Low priority.
  - Proposal: A verifier MUST reject a digest whose algorithm prefix it does not recognize, so an algorithm added later cannot be exploited as a downgrade.
  - Home: #231
- **#239** L2798 `lifecycle` MUST NOT: Restates #238's unrecognized-value clause.
  - Proposal: (delete; 'including one it does not recognize' in #238 already forbids failing open)
  - Home: #238
- **#299** L3237 `mission-claim` MUST NOT: Treating absence as an error already rules out substituting exp.
  - Proposal: (delete the MUST NOT; keep 'the token's `exp` bounds only that one credential' as the reason)
  - Home: #298
- **#309** L3319 `rs-enforcement` MUST NOT: Disclosure-only reduction is non-enforcement, already covered.
  - Proposal: (delete bullet; #307 requires enforcing each entry per its type and #308 fails closed; line 3392 gives the reason)
  - Home: #308
- **#311** L3319 `rs-enforcement` MUST NOT: A special case of #310.
  - Proposal: (delete 'in particular...'; a constraint bypass is access broader than the entry permits)
  - Home: #310
- **#315** L3339 `rs-enforcement` MUST NOT: Reinterpretation is already excluded by #312 and #313.
  - Proposal: (delete 'but MUST NOT reinterpret `client_id` to do so')
  - Home: #312
- **#342** L3645 `caller-authorization-and-minimization` MUST: The #339-#341 bullets already govern all Mission data, active or not; the deviation itself is stated once at #337.
  - Proposal: Replace the paragraph with: "These rules apply equally to the `mission` member of an `active: false` response ({{composite-active}})."
  - Home: #340
- **#343** L3645 `caller-authorization-and-minimization` MUST NOT: "MUST NOT reveal Mission detail to an unauthorized introspection caller" is the negation of #340.
  - Proposal: Merged into the #342 replacement sentence.
  - Home: #340
- **#427** L5207 `denial-disclosure` SHOULD: Complement of #426. Merge drops one SHOULD (keyword count changes by one).
  - Proposal: Delete 'and SHOULD omit the attribute otherwise'; the 'only' in #426 already requires omission.
  - Home: #329
- **#436** L5283 `client-id-misattribution` MUST: Same duty as #325; its only addition, logging and audit infrastructure, folds into the one home.
  - Proposal: In {{rs-enforcement}}, #325 becomes: A deployment MUST NOT route a delegated Mission-bound token to a Mission-unaware Resource Server, or to logging or audit infrastructure, that authorizes or logs the caller on `client_id` without processing the `act` chain.
  - Home: #325

### SEC-OBS (3)

- **#38** L950 `submission-via-par` MUST: Same party, error, and conditions as #37; one sentence covers both objects. Masquerade and closure rationale cut.
  - Proposal: **Closed top levels.** The AS MUST reject with `invalid_request` a Submission envelope containing a top-level member other than `intent` and `evidence`, or an `intent` containing a top-level member that neither this document nor a companion profile the AS implements defines ({{extensibility}}).
  - Home: #37
- **#78** L1327 `authorization-derivation` MUST: Umbrella #77 and test #78 become one MUST. Undecided: 'among' is exact match, yet resource subset allows prefix narrowing.
  - Proposal: In both modes, each derived entry that carries a `resource` member MUST have it among the Intent's `target_resources` values.
  - Home: #77
- **#247** L2859 `issuance-gating` MUST: The refusal and its error code form one obligation; also drops the implied 'revoked or expired' enumeration.
  - Proposal: The AS MUST refuse with `invalid_grant` to derive a token at the token endpoint, on refresh, or on Token Exchange ({{RFC8693}}) unless the referenced Mission is `active`.
  - Home: #246

### EXT-HOOK (2)

- **#120** L1719 `approval-event` MAY: Permission already lives in the `approval_basis.type` definition; #190/#191 constrain such profiles.
  - Proposal: Every Mission is rooted in an approved authorization basis (`approval_basis`, {{mission-record}}); the steps above define the `direct` basis, and {{mission-record}} states the rules for it and for a standing-consent basis a companion profile defines.
  - Home: #190
- **#194** L2322 `mission-record` MUST NOT: Two MUST NOTs on new `kind` values sit in separate paragraphs.
  - Proposal: In the `kind` definition: 'a companion profile MUST NOT define a `kind` value that names a record, an evidence store, or the requesting or dispatching party.'
  - Home: #181

### DEPLOYMENT (1)

- **#2** L443 `applicability` SHOULD: Same advice as #1 restated from the deployment side.
  - Proposal: Merged into the #1 proposal.
  - Home: #1

### LOCAL-IMPL (1)

- **#316** L3339 `rs-enforcement` MAY: Configuration permission becomes the condition of #317.
  - Proposal: - MUST, when configured to require the `mission` claim for a Mission-governed resource, reject a token that lacks it with `invalid_token` ({{downgrade-by-omission}}).
  - Home: #317

### INTEROP (1)

- **#426** L5207 `denial-disclosure` SHOULD: Conditions when the body's SHOULD emits a wire attribute; belongs with #329. Keep the disclosure analysis here.
  - Proposal: In {{rs-enforcement}}, after #329: It SHOULD include the attribute only in a response to a validly signed, audience-correct token whose holder its deployment accepts learning the distinction ({{denial-disclosure}}).
  - Home: #329

## DEMOTE (105)

### DEPLOYMENT (33)

- **#1** L442 `applicability` SHOULD: Mission scoping is operator practice; no party observes it. Merged text also carries #2. Security Considerations already cites it.
  - Proposal: A Mission is intended to cover one concrete task, not an agent's whole lifetime: narrow, per-task Missions, each separately approved and revocable, are preferred over a single broad standing Mission that accumulates authority across unrelated tasks.
- **#24** L812 `mission-intent` MAY: Permission to log is operator practice.
  - Proposal: Cut the sentence: #23 already bounds every use that affects authority, and logging needs no permission.
- **#73** L1291 `authorization-derivation` RECOMMENDED: Mode choice is deployment integration guidance; KEEP is defensible.
  - Proposal: - **Narrowing mode** (preferred where the client can author `authorization_details`): the client submitted an authority proposal ({{authority-proposal}}), and the Authority Set is the proposal narrowed to policy.
- **#75** L1303 `authorization-derivation` SHOULD ledger `core.derivation.configured-mapping-lookup` (none): error_description is 'Human-readable ... to assist the client developer' (RFC 6749 Section 5.2). Proposal keeps ledger span L1304-1307 verbatim.
  - Proposal: The mapping is a lookup, never synthesis; because no `authorization_details` object was submitted, the AS refuses an Intent that matches no configured mapping, or whose mapped candidates policy narrows to nothing, with `access_denied` ({{error-mapping}}); its `error_description` can say whether no mapping matched or policy narrowed the candidates to nothing.
- **#76** L1309 `authorization-derivation` MAY: Eligibility scoping is local policy.
  - Proposal: eligibility can be scoped per Subject and client
- **#85** L1401 `authorization-derivation` SHOULD: Publishing fixtures is operator practice; no wire element.
  - Proposal: A deployment whose partners reason about its derivations can publish a derivation policy identifier and test fixtures that pin Intent-to-Authority-Set outcomes; the policy itself does not travel.
- **#86** L1406 `authorization-derivation` SHOULD: Policy-authoring guidance for deployments.
  - Proposal: For an open-ended task whose concrete objects cannot be enumerated at approval (for example, ...), bounding the derived authority by `constraints` that hold as invariants over those objects (...) is preferable to an exhaustive `resource` enumeration.
- **#126** L1738 `approval-event` MUST: No wire form or metadata member; publication is operator practice. #135 keeps the observable enforcement MUST.
  - Proposal: A deployment publishes a statement declaring the minimum approval-authentication strength it enforces for Missions whose derived Authority Set carries high-risk authority (irreversible, external-commitment, or privileged-administration actions under the deployment's classification, or a consumption bound) and the deployment scope it applies to; this document requires no particular serialization.
- **#146** L2002 `grant-binding` MUST: Both outcomes already forbid derivation; which terminal state follows is operator policy, not wire interop.
  - Proposal: The deployment either revokes the Mission or lets it reach `expired` at `expires_at`, and applies one choice consistently; both outcomes are terminal ({{lifecycle}}), so reprocessing the same timeout changes nothing.
- **#147** L2002 `grant-binding` MUST NOT: Consistency across events is operator practice; merged into the demoted #146 sentence.
  - Proposal: The deployment either revokes the Mission or lets it reach `expired` at `expires_at`, and applies one choice consistently; both outcomes are terminal ({{lifecycle}}), so reprocessing the same timeout changes nothing.
- **#196** L2331 `mission-record` MAY: Configuration permission; becomes the condition of #198 (COMMIT 5).
  - Proposal: A deployment can declare a maximum standing-consent age (a recency ceiling), overall or per consequence class.
- **#197** L2331 `mission-record` MAY: Merged into the demoted #196 sentence.
  - Proposal: A deployment can declare a maximum standing-consent age (a recency ceiling), overall or per consequence class.
- **#258** L2932 `revocation` MUST NOT: Documenting a behavior is operator practice, not observable on the wire.
  - Proposal: A deployment that couples token revocation to Mission revocation documents that behavior.
- **#262** L2944 `revocation` OPTIONAL: Describes an informative companion; a BCP 14 keyword with no party.
  - Proposal: Mission Status ({{I-D.draft-mcguinness-oauth-mission-status}}) specifies another optional overlay: a status surface keyed by `mission_id` with signed responses.
- **#263** L2951 `revocation` SHOULD: Deployment choice of optional surfaces; nothing observable.
  - Proposal: A deployment whose consumers rely on Mission state beyond a token's lifetime offers introspection ({{introspection}}) or Mission Status, so they read current state rather than infer it from token validity.
- **#289** L3126 `mission-bound-tokens` MAY: Runtime-companion deployment guidance; could move with 3133-3139 to runtime-boundary.
  - Proposal: Where a runtime layer gates the high-consequence classes with an active freshness source, the point-of-use decision is the revocation cutoff, and lifetimes can be sized by action class ({{runtime-boundary}}).
- **#331** L3476 `rs-enforcement` MUST: Tautological deployment rule; the AS-side refusal (#291) is the enforceable part.
  - Proposal: Constrained authority that no safe projection carries is enforced only where a Resource Server, or a runtime layer, evaluates `authorization_details`.
- **#334** L3523 `remediation-grains` MAY: Deployment choice; the no-widening clause is the real invariant.
  - Proposal: The three grains compose: a deployment can offer any subset, and none widens authority beyond what {{authorization-derivation}} derives from the same proposal unremediated.
- **#377** L4201 `lasv-retrieval` MAY: A conformance claim, not wire behavior. Also repeated at 4144-4146 and in the conformance LASV bullet; keep one.
  - Proposal: A conforming implementation claims Tier 1 alone or Tier 1 with Tier 2 and states which ({{conformance}}): a "verified" result means different things under each.
- **#381** L4316 `adjacent-work` MAY: Misplaced keyword in design context; #256 already lets any authenticated surface satisfy the revocation MUST.
  - Proposal: ... no derivation gating; a deployment can surface Mission revocation through a grant-management-style API ({{revocation}}).
- **#399** L4698 `discovery` MAY: Deployment permission; this also absorbs the out-of-band restatement at 4747-4750.
  - Proposal: A deployment can instead arrange Mission-bound authorization, including its supported types and schemas, out of band.
- **#423** L5051 `downgrade-by-omission` MAY: Local registration choice; split from #424, whose MUST carries the observable duty and restates the condition.
  - Proposal: A deployment can register a client as Mission-governed.
- **#431** L5238 `delegation-and-chain-compromise` MUST: Conditioned on 'needs to limit breadth', so tautological configuration advice; nothing observable.
  - Proposal: `max_depth` bounds the length of a delegation chain, not its breadth: only `allowed_delegates` bounds fan-out to many distinct depth-1 delegates, and `derivation_limit` ({{derivation-issuance-policy}}) caps total derivations.
- **#432** L5238 `delegation-and-chain-compromise` MAY: Restates that derivation_limit exists ({{derivation-issuance-policy}}); grants nothing new.
  - Proposal: `max_depth` bounds the length of a delegation chain, not its breadth: only `allowed_delegates` bounds fan-out to many distinct depth-1 delegates, and `derivation_limit` ({{derivation-issuance-policy}}) caps total derivations.
- **#434** L5247 `delegation-and-chain-compromise` SHOULD: Derivation-policy authoring advice; no party observes it.
  - Proposal: Short derived-token lifetimes ({{issuance-gating}}), and marking delegable only the entries that need delegation, keep this exposure small.
- **#437** L5283 `client-id-misattribution` SHOULD: Operator practice; no party observes the review.
  - Proposal: An existing component that authorizes or logs solely from `client_id` needs review for this gap before it receives delegated Mission-bound tokens.
- **#441** L5315 `key-rotation` SHOULD: Operator key-management choice; verifiers see kid-indexed keys either way.
  - Proposal: Segmenting keys by artifact class under distinct `kid` values within the one `jwks_uri` lets high-value, low-volume signing (long-lived evidence and portable artifacts) sit under stricter custody than high-volume token signing; verification is `kid`-indexed, so this needs no wire change.
- **#443** L5386 `composition-and-the-effective-ceiling` SHOULD: Consent-surface advice about companion composition; the core neither defines nor observes the composed bound.
  - Proposal: A deployment can disclose the composed bound, not only the immediate Mission's, at the consent surface, and can impose a global cap out of band where a single approval's apparent bound must hold in practice.
- **#444** L5386 `composition-and-the-effective-ceiling` MAY: Out-of-band permission a deployment already has.
  - Proposal: A deployment can disclose the composed bound, not only the immediate Mission's, at the consent surface, and can impose a global cap out of band where a single approval's apparent bound must hold in practice.
- **#445** L5410 `the-containment-materialized-capability-residual` SHOULD: Lifetime policy for companion artifacts; guidance, better homed in the containment companion.
  - Proposal: Short cross-domain grant and offline attenuation root lifetimes keep that residual window to one the next lease or re-mint closes.
- **#447** L5533 `third-party-data-subjects` MUST: Legal policy the paragraph itself places outside this protocol (5531).
  - Proposal: Where the resource domain requires data-subject consent or another basis, that domain's own lane (the Resource Server, a gateway, a policy decision point, or an authorization server acting for the domain) evaluates it through that lane's mechanisms, such as claims gathering or a resource-domain consent artifact.
- **#448** L5533 `third-party-data-subjects` MUST: Fail-closed guard considered: the check is the domain's own undefined policy, so the MUST binds nothing new. Split from #447.
  - Proposal: That lane refuses access while required evidence is absent or invalid; the refusal is the resource's answer, not a Mission gap to route around.
- **B1** Lback `e2e-example` OPTIONAL: Line 5833: "Stage 3 notes where the OPTIONAL runtime layer adds a point-of-use check." Descriptive keyword in an appendix that adds no requirements (5825).
  - Proposal: Stage 3 notes where the optional runtime layer adds a point-of-use check.

### DUPLICATE (23)

- **#132** L1818 `approval-authentication` MAY: Descriptive 'MAY' grants nothing; step 2 already establishes that the Approver can differ from the Subject.
  - Proposal: who can be a different principal ({{approval-event}}, step 2)
  - Home: #104
- **#242** L2814 `derivation-issuance-policy` MAY: The client permission is the OPTIONAL member definition (#29).
  - Proposal: The limit is AS-established operational policy; a client can request a narrower ceiling through the Mission Intent's `requested_derivation_limit` member ({{mission-intent}}).
  - Home: #29
- **#260** L2940 `revocation` MAY: The introspection section owns optionality (#335, #338).
  - Proposal: Token introspection ({{introspection}}) is a state-observable overlay that lets a Resource Server see Mission state per request and cut off a revoked Mission before the token expires.
  - Home: #338
- **#261** L2940 `revocation` OPTIONAL: Capitalized OPTIONAL modifies a noun; the introspection section already says OPTIONAL.
  - Proposal: (folded into the #260 demotion)
  - Home: #335
- **#271** L2985 `mission-bound-tokens` REQUIRED: #336 and #349 already require it for opaque tokens.
  - Proposal: An opaque Mission-bound token is profiled only under the introspected consumption mode ({{introspected-consumption}}), where introspection is its claims carriage.
  - Home: #349
- **#295** L3214 `mission-claim` MAY: The introspection disclosure privilege is defined in #344.
  - Proposal: an authorized introspection caller can receive `authority_hash` and `approval_basis.type` ({{caller-authorization-and-minimization}})
  - Home: #344
- **#321** L3352 `rs-enforcement` MAY: LASV is OPTIONAL in its own section; line 3406 repeats the pointer.
  - Proposal: (A Resource Server that needs to check a carried entry against the complete approved set adopts {{local-approved-set-verification}}.)
  - Home: #370
- **#322** L3352 `rs-enforcement` MAY: Third mention of optional introspection.
  - Proposal: (A Resource Server can introspect ({{introspection}}) to observe Mission state per request.)
  - Home: #338
- **#370** L4113 `local-approved-set-verification` OPTIONAL: The heading and the conformance list already mark it optional.
  - Proposal: This optional profile lets a verifying party check a token's carried authority against the Mission's complete approved Authority Set ...
  - Home: #413
- **#376** L4187 `lasv-retrieval` MUST NOT: #375 already requires the held value to come from a source independent of the Tier 1 channel; a replacement is another acquisition.
  - Proposal: a **retention rule**: how long the retained value is held and when, if ever, it is replaced, always from a source that meets the independence rule above.
  - Home: #375
- **#382** L4408 `scope-and-future-work` OPTIONAL: Misplaced keyword in design context; descriptive reference to the capability.
  - Proposal: ... for the `act` chain shape the optional Delegation capability uses.
  - Home: #413
- **#383** L4424 `scope-and-future-work` OPTIONAL: Misplaced keyword in design context; each companion states its own optionality.
  - Proposal: Separate from this document, and not required to implement it, several capabilities are specified as optional companion profiles:
  - Home: #413
- **#385** L4485 `non-goals` OPTIONAL: Misplaced keyword in design context; #235 (lifecycle) already covers companion-registered states.
  - Proposal: A `suspended` state with `resume`/`complete` transitions is defined as an optional extension by the Mission Status and Lifecycle profile ...
  - Home: #235
- **#392** L4653 `discovery` MAY: Two keywords for one fact; RFC 8414 idiom puts OPTIONAL on the member only.
  - Proposal: This specification defines the following authorization server metadata parameter {{RFC8414}}:
  - Home: #393
- **#394** L4664 `discovery` OPTIONAL: Also inaccurate: 4894-4897 discovers them first through introspection_endpoint and grant_types_supported, not only out of band.
  - Proposal: It asserts Mission Issuer support only; it makes no claim about any Resource Server or about the optional capabilities, whose discovery {{conformance}} describes.
  - Home: #413
- **#407** L4759 `protected-resource-metadata` MAY: Two keywords for one fact; RFC 9728 idiom puts OPTIONAL on the member only.
  - Proposal: This specification defines the following protected resource metadata parameter {{RFC9728}}:
  - Home: #408
- **#409** L4775 `conformance` OPTIONAL: Informative starting-point note ("creates no new conformance class"); descriptive keyword.
  - Proposal: ... and implements none of the optional capabilities; ... (move the paragraph to {{implementation-map}}).
  - Home: #413
- **#410** L4785 `conformance` MAY: The derivation modes are defined in authorization-derivation (#73 onward); this adds no conformance content.
  - Proposal: A Mission Issuer can instead start from configured-mapping mode ({{authorization-derivation}}), which is equally conforming.
  - Home: #73
- **#412** L4828 `conformance` MAY: MAY and OPTIONAL state one fact twice.
  - Proposal: Beyond these roles, an implementation can additionally claim four OPTIONAL capabilities.
  - Home: #413
- **#417** L4894 `conformance` OPTIONAL: Descriptive reference; consider moving this paragraph into {{discovery}} and pointing #394 to it.
  - Proposal: The optional capabilities are discovered first through existing OAuth metadata ({{RFC8414}}):
  - Home: #413
- **#453** L5742 `iana-lifecycle-states` MAY: Keyword inside a registry Semantics cell; #234 is the rule.
  - Proposal: The only state from which tokens are derived.
  - Home: #234
- **B2** Lback `oauth-statement` OPTIONAL: Line 6432: "This appendix applies to the substrate edition published from the same repository revision as this document (the two editions revise and publish in lockstep, so the assessed revision is exact; for a copy obtained independently of the repository, the family's conformance manifest publishes the assessed substrate's content digest in its `source.specs` entry, identifying the exact assessed bytes), in this document's base single-domain mode with the OPTIONAL capabilities as the activation conditions below state, and to the kernel and capability vocabulary of the substrate document as of that revision." Names #413's term.
  - Proposal: The assessment applies to the substrate revision published with this document, in this document's base single-domain mode, with the optional capabilities active as the conditions below state.
  - Home: #413
- **B6** Lback `oauth-statement` OPTIONAL: Line 6521: "Declaring an OPTIONAL role never creates a claim beyond the eight already stated above." Same 'role' term collision.
  - Proposal: Declaring an optional capability never creates a claim beyond the eight already stated above.
  - Home: #413

### LOCAL-IMPL (15)

- **#22** L806 `mission-intent` MAY: Mapping configuration is local; configured-mapping bullet (L1301) already says the mapping keys on `purpose`.
  - Proposal: It is an opaque lookup key: a configured mapping can key on it ({{authorization-derivation}}), and the derived set stays bounded by the Intent and by policy like any derivation.
- **#49** L1018 `submission-via-par` MUST: Derivation policy is local (#84), so compliance is unobservable. Observable bounds are #59, #77, #88.
  - Proposal: The AS treats the submission as a proposal and derives and bounds authority by its own policy, whatever the client submitted ({{authorization-derivation}}).
- **#64** L1180 `intent-submission-evidence` MUST NOT: Interpretation is internal; observable bounds are #59, #77, and approval-event activation. Second keyword of the joined record.
  - Proposal: A verified entry is policy input, never authority: it is not copied into the Authority Set and does not stand in for the approval event ({{approval-event}}), the sole activation of authority.
- **#65** L1185 `intent-submission-evidence` MAY: Permission to use input in local policy.
  - Proposal: Verified evidence can serve as authenticated input to admission and derivation policy; AS policy decides whether the verified claims are acceptable for this request.
- **#80** L1332 `authorization-derivation` MAY: Local implementation choice; the least-portable remark is rationale.
  - Proposal: Generative derivation, with model assistance over the structured inputs above, is not one of this document's modes; a deployment that uses it as a local-policy extension stays bound by the Intent bounds, the prose boundary, and the recording rule.
- **#82** L1355 `authorization-derivation` MAY: Keyword used descriptively inside rationale; grants no permission.
  - Proposal: its structured members constrain what the AS can derive mechanically
- **#84** L1387 `authorization-derivation` MAY: Describes locality; RFC 9396 Section 7 already leaves the result 'at its discretion'. Paragraph moves to design-context (Part D).
  - Proposal: different authorization servers can derive different Authority Sets from the same Mission Intent, as they can grant different authority for the same {{RFC9396}} request or the same scope.
- **#143** L1974 `grant-binding` MUST NOT ledger `core.grant-binding.runtime-join-not-persistent-binding` (reword): 'Modeled as' is internal; only the AS establishes bindings (1883-1884), so state it as a definition. Row is todo.
  - Proposal: Such a join is not a Mission grant binding: it does not make the joined OAuth grant Mission-bound, and it rests on its own authenticated inputs and evidence, never on this section's binding.
- **#148** L2008 `grant-binding` MUST: Cleanup-job idempotency is implementation; terminal states already make reprocessing a no-op.
  - Proposal: The deployment either revokes the Mission or lets it reach `expired` at `expires_at`, and applies one choice consistently; both outcomes are terminal ({{lifecycle}}), so reprocessing the same timeout changes nothing.
- **#149** L2008 `grant-binding` MUST NOT: Terminality of revoked/expired (lifecycle, BASE.md 2774-2775, unkeyworded) already forbids the change; 'second transition' concerns a companion event stream.
  - Proposal: The deployment either revokes the Mission or lets it reach `expired` at `expires_at`, and applies one choice consistently; both outcomes are terminal ({{lifecycle}}), so reprocessing the same timeout changes nothing.
- **#241** L2807 `lifecycle` MAY: Internal persistence freedom; the permission follows from #240.
  - Proposal: Persisting the `expired` transition, and emitting any lifecycle event a state-distribution companion defines, can happen after the decision that observed the boundary.
- **#243** L2818 `derivation-issuance-policy` MAY: AS policy freedom; not an interop permission.
  - Proposal: Omitting `requested_derivation_limit` means no client-requested ceiling; the effective limit is then set by AS policy alone, which can impose none.
- **#314** L3339 `rs-enforcement` MAY: Local RS policy is always permitted.
  - Proposal: (A Resource Server can impose stronger actor-chain requirements, for example requiring and recording the chain.)
- **#378** L4207 `lasv-retrieval` MAY: Retention is local; the useful content is that no re-retrieval duty exists. TTL-friendly, keep the statement.
  - Proposal: Once retrieved and verified under the tier(s) claimed, they can be retained for as long as the verifying party relies on the Mission; this profile imposes no re-retrieval requirement of its own.
- **#440** L5315 `key-rotation` SHOULD: Key custody is internal practice; Security Considerations guidance is its home.
  - Proposal: Holding issuer signing keys in non-exportable, HSM- or KMS-grade custody with dual-controlled generation reduces that risk.

### EXT-HOOK (14)

- **#6** L619 `principal-model` MAY: Future-versions permission is not a requirement on any implementer. Timeless-prose concern with "future versions".
  - Proposal: This document uses only (`iss`, `sub`) pairs; the subject identifier formats of {{RFC9493}} are not used.
- **#141** L1970 `grant-binding` MAY: Permission for a mechanism the companion specifies in full; the core needs only the distinction.
  - Proposal: A grant binding is distinct from a decision-time runtime join, such as the Mission Join of {{I-D.draft-mcguinness-mission-authority-server}}, in which a Policy Decision Point joins an ordinary OAuth credential to a Mission per request.
- **#142** L1974 `grant-binding` MAY: Describes the companion mechanism; no core party relies on the permission.
  - Proposal: Such a join can associate the same credential with different Missions across separate requests where its subject and client are eligible for more than one.
- **#144** L1995 `grant-binding` MAY: A MAY on a future companion's scope is not a requirement; the paragraph is management-plane (Part C).
  - Proposal: A Mission Management companion ({{I-D.draft-mcguinness-oauth-mission-management}}) can standardize that index's wire surface.
- **#156** L2108 `mission-record` MAY: Future-revision permission is not a requirement; namespace-taxonomy #390 says the same. Temporal meta-commentary.
  - Proposal: (delete the sentence)
- **#178** L2257 `mission-record` MAY: Future breaking-change promotion note; temporal meta-commentary, not a requirement.
  - Proposal: (delete the sentence)
- **#179** L2257 `mission-record` REQUIRED: 'REQUIRED' is a noun mention inside the #178 sentence, not a member-presence keyword.
  - Proposal: (delete the sentence; same as #178)
- **#223** L2564 `worked-example` MUST: Editorial rule for companion drafts' examples, plus drift history; move to the family's editorial conventions.
  - Proposal: The test vectors ({{test-vectors}}) compute over this recorded `intent`, `proposed_authority`, and `authority_set` and the anchors above.
- **#292** L3185 `scope-projection` MAY: Grants a permission to an informative companion.
  - Proposal: A runtime profile's enforcement-scope declarations ({{I-D.draft-mcguinness-mission-runtime}}) can reference the same mapping; this rule does not depend on that profile.
- **#380** L4245 `lasv-proof-future` MAY: A permission to a future document binds no implementer; the section is future-work commentary.
  - Proposal: Rather than retrieving the complete set, a future profile could define a proof type under which ...
- **#384** L4446 `scope-and-future-work` OPTIONAL: Misplaced keyword in design context; describes unwritten future work.
  - Proposal: ... an optional derivation profile: a registry of standard task types mapped to authority templates ...
- **#387** L4519 `extensibility` MAY: A stability promise about future revisions of this document, not an implementer permission.
  - Proposal: The following remain stable across revisions of this profile:
- **#390** L4626 `namespace-taxonomy` MAY: Promise about a future revision; binds no implementer.
  - Proposal: A future revision can establish a registry for such a set; until one exists, the defining documents are the value space.
- **#454** L5765 `iana-intent-members` MAY: Restates extensibility 4547-4548 (no keyword there). 'reuse across the family' (5767) breaks core-stands-alone; cut it.
  - Proposal: A companion profile can instead use a collision-resistant name without registering it ({{extensibility}}).

### SECCONS (8)

- **#279** L3023 `mission-bound-tokens` MUST: Reports the cross-domain companion's keyword. The companion text is not in ../deps, so RESTATES cannot be quoted.
  - Proposal: (delete; token-theft at line 5221 already says the cross-domain companion requires it)
- **#328** L3418 `rs-enforcement` MUST NOT: Client reasoning, not a wire behavior; see the RFC 9068 Section 2.2.1 tension.
  - Proposal: Satisfying one does not satisfy the other.
- **#361** L3875 `delegation` MUST NOT: Local interpretation; no party can observe compliance. The declarative semantic carries it.
  - Proposal: The chain is attribution, never authority: an `act` entry names who acted, an asserted actor identity grants nothing, and the `authorization_details` subset relations ({{subset}}), not the chain, show that authority narrowed.
- **#418** L5009 `consent-binding` MUST: Rationale for the anchor split; integrity-anchors realizes it. No party acts (AS nominal). 'Verifiable from a token' conflicts with 4939-4941.
  - Proposal: `authority_hash` commits what a Resource Server enforces and what a cross-domain projection carries, so it is computed over the Authority Set alone ({{integrity-anchors}}) and can be checked without the Intent.
- **#420** L5034 `consent-binding` OPTIONAL: Describes a companion's status, not a requirement of this document.
  - Proposal: Mission Consent Evidence {{I-D.draft-mcguinness-oauth-mission-consent-evidence}} binds this on the wire, as a `consent_rendering_hash` over a structured consent-disclosure object; an AS that does not implement it can record equivalent evidence out of band.
- **#446** L5427 `i18n` MUST NOT: Unobservable caution; the refusal half already lives at #15. The fact suffices.
  - Proposal: `goal_lang` is a syntactic declaration: the AS checks only its well-formedness ({{mission-intent}}), not that the prose is in the declared language, so the tag is never a verified property of the text.
- **#449** L5543 `third-party-data-subjects` MUST NOT: Restates 5527-5531 as MUST NOT; meaning holds declaratively. Judgment: KEEP if the author wants an explicit consumer rule.
  - Proposal: Mission approval and Mission authority are not the data subject's consent: a Mission record can retain a verified consent reference or facts as `submission_evidence` ({{mission-record}}), and those facts are provenance and policy input only, which the resource domain validates independently under its current disclosure policy.
- **#451** L5568 `third-party-data-subjects` SHOULD: Data-minimization advice on prose content; unobservable. RFC 9396 Section 13 words this class lowercase. Judgment call.
  - Proposal: Referencing a third party through resource-scoped or pseudonymous identifiers, rather than identifying prose, minimizes this exposure; an opaque identifier is minimization, not anonymity, and personal-data obligations follow it.

### AUDIT (7)

- **#202** L2341 `mission-record` MUST: Audit reproducibility and retention; no party observes it on the wire.
  - Proposal: The ceilings and the skew allowance belong to the versioned policy that `policy_version` identifies, or to a separately versioned declaration retained with it, so an auditor can reproduce the eligibility decision.
- **#203** L2341 `mission-record` MUST NOT: Excludes mutable statements, an audit property only.
  - Proposal: (delete; implied by the demoted #202 sentence)
- **#220** L2443 `mission-record` MUST: Retention after termination serves audit, not a wire party. Keep the definition here; four sections reference it.
  - Proposal: A deployment retains a terminal (`revoked` or `expired`) Mission's record for its audit horizon.
- **#320** L3352 `rs-enforcement` SHOULD: Audit practice fails test 1; could go to privacy/record-access guidance.
  - Proposal: Logging the `mission` claim's `id` and the token `jti` with each served request joins access logs to Mission evidence.
- **#419** L5028 `consent-binding` SHOULD: Retention of internal audit evidence; no party observes it. Honest home is this guidance.
  - Proposal: A deployment whose Missions carry high-risk authority can record presentation-level audit evidence, for example a hash over the exact consent disclosure rendered to the Approver, retained so the disclosure shown can be reconstructed and audited after the fact.
- **#421** L5034 `consent-binding` MAY: Permission for out-of-band internal recording; unobservable. Overlaps #419.
  - Proposal: Mission Consent Evidence {{I-D.draft-mcguinness-oauth-mission-consent-evidence}} binds this on the wire, as a `consent_rendering_hash` over a structured consent-disclosure object; an AS that does not implement it can record equivalent evidence out of band.
- **#439** L5301 `key-rotation` SHOULD: Audit retention (judgment call). Companion extensions of 'this same rule' (5304-5307) still anchor on the token-lifetime floor.
  - Proposal: Verification for audit outlives validity; keeping a key resolvable for the audit horizon ({{mission-record}}) of every Mission whose tokens it signed lets an auditor verify those tokens later.

### INTEROP (3)

- **#234** L2771 `lifecycle` MAY: Definitional; #246 carries the rule. The IANA seed row repeats 'Tokens MAY be derived'.
  - Proposal: - `active`: the only state in which the AS derives tokens.
- **#244** L2824 `derivation-issuance-policy` MAY ledger `core.derivation-issuance-policy.effective-limit-is-clamped-minimum` (none): 'MAY only narrow' misuses MAY for a constraint the minimum rule already fixes; the ledger quotes the unchanged first half.
  - Proposal: ...where one was submitted, so a client's request narrows, and never widens, the AS's own policy ceiling.
- **B3** Lback `oauth-statement` MUST NOT: Line 6512: "Failure behavior: an unknown lifecycle state is non-active; an unresolvable reference, a failed anchor verification, and an unknown `authorization_details` type fail closed; where a row's activation condition does not hold, the property is not supplied and a consumer MUST NOT rely on it." Requirement in an informative appendix; no body home.
  - Proposal: where a row's activation condition does not hold, the property is not supplied, and a consumer cannot rely on it.

### RESTATES (2)

- **#257** L2931 `revocation` MAY: RFC 7009 already permits cascading to the grant; the Mission is the grant's governing record.
  - Proposal: A deployment's {{RFC7009}} revocation policy can extend to revoking the Mission when a Mission's refresh token is revoked.
  - Dependency: RFC7009 Section 2.1: Depending on the authorization server's revocation policy, the revocation of a particular token may cause the revocation of related tokens and the underlying authorization grant.
- **#276** L3012 `mission-bound-tokens` MAY: Base behavior.
  - Proposal: (and can further narrow with `scope`)
  - Dependency: RFC8707 Section 2.2: When requesting a token, the client can indicate the desired target service(s) where it intends to use that token by way of the "resource" parameter and can indicate the desired scope of the requested token using the "scope" parameter.

## MOVE-SECCONS (3)

### SECCONS (3)

- **#326** L3396 `rs-enforcement` MUST: Verifier interpretation of an optionally disclosed value; nothing on the wire changes.
  - Proposal: Move to {{authority-hash-is-not-a-mission-identifier}}: a disclosed `authority_hash` is an audit correlator, not an enforcement input, and not proof that carried entries are a subset of the approved set.
- **#327** L3396 `rs-enforcement` MUST NOT: Same move as #326.
  - Proposal: (moves with #326)
- **#401** L4703 `discovery` MUST NOT: No other party observes the client's choice. Keyword kept: this is the only home of the client duty (#422-#424 bind AS and deployment).
  - Proposal: Move to {{downgrade-by-omission}} as its client-side rule: "A client holding a Mission Intent MUST NOT submit the same authority as bare `scope` or `authorization_details` to an AS whose Mission support is neither advertised nor otherwise established; it surfaces the inability instead."

## RECAST (31)

### INTEROP (9)

- **#41** L983 `submission-via-par` MUST NOT: Passive "MUST NOT appear" binds the sender; covers the request_uri-redeem case that #32 and #40 do not.
  - Proposal: A client MUST NOT send `mission_intent` as a plaintext front-channel authorization-request parameter, whether or not a Request Object is also present.
- **#222** L2478 `mission-id` MUST NOT: Passive; names the issuer. Consumers of (issuer, id) rely on uniqueness.
  - Proposal: The AS MUST NOT reuse a Mission Identifier.
- **#228** L2673 `canonicalization` MUST: 'Fixed, reproducible' is internal; the observable outcome is the same order on every surface, so digests recompute.
  - Proposal: The AS MUST present each committed array in its recorded order wherever it emits the committed object; that order is part of the canonical form.
- **#237** L2793 `lifecycle` MUST: 'MUST apply this rule' is a keyword on a pointer; fold #237 and #238 into one sentence that states the rule.
  - Proposal: Wherever a Mission state is reported, including the Mission record and the introspection `mission` member, a consumer MUST treat only the exact value `active` as permitting derivation or continued reliance, and MUST treat every other value, including one it does not recognize, as non-active and non-deriving.
- **#330** L3460 `rs-enforcement` MUST NOT: Passive voice with no party; name the client.
  - Proposal: A client MUST NOT treat `constraint_unrecognized` as inviting retry, step-up, or fresh approval: none of those makes a Resource Server enforce a constraint it does not implement.
- **#400** L4700 `discovery` MUST NOT: The AS-metadata boolean idiom (RFC 9126 Section 5) carries the same client inference; out-of-band knowledge stays covered by #401's "not otherwise established".
  - Proposal: Delete the sentence and add to the member definition: "If omitted, the default value is `false`."
  - Dependency: RFC9126 Section 5: "Boolean parameter indicating whether the authorization server accepts authorization request data only via PAR. If omitted, the default value is "false"."
- **#422** L5047 `downgrade-by-omission` MUST NOT: Sole home; rs-enforcement 3350-3352 and authority-proposal 1109-1111 point here. Move to body, fix pointers. Refusal error code unstated: author's call.
  - Proposal: In {{authority-proposal}}: Where a deployment designates a resource Mission-governed, its AS MUST NOT issue a token for that resource outside a Mission, except under documented policy exceptions.
- **#438** L5294 `key-rotation` MUST: Narrows RFC 9068's SHOULD; keep. Retention floor (5299-5301) is the new content, stated only here: move to body. Keyword count unchanged.
  - Proposal: In {{mission-bound-tokens}}: An AS MUST publish its token verification keys (for example, at its {{RFC8414}} `jwks_uri`, as {{Section 4 of RFC9068}} recommends); rotation retires a key from signing, never from resolvability while tokens signed under it remain valid.
  - Dependency: RFC9068 Section 4: Authorization servers SHOULD use OAuth 2.0 Authorization Server Metadata [RFC8414] to advertise to resource servers their signing keys via "jwks_uri" and what "iss" claim value to expect via the "issuer" metadata value.
- **#442** L5344 `authority-hash-is-not-a-mission-identifier` MUST NOT: Interpretation rule for a record value, sole home here; parallels the entry-commitment MUST in integrity-anchors.
  - Proposal: In {{integrity-anchors}}, beside the entry-commitment rule: `authority_hash` commits an Authority Set, not a Mission, and two Missions that approve byte-identical authority share it; a consumer MUST NOT use it as a Mission Identifier or as a replay or idempotency key for a Mission.

### SEC-OBS (8)

- **#68** L1204 `intent-submission-evidence` MUST: Original party unstated ('MUST obtain new evidence'); the AS is the party that acts. Absorbs #69.
  - Proposal: When a shaping or approval revision changes `intent_hash`, the AS MUST NOT treat evidence bound to the predecessor Intent as evidence for the revised Intent, unless the evidence type's specification defines that transformation and how its lineage is verified.
- **#89** L1470 `subset` MUST NOT: Passive 'Authority ... MUST NOT widen' already says 'is refused'; recast is actor-first with the same condition.
  - Proposal: The AS MUST refuse a request that would widen authority after the approval event on any dimension (a new resource, action, actor, delegation path, longer duration, or constraint relaxation); broader authority requires a fresh approval event, either a new Mission or a successor ({{I-D.draft-mcguinness-oauth-mission-expansion}}).
- **#92** L1505 `other-types` MAY: 'MAY be issued only to' is a prohibition written as a permission; recast states it as one.
  - Proposal: The AS MUST NOT issue such an entry to any audience other than its original approved audience, or in any form other than exactly as approved.
- **#198** L2331 `mission-record` MUST ledger `core.approval-basis.standing-consent-recency` (reword): Passive MUST with no actor; names the issuer. No error code stated, none added. Row is todo.
  - Proposal: Where a declared ceiling applies, the activating issuer MUST refuse to activate an instance whose `approved_at` is older than the ceiling.
- **#199** L2341 `mission-record` MUST NOT: Value constraint plus passive 'is refused' become one actor-first refusal.
  - Proposal: The activating issuer MUST refuse an `approved_at` later than the evaluation instant by more than the deployment's declared, bounded clock-skew allowance.
- **#367** L3981 `self-exchange` MUST: States the observable refusal. RFC 8693 already mandates invalid_request for a policy-unacceptable subject_token. The error-mapping table has no row for it.
  - Proposal: The AS MUST refuse a no-actor exchange with `invalid_request` ({{RFC8693}}, Section 2.2.2) unless the authenticated client is the Mission's approved agent (the Mission Record's `client_id`, {{mission-record}}); a delegate narrows only through a delegated exchange that names it in the `act` chain.
- **#379** L4219 `lasv-retrieval` MUST ledger `core.local-approved-set-verification.retrieval-transport-and-disclosure-gate` (reword): Recast from internal gate strength to the observable refusal; the endpoint itself is deployment-provisioned. Row is todo.
  - Proposal: The retrieval surface MUST refuse a caller that does not hold the disclosure privilege ({{caller-authorization-and-minimization}}) for every audience the Mission has issued to, because a complete-set response discloses every audience's entries.
- **#424** L5051 `downgrade-by-omission` MUST: Observable refusal, sole home here. Move beside 1107-1111. No error code stated; do not add one editorially.
  - Proposal: In {{authority-proposal}}: The AS MUST reject an `authorization_details` request that carries no `mission_intent` from a client registered as Mission-governed, so the client cannot strip the Intent to obtain ungoverned tokens.

### LOCAL-IMPL (6)

- **#23** L810 `mission-intent` MUST NOT: 'Used to derive' is internal; recast states the testable effect. Member-specific exception keeps it out of #83.
  - Proposal: Other than as that lookup key, `purpose` MUST NOT affect the derived Authority Set or any issuance decision; once the Mission is approved it is inert.
- **#83** L1363 `authorization-derivation` MUST NOT: One home for the prose boundary (#14, #18, #20). 'Parse for machine semantics' is internal and conflicts with goal_lang rendering use.
  - Proposal: The AS MUST derive the same Authority Set, under the same policy, for two submissions that differ only in `goal`, `goal_lang`, `task_bounds`, or `success_criteria`, and MUST NOT gate issuance on those members; translating a user's words into structure is the shaper's job, before admission and outside the trust boundary ({{I-D.draft-mcguinness-mission-shaping}}).
- **#240** L2802 `lifecycle` MUST ledger `core.lifecycle.effective-active-before-reliance` (reword): Evaluation order is internal; the effective-active outcome is what callers observe. The ledger row (todo) quotes the evaluation-order wording.
  - Proposal: For every state-dependent decision this document defines, the AS MUST treat a Mission as `active` only when its stored state is `active` and the decision time is strictly before `expires_at`.
- **#248** L2862 `issuance-gating` MUST: Atomicity is internal; the observable outcome is that no issuance succeeds after the revocation takes effect.
  - Proposal: A derivation request the AS answers after it has acknowledged a revocation of the Mission MUST fail with `invalid_grant`.
- **#249** L2867 `issuance-gating` MUST ledger `core.lifecycle.derivation-cap-exhaustion` (reword): Keeping a count is internal state; the refusal is the observable part. The ledger row (partial) quotes 'maintain a per-Mission count'.
  - Proposal: When the Mission's `derivation_limit` ({{derivation-issuance-policy}}) is established, the AS MUST refuse with `invalid_grant` any derivation that would make the number of derivations under the Mission exceed it.
- **#252** L2879 `issuance-gating` MUST: The atomic check-and-increment is internal; the observable invariant is the bound under concurrency.
  - Proposal: - The AS MUST NOT let concurrent derivations collectively exceed the bound.

### EXT-HOOK (3)

- **#72** L1266 `submission-processing` MUST: Same party and condition; cuts 'not an annotation beside it' and the 'so ... proves' tail. Only a companion commits the surface.
  - Proposal: Where a deployment commits the rendered approval surface, that commitment MUST cover the normalized provenance facts, at least as a digest of their canonical `submission_evidence` representation ({{mission-record}}).
- **#235** L2786 `lifecycle` OPTIONAL: 'OPTIONAL companion profile' puts a BCP 14 keyword on a noun; drop it.
  - Proposal: A companion profile MAY register an additional state for a lifecycle it introduces (for example, a paused or superseded state); only `active` permits issuance.
- **#455** L5775 `iana-intent-members` MUST NOT: Keep the duty; replace the informal 'unverified say-so' with the checkable condition.
  - Proposal: A Designated Expert MUST NOT register a member as `stable` without confirming that its owning specification's promotion criteria are met, and MUST NOT treat registration itself as a promotion event for an experimental member.

### DEPLOYMENT (2)

- **#94** L1527 `other-types` MUST ledger `core.other-types.transformation-boundary-declared` (reword): Vacuous as written: #95 lets documentation that merely names the type satisfy it. Recast states the fail-closed outcome. See COMMIT 5.
  - Proposal: The AS MUST NOT narrow, delegate, or project to `scope` an entry of a type for which it has not declared the corresponding capability; on an undeclared capability the entry is carried as approved.
- **#95** L1535 `other-types` MUST: Keyword used as a noun ('satisfies this MUST'); carrier choice is deployment documentation.
  - Proposal: The AS declares the capabilities through these carriers, in order of preference: ...

### DUPLICATE (2)

- **B4** Lback `oauth-statement` OPTIONAL: Line 6514: "This document's three OPTIONAL implementation roles, which its Conformance section names OPTIONAL capabilities ({{conformance}}), are surfaces an implementation may or may not offer, each independent of the others." Conformance names four; LASV unmapped.
  - Proposal: This document's four optional capabilities ({{conformance}}) are surfaces an implementation may or may not offer, each independent of the others.
  - Home: #413
- **B5** Lback `oauth-statement` OPTIONAL: Line 6515, same sentence as B4 (second OPTIONAL). 'roles' collides with Conformance's three mandatory roles.
  - Proposal: This document's four optional capabilities ({{conformance}}) are surfaces an implementation may or may not offer, each independent of the others.
  - Home: #413

### RESTATES (1)

- **#283** L3091 `mission-bound-tokens` MUST: Quotes the base keyword; not a new rule.
  - Proposal: This extends {{Section 2.2.2 of RFC9700}}, which requires this for public clients, to every Mission-bound refresh token.
  - Dependency: RFC9700 Section 2.2.2: Refresh tokens for public clients MUST be sender-constrained or use refresh token rotation as described in Section 4.14.

## NARROW (9)

### RESTATES (4)

- **#55** L1067 `authority-proposal` MUST: Unsupported-type and definition failures, and 'never repaired by omitting' (abort), restate Section 5; keep only the schema refusal.
  - Proposal: ... the entry MUST also validate against that schema, and the AS MUST refuse an entry that fails it with `invalid_authorization_details`.
  - Dependency: RFC9396 Section 5: 'The AS MUST abort processing and respond with an error invalid_authorization_details to the client if any of the following are true of the objects in the authorization_details structure: contains an unknown authorization details type value, ...'
- **#281** L3032 `mission-bound-tokens` MUST: Only narrowing: removes Section 7's 'The AS MAY omit values'. Confirm that 'exactly' is meant to remove it.
  - Proposal: The AS returns the granted `authorization_details` in every token response, including refresh and Token Exchange responses, per {{Section 7 of RFC9396}}, and MUST NOT omit values from it, so the client learns exactly the (possibly narrowed) set assigned to the issued token.
  - Dependency: RFC9396 Section 7: In addition to the token response parameters as defined in [RFC6749], the AS MUST also return the authorization_details as granted by the resource owner and assigned to the respective access token.
- **#345** L3671 `composite-active` MUST: The signature, expiry, and revocation conjunct is the base's check list; only the Mission-state conjunct is new.
  - Proposal: In addition to the token checks of {{RFC7662}} Section 4, the AS MUST return `active: true` only when the Mission is `active`.
  - Dependency: RFC7662 Section 4: "However, since resource servers using token introspection rely on the authorization server to determine the state of a token, the authorization server MUST perform all applicable checks against a token's state."
- **#363** L3916 `delegated-instance-context` MUST ledger `core.instance-context.current-presenter-binding` (reword): Attestation validation belongs to the instance spec; presenting-instance selection, association, and key binding are this profile's Section 7.4 choices.
  - Proposal: When issuing context under this composition, the AS MUST use the presenting instance validated under {{I-D.draft-mcguinness-oauth-client-instance-id}}, Section 5, establish its trusted association with the separately authenticated delegate, and bind the output token to an instance-unique key whose possession it verified in that exchange.
  - Dependency: draft-mcguinness-oauth-client-instance-id-00 Section 5: "The Receiver MUST: 1. Validate the attestation and proof under the configured [ATTEST] method."

### INTEROP (4)

- **#161** L766 `mission-record` OPTIONAL: OPTIONAL label contradicts 'Present iff'; use the conditional form approved_at and authority_source.policy already use.
  - Proposal: REQUIRED when the client submitted an authority proposal ({{authority-proposal}}), absent otherwise. An array: the submitted `authorization_details` array, recorded exactly as submitted.
- **#165** L766 `mission-record` OPTIONAL: OPTIONAL label contradicts 'Present iff'.
  - Proposal: REQUIRED when `proposed_authority` is present, absent otherwise. A string. The integrity commitment over the recorded `proposed_authority` ({{integrity-anchors}}).
- **#166** L766 `mission-record` OPTIONAL: OPTIONAL label contradicts 'present iff'.
  - Proposal: REQUIRED when the approved submission carried evidence, absent otherwise. An array. The verified Intent Submission Evidence facts ({{intent-submission-evidence}}), one element per verified entry.
- **#219** L766 `mission-record` OPTIONAL: OPTIONAL label contradicts 'Present whenever ... absent only where it imposes none'.
  - Proposal: REQUIRED when an effective derivation ceiling is established for this Mission ({{derivation-issuance-policy}}), absent otherwise. A positive integer: the AS-established effective ceiling on derivations under this Mission, fixed at the approval event ({{derivation-issuance-policy}}).

### EXT-HOOK (1)

- **#388** L4564 `extensibility` MUST: Only keyword home for 'use the envelope'; "collision-resistant `typ`" duplicates #224. Could move to integrity-anchors next to #224.
  - Proposal: A profile that commits an evidence or disclosure object MUST commit it with this envelope and a `typ` that meets {{integrity-anchors}}, not by hashing the bare object.
