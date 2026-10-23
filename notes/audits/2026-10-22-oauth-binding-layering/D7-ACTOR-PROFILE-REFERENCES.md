# D-7: The Actor Profile's Normative References

Decision D-7 of the layering plan (`PLAN.md`, Section 8): for each
normative reference of `draft-mcguinness-oauth-actor-profile`,
establish why it is normative, at the revision cited. Analysis
2026-10-23. Nothing in the Actor Profile is edited; any change is the
owner's, in that draft's own repository.

## Source and method

- **Text analyzed:** the local
  `/Users/karl/src/draft-mcguinness-oauth-actor-profile/draft-mcguinness-oauth-actor-profile.md`.
  - It matches the published `-01`: the same normative and informative
    blocks (apart from the RFC 2119 and RFC 8174 boilerplate entries)
    and the same Document History.
  - A word-level diff of the rendered text found only the date, the TOC
    page numbers and the docname.
  - Revisions `-01` cites: transaction-tokens `-11`, wimse-workload-creds
    `-02`, wimse-wpt `-02`, entity-profiles `-01`,
    identity-assertion-authz-grant `-04`.
- **Test applied:** the IESG statement on normative and informative
  references, including its Note 1: "Even references that are relevant
  only for optional features must be classified as normative if they
  meet the above conditions."
  - A citation is REQUIRED when a BCP 14 requirement or a definition the
    profile relies on cannot be implemented without the cited document,
    including on an optional path the profile itself specifies.
  - It is INFORMATIVE-USE when it is an example ("such as"), a
    comparison, a pointer to related work, or a parallel citation for a
    rule stated fully in the profile.
- **Who did what:** a subagent swept every citation. This session
  checked the pivotal WPT and identity-chaining sentences against the
  local text.

## Verdicts

| Reference | Citations that force normative (examples) | Verdict |
|---|---|---|
| draft-ietf-oauth-transaction-tokens | Terms defined there (Section 2); validation "per [TT]" (6.3.1.3); claim semantics "defined in [TT]" (7.1, 7.3); "MUST validate and process that token according to [TT]" (8.3); token-type URI "defined and registered by [TT]" (15.7) | **Correctly normative** |
| draft-mora-oauth-entity-profiles | `sub_profile` "as defined in Section 4.2", values "MUST be registered" (3.4); "MUST conform to Section 4.2" (4.1, 5.1); metadata `entity_profiles_supported.actor` (10) | **Correctly normative** |
| draft-ietf-oauth-identity-assertion-authz-grant (ID-JAG) | The `aud` MUST "for an ID-JAG, to the Resource Authorization Server's issuer identifier" (6.6.1); `authorization_grant_profiles_supported`, "defined by [ID-JAG]", with a SHOULD (10, 10.1); the `id-jag` token-type value (10.1) | **Mixed: keep normative.** Several citations are examples or parallels, but the metadata parameter, its SHOULD and the `aud` MUST need it. The `-01` history records the promotion as deliberate. |
| draft-ietf-wimse-workload-creds | "For WIMSE ... credentials ([WC]), validation follows the rules defined in that specification", including the issuer identified through the trust anchors of `sub` when `iss` is absent (6.4.2.2); rule 2's `act.iss` derivation depends on it | **Mixed: keep normative.** Rewording it to "per its type specification" would leave the `act.iss` derivation for a WIT without `iss` without a defined source. |
| draft-ietf-wimse-wpt | 6.4.2.2: "MUST validate any proof the workload-credential profile requires, such as a WIMSE Workload Proof Token (WPT ...) per its specification" (an example), then "the AS MUST also validate proof for the new presenter binding: the WPT, or a DPoP proof" | **Borderline: keep normative unless the owner accepts the risk.** The profile states no WPT-specific rule, and DPoP is a fully specified alternative. But the rebind MUST names "the WPT" as an accepted proof on a path the profile specifies, which Note 1 treats as normative. The rewording that would avoid it ("a proof the workload-credential profile defines") broadens the accepted proofs, which is a change in meaning. |
| OpenID Connect Core | The ID Token row of the subject-token validation table, under "MUST validate the input per the specification in its table row" (6.2); an ID Token "establishes subject identity only" (6.3.2.1) | **Correctly normative.** It is not an Internet-Draft, so it does not affect the closure. |

**An informative reference that should be normative.**
`draft-ietf-oauth-identity-chaining` is informative, but Section 10.4
says: "When this profile is combined with Identity Chaining ([IC]),
clients SHOULD additionally consult
`identity_chaining_requested_token_types_supported`". That is a
BCP 14 SHOULD on a parameter only Identity Chaining defines.
- Recommended: promote identity-chaining to normative.
- It costs nothing in the closure: it is already reachable through
  Transaction Tokens and ID-JAG.
- Lowercasing the "SHOULD" would also resolve the inconsistency, but it
  changes a requirement.

The other informative references (RFC 9700, RFC 8792,
`draft-parecki-oauth-jwt-dpop-grant`, OpenID Federation) are correctly
informative.

## Closure effect

The Actor Profile's normative Internet-Draft closure (latest-revision
traversal; `tls-rfc8446bis` excluded as now RFC 9846) is **11
drafts**:
- **5 direct:** Transaction Tokens, workload-creds, WPT, Entity
  Profiles, ID-JAG.
- **6 transitive:**
  - identity-chaining, through Transaction Tokens and ID-JAG;
  - wimse-identifier, through workload-creds and wimse-arch;
  - wimse-mutual-tls, through workload-creds;
  - wimse-arch, through WPT only;
  - rfc7523bis and `parecki-oauth-jwt-dpop-grant`, through ID-JAG.

| Change | Closure | Effect on the binding's latest-revision inventory (PLAN.md Appendix E, 16) |
|---|---|---|
| None (recommended) | 11 | 16 |
| Promote identity-chaining | 11 (already reached) | 16 |
| Also demote WPT (borderline; Note 1 risk) | 9 (WPT and wimse-arch leave; wimse-identifier stays through workload-creds) | 14 |
| Demote workload-creds as well (not recommended: changes a requirement) | 6 | 11 |

`draft-parecki-oauth-jwt-dpop-grant`, an expired individual draft,
stays in the closure through ID-JAG's normative reference, not through
the Actor Profile's. Its removal is a matter for ID-JAG.

## Conclusion

The Actor Profile's publication coupling is structural. Transaction
Tokens, Entity Profiles, ID-JAG and workload-creds are needed by
requirements the profile states. The OAuth binding in turn needs the
Actor Profile for the delegate model's `act` members, which Resource
Access's `sub_profile` matcher relies on. D-7 therefore yields no
material reduction.

Recommendations for the owner, in the Actor Profile draft:
1. Promote identity-chaining to normative (zero closure cost).
2. Leave WPT normative, unless the owner accepts that an IESG reviewer
   may read the rebind MUST under Note 1.

## Not verified

- The inventory against the revisions each citer names, beyond the
  Actor Profile's own (Transaction Tokens `-11`, Entity Profiles `-01`,
  ID-JAG `-04`, identity-chaining `-17`).
- The Transaction Tokens (Sections 9.2, 11.5, 13.6, 13.14, 13.15) and
  Entity Profiles (Sections 4.2, 14.1) section numbers the profile
  cites. The ID-JAG `-04` and workload-creds `-02` sections were
  confirmed.
- Whether the uncited "trust domain" in 6.4 rule 2 is meant to be
  WIMSE-specific.
