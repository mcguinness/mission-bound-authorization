# Core-standalone example fixture

`core-standalone.json` is one Mission that needs no Mission companion: issuer `https://as.example.com`, ID `msn_` plus the first 32 base64url characters of SHA-256 over `core-standalone/mission`. Its only authority is the `payment_initiation` example of RFC 9396. It is prepared for P4 of the OAuth binding independence plan (#2009, `notes/audits/2026-10-31-core-independence/PLAN.md`), which replaces the binding's baseline examples with this type.

`scripts/generate-core-standalone-fixture.mjs` builds the file and the anchors table below; `--check` fails when either is not what the script builds. Before building, the script reads the binding's "Integrity Anchor Test Vectors" appendix and reproduces every vector in it (displayed value, canonical bytes and digest), so the construction that computes these anchors is the one the binding specifies.

This fixture is separate from `vectors/baseline-q3` and the Resource Access fixtures, which stay unchanged.

## The example type

`payment_initiation` is an illustrative API type, taken from RFC 9396 rather than minted. It is not a Mission type, and it is not a complete standardized payment API: RFC 9396 leaves a type's interpretation to the AS and the API. Nothing here makes it a protocol requirement.

RFC 9396's payment fields define no subset relation. The Mission therefore holds one approved entry, the client's proposed entry unchanged, with no narrowing.

The entry is RFC 9396, Section 2, Figure 2, quoted here without the page margin. The check requires this quote to be the fixture's proposal.

<!-- rfc9396-figure-2:begin -->
```json
[
   {
      "type": "payment_initiation",
      "actions": [
         "initiate",
         "status",
         "cancel"
      ],
      "locations": [
         "https://example.com/payments"
      ],
      "instructedAmount": {
         "currency": "EUR",
         "amount": "123.50"
      },
      "creditorName": "Merchant A",
      "creditorAccount": {
         "iban": "DE02100100109307118603"
      },
      "remittanceInformationUnstructured": "Ref Number Merchant"
   }
]
```
<!-- rfc9396-figure-2:end -->

## Local assumptions

The example assumes these semantics for the type. They belong to the example, not to the binding.

- **Accepted shape.** `type` is `payment_initiation`; `actions` is a non-empty subset of `initiate`, `status` and `cancel`; `locations` lists absolute URIs; `instructedAmount` is `currency` (an ISO 4217 code) and `amount` (a decimal string); `creditorName`, `creditorAccount.iban` and `remittanceInformationUnstructured` are strings. The AS refuses a malformed entry, an unknown member, or an unsupported type with `invalid_authorization_details`.
- **Resource and audience.** The entry carries `locations`, not `resource`, so the binding's `target_resources` membership rule, which binds a `resource` member, does not apply to it. By local assumption every location is among the Intent's `target_resources`, and the token's audience is the payments resource server, `https://example.com/payments`.
- **Requested payment.** The entry authorizes initiating the one described credit transfer (EUR 123.50 to Merchant A's account with that remittance text), and checking or cancelling it.
- **Resource server enforcement.** The payments resource server permits an initiation only when its amount, currency, creditor and remittance text equal the entry's, and `status` or `cancel` only for that transfer.

## Contents

| Member | Meaning |
|---|---|
| `reproduces_binding_vectors` | The binding's appendix vectors the generator reproduced, by anchor name |
| `example_type` | The type, its source, its illustrative status, and the absence of narrowing |
| `mission` | The full reference (`issuer`, `id`) and the label its `id` is derived from |
| `cast` | Client, Subject and direct Approver (the same person), identity provider, and the payments resource |
| `submission` | What the client pushes: the Submission envelope (`mission_intent`, no `evidence`) and the `authorization_details` proposal |
| `anchors` | The expected `intent_hash`, `proposal_hash` and `authority_hash` |
| `commitments` | Per anchor: `typ`, `iss`, the record member committed, the envelope, its exact JCS bytes, and the digest |
| `record` | The Mission Record as the AS retains it |
| `member_presence` | Which record members are present, which are implied (with their implied values), and which are absent and why |

## Anchors

Each anchor is the binding's integrity anchor: JCS (RFC 8785) over `{"typ", "iss", "value"}`, SHA-256, then `sha-256:` and the unpadded base64url digest, with `iss` the record's `issuer`.

<!-- anchors:begin -->
| Anchor | `typ` | Committed value | Expected digest |
|---|---|---|---|
| `intent_hash` | `mission-intent` | `record.intent` | `sha-256:Vo-xrC5HtrAUS9ZAPSWhhpLd7fr43eQsbH6AMiooa5Y` |
| `proposal_hash` | `mission-proposed-authority` | `record.proposed_authority` | `sha-256:jd1SqDhGAl1PQn3rnJFPHyaUG_Wfy8KusEBKh8s1lNg` |
| `authority_hash` | `mission-authority-set` | `record.authority_set` | `sha-256:G5P5feAebBxFgyxOHNoSZwB4DfCqufYXQXEZFTxvgQY` |
<!-- anchors:end -->

The client submits a proposal, as RFC 9396's request parameter does, so `proposed_authority` is recorded and `proposal_hash` is defined. The proposal and the Authority Set are the same array, yet their anchors differ: `typ` separates them.

## Record members

The record carries every required member, `proposed_authority` (a proposal was submitted), and all three anchors, each equal to its implied value. The `direct` basis omits `activation`, `activation_actor` and `root_commitment`, whose implied values `member_presence.implied` lists; `adjudication` is absent. `termination`, `submission_evidence` and `policy_version` are absent for the reasons `member_presence.absent` gives.

## Tokens

The fixture holds no access token. The binding's token examples use ES256, whose signatures are randomized, so a signed token would not regenerate byte for byte under `--check`. Any compact token the binding displays for this example must be labelled illustrative and must not be presented as verifiable; a verifiable token needs test-only keys and a signature check.

## Authorization server support

The fixture and its checks do not show that an authorization server accepts `payment_initiation`. The reference AS advertises and accepts only `mission_resource_access`; an end-to-end AS witness for this example needs explicit support for the illustrated type.
