# Deployment configuration

Each file here is static deployment configuration, read once at boot by the
typed, validating loaders in `packages/demo-data/src/index.ts`. A file that
fails validation stops the boot with a `ConfigError` naming the file.

## `approval-floor.json`

The published approval-authentication floor (`@spec
mission#approval-authentication`, #826, D425): its deployment scope, the
floors, and the AS-owned classification of every action the AS can admit,
keyed by authority type, resource and action. The shipped floor,
`high-risk-authority`, applies to `irreversible_action`,
`external_commitment` and `privileged_administration`. It accepts only a
browser Approver whose achieved `acr` is `mfa`, authenticated at most 300
seconds before the decision. Payment execution and remittance are its
high-risk actions, matching the payments Operation Profile. The approval
interaction and an Expansion deferral approval both apply it. The demo's
approval console presents a login recorded once (simulated; the demo has no
Approver identity provider) and never at an approval, so it ages out of the
floor until the demo server's `POST /bff/approver/login` records a new one.

- **Owner.** The deployment's security owner owns the floors; each Resource
  Server's operator owns its actions' classes, which follow that server's
  operation definitions.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, duplicate member names, an unknown action class, an empty
  floor and a second classification for one type and resource. An admitted
  action the classification does not name refuses at the approval decision.
- **Updating.** Edit, review, and restart the AS. A change applies to the
  next approval decision; Missions already approved are unaffected.

## `delegation.json`

The clients a same-Mission delegation may designate (`@spec
mission#designation`, #869, D449). A designation names its client in `aud`,
so the binding forbids designating a client whose identifier any resource
server accepts as an audience for this AS's tokens, aliases included, and
refuses a client for which the AS cannot establish that separation. Listing
a client in `designable_clients` is this deployment's statement that no
resource server accepts its identifier as an audience; the AS also refuses a
listed client whose identifier is a configured resource audience, a
registered resource server's accepted audience or alias, or one of the
Mission's own resources. The shipped list names the invoice-extraction
sub-agent. Delegation itself is opt-in and off in both baselines.

- **Owner.** The deployment's security owner, with each resource server's
  operator for the audiences it accepts.
- **Integrity.** Repository review and the strict loader, which refuses
  unknown members, an empty identifier and a duplicate.
- **Updating.** Edit, review, and restart the AS. A change applies to the
  next designation.

## `scope-projection.json`

The trusted scope-projection mapping (`@spec mission#scope-projection`, step
2: authenticated out-of-band configuration). For each target audience it
records a `version`, the target's enforcement `mode` (`authorization_details`
or `scope_only`), the REQUIRED `mission_aware` classification used by the
delegated-routing rule (`@spec mission#rs-enforcement`), and, for a
`scope_only` target, the rights and independently enforced controls each
`scope` value stands for.

- **Owner.** The deployment operator responsible for each target Resource
  Server owns that audience's entry, because it describes how that server
  enforces.
- **Integrity.** The file is protected by repository review and by the strict
  loader, which refuses unknown members, duplicate member names, a missing or
  non-boolean `mission_aware`, and any control it has no comparison for. The
  AS never fetches it at runtime.
- **Updating.** Edit the entry, bump its `version`, land the change through
  review, and restart (or reload) the AS. Every issuance, refresh included,
  is evaluated against the mapping current at that issuance, so a bumped
  version does not by itself invalidate existing grants. An audience missing
  from the mapping fails closed.

The AS refuses a token whose audiences span both modes. That is an
implementation restriction (one `scope` claim is shared by every audience),
not a protocol rule.
