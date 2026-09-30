# Deployment configuration

Each file here is static deployment configuration, read once at boot by the
typed, validating loaders in `packages/demo-data/src/index.ts`. A file that
fails validation stops the boot with a `ConfigError` naming the file.

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
