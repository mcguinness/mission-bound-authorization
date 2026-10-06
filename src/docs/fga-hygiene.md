# OpenFGA Hygiene Policy

Decisions D26/D39, #828. How the PDP uses OpenFGA correctly.

- **Two relation families.** The domain model (`DOMAIN_MODEL`,
  `services/pdp/src/fga.ts`) keeps them disjoint. Mission-context relations
  (`payer` and `reader` on invoices and vendors, `approved` on vendors) admit
  only `mission` subjects and are never stored. Stored entitlement relations
  (`authorized_payer` and `authorized_reader`) admit only `user` principals,
  granted on a vendor or an invoice; an invoice inherits its owning vendor's
  entitlements through the stored `invoice#vendor` tuple. No rewrite links
  the families, so no `mission:` tuple can satisfy an entitlement.
- **Contextual tuples (D26).** Mission authority is never written to the
  store. Per check, the PDP derives contextual tuples from the Mission
  Record's `authority_set` and sends them with the Mission-authority query
  (`Fga.checkWithContext`). The independent Resource-policy query
  (`Fga.checkStored`) takes no contextual tuples at all.
- **Bootstrap and attach.** `Fga.bootstrap` creates a store and writes the
  model: a development operation, used by tests and by the demo's
  `{ bootstrap: "development" }` store, which then seeds
  `config/seed/resource-policy.json` and the payments store's invoice
  ownership. `Fga.attach` is normal startup: it takes the configured store
  and model ids, reads the model back, verifies it is the domain model, and
  never creates or writes anything. The demo entrypoints attach when
  `OPENFGA_STORE_ID` and `OPENFGA_MODEL_ID` are set.
- **Administration.** `FgaDomainAdmin` grants and revokes stored
  entitlements and moves an invoice between vendors. It refuses any tuple
  that is not a `user` entitlement on a vendor or invoice, or an invoice's
  owning vendor, before anything reaches the store, so nothing a Mission
  approval or a token carries is written as durable policy.
- **Model pinning.** Every check and every administrative write sends an
  explicit `authorization_model_id`. `policy_view_id` is the content hash of
  (Mission Record version + model id), so a model change visibly changes
  every subsequent decision's correlator. A model id identifies the schema,
  not the tuple data: neither it nor a timestamp is a policy-data revision.
- **Consistency.** Every Resource-policy check requests `HIGHER_CONSISTENCY`
  with no cache: the declared Resource-policy freshness is "current as of
  the decision", separate from Mission-state freshness. A revocation written
  before a decision is what that decision reads. The read is not atomic with
  any later business effect; the runtime's commit and freshness obligations
  still apply. Mission-authority checks that follow a domain write in the
  same flow request `HIGHER_CONSISTENCY`; steady-state Mission checks use the
  default.
- **Write limits.** Administrative writes are batched under the 100-tuple
  write limit. No lifecycle-driven tuple writes exist.
- **Authn/transport.** Pre-shared key + TLS (self-signed dev CA) per the
  channel matrix; the PDP validates the dev CA explicitly rather than
  disabling verification.
- **Failure posture.** At startup, an unreadable store or model, or a model
  that is not the domain model, refuses attach (`FgaAttachError`); nothing
  falls back to creating a store or to an unpinned model. At decision time,
  an unreachable OpenFGA, a timeout or a malformed answer is no answer: the
  Resource policy throws `ResourcePolicyUnavailableError`, the PDP issues no
  decision (co-resident, the call throws; remote, 503), and the PEP records
  `pdp_unreachable` with no Decision Evidence and no effect. A reached
  refusal denies `resource_policy`.
- **Storage.** The development compose file and CI run OpenFGA's memory
  engine, so a stack restart preserves stored tuples only while the OpenFGA
  container keeps running.
