# Mission Receipt verification boundary

`verifyMissionReceipt` accepts unknown input and verifies an immutable
snapshot. It requires a receipt-key resolver created by
`createReceiptIssuerKeyResolver`; an arbitrary callback that knows a public
key does not establish receipt-issuer authorization.

The trusted assembly supplies an Enforcement Scope Statement and key sets
already obtained through its declared `signing_key_locations`. The evidence
extension's `receipt_issuers` entries name `{emitter, key_set}` pairs. Each
issuer must already be a PDP or executing PEP named by the statement. The
resolver enforces exact key/emitter/role bindings and retains a scope/key-status
snapshot; rebuild it from current trusted policy when key status or scope
changes. Data supplied by the receipt never chooses a key-set location or
adds an issuer. This is a resolver over trusted published-key inputs, not a
network JWKS discovery, key-retention or compromise-status refresh service.

Envelope verification precedes the kind/shape and evidence combination checks;
source-record verification precedes digest/identifier/emitter comparisons,
qualified Mission joins and copied-member checks. `policy`, `executor` and
`target` are compared to their verified sources, not trusted merely because the
receipt issuer signed them. Chaining remains unimplemented and refuses;
issuer assertions require a separate explicit-policy path and also refuse.

An execution receipt requires a terminal Execution Evidence record and a
permit Decision Evidence record. A Decision receipt cannot carry an execution
outcome. A completed/failed execution with differing authorized/effective
parameter digests remains valid evidence, returned with
`unauthorized_execution: true`; integrity verification is not proof that an
action was authorized or that it happened as reported.

The low-level `buildAndSignMissionReceipt` helper constructs a projection from
its supplied records and guards kind/final-outcome shape. It does not fetch or
verify those source records before signing: a caller remains responsible for
verified assembly. Consequently this slice does not claim the complete receipt
issuer bar. The richer source-content families, verified assembly, deployment
publication/retention, and cross-component reconciliation remain tracked by
#594 rather than inferred from signature verification tests.
