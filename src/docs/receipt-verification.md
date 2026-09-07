# Mission Receipt verification boundary

`verifyMissionReceipt` accepts unknown input and verifies an immutable
snapshot. The trusted receipt-issuer scope is an explicit parameter, a
snapshot created by `createReceiptIssuerScope`; an arbitrary callback that
knows a public key does not establish receipt-issuer authorization and does
not type-check as a scope.

The trusted assembly supplies an Enforcement Scope Statement and key sets
already obtained through its declared `signing_key_locations`. The evidence
extension's `receipt_issuers` entries name `{emitter, key_set}` pairs. Each
issuer must already be a PDP or executing PEP named by the statement. The
scope snapshot holds the designated issuers and, for each, only the keys
published in a key set the statement binds to that issuer. It is frozen
through every level verification reads, including the scope statement and
each key's status: mutating the caller's statement, the published key sets,
or the returned scope cannot broaden a scope that already exists. Rebuild it
from current trusted policy when key status or scope changes. Data supplied
by the receipt never chooses a key-set location or adds an issuer. This is a
snapshot over trusted published-key inputs, not a network JWKS discovery,
key-retention or compromise-status refresh service.

Step 1 runs in its own order: structural validation of the envelope (a
well-formed compact JWS carrying `typ`, a `kid` and the claimed issuer), then
the issuer-designation check against the scope, then the key lookup bound to
that issuer inside that scope, then byte equality and signature. An issuer
the scope does not designate refuses as `issuer_not_authorized`, an issuer
removed from `receipt_issuers` included. A key bound to another issuer, or
published in a key set the scope does not bind, resolves to nothing even when
the claimed issuer is designated: an authorized issuer plus an arbitrary key
never suffices. Envelope verification precedes the kind/shape and evidence
combination checks; source-record verification precedes digest/identifier/emitter
comparisons, qualified Mission joins and copied-member checks. `policy`, `executor` and
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
