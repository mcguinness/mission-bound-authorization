# Decision constraint evidence

The PDP records a private, per-evaluation set of the loaded authority entry
types and constraint keys it actually inspects. It passes that set to its own
signing emitter, never accepting a list from the request or reconstructing one
by scanning the policy after reaching a decision.

The set includes entry types checked during delegate narrowing and authority
matching, plus the `vendors`, `max_amount`, and `requires_action_approval` keys
when their respective gates are reached. It deduplicates identifiers, as the
wire member names types/keys rather than individual entry instances. An early
lifecycle or credential refusal has no invented authority contributions. A
constraint denial does not claim that later gates or later entries ran.

A constraint the PDP evaluated and whose parameters the request violates
returns `parameter_violation` on both the response and the signed evidence; the
deployment carries no `constraint_exceeded` code. A constraint that excludes the
target instead withholds the contextual relationship entirely, so it keeps the
boundary reason `out_of_authority`, which an independent FGA resource-policy
denial also carries. Failing constraint keys are carried separately in
`contributing_constraints`, so the reason enum and the open constraint-key space
never mix in one field.

Receipt verification accepts an unfamiliar nonempty denial-reason value as a
deny without assigning new semantics or allowing it to authorize execution.
Evidence remains retrospective; this trace introduces no authority or permit
condition. The producer and verifier still have the broader partial coverage
listed in the conformance manifest; these two assertions do not claim full
Runtime Evidence conformance.
