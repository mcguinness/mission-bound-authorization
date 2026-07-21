# OpenFGA Hygiene Policy

Decisions D26/D39. How the PDP uses OpenFGA correctly.

- **Model pinning.** Every check sends an explicit `authorization_model_id`.
  The active model id is recorded at seed time; `policy_view_id` is the
  content hash of (Mission Record version + model id), so a model change
  visibly changes every subsequent decision's correlator.
- **Contextual tuples (D26).** Mission authority is never written to the
  store. Per check, the PDP derives contextual tuples from the Mission
  Record's `authority_set` and sends them with the query. Stored tuples
  hold only the durable domain substrate (invoice ownership, vendor
  status, roles).
- **Consistency.** Checks that follow a domain-substrate write in the same
  flow (e.g., vendor approval flipping during an expansion) request
  `HIGHER_CONSISTENCY`. Steady-state checks use the default.
- **Write limits.** The 100-tuple-per-write limit applies to seed loading:
  the seeder batches domain tuples accordingly. No lifecycle-driven tuple
  writes exist.
- **Authn/transport.** Pre-shared key + TLS (self-signed dev CA) per the
  channel matrix; the PDP validates the dev CA explicitly rather than
  disabling verification.
- **Failure posture.** OpenFGA unreachable or the pinned model id missing:
  fail closed (deny with a `policy_unavailable`-class reason), never fall
  back to an unpinned model.
