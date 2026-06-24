# Design note: revisable deferred approval and the Mission suite

Status: working note, not a draft. Helps decide whether and how to adopt a
"revisable deferred authorization" capability (an OAuth deferred-request-processing
profile) into the Mission-Bound Authorization suite, and how it relates to shaping,
expansion, consent evidence, and progressive authorization.

## The gap it fills

The suite specifies that an **approval event** happens and commits `intent_hash` /
`authority_hash`, but treats that event as atomic and synchronous. Two real things are
left unspecified:

1. **Async approval.** A human Approver takes minutes to days. The agent must wait. The
   suite has no defined "submit, then poll for the decision" handshake.
2. **Reviewer-driven narrowing.** Reviewers commonly approve a *narrowed subset*, not
   approve-all-or-decline. Today that forces abandon-and-resubmit, losing the deferred
   state and any prior work.

Revisable deferred approval supplies exactly this: a deferred approval state, a
`revision_required` outcome carrying what was refused, a narrowing-only revision the
client pushes (bound by a single-use handle), and continuation on the same deferred
code. It is the **approval-time interaction protocol** the suite is missing.

## Where it slots (narrowing / widening map)

| Direction | Mechanism | When / who | Draft |
|---|---|---|---|
| narrow before submission | shaping | client, pre-PAR | shaping |
| narrow at derivation | derivation + subset rule | AS, at approval | core |
| **negotiate the approval (async + narrow)** | **revisable deferred approval** | **AS/reviewer, during approval** | **(proposed)** |
| widen after approval | expansion | fresh approval | expansion |
| draw down within a ceiling | progressive authorization | policy, no per-step human | expansion |

Revisable is the **fifth, distinct** concept. The boundary lines that keep it from
overlapping the others:

- vs **shaping**: shaping narrows *before* submission, client-side and untrusted;
  revisable narrows *during* review, AS-side and authoritative. They compose: shaper
  proposes -> reviewer narrows and returns the refused dimensions -> orchestrator
  re-shapes a tighter Intent. Revisable is what makes shaping a closed loop instead of
  one-shot.
- vs **derivation/subset**: the AS already narrows Intent -> Authority Set. Revisable is
  not a second derivation; it is the *protocol* by which a reviewer's narrowing is
  surfaced to the client and a revised, still-narrower request is accepted without losing
  state. The subset rule is the comparison both use.
- vs **expansion**: opposite direction. Revisable is narrowing-only. It does **not** do
  expansion's job. It only gives expansion the same async handshake for *adjudicating an
  expansion request* (defer it for review; grant a narrowed version of the requested
  widening). "Negotiate the expansion approval," not "expand."
- vs **progressive authorization**: orthogonal. Progressive auth is pre-consented,
  no-human-per-step drawdown within a ceiling. Revisable is per-request human narrowing
  negotiation. Cross-reference so they don't blur.

## Recommended shape: abstract capability + substrate binding

Mirror the suite's runtime <-> authzen split so Mission does not hard-depend on one early
substrate draft:

- **Abstract (Mission side).** The approval event MAY be deferred. States: `pending` ->
  `revision_required` -> `pending` (re-review) -> `complete` / `denied` / `expired`. A
  revision MUST be narrowing-only under the core subset rule and MUST preserve the
  deferred approval state (the agent keeps its place, not a new request). The AS MAY
  return the refused dimensions so the agent can re-shape.
- **Binding (substrate side).** Bind the abstract states/handshake to a concrete
  deferred-request-processing substrate (the `revisable` profile on
  deferred-code-processing, or draft-gerber-oauth-deferred-token-response). The binding
  supplies the wire: deferred code / continuation polling, the `revision_required` error,
  the clarification handle, PAR (or a dedicated endpoint) for the narrowed revision.

This keeps Mission coupled to the *idea* of deferred processing, not to one draft, and
lets the binding follow whichever substrate gains WG traction.

## Integration points

- **consent-evidence**: a re-reviewed (narrowed) request MUST get a fresh
  `consent_rendering_hash`; prior consent does not transfer. The revisable proposal
  already names this hook, so reuse the consent-evidence draft rather than re-inventing.
- **the refused-dimensions signal** (`rejected_scope` / `rejected_authorization_details`)
  is the input an orchestrator uses to plan a narrower Mission Intent; this is the
  machine-readable bridge to shaping.
- **integrity anchors**: each accepted revision is a new derived Authority Set, so it gets
  its own `authority_hash`; the committed approval is over the *final* narrowed set, not
  the originating proposal.

## Open decisions

1. **Substrate choice**: gerber deferred-token-response vs the mcguinness deferred-code
   stack. Pick the one with the best adoption odds; the abstract/binding split makes this
   reversible.
2. **Separate companion vs fold**: recommend a single OPTIONAL companion ("Mission
   Approval Processing"), core untouched.
3. **Sequencing**: do this *after* the status+signals and runtime+authzen consolidation.
   Adding a 12th draft to an 11-draft suite two reviews said should be ~6 is the wrong
   order; consolidate to ~7 first, then add this.

## One-line verdict

Worth adopting: it is the missing approval-time protocol and it closes the shaping loop.
Add it as a tightly-scoped abstract+binding companion, substrate-agnostic, scoped against
the four existing narrow/widen concepts, after the consolidation.
