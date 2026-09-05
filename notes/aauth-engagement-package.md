# AAuth engagement package

Banked locally under [#445](https://github.com/mcguinness/mission-bound-authorization/issues/445).
Nothing in this document authorizes filing issues or posting comments in
the AAuth repository. The owner chooses the timing and outbound venue.
The six items travel as one engagement, retaining the stable A-IDs even
if the editor later chooses separate disposition threads.

This incorporates the September 4 sketch and review refinements. The
quoting baseline is `dickhardt/AAuth@fc5e972c58d42a4f899d43acba39995081b87712`.
Upstream proposals are separately identified, not represented as landed:

| Proposal | Reviewed head | Relevance |
| --- | --- | --- |
| [#128](https://github.com/dickhardt/AAuth/pull/128) | `74799af35e91e27be7ab592d4f16da44883cbf96` | Per-call and result-release gating |
| [#131](https://github.com/dickhardt/AAuth/pull/131) | `b3859fd4f3cd7350800fe6fccbbc86fabb3a9c95` | PS-side expiry bound and person-token presentation |
| [#132](https://github.com/dickhardt/AAuth/pull/132) | `56884a8ca7d626bec0a17cecb203ef2e90586e4a` | Mission control-plane caller wording |

Before dispatch, refresh the baseline and proposal states, refresh the
quoted text and its section references, and remove any ask already
resolved. On an authorized dispatch the items travel as discrete
per-item threads in the order A17, A16, A15, A18, A11, plus the A20
question, filed as issues on `dickhardt/AAuth`, whose CONTRIBUTING makes
GitHub Issues the primary venue for specification proposals. A11 goes
first as a comment on upstream PR #131, the open expiry-ceiling rewrite,
and becomes its own issue only if #131 merges without the sentence.
Nothing here executes that. The package does not wait for or travel with
a WG submission bundle. A5, A7, and A12 remain separate watches; A14
and A19 were handled by family PRs #767 and #763. No new upstream issue
is implied by this local document.

## Cover note

We are profiling AAuth as a carrier for Mission-bound authorization.
Five remaining properties affect that binding, with a separate question
about the owning agent's control-plane access. The requests below state
the interoperability property first; native encodings remain the
editor's choice. They do not reopen the single-use/result-retention
ruling in AAuth #92. A17 and A16 compose: an instance identity makes
single-use state addressable, and a distinguishable credential class
makes the verification path mandatory.

The family binding's
[transaction-authorization assessment](https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-aauth.html#transaction-authorization)
records both the supplied and missing carrier properties. Where a
property remains unavailable, that assessment remains an explicit
non-claim rather than a downstream invention of an AAuth wire member.

## A17: transaction instance, pending lifetime, and terminal result

**Problem.** A proposal's content hash identifies its bytes. Two
intentional, byte-identical calls can share that hash while being
different transactions. Conversely, retrying one admission must not
create parallel approvals or executions. Pending lifetime is a separate
bound from challenge or resulting token expiry.

**Upstream text (`fc5e972c`).** R3 Content Addressing: "The `r3_s256`
hash is the document's identity, not the URI." Per-Call Proposals, Flow
step 1: "The resource builds the proposal, persists it keyed by its
`r3_s256`". Flow step 4: "The resource SHOULD retain the result at least
until the auth token's `exp`."

**Request.** Define a transaction-instance handle distinct from
`r3_s256`, with a declared pending lifetime and admission idempotency
bound to the resource, challenge identity, agent, and presenter key.
Repeated submission of the same admission returns its existing workflow
or a deterministic refusal. A later intentional invocation gets a new
instance even when its proposal bytes are identical.

Completion and result lookup use that instance. It has at most one
terminal outcome; retries return the existing outcome and never execute
again. A16's class dispatch is what makes that rule enforceable: a
verifier that cannot recognize the per-call class never reaches the
instance's terminal-result check. An indeterminate execution is
reconciled rather than retried as a fresh execution under the same
instance. Expiry cannot silently re-pin an approval to newly generated
proposal bytes. If the resource token's `jti` is the challenge identity,
make that role and tuple explicit. The handle's encoding is the editor's
choice.

**Decline posture.** No native handle means the family continues to
record this carrier slot as missing. A16 cannot establish an at-most-one
result invariant without a corresponding transaction instance.

## A16: distinguish the per-call authorization class

**Problem.** An ordinary auth-token class can be dispatched as general
authorization if a verifier does not first consult the pending proposal
record. Endpoint context alone does not give every verifier an
interoperable class distinction.

**Upstream text (`fc5e972c`).** R3 Auth Token Extensions: the per-call
result is "a JWT with `typ: aa-auth+jwt`". Per-Call Proposals, Flow step
2: "the AS issues a per-call auth token that echoes the proposal's
`r3_uri`/`r3_s256` and lists the now-approved operation in
`r3_granted`". Resource Enforcement step 1: "Match in `r3_granted`:
serve the request."

**Request.** Give the per-call result a class distinguishable from
general authorization, with acceptance only for the approved invocation
or completion. A distinct JWT `typ` or a required discriminator with
equivalent dispatch could provide it. Single-use and retained-result
behavior are semantics of the class, and both the 202 and 401 paths
enforce them. The token is neither a person token nor general resource
authorization. The verification path also distinguishes execution from
release of an already-computed result under the release gating upstream
#128 proposes.

**Decline posture.** The family invents no AAuth class member. It keeps
transaction authorization unsupported if native class dispatch remains
missing. Encoding choice remains upstream's, not this package's.

## A15: definition supersession and bounded retention

**Problem.** A content hash establishes identity, not eligibility for new
admission or retention of the old bytes. Replacing a document at one URI
can strand a previously admitted workflow or leave a stale definition
eligible for a new one.

**Upstream text (`fc5e972c`).** R3 Content Addressing: "If a resource
updates the document at the same URI, existing auth tokens still
reference the previous hash (which the AS has cached). New resource
tokens reference the new hash." AS Processing step 3: "If the hashes do
not match, the AS MUST reject the resource token." Caching: "The AS is
not required to retain R3 documents beyond their immediate use in token
issuance."

**Proposed property.** A superseded definition remains resolvable for
workflows admitted under it and is closed to new admission. An admitted
workflow remains pinned to its original `r3_s256`. Define an authoritative
current/superseded signal, or make current resource-token issuance the
admission signal and specify the replacement race.

Retention has a declared admitted-workflow, completion/recovery, and
required audit horizon; this is not a request to retain every superseded
definition indefinitely. Admission closure and resolution availability
are separate lifecycle facts. No `version` member is being restored.

**Decline posture.** The family can retain the behavior as a profile
rule without adding a wire member, while disclosing what upstream does
not itself guarantee.

## A18: completion proof covers the exact presented artifact

**Problem.** One presenter key can hold several auth tokens. Possession
of that key alone does not identify which artifact's single-use state a
request is consuming.

**Upstream text (`fc5e972c`).** Protocol Covered Components: the
signature MUST cover "`signature-key`: The Signature-Key header value",
because "`signature-key` binds the signature to the presented key
material, preventing key substitution". R3 Flow step 3: under `202` "the
resource executes the held call when a valid per-call auth token arrives
at the pending URL"; under `401` the resource "MUST verify that the
agent's actual parameters match the approved proposal".

**Verification first.** Check the base profile's exact `Signature-Key`
coverage and token-bound key verification on both supported completion
paths. If that already covers the presented artifact bytes, request only
an explicit cross-reference and verification-order clarification in R3:
before consuming single-use state, verify the message signature covers
the field carrying this per-call token and verifies under that token's
bound key. Do not request an additional digest for an already-covered
path. A path lacking the property needs artifact-digest-equivalent
substitution resistance; no particular encoding is prescribed here.

Parameter matching does not substitute for artifact binding, including
under the release gating upstream #128 proposes, where there are no
original input parameters to compare.

**Decline posture.** Keep the verification-order rule in the family
profile where existing AAuth signature coverage supplies the property.

## A11: documented expiry-comparison clock posture

**Problem.** The expiry rule needs an explicit clock posture for the PS
performing the `expires_at` comparison, separately from message-signature
freshness policy.

**Upstream text (`fc5e972c`).** Mission Approval: "Every PS decision
path that acts on a mission MUST compare the current time to
`expires_at` and MUST treat a mission past it as terminated".
Verification step 3: "Servers and agents SHOULD synchronize their clocks
using NTP", with `signature_window` advertised in resource metadata.

**Proposed sentence.** A PS should synchronize its clock and document
the comparison precision and tolerated skew it uses for `expires_at`;
there is no implicit grace period beyond the declared rule. This is
deployment documentation, not a standardized skew value or permission
to extend the approved lifetime.

The family's
[expiry profile](https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-aauth-mission-expiry.html)
already carries this delta. At dispatch this text goes as a comment on
upstream PR #131, the open expiry-ceiling rewrite, where the editor's
attention already is, and becomes its own issue only if #131 merges
without the sentence. That still requires the owner's authorization;
this document sends nothing.

## A20: owning-agent control-plane caller, question only

**Upstream text (`fc5e972c`).** Person Server Metadata:
`mission_control_endpoint` is the "URL of the PS's mission control
plane", "where parties other than the owning agent read and manage
missions". Mission Management: "Reading a mission's status, terminating
one, and querying delegation are operations for parties other than the
owning agent, and belong at the `mission_control_endpoint`". The
`revoked` termination reason: "The person, the owning agent, or an
authorized administrator withdrew the mission".

The control plane is described for parties other than the owning agent,
while owning-agent withdrawal is a named termination cause. Is that
withdrawal expected at `mission_control_endpoint` when the PS admits the
agent, through a completion proposal, or deliberately out of band?
Likewise, may a companion define agent status access at that control
plane when the PS admits it?

The family keeps its Owning Agent caller class conditional and adds no
management action at `mission_endpoint`. Either answer can be reflected
without inventing a new upstream endpoint; this item proposes no change.

## Recording and local follow-up

The canonical disposition stays in #445. Only after an authorized
engagement is actually sent does the tracker record it: the batch date
in the preamble, one upstream URL per item id in a `Filed` column of the
open-asks table, `asked: #NNN` on A20's coordination-watch row, and each
item's later disposition beside its stable A-ID. The package itself
remains banked until then. A21 remains a local expiry-alignment
follow-up, contingent on the final merged/released semantics of upstream
#131; neither that proposed change nor retirement of the expiry
companion is presumed here.
