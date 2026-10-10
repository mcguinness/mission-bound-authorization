# Design note: Personal Agent Protocol evaluation and an adoption-first Mission sketch

Status: working note, not an Internet-Draft and not normative. Nothing here
is adopted by PAP or by the Mission family.

Reviewed against Personal Agent Protocol ("Poppy") Draft 0.1, updated
2026-10-09: the [specification](https://personalagentprotocol.org/docs/spec),
the [Operations extension](https://personalagentprotocol.org/docs/extensions/operations)
version 1, the [extension rules](https://personalagentprotocol.org/docs/extensions),
the [guides](https://personalagentprotocol.org/docs/guides), and
[open topics](https://personalagentprotocol.org/docs/open-topics). Mission
drafts read at `main` ea1a1490. PAP section numbers are cited as "Spec 4.8"
and "Ops 5.1".

## Recommendation

- PAP is a sound base. Its Operations extension already solves the hard
  execution problems: exact terms per immutable revision, one record across
  channels, one confirm point, and at-most-once execution.
- PAP's gap is authority, not execution. Credentials are account-wide, and a
  standing permission is a string the Company has to take on trust.
- Mission fits in one sentence: **a Mission is a standing permission the User
  approves on the Company's own sign-in page, which the Company checks at
  confirm.**
- The first profile adds no endpoint of its own, no confirm request member,
  and no error code. Session Tokens stay opaque to the agent. The cost is
  concentrated in the Company's AS: it gains a PAR endpoint, which core
  requires; it becomes a core Mission Issuer; and it issues JWT access
  tokens or offers introspection. The operations endpoint checks the carried
  authority at read, confirm, and cancel. The Personal Agent pushes its
  Direct Sign-In request through PAR.
- The earlier Draft 00 should be narrowed to this profile. Section 5 lists
  what moves out and what each cut loses.

## 1. PAP evaluation

### 1.1 What PAP gets right

- **Standards reuse with a small surface.** Client ID Metadata Documents with
  `private_key_jwt` (Spec 4.1), DPoP everywhere except MCP (Spec 4.3), PKCE
  with RFC 9207 `iss` checking (Spec 4.5), RFC 8707 narrowing, RFC 7009
  sign-out, and RFC 8628 device sign-in.
- **Privacy by construction.** Pairwise User IDs that are not derived from
  personal data (Spec 4.2), and signed-out Sessions as the default.
- **Progressive adoption.** Both sides ignore unknown extensions and fields
  (Spec 3.3), so either side can work with the other under the
  specification alone.
- **Operations get the execution semantics right.** Only the latest immutable
  revision can be confirmed (Ops 3.1). Every channel converges on one confirm
  endpoint (Ops 4). The operation ID makes retries safe (Ops 6). An unknown
  outcome stays `in_progress`, and a final result describes partial effects
  (Ops 6).
- **Approval boundaries are explicit.** A message never confirms an
  operation (Ops 4.3), Company text is never the User's approval (Ops 5.1),
  and Account Tokens stay out of model context (Spec 4.8).
- **Honest about proof.** Ops 8 states that a confirmation does not prove
  the User saw or approved the terms.

### 1.2 Gaps

Ranked by consequence for agents acting on a User's behalf.

| # | Gap | Where | Consequence |
| --- | --- | --- | --- |
| G1 | Authority is account-wide and task-blind | Spec 4.4 scopes (`poppy:read`, `poppy:write`); Spec 4.8 "the User's approval for this Personal Agent to use their account" | One write-capable credential serves every task. Nothing narrower than a scope plus an audience exists. |
| G2 | Standing permissions are invisible to the Company | Ops 5.1, where confirm carries only `approved_by: "standing_permission"`; Ops 8, "`approved_by` works on trust" | The Company cannot bound, audit, or revoke the permission. An injected or buggy agent's autonomous confirm looks the same as a legitimate one. The Company's only levers are `user_approval_required`, which is also on trust, and revoking the whole `client_id`. |
| G3 | No proof of the User's approval | Ops 8: approval on the Company's website "the way Direct Sign-In works ... This extension doesn't define that step" | A Company that needs evidence must step outside the protocol. |
| G4 | No per-task lifecycle | Spec 4.9 sign-out revokes the Account Token; "disconnect" is all or nothing | Ending one task's authority ends the agent's access to the account. |
| G5 | Standing permissions cannot be checked mechanically | Ops 3 has no action identifier and `terms` keys are Company-defined; the Guides say "If a term you need to check is missing from `terms`, ask the user" | The Ops 5.1 MUST that a permission cover "the action, and every term" depends on interpreting prose. |
| G6 | Whether an endpoint proposes or executes is not machine-discoverable | Operations are optional per action (Ops 1); "SHOULD say in its OpenAPI description" with no keyword (Ops 4.1) | With a `poppy:write` token, a call the agent meant as a proposal can execute. |
| G7 | The confirm checks leave atomicity, retries, and concurrent change open | Ops 5.2 lists the checks, then "records the confirmation". It does not say the checks and the record are atomic. It gives no status for a retry against an operation that is no longer `proposed`. It does not say what happens when a new revision or a scope change lands between check and record. | Two implementations can disagree on whether a confirm that races a revision is admitted. Lowercase wording is not the problem: RFC 8174 does not require capitalized key words in normative text. |
| G8 | Code redemption checks the Session's client only | Spec 4.5: the Company "checks that the Session belongs to the same `client_id`" | A multi-user agent with a bug can attach one User's account to another User's Session. The Company cannot detect it. |
| G9 | No Security or Privacy Considerations section | Whole spec | The threat model is scattered across sections. |

Mission addresses G1 to G4. For Mission sign-ins, the profile also closes
the redemption half of G8 (Section 3.4). G5 to G9 are otherwise PAP-only
fixes (Section 6).

## 2. Where Mission fits

PAP Operations routes every channel's effect through one confirm endpoint,
and in PAP the Company is both the authorization server and the resource
server. So the Company can read Mission state locally at the exact moment of
commitment. That makes the confirm endpoint the natural, and nearly free,
place to enforce Mission.

| PAP concept | Mission concept |
| --- | --- |
| Standing permission (Ops 5.1) | Mission: approved Intent plus an Authority Set |
| "the Company, the account, the action, and every term" | `resource`, Subject, `actions`, `constraints` |
| `user_approval_required: true` | No version 1 equivalent. The `requires_action_approval` Common Constraint needs a verifiable action-bound approval, and PAP's `approved_by: "user"` is the agent's assertion (Ops 8), so version 1 fails such entries closed. |
| Account Token (Spec 4.8) | Mission-bound grant lineage (refresh token) |
| Sign-out by RFC 7009 (Spec 4.9) | Mission revocation, which core lets a deployment couple to refresh-token revocation |
| Confirm checks (Ops 5.2) | Resource-server enforcement of carried authority (core, resource-access) |

## 3. The sketch: Mission-backed standing permissions

A PAP extension named `karlmcguinness.com/mission`, version 1. PAP requires
the domain prefix (Spec 3.3) until PAP adopts the extension as `mission`. It
profiles OAuth Mission core and the Mission Resource Access Profile, and
defines nothing those documents already define.

### 3.1 What each side changes

| Side | Change |
| --- | --- |
| Company AS | Accept `mission_intent`, `authorization_details`, and the PAP `session_id` through PAR at Direct Sign-In. Bind the Session into the authorization transaction. Render the task and its authority on the existing consent page. Store the Mission. Issue a Mission-bound Account Token. Gate refresh on Mission state. Issue JWT access tokens or offer introspection. |
| Company APIs, MCP, Company Agent | Under a Mission Session Token, propose and never perform. Existing scope checks already refuse direct writes, because the token never carries `poppy:write`. |
| Company operations endpoint | Check the carried authority at read, confirm, and cancel (Section 3.7). Admit confirmations in the same transaction as the Mission state check. Record the Mission in `confirmation`. |
| Company account settings | List the agent's active Missions, each with its goal and a revoke control. |
| Personal Agent | Discover the extension. Sign in with PAR for each task. Keep each task's credential in the trusted runtime, not the model. Stop when the Company lacks the extension. Confirm with `standing_permission`, or with `user` when the operation requires it. Revoke the Mission when the task ends. |

### 3.2 Flow

```
User        Personal Agent                     Company AS / APIs / operations
 |  "exchange the jacket if ≤ $75 extra"
 |---------->|  PAR: mission_intent + authorization_details + scope + session_id
 |           |-------------------------------->|
 |           |  open authorize?request_uri=...  |
 |<----------------------------------------------| consent page: task + authority
 |  approve (signs in at the Company) ---------->| Mission recorded
 |           |  code + session_id (Spec 4.5)    |
 |           |<---------------------------------| Mission Account Token + Session Token
 |           |  POST /orders/ord_7Hk2/exchanges |
 |           |-------------------------------->| 202 operation, revision 1, $70.00
 |           |  confirm, standing_permission    |
 |           |-------------------------------->| Mission covers terms? yes: perform once
 |           |<---------------------------------| succeeded, confirmation.mission
```

### 3.3 Discovery

The Company lists the extension in `poppy.json` beside `operations`:

```json
"extensions": {
  "operations": {
    "version": "1",
    "endpoint": "https://api.example.com/poppy/operations"
  },
  "karlmcguinness.com/mission": {
    "version": "1",
    "resource": "https://api.example.com",
    "actions": {
      "exchange": ["order_id", "item_id", "replacement_sku", "max_amount"],
      "return": ["order_id", "item_id"]
    }
  }
}
```

- `resource` is the resource identifier for the Company's APIs and
  conversations. A read entry names it.
- `actions` maps each operation action the Company governs to the
  `constraints` keys it enforces for that action.
  - A Common Constraint name (`max_amount`, `time_window`) has its
    resource-access meaning.
  - Any other name is an operation `terms` key and constrains that term to
    equal the given value.
- An action listed with `max_amount` is chargeable. The AS refuses an entry
  that grants its `a.confirm`, directly or through `a.*`, without
  `max_amount`, so every confirm authority for a chargeable action has a
  money bound. An action listed
  without `max_amount` never carries a charge.
- Version 1 never lists `requires_action_approval`. Its `true` value needs
  a verifiable action-bound approval, and PAP's `approved_by: "user"` is the
  agent's assertion (Ops 8). The AS therefore refuses an entry carrying
  `true` and never grants it with the key dropped, and the operations
  endpoint fails such an entry closed. A `false` value is the same as
  omitting the key.
- Each action `a` yields three action identifiers on the operations
  resource: `a.read`, `a.confirm`, and `a.cancel`. An entry can name them
  separately or as the family `a.*`.
- Operation entries name the operations resource: the `operations` entry's
  `resource` when it has one, otherwise its `endpoint`. The operations
  endpoint identifies itself by that identifier for every path beneath it,
  including `/{operation_id}/confirm`, so the default `exact`
  `resource_match` applies to confirm requests.

Core makes Mission metadata optional and attaches obligations to
advertising it. This profile requires the Company's AS to advertise
`mission_bound_authorization_supported: true`. Under core, that obliges the
AS to publish `pushed_authorization_request_endpoint` and to list a
supported type in `authorization_details_types_supported`. This profile
further requires `mission_resource_access` among those types. The agent
lists the extension in its client metadata document (Spec 4.1).

Operations returned to an agent that lists the extension carry `action`, the
identifier `a` from which the checks derive `a.read`, `a.confirm`, and
`a.cancel`. PAP implementations ignore fields they do not recognize (Spec
3.3), so the added member is backward compatible.

### 3.4 Creating a Mission

Direct Sign-In (Spec 4.5) with its request pushed through PAR, because core
accepts `mission_intent` only through PAR. The decoded PAR body:

```
POST https://auth.example.com/oauth/par

response_type=code
client_id=https://agent.example/agent.json
redirect_uri=https://agent.example/oauth/callback
scope=poppy:read
state=Xq81vR
code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method=S256
session_id=ses_2Lm0
mission_intent=<Submission envelope>
authorization_details=<entries>
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<private_key_jwt>
```

The Submission envelope:

```json
{
  "intent": {
    "goal": "Exchange the Stormline Jacket (M) on order ord_7Hk2 for the insulated version if it costs no more than $75 extra.",
    "target_resources": [
      "https://api.example.com",
      "https://api.example.com/poppy/operations"
    ],
    "expires_at": "2026-10-11T00:00:00Z"
  }
}
```

The authority proposal has three entries:

```json
[
  { "type": "mission_resource_access",
    "resource": "https://api.example.com",
    "actions": ["poppy:read"] },
  { "type": "mission_resource_access",
    "resource": "https://api.example.com/poppy/operations",
    "actions": ["exchange.read", "exchange.cancel"],
    "constraints": {
      "order_id": "ord_7Hk2",
      "item_id": "itm_4Qa",
      "replacement_sku": "stormline-insulated-m"
    } },
  { "type": "mission_resource_access",
    "resource": "https://api.example.com/poppy/operations",
    "actions": ["exchange.confirm"],
    "constraints": {
      "order_id": "ord_7Hk2",
      "item_id": "itm_4Qa",
      "replacement_sku": "stormline-insulated-m",
      "max_amount": { "amount": "75.00", "currency": "USD" }
    } }
]
```

The read entry reconciles a conflict between the two specifications. PAP
requires `scope` on every sign-in (Spec 4.4). Core emits a `scope` only when
it projects safely from a carried entry, and emits none for a target that
consumes `authorization_details`. The read entry projects to `poppy:read`,
which the Company's APIs already enforce unchanged. The operation entries
are consumed by the operations endpoint. Because the two resources are
distinct, each audience follows one rule, and neither specification needs an
exception.

The operation entries are split by phase. The read and cancel entry pins
which operation the task may see and stop, but sets no price cap, so the
agent can inspect a quote above the cap without being able to accept it.
The confirm entry adds the cap.

The agent then opens `authorize?client_id=...&request_uri=...` in the User's
browser. The consent page renders the goal and the structured authority, for
example "View your account. See or cancel an exchange of item itm_4Qa on
order ord_7Hk2 for Stormline Insulated Jacket (M), and confirm it for at
most $75.00 more. Until October 11."
The User signs in and approves, which satisfies PAP's rule that the User
signs in themselves (Spec 4.4).

The code exchange is PAP's, with one added check. The pushed request
carries the PAP `session_id`. At PAR, the AS checks that the Session belongs
to the authenticated client and binds the Session into the authorization
transaction. At redemption, it refuses with `invalid_grant` any `session_id`
that differs from the pushed one.

This closes the redemption half of G8: a code redeems only into the Session
its request was started for, so a crossed callback in a multi-user agent
cannot attach one User's Mission to another User's Session. It cannot catch
an agent that starts the request for the wrong Session in the first place,
because PAP User IDs are assigned by the agent (Spec 4.2).

### 3.5 Token response

PAP's sign-in response, plus core's members:

```json
{
  "access_token": "eyJhbGciOi…Qp4w",
  "token_type": "DPoP",
  "expires_in": 3600,
  "refresh_token": "pat_M7c2…Rr4",
  "scope": "poppy:read",
  "session_id": "ses_2Lm0",
  "signed_in": true,
  "mission_id": "msn_8RfX2Lqv9TqM",
  "mission_expires_at": "2026-10-11T00:00:00Z",
  "authorization_details": [ "…the granted entries…" ]
}
```

- The `refresh_token` is a Mission Account Token. It is added beside any
  ordinary Account Token the agent holds and replaces nothing, so the
  step-up replacement rule of Spec 4.4 does not apply.
- It is already sender-constrained, which is what core requires of
  Mission-bound refresh tokens (sender-constrained or rotated). PAP accepts
  an Account Token only from the `client_id` it was issued to, authenticated
  by `private_key_jwt` (Spec 4.8). RFC 9449 Section 5 names this
  client-authentication binding as the sender constraint for a confidential
  client's refresh token. Rotation stays optional (Spec 4.8).
- No credential outlives `mission_expires_at`, per core.
- Session Tokens stay opaque to the agent (Spec 4.2). Core profiles two
  forms of Mission-bound access token: an RFC 9068 JWT, or an opaque token
  whose AS offers introspection (core's introspected-consumption mode). PAP
  lets the Company choose either, since the agent never reads the token. A
  Company that resolves opaque tokens only from its own records, with no
  introspection offered, is outside core as written. Section 6.2 proposes
  the clarification that would admit it.
- Governance rides the token, not the Session. A Session renewed with an
  ordinary Account Token gets ordinary tokens. Agents should still use a
  separate Session per Mission, for clarity.

### 3.6 Proposals under a Mission token

Proposals are unchanged from Ops 4: an existing endpoint, MCP tool, or the
Company Agent proposes an operation. The extension adds two rules:

1. Under a Mission Session Token, the Company proposes and never performs. A
   proposal has no effect, so proposing needs no `poppy:write`. The Company
   returns a proposal only if the token may read it (`decide(op, token,
   op.action + ".read", now)`, Section 3.7); otherwise it refuses with
   `mission_denial="insufficient_authority"` and discards the proposal.
2. An endpoint that only executes directly refuses with `insufficient_scope`,
   as it already does for a token without `poppy:write`.

Rule 2 gives the no-direct-execution property without a dedicated proposal
endpoint, so G6 cannot bite an agent holding only a Mission token. It also
covers the Company Agent, which is "held to the same scopes" (Spec 7.9,
7.11).

### 3.7 Confirm

The request is PAP's, unchanged:

```
POST https://api.example.com/poppy/operations/exc_5Rt2/confirm
Authorization: DPoP <Mission Session Token>
DPoP: <proof>

{ "revision": 1, "approved_by": "standing_permission" }
```

The Company's added check:

```
confirm(op, token, body):
  PAP checks: ownership (3.2), latest revision, approved_by allowed,
              state proposed and unexpired                     # Ops 5.2

  if token has no Mission:
    if body.approved_by == "standing_permission" and policy.missions_required:
      refuse 403 user_approval_required                        # existing Ops 9 error
    check poppy:write as PAP does; continue as PAP

  else:
    C = decide(op, token, op.action + ".confirm", now)

  in one transaction that locks the Mission record:            # revocation takes the same lock
    t = now                                                    # the admission instant; becomes confirmed_at
    if op is no longer proposed at this revision, or t >= op.expires_at:
      return op as it is, with no effect                       # Ops 5.2; concurrent confirms, Ops 6
    if the token has a Mission:
      if its state != active or t >= its expires_at:
        refuse 401 invalid_token
      if no entry in C holds time_window at t:
        refuse 403 insufficient_scope, mission_denial="insufficient_authority"
    record confirmation at t (with mission), move to in_progress
  perform once                                                 # Ops 5.2, 6

decide(op, token, action, t):                                  # also used for read, cancel, proposals
  if op has a charge and the Company lists op.action without max_amount:
    refuse 403 insufficient_scope, mission_denial="insufficient_authority"
  A = granted entries on the operations resource whose actions include action,
      each with any requires_action_approval: false removed     # false = absent
  if any entry in A has a resource_match value or constraint key the
     Company does not enforce for op.action:                   # includes requires_action_approval: true
    refuse 403 insufficient_scope, mission_denial="constraint_unrecognized"
  C = entries in A for which every constraint holds for op at t
  if C is empty:
    refuse 403 insufficient_scope, mission_denial="insufficient_authority"
  return C

holds(key, value, op, t):
  max_amount              -> op's total charge, every fee and tax included,
                             <= value in the same currency, exact decimal
  time_window             -> t is inside the window
  any other enforced key  -> op.terms[key] equals value
```

- **Every applicable entry is checked before one is chosen.** A key the
  Company does not enforce, in any entry that names the action, fails the
  request closed (core and resource-access). Only then are the remaining
  entries treated as alternative grants. Entry order never changes the
  outcome.
- **The covering entries replace one PAP check.** Under a Mission token,
  they stand in for the second check of Ops 5.2, "the token has the scopes
  the action needs". This is the one PAP confirm rule the extension
  overrides.
- **`requires_action_approval: true` fails closed.** It is never among the
  Company's enforced keys in version 1 (Section 3.3), so the AS refuses it,
  and an entry that carries it anyway fails with `constraint_unrecognized`.
  It is not mapped to PAP's `user_approval_required`. That flag stays the
  Company's own per-operation choice, and the `approved_by: "user"` that
  satisfies it is the agent's assertion (Ops 8).
- **Charges are bounded, never inferred.** `max_amount` bounds the
  operation's total charge: everything the User pays for it, every fee and
  tax included. An action listed without `max_amount` carries no charge, so
  a fee added in a later revision is refused rather than covered by
  omission.
- **Admission is judged at one instant and serializes with revocation.** A
  confirmation is admitted only if, at the instant it commits, three things
  hold:
  - the Mission is active and before its `expires_at`;
  - the operation is still `proposed` at that revision and unexpired;
  - a covering entry's `time_window`, if any, contains that instant.

  Revocation updates the same Mission record under the same lock, so a
  confirmation and a revocation cannot interleave. Expiry and time windows
  are judged at the admission instant, not when the request arrived, so a
  confirm that waits on the lock past a bound is refused. Once the Company
  acknowledges a revocation, it admits no further confirmation under that
  Mission.
- **Read and cancel need the same check.** Under a Mission token, `GET
  {endpoint}/{operation_id}` requires `decide(op, token, op.action +
  ".read", now)`, and cancel requires `decide(op, token, op.action +
  ".cancel", now)`. Ownership under Ops 3.2 applies in addition. An
  exchange-only Mission therefore cannot read or cancel another task's
  operation.
- **A Mission token acts only within its Mission**, whatever `approved_by`
  says. If the User wants a revision the Mission does not cover, the remedy
  is a new Mission. Confirming with an ordinary credential instead is the
  separate PAP workflow of Section 3.10, outside this profile.
- `policy.missions_required` is the Company's adoption lever. It accepts
  `standing_permission` only when a Mission backs it, and `approved_by:
  "user"` keeps working as PAP defines it.
- The refusal reuses PAP's token error and core's `mission_denial`
  attribute, with the current operation in the body (Ops 9):

```
HTTP/1.1 403 Forbidden
WWW-Authenticate: DPoP error="insufficient_scope", mission_denial="insufficient_authority"
Content-Type: application/json

{ "error": "insufficient_scope", "operation": { "operation_id": "exc_5Rt2", "revision": 2, "state": "proposed", "…": "…" } }
```

An agent that sees `mission_denial` does not sign in for more scopes, which
is PAP's usual reaction to `insufficient_scope`. It asks the User.

A successful confirmation records the Mission, using core's `mission` claim
shape:

```json
"confirmation": {
  "revision": 1,
  "approved_by": "standing_permission",
  "confirmed_at": "2026-10-09T12:04:31-07:00",
  "mission": { "id": "msn_8RfX2Lqv9TqM", "issuer": "https://auth.example.com" }
}
```

### 3.8 Ending a Mission

- **Expiry** at the Mission's `expires_at`.
- **The User revokes it** in the Company's account settings. Core requires an
  authenticated means to revoke by `mission_id`, and the settings page is
  that means. "Disconnect" still revokes everything.
- **The agent revokes it** by revoking the Mission Account Token with RFC
  7009, exactly as PAP signs out (Spec 4.9). This profile couples the two, as
  core permits. An agent revokes the Mission when its task is done.

Afterward:

- The Mission's Session Tokens fail with `invalid_token`, because the Company
  checks Mission state on each request, as Spec 4.9 already recommends for
  sign-in state.
- Refresh fails with `invalid_grant` and `mission_error` set to `revoked` or
  `expired`. Per PAP, the Session continues signed out.
- A confirmation racing the revocation is admitted only if it committed
  before the Company acknowledged the revocation (Section 3.7).
- Operations confirmed before the end continue (Ops 5.2). Authority was
  checked at the commit point.
- The Mission's tokens no longer read or cancel anything. To track or stop
  those operations, an ordinary signed-in Session follows PAP's rules (Ops
  3.2). That is recovery under the account's own authority, not Mission
  authority.

### 3.9 Channels

| Channel | Rule |
| --- | --- |
| OpenAPI | Proposals under a Mission token. Direct-execution endpoints refuse. |
| MCP | Bearer tokens are per MCP server (Spec 4.3), so each MCP server the task uses needs its own read entry. Tools propose operations. Confirmation happens at the DPoP operations endpoint. |
| Conversations | The Company Agent proposes. A message never confirms (Ops 4.3). |
| Web | A browser joined to a Mission Session is treated as signed out, unless the website enforces the same scopes as the APIs and confirms only through the Section 3.7 check and admission. A User who confirms in their own browser, signed in to their own account, acts on their own authority, outside the Mission. |

### 3.10 What the agent developer writes

```
company = discover(domain)                         # poppy.json + AS metadata (Spec 3)
if company does not list both "operations" and "karlmcguinness.com/mission":
    tell the User the Company cannot hold this task's limits; stop
cred = sign_in_with_mission(company, goal, entries)   # PAR + Direct Sign-In
task.credential = cred                             # trusted runtime; the model never picks it

op = call(cred, POST /orders/ord_7Hk2/exchanges, ...)   # 202 + operation; cred cannot execute
if op.user_approval_required:
    show the User op.summary; if approved: approval = "user" else: cancel(op, cred); stop
else:
    approval = "standing_permission"
r = confirm(op, cred, approved_by=approval)
if r.mission_denial == "insufficient_authority":
    tell the User this Mission does not cover it; a wider task is a new Mission
when task completes: revoke(cred.account_token)
```

Without the extension, the Mission workflow stops, and the agent tells the
User why. That follows core's no-downgrade rule. A client holding a Mission
Intent must not submit the same authority as bare `scope` or
`authorization_details` to an AS whose Mission support is neither advertised
nor otherwise established. It surfaces the inability instead.

Stopping also keeps any ordinary credential the agent holds out of the task.
That is this profile's rule, not core's.

The User may separately choose to run an ordinary PAP workflow instead. That
is a different authorization, outside this profile:

- The agent holds an account-wide credential.
- It cannot assume that an action endpoint returns a proposal rather than
  executing (G6).
- It therefore needs the User's approval before calling any endpoint the
  Company does not document as returning operations, and it confirms with
  `approved_by: "user"` after showing the revision (Ops 5.1).

## 4. Guarantees and losses

| Guarantee | Enforced by |
| --- | --- |
| Under a Mission token, the Company performs an action only by confirming an operation whose `action` and `terms` an active Mission entry covers | Company: existing scope checks, plus the confirm check |
| Under a Mission token, reading, cancelling, and receiving a proposal stay within the Mission's `a.read` and `a.cancel` entries | Company: the same authority check, plus Ops 3.2 ownership |
| The Company holds its own record of what the User approved, on its own page, and when | Company AS (core Mission Record) |
| After the Company acknowledges a revocation, it admits no further confirmation and issues no further token under that Mission. No confirmation is admitted after the Mission's or the operation's `expires_at`, or outside a covering `time_window`. | Confirmation admitted in one transaction with the state check, serialized with revocation on the Mission record and judged at its commit instant; core issuance gating |
| A chargeable action is confirmed only within a money bound, and an action listed without one is never charged | AS refuses an uncapped `a.confirm` entry; confirm check on the total charge |
| One task's credential cannot read, confirm, or cancel another task's operations beyond its own Mission | Authority check |
| The planner cannot choose a broader task credential | Agent's trusted runtime. The Company cannot verify this. |

| Not provided in version 1 | Consequence | Where it comes back |
| --- | --- | --- |
| Cumulative limits (count, total spend) | Two operations under one Mission can each commit if each fits. Narrow entries, such as order and item equality, limit this in practice. | Mission Metering (`max_calls`, `max_budget`) |
| Verified per-revision User approval | `approved_by: "user"` stays on trust (Ops 8). An entry with `requires_action_approval: true` is refused rather than satisfied by it. | Mission Transaction Authorization, or another action-bound approval hosted by the Company |
| Device Sign-In and Mediated Sign-In | Agents without a redirect cannot create Missions. Mediated Sign-In has no Company-rendered approval, so it stays out. | Core issue: Intent carriage on the RFC 8628 request (Section 6.2) |
| Conditions outside `terms` | Only `terms` and Common Constraints are checked. Summary prose is not. | Ops 3 already requires every effect in `terms` when present. A Company governing an action puts its conditions there. |
| Other credentials the agent holds | An ordinary `poppy:write` token is not bounded by any Mission. It can confirm with `approved_by: "user"` on the agent's word (T11). | Company policy: offer agents no `poppy:write` (Spec 4.4 permits it), so every agent write goes through a Mission |
| Missions across Companies | Each Company sees only its own Mission. Aggregate limits are the agent's job. | Cross-Domain companion, opt-in, at the cost of correlation (Section 5) |

The profile claims no assurance level beyond Baseline Issuance. It adds two
capabilities on top:

- **A state check at confirm, serialized with revocation**, the freshness
  half-step the architecture describes.
- **Enforcement of the carried authority at one resource server**, the
  operations endpoint, for actions that go through operations.

It does not claim Runtime-Enforced. It has no PDP, no permits, and no
runtime evidence, and paths outside operations are covered only by the
absence of `poppy:write`.

## 5. Disposition of Draft 00

The earlier draft (Draft 00, 9 October 2026; 76 KB; 30 conformance cases)
should be narrowed to Section 3. Three findings drive this.

1. **It replaces PAP's proposal model.** Draft 00 adds an agent-called
   proposal endpoint with `request_id` and revision members. PAP has
   Companies propose from the channels that already exist (Ops 4) and
   deduplicates by operation ID (Ops 6). The draft's goal, never executing
   when the agent meant to propose, is met by a Mission token that never
   carries `poppy:write` (Section 3.6).
2. **It puts machinery into the first profile that PAP or core already
   supply.**
   - `parameter_digest`: PAP revisions are immutable and held by the Company.
   - `account_ref`: the Company binds the account to the grant.
   - `request_id`: the operation ID already serves.
   - Ten `pap_*` constraints: `terms`-key equality plus `max_amount` covers
     them.
   - New error codes: `insufficient_scope` with `mission_denial`.
   - The scope-omission exception: a read entry projects to `poppy:read`.
3. **Its target architecture undoes PAP's privacy design.** One Mission shared
   across Companies correlates the User at each of them, despite pairwise
   User IDs (Spec 4.2). Draft 00 notes the correlation but treats it as the
   goal. Per-Company Missions keep the property. Cross-Company work is a
   later composition that a User opts into.

| Draft 00 element | Disposition | What is lost |
| --- | --- | --- |
| Proposal endpoint, `request_id`, `revises_operation_id`, `expected_revision` | Remove | Nothing. Ops 4 and Ops 6 cover it. |
| `session_id` at PAR | Retain (Section 3.4) | Nothing. G8 stays open for ordinary sign-ins (Section 6.1). |
| `account_ref` | Remove | Cross-client account comparison, which no check needs |
| `parameter_digest` | Remove | A client-side tamper check of a revision the Company holds and cannot change (Ops 3.1) |
| `pap_*` constraints and the retail profile | Replace with `terms`-key equality and Common Constraints | Range checks other than `max_amount` and `time_window` |
| `pap_commit_limit` | Defer to Metering | Cumulative counts (Section 4) |
| Scope-omission exception | Remove | Nothing |
| `mas_join` mode | Remove | Nothing for PAP. A PAP Company already changes its AS. |
| ARAP approval object | Defer | Verified per-revision approval (Section 4) |
| Enforcement statement URI | Remove | Coverage is stated by the rules of Sections 3.6 and 3.9 |
| One Mission per Session | Remove; governance rides the token | Nothing. The rule fought Spec 4.8. |
| Cross-domain projection, ID-JAG (Section 16 of Draft 00) | Out of version 1 | Section 4 |
| 30 conformance cases | Replace with the tests in Section 7 | Coverage of removed mechanisms only |
| Separate proposal/read and commit entries | Retain, as `a.read`/`a.cancel` and `a.confirm` entries (Section 3.4) | Nothing |
| Confirmation admission inside one transaction with the state check | Retain, narrowed to the Mission state check and the confirmation record (Section 3.7) | Nothing |

## 6. Upstream asks

### 6.1 To PAP

These help PAP whether or not Mission is used.

1. Add an optional `action` (a Company-documented identifier) and an
   optional typed charge (`amount` and `currency`) to operations. Standing
   permissions then become checkable by machine (G5).
2. Define an OpenAPI keyword that marks endpoints returning operations (G6).
3. Say that the confirm checks and the confirmation record are atomic. Give
   a status for a retry that finds "the operation as it is", and state the
   outcome when a revision or a scope change lands between check and record
   (G7).
4. Bind the Session at authorization for every sign-in, as Section 3.4 does
   for Mission sign-ins, not only the client at redemption (G8).
5. Add Security and Privacy Considerations sections (G9).

### 6.2 To the Mission family

Proposed issues. None has been filed.

1. **Core: Intent carriage on the RFC 8628 device authorization request.**
   PAR exists to keep the Intent off the front channel. The device
   authorization request is already a client-authenticated back-channel
   POST. Allowing it unblocks PAP Device Sign-In and headless agents
   generally.
2. **Core: in-house introspected consumption.** State that an estate whose AS
   and resource servers are one deployment satisfies introspected
   consumption with an internal lookup. No public RFC 7662 endpoint is then
   needed for opaque Mission-bound tokens.

## 7. Decisive tests

Each test uses a Mission for "exchange `itm_4Qa` on `ord_7Hk2` for
`stormline-insulated-m`, `max_amount` 75.00 USD" unless the setup says
otherwise.

| # | Setup | Action | Required result |
| --- | --- | --- | --- |
| T1 | Revision at 90.00 USD | Read it, then confirm it with `standing_permission` under the Mission token | The read succeeds, because `exchange.read` sets no cap. The confirm returns `403`, `insufficient_scope`, `mission_denial="insufficient_authority"`. The operation stays `proposed`. No charge. |
| T2 | Revision at 70.00 USD | Confirm it with `standing_permission` under the Mission token | `200`. `confirmation.mission` is set. Exactly one exchange. |
| T3 | Mission token (`poppy:read`) | (a) Call a direct-execution write endpoint. (b) Ask the Company Agent to perform the exchange. (c) Request the exchange for a different SKU at an operation-aware endpoint. (d) Request the approved exchange there. | (a) and (b): `insufficient_scope`, no effect. (c): `403`, `insufficient_authority`, no operation returned. (d): `202` with a proposal. |
| T4 | The Company requires Missions for standing permissions | An ordinary `poppy:write` token confirms with `standing_permission` | `403 user_approval_required` |
| T5 | A revocation and a confirmation of the same proposed operation run concurrently, repeated many times, with revocation both in settings and by RFC 7009 | Confirm. After the revocation is acknowledged, confirm again and refresh. | Every admitted confirmation committed before the revocation was acknowledged, and none after. Refused attempts have no effect. After acknowledgement: confirm returns `401 invalid_token`, and refresh returns `invalid_grant` with `mission_error="revoked"`. Confirmations admitted earlier complete. |
| T6 | Mission A covers this exchange; Mission B covers returning `itm_9Zp` | A's token reads, cancels, and confirms B's return | `403`, `insufficient_authority` for each request. B's operation is unchanged. |
| T7 | Two `exchange.confirm` entries: one covers the revision; the other carries a key the Company stopped enforcing after issuance | Confirm, with the entries in each order | `403`, `mission_denial="constraint_unrecognized"` in both orders. No effect. |
| T8 | (a) An authority proposal whose `exchange.confirm` entry carries `requires_action_approval: true`. (b) A grant that carries such an entry anyway. | (a) Sign in. (b) Confirm with `user`, then with `standing_permission`. | (a) The AS refuses the entry, or omits it and the granted `authorization_details` shows the omission. It never grants the entry with the key dropped. (b) `403`, `mission_denial="constraint_unrecognized"` for both confirms. No effect. |
| T9 | The covering entry carries `requires_action_approval: false` | Confirm with `standing_permission` | `200`. `false` is the same as absent. |
| T10 | The Company lists `operations` but not the extension | The agent starts the Mission workflow | The agent makes no action call and tells the User why. It submits the authority neither as bare `scope` nor as `authorization_details`. |
| T11 | An operation proposed under the Mission token at 90.00 USD; the agent also holds an ordinary signed-in credential | Confirm with the ordinary credential and `approved_by: "user"` | (a) Where the Company offers agents `poppy:write`: `200` as an ordinary PAP confirmation, with no `confirmation.mission`. The label is the agent's assertion (Ops 8), and the record does not attribute the confirmation to the Mission. (b) Where the Company offers agents no `poppy:write` (Spec 4.4): sign-in refuses that scope with `invalid_scope`, so the credential cannot exist and the confirm cannot happen. |
| T12 | Two open operations for the same exchange (two operation IDs) proposed in two channels | Confirm both under the Mission token | Ops 4 has the Company return the existing operation instead of a second. Where two exist anyway, each confirm is decided on its own and each operation is performed at most once. The Mission does not stop the second (Section 4). The Company's own business rule, such as an item being exchangeable once, or Metering with a `max_calls` of 1 on `exchange.confirm`, refuses it. |
| T13 | The agent's browser is joined to the Mission Session, and the website offers confirmation (Ops 4.4) | Confirm on the website and, concurrently, at the endpoint | Either the website treats the browser as signed out and offers no confirmation, or it runs the Section 3.7 check and admission. No confirmation is admitted outside the Mission. The action is performed at most once across both channels. |
| T14 | (a) Revision 2 of the exchange adds a 10.00 USD fee to 70.00 USD. (b) A `return` operation, an action listed without `max_amount`, gains a 5.00 USD restocking fee in revision 2. | Confirm each with `standing_permission` | (a) `403`, `insufficient_authority`: the total charge, 80.00 USD, exceeds the cap. (b) `403`, `insufficient_authority`: an action listed without `max_amount` carries no charge. No effect in either case. |
| T15 | A confirm waits on the Mission lock, held by a concurrent writer, while (a) the Mission's `expires_at`, (b) the operation's `expires_at`, or (c) the covering entry's `time_window` end passes | Release the lock | (a) `401 invalid_token`. (b) The operation is returned as it is, `expired`, with no confirmation. (c) `403`, `insufficient_authority`. No effect in any case. Every admitted confirmation's `confirmed_at` precedes the bound. |

## 8. Adoption path

1. **PAP with Operations as it is.** Standing permissions are held by the
   agent; the Company trusts them or requires per-revision approval.
2. **This profile.** Missions back standing permissions, and the Company sets
   `missions_required` when it is ready.
3. **Cumulative limits** with Mission Metering.
4. **Company-verified per-revision approval** for actions that carry
   `requires_action_approval`.
5. **Recurring and evolving tasks** with Mission Template and Progressive
   Authorization.
6. **Work spanning Companies** with Cross-Domain projection, for Users who
   accept the correlation.

The profile belongs in PAP's own format: a short extension page proposed for
adoption as `mission`, citing core and resource-access. It is not a new
family Internet-Draft. On the family side,
`notes/mission-agent-protocol-composition.md` can link to it.
