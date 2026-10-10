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
  no error code, and no change to PAP's opaque tokens. The cost is
  concentrated in the Company's AS: it gains a PAR endpoint, which core
  requires, and becomes a core Mission Issuer. The operations endpoint adds
  one check at confirm. The Personal Agent pushes its Direct Sign-In request
  through PAR.
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
| G7 | Confirm checks are lowercase prose | Ops 5.2 lists "the Company checks that" without BCP 14 keywords or an order; no status is given for "returns the operation as it is" | An interoperability ambiguity, not a security hole. |
| G8 | Code redemption checks the Session's client only | Spec 4.5: the Company "checks that the Session belongs to the same `client_id`" | A multi-user agent with a bug can attach one User's account to another User's Session. The Company cannot detect it. |
| G9 | No Security or Privacy Considerations section | Whole spec | The threat model is scattered across sections. |

Mission addresses G1 to G4. G5 to G9 are PAP-only fixes (Section 6).

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
| `user_approval_required: true` | `requires_action_approval` Common Constraint |
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
| Company AS | Accept `mission_intent` and `authorization_details` through PAR at Direct Sign-In. Render the task and its authority on the existing consent page. Store the Mission. Issue a rotating, Mission-bound Account Token. Gate refresh on Mission state. |
| Company APIs, MCP, Company Agent | Under a Mission Session Token, propose and never perform. Existing scope checks already refuse direct writes, because the token never carries `poppy:write`. |
| Company operations endpoint | One added check at confirm (Section 3.7). Record the Mission in `confirmation`. |
| Company account settings | List the agent's active Missions, each with its goal and a revoke control. |
| Personal Agent | Discover the extension. Sign in with PAR for each task. Keep each task's credential in the trusted runtime, not the model. Confirm with `standing_permission`. Revoke the Mission when the task ends. |

### 3.2 Flow

```
User        Personal Agent                     Company AS / APIs / operations
 |  "exchange the jacket if ≤ $75 extra"
 |---------->|  PAR: mission_intent + authorization_details + scope=poppy:read
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
  `constraints` keys it enforces for that action at confirm. A Common
  Constraint name (`max_amount`, `time_window`, `requires_action_approval`)
  has its resource-access meaning. Any other name is an operation `terms` key
  and constrains that term to equal the given value.
- Operation entries name the operations resource: the `operations` entry's
  `resource` when it has one, otherwise its `endpoint`. The operations
  endpoint identifies itself by that identifier for every path beneath it,
  including `/{operation_id}/confirm`, so the default `exact`
  `resource_match` applies to confirm requests.

The Company's AS metadata carries what core already requires:
`mission_bound_authorization_supported`,
`pushed_authorization_request_endpoint`, and `mission_resource_access` in
`authorization_details_types_supported`. The agent lists the extension in
its client metadata document (Spec 4.1).

Operations returned to an agent that lists the extension carry `action`, the
action identifier the confirm check matches. PAP lets extensions add fields
(Spec 3.3, 7.4).

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

The authority proposal has two entries:

```json
[
  { "type": "mission_resource_access",
    "resource": "https://api.example.com",
    "actions": ["poppy:read"] },
  { "type": "mission_resource_access",
    "resource": "https://api.example.com/poppy/operations",
    "actions": ["exchange"],
    "constraints": {
      "order_id": "ord_7Hk2",
      "item_id": "itm_4Qa",
      "replacement_sku": "stormline-insulated-m",
      "max_amount": { "amount": "75.00", "currency": "USD" }
    } }
]
```

The two entries reconcile a conflict between the two specifications. PAP
requires `scope` on every sign-in (Spec 4.4). Core emits a `scope` only when
it projects safely from a carried entry, and emits none for a target that
consumes `authorization_details`. The read entry projects to `poppy:read`,
which the Company's APIs already enforce unchanged. The operation entry is
consumed by the operations endpoint at confirm. Because the two resources are
distinct, each audience follows one rule. Neither specification needs an
exception.

The agent then opens `authorize?client_id=...&request_uri=...` in the User's
browser. The consent page renders the goal and the structured authority, for
example "View your account. Exchange item itm_4Qa on order ord_7Hk2 for
Stormline Insulated Jacket (M), for at most $75.00 more. Until October 11."
The User signs in and approves, which satisfies PAP's rule that the User
signs in themselves (Spec 4.4). The code exchange is PAP's, unchanged,
including `session_id`.

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
- It rotates on every use. Core requires Mission-bound refresh tokens to be
  sender-constrained or rotated. PAP's Bearer-for-MCP refresh omits the DPoP
  header (Spec 4.3), so rotation is the compatible choice. PAP already
  permits rotation (Spec 4.8).
- No credential outlives `mission_expires_at`, per core.
- Session Tokens stay opaque (Spec 4.2). The Company resolves them against
  its own records, which is core's introspected-consumption mode run in-house.
  A JWT is not required.
- Governance rides the token, not the Session. A Session renewed with an
  ordinary Account Token gets ordinary tokens. Agents should still use a
  separate Session per Mission, for clarity.

### 3.6 Proposals under a Mission token

Proposals are unchanged from Ops 4: an existing endpoint, MCP tool, or the
Company Agent proposes an operation. The extension adds two rules:

1. Under a Mission Session Token, the Company proposes and never performs. A
   proposal has no effect, so proposing needs no `poppy:write`.
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
    m = mission_record(token)                                  # local read: the Company is the issuer
    if m.state != active:          refuse 401 invalid_token
    for each granted entry e on the operations resource with op.action in e.actions:
      if e has a constraint key the Company does not enforce:
        refuse 403 insufficient_scope, mission_denial="constraint_unrecognized"
      if every constraint in e holds for op:  covered = e; stop
    if no entry covered op:
      refuse 403 insufficient_scope, mission_denial="insufficient_authority"
    if covered.requires_action_approval and body.approved_by != "user":
      refuse 403 user_approval_required

  record confirmation (with mission), move to in_progress, perform once   # Ops 5.2, 6

holds(key, value, op):
  max_amount     -> op's charge <= value in the same currency, exact decimal
  time_window    -> now is inside the window
  any other key  -> op.terms[key] equals value
```

- Under a Mission token, the covering entry stands in for the second check
  of Ops 5.2, "the token has the scopes the action needs". This is the one
  PAP confirm rule the extension overrides.
- Reading (`GET {endpoint}/{operation_id}`) and cancelling follow the
  ownership rules of Ops 3.2 unchanged and need no entry. Only confirm
  consumes Mission authority.
- A Mission token confirms only within its Mission, whatever `approved_by`
  says. If the User approves a revision outside the Mission, the agent
  confirms it with an ordinary write-capable Session, if it has one and the
  Company allows it, or gets a new Mission.
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
- Operations confirmed before the end continue (Ops 5.2). Authority was
  checked at the commit point.
- Any Session signed in to the account can still read or cancel those
  operations (Ops 3.2).

### 3.9 Channels

| Channel | Rule |
| --- | --- |
| OpenAPI | Proposals under a Mission token. Direct-execution endpoints refuse. |
| MCP | Bearer tokens are per MCP server (Spec 4.3), so each MCP server the task uses needs its own read entry. Tools propose operations. Confirmation happens at the DPoP operations endpoint. |
| Conversations | The Company Agent proposes. A message never confirms (Ops 4.3). |
| Web | A browser joined to a Mission Session is treated as signed out, unless the website enforces the same scopes as the APIs. |

### 3.10 What the agent developer writes

```
company = discover(domain)                         # poppy.json + AS metadata (Spec 3)
if company lists "karlmcguinness.com/mission":
    cred = sign_in_with_mission(company, goal, entries)   # PAR + Direct Sign-In
    approval = "standing_permission"
else:
    cred = existing_signed_in_session(company)     # PAP unchanged
    approval = "user"                              # ask the User per revision
task.credential = cred                             # trusted runtime; the model never picks it

op = call(task.credential, POST /orders/ord_7Hk2/exchanges, ...)   # 202 + operation
r  = confirm(op, task.credential, approved_by=approval)
if r.mission_denial == "insufficient_authority":
    ask the User; confirm by per-revision approval or get a new Mission
when task completes: revoke(cred.account_token)
```

Against a Company without the extension, the agent says so to the User and
falls back to per-revision approval. This is core's no-downgrade rule for a
client holding an Intent. The agent never submits the authority as plain
`scope`.

## 4. Guarantees and losses

| Guarantee | Enforced by |
| --- | --- |
| Under a Mission token, the Company performs an action only by confirming an operation whose `action` and `terms` an active Mission entry covers | Company: existing scope checks, plus the confirm check |
| The Company holds its own record of what the User approved, on its own page, and when | Company AS (core Mission Record) |
| Ending a Mission immediately stops new confirmations and new tokens | Live Mission state at confirm; core issuance gating |
| One task's credential cannot confirm another task's operations beyond its own Mission | Confirm check |
| The planner cannot choose a broader task credential | Agent's trusted runtime. The Company cannot verify this. |

| Not provided in version 1 | Consequence | Where it comes back |
| --- | --- | --- |
| Cumulative limits (count, total spend) | Two operations under one Mission can each commit if each fits. Narrow entries, such as order and item equality, limit this in practice. | Mission Metering (`max_calls`, `max_budget`) |
| Verified per-revision User approval | `approved_by: "user"` stays on trust (Ops 8) | Mission Transaction Authorization, or another action-bound approval hosted by the Company |
| Device Sign-In and Mediated Sign-In | Agents without a redirect cannot create Missions. Mediated Sign-In has no Company-rendered approval, so it stays out. | Core issue: Intent carriage on the RFC 8628 request (Section 6.2) |
| Conditions outside `terms` | Only `terms` and Common Constraints are checked. Summary prose is not. | Ops 3 already requires every effect in `terms` when present. A Company governing an action puts its conditions there. |
| Other credentials the agent holds | An ordinary `poppy:write` Account Token is not bounded by any Mission | Company policy: grant agents `poppy:read` plus Missions only |
| Missions across Companies | Each Company sees only its own Mission. Aggregate limits are the agent's job. | Cross-Domain companion, opt-in, at the cost of correlation (Section 5) |

The profile claims no assurance level beyond Baseline Issuance. It adds two
capabilities on top:

- **A live state read at confirm**, the freshness half-step the architecture
  describes.
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
| `session_id` at PAR | Remove from the profile; ask PAP (Section 6.1) | The G8 mix-up stays at PAP's baseline |
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

## 6. Upstream asks

### 6.1 To PAP

These help PAP whether or not Mission is used.

1. Add an optional `action` (a Company-documented identifier) and an
   optional typed charge (`amount` and `currency`) to operations. Standing
   permissions then become checkable by machine (G5).
2. Define an OpenAPI keyword that marks endpoints returning operations (G6).
3. Make the confirm checks normative and ordered, and give a status for "the
   operation as it is" (G7).
4. Bind the User ID at authorization, for example `session_id` in a pushed
   request, not only the client at redemption (G8).
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
| T1 | Revision at 90.00 USD, or with a different SKU | Confirm with `standing_permission` under the Mission token | `403`, `insufficient_scope`, `mission_denial="insufficient_authority"`. The operation stays `proposed`. No charge. |
| T2 | Revision at 70.00 USD | Same | `200`. `confirmation.mission` is set. Exactly one exchange. |
| T3 | Mission token (`poppy:read`) | Call a direct-execution write endpoint; ask the Company Agent to do it; call an operation-aware endpoint | The first two return `insufficient_scope` and have no effect. The third returns `202` with a proposal. |
| T4 | Company requires Missions for standing permissions | An ordinary `poppy:write` token confirms with `standing_permission` | `403 user_approval_required` |
| T5 | Revoke the Mission between proposal and confirm, in settings and by RFC 7009 | Confirm, then refresh | `401 invalid_token`, then `invalid_grant` with `mission_error="revoked"`. An operation confirmed before revocation still completes. |
| T6 | Mission A covers this exchange; Mission B covers returning `itm_9Zp` | A's token confirms B's return | `403`, `mission_denial="insufficient_authority"` |

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
