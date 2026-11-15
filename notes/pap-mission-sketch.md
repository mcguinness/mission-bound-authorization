# Design note: Personal Agent Protocol evaluation and an adoption-first Mission sketch

Status: working note, not an Internet-Draft and not normative. Nothing here
is adopted by PAP or by the Mission family.

Reviewed against Personal Agent Protocol ("Poppy") version 1.0, published
2026-11-14: the [specification](https://personalagentprotocol.org/docs/1.0/spec),
the [Operations extension](https://personalagentprotocol.org/docs/1.0/extensions/operations)
version 3, the [extensions list](https://personalagentprotocol.org/docs/1.0/extensions),
the [Mediated Sign-In extension](https://personalagentprotocol.org/docs/1.0/extensions/mediated-sign-in),
and the [roadmap](https://personalagentprotocol.org/docs/roadmap). Mission
drafts read at `main` bd904a85. PAP section numbers are cited as "Spec 4.7"
and "Ops 6". Rounds 1 to 4 of this note reviewed Draft 0.1; Section 9 lists
what version 1.0 changed in the sketch.

## Recommendation

- PAP 1.0 is a sound base. Its Operations extension (version 3) solves the
  execution problems without an endpoint of its own: an approval covers one
  immutable revision of exact terms, travels with a repeat of the original
  request, and never performs an action twice (Ops 1, 6, 7).
- PAP's gap is still authority, not execution. Scopes are account-wide, and
  an agent approval, made "on an instruction the User gave it", rests on the
  agent's word: the Company never sees the instruction (Ops 5, 8.1).
- PAP's roadmap names the fix it wants: mandates, "where the User signs once
  for a class of actions with limits", with "the User approves on the
  Company's own page or in its app" as one of three approaches (roadmap,
  Signed approvals). Mission is that approach, built from OAuth the Company
  already runs: **a Mission is the User's instruction, approved on the
  Company's own sign-in page, which the Company checks when the agent's
  approval arrives.**
- The first profile adds no endpoint, no approval member, and no error
  code. The cost sits in the Company's AS and in the service that hosts its
  governed actions. The AS accepts the Mission Intent through PAR, which
  PAP 1.0 already supports (Spec 4.2), becomes a core Mission Issuer, and
  binds Mission tokens to DPoP keys. The service checks the carried
  authority when an approval arrives.
- The earlier Draft 00 should still be narrowed to this profile. Section 5
  lists what moves out and what each cut loses.

## 1. PAP evaluation

### 1.1 What PAP gets right

- **Standards reuse with a small surface.** Client ID Metadata Documents
  with `private_key_jwt` and an assertion addressed to the issuer (Spec
  4.1), PKCE with RFC 9207 `iss` checking and PAR where the Company asks
  for it (Spec 4.2), RFC 8628 device sign-in under RFC 10027's best
  practices (Spec 4.3), RFC 8707 per-service tokens (Spec 4.5), RFC 7009
  sign-out (Spec 4.6), and DPoP at the Company's choice (Spec 4.5).
- **Privacy by construction.** Pairwise User IDs the agent assigns and
  never derives from personal data (Spec 5.1), delegated keys that each
  sign for one User ID (Spec 5.2), blind signing so the agent's own servers
  need not learn which Companies a User works with (Spec 10.7), and
  signed-out Sessions by default (Spec 5.4).
- **Progressive adoption.** Both sides ignore unknown extensions and fields
  (Spec 3.3), a newer minor version doesn't break older implementations
  (Spec 3.4), and a Company can serve signed-out Sessions without an OAuth
  server (Spec 3.2).
- **Operations get the execution semantics right.** An approval covers one
  revision, and the Company performs only what that revision describes
  (Ops 3). APIs, MCP servers, conversations, and websites all use the same
  approval and the same checks (Ops 4, 6). A retry with the same approval
  never performs twice, an unknown outcome is never reported as a failure,
  and the Company remembers an operation until the approved revision
  expires (Ops 7). A Company can decline an approval for its own reasons,
  with no reason codes to work around (Ops 6).
- **Approval boundaries are explicit.** Text from a Company is never the
  User's approval (Spec 10.1, Ops 5), a message's text approves nothing
  (Ops 6), a reference from a web page is not a credential (Ops 8.2), and
  tokens and codes stay out of model context (Spec 10.2).
- **Consequence is described.** Scope hints say whether a scope's actions
  change nothing, change something reversibly, or change something
  irreversibly (Spec 4.7).
- **Honest about proof.** An approval is the agent's statement, and
  accepting only user approvals "still relies on the Personal Agent's
  statement" (Ops 8.1). The security considerations name the risks PAP
  accepts, such as sign-ins someone else started (Spec 10.8).

### 1.2 Gaps

Ranked by consequence for agents acting on a User's behalf.

| # | Gap | Where | Consequence |
| --- | --- | --- | --- |
| G1 | Authority is account-wide and task-blind | Spec 4.7, "Scopes say what account access a sign-in grants"; Spec 4.5, a sign-in without `resource` "grants every resource the Company offers Personal Agents" | One write-capable token serves every task. Nothing narrower than a scope plus an audience exists. |
| G2 | Agent approvals are invisible to the Company | Ops 5, the agent approves "on an instruction the User gave it"; Ops 8.1, the Company "relies on the Personal Agent" | The Company cannot bound, audit, or revoke the instruction. An injected or buggy agent's approval looks the same as a legitimate one. The Company's levers are declining agent approvals for an action (Ops 6) and revoking the whole `client_id` (Ops 8.1). |
| G3 | No proof of the User's approval | Ops 8.1: a Company that wants to see the User approve "has the User confirm on its own website or in its app", and "This extension doesn't define that step". Signed user approvals are on the roadmap. | A Company that needs evidence must step outside the protocol. |
| G4 | No per-task lifecycle | Spec 5.5, sign-out revokes every refresh token for the account, and disconnecting does the same | Ending one task's authority ends the agent's access to the account. |
| G5 | Agent approvals cannot be checked mechanically | Ops 3, `terms` keys are Company-defined and an operation names no action; Ops 5, the agent checks the terms against the instruction, and "This extension doesn't say how" | Two agents can reach different answers for the same instruction and the same terms. |
| G6 | Whether a request needs approval is not discoverable before it is sent | Ops 1, "A Company chooses which actions need approval" | With a write-capable token, a request the agent meant to start an approval can be performed at once. |

Resolved in 1.0, from the Draft 0.1 review:

- **G7, confirm atomicity and retries.** Ops 7 defines at-most-once across
  retries, the response to a retry of a performed operation, and the `503`
  while an outcome is unknown.
- **G8, code redemption checked only the Session's client.** Sign-in no
  longer knows the Session (Spec 5.4). What remains is the cross-device
  risk of a sign-in someone else started, which PAP accepts and limits
  (Spec 10.8). A Mission sign-in inherits it unchanged.
- **G9, no security considerations.** Spec 10 and Ops 8.

Mission addresses G1 to G4. G5 and G6 are PAP fixes (Section 6.1).

## 2. Where Mission fits

Operations performs an action only after the Company checks an approval, on
the request that performs it, and in PAP the Company is both the
authorization server and the resource server. So the Company can read
Mission state locally at the moment of commitment. That makes the approval
checks the natural, and nearly free, place to enforce a Mission.

| PAP concept | Mission concept |
| --- | --- |
| Agent approval on "an instruction the User gave it" (Ops 5) | Mission: approved Intent plus an Authority Set, held by the Company |
| An instruction such as "go ahead with any exchange under $20" (Ops 5) | `resource`, Subject, `actions`, `constraints` |
| User approval, `approver="user"` (Ops 6) | No version 1 equivalent. The `requires_action_approval` Common Constraint needs a verifiable action-bound approval, and a user approval is the agent's statement (Ops 8.1), so version 1 fails such entries closed. |
| Refresh token (Spec 4.4) | Mission-bound grant lineage |
| Revocation by RFC 7009 (Spec 4.6) | Mission revocation, which core lets a deployment couple to refresh-token revocation |
| Approval checks (Ops 6) | Resource-server enforcement of carried authority (core, resource-access) |
| Mandates with limits over time (roadmap) | A Mission, with Mission Metering for cumulative limits |

## 3. The sketch: Mission-backed agent approvals

A PAP extension named `karlmcguinness.com/mission`, version 1. PAP requires
the domain prefix (Spec 3.3) until PAP adopts the extension as `mission`.
It requires `operations` version 3. It profiles OAuth Mission core and the
Mission Resource Access Profile, and defines nothing those documents already
define.

### 3.1 What each side changes

| Side | Change |
| --- | --- |
| Company AS | Accept `mission_intent` and `authorization_details` through PAR at Direct Sign-In, and through the Mission Device Authorization companion at Device Sign-In (Section 3.4). Render the task and its authority on the existing consent page. Store the Mission. Issue a Mission-bound refresh token as a grant of its own, bound to the agent's DPoP key. Gate refresh on Mission state. Project the read scope for the default resource, and issue tokens for the actions service that carry the granted entries. |
| Company actions service | Host the governed actions at a service with its own resource identifier (Spec 4.5): an API, an MCP server, or the conversation endpoint where the Company Agent performs them. Under a Mission token, return an operation for every governed action, check the carried authority when an approval arrives (Section 3.7), and record the Mission with what it performs. |
| Company account settings | List the agent's active Missions, each with its goal, what was performed under it, and a revoke control. |
| Company prerequisites | A scope hinted `changes: "none"` that covers the reads a governed task needs (Section 3.3), and DPoP at the actions service (Section 3.5). |
| Personal Agent | Discover the extension. Declare it and `operations` version 3 (Spec 3.4). Sign in with PAR for each task, as a separate grant, with DPoP proofs. Keep each task's tokens in the trusted runtime, not the model. Approve with `approver="agent"` under the Mission token. Stop when the Company lacks the extension. Revoke the Mission when the task ends. |

### 3.2 Flow

```
User        Personal Agent                     Company AS / actions service
 |  "exchange the jacket if ≤ $75 extra"
 |---------->|  PAR: mission_intent + authorization_details + scope=orders:read
 |           |-------------------------------->|
 |           |  open authorize?request_uri=...  |
 |<----------------------------------------------| consent page: task + authority
 |  approve (signs in at the Company) ---------->| Mission recorded
 |           |  code (Spec 4.2)                 |
 |           |<---------------------------------| Mission refresh token, read token
 |           |  refresh, resource=actions service (Spec 4.5)
 |           |<---------------------------------| token carrying the exchange entry
 |           |  POST .../orders/ord_7Hk2/exchanges
 |           |-------------------------------->| 403 approval_required, $70.00
 |           |  same request + Poppy-Approval, approver="agent"
 |           |-------------------------------->| Mission covers terms? yes: perform once
 |           |<---------------------------------| the exchange; Mission recorded with it
```

### 3.3 Discovery

The Company lists the extension in `poppy.json` beside `operations`, with
an entry for each major version it supports (Spec 3.3):

```json
"extensions": {
  "operations": [{ "version": "3" }],
  "karlmcguinness.com/mission": [{
    "version": "1",
    "actions": {
      "exchange": {
        "resources": ["https://api.example.com/actions"],
        "constraints": ["order_id", "item_id", "replacement_sku", "max_amount"]
      },
      "return": {
        "resources": ["https://api.example.com/actions"],
        "constraints": ["order_id", "item_id"]
      }
    }
  }]
}
```

The `operations` entry lists no `endpoint` because this Company returns no
operations on its website (Ops 2).

- `actions` maps each operation action the Company governs to the services
  where the agent requests it and the `constraints` keys the Company
  enforces for it.
  - Each entry in `resources` is a service with its own resource
    identifier, which its protected resource metadata names (Spec 4.5). A
    Mission entry for the action names one of them. A task that uses one
    interface needs one entry.
  - A Common Constraint name (`max_amount`, `time_window`) has its
    resource-access meaning.
  - Any other name is an operation `terms` key and constrains that term to
    equal the given value.
- An action listed with `max_amount` is chargeable. The AS refuses an entry
  that grants it without `max_amount`, so every grant for a chargeable
  action has a money bound. An action listed without `max_amount` never
  carries a charge component (Section 3.7), not even a deduction from a
  refund.
- Version 1 never lists `requires_action_approval`. Its `true` value needs
  a verifiable action-bound approval, and a user approval is the agent's
  statement (Ops 8.1). The AS therefore refuses an entry carrying `true`
  and never grants it with the key dropped, and the actions service fails
  such an entry closed. Resource-access defines `false` as equivalent to
  omission, so the AS grants an entry carrying `false` without the key.
  That removes nothing the entry granted.
- **The agent never drops a limit the Company cannot hold.** The agent maps
  every limit in the User's permission to a constraint key the Company
  lists for that action. It never omits a limit the Company does not list,
  and never widens one to a key the Company does list.
  - A money limit on an action listed without `max_amount` is already held,
    because such an action carries no charge component (Section 3.7).
  - When a limit has no listed key, the agent tells the User which limit
    the Company cannot hold. It proceeds only on the User's choice:
    - the task without that limit, which the consent page then renders as
      the broader authority it is;
    - per-revision user approval under an ordinary token, outside this
      profile (Section 3.10);
    - not proceeding.

    The choice is taken through the agent's own interface (Ops 5), never
    from the planner that did the mapping.

  This is this profile's rule, the per-constraint counterpart of core's
  Downgrade by Omission.
- Each governed action has a **contract version**: the documented meaning
  of the action and the complete set of `terms` keys that describe its
  effects. For a chargeable action, it also defines how the action's
  charge components, credits, and net charge are computed (Section 3.7).
  - The AS records in the Mission Record the version of each governed
    action current at the approval event.
  - The actions service evaluates an approval against the recorded
    version. It refuses with `insufficient_authority` a revision whose
    `terms` carry a key outside that version's set, or that the Company can
    perform only under a different version.
  - A changed contract needs a new Mission.

  The version stays in the Company's own Mission Record, so nothing changes
  on the wire. The alternative would put it in `authorization_details`,
  through versioned action identifiers such as `exchange.v1`.
- **Read scope.** PAP requires `scope` on every sign-in request and grants
  at least one scope (Spec 4.7). Core projects `scope` only where the
  projection is no broader than a carried entry, and refuses a requested
  `scope` for a target that consumes `authorization_details` (core, Scope
  Projection). So the agent requests, for the default resource
  `https://{organization.domain}`, Company scopes hinted `changes: "none"`
  that the task's reads need (Spec 4.7), and the authority proposal carries
  a read entry they project from. The AS's projection mapping is the
  Company's own configuration (core projection step 2); the hints let the
  agent choose before sign-in. A Company with no such scope cannot offer
  this profile: core refuses the projection (step 5), and a PAP sign-in that
  grants no scope ends as a decline (Spec 4.7).
- **The actions service consumes `authorization_details`.** For a Mission
  token, it evaluates the carried entries, and the AS issues its tokens with
  the action entries and no `scope` (core projection step 4). The default
  resource and the actions service are distinct audiences, so each follows
  one rule, and neither specification needs an exception. Section 6.2 asks
  whether one resource could serve both.
- The actions service identifies itself by its resource identifier for
  every path beneath it, so the default `exact` `resource_match` applies to
  every governed request.

Core makes Mission metadata optional and attaches obligations to
advertising it. This profile requires the Company's AS to advertise
`mission_bound_authorization_supported: true`. Under core, that obliges the
AS to publish `pushed_authorization_request_endpoint` and to list a
supported type in `authorization_details_types_supported`. This profile
further requires `mission_resource_access` among those types.

The agent declares both extensions in `Poppy-Extensions` on every request
in the Session (Spec 3.4):

```
Poppy-Extensions: "operations";v="3", "karlmcguinness.com/mission";v="1"
```

Operations already forbids returning an operation to a request that does
not declare version 3 (Ops 2). A Mission-aware service refuses a Mission
token on a request that does not declare both with `extension_required`
(Spec 3.3), since it handles a governed action under a Mission token only
with them.

Operations returned to an agent that declares the extension carry `action`,
the identifier from which the checks derive. PAP implementations ignore
fields they do not recognize (Spec 3.3), so the added member is backward
compatible.

### 3.4 Creating a Mission

Direct Sign-In (Spec 4.2) with its request pushed through PAR, because core
accepts `mission_intent` on the authorization-code path only through PAR.
PAP 1.0 supports this directly: a Company MAY require PAR, and an agent
SHOULD use it whenever the metadata lists the endpoint (Spec 4.2). The
decoded PAR body:

```
POST https://auth.example.com/oauth/par
DPoP: <proof>

response_type=code
client_id=https://agent.example/agent.json
redirect_uri=https://agent.example/oauth/callback
scope=orders:read
prompt=consent
state=Xq81vR
code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
code_challenge_method=S256
mission_intent=<Submission envelope>
authorization_details=<entries>
client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion=<private_key_jwt>
```

The DPoP proof on the pushed request lets the Company bind the code to the
key (Spec 4.2). `prompt=consent` is PAP's rule unless the redirect returns
only to the device that opened the authorization URL (Spec 4.2). The
request carries no `resource`, as PAP recommends, so the grant covers every
service the Company offers (Spec 4.5).

The Submission envelope:

```json
{
  "intent": {
    "goal": "Exchange the Stormline Jacket (M) on order ord_7Hk2 for the insulated version if it costs no more than $75 extra.",
    "target_resources": [
      "https://example.com",
      "https://api.example.com/actions"
    ],
    "expires_at": "2026-11-16T00:00:00Z"
  }
}
```

The authority proposal has two entries:

```json
[
  { "type": "mission_resource_access",
    "resource": "https://example.com",
    "actions": ["orders:read"] },
  { "type": "mission_resource_access",
    "resource": "https://api.example.com/actions",
    "actions": ["exchange"],
    "constraints": {
      "order_id": "ord_7Hk2",
      "item_id": "itm_4Qa",
      "replacement_sku": "stormline-insulated-m",
      "max_amount": { "amount": "75.00", "currency": "USD" }
    } }
]
```

The read entry projects to `orders:read`, which the Company's APIs already
enforce unchanged. The exchange entry is consumed by the actions service.
One entry per action suffices. Earlier rounds split each action into read,
confirm, and cancel entries, because Draft 0.1 let an agent read and cancel
operations. Operations version 3 has neither, and a request without an
approval performs nothing. So the money cap applies only when an approval
arrives, and the agent can still see a quote above the cap (Section 3.6).

The agent then opens `authorize?client_id=...&request_uri=...` in the User's
browser. The consent page renders the goal and the structured authority,
for example "See your orders. Exchange item itm_4Qa on order ord_7Hk2 for
Stormline Insulated Jacket (M), for at most $75.00 more after the credit
for this jacket, fees and tax included. Until November 16." The User signs
in and approves, which satisfies PAP's rule that the User signs in
themselves (Spec 5.4). The code exchange is PAP's, unchanged.

**Device Sign-In.** An agent that cannot receive a redirect uses Device
Sign-In (Spec 4.3) under the Mission Device Authorization companion. The
device authorization request carries `mission_intent` and
`authorization_details`. The User approves on the Company's page on a
second device, and polling returns the Mission-bound tokens.
- The agent sends `scope`, as PAP requires (Spec 4.7), which the companion
  permits.
- The companion is experimental and opt-in. The agent uses it only where
  the AS advertises `mission_device_authorization_supported` beside
  `mission_bound_authorization_supported`; support is never inferred from
  generic device-grant support.
- #1202 is open only for acceptance of its reference remainder.

Device Sign-In's phishing risk applies unchanged (Spec 4.3, 10.8).

### 3.5 Tokens

The code exchange returns PAP's response, plus core's members:

```json
{
  "access_token": "eyJhbGciOi…Qp4w",
  "token_type": "DPoP",
  "expires_in": 3600,
  "refresh_token": "pat_M7c2…Rr4",
  "scope": "orders:read",
  "mission_id": "msn_8RfX2Lqv9TqM",
  "mission_expires_at": "2026-11-16T00:00:00Z",
  "authorization_details": [ "…the read entry…" ]
}
```

The agent then refreshes with `resource=https://api.example.com/actions`
for a token at the actions service (Spec 4.5):

```json
{
  "access_token": "eyJhbGciOi…Zt7m",
  "token_type": "DPoP",
  "expires_in": 600,
  "authorization_details": [ "…the exchange entry…" ]
}
```

- **A separate grant.** The refresh token is a Mission-bound refresh token,
  a grant of its own beside any ordinary refresh token or another Mission's.
  A Mission sign-in replaces none of them. Spec 4.7's replacement rule is
  for a sign-in that asks for more access in place of an existing grant, so
  the agent revokes nothing because of a Mission sign-in. The Company keeps
  each Mission's refresh token independent of the client's other refresh
  tokens for the account. Sign-out still means revoking all of them (Spec
  5.5).
- **DPoP binding.** Core binds a confidential client's refresh token by
  client authentication. PAP 1.0 shows why that is weaker here: when Users'
  devices can get client assertions, blindly or not, a refresh token copied
  from one User works for another User of the same agent (Spec 10.7). The
  profile therefore requires what PAP permits:
  - the agent sends DPoP proofs with its Mission sign-in and refreshes,
    with a key it uses for that User only (Spec 4.5);
  - the Company binds the Mission refresh token, and the access tokens for
    the actions service, to that key (Spec 4.4, 4.5).

  A service that accepts only Bearer tokens (Spec 7) can serve the read
  scope, but it cannot host governed actions under this profile. The
  binding is stricter than core and needs no core change.
- **The actions-service token carries no `scope`.** RFC 6749 has no empty
  `scope`, so the response cannot report the difference from the grant's
  scope by omission; core states the same limit. The response reports the
  grant in `authorization_details`, and the agent reads that, never
  `scope`, for this token. Section 6.1 asks PAP to say so for a per-service
  token without scopes.
- No credential outlives `mission_expires_at`, per core.
- Access tokens stay opaque to the agent. Core profiles an RFC 9068 JWT or
  an opaque token resolved through introspection or issuer-local
  resolution. The latter suits a Company that is both the AS and the
  resource server.
- **Sessions are not constrained.** A refresh token serves any of the
  User's Sessions (Spec 4.4, 5.4), so a Mission does too. An agent should
  still give each task its own Session, as PAP suggests for parallel tasks
  (Spec 5), so that carts and conversations do not mix. Nothing in the
  profile depends on it.

### 3.6 Requests under a Mission token

At the default resource, a Mission token carries only the read scope, so
every write endpoint there already refuses it with `insufficient_scope`. So
does the Company Agent at a conversation endpoint on the default resource,
because a signed-in conversation "respects the token's scopes" (Spec 8.11).
At the actions service, the extension adds two rules:

1. **Every governed action returns an operation.** A request under a
   Mission token without an approval performs nothing. The service returns
   `approval_required` with the operation (Ops 4) when a granted entry
   names the operation's action, whatever its constraints. Otherwise it
   refuses with `insufficient_scope` and
   `mission_denial="insufficient_authority"`, and returns no operation.
   Showing terms above the cap performs nothing, so the agent can show the
   User a $90 quote without being able to have it performed.
2. **An action the service does not govern is refused.** No entry names it,
   so the service refuses with `insufficient_scope` and
   `mission_denial="insufficient_authority"`.

Together, these give the no-direct-execution property without a dedicated
proposal endpoint, so G6 cannot bite an agent holding only a Mission token.

### 3.7 The approval check

The request is PAP's, unchanged: the same request again, with the approval
in `Poppy-Approval` (Ops 6):

```
POST https://api.example.com/actions/orders/ord_7Hk2/exchanges
Poppy-Session: eyJ0eXAiOiJwb3BweS1zZXNzaW9uK2p3dCIs…
Poppy-Version: 1.0
Poppy-Extensions: "operations";v="3", "karlmcguinness.com/mission";v="1"
Authorization: DPoP <Mission access token for the actions service>
DPoP: <proof>
Content-Type: application/json
Poppy-Approval: operation_id="exc_5Rt2", revision="1791487200-k3Jd9Qx2mW8v", approver="agent", approved_at=1791487255, reference="apr_01JD8ZK3R4"

{ "item_id": "itm_4Qa", "replacement_sku": "stormline-insulated-m" }
```

The Company's added check:

```
request(req, token):                                    # after Spec 5.3 and Spec 7 checks
  if token has no Mission:
    if req carries approver="agent", the Company governs the action,
       and policy.missions_required:
      decline: approval_declined                        # Ops 6, "such as approver"
    continue as PAP

  op = the operation req asks for, as the Company computes it (Ops 3)
  if no granted entry names op.action:                  # Section 3.6, rule 2
    refuse 403 insufficient_scope, mission_denial="insufficient_authority"
  if req carries no approval:                           # Section 3.6, rule 1
    return 403 approval_required with op                # Ops 4
  C = decide(op, token, now)
  v = the contract version the Mission Record holds for op.action
  if op needs a version other than v, or op.terms has a key outside v's set:
    refuse 403 insufficient_scope, mission_denial="insufficient_authority"
  Ops 6 checks 1 to 3; on a failure, respond as Ops 6 says    # new revision, or Ops 7 replay

  in one transaction that locks the Mission record:     # revocation takes the same lock
    t = now                                             # the admission instant
    if op is performed or being performed: respond as Ops 7
    if t >= the approved revision's expires_at: respond as Ops 6 check 3
    if the Mission's state != active or t >= its expires_at:
      refuse 401 invalid_token
    if no entry in C holds time_window at t:
      refuse 403 insufficient_scope, mission_denial="insufficient_authority"
    recheck at t the Company's eligibility rules that depend on mutable
      state, such as one exchange per order item; if one fails:
      decline: approval_declined, reason "nothing was changed"   # Ops 6
    record op as being performed at t, with the Mission
  perform once                                          # Ops 7

decide(op, token, t):
  if op has a charge component and the Company lists op.action without max_amount:
    refuse 403 insufficient_scope, mission_denial="insufficient_authority"
  A = granted entries for this service whose actions include op.action,
      each with any requires_action_approval: false removed     # false = absent
  if any entry in A has a resource_match value or constraint key the
     Company does not enforce for op.action:                    # includes requires_action_approval: true
    refuse 403 insufficient_scope, mission_denial="constraint_unrecognized"
  C = entries in A for which every constraint holds for op at t
  if C is empty:
    refuse 403 insufficient_scope, mission_denial="insufficient_authority"
  return C

holds(key, value, op, t):
  max_amount              -> op's net charge, as the recorded contract version
                             computes it: charge components minus credits;
                             <= value in the same currency, exact decimal
  time_window             -> t is inside the window
  any other enforced key  -> op.terms[key] equals value
```

- **Every applicable entry is checked before one is chosen.** A key the
  Company does not enforce, in any entry that names the action, fails the
  request closed (core and resource-access). Only then are the remaining
  entries treated as alternative grants. Entry order never changes the
  outcome.
- **The Mission checks are token checks.** Ops 6 makes its own checks
  "after the Session header checks in spec 5.3 and the token checks in
  spec 7". A Mission refusal is the resource server's enforcement of the
  token's carried authority, so it is a token check and uses core's
  `insufficient_scope` (core, Denial Responses). At the actions service, a
  Mission token carries no scope, so the covering entries stand in for the
  scope check Spec 7 makes for an ordinary token.
- **`requires_action_approval: true` fails closed.** It is never among the
  Company's enforced keys in version 1 (Section 3.3), so the AS refuses it,
  and an entry that carries it anyway fails with `constraint_unrecognized`.
  It is not satisfied by `approver="user"`, which is the agent's statement
  (Ops 8.1).
- **Charges are bounded, never inferred.** The recorded contract version
  (Section 3.3) defines the money an operation moves:
  - **Charge components** are every amount the User pays, every fee and tax
    included, plus any deduction from a credit. A deduction is any amount by
    which a credit falls short of what the contract version computes for it.
  - **Net charge** is the charge components minus the credits.

  `max_amount` bounds the net charge, so for an exchange it bounds the
  replacement's price, less the credit for the returned item, plus fees and
  tax. An action listed without `max_amount` carries no charge component.
  A fee added in a later revision, including one taken out of a refund, is
  therefore refused rather than covered by omission.
- **Admission is judged at one instant and serializes with revocation.** An
  approval is admitted only if, at the instant it commits, four things hold:
  - the Mission is active and before its `expires_at`;
  - the operation is not yet performed or being performed;
  - the approved revision is unexpired;
  - a covering entry's `time_window`, if any, contains that instant.

  Revocation updates the same Mission record under the same lock, so an
  approval and a revocation cannot interleave. Expiry and time windows are
  judged at the admission instant, not when the request arrived, so an
  approval that waits on the lock past a bound is refused. Once the Company
  acknowledges a revocation, it admits no further approval under that
  Mission.
- **An eligibility failure is a decline.** The same transaction rechecks
  the Company's own eligibility rules that depend on mutable state, such as
  one exchange per order item. An approval that fails one is declined
  (Ops 6), performing nothing. The agent then follows Ops 6: it does not
  send that approval again, and asks the User before approving a new
  revision. When two operations race on such a rule, at most one is
  performed and the other is declined.
- **The approved contract governs.** An approval is evaluated against the
  contract version the Mission Record holds for the action (Section 3.3).
  A revision that adds a `terms` key outside that version, or that needs a
  newer version, is refused, even when every listed constraint holds.
- **The Mission in force is the token's.** An operation can be approved in
  any Session of the same agent and User signed in to the same account
  (Ops 3), so an operation returned under an ordinary token, or under
  another Mission's token, can be approved under this Mission's token. The
  Mission checked is always the one whose token accompanies the approval,
  never the one under which the operation was returned.
- **A Mission token acts only within its Mission**, whatever `approver`
  says. If the User wants a revision the Mission does not cover, the remedy
  is a new Mission. Approving with an ordinary token instead is the separate
  PAP workflow of Section 3.10, outside this profile.
- **`policy.missions_required` is the Company's adoption lever.** The
  Company declines an agent approval under an ordinary token for an action
  it governs. Ops 6 lets a Company decline "for its own reasons, such as
  `approver`", with no reason codes, so nothing new appears on the wire.
  User approvals keep working as PAP defines them.

**Refusals.** PAP sends access token errors in `WWW-Authenticate` and
other errors as a JSON body (Spec 7). Operations sends its outcomes as JSON
bodies (Ops 4, 6).

| Condition | Status | `WWW-Authenticate` | Body |
| --- | --- | --- | --- |
| Mission token: no granted entry names the action, or none covers the approved request (amount, terms, contract version, time window) | 403 | `DPoP error="insufficient_scope", mission_denial="insufficient_authority"`, no `scope` attribute | No operation |
| Mission token: a granted entry names the action with a key or `resource_match` the Company does not enforce | 403 | `… mission_denial="constraint_unrecognized"`, no `scope` | No operation |
| Mission token at a write endpoint of the default resource | 403 | `DPoP error="insufficient_scope"`, as for any token without the needed scope. It carries `mission_denial="insufficient_authority"` and no `scope` where the endpoint recognizes the Mission token. | Whatever the endpoint returns today |
| Mission token with the Company Agent on the default resource | 200 or 202 | None | An `authorization` event (Spec 8.11) |
| Mission not active, or past its `expires_at`, at admission or on any request | 401 | `DPoP error="invalid_token"` | None |
| Mission token on a request that does not declare both extensions | 403 | None | `{ "error": "extension_required", "extension": "karlmcguinness.com/mission" }` (Spec 3.3) |
| Ordinary token, agent approval, where the Company requires Missions | 403 | None | `approval_declined` (Ops 6) |
| A Company eligibility rule fails at admission | 403 | None | `approval_declined`, with a `reason` stating that nothing was changed |

- **No `scope` on a Mission refusal.** Where the Company recognizes the
  Mission token, its `insufficient_scope` carries no `scope` attribute,
  because no scope remedies a Mission refusal. RFC 6750 makes the attribute
  optional, and PAP's "which the response names in the `scope` attribute"
  (Spec 7) describes the ordinary case rather than requiring it.
- **Who sees `mission_denial`.** The Company sends it only in a response to
  a validly signed, audience-correct Mission token (core). An agent treats a
  value it does not recognize as `insufficient_authority` (core).
- **What the agent does on any `insufficient_scope` under a Mission
  token**, with or without `mission_denial` and with or without a `scope`
  attribute, and on an `authorization` event in a conversation under one:
  - It never requests more scopes.
  - It never retries the request with another credential.
  - It never approves the same revision again under this Mission.
  - It tells the User. Proceeding needs a new Mission, or the User acting
    on their own authority.

  This replaces PAP's usual response to `insufficient_scope`, a refresh or
  a new sign-in for the named scopes (Spec 7, 8.11), for Mission tokens
  only. Only an agent that declares the extension holds Mission tokens, so
  every agent this reaches implements it.
- **On `invalid_token`**, the agent refreshes once. If the refresh fails
  with `mission_error`, the agent stops the task.
- **On `approval_declined`**, the agent follows Ops 6. It does not send the
  approval again, and it approves no new revision for the action without
  asking the User.

A performed action's response is the action's own (Ops 6), with nothing
added. The Company records the Mission with each operation it performs
under it, using core's `mission` claim shape
(`{ "id": "msn_8RfX2Lqv9TqM", "issuer": "https://auth.example.com" }`),
and shows those operations against the Mission in account settings
(Section 3.8).

### 3.8 Ending a Mission

- **Expiry** at the Mission's `expires_at`.
- **The User revokes it** in the Company's account settings. Core requires
  an authenticated means to revoke by `mission_id`, and the settings page
  is that means. Disconnecting the agent still revokes everything (Spec
  5.5).
- **The agent revokes it** by revoking the Mission refresh token with RFC
  7009 (Spec 4.6). This profile couples the two, as core permits. An agent
  revokes the Mission when its task is done. Revoking one refresh token is
  not sign-out while the agent holds others for the account (Spec 5.5).

Afterward:

- The Mission's access tokens fail with `invalid_token`, because the
  Company checks Mission state on each request.
- Refresh fails with `invalid_grant` and `mission_error` set to `revoked`
  or `expired`. The agent's Sessions continue, signed out or signed in
  under its other grants.
- An approval racing the revocation is admitted only if it committed
  before the Company acknowledged the revocation (Section 3.7).
- Operations performed before the end continue. Authority was checked at
  the commit point.
- An operation returned but not performed stays unperformed. An approval
  of it under another Mission's token is checked against that Mission
  (Section 3.7), and one under an ordinary token is ordinary PAP (Section
  3.10).
- To learn the outcome of an operation whose result was in doubt (Ops 7)
  after the Mission ends, the agent uses an ordinary signed-in Session, or
  asks the User. That is recovery under the account's own authority, not
  Mission authority.
- Other Missions are unaffected: each is a separate grant (Section 3.5).

### 3.9 Channels

| Channel | Rule |
| --- | --- |
| OpenAPI | Governed actions sit at an API with its own resource, and approvals arrive in `Poppy-Approval` (Ops 6). Write endpoints on the default resource refuse the Mission token. |
| MCP | An MCP server already takes tokens for its own resource (Spec 7), so it can be the actions service. Tools return operations as error results and take approvals in `_meta` (Ops 4, 6). An entry names the server's `url`. A server that accepts only Bearer tokens cannot host governed actions (Section 3.5). |
| Conversations | A conversation endpoint that declares its own resource (Spec 4.5) can be an actions service: the Company Agent returns operations and takes approvals in messages (Ops 4, 6), and performs only under the Section 3.7 check. Otherwise the Company Agent, held to the read scope, asks for authorization (Spec 8.11), which the agent treats as a Mission refusal (Section 3.7). A message's text never approves (Ops 6). |
| Web | Out of version 1. A Mission sign-in neither requests nor receives `poppy:browser-sign-in`, so a browser the agent joins under a Mission is signed out (Spec 6). Website operations, approved at `endpoint` and performed with the browser's own access (Ops 4, 6), never act under a Mission. A User who acts in their own browser, signed in to their own account, acts on their own authority. |

### 3.10 What the agent developer writes

```
company = discover(domain)                         # poppy.json + metadata (Spec 3)
if company does not list "operations" v3 and "karlmcguinness.com/mission" v1:
    tell the User the Company cannot hold this task's limits; stop
for each limit in the User's permission:                # Section 3.3
    if the Company lists no key for it on the action:  # a money limit on an uncapped action is held
        tell the User the Company cannot hold this limit
        continue only on the User's choice, taken in the agent's own interface:
            the task without the limit, per-revision user approval, or stop
reads = Company scopes hinted changes: "none" that the task needs   # Spec 4.7
session = start_session(company, extensions=["operations";v=3, mission;v=1])
grant = sign_in_with_mission(company, goal, entries, reads)  # PAR, Direct Sign-In, DPoP
task.grant = grant                                 # trusted runtime; the model never picks it
token = refresh(grant, resource=actions_service)   # Spec 4.5

r = call(token, POST /actions/orders/ord_7Hk2/exchanges, ...)
if r is approval_required:
    check r.operation.terms against the request (Ops 5)
    r = call(token, the same request, approval(r.operation, approver="agent"))
if r is insufficient_scope:                        # with or without mission_denial or scope
    tell the User this Mission does not cover it; no new scopes, no other credential
if r is approval_declined:
    tell the User; never resend it, never approve a new revision without asking   # Ops 6
if r failed or timed out:
    send it again with the same approval            # Ops 7
when task completes: revoke(grant.refresh_token)
```

Without the extension, the Mission workflow stops, and the agent tells the
User why. That follows core's no-downgrade rule. A client holding a Mission
Intent must not submit the same authority as bare `scope` or
`authorization_details` to an AS whose Mission support is neither
advertised nor otherwise established. It surfaces the inability instead.

Stopping also keeps any ordinary credential the agent holds out of the
task. Core requires this of a client acting under a Mission, unless a
deployment-defined enforcement path establishes the Mission for the request.

The User may separately choose to run an ordinary PAP workflow instead.
That is a different authorization, outside this profile, and it is the
User's conscious choice, not the agent's:

- It is available only at a resource the Company has not designated
  Mission-governed. It cannot pass around mandatory mediation where a
  deployment requires it.
- The agent cannot label its own fallback after a Mission refusal a new
  workflow. Retrying the task under an ordinary credential without the
  User's separate choice is the substitution core forbids.
- The agent holds an account-wide credential.
- It cannot assume that a request returns an operation rather than
  performing the action (G6).
- It therefore needs the User's approval before sending any request the
  Company does not document as returning an operation, and it approves
  with `approver="user"` after showing the revision (Ops 5).

## 4. Guarantees and losses

This profile bounds Mission tokens; it does not bound the agent. An agent
that holds any ordinary write-capable credential at the Company can act
outside every Mission on its own word (T11). The guarantees below hold for
what is done under a Mission token.

| Guarantee | Enforced by |
| --- | --- |
| Under a Mission token, the Company performs a governed action only on an approval whose operation's `action` and `terms` an active Mission entry covers | Company: the read-only scope at the default resource, and the approval check at the actions service |
| Under a Mission token, every governed request returns an operation before anything is performed | Actions service (Section 3.6) |
| The Company holds its own record of what the User approved, on its own page, and when, and of what was performed under it | Company AS (core Mission Record), account settings |
| After the Company acknowledges a revocation, it admits no further approval and issues no further token under that Mission. No approval is admitted after the Mission's or the revision's `expires_at`, or outside a covering `time_window`. | Approval admitted in one transaction with the state check, serialized with revocation on the Mission record and judged at its commit instant; core issuance gating |
| A chargeable action is performed only within a bound on its net charge, and an action listed without one carries no charge component | AS refuses an uncapped entry; approval check on the net charge, as the recorded contract version computes it |
| No limit the User set is dropped silently | Agent maps every limit to a listed key, or takes the User's choice through its own interface (Section 3.3) |
| An approval is held to the action contract the User approved; a changed contract needs a new Mission | Contract version recorded in the Mission Record; approval check |
| The Mission checked is the one whose token carries the approval | Approval check (Section 3.7) |
| Revoking one Mission never ends another Mission or the agent's ordinary access | Separate grants (Section 3.5) |
| A Mission token copied from one User's device does not work for another User of the same agent | DPoP binding of the Mission refresh token and actions-service tokens (Section 3.5) |
| The planner cannot choose a broader task credential | Agent's trusted runtime. The Company cannot verify this. |

| Not provided in version 1 | Consequence | Where it comes back |
| --- | --- | --- |
| Cumulative limits (count, total spend) | Two operations under one Mission can each be performed if each fits. Narrow entries, such as order and item equality, limit this in practice. PAP's roadmap mandates, "transfers of up to $50 a week", need it. | Mission Metering (`max_calls`, `max_budget`) |
| Verified per-revision user approval | `approver="user"` stays the agent's statement (Ops 8.1). An entry with `requires_action_approval: true` is refused rather than satisfied by it. | Mission Transaction Authorization, or PAP's signed user approvals (roadmap) |
| Website operations | A Mission never acts in a browser (Section 3.9). | A later version, where the website applies the Section 3.7 check to its own requests |
| Mediated Sign-In | It has no consent page, so it creates no Mission. PAP plans to retire it on 2027-03-17 (roadmap). | Nothing needed |
| Conditions outside `terms` | Only `terms` and Common Constraints are checked. Summary prose is not. | Ops 3 already requires every effect in `terms`. A Company governing an action puts its conditions there. |
| Other credentials the agent holds | An ordinary write-capable token is not bounded by any Mission. It can approve with `approver="user"` on the agent's word (T11). Core forbids this for a Mission's task, but the Company cannot observe the violation. | Company policy: decline agent approvals under ordinary tokens (Section 3.7), and issue agents no write-capable scope for the governed actions, so every agent write to them goes through a Mission |
| Governed actions on the default resource | A Company hosts them at a service with its own resource. | Section 6.2, item 5 |
| Missions across Companies | Each Company sees only its own Mission. Aggregate limits are the agent's job. | Cross-Domain companion, opt-in, at the cost of correlation (Section 5) |

The profile claims no assurance level beyond Baseline Issuance. It adds two
capabilities on top:

- **A state check at approval, serialized with revocation.** This is the
  Architecture's freshness half-step: issuer-local resolution on each
  request, plus the serialization boundary between a revocation and an
  effect, which the Architecture says a per-use read alone does not supply.
- **Enforcement of the carried authority at one resource server**, the
  actions service, for actions that go through operations.

It does not claim Runtime-Enforced. It has no PDP, no permits, and no
runtime evidence, and paths outside the actions service are covered only by
the read-only scope.

## 5. Disposition of Draft 00

The earlier draft (Draft 00, 9 October 2026; 76 KB; 30 conformance cases)
should be narrowed to Section 3. Three findings drive this, and version 1.0
sharpens the first.

1. **It replaces PAP's proposal model.** Draft 00 adds an agent-called
   proposal endpoint with `request_id` and revision members. In Operations
   version 3 the Company returns the operation from the agent's own
   request (Ops 4), and the operation ID identifies retries (Ops 7). The
   draft's goal, never executing when the agent meant to propose, is met by
   a Mission token that carries no write scope and by Section 3.6.
2. **It puts machinery into the first profile that PAP or core already
   supply.**
   - `parameter_digest`: PAP revisions are immutable and held by the Company
     (Ops 3).
   - `account_ref`: the Company binds the account to the grant.
   - `request_id`: the operation ID already serves.
   - Ten `pap_*` constraints: `terms`-key equality plus `max_amount` covers
     them.
   - New error codes: `insufficient_scope` with `mission_denial`, and PAP's
     own `approval_declined`.
   - The scope-omission exception: a read entry projects to a Company read
     scope.
3. **Its target architecture undoes PAP's privacy design.** One Mission
   shared across Companies correlates the User at each of them, despite
   pairwise User IDs (Spec 5.1). Draft 00 notes the correlation but treats
   it as the goal. Per-Company Missions keep the property. Cross-Company
   work is a later composition that a User opts into.

| Draft 00 element | Disposition | What is lost |
| --- | --- | --- |
| Proposal endpoint, `request_id`, `revises_operation_id`, `expected_revision` | Remove | Nothing. Ops 4 and Ops 7 cover it. |
| `session_id` at PAR | Remove (rounds 1 to 4 retained it) | Nothing. Sign-in no longer knows the Session (Spec 5.4). |
| `account_ref` | Remove | Cross-client account comparison, which no check needs |
| `parameter_digest` | Remove | A client-side tamper check of a revision the Company holds and cannot change (Ops 3) |
| `pap_*` constraints and the retail profile | Replace with `terms`-key equality and Common Constraints | Range checks other than `max_amount` and `time_window` |
| `pap_commit_limit` | Defer to Metering | Cumulative counts (Section 4) |
| Scope-omission exception | Remove | Nothing |
| `mas_join` mode | Remove | Nothing for PAP. A PAP Company already changes its AS. |
| ARAP approval object | Defer | Verified per-revision approval (Section 4) |
| Enforcement statement URI | Remove | Coverage is stated by the rules of Sections 3.6 and 3.9 |
| One Mission per Session | Remove (rounds 3 and 4 retained it as one Session per Mission) | Nothing. Missions are separate grants (Section 3.5), and a Mission never joins a browser (Section 3.9). |
| Cross-domain projection, ID-JAG (Section 16 of Draft 00) | Out of version 1 | Section 4 |
| 30 conformance cases | Replace with the tests in Section 7 | Coverage of removed mechanisms only |
| Separate proposal/read and commit entries | Remove (rounds 1 to 4 retained them as per-phase entries) | Nothing. Operations version 3 has no read or cancel, and a request without an approval performs nothing. |
| Admission inside one transaction with the state check | Retain, as approval admission (Section 3.7) | Nothing |

## 6. Upstream asks

### 6.1 To PAP

These help PAP whether or not Mission is used. Sending them is the owner's
call.

1. Add an optional `action` (a Company-documented identifier) and an
   optional typed charge (`amount` and `currency`) to the operation. Agent
   approvals then become checkable by machine (G5).
2. Let a Company say which actions need approval, in its API descriptions
   or tool annotations, before the agent sends the request (G6).
3. Say how a per-service token without scopes is reported (Spec 4.5,
   4.7). RFC 6749 cannot express an empty grant, so a service authorized by
   `authorization_details` needs its token response's `scope` left out
   without meaning "the scopes requested".
4. On the roadmap's Signed approvals topic, offer this profile as the
   "Company's own page" approach to mandates: the Company holds the record
   the User approved and checks each agent approval against it.

### 6.2 To the Mission family

1. **#1202, Device Sign-In.** The experimental Mission Device Authorization
   companion and the reference device flow are on `main`. #1202 is open
   only for acceptance of the reference remainder. Section 3.4 relies on
   the companion.
2. **#1203, in-house resolution.** Closed. Core admits issuer-local
   resolution, and the Architecture's half-step names it (Section 4).
3. **#1204, refresh-token sender constraint.** Ruled (D412): client
   authentication is a confidential client's refresh-token binding. This
   profile adds DPoP binding for PAP's reason (Section 3.5), which core
   permits.
4. **#1205, ordinary credentials.** Ruled (D412). Core forbids a client
   acting under a Mission to present an ordinary credential for the task,
   except through a deployment-defined enforcement path that establishes
   the Mission. Section 3.10's rule follows core.
5. **New, not filed: per-entry consumption at one audience.** Core projects
   `scope` for a target that consumes only `scope`, and refuses a requested
   `scope` value associated with a target that consumes
   `authorization_details` (core, Requested Scope Values). Version 1
   therefore keeps the actions service apart from the default resource. If
   core confirmed that one audience may consume `authorization_details` for
   some entries and a projected `scope` for others, a Company could keep its
   governed actions on its default resource. Recommendation: file it before
   asking a Company to split an API.

## 7. Decisive tests

Each test uses a Mission for "exchange `itm_4Qa` on `ord_7Hk2` for
`stormline-insulated-m`, `max_amount` 75.00 USD", at the actions service
`https://api.example.com/actions`, unless the setup says otherwise.

| # | Setup | Action | Required result |
| --- | --- | --- | --- |
| T1 | Revision at 90.00 USD | Request the exchange under the Mission token without an approval, then with an agent approval of that revision | First: `403 approval_required` with the operation. Second: `403`, `insufficient_scope`, `mission_denial="insufficient_authority"`, no `scope` attribute; nothing performed, no charge. Afterward, the agent sends no sign-in or refresh for more scopes, no retry with another credential, and no approval of that revision under this Mission. |
| T2 | Revision at 70.00 USD | Approve it with `approver="agent"` under the Mission token | The action's own success response. Exactly one exchange. The Company's record of the performed operation names the Mission, and account settings list it under the Mission. |
| T3 | Mission tokens | (a) Call a write endpoint on the default resource. (b) Ask the Company Agent on the default resource to perform the exchange. (c) At the actions service, request the exchange for a different SKU, then approve it. (d) Request an action the actions service does not govern. (e) Request the approved exchange without an approval. | (a) `403 insufficient_scope`, no effect. (b) An `authorization` event (Spec 8.11) and no effect; the agent does not sign in again. (c) `approval_required` with an operation, and its approval is refused with `insufficient_authority`; no effect. (d) `403`, `insufficient_authority`, no operation. (e) `approval_required` with the operation. |
| T4 | The Company requires Missions for agent approvals | An ordinary token with the action's write scope approves the exchange, first with `approver="agent"`, then with `approver="user"` | `403 approval_declined`, nothing performed; then performed as ordinary PAP, with no Mission recorded. |
| T5 | A revocation and an approval of the same operation run concurrently, repeated many times, with revocation both in settings and by RFC 7009 | Approve. After the revocation is acknowledged, approve again and refresh. | Every admitted approval committed before the revocation was acknowledged, and none after. Refused attempts have no effect. After acknowledgement: the approval returns `401 invalid_token`, and refresh returns `invalid_grant` with `mission_error="revoked"`. Actions admitted earlier complete. |
| T6 | Mission A covers this exchange; Mission B covers returning `itm_9Zp` | (a) A's token approves B's return operation. (b) An operation for this exchange, returned under an ordinary token in another Session, is approved under A's token. | (a) `403`, `insufficient_authority`; B's operation is not performed. (b) Performed once, recorded with Mission A: the Mission checked is the one whose token carries the approval. |
| T7 | Two exchange entries: one covers the revision; the other carries a key the Company stopped enforcing after issuance | Approve, with the entries in each order | `403`, `mission_denial="constraint_unrecognized"` in both orders. No effect. |
| T8 | (a) An authority proposal whose exchange entry carries `requires_action_approval: true`. (b) A grant that carries such an entry anyway. | (a) Sign in. (b) Approve with `user`, then with `agent`. | (a) The AS refuses the entry, or omits it and the granted `authorization_details` shows the omission. It never grants the entry with the key dropped. (b) `403`, `mission_denial="constraint_unrecognized"` for both approvals. No effect. |
| T9 | An authority proposal whose exchange entry carries `requires_action_approval: false` | Sign in, then approve a covered revision with `agent` | The granted `authorization_details` echoes the entry without the key, because `false` is the same as absent. The action is performed. |
| T10 | The Company lists `operations` version 3 but not the extension | The agent starts the Mission workflow | The agent makes no action request and tells the User why. It submits the authority neither as bare `scope` nor as `authorization_details`. |
| T11 | An operation returned under the Mission token at 90.00 USD; the agent also holds an ordinary credential | Approve it at the actions service with the ordinary credential and `approver="user"` | (a) Where the Company issues agents any write-capable scope for the action: performed as ordinary PAP, with no Mission recorded. The label is the agent's statement (Ops 8.1). (b) Where the Company issues agents no write-capable scope for the governed actions: no such credential exists, so the approval cannot happen. |
| T12 | Two operations for the same exchange, with two operation IDs, returned in two interfaces; the Company relies on a one-exchange-per-item rule | Approve both concurrently under the Mission token | Exactly one is performed, once. The other is declined (`approval_declined`) with nothing changed. Without such a rule, both may be performed, because the Mission alone does not count them (Section 4); only Metering's `max_calls` of 1 refuses the second. Recommended: the Company gives one action one operation ID across interfaces (Ops 3), so Ops 7 alone keeps it at most once. |
| T13 | The Company lists `browser_session_endpoint` and returns operations on its website | (a) A Mission sign-in that requests `poppy:browser-sign-in`. (b) The agent joins its browser with the Mission read token. | (a) The AS refuses the scope with `invalid_scope`. (b) Step 2 of the join refuses the token with `insufficient_scope` (Spec 6); the agent does not sign in again and joins signed out. No website operation is performed under the Mission. |
| T14 | (a) Revision 2 of the exchange adds a 10.00 USD fee to a 70.00 USD net. (b) A `return` operation, an action listed without `max_amount`, takes a 5.00 USD restocking fee out of its refund in revision 2. (c) A revision charges 170.00 USD for the replacement, credits 100.00 USD for the returned jacket, and adds 3.00 USD tax. | Approve each with `agent` | (a) `403`, `insufficient_authority`: the net charge, 80.00 USD, exceeds the cap. (b) `403`, `insufficient_authority`: the deduction from the refund is a charge component, which an action listed without `max_amount` never carries. (c) Performed: the net charge, 73.00 USD, is within the cap, which a gross reading would wrongly refuse. No effect in (a) or (b). |
| T15 | An approval waits on the Mission lock, held by a concurrent writer, while (a) the Mission's `expires_at`, (b) the revision's `expires_at`, or (c) the covering entry's `time_window` end passes | Release the lock | (a) `401 invalid_token`. (b) A new revision (`approval_required`), nothing performed. (c) `403`, `insufficient_authority`. No effect in any case. Every admitted approval's admission instant precedes the bound. |
| T16 | The jacket Mission is approved under `exchange` contract v1. The Company then deploys v2, which adds a `protection_plan` term with a monthly charge. | Request the exchange under v2, then approve it with `agent` under the Mission token | `403`, `insufficient_authority`; nothing performed. A new Mission approved under v2 performs it. |
| T17 | Missions A (the jacket exchange) and B (returning `itm_9Zp`), and an ordinary grant, for the same client, User, and account | (a) Sign in B. (b) Revoke A in settings, then repeat the case with RFC 7009 revocation. | (a) A's refresh token and the ordinary refresh token still work: neither the Company nor the agent revoked them (Section 3.5). (b) A's tokens fail. B's tokens and the ordinary grant keep working, and B's return is performed. |
| T18 | The Company lists `exchange` with `order_id`, `item_id`, and `max_amount`, but not `replacement_sku`. The User's permission names the insulated replacement. | The agent starts the Mission workflow | The agent sends no pushed request with an exchange entry that leaves out the replacement until the User chooses, in the agent's own interface. If the User accepts the broader task, the consent page shows an exchange entry with no replacement constraint. If the User chooses per-revision approval, the agent approves each revision with `user` after showing it, under an ordinary token, outside the Mission. |
| T19 | A Mission token at a write endpoint of the default resource, both legacy (it sends `scope="orders:write"`) and Mission-aware | Call the endpoint | `403`, `insufficient_scope`, no effect. The Mission-aware endpoint sends `mission_denial="insufficient_authority"` and no `scope`. In both cases the agent requests no scope, starts no sign-in, and makes no retry with another credential. |
| T20 | A Mission refresh token copied to another User's device of the same agent, which has its own DPoP key and can get client assertions (Spec 10.7) | Refresh | `invalid_grant`: the proof's key is not the one the token is bound to (Spec 4.4). No token is issued. |
| T21 | A Mission token on a request to the actions service that declares `operations` version 3 but not the extension | Request the exchange | `403 extension_required` naming the extension. Nothing performed, and no operation returned. |

## 8. Adoption path

1. **PAP 1.0 with Operations version 3 as it is.** Agent approvals rest on
   the agent's word; the Company accepts them or declines them.
2. **This profile.** Missions back agent approvals, and the Company
   declines agent approvals without a Mission when it is ready.
3. **Cumulative limits** with Mission Metering: the limits over time that
   PAP's roadmap mandates describe.
4. **Company-verified per-revision approval** for actions that carry
   `requires_action_approval`, through Mission Transaction Authorization or
   PAP's signed user approvals.
5. **Recurring and evolving tasks** with Mission Template and Progressive
   Authorization.
6. **Work spanning Companies** with Cross-Domain projection, for Users who
   accept the correlation.

The profile belongs in PAP's own format: a short extension page proposed for
adoption as `mission`, citing core and resource-access. It is not a new
family Internet-Draft. On the family side,
`notes/mission-agent-protocol-composition.md` can link to it.

## 9. Changes from the Draft 0.1 sketch

| Draft 0.1 sketch (rounds 1 to 4) | Version 1.0 sketch | Why |
| --- | --- | --- |
| Checks at the operations confirm endpoint | Checks when an approval arrives, at the actions service (Section 3.7) | Operations version 3 has no confirm endpoint; the approval travels with the repeated request (Ops 6). |
| `approved_by: "standing_permission"` | `approver="agent"` | Ops 5, 6 |
| `user_approval_required` and a `403` for an unbacked standing permission | `approval_declined` | Ops 6 lets a Company decline for reasons such as `approver`. |
| `poppy:read` projection; no `poppy:write` | A Company read scope hinted `changes: "none"` | PAP 1.0 scopes are the Company's own (Spec 4.7). |
| A separate operations resource | An actions service with its own resource | Per-service tokens (Spec 4.5) |
| Per-phase `a.read`, `a.confirm`, `a.cancel` entries | One entry per action | No operation read or cancel in Operations version 3 |
| `session_id` bound at PAR; one Session per Mission, enforced with `invalid_session` | Removed; Missions are separate grants | Sign-in does not know the Session (Spec 5.4). |
| Refresh token bound by client authentication | Also DPoP-bound | Spec 10.7 |
| An eligibility failure recorded, then `failed` | Declined | Ops 6 |
| `confirmation.mission` in the response | The Company's record and account settings | A performed action responds as it would without operations (Ops 6). |
| Device Sign-In out of scope | Through the experimental Device Authorization companion | The companion landed (#1202). |
| Gaps G7 to G9 open | Resolved | Ops 7, Spec 5.4, Spec 10 |
