# Design note: Mission composition with A2A and agentic commerce protocols

Status: working architecture note, not an Internet-Draft and not normative.

Reviewed against the external protocol specifications available on 2026-08-12.

## 1. Purpose

This note sketches how Mission composes with agent interaction and agentic
commerce protocols, especially:

* Agent2Agent Protocol (A2A);
* Agent Payments Protocol (AP2);
* Agentic Commerce Protocol (ACP);
* Universal Commerce Protocol (UCP);
* Model Context Protocol (MCP); and
* payment challenge protocols such as x402.

The goal is not to absorb these protocols into the Mission family. The goal is
to identify the smallest binding surface that lets each protocol retain its
native objects and lifecycle while Mission supplies durable, governed
authority across them.

The main architectural conclusion is:

> Mission is the durable authorization and governance spine. A2A carries work
> between agents, MCP carries tool invocations, ACP and UCP carry commerce
> operations, and AP2 carries payment-specific authorization artifacts. OAuth
> or another native substrate carries the credentials that enforce Mission at
> each protected hop.

Mission therefore should not become an agent messaging protocol, a checkout
protocol, or a payment credential. Conversely, task identifiers, checkout
sessions, and payment mandates should not be treated as if they were Mission
authority.

## 2. Layer model

The protocols occupy different layers and can be composed without requiring a
single end-to-end wire protocol.

| Concern | Primary protocol or object | Mission role |
| --- | --- | --- |
| Human or organizational goal | Mission | Defines durable purpose, authority, constraints, lifecycle, and accountability |
| Agent-to-agent work | A2A Task and Message | Governs whether the remote work may be requested, continued, or delegated |
| Agent-to-tool work | MCP tool call | Governs the particular capability invocation at the tool edge |
| Cart, checkout, fulfillment, and order | ACP or UCP | Governs whether the commerce operation is within Mission authority |
| Payment-specific consent and authorization | AP2 Mandates | Supplies payment-domain evidence and authorization beneath the broader Mission |
| Per-hop access | OAuth, AAuth, or another substrate-native credential | Carries enforceable authority to the protected service |
| Action-time control | Mission Runtime and policy enforcement points | Re-evaluates lifecycle, limits, exposure, and evidence before consequential actions |
| Work result | A2A Artifact, MCP result, receipt, or Mission work product | Records output and provenance without itself becoming authority |

A representative flow is:

~~~
Human approval or governed activation
                 |
                 v
              Mission
                 |
       +---------+----------+
       |                    |
       v                    v
    A2A Task            MCP tool call
       |                    |
       v                    v
 ACP/UCP checkout     non-commerce action
       |
       v
  AP2 payment artifacts
       |
       v
 receipt and Mission evidence
~~~

This is a layering relationship, not a requirement that every deployment use
every protocol.

## 3. Composition invariants

Any binding should preserve the following invariants.

### 3.1 Native objects remain native

An A2A Task remains an A2A Task. An AP2 Mandate remains an AP2 Mandate. An ACP
checkout remains merchant-owned commerce state. Mission correlates and governs
these objects but does not redefine their native validity rules.

### 3.2 Correlation is not authorization

A Mission identifier in A2A metadata or a checkout extension is only a
correlation claim unless it is authenticated and bound to an enforceable
credential. An untrusted caller MUST NOT obtain authority merely by copying a
Mission identifier into a request.

The protected service derives effective authority from its verified
credential and local policy. It may then cross-check the protocol metadata
against that authority.

### 3.3 Session identity is not Mission identity

A2A `contextId`, an A2A Task identifier, an ACP checkout session identifier,
and an AP2 Mandate identifier all describe different continuity domains. None
is a substitute for the Mission identifier.

A Mission may span many protocol sessions. A protocol session should be bound
to at most one Mission where Mission governance is asserted.

### 3.4 Capability declaration is not authority

Agent Cards, advertised skills, MCP tool descriptions, and commerce
capabilities say what an endpoint is able or willing to process. They do not
grant a caller permission to invoke those capabilities.

Capability discovery is policy input. The verified Mission-bound credential is
the authority presented at execution time.

### 3.5 Evidence is not authority

Artifacts, receipts, intent traces, and Mission evidence can prove what was
requested or performed. They must not silently become reusable authorization
artifacts. A verifier must know which artifact authorizes an action and which
artifact only records one.

### 3.6 Least exposure applies across protocol boundaries

Bindings should disclose only the Mission facts required by the receiving
service. They should not forward full Mission Intent, hidden policy, internal
reasoning, unrelated constraints, competitor information, or an actor's
complete delegation history.

### 3.7 Idempotency domains remain independent

Mission creation idempotency, A2A task identity, ACP checkout idempotency, AP2
payment replay protection, and OAuth proof replay protection solve different
problems. A single identifier must not be reused across these domains merely
because the operations are correlated.

### 3.8 Lifecycle is enforced at consequential transitions

Establishing an A2A Task or checkout while a Mission is active does not grant a
permanent exemption from later suspension, expiry, revocation, or budget
exhaustion. Long-running and resumable protocols need action-time lifecycle
checks.

## 4. A2A composition

### 4.1 Semantic mapping

The following mapping keeps A2A and Mission responsibilities separate.

| A2A concept | Mission interpretation |
| --- | --- |
| Agent Card | Capability and endpoint discovery; not authority |
| Skill | Candidate operation or policy input; not a granted capability |
| Message | Request or information supplied to an agent; potentially untrusted input |
| Task | A unit of remote execution governed by a Mission |
| `contextId` | A2A conversational continuity only |
| Task state | Execution lifecycle, distinct from Mission lifecycle |
| Artifact | Work output that may become a Mission work product or evidence reference |
| `TASK_STATE_AUTH_REQUIRED` | A signal that additional authentication, approval, expansion, or delegation may be required |
| HTTP credential | The actual per-hop authority presented to the A2A server |

The useful default is:

* one governed A2A Task is associated with exactly one Mission;
* one Mission may govern many A2A Tasks; and
* one A2A `contextId` may contain governed and non-governed Tasks, but the
  authorization decision remains task-specific.

This avoids ambiguous authority when a conversation switches goals or when a
remote agent multiplexes unrelated work in one context.

### 4.2 Three execution relationships

An A2A request can represent three materially different relationships.

#### 4.2.1 Remote execution under the same Mission

The caller asks a remote agent to perform part of the existing Mission. The
remote A2A server is a protected resource for that Mission and receives an
audience-restricted Mission-bound credential.

No Child Mission is created merely because a network boundary was crossed.
The remote agent is another executor under the same governed authority.

#### 4.2.2 Cross-domain projection of the same Mission

The remote domain cannot or should not consume the caller's original
credential. A cross-domain mechanism projects a constrained form of the
Mission into the remote trust domain. The projected credential identifies the
same Mission but is restricted for the remote audience, operation, and
exposure policy.

ID-JAG or a comparable assertion-based exchange can be one OAuth realization
of this relationship. The binding should not require the remote service to
receive the full source-domain Mission representation.

#### 4.2.3 Actual delegation through a Child Mission

The caller delegates independently accountable authority to another actor.
This is appropriate when the remote actor needs a distinct scope, lifecycle,
budget, evidence stream, or revocation boundary.

The A2A Task is then governed by the Child Mission. The parent-child
relationship is represented in Mission, not inferred from the A2A roles or the
fact that one agent sent a Message to another.

Crossing an A2A hop therefore does not automatically mean delegation. The
binding needs an explicit choice among same-Mission execution, cross-domain
projection, and Child Mission creation.

### 4.3 Actor identity

A2A Message roles such as `user` and `agent` describe message participation.
They are not a Mission actor chain.

Mission actor identity should come from authenticated protocol facts, such as:

* the OAuth client and subject;
* a sender-constrained key;
* an RFC 8693 `act` chain where applicable;
* an authenticated AAuth actor; or
* a validated cross-domain assertion.

The server should reject a mismatch between authenticated actor information
and any actor correlation supplied in A2A metadata.

### 4.4 Agent Card declaration

An A2A server can advertise support for a Mission binding through an A2A
extension declaration. The declaration means that the endpoint understands
the binding. It does not mean that every advertised skill is authorized for
every Mission.

Illustrative, non-normative Agent Card fragment:

```json
{
  "capabilities": {
    "extensions": [
      {
        "uri": "https://example.org/a2a/extensions/mission/v1",
        "required": false,
        "description": "Mission-governed task execution"
      }
    ]
  }
}
```

The eventual extension specification would need a stable URI, versioning
rules, and the A2A extension governance required for interoperability.

### 4.5 Task correlation metadata

The A2A binding needs a small correlation object. It should not carry full
Mission Intent or serve as a bearer credential.

Illustrative, non-normative metadata:

```json
{
  "extensions": [
    "https://example.org/a2a/extensions/mission/v1"
  ],
  "metadata": {
    "https://example.org/a2a/extensions/mission/v1": {
      "mission": {
        "issuer": "https://as.example",
        "id": "m-7f5a",
        "authority_hash": "sha-256:base64url-value"
      },
      "operation": "research.compare",
      "relationship": "same_mission"
    }
  }
}
```

The authenticated credential remains authoritative. The A2A server checks
that the credential permits the requested operation and that its Mission
identity and authority anchor agree with the metadata.

Useful metadata fields are likely limited to:

* Mission issuer and identifier;
* an authority or proposal anchor needed to prevent mix-up;
* the requested Mission operation;
* the execution relationship;
* an opaque remediation reference; and
* provenance references on resulting Artifacts.

The metadata should not include refresh tokens, Child Mission assertions,
complete authorization details, or secrets usable outside the A2A exchange.

### 4.6 Credential binding

In the OAuth realization, the A2A server is an OAuth protected resource. The
client obtains a credential whose audience and authorization details cover the
specific A2A endpoint and operation. Sender constraint should be used where
the substrate and transport support it.

The binding needs to define:

1. how an A2A operation is represented in the relevant authorization details;
2. how the A2A server discovers Mission and authorization metadata;
3. how task metadata is cross-checked with the credential;
4. whether the credential is valid for task creation only or for later task
   operations as well;
5. how streaming and push notification channels are authenticated; and
6. how a resumed Task proves continuity without treating `contextId` as an
   authorization handle.

For a native AAuth realization, the equivalent gate can consume AAuth-native
authority and actor facts. An A2A binding should define the semantic checks
once and place substrate-specific credential carriage in separate profiles.

### 4.7 Mission and Task lifecycle

A2A Task state and Mission state form a product state, not one merged state
machine.

| Mission condition | A2A behavior |
| --- | --- |
| Active and authorized | Task may proceed subject to current limits |
| Suspended | Pause before the next consequential action; do not start new side effects |
| Expired or revoked | Cancel or fail further governed execution, subject to safe cleanup |
| Awaiting approval or expansion | Place the Task in an authorization-required condition |
| Budget or capability exhausted | Refuse the action or request governed remediation |
| Terminal Mission | Do not resume merely because the A2A Task remains resumable |

Checks should occur at least when:

* a Task is created;
* a queued Task begins execution;
* a Task resumes after interruption;
* the agent crosses a consequential action boundary;
* a new credential is required; and
* the Task emits an externally consequential result.

A server does not need to poll continuously if it has a sound freshness and
event strategy. The binding does need to state how stale authorization is
bounded.

### 4.8 `TASK_STATE_AUTH_REQUIRED` remediation

`TASK_STATE_AUTH_REQUIRED` can cover several different conditions:

* the client lacks an ordinary access credential;
* the Mission requires a human approval;
* the requested action exceeds existing Mission authority and needs expansion;
* the work requires a Child Mission; or
* the remote domain requires a projected credential.

The binding should expose a typed, machine-readable remediation object rather
than forcing agents to infer the condition from prose.

Illustrative, non-normative metadata:

```json
{
  "kind": "mission_expansion_required",
  "request_uri": "urn:example:single-use-remediation-reference",
  "requested_authority_hash": "sha-256:base64url-value"
}
```

The remediation reference should be opaque, short-lived, audience-bound, and
single-use where appropriate. It must not itself authorize execution unless
the relevant Mission specification explicitly defines it as an authorization
artifact.

### 4.9 Artifacts and work products

An A2A Artifact can be registered as a Mission work product or referenced from
Mission evidence. The binding should preserve:

* the A2A Task identifier;
* the Mission identifier;
* the producing actor or service;
* an artifact digest and media type;
* the authority anchor under which it was produced; and
* the relevant time and lifecycle state.

This is provenance, not proof that every statement inside the Artifact is
true. Artifact content remains subject to application validation.

### 4.10 A2A security considerations

An A2A binding needs explicit treatment of:

* **confused deputies:** an agent must not use its own broad authority when the
  caller's Mission is narrower;
* **token forwarding:** a credential for one agent or audience must not be
  passed unchanged to another;
* **Mission mix-up:** Task metadata and credential authority must agree;
* **context confusion:** `contextId` must not cause authority from one Task to
  leak into another;
* **metadata forgery:** Mission correlation fields are untrusted until bound to
  authenticated authority;
* **replay:** A2A request replay and OAuth proof replay require their native
  controls;
* **resumption:** a resumable Task must re-establish current authority; and
* **artifact substitution:** evidence should bind the exact Artifact digest,
  not only its URL or name.

## 5. AP2 composition

### 5.1 Division of responsibility

AP2 and Mission both discuss durable authority, but at different layers.

Mission is the broader authority for a governed objective. It may include
commerce among many possible actions. AP2 supplies payment-specific Mandates,
checkout commitments, and receipts that payment ecosystem participants can
validate using AP2 rules.

This layering is not automatic. AP2's Agent Authorization Framework explicitly
defines Mandate Delegation and Action Authorization as a general model that
could apply beyond payments. That creates genuine semantic overlap with Mission
approval, delegation, and action-time enforcement.

For every integration, the authority relationship therefore needs an explicit
choice:

* AP2 is the payment-specific action authorization beneath a broader Mission;
* an AP2 Mandate is a substrate-native realization of a Mission capability; or
* AP2 independently authorizes an action outside Mission governance.

The same action must not depend on two grants whose constraints, actors, or
lifecycle rules can disagree without a defined resolution algorithm. Where
both systems govern an action, execution requires the intersection of their
authority, and failure of either verifier denies the action.

A useful composition is:

~~~
Mission authority
      |
      v
AP2 open Checkout or Payment Mandate
      |
      v
closed checkout and payment Mandates
      |
      v
payment execution and receipts
      |
      v
Mission evidence and budget reconciliation
~~~

An AP2 Mandate should not be treated as a replacement for the Mission. The
Mission should not attempt to replace AP2's payment-domain authorization and
verification rules.

### 5.2 Purchase within existing authority

A purchase that fits existing Mission authority does not inherently require a
successor Mission. The AP2 closed Mandate is an action-bound realization of a
portion of the existing Mission authority.

The action-time policy enforcement point should compare the final purchase
against the Mission's current commerce authorization, lifecycle, budget, and
exposure policy before the AP2 payment step is allowed.

If the final checkout exceeds the Mission, the correct result is an approval,
expansion, or refusal. The agent must not manufacture a broader AP2 Mandate and
treat it as if it retroactively expanded the Mission.

### 5.3 Approval and activation ceremonies

One trusted user ceremony may provide the facts needed both to approve or
activate a Mission and to create an AP2 artifact. The outputs should remain:

* separately typed;
* domain-separated in their signatures and hashes;
* scoped to their own verifiers; and
* independently valid under Mission and AP2 rules.

A payment verifier validates AP2 authorization. A Mission runtime validates
Mission authority. Correlation between the two is valuable, but correlation
must not make either verifier silently depend on an artifact it does not
understand.

### 5.4 AP2 as an approval basis

If deployments want an AP2 consent artifact to contribute to Mission
activation, the family could eventually define an `approval_basis` profile for
it. An illustrative shape is:

```json
{
  "type": "ap2_open_mandate",
  "consent_principal": {
    "iss": "https://wallet.example",
    "sub": "user-2487"
  },
  "activation": {
    "mandates": [
      {
        "vct": "mandate.checkout.open.1",
        "digest": "sha-256:base64url-value"
      },
      {
        "vct": "mandate.payment.open.1",
        "digest": "sha-256:base64url-value"
      }
    ]
  },
  "activation_actor": {
    "iss": "https://wallet.example",
    "sub": "wallet-agent-12"
  },
  "root_commitment": "sha-256:domain-separated-aggregate-value"
}
```

This should not be standardized until the following are precisely defined:

* which AP2 Mandate type is acceptable;
* whether one or both open Mandate types are required;
* which exact AP2 serialization is committed by each digest;
* how consent principal and activation actor are derived;
* how freshness, revocation, and replay are checked;
* how verifier and audience separation is maintained; and
* whether the AP2 artifact proves approval of the complete Mission or only its
  payment-related subset.

The `root_commitment` in such a profile would need a domain-separated,
deterministic aggregate over the ordered, versioned AP2 Mandate digests. The
illustrative value above is not a currently defined Mission anchor.

The conservative default is that AP2 authorizes payment and Mission approval
is established independently.

### 5.5 AP2 agent authorization and delegation

AP2's authorization of an agent to participate in payment is not automatically
a Mission Child delegation. If a remote agent needs independently governed
Mission authority, the caller creates or uses a Child Mission and then binds
the AP2 action to that Child Mission.

The AP2 binding should make explicit:

* which Mission governs the payment actor;
* whether the actor executes under the same Mission or a Child Mission;
* which credential or key is authorized to create the AP2 artifact;
* how the AP2 artifact commits to the relevant Mission authority anchor; and
* how revocation or suspension affects an unexecuted payment.

### 5.6 Budget reservation and reconciliation

Autonomous commerce creates a distributed metering problem. A simple
`max_total` check is insufficient if several agents or merchants can reserve or
spend concurrently.

A robust system needs defined semantics for:

1. reservation before payment authorization;
2. atomic or conflict-safe consumption of shared budget;
3. reservation expiry and release;
4. partial capture and partial fulfillment;
5. refunds, reversals, tips, taxes, shipping changes, and currency conversion;
6. reconciliation from AP2 and merchant receipts; and
7. behavior when the Mission becomes suspended between reservation and
   capture.

Until these semantics exist, an MVP should either use a single authoritative
budget enforcement point or disallow concurrent autonomous payment against the
same limit.

### 5.7 Receipts and evidence

AP2 receipts are strong candidates for Mission evidence references. The
Mission evidence entry should bind the exact receipt or receipt digest and
record its AP2 type. It should not copy sensitive payment data that Mission
auditors do not need.

Receipt ingestion can support:

* spend reconciliation;
* proof that payment followed an authorized checkout;
* dispute and refund correlation;
* budget release for failed or reversed transactions; and
* later audit of which Mission and actor initiated the payment.

### 5.8 Terminology collision

AP2 uses **Mandate** for an authority-bearing payment artifact. The Mission
family has used **Mission Mandate** for an artifact that explicitly grants no
authority. That collision will be actively misleading in a joint deployment.

Before publishing a commerce binding, the Mission family should strongly
consider renaming its non-authorizing artifact to a term such as **Mission
Record Statement** or **Mission Evidence Statement**. This note does not make
that rename, but the binding should not normalize the ambiguity.

## 6. ACP and UCP composition

### 6.1 Commerce systems remain authoritative for commerce state

ACP and UCP describe merchant-facing commerce operations such as product
selection, checkout, fulfillment, order creation, and post-purchase state. The
merchant remains the system of record for its checkout and order.

Mission decides whether the agent is authorized to request the operation. It
does not make an agent's local cart more authoritative than the merchant's
final checkout representation.

### 6.2 Representative checkout flow

An ACP-style governed purchase can proceed as follows:

1. the agent creates or updates a merchant checkout using the commerce
   protocol;
2. the merchant returns its current authoritative checkout, including final
   price, currency, fulfillment terms, and merchant-specific conditions;
3. the Mission runtime evaluates that exact checkout against current Mission
   authority;
4. a payment component obtains or presents the required AP2 or other delegated
   payment credential;
5. the agent completes the checkout using a commerce-protocol idempotency key;
6. the merchant receipt and payment receipt are recorded by digest as Mission
   evidence; and
7. the Mission budget and lifecycle are reconciled.

The critical rule is that authorization is evaluated against the final
merchant-authoritative checkout immediately before completion, not only
against an earlier product search result or agent-local estimate.

### 6.3 Dedicated authorization details

A commerce binding should use a dedicated Rich Authorization Request type
rather than overloading a generic URL or tool capability. Commerce-specific
subset and comparison rules are needed.

Illustrative, non-normative authorization details:

```json
{
  "type": "mission_agentic_commerce",
  "resource": "https://merchant.example",
  "actions": [
    "checkout.create",
    "checkout.update",
    "checkout.complete"
  ],
  "constraints": {
    "currency": "USD",
    "max_total": "250.00",
    "merchant_categories": [
      "office-supplies"
    ],
    "latest_completion": "2026-08-14T23:59:59Z",
    "fulfillment": {
      "countries": [
        "US"
      ]
    },
    "payment_method_class": [
      "corporate-card"
    ]
  }
}
```

A specification would need exact semantics for:

* merchant and resource identity;
* decimal amount and currency comparison;
* tax, shipping, discount, and tip treatment;
* category vocabularies;
* product substitutions and quantity changes;
* time windows;
* fulfillment destinations;
* payment method constraints;
* subscriptions and recurring charges; and
* partial orders and post-purchase modifications.

String equality over the JSON structure is not an adequate authorization
algorithm.

### 6.4 Merchant-enforced and platform-enforced modes

There are two materially different assurance modes.

#### Merchant-enforced Mission authority

The merchant accepts a Mission-bound, audience-specific credential and
independently verifies the Mission authorization relevant to its commerce
operation. The merchant is a Mission-aware protected resource.

#### Platform-enforced Mission authority

The merchant accepts an ordinary ACP or UCP credential. A platform-side policy
enforcement point checks Mission authority before permitting the agent to use
that credential.

This may be practical, but the merchant is trusting the platform's enforcement
and cannot independently verify the Mission. A specification must not describe
these modes as equivalent.

### 6.5 Sender constraint and request signing

ACP commonly uses an HTTP authorization credential. An mTLS-bound access token
can remain a bearer-scheme token at the HTTP layer while being sender
constrained by OAuth rules. DPoP requires the DPoP authorization scheme and
proof header, which may require an explicit ACP binding or profile.

A commerce protocol's generic request signature is not automatically an OAuth
sender constraint. The two mechanisms are joined only if a specification binds
the same key and verified request elements with unambiguous semantics.

### 6.6 Credential custody

Delegated payment credentials, refresh tokens, AP2 private keys, and broad
merchant credentials should remain in a credential broker, wallet, or trusted
policy enforcement point. They should not be exposed to the language model or
copied into A2A Messages, MCP arguments, or intent traces.

The model may request an operation. The trusted component evaluates the
Mission, obtains a narrowly scoped credential, and performs or authorizes the
protocol call.

### 6.7 Independent idempotency

ACP checkout idempotency identifies a commerce operation. A Mission
`creation_request_id` identifies Mission-object creation. An OAuth DPoP `jti`
identifies one proof. A payment-network identifier identifies a payment
operation.

They may be linked in evidence, but must not be reused as one universal
idempotency key. Each service retains its own atomicity, retention, collision,
and retry semantics.

### 6.8 Intent traces and least exposure

Commerce intent traces can improve merchant understanding, but they create an
obvious least-exposure hazard. A binding must not assume that the complete
Mission Intent should be copied into an ACP trace.

Information that usually should remain undisclosed includes:

* the user's maximum budget when a lower offer is sufficient;
* competitor prices and merchant rankings;
* unrelated Mission constraints;
* internal approval policy;
* complete actor or delegation history;
* chain-of-thought or hidden model reasoning; and
* credentials and authorization artifacts.

Mission should govern disclosure as a distinct capability. A commerce request
may reveal the minimum facts required to complete that transaction, with any
additional disclosure separately authorized and recorded.

### 6.9 UCP

UCP covers a broader commerce surface, but the binding principles are the
same:

* UCP owns commerce object semantics;
* the final merchant-authoritative state is the authorization input;
* Mission supplies current goal-bound authority;
* payment-specific authorization remains separately verifiable;
* receipts feed evidence and reconciliation; and
* merchant-enforced and platform-enforced assurance are distinguished.

A single **Mission Binding for Agentic Commerce** should define shared semantic
requirements and use protocol-specific profiles for ACP, UCP, and AP2 rather
than cloning the entire Mission model into three drafts.

## 7. MCP, x402, and the other ACP

### 7.1 MCP

MCP sits primarily at the agent-to-tool edge. A2A may deliver a Task to an
agent, after which that agent invokes one or more MCP tools. Mission should
govern each consequential tool call through the Runtime and capability-binding
model.

The A2A Task does not automatically authorize every MCP tool the remote agent
can see. The tool call still needs a capability and constraints that are a
subset of the governing Mission, together with an actor and evidence chain
appropriate to the deployment.

This separation also supports least exposure: the A2A peer can receive only
the task facts it needs, and the MCP server can receive only the action facts
it needs.

### 7.2 x402 and similar payment challenges

An HTTP payment challenge can be another action beneath a Mission. The Mission
runtime decides whether satisfying the challenge is authorized. The payment
protocol defines settlement and proof of payment.

The challenge itself does not expand the Mission. A price above the current
limit should cause approval, expansion, or refusal rather than autonomous
payment.

### 7.3 IBM Agent Communication Protocol

The name ACP has also referred to IBM's Agent Communication Protocol. That
project has been incorporated into A2A and its repository is archived. New
Mission work should target A2A rather than define a separate binding for the
archived protocol. This note uses **ACP** for Agentic Commerce Protocol unless
stated otherwise.

## 8. Substrate neutrality

The binding architecture should have two parts.

### 8.1 Semantic binding

The semantic layer defines:

* how a protocol operation maps to Mission authority;
* correlation and mix-up prevention;
* lifecycle and action-time enforcement;
* delegation choices;
* least-exposure requirements;
* remediation behavior;
* provenance and evidence; and
* conformance scenarios.

These requirements do not depend on OAuth field names.

The semantic binding can be expressed as an authenticated authority tuple with
at least:

* the Mission issuer and identifier;
* the governing authority or proposal anchor;
* the authenticated actor and any relevant delegation context;
* the target resource or audience;
* the permitted actions and constraints;
* lifecycle and freshness information; and
* the key or channel binding when possession is part of the authority.

This tuple is a review model, not a new wire object. Each substrate should map
its native objects to these facts and prove the mapping at the enforcement
point. The common specification should define the facts and invariants, not
require every substrate to serialize an OAuth-shaped JSON object.

### 8.2 Credential realization

A realization defines how a substrate carries and verifies the authority. The
OAuth realization can use protected-resource metadata, authorization details,
token exchange, sender constraint, and Mission-bound access tokens. An AAuth
realization can use its native actor, Structured Authority, and capability
artifacts. It should define a Mission binding or extension only for facts AAuth
does not already represent, instead of placing OAuth
`authorization_details` inside an AAuth envelope.

For A2A, extension negotiation and Mission correlation remain identical across
realizations. Only the credential presentation and verification profile
changes. For commerce, the same final-checkout comparison applies regardless
of whether the authorization is represented as OAuth rich authorization
details, AAuth-native capability constraints, or an AP2 Mandate profile.

This separation prevents two failures:

1. making the conceptual Mission model OAuth-specific; and
2. weakening the OAuth profile into vague correlation metadata that an OAuth
   protected resource cannot enforce.

OAuth should be the concrete realization where it is the deployed security
substrate, not the definition of Mission itself.

## 9. Recommended specification work

The family should initially produce two focused documents.

### 9.1 Mission Binding for A2A

This document should define:

* the A2A extension URI and Agent Card declaration;
* Task-to-Mission cardinality;
* task metadata and credential cross-checking;
* same-Mission, cross-domain, and Child Mission relationships;
* authenticated actor derivation;
* OAuth and AAuth realization hooks;
* lifecycle checks for task creation, execution, streaming, and resumption;
* typed `TASK_STATE_AUTH_REQUIRED` remediation;
* Artifact provenance; and
* security and conformance requirements.

This is sufficiently stable to draft now, provided the first version remains
small and does not attempt to redesign A2A.

### 9.2 Mission Binding for Agentic Commerce

This document should define shared semantics for ACP, UCP, and AP2, including:

* a commerce authorization-details type and subset algorithm;
* final-checkout binding;
* merchant-enforced and platform-enforced modes;
* payment artifact correlation;
* approval and activation separation;
* budget reservation and reconciliation;
* receipt evidence;
* credential custody;
* least-exposure rules for intent traces; and
* protocol-specific profiles.

This work should begin as an experimental design draft. AP2, ACP, and UCP are
still evolving, and distributed budget semantics need more proof before the
family makes strong interoperability claims.

Separate full drafts for every protocol would create unnecessary duplication.
Protocol-specific profiles can be split later if their registries or standards
venues require independent documents.

## 10. Minimum viable implementation

An MVP should prove enforcement and composition before attempting universal
interoperability.

### 10.1 A2A MVP

1. Advertise one Mission A2A extension in the Agent Card.
2. Associate at most one Mission with each governed Task.
3. Require an audience-specific Mission-bound credential at the A2A protected
   resource.
4. Cross-check Mission issuer, identifier, authority anchor, actor, and
   operation between credential and task metadata.
5. Re-evaluate Mission state at Task creation, execution start, resumption, and
   each consequential action.
6. Return typed `TASK_STATE_AUTH_REQUIRED` remediation for missing authority, expansion,
   approval, or Child Mission creation.
7. Bind resulting A2A Artifacts into Mission work-product provenance by digest.

The first implementation can support same-Mission execution only. Cross-domain
projection and Child Mission creation can be added as separate, explicit
relationships after the base checks are proven.

### 10.2 Commerce MVP

1. Define one dedicated commerce authorization-details type.
2. Support a single currency and a single authoritative budget service.
3. Bind authorization to the exact final merchant checkout digest.
4. Keep payment credentials in a broker or wallet outside the model process.
5. Correlate AP2 payment artifacts without making them implicit Mission
   approval.
6. Record merchant and payment receipt digests as evidence.
7. Keep commerce and Mission idempotency identifiers separate.
8. Disable concurrent autonomous spending from the same budget unless the
   budget service implements reservation and reconciliation.

The MVP should not claim safe autonomous payment across multiple independent
merchants until the reservation model is implemented and tested.

## 11. Conformance scenarios

At minimum, an implementation should test the following cases.

### 11.1 A2A

* a valid Mission-bound credential creates an authorized Task;
* forged Mission metadata without matching authority is rejected;
* a credential for Mission A cannot create a Task labeled Mission B;
* a credential for one A2A audience cannot be forwarded to another agent;
* suspension before execution prevents the queued Task from starting;
* revocation before resumption prevents a resumable Task from continuing;
* an out-of-bounds operation returns typed remediation without executing;
* a same-Mission hop does not create an unnecessary Child Mission;
* a Child Mission Task is attributed to the Child rather than its parent; and
* an Artifact digest and producer are preserved in Mission provenance.

### 11.2 Commerce

* a final checkout within the authorized amount and constraints is allowed;
* a merchant price change after an earlier check triggers re-evaluation;
* a final checkout above the limit cannot be completed with the old authority;
* a copied AP2 identifier without a valid AP2 artifact grants nothing;
* a copied Mission identifier without a valid credential grants nothing;
* concurrent purchases cannot overspend a shared reserved budget;
* a refund or failed capture releases or reconciles budget correctly;
* receipt evidence binds the exact merchant and payment artifacts;
* commerce idempotency retry does not create a second order; and
* an intent trace omits non-required Mission constraints and credentials.

## 12. Open design decisions

The following decisions should remain explicit rather than being hidden in an
implementation.

1. What is the stable A2A extension URI and registration venue?
2. Is one Mission per A2A Task mandatory whenever the extension is used?
3. Which Task operations require a newly evaluated credential rather than the
   credential used at creation?
4. What freshness mechanism bounds lifecycle changes during long-running A2A
   execution?
5. Which remediation object is safe to expose through A2A intermediaries?
6. What exact commerce constraint algebra supports interoperable subset
   evaluation?
7. Who owns an atomic budget reservation when several merchants or agents are
   involved?
8. Can an AP2 artifact serve as Mission approval, or only as payment evidence?
9. Which Mission anchor should AP2 and commerce artifacts commit to?
10. How are subscriptions, recurring payments, refunds, and post-purchase
    changes represented?
11. What information-disclosure policy applies to commerce intent traces?
12. Should the non-authorizing Mission Mandate be renamed before an AP2 binding
    is published?

## 13. Non-goals

The proposed bindings should not:

* replace A2A Task or Message semantics;
* turn an Agent Card into an authorization grant;
* treat `contextId` as a Mission or credential;
* require full Mission Intent disclosure to remote agents or merchants;
* replace AP2's payment-domain verification;
* replace merchant checkout and order state;
* expose payment or refresh credentials to the language model;
* infer Child Mission delegation from every agent-to-agent call;
* merge all replay and idempotency mechanisms into one identifier; or
* claim substrate neutrality by omitting the concrete enforcement rules each
  substrate requires.

## 14. Relationship to current Mission documents

This note builds on the roles already separated across:

* the [Mission Substrate](../draft-mcguinness-mission-substrate.md), for the
  substrate-neutral authorization model;
* the [Mission Core](../draft-mcguinness-oauth-mission.md), for the OAuth
  realization;
* the [Mission Runtime](../draft-mcguinness-mission-runtime.md), for
  action-time policy enforcement;
* the [Mission Capability Binding](../draft-mcguinness-mission-capability-binding.md),
  for mapping Mission authority to actionable capabilities;
* the [Mission Cross-Domain](../draft-mcguinness-oauth-mission-cross-domain.md), for
  constrained authority projection;
* the [Mission Child Delegation](../draft-mcguinness-oauth-mission-child-delegation.md),
  for independently governed delegated authority; and
* the [Mission Work Products](../draft-mcguinness-oauth-mission-work-products.md), for
  result provenance.

Any future binding should reference those semantic responsibilities instead of
creating a protocol-specific second Mission model.

## 15. External references

The protocol descriptions in this note were checked against:

* [A2A Protocol specification](https://a2a-protocol.org/latest/specification/)
* [A2A extension and binding governance](https://a2a-protocol.org/latest/topics/extension-and-binding-governance/)
* [AP2 specification](https://ap2-protocol.org/ap2/specification/)
* [AP2 agent authorization](https://ap2-protocol.org/ap2/agent_authorization/)
* [Agentic Commerce Protocol repository](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol)
* [ACP agentic checkout RFC](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/blob/main/rfcs/rfc.agentic_checkout.md)
* [ACP intent traces RFC](https://github.com/agentic-commerce-protocol/agentic-commerce-protocol/blob/main/rfcs/rfc.intent_traces.md)
* [Universal Commerce Protocol](https://ucp.dev/)
* [Archived IBM Agent Communication Protocol repository](https://github.com/i-am-bee/acp)

## 16. Recommendation

Proceed with a small A2A binding first. It has a clear protected-resource
boundary, a concrete Task object to govern, and a tractable extension surface.
Use it to validate the separation between Mission semantics and OAuth or AAuth
credential realization.

Develop the commerce binding in parallel as an experimental note, but gate the
autonomous-payment MVP on final-checkout binding, credential custody, and an
authoritative budget reservation model. The most important commerce result is
not another token format. It is a precise rule for when a changing merchant
checkout remains within durable Mission authority, with evidence that lets the
decision be audited later.
