---
title: "Mission Security Model"
abbrev: "Mission Security Model"
category: info

docname: draft-mcguinness-mission-security-model-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
keyword:
 - oauth
 - mission
 - agent
 - authorization
 - threat model
 - trust
venue:
  github: "mcguinness/mission-bound-authorization"
  latest: "https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-security-model.html"

author:
 -
    fullname: Karl McGuinness
    organization: Independent
    email: public@karlmcguinness.com

normative:
  I-D.draft-mcguinness-oauth-mission:
    title: "Mission-Bound Authorization for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

informative:
  I-D.draft-mcguinness-oauth-id-assertion-framework:
  I-D.draft-mcguinness-oauth-domain-authorized-issuer:
  I-D.draft-mcguinness-oauth-client-instance-assertion:
  I-D.draft-mcguinness-oauth-ai-agent-instance:
  I-D.draft-mcguinness-oauth-mission-cross-domain:
    title: "Mission Cross-Domain Projection for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-cross-domain.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-runtime:
    title: "Mission-Bound Runtime Enforcement"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-runtime.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-harness:
    title: "Mission-Aware Agent Harnesses"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-harness.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-consent-evidence:
    title: "Mission Consent Evidence for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-consent-evidence.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-status:
    title: "Mission Status and Lifecycle for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-status.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-audit:
    title: "Mission Audit Transparency"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-audit.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-mandate:
    title: "Mission Mandate"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-mandate.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-completion:
    title: "Mission Completion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-completion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-attenuation:
    title: "Mission Offline Attenuation for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-attenuation.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authzen:
    title: "Mission-Bound Runtime Enforcement: AuthZEN Profile"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authzen.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-approval:
    title: "Mission Deferred Approval for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-approval.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-expansion:
    title: "Mission Expansion for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-expansion.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-orchestration:
    title: "Mission Orchestration and Unwinding"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-orchestration.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-oauth-mission-signals:
    title: "Mission Lifecycle Signals for OAuth 2.0"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-oauth-mission-signals.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026
  I-D.draft-mcguinness-mission-authority-server:
    title: "Mission Authority Server"
    target: https://mcguinness.github.io/mission-bound-authorization/draft-mcguinness-mission-authority-server.html
    author:
      -
        ins: K. McGuinness
        name: Karl McGuinness
    date: 2026

--- abstract

Mission-Bound Authorization for OAuth 2.0 and its companion profiles
spread enforcement across several components: a Mission Issuer derives
authority and, in the OAuth binding, gates issuance (an OAuth
Authorization Server, or a standalone Mission Authority Server that
records and serves Missions without issuing tokens); a Policy
Enforcement Point and Policy Decision Point evaluate each action; a
harness establishes a mediated execution environment; a consent
rendering layer discloses authority to an Approver; an orchestrator
unwinds in-flight work; and optional services report Mission state,
adjudicate requested authority, log evidence, and report completion
events. In cross-domain use, a resource-side Authorization Server
joins this base. Each
profile states its own security considerations, but no single document
says which components must be trusted, what each assumes of the others,
and how the compromise of each degrades the guarantees. This document
provides that consolidated view. It is an Informational security model
for the Mission suite: it defines the trusted base, the cross-cutting
assumptions, and the consequence of each component's compromise, and it
points to the normative security considerations of each profile rather
than restating them.

--- middle

# Introduction

The Mission model treats the agent as part of the attack surface: an
agent may be prompt-injected or compromised, and the suite's purpose is
to bound what such an agent can do, not to make it trustworthy
({{I-D.draft-mcguinness-mission-runtime}}). Bounding the agent
means relying on other components: the Mission Issuer that derives
authority and, in the OAuth binding, gates issuance (an Authorization
Server or a standalone Mission Authority Server), the enforcement
points that evaluate each action,
the harness that removes unmediated paths, and a set of optional
services. Those components are the **trusted base**: the parts that, if
compromised, degrade or void the guarantees the suite otherwise provides.

Each profile documents the security considerations local to its own
mechanism. What no single profile provides, and what a reviewer or a
deploying operator needs, is the consolidated picture: the full trusted
base in one place, what each component must achieve, what it assumes of
the others, and what its compromise costs. This document is that picture.

This document defines no new mechanism, claim, or wire format. It is a
model that aids review and deployment; the normative requirements live in
the profiles it references.

# Status: An Informational Model {#status}

This document is Informational. It does not place normative requirements
on implementations; the enforcement obligations are defined by the
issuance profile ({{I-D.draft-mcguinness-oauth-mission}}) and its
companions. Where this document uses words like "must," it describes an
expectation the consolidated model places on a deployment that claims the
suite, realized by the referenced profile, not a new conformance
requirement of its own.

# Conventions and Terminology {#conventions}

This document uses Mission, Mission Issuer (the Authorization Server
in the OAuth binding; the Mission Authority Server in the standalone
binding), Policy
Enforcement Point (PEP), Policy Decision Point (PDP), Approver, Subject,
agent, Authority Set, and Mission state as defined in
{{I-D.draft-mcguinness-oauth-mission}} and
{{I-D.draft-mcguinness-mission-runtime}}.

# Mission Substrate {#mission-substrate}

This model describes the components and trust relationships of the
Mission model, not of OAuth 2.0 mechanics. Its analysis applies to any
substrate that provides the Mission primitives the profiles consume:
the identifier and issuer, the state space with its only-active rule,
an authority representation with a subset rule, the integrity-anchor
envelope, and, where the binding provides one, a Mission-bound
credential; a binding without that credential supplies an externally
established Mission reference instead, verified under the runtime
profile's Mission binding establishment step
({{I-D.draft-mcguinness-mission-runtime}}). The issuance profile
{{I-D.draft-mcguinness-oauth-mission}} is the OAuth 2.0 binding of
those primitives and the substrate the profiles' security
considerations assume; a different binding re-derives only the
substrate-specific entries of this model.

# The Untrusted Agent {#untrusted-agent}

The agent is not in the trusted base. The model assumes the agent can be
prompt-injected, can be compromised, and can attempt any action its
position allows. Every guarantee below is a bound on what such an agent
can achieve, and is stated relative to a trusted base that excludes the
agent. Two structural choices carry this:

- **Authority is fixed by an approval the agent cannot move.** Authority
  is derived by the Authorization Server and committed at the approval
  event, which may be asynchronous
  ({{I-D.draft-mcguinness-oauth-mission}},
  {{I-D.draft-mcguinness-oauth-mission-approval}}); the agent proposes
  but does not grant, and intent fields the agent can influence are
  inert.
- **The credential whose misuse is unacceptable is not held by the
  agent.** Under mediated execution
  ({{I-D.draft-mcguinness-mission-runtime}}) the PEP holds the
  sender-constraint key, so a compromised agent cannot present a
  high-consequence credential directly.

The agent and harness boundary assumes an isolation boundary between
them: process, host, or service separation within a single operator.
Without that separation, agent compromise and harness compromise are one
event, and the harness-compromise degradation ({{trusted-base}}) applies
to a compromised agent. A deployment claiming the runtime profile's
agent-compromise-resistant enforcement therefore isolates the mediating
PEP and its key custody from agent-facing components; the harness profile
requires this separation
({{I-D.draft-mcguinness-mission-harness}}).

# The Trusted Base {#trusted-base}

The following components are trusted to varying degrees. For each: what
it must achieve, what it assumes of the others, and how its compromise
degrades the guarantees. The authoritative security considerations are in
the cited profile.

Authorization Server (Mission Issuer):
: The root of trust. It derives the Authority Set, runs the approval
  event, commits the integrity anchors, and gates issuance on Mission
  state. It must derive faithfully and gate correctly; it assumes the
  Approver is authenticated and the agent is untrusted. Its compromise
  voids the model: a compromised issuer can mint arbitrary authority.
  This is the strongest trust assumption in the suite
  ({{I-D.draft-mcguinness-oauth-mission}}).

Resource Authorization Server (cross-domain):
: When cross-domain access is used, a resource-side Authorization Server
  mints local Mission-bound tokens that the Mission's issuer cannot
  observe. It must mint only within the audience and lifetime the
  cross-domain grant scopes. Its compromise mints arbitrary authority
  within its own domain under the Mission's name; the damage is bounded
  by audience scoping, short grant lifetimes, and audit, not by the
  issuer, which never sees these tokens
  ({{I-D.draft-mcguinness-oauth-mission-cross-domain}}).

Mission Authority Server (standalone binding):
: When the standalone Mission Authority Server binding is used, a
  service outside the OAuth Authorization Server implements the Mission
  Issuer role: it must run the approval ceremony faithfully, keep the
  Mission record and its anchors intact, and serve accurate Mission
  state, while the deployment's tokens remain ordinary and carry no
  Mission binding. Its compromise is equivalent to Mission Issuer
  compromise (forged approvals, altered records, false state), with one
  addition: in this mode the PDP's credential-to-Mission join is the
  only binding between a presented credential and a Mission, so a
  compromised Mission Authority Server combined with the PDP's trust in
  it yields arbitrary attribution of authority to any credential the
  join accepts
  ({{I-D.draft-mcguinness-mission-authority-server}}).

Policy Enforcement Point (PEP):
: Sits at the last controllable boundary before an action and obtains a
  permit before each consequential action; under mediated execution it
  holds the sender-constraint key. It must be at the last boundary and
  must not act without a permit; it assumes the harness leaves no
  unmediated path. A compromised PEP can decline to consult the PDP or
  ignore its decision; the suite does not prevent this, and evidence
  makes it detectable after the fact, not in the moment
  ({{I-D.draft-mcguinness-mission-runtime}}).

Policy Decision Point (PDP):
: Evaluates each action against the Mission and returns a permit or deny.
  It must evaluate faithfully and fail closed; it assumes the inputs the
  PEP supplies are authentic. A compromised PDP can return arbitrary
  decisions; as with the PEP, evidence detects this after the fact but
  does not prevent it
  ({{I-D.draft-mcguinness-mission-runtime}}).

Mission state source:
: Reports current Mission state for the freshness the runtime layer
  requires, whether by introspection, the Status surface, or pushed
  Signals. It must report accurately within the staleness bound and be
  authenticated and integrity-protected. A compromised or spoofed state
  source can report `active` for a Mission that is revoked, defeating the
  kill switch; the runtime layer fails closed when state cannot be
  established within the bound
  ({{I-D.draft-mcguinness-oauth-mission-status}},
  {{I-D.draft-mcguinness-oauth-mission-signals}},
  {{I-D.draft-mcguinness-mission-runtime}}).

Harness:
: Establishes the execution environment in which governed work has no
  unmediated path to the actions the PEP mediates, and binds sessions,
  queues, and caches to Mission state. It must ensure no unmediated
  egress and must re-check state. A compromised harness can hand the
  agent an unmediated path, which defeats mediated execution for the
  classes that path reaches
  ({{I-D.draft-mcguinness-mission-harness}}).

Orchestrator:
: When multi-step unwinding is used, it drives compensation of in-flight
  work after a Mission stops. It must derive each step's reversibility
  class from a trusted source, and must compensate only under a
  documented authority basis: resource policy (`resource_policy`) or a
  separate remedial Mission
  ({{I-D.draft-mcguinness-mission-orchestration}}). Its compromise
  converts the kill switch into a channel for unauthorized remedial
  actions, driving compensating writes under the guise of unwinding.

Consent rendering layer:
: Renders the approved authority to the Approver at the approval event.
  It must render faithfully what is committed. A compromised renderer can
  display something other than the committed disclosure; the rendering
  assurance ladder bounds this by degree, up to an Approver authenticator
  signing the disclosure commitment, but no server-side commitment proves
  what a human perceived
  ({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}).

Access-request and approval workflow:
: When requestable denials are used, this workflow adjudicates an agent's
  request for authority it discovers it needs, integrating the AuthZEN
  Access Request and Approval Profile
  ({{I-D.draft-mcguinness-mission-authzen}}). It must not
  auto-approve a high-consequence escalation without an independent
  approver. A compromised approval service can grant escalations the
  model would otherwise route to a human, so it is in the trusted base
  wherever the access-request flow is enabled
  ({{I-D.draft-mcguinness-mission-runtime}}).

Transparency Service:
: When audit transparency is used, it is an append-only, non-equivocating
  log that issues inclusion receipts. It must not equivocate. A single
  compromised service can present different histories to different
  auditors; registering with more than one service makes equivocation
  detectable, but the non-equivocation guarantee is per-service
  ({{I-D.draft-mcguinness-mission-audit}}).

Event source:
: When completion or trigger-based discharge is used, it reports whether
  a completion event has occurred. It must report accurately and be
  authenticated. A compromised event source can keep a discharged entry
  derivable or falsely discharge one; the Authorization Server fails
  closed when it cannot determine the event status
  ({{I-D.draft-mcguinness-oauth-mission-completion}}).

Instance identity is identity substrate, like agent identity
generally. The instance issuer or agent attester that mints instance
assertions ({{I-D.draft-mcguinness-oauth-client-instance-assertion}},
{{I-D.draft-mcguinness-oauth-ai-agent-instance}}) sits outside this
model's trusted base, and its compromise forges actor attribution (who
executed) without forging Mission authority (what was approved). A
deployment that relies on instance-grade joins or instance-attributed
evidence extends its documented trust statement ({{documenting}}) to
that issuer.

# Cross-Cutting Assumptions {#cross-cutting}

Five assumptions hold across the whole model:

- **Sender-constrained credentials.** Mission-bound tokens are
  sender-constrained ({{I-D.draft-mcguinness-oauth-mission}}); a token
  exfiltrated without its proof-of-possession key is unusable. The model
  assumes the proof-of-possession mechanism is sound and keys are
  protected by their holder.
- **Fail-closed on authority, fail-safe on inert evidence.** Wherever
  a trusted component cannot establish an authority-relevant fact it
  needs (Mission state, a completion event, a verifiable decision),
  the relying component refuses rather than proceeds; a deployment
  that fails open at any such point forfeits the guarantee that point
  protects. Unavailability of inert evidence (a consent-evidence
  retrieval, the transparency feed, a Mandate) is recorded and is
  never by itself grounds for refusal
  ({{I-D.draft-mcguinness-mission-audit}}); tampered inert evidence
  is an integrity failure, handled by the profile that defines the
  artifact.
- **Role-scoped trust anchors.** A party trusted in one role (Mission
  issuer, evidence producer for one evidence type, SET transmitter,
  Transparency Service) is not thereby trusted in any other, and
  issuer trust is established by local policy or metadata, never
  inferred from being named inside a signed artifact
  ({{I-D.draft-mcguinness-mission-audit}},
  {{I-D.draft-mcguinness-mission-mandate}},
  {{I-D.draft-mcguinness-oauth-mission-cross-domain}}). The
  identity-assertion trust framework and its domain-authorized-issuer
  method ({{I-D.draft-mcguinness-oauth-id-assertion-framework}},
  {{I-D.draft-mcguinness-oauth-domain-authorized-issuer}}) are
  concrete publication and evaluation mechanisms for such policy.
- **Authority does not move on inert input.** Intent that the agent or
  attacker-reachable content can influence (`goal`, `purpose`,
  `success_criteria`, and disclosure-only audit material) is inert and
  cannot derive, widen, or gate authority
  ({{I-D.draft-mcguinness-oauth-mission}}).

# What the Model Does and Does Not Guarantee {#guarantees}

Given an intact trusted base, the model guarantees that a compromised or
injected agent cannot exceed the approved Authority Set and cannot move
authority by influencing inert intent; authority grows only by a fresh
approval that supersedes the prior Mission
({{I-D.draft-mcguinness-oauth-mission-expansion}}), not by agent action.
In a deployment that claims the runtime profile's
agent-compromise-resistant enforcement
({{I-D.draft-mcguinness-mission-runtime}}), the model further
guarantees that such an agent cannot unilaterally take a high-consequence
action it does not hold a mediated credential for. In the base profiles
the mechanisms behind that further guarantee (mediated credential
custody, no unmediated path, action-bound approval, and an
active-freshness state source) are recommendations, not requirements, and
a deployment that leaves them as recommendations does not obtain it. This
matches the suite's front-door framing: adopting the profiles does not by
itself make a deployment resistant to a compromised agent. The model
makes misuse bounded and, where evidence is produced, attributable. A
deployment that additionally claims the runtime profile's trifecta
containment enforces least exposure and the harness taint rule as
MUSTs, so an injected agent cannot egress on the strength of
untrusted content alone.

It does not make a compromised trusted component safe. The compromise of
each component degrades a specific guarantee, as listed in
{{trusted-base}}. It does not verify the agent's reasoning or the
truthfulness of its outputs; semantic and intent verification are a
non-goal of the suite ({{I-D.draft-mcguinness-oauth-mission}}). And it
inherits the threat models of the substrates the companions profile
(Token Exchange, Attenuating Agent Tokens, SCITT, Deferred Token
Response), which those substrates own. {{adversary-model}} gives the
per-adversary-move detail: what addresses each move, and the residual it
leaves.

"On behalf of" is not treated as a permission model. The family
splits what that phrase conflates: the Mission carries the approved
task the agent pursues for the Subject; a derived token presents
delegated authority without identity collapse, since `sub` remains
the Subject, `client_id` remains the approved agent, and the `act`
chain names who executed; and personal sanction is carried only by
approval events (the approval event, action-bound approval), never
inferred from token possession. Authority derived down this chain
never exceeds its source (the subset rule), so broad "acting as"
standing cannot be laundered out of a narrow approval.

# Adversary Model and Coverage {#adversary-model}

The trusted base ({{trusted-base}}) is the component view; this is the
adversary view. The adversary is assumed to control the agent, to reach
the content and inputs the agent processes (so it can attempt prompt
injection), and to capture tokens in transit. The adversary is assumed
not to break the cryptographic primitives, not to forge an
authenticated component's signing key, and not to compromise a
trusted-base component; those last two are the residuals of
{{trusted-base}}, not adversary moves this table covers.

The following maps each adversary move to the mechanism that addresses
it and to what is explicitly not stopped. The residual column is the
honest part: it is what a deploying party still owns.

| Adversary move | Addressed by | Residual: not stopped |
|---|---|---|
| Compromised or injected agent acts beyond its task | Authority fixed at the approval event (issuance); per-action PDP check (runtime) | Misuse within the approved scope; low-consequence authority the agent legitimately holds |
| Prompt injection tries to widen authority | Inert intent: `goal`, `purpose`, `success_criteria` never derive, widen, or gate authority | Injected text can still drive actions already in scope |
| Stolen or exfiltrated token | Sender-constraint (proof-of-possession); the high-consequence key is held by the PEP, not the agent (mediated execution) | A token stolen together with its key; soundness of the PoP mechanism |
| Token replayed at another resource (confused deputy) | Permit bound to audience, resource, `sub`, `client_id`, and action; cross-domain grant single-use and audienced | Correct binding configuration is the deployment's |
| Parameters change between decision and use (TOCTOU) | Parameter binding; the digest is reverified at the executing PEP immediately before acting | The PEP must sit at the last controllable boundary |
| Active Mission used as ambient standing authority | Per-action runtime enforcement, state re-check, fail-closed on stale state | An issuance-only deployment gets audit, not action-time defense |
| Revoked or expired Mission still acts (kill switch) | Issuance gating; runtime state re-check within the staleness bound; short token lifetimes | A window up to the staleness bound or token TTL; a spoofed state source (a trusted component) |
| Approver approves more than was shown | The rendered disclosure is committed; rendering-assurance ladder up to an authenticator-signed commitment | Comprehension: no server-side commitment proves what a human perceived or understood |
| Exfiltration of private data (the third leg of the lethal trifecta) | External communication is a gated consequential action; harness leaves no unmediated path; session taint downgrades egress after untrusted input (optional; recommended, not required); least-exposure context minimization narrows what an injected agent sees (runtime, harness); the composite is claimable as trifecta containment (runtime) | PEP-placement completeness; no information-flow control, so a sequence of in-scope steps can launder data |
| Offline sub-agent fan-out abuse | Capability monotonicity (narrow-only) and the runtime kill-switch re-check on the carried chain | Fan-out breadth is unobserved by the issuer; bounded by depth and policy, not by the issuer |
| Audit tampered, dropped, or reordered | Transparency: append-only log, inclusion receipts, non-equivocation | Single-service equivocation (per-service only; register with several); a producer can still log a false record (accountability, not prevention) |
| Agent fabricates results or acts on false data | Not addressed | Full: semantic and grounding verification are a non-goal; pair with a grounding layer if needed |
| A trusted-base component is compromised | Not addressed; evidence detects it after the fact | Not prevented; degrades the specific guarantee per {{trusted-base}} |

Four residuals are worth stating on their own, because they are the
limits most likely to matter and most often overstated away elsewhere:

- **Comprehension.** The suite can commit and bind what an Approver was
  shown; it cannot prove what the Approver perceived or understood. No
  electronic-consent scheme can.
- **Single-service equivocation.** Transparency is non-equivocating only
  per service; a deployment that needs that property checked registers
  with more than one independent service.
- **Offline breadth.** Offline attenuation
  ({{I-D.draft-mcguinness-oauth-mission-attenuation}}) bounds each child
  to a narrowing of its parent, but the issuer does not observe how many
  children are minted; breadth is bounded by depth and policy, not by the
  issuer.
- **Availability.** The model fails closed everywhere a trusted component
  cannot establish the fact it needs ({{cross-cutting}}), which trades
  availability for safety. An attacker who degrades a state source, an
  event stream, or a PDP does not gain unauthorized action, but converts
  the attack into work stoppage and, for in-flight work, unwind activity.
  A deployment provisions state-source, event-stream, and PDP
  availability accordingly, because under this model their outage stops
  governed work rather than loosening it.

# Revocation-to-Action Latency {#revocation-latency}

The kill switch is not instantaneous. Between the moment a Mission is
revoked and the last possible consequential action under it there is a
window, and its size is a composition of the mechanisms a deployment
runs. The following non-normative table names the governing parameter at
each layer; the end-to-end worst case for an action class is the tightest
layer the deployment enforces for that class.

| Configuration | Worst-case window | Governing parameter |
|---|---|---|
| Baseline (token lifetime only) | until the token expires | access-token `exp` |
| With introspection | one introspection cycle | per-request introspection at the issuer |
| With Mission Status | the staleness bound of the status view | published status staleness bound |
| With Mission Lifecycle Signals | event delivery latency, bounded by the poll fallback | signal delivery latency plus poll interval |
| With runtime enforcement | the per-class freshness bound | published per-class staleness bound |

The token lifetime and introspection layers are the issuance profile's
({{I-D.draft-mcguinness-oauth-mission}}); Mission Status
({{I-D.draft-mcguinness-oauth-mission-status}}), Mission Lifecycle Signals
({{I-D.draft-mcguinness-oauth-mission-signals}}), and runtime enforcement
({{I-D.draft-mcguinness-mission-runtime}}) each tighten the window
as their own profile defines. A deployment reads the row for the
mechanism it runs, or the tightest of several, to state how long a
revoked Mission can still act.

# Documenting the Trusted Base {#documenting}

A deployment cannot be evaluated against this model without knowing which
components it actually trusts. The runtime profile already requires a
deployment to document its enforcement scope, including its PEP locations,
PDP identities, Mission state source, and the execution paths it mediates
({{I-D.draft-mcguinness-mission-runtime}}). This model recommends
that a deployment claiming the Mission suite extend that documentation to
its full trusted base: which of the components in {{trusted-base}} it
relies on, which it does not deploy, and, for each consequential action
class, which components must be intact for the class's guarantee to hold.
This documentation is what lets a relying party or auditor reason about
the deployment's actual security posture rather than the model's
idealized one.

# Retention and the Audit Horizon {#retention}

The guarantees this model states at audit time depend on artifacts that
several profiles retain independently: Consent Evidence
({{I-D.draft-mcguinness-oauth-mission-consent-evidence}}), runtime
decision and execution evidence
({{I-D.draft-mcguinness-mission-runtime}}), and, where audit
transparency is used, the receipts that stand over evidence a deployment
may later erase ({{I-D.draft-mcguinness-mission-audit}}). Each of
those profiles anchors its retention on the Mission's audit horizon, the
deployment-declared window that runs at least the Mission's lifetime plus
a post-terminal period ({{I-D.draft-mcguinness-oauth-mission}}). A
deployment that retains every such artifact for at least the audit
horizon can answer, at audit time, how long each artifact was to be kept
for the guarantee that rests on it to still hold; an artifact dropped
before the horizon forfeits the guarantee that depended on it.

# Security Considerations {#security-considerations}

This document is itself a security-considerations document. It defines no
mechanism and adds no attack surface. Its content is the consolidation
above; the authoritative, normative security considerations are those of
the issuance profile ({{I-D.draft-mcguinness-oauth-mission}}) and each
companion it cites. Where this document and a profile appear to differ,
the profile governs.

# Privacy Considerations {#privacy-considerations}

The trusted components see Mission data: the Authorization Server and PDP
see the Authority Set, the consent rendering layer and Approver see the
disclosed authority, and the Transparency Service and state sources see
the Mission Identifier and its activity over time. The single canonical
Mission Identifier is a durable cross-audience correlator the suite
acknowledges and does not yet narrow
({{I-D.draft-mcguinness-oauth-mission}}); unlinkable or per-audience
presentation of Mission-bound authority is out of scope across the suite.
Each profile's Privacy Considerations govern the data its own component
handles.

# IANA Considerations {#iana}

This document makes no IANA request.

--- back

# Acknowledgments
{:numbered="false"}

This document is part of the Mission-Bound Authorization for OAuth 2.0
work and consolidates the trusted base and security assumptions that its
profiles establish individually.
