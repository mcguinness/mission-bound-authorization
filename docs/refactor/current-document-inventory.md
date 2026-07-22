# Current Document Inventory

Phase 0 baseline record for the repository repositioning. Factual snapshot of the repository as of branch `repositioning-exploration` (HEAD `dc7a897`). No draft was modified to produce this document.

## Build mechanism

- The repository builds with the [martinthomson/i-d-template](https://github.com/martinthomson/i-d-template) harness. The root `Makefile` includes `lib/main.mk`, cloning the template into `lib/` on first run (or symlinking `ID_TEMPLATE_HOME`).
- Toolchain per draft: kramdown-rfc (`kdrfc`, Ruby gem) renders `draft-*.md` to RFCXML, then `xml2rfc` produces `.txt` and `.html`. The default `make` target builds both formats for all drafts.
- The `Makefile` carries a repo-specific guard: GNU sed is required because the template's draft-name substitution exceeds BSD sed's per-expression buffer at this repository's draft count (`sed: unterminated substitute pattern`). On macOS: `brew install gnu-sed` and prepend `/opt/homebrew/opt/gnu-sed/libexec/gnubin` to `PATH`, or set `SKIP_SED_CHECK=1`. CI uses GNU sed and is unaffected. The README documents this in its "Command Line Usage" section.

## Inventory

28 drafts plus the README. Titles and categories are from kramdown-rfc front matter (`title:`, `category:`); the family uses three categories: `std` (19), `info` (3), `exp` (6). Purpose is condensed from each draft's abstract. README description is condensed from the draft's entry under the README's "The documents" section; the README groups the entries under headings noted in parentheses.

| Filename | Title | Cat | Purpose (from abstract) | Lines | README description (section) |
|---|---|---|---|---|---|
| draft-mcguinness-oauth-mission.md | Mission-Bound Authorization for OAuth 2.0 | std | Defines the Mission (durable record of an approved task), Mission Intent, Authority Set derivation, approval event, integrity anchors, the `mission` claim, and state-gated issuance, bound to the OAuth 2.0 AS | 3789 | The mandatory core, the "issuance profile"; "Every other document builds on this one" (The core) |
| draft-mcguinness-mission-architecture.md | An Architecture for Mission-Bound Authorization | info | The single structural view: thesis, invariants, roles, substrate interface, verb spine, deployment patterns, assurance levels; defines no mechanism | 2403 | The single structural view; Informational, profiles remain authoritative; "Read this first" (Architecture) |
| draft-mcguinness-mission-shaping.md | Mission Intent Shaping | info | How a client-side shaper turns a user request into a candidate Mission Intent; shaper output is untrusted input; optional Shaping Evidence | 1204 | How a shaper proposes a candidate Intent before submission; Informational (Approval time) |
| draft-mcguinness-oauth-mission-consent-evidence.md | Mission Consent Evidence for OAuth 2.0 | std | Commits the consent disclosure shown to the Approver via `consent_rendering_hash` and a signed Consent Evidence object; translation floor; Disclosure Interrogation | 1505 | Commits the recorded approval surface so an auditor can reconstruct it (Approval time) |
| draft-mcguinness-oauth-mission-approval.md | Mission Deferred Approval for OAuth 2.0 | std | Makes the approval event asynchronous by profiling OAuth Deferred Token Response; record created atomically with the async decision | 544 | Asynchronous approval; narrowed grants resolve to denial and resubmission (Approval time) |
| draft-mcguinness-oauth-mission-approval-revision.md | Mission Approval Revision for OAuth 2.0 | exp | Adds a `revisable` mode to Deferred Approval: the AS signals refused dimensions and invites a narrowing revision within the same deferred approval | 677 | Experimental companion to Deferred Approval; narrowing only (Approval time) |
| draft-mcguinness-oauth-mission-status.md | Mission Status and Lifecycle for OAuth 2.0 | std | `mission_id`-keyed signed status surface plus a lifecycle endpoint (revoke, suspend, resume, complete), the `suspended`/`completed` states, and Mission Completion (`terminal_when`, entry discharge) | 1878 | Status surface, lifecycle endpoint, and Completion as the narrowing counterpart of Expansion (Lifecycle) |
| draft-mcguinness-oauth-mission-signals.md | Mission Lifecycle Signals for OAuth 2.0 | std | Shared Signals Framework profile: signed SETs on each Mission lifecycle transition, push or poll; the push complement to Status | 794 | Push complement to the pull-based Status surface; latency optimization (Lifecycle) |
| draft-mcguinness-oauth-mission-expansion.md | Mission Expansion for OAuth 2.0 | std | Widening authority requires a fresh approval creating a successor Mission that supersedes its predecessor | 1154 | How to widen a Mission's authority; distinct from authentication step-up (Lifecycle) |
| draft-mcguinness-oauth-mission-progressive.md | Mission Progressive Authorization for OAuth 2.0 | exp | Approver pre-consents to an authority ceiling and drawdown policy; expansions within the ceiling may be adjudicated by policy | 606 | Experimental companion to Expansion; high-consequence widening still requires the human (Lifecycle) |
| draft-mcguinness-mission-discovery.md | Mission Open-World Discovery | exp | Governed discovery for agents that meet resources their approval could not name: the Encounter, identity pinning, Discovery Adjudication, Discovery Evidence | 739 | Experimental; default-closed adjudication against a pre-consented ceiling; two floors (Lifecycle) |
| draft-mcguinness-oauth-mission-management.md | Mission Management for OAuth 2.0 | std | Fleet management: authenticated Mission enumeration and bulk lifecycle operations with dry-run and per-Mission outcome manifest | 1018 | The fleet-management surface the status profile defers; "highest-blast-radius surface in the family" (Lifecycle) |
| draft-mcguinness-mission-runtime.md | Mission-Bound Runtime Enforcement | std | Decision contract at the point of use: PEP obtains a permit from a PDP per consequential action; permit-parameter binding, fail-closed posture, credential custody, mediated execution, Mission Receipt | 2635 | The runtime decision contract; sets the High-Assurance Agent bar (Runtime enforcement) |
| draft-mcguinness-mission-authzen.md | Mission-Bound Runtime Enforcement: AuthZEN Profile | std | Concrete OpenID AuthZEN binding of the runtime decision contract; Decision Evidence, Execution Evidence, Refusal Record objects; wire-visible failure identifiers | 2676 | Binds the contract; does not restate the enforcement semantics the runtime profile owns (Runtime enforcement) |
| draft-mcguinness-mission-authority-server.md | Mission Authority Server | std | Standalone Mission Issuer beside an unchanged AS: full Mission governance without Mission-bound tokens or issuance gating; Mission Join; Enterprise Mission Authority Profile | 2086 | Peer binding, AS-optional deployment mode, estate control plane (Alternate bindings and the substrate) |
| draft-mcguinness-oauth-mission-issuance-grant.md | Mission Issuance Grant for OAuth 2.0 | std | Short-lived one-time assertion minted by a MAS for an active Mission; an estate AS redeems it (RFC 7523) to mint Mission-bound tokens | 791 | The issuance join between the standalone binding and a Mission-aware AS (Alternate bindings and the substrate) |
| draft-mcguinness-mission-aauth.md | Mission-Bound Authorization for AAuth | std | Binds the Mission model to AAuth's native mission concept: blob-carried record, projected integrity anchors, lifecycle on the mission log, Person Server gates issuance | 1250 | The AAuth binding, first to a non-OAuth substrate; PS-asserted mode is full provision (Alternate bindings and the substrate) |
| draft-mcguinness-mission-uma.md | Mission-Bound Authorization for UMA 2.0 | exp | Fourth binding: Mission fills UMA 2.0's unspecified authorization assessment; RPT is the Mission-bound credential, PCT is continuity not authority | 1076 | Experimental sketch; first binding authored against the Substrate Requirements contract (Alternate bindings and the substrate) |
| draft-mcguinness-mission-substrate.md | Mission Substrate Requirements | std | Normative consolidation of what any further binding must provide: eight requirements, composition table, conformance via a Mission Substrate Statement | 688 | For authors of new bindings; changes nothing for the three existing bindings; "the core remains the model's definitional home" (Alternate bindings and the substrate) |
| draft-mcguinness-mission-metering.md | Mission Consumption Metering | exp | Cumulative consumption bounds (`max_budget`, `max_calls`, `max_duration`, `max_egress_volume`), the `exclusive` control, runtime metering, AuthZEN wire binding | 693 | Experimental; without it Missions carry no cumulative bounds (Alternate bindings and the substrate) |
| draft-mcguinness-mission-harness.md | Mission-Aware Agent Harnesses | std | How a harness binds sessions, task graphs, queues, cached connections, and sub-agent handles to Mission state; re-check, pause, suppress, terminate; mediated execution environment | 1382 | "Session continuity is not authority"; establishes the mediated execution environment (Agent runtime) |
| draft-mcguinness-mission-orchestration.md | Mission Orchestration and Unwinding | exp | Reversibility classes per step, unwind plan recorded before dispatch, safe unwinding when a Mission stops, compensation after termination | 941 | Governs how workflow state is unwound once continuation is stopped (Agent runtime) |
| draft-mcguinness-oauth-mission-child-delegation.md | Mission Child Delegation for OAuth 2.0 | std | Parent Mission authorizes a Child Mission for a sub-agent: lineage, strict-subset authority, expiry capped by parent, fan-out controls, cascade revocation | 1353 | A child is never created by session ancestry alone (Sub-agents) |
| draft-mcguinness-oauth-mission-attenuation.md | Mission Offline Attenuation for OAuth 2.0 | exp | Profiles Attenuating Agent Tokens: a Mission-bound token holder mints a narrower child token offline, same `mission` claim, chain-verifiable narrowing | 755 | Removes the AS from the fan-out hot path; kill switch preserved via runtime state re-check (Sub-agents) |
| draft-mcguinness-oauth-mission-cross-domain.md | Mission Cross-Domain Projection for OAuth 2.0 | std | One Mission honored across trust domains: originating Issuer projects audience-scoped authority via a short-lived cross-domain grant; Resource AS mints local Mission-bound tokens | 1110 | One hop; extracted from the core so the mandatory profile carries no cross-domain dependencies (Cross-domain projection) |
| draft-mcguinness-mission-mandate.md | Mission Mandate | std | Signed, portable, independently verifiable statement of a Mission's committed facts; evidence, not a credential; optional SD-JWT selective disclosure | 1028 | Makes committed facts portable; presenting it authorizes nothing; state still comes from Status or Signals (Proof and portability) |
| draft-mcguinness-mission-audit.md | Mission Audit Transparency | std | Registers Mission evidence into a SCITT Transparency Service as Signed Statements keyed by Mission; offline-verifiable Receipts; hash-committed evidence | 1139 | Makes the suite's evidence tamper-evident; one append-only feed per Mission; layers onto any level (Proof and portability) |
| draft-mcguinness-mission-security-model.md | Mission Security Model | info | Cross-cutting consolidation of the trusted base: what each component must achieve, what it assumes of the others, how its compromise degrades guarantees | 1227 | The single view of the spread-out trusted base; defines no new mechanism (Security model) |
| README.md | Mission-Bound Authorization (repo landing page) | n/a | Suite overview: the Mission, the architecture, reading order, minimal implementation, deployment levels and adoption order, the standardization ask, per-document catalog, build usage | 829 | n/a (is itself the source of the description column) |

Notes:

- The README's "The documents" section states the suite's naming boundary: profiles extending the Authorization Server's own surfaces keep "oauth" in the draft name; profiles specifying components outside the AS are named without it and are defined against the Mission model's substrate primitives.
- The README refers to the core as the "issuance profile" throughout.
- `docs/adr/` contains ADR 0001 (AAuth/Mission/OAuth layering); `notes/` contains one integration note. Neither is part of the draft set.

## Baseline build report

Environment: macOS (Darwin 25.5.0), GNU sed prepended to `PATH` per the Makefile guard, kramdown-rfc 1.7.39 (`kdrfc` from the user gem bin), xml2rfc from Homebrew. The i-d-template `lib/` was cloned fresh by the Makefile on first invocation.

Command run from the worktree root:

| Item | Value |
|---|---|
| Command | `PATH="/opt/homebrew/opt/gnu-sed/libexec/gnubin:..." make <six .txt targets>` |
| Targets | draft-mcguinness-oauth-mission.txt, draft-mcguinness-mission-substrate.txt, draft-mcguinness-mission-architecture.txt, draft-mcguinness-mission-aauth.txt, draft-mcguinness-mission-runtime.txt, draft-mcguinness-mission-authzen.txt |
| Result | PASS (exit 0); all six .txt artifacts produced |

Per-target result (kramdown-rfc then xml2rfc-txt, both `OK` for each):

| Target | kramdown-rfc | xml2rfc-txt |
|---|---|---|
| draft-mcguinness-oauth-mission | OK | OK |
| draft-mcguinness-mission-substrate | OK | OK |
| draft-mcguinness-mission-architecture | OK | OK |
| draft-mcguinness-mission-aauth | OK | OK |
| draft-mcguinness-mission-runtime | OK | OK |
| draft-mcguinness-mission-authzen | OK | OK |

Known pre-existing warnings (present before this phase; not introduced by it):

- kramdown-rfc emits `*** warning: explicit settings completely override canned bibxml in reference I-D.draft-...` once per front-matter reference that carries an explicit title/target/author block. Every family cross-reference is written this way (so the editor's-copy links resolve to the GitHub Pages builds), so each draft build emits one such warning per family reference it carries. The same warning fires for the externally referenced drafts (I-D.draft-mcguinness-oauth-actor-profile, -client-instance-assertion, -ai-agent-instance, -id-assertion-framework, -domain-authorized-issuer, -actor-receipts, -actor-proofs, and I-D.draft-hardt-oauth-aauth-protocol / -aauth-r3).
- kramdown-rfc emits `** simplified markup "<spanx style=\"verb\">error</spanx>" into "error" in table heading` for table headings that use code markup; 5 occurrences across the full-family build.
- No errors and no other warning classes were observed.

Full default target: PASS (exit 0). After the six-target baseline, `make -j4` (the default target) built kramdown-rfc, xml2rfc-txt, and xml2rfc-html for all 28 drafts: 28 `.txt` and 28 `.html` artifacts produced, no errors, only the two warning classes described above.
