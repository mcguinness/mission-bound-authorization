# OAuth Mission Baseline Bundle: Preview (v0-preview.1)

This is an exploratory preview of the OAuth Mission Baseline Bundle, not the
marketed v0 publication. `v0-preview.1` and `v0` never share a version
identity: this preview is not digest-verified immutable in the way a gated
publication promises, and it carries no conformance-coverage claims. Treat
every claim here as provisional until v0 proper ships.

## What this bundle is

The OAuth Mission Baseline Bundle is an implementation guide, not a 42nd
Internet-Draft. It selects and pins existing normative text; it never
invents a requirement of its own. It replaces the work of discovering,
ordering, and reconciling six documents (plus a preface) with one
publication a reader can start from. Bundle contents and minimum
conformance profile are never synonymous: the seven-document bundle below is
the reader edition's union, and each level's exact normative slice is the
profile matrix in the next section.

Bundle contents: substrate, core, status, runtime, runtime-evidence, authzen
(the six normative floor documents), plus architecture as the informative
reader preface.

## The two levels

| Level | Normative document slugs | Disabled conditionals | Named extensions |
|---|---|---|---|
| OAuth Mission Issuance Baseline | `draft-mcguinness-oauth-mission` | Cross-Domain | (none) |
| OAuth Mission Runtime-Enforced Baseline | `draft-mcguinness-oauth-mission`, `draft-mcguinness-mission-substrate`, `draft-mcguinness-oauth-mission-status`, `draft-mcguinness-mission-runtime`, `draft-mcguinness-mission-runtime-evidence`, `draft-mcguinness-mission-authzen` | Cross-Domain | Transaction Assurance |

Core (`draft-mcguinness-oauth-mission`) is self-contained by design: the
Issuance Baseline names no other floor document. An issuance-only adopter
is never told the runtime documents are mandatory, and the Issuance
Baseline is never blocked on their conformance inventories.

## Reading order

1. mission-architecture (preface): the Mission model, invariants, and
   assurance levels the rest cite.
2. oauth-mission (floor, core): the floor itself, self-contained by
   design. An Issuance Baseline adopter stops here.
3. mission-substrate (floor): the commitment construction and kernel
   contract runtime implementers consume and binding authors profile.
4. oauth-mission-status (floor): observing or changing Mission state beyond
   token expiry (revoke, suspend, complete).
5. mission-runtime (floor): point-of-use checks, not just issuance-time
   gating.
6. mission-runtime-evidence (floor): durable, verifiable records of runtime
   enforcement decisions.
7. mission-authzen (floor): the wire mapping for a PDP that speaks AuthZEN.

## Pin table

Pinning is one coherent snapshot. The in-repository documents below share a
single `source_repository_commit`; per-document commits are traceability,
not assembly inputs, but they are checked traceability: scripts/check-bundle-manifest.mjs
re-derives each one from git and rejects the build on a mismatch. External
dependencies are pinned by repository (or datatracker document, or
published standard), commit or revision, path or URL, and a content
digest where one can be taken.

Coherent snapshot commit: `eb3a8f234a6367d388957f1be4ac73b0cc78fb13` (2026-08-18).

### In-repository documents

| Document | Title | File | Last-touched commit (verified) | Date |
|---|---|---|---|---|
| mission-architecture | An Architecture for Mission-Bound Authorization | draft-mcguinness-mission-architecture.md | `122586a334069ba4a934a9b988b7bb1b0ed7926a` | 2026-08-17 |
| mission-substrate | Mission Substrate Requirements | draft-mcguinness-mission-substrate.md | `77eb14b40b6a203bcdc4ea6bab270ebbbc1c767f` | 2026-08-16 |
| oauth-mission (core) | Mission-Bound Authorization for OAuth 2.0 | draft-mcguinness-oauth-mission.md | `7d97a7b38a844163db1eaa6bf6e01e002554e487` | 2026-08-16 |
| oauth-mission-status | Mission Status and Lifecycle for OAuth 2.0 | draft-mcguinness-oauth-mission-status.md | `2399f170964924d80f8ceaad81d41892411d4465` | 2026-08-17 |
| mission-runtime | Mission-Bound Runtime Enforcement | draft-mcguinness-mission-runtime.md | `122586a334069ba4a934a9b988b7bb1b0ed7926a` | 2026-08-17 |
| mission-runtime-evidence | Mission Runtime Evidence | draft-mcguinness-mission-runtime-evidence.md | `3694449a787e0be021803eb82c5ee6eaae3f7ddd` | 2026-08-14 |
| mission-authzen | Mission-Bound Runtime Enforcement: AuthZEN Profile | draft-mcguinness-mission-authzen.md | `f5977e02bfb4bf8af22d2114ed1e16f520672b07` | 2026-08-16 |

### External normative dependencies

The six external normative dependencies of the seven documents above.
`notes/external-pins.json` is the registry of record: it carries each
pin's immutable `pin_id`, its `reference_keys` (the citation keys these
documents actually use), and the full provenance history behind each pin,
including corrections. The table below is a reader-facing summary, one
concise provenance note per pin, not a substitute for the registry.

| Id | Kind | Source | Pin | Location | SHA-256 | Provenance |
|---|---|---|---|---|---|---|
| ARAP | git | openid/authzen | `7327cb1bcea8cfc223e7b6816535f60149845468` | profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md | `621cebdba15a99eff00398052b560904793564de28b2062fce161fd73320094d` | OIDF WG-stream commit #515; corrected onto this commit at PR #595 (registry has the full correction history). |
| AUTHZEN | git | openid/authzen | `2b07366d2dfd7ad9e2dedf44b97bd41e8a2b8c63` | api/authorization-api-1_0.md | `c8031f32b10c285bb002d429e1d42adeb5d700997429052cc7c269451a18f360` | Cited by mission-authzen as AUTHZEN; pins the commit that last touched this file, corrected at Ship 3 review from a later, unrelated commit. |
| AUTHZEN-OBL | git | openid/authzen | `de66ead0f722c2eb2fe8f2b399c36ce90c8ddcd3` | profiles/authzen-obligations-profile-1_0.md | `c166295296903934368f645e2dd18b82c1f7b5572aa901df8c7061cf03899025` | Cited by mission-authzen as AUTHZEN-OBL; pins the commit that last touched this file, corrected at Ship 3 review from a later, unrelated commit. |
| RAR-METADATA | git | yaron-zehavi/oauth-rich-authorization-requests-metadata | `524bd83b47f63f64af91803364a53f1b82b07beb` | draft-zehavi-oauth-rar-metadata.md | `f95b9441d0159af2e280ad8afc833bb24431229cf58b85a9ec3ef4db9afeb74d` | Editor's GitHub copy; datatracker's own latest submitted revision is -06. |
| STATUS-LIST | datatracker | draft-ietf-oauth-status-list | rev 21 (2026-06-21) | https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt | `21e4867a01f73cee2ebc1408d150c87f77898c3d1549ebc25c80fa352221f846` | Latest datatracker revision as of establishment; the citing draft pins no revision itself. |
| ISO4217 | standard | ISO (International Organization for Standardization) | ISO 4217:2015 | (paywalled standard, no fetchable canonical file) | (none) | Publisher and edition are the pin; no freely republishable text exists to hash. |

## Coverage

This preview makes no conformance-coverage claim. The coverage ledger joins
v0 proper, tracked by issues #591 through #594.

## Worked example

The worked example stitches demo scenarios 1, 2, and 8 from `src/DEMO.md`:
issuance (scenario 1), the happy path with Decision Evidence (scenario 2),
and revocation freshness (scenario 8). The revocation-denial leg is
required because prompt cutoff is the entire value of the Runtime-Enforced
level over the Issuance level.
