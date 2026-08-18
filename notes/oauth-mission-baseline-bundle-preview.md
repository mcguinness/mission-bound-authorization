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

| Level | Normative documents | Disabled conditionals |
|---|---|---|
| OAuth Mission Issuance Baseline | core (self-contained by design) | core's OPTIONAL capabilities as elected; Cross-Domain disabled |
| OAuth Mission Runtime-Enforced Baseline | the issuance slice plus substrate, status, runtime, runtime-evidence, authzen | Cross-Domain disabled; the transaction-assurance tier a named extension |

An issuance-only adopter is never told the runtime documents are mandatory,
and the Issuance Baseline is never blocked on their conformance inventories.

## Reading order

1. mission-architecture (preface): the Mission model, invariants, and
   assurance levels the rest cite.
2. mission-substrate (floor): the commitment construction and kernel
   contract runtime implementers consume and binding authors profile.
3. oauth-mission (floor, core): the floor itself. An Issuance Baseline
   adopter can stop here.
4. oauth-mission-status (floor): observing or changing Mission state beyond
   token expiry (revoke, suspend, complete).
5. mission-runtime (floor): point-of-use checks, not just issuance-time
   gating.
6. mission-runtime-evidence (floor): durable, verifiable records of runtime
   enforcement decisions.
7. mission-authzen (floor): the wire mapping for a PDP that speaks AuthZEN.

## Pin table

Pinning is one coherent snapshot. The in-repository documents below share a
single `source_repository_commit`; per-document commits are informational
traceability only, never assembly inputs. External dependencies are pinned
by repository (or datatracker document, or published standard), commit or
revision, path or URL, and a content digest where one can be taken.

Coherent snapshot commit: `eb3a8f234a6367d388957f1be4ac73b0cc78fb13` (2026-08-18).

### In-repository documents

| Document | Title | File | Last-touched commit (informational) | Date |
|---|---|---|---|---|
| mission-architecture | An Architecture for Mission-Bound Authorization | draft-mcguinness-mission-architecture.md | `122586a334069ba4a934a9b988b7bb1b0ed7926a` | 2026-08-17 |
| mission-substrate | Mission Substrate Requirements | draft-mcguinness-mission-substrate.md | `77eb14b40b6a203bcdc4ea6bab270ebbbc1c767f` | 2026-08-16 |
| oauth-mission (core) | Mission-Bound Authorization for OAuth 2.0 | draft-mcguinness-oauth-mission.md | `7d97a7b38a844163db1eaa6bf6e01e002554e487` | 2026-08-16 |
| oauth-mission-status | Mission Status and Lifecycle for OAuth 2.0 | draft-mcguinness-oauth-mission-status.md | `2399f170964924d80f8ceaad81d41892411d4465` | 2026-08-17 |
| mission-runtime | Mission-Bound Runtime Enforcement | draft-mcguinness-mission-runtime.md | `122586a334069ba4a934a9b988b7bb1b0ed7926a` | 2026-08-17 |
| mission-runtime-evidence | Mission Runtime Evidence | draft-mcguinness-mission-runtime-evidence.md | `3694449a787e0be021803eb82c5ee6eaae3f7ddd` | 2026-08-14 |
| mission-authzen | Mission-Bound Runtime Enforcement: AuthZEN Profile | draft-mcguinness-mission-authzen.md | `f5977e02bfb4bf8af22d2114ed1e16f520672b07` | 2026-08-16 |

### External normative dependencies

Copied verbatim from `notes/external-pins.json`, whose entries are all
established (none pending) as of this preview. This copies every
established registry entry for registry fidelity, not only those a bundle
document cites. Six entries (ARAP, AUTHZEN, AUTHZEN-OBL, RAR-METADATA,
STATUS-LIST, ISO4217) are normative dependencies of the seven documents
above. AAUTH is not: it pins the upstream for `mission-aauth`, a
Compose/bindings document (the AAuth Mission Context Bundle) outside this
bundle's Start/floor set, and is carried here for registry completeness
rather than because any floor document cites it.

| Id | Kind | Source | Pin | Location | SHA-256 |
|---|---|---|---|---|---|
| AAUTH | git | dickhardt/AAuth | `f1569261d0b9d179324f1665db1597f81cd0a851` (PR #73 merged) | draft-hardt-oauth-aauth-protocol.md | `041f6a1f0ece3ca5b2f9820821e8fb6b1d7a8f2c2e8c58b53b52157684a5c4b6` |
| ARAP | git | openid/authzen | `7327cb1bcea8cfc223e7b6816535f60149845468` (openid/authzen #515, OIDF WG stream) | profiles/authzen-access-request-approval/authzen-access-request-approval-profile-1_0.md | `621cebdba15a99eff00398052b560904793564de28b2062fce161fd73320094d` |
| AUTHZEN | git | openid/authzen | `046040e419b553f3a27683d6caf7cf30c32f7909` (main branch, established at Ship 3) | api/authorization-api-1_0.md | `c8031f32b10c285bb002d429e1d42adeb5d700997429052cc7c269451a18f360` |
| AUTHZEN-OBL | git | openid/authzen | `046040e419b553f3a27683d6caf7cf30c32f7909` (main branch, established at Ship 3) | profiles/authzen-obligations-profile-1_0.md | `c166295296903934368f645e2dd18b82c1f7b5572aa901df8c7061cf03899025` |
| RAR-METADATA | git | yaron-zehavi/oauth-rich-authorization-requests-metadata | `524bd83b47f63f64af91803364a53f1b82b07beb` (main branch, established at Ship 3) | draft-zehavi-oauth-rar-metadata.md | `f95b9441d0159af2e280ad8afc833bb24431229cf58b85a9ec3ef4db9afeb74d` |
| STATUS-LIST | datatracker | draft-ietf-oauth-status-list | rev 21 (2026-06-21, established at Ship 3) | https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-21.txt | `21e4867a01f73cee2ebc1408d150c87f77898c3d1549ebc25c80fa352221f846` |
| ISO4217 | standard | ISO (International Organization for Standardization) | ISO 4217:2015, Codes for the representation of currencies and funds | (paywalled standard, no fetchable canonical file) | (none, see note below) |

Notes, copied from each entry's registry `note` field:

- **AAUTH**: datatracker -10 is divergent (pre-person-token); disclosed, not
  the pin.
- **ARAP**: corrected at PR #595 review (P1). Pins the later OIDF WG-stream
  commit (#515, 2026-06-03, "Mark profile as OIDF stream document"), one day
  after the PR #508 merge commit (`f4003c6b4604f889f2379f8953bc93ae8a8df961`,
  2026-06-02): the reference implementation was verified against this later
  content. Git blob hash `670f5831f6e786c70944887dec6ab14de26986f8` is
  preserved as supplementary detail, confirmed by API to be the blob at this
  commit's path. The prior entry labeled that same blob "PR #508 merged",
  which named the wrong commit for the pinned content: PR #508's own merge
  commit carries a different file at a different digest
  (`27893ad72a766680c73530cbe911648dc28d921de6a76bf2f38b907aeb3f06cd`,
  confirmed by API), so the old row mixed two WG streams under one label.
- **AUTHZEN**: draft-mcguinness-mission-authzen cites AUTHZEN (OpenID
  AuthZEN Authorization API 1.0) as a normative reference; derived at PR
  #595 review (P3). Located via the repo tree at
  `api/authorization-api-1_0.md` (front matter docname:
  `authorization-api-1_0`); the `archive/` and `certification/` paths in the
  same repo hold prior and scenario variants and are not the pin. Commit and
  content fetched and digested directly from the GitHub API and raw content
  at the pinned commit.
- **AUTHZEN-OBL**: the AuthZEN Obligations profile the family's ARAP-native
  lanes cite alongside ARAP itself. Located via the repo tree at
  `profiles/authzen-obligations-profile-1_0.md` (front matter docname:
  `authzen-obligations-profile-1_0`, title "AuthZEN Profile for Obligations
  - Draft 1"); same commit as AUTHZEN since both live in `openid/authzen`
  and were pinned in the same lookup. Had no pin anywhere before Ship 3;
  established from scratch.
- **RAR-METADATA**: draft-mcguinness-oauth-mission and
  draft-mcguinness-mission-authzen cite `I-D.draft-zehavi-oauth-rar-metadata`
  (RAR-type metadata) as a normative reference; derived at PR #595 review
  (P3). A GitHub repo exists for this draft (checked at Ship 3 via
  repository search), so it is pinned as a git source rather than a bare
  datatracker revision. The file's own front matter docname is
  `draft-zehavi-oauth-rar-metadata-latest` (the editor's copy); datatracker's
  latest submitted revision at Ship 3 is -06 (id 153116, checked via the
  datatracker document API), disclosed for cross-reference, not the pin.
- **STATUS-LIST**: draft-mcguinness-oauth-mission-status cites
  `I-D.draft-ietf-oauth-status-list` (OAuth Status List) as a normative
  reference; derived at PR #595 review (P3). The citing draft's front matter
  carries no seriesinfo override on this reference (a bare
  `I-D.draft-ietf-oauth-status-list:` entry), so no revision is pinned in
  the draft text itself; this registry pins the latest datatracker revision
  as of establishment (-21, confirmed via the datatracker document API, id
  121268), which coincides with the implemented revision
  `src/SPEC_VERSIONS.md` already records for shipped code. That
  `SPEC_VERSIONS.md` row is a version pin for shipped code, not the
  commit-and-digest planning pin this registry tracks; the two are
  independently sourced and happen to agree on -21.
- **ISO4217**: draft-mcguinness-oauth-mission cites ISO4217 as a normative
  reference with front-matter seriesinfo `ISO: "4217:2015"`; this entry
  pins that same edition. No sha256: ISO 4217:2015 is a paywalled standard
  with no freely republishable canonical file, so there is no text this
  registry can legally fetch and hash; the publisher and edition identifier
  are the pin, and this is the disclosed reason sha256 is absent.

## Coverage

This preview makes no conformance-coverage claim. The coverage ledger joins
v0 proper, tracked by issues #591 through #594.

## Worked example

The worked example stitches demo scenarios 1, 2, and 8 from `src/DEMO.md`:
issuance (scenario 1), the happy path with Decision Evidence (scenario 2),
and revocation freshness (scenario 8). The revocation-denial leg is
required because prompt cutoff is the entire value of the Runtime-Enforced
level over the Issuance level.
