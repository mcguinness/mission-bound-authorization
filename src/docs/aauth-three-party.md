# AAuth three-party route

The reference AAuth Person Server and Resource for issue #836 slice 2
(D303), with the test kit's agent. This note records what the slice
builds and which paths its tests demonstrate. It makes no conformance or
interoperability claim: the results below name demonstrated paths only,
between components of this repository, on loopback.

## Pins

- AAuth: `draft-hardt-oauth-aauth-protocol-11` (2026-09-25).
- Signature-Key: `draft-hardt-httpbis-signature-key-09` (2026-09-13).
- The AAuth binding: `draft-mcguinness-mission-aauth.md` at `59720df0`, as
  `conformance-manifest.json` pins it in `source.specs`.
- RFC 9421, Signature-Key, key discovery and token verification come from
  `@mission/aauth-wire` (slice 1) at the same pins; nothing here
  re-implements them. `src/SPEC_VERSIONS.md` maps each pin to code and tests.

## Components

| Package | Path | Configuration |
|---|---|---|
| `@mission/aauth-ps` | `src/services/aauth-ps` | `src/config/aauth-ps.json` |
| `@mission/aauth-resource` | `src/services/aauth-resource` | `src/config/aauth-resource.json` |
| `@mission/aauth-testkit` (test only) | `src/packages/aauth-testkit` | none: the agent-provider stub, the agent client and the loopback network |

## Governance mode

Deterministic, from static configuration; no model and no person in the
loop. `agents` in `aauth-ps.json` is both the agent allowlist and the
agent-person binding, and `mission_governed` places an agent under mission
governance. A proposal is decided at once: the first `description_rules`
entry whose text the description contains (case-insensitive) decides,
else `default_decision`. The shipped file governs `aauth:assistant@ap.test`
and `aauth:planner@ap.test` (alice) and admits `aauth:helper@ap.test` (bob)
missionless.

## Access mode covered

Three-party access with PS-issued auth tokens: agent, PS and Resource,
with no access server. The Resource accepts an auth token only when its
`iss` equals its `ps`.

## Endpoints

| Party | Endpoint | Behavior |
|---|---|---|
| PS | `GET /.well-known/aauth-person.json`, `GET /.well-known/jwks.json` | metadata and JWKS, `cache-control: max-age=300` |
| PS | `POST /mission` (`mission_endpoint`) | propose and decide; an approval returns `s256`, the exact blob bytes as `mission`, and a person token per proposed resource; the agent client accepts it only when the blob's `agent` is its own identifier |
| PS | `GET /mission/{mission_s256}` | the owner's read of the persisted bytes; a local surface (AAuth defines only POST at this URL, which answers 405 here) |
| PS | `POST /person` (`person_token_endpoint`) | person tokens, with or without `mission_s256` |
| PS | `POST /token` (`auth_token_endpoint`) | Section 6.7.2 steps 1 to 4, then a direct auth token; a resource token carrying `interaction` is refused |
| Resource | `GET /.well-known/aauth-resource.json`, `GET /.well-known/jwks.json` | metadata and JWKS |
| Resource | `POST /authorize` (`authorization_endpoint`) | a resource token for a person token and a defined scope |
| Resource | `GET /api/documents`, `POST /api/documents` | protected operations (`documents.read`, `documents.write`), challenged with `AAuth-Requirement` |

## State

- **PS, durable.** Missions with their exact blob bytes, issued-token
  records (`iss`, `jti`, kind, `aud`, `exp`, `sub`, agent and
  `mission_s256`), the mission log and the pairwise-`sub` key, in SQLite
  through `@mission/store`'s `openDurableStore`, at a file the caller names.
- **PS, in memory.** The replay cache, the bounded security-event list, and
  the signing key, generated at each boot.
- **Resource, in memory.** The effect log, person records, issued resource
  tokens, the replay cache, the operations' data and the signing key.
- Restart and recovery are slice 3.

## Issuance commit

Key resolution and token verification await, and time passes while they
do. Each issuance therefore reads the clock again and checks, with no
await before its record is written:

- at the auth token endpoint, after step 4: the resource token's `exp`
  (`expired_resource_token`), the presented token's `exp`
  (`expired_presented_token`), the mission's state and `expires_at`
  (`mission_terminated`), and the issued token's `exp` cap;
- at the person token endpoint (the mission gate and the `exp` cap) and the
  approval (the requested `expires_at` and each person token's `exp` cap),
  which read the time after authentication.

The record is written first and the token is minted after, from claims
already fixed, so no token is issued already expired. When the cap fails
because the agent token that authenticated the request expired meanwhile,
the answer is 401 with `Signature-Error: error=expired_jwt`, as for any
failure of the Signature-Key token. Tests drive these paths by advancing
the clock while a key is resolved.

## Exclusions

- No access server: four-party access, V6 and V15 are out.
- No call chaining (V13): `upstream_token` is refused `invalid_request`.
- No sub-agents: a sub-agent calling the PS directly is refused.
- No 202 deferral and no interaction: the approver decides at once, the
  agent client reports a 202 as unsupported, and the PS refuses a resource
  token carrying `interaction` (AAuth -11 Section 7.2.3) with 403
  `user_unreachable`, issuing and recording nothing.
- No status or termination surface, and no P2 (the management control
  plane): slice 3. Tests terminate a mission by a direct store transition.
- No revocation: the issued-token records exist, and nothing consults them.
- No launcher.

## Test topology

- Identifiers carry no port: `https://ap.test`, `https://ps.test`,
  `https://resource.test`.
- Each party is real HTTP on an ephemeral port of 127.0.0.1. An
  `https://host/path` URL travels as plain HTTP to that port, with `Host`
  the identifier's host. There is no TLS.
- The agent signs `@method`, `@authority`, `@path` and `signature-key`, plus
  `content-digest` and `content-type` on a body; `@target-uri` is not
  covered. Each verifier builds the signature base from its own identifier
  and the raw request target, never from the Host field.
- Key discovery uses the library's egress admission and pinned fetch,
  admitting only the hosts the test registers. One clock drives every party.

## Demonstrated paths

`src/services/aauth-resource/test/integration/three-party.test.ts` runs the
vectors of `notes/aauth-propagation-vectors.md` through the real agent
client, the PS on a temporary SQLite file, and the Resource, all on the
shipped configuration. Every negative vector asserts its exact refusal,
unchanged PS records (issued tokens and mission logs), no token in the
response, and an unchanged effect log.

| Vector | Demonstrated |
|---|---|
| V1 | `mission_s256` exact from approval through the person token, resource token and auth token to the run; each token recorded under the mission; the agent's bytes equal the persisted blob |
| V2, V3 | a stripped or substituted resource-token reference: refused by the agent, and by the PS (`invalid_resource_token`) when the agent skips its check; V3 is surfaced to operators |
| V4 | another person token forwarded: `invalid_resource_token` |
| V5 | an honest step-up carries the mission; a stripped step-up is refused by the agent and by the PS |
| V7, V8 | malformed, unknown and foreign references at the person token endpoint: `invalid_request` |
| V9 | a governed agent's missionless request: `denied` at the person token endpoint, and at both endpoints after a restart that places a missionless agent under governance |
| V10 | a mission terminated after issuance: `mission_terminated` at both endpoints |
| V11 | a person token capped at `expires_at`, presented after it: `expired_presented_token` |
| V12 | mission state unreadable: `server_error` at both endpoints |
| V14 | missionless access by policy; the same agent's failing reference is refused, not served missionless |
| P1 | identical status, body bytes and headers (`Date` aside) for an absent and another agent's mission, active or terminated, at the person token endpoint, `GET /mission/{mission_s256}` and the auth token endpoint's mission check |

The P1 probe at the auth token endpoint re-signs the agent's real person
token with the PS's key, changing only `mission_s256`, because no honest PS
issues one naming a mission the agent does not own. P1 timing is not
measured. A further test shows the PS refuses a resource token naming
another PS in `ps` before reading any mission state.

## Readings a second implementer could make differently

1. An agent the allowlist does not name is refused `user_unreachable`
   (403) at every endpoint: the PS reads an agent with no bound person as
   one with no person to reach.
2. An unknown or foreign `mission_s256` is `invalid_request` at the person
   token endpoint, where -11 says only "MUST reject the request
   otherwise", and `invalid_resource_token` at the auth token endpoint's
   mission check, where the reference rides in the resource token.
3. A governed agent's missionless request is `denied` (403); the binding
   names no error.
4. A denied proposal is 403 `denied` at once, never a 202.
5. A sub-agent calling the PS directly is `denied`, even when the allowlist
   names it.
6. "`expired_presented_token` when only `exp` fails": the PS verifies the
   token again at one second before its `exp`, and reports
   `expired_presented_token` only if that passes.
7. The check that the resource token's `ps` names this PS runs after step 3
   and before the mission check, and fails `invalid_resource_token`.
8. `GET {mission_endpoint}/{mission_s256}` is a local owner's read; -11
   defines only POST there.
9. Neither server signs responses; both sign tokens only, as -11 defines no
   signed response.
10. The signature base comes from the verifier's own identifier and the raw
    target, never from the Host field.
11. Time is whole seconds with no tolerance on `exp` ("no tolerance for
    clock skew on exp") or on `expires_at`: a mission is past `expires_at`
    once the clock reaches it.
12. The issued-token records support revocation, but nothing consults them
    yet.
13. The mission log records approvals and issuance, not refusals; a
    presented-token mismatch and a missed reference become security events.
14. The PS verifies its own person and auth tokens, when presented back to
    it, through its own `jwks_uri`.
15. P1 equivalence rests on one lookup keyed by owning agent and `s256`
    together, not a lookup followed by an ownership check; timing is not
    measured.
16. A step-up resource token's `aud` is the presented auth token's `ps`;
    -11 states three-party `aud` only for "the iss of the person token".
17. The Resource accepts only PS-issued auth tokens (`iss` equal to `ps`).
18. An unsigned request is challenged `requirement=person-token`, as an
    agent-token request is, not answered with Signature-Error.
19. The optional replay cache keys on "(signing-key-thumbprint, created,
    @method, @authority, @path)", so an honest retry in the same second
    collides; the agent waits for the next second. A possible upstream
    note, the owner's call.
20. Content-Digest and Content-Type are required on requests with a body
    only, and the Resource publishes no `additional_signature_components`.
21. An auth token whose scope lacks the operation's is challenged for a
    step-up, not refused.
22. An `account` parameter at the authorization endpoint is
    `invalid_account`: the Resource holds no accounts.
23. The Resource establishes a person record on first sight of an
    (`iss`, `sub`) pair.
24. The agent checks a resource token's `aud` against its own PS.
25. An agent with no mission refuses a resource token that carries a
    `mission_s256`.
26. The Resource copies `mission_s256` unchanged even when it is malformed;
    validating it is the PS's job.
27. A resource token carrying `interaction` is refused 403
    `user_unreachable`, after the mission check. -11 defines no code for a
    PS that cannot conduct the resource's flow; Table 16 gives
    `user_unreachable` for "The PS has no channel to reach the user and the
    agent did not declare the interaction capability". This PS has no
    interaction surface at all, so the agent's capability cannot help, and
    the reference reads the first condition alone as sufficient.
28. An agent token that expires after authentication but before an
    issuance commits is 401 `expired_jwt` with Signature-Error, since the
    Signature-Key token "has no codes in this table".
