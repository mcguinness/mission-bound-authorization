/**
 * @spec cross-org-delegation#projection-exchange — the RFC 8693 token-exchange
 * seam on the real `/token` endpoint: a destination Resource AS accepts a
 * Chain Presentation and mints an audience-local Mission-bound access token.
 * `verifyCrossOrgChain`'s own conformance matrix (widening, substitution,
 * missing hops, untrusted issuers, ...) is exercised in
 * cross-org-delegation.test.ts against the kernel functions directly; this
 * file exercises the ADAPTER around it over a real HTTP AS built with
 * `crossOrg` configured: the wire shape, leaf proof of possession, the
 * origin-principal mapping, the local-ceiling intersection, the mint, error
 * minimization on refusals, and derivation evidence.
 */

import { type Server } from "node:http";
import {
  calculateJwkThumbprint,
  createRemoteJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
} from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  buildAuthorizationServer,
  deriveCrossOrgRoot,
  mintCrossOrgChild,
  MissionKernel,
  validateMissionIntent,
  type AuthorityEntry,
  type BuiltAs,
  type CrossOrgDerivationRecord,
  type CrossOrgOptions,
  type FederationConfig,
} from "../src/index.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const PORT = 14503;
const ISSUER = `http://localhost:${PORT}`;
const ORIGIN_ISS = "https://as.org1.test";
/** The destination's protected resource; also the requested audience. */
const RESOURCE = "https://api.org3.test";
const ORIGIN_SUBJECT = { iss: "https://id.org1.test", sub: "p-alice" };
const LOCAL_SUB = "local-bob";
const GRANT_TYPE = "urn:ietf:params:oauth:grant-type:token-exchange";
const CHAIN_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:mission-delegation-chain";
const READ = "payments:invoice.read";
const SCHEDULE = "payments:payment.schedule";

type Keys = { privateKey: CryptoKey; publicKey: CryptoKey };

let as: BuiltAs;
let asServer: Server;
let clientKey: CryptoKey;
let remoteJwks: ReturnType<typeof createRemoteJWKSet>;
let originKernel: MissionKernel;
let originKeys: Keys; // origin Mission Issuer signing key ("as-token")
/** Mutated between tests; the same object identity is captured by the AS at boot. */
let crossOrgOptions: CrossOrgOptions;
let evidence: CrossOrgDerivationRecord[];

const FULL_CEILING: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: RESOURCE, actions: [READ, SCHEDULE], constraints: { max_amount: { amount: "500.00", currency: "USD" } } },
];
const READ_ONLY_CEILING: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: RESOURCE, actions: [READ], constraints: { max_amount: { amount: "500.00", currency: "USD" } } },
];
const DISJOINT_CEILING: AuthorityEntry[] = [
  { type: "mission_resource_access", resource: "https://unrelated.test", actions: ["storage:object.read"] },
];

async function pub(k: Keys): Promise<JWK> {
  return exportJWK(k.publicKey) as Promise<JWK>;
}

async function newKeys(): Promise<Keys> {
  return generateKeyPair("ES256", { extractable: true });
}

/**
 * Approve an origin Mission (subject defaults to ORIGIN_SUBJECT) and derive +
 * mint a root -> leaf (key-only) chain. Root and leaf-hop actor identity are
 * out of scope here (cross-org-delegation.test.ts already covers named-hop
 * attestation); this file only needs a chain that verifies.
 */
async function buildChain(
  opts: {
    actions?: string[];
    maxAmount?: string;
    subject?: { iss: string; sub: string };
  } = {},
): Promise<{ chain: string[]; leafKeys: Keys; tools: import("@mission/core").AATTools; missionId: string }> {
  const actions = opts.actions ?? [READ, SCHEDULE];
  const rootKeys = await newKeys();
  const leafKeys = await newKeys();
  const mission = originKernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Cross-org reconcile", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" }),
    ),
    proposedAuthority: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions,
        constraints: { max_amount: { amount: opts.maxAmount ?? "500.00", currency: "USD" } },
        delegation: { max_depth: 3 },
      },
    ] as never,
    subject: opts.subject ?? ORIGIN_SUBJECT,
    approver: { iss: ORIGIN_ISS, sub: "bob" },
    clientId: "agent-a",
    approvalEventId: `apev-${crypto.randomUUID()}`,
  });
  const derived = await deriveCrossOrgRoot(originKernel, originKeys.privateKey, "as-token", {
    missionId: mission.id,
    aud: RESOURCE,
    clientId: "agent-a",
    cnfJwk: await pub(rootKeys),
    actor: { iss: "https://id.org1.test", sub: "wl-agent-a" },
    mappingVersion: "map-1",
  });
  const leaf = await mintCrossOrgChild(derived.root, rootKeys.privateKey, derived.tools, { cnfJwk: await pub(leafKeys) });
  return { chain: [derived.root, leaf], leafKeys, tools: derived.tools, missionId: mission.id };
}

function present(chain: string[]): string {
  return Buffer.from(JSON.stringify({ chain }), "utf8").toString("base64url");
}

async function clientAssertion(): Promise<string> {
  return new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(clientKey);
}

async function dpopProof(keys: Keys, extra: Record<string, unknown> = {}): Promise<string> {
  return new SignJWT({ htu: `${ISSUER}/token`, htm: "POST", ...extra })
    .setProtectedHeader({ alg: "ES256", typ: "dpop+jwt", jwk: await exportJWK(keys.publicKey) })
    .setIssuedAt()
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

interface ExchangeOpts {
  subjectToken: string;
  audience?: string;
  dpop?: string; // a raw override; when absent, a fresh proof is signed with `leafKeys`
  leafKeys?: Keys;
}

async function exchange(opts: ExchangeOpts): Promise<Response> {
  const htu = `${ISSUER}/token`;
  const dpop = opts.dpop ?? (opts.leafKeys ? await dpopProof(opts.leafKeys) : undefined);
  return fetch(htu, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      ...(dpop !== undefined ? { dpop } : {}),
    },
    body: new URLSearchParams({
      grant_type: GRANT_TYPE,
      subject_token: opts.subjectToken,
      subject_token_type: CHAIN_TOKEN_TYPE,
      audience: opts.audience ?? RESOURCE,
      client_assertion: await clientAssertion(),
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

beforeAll(async () => {
  originKeys = await newKeys();
  const originPubJwk = { ...(await exportJWK(originKeys.publicKey)), kid: "as-token", alg: "ES256" };
  const federation: FederationConfig = {
    issuers: [{ issuer: ORIGIN_ISS, jwks: { keys: [originPubJwk as JWK] } }],
    attestationSources: [],
    actorCredentialTypes: [],
    bounds: { maxHops: 6, maxBytes: 200_000 },
    stateFreshnessSeconds: 300,
  };
  const originPolicy = {
    policy_version: "xorg-endpoint-1",
    ceiling: [
      {
        type: "mission_resource_access",
        resource: RESOURCE,
        actions: [READ, SCHEDULE],
        constraints: { max_amount: { amount: "500.00", currency: "USD" } },
        delegation: { max_depth: 3 },
      },
    ],
  };
  originKernel = new MissionKernel({
    issuer: ORIGIN_ISS,
    policy: originPolicy as never,
    authoritySourceCatalog: testAuthoritySourceCatalog(originPolicy.ceiling, ["agent-a"], ["bob"]),
    statusKey: originKeys.privateKey,
    statusKid: "as-status",
  });
  evidence = [];
  crossOrgOptions = {
    federation,
    stateSource: () => ({ state: "active", observedAtS: Math.floor(Date.now() / 1000) }),
    mappingPolicy: {
      id: "xorg-map",
      version: "v1",
      entries: [
        {
          origin: ORIGIN_SUBJECT,
          local_sub: LOCAL_SUB,
          observed_at: "2020-01-01T00:00:00Z",
          valid_until: "2099-01-01T00:00:00Z",
        },
      ],
    },
    localCeiling: FULL_CEILING,
    evidence,
    accessTokenTTL: 300,
    // Always entitled, freshly observed: this file exercises the mapping
    // and ceiling axes; cross-org-entitlement.test.ts exercises this one.
    entitlement: { resolve: async () => ({ entitled: true, observed_at: new Date().toISOString() }) },
    entitlementStalenessBoundSeconds: 86_400,
  };

  as = await buildAuthorizationServer({ issuer: ISSUER, crossOrg: crossOrgOptions });
  asServer = as.provider.listen(PORT);
  clientKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  remoteJwks = createRemoteJWKSet(new URL(`${ISSUER}/jwks`));
});

afterAll(() => {
  asServer?.close();
});

describe("leaf proof of possession (@spec cross-org-delegation#projection-exchange)", () => {
  it("refuses a missing DPoP proof (invalid_request)", async () => {
    const { chain } = await buildChain();
    const res = await exchange({ subjectToken: present(chain) });
    const body = (await res.json()) as { error: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_request");
  });

  it("refuses a structurally invalid DPoP proof (invalid_dpop_proof)", async () => {
    const { chain, leafKeys } = await buildChain();
    // A proof that verifies under the leaf key but is bound to the WRONG htm,
    // so the manual htu/htm check inside the try block throws.
    const badProof = await dpopProof(leafKeys, { htm: "GET" });
    const res = await exchange({ subjectToken: present(chain), dpop: badProof });
    const body = (await res.json()) as { error: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_dpop_proof");
  });

  it("refuses a DPoP proof over a key that is not the leaf's cnf key (invalid_grant)", async () => {
    const { chain } = await buildChain();
    const otherKeys = await newKeys(); // valid proof, but not the leaf's key
    const res = await exchange({ subjectToken: present(chain), leafKeys: otherKeys });
    const body = (await res.json()) as { error: string; error_description: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toBe("chain verification failed");
  });
});

describe("audience validation (@spec cross-org-delegation#projection-exchange)", () => {
  it("refuses an audience outside the leaf's aud (invalid_target)", async () => {
    const { chain, leafKeys } = await buildChain();
    const res = await exchange({ subjectToken: present(chain), leafKeys, audience: "https://not-the-resource.test" });
    const body = (await res.json()) as { error: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_target");
  });
});

describe("origin-principal mapping and local-ceiling intersection (@spec cross-org-delegation#projection-exchange)", () => {
  it("refuses a chain whose origin subject has no registered mapping (invalid_grant)", async () => {
    const { chain, leafKeys } = await buildChain({ subject: { iss: "https://id.org1.test", sub: "unmapped-carol" } });
    const res = await exchange({ subjectToken: present(chain), leafKeys });
    const body = (await res.json()) as { error: string; error_description: string };
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_grant");
    expect(body.error_description).toBe("chain verification failed");
  });

  it("refuses a chain whose authority does not intersect the local ceiling (invalid_grant)", async () => {
    crossOrgOptions.localCeiling = DISJOINT_CEILING;
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      const body = (await res.json()) as { error: string; error_description: string };
      expect(res.status).toBe(400);
      expect(body.error).toBe("invalid_grant");
      expect(body.error_description).toBe("chain verification failed");
    } finally {
      crossOrgOptions.localCeiling = FULL_CEILING;
    }
  });

  it("narrows the projected authority to the local ceiling, never exceeding it", async () => {
    crossOrgOptions.localCeiling = READ_ONLY_CEILING;
    try {
      const before = evidence.length;
      const { chain, leafKeys } = await buildChain(); // origin grants READ + SCHEDULE
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      const body = (await res.json()) as { authorization_details: AuthorityEntry[] };
      expect(res.status).toBe(200);
      expect(body.authorization_details).toHaveLength(1);
      expect(body.authorization_details[0]?.actions).toEqual([READ]);
      // The projected set never exceeds the ceiling: every action is a ceiling action.
      const ceilingActions = new Set(READ_ONLY_CEILING.flatMap((e) => e.actions));
      for (const entry of body.authorization_details) {
        for (const action of entry.actions) expect(ceilingActions.has(action)).toBe(true);
      }
      // The origin granted both actions; the ceiling narrowed the projection down to one.
      const record = evidence[evidence.length - 1] as CrossOrgDerivationRecord;
      expect(evidence.length).toBe(before + 1);
      expect(record.input_authority.flatMap((e) => e.actions)).toEqual(expect.arrayContaining([READ, SCHEDULE]));
      expect(record.output_authority).toEqual(body.authorization_details);
      expect(record.output_authority).not.toEqual(record.input_authority);
    } finally {
      crossOrgOptions.localCeiling = FULL_CEILING;
    }
  });
});

describe("the minted token and derivation evidence (@spec cross-org-delegation#projection-exchange, #projection)", () => {
  it("mints a local access token with the expected claims and records derivation evidence", async () => {
    const before = evidence.length;
    const { chain, leafKeys, missionId } = await buildChain();
    const dpopJkt = await calculateJwkThumbprint(await pub(leafKeys));
    const res = await exchange({ subjectToken: present(chain), leafKeys });
    const body = (await res.json()) as {
      access_token: string;
      issued_token_type: string;
      token_type: string;
      expires_in: number;
      authorization_details: AuthorityEntry[];
    };
    expect(res.status, JSON.stringify(body)).toBe(200);
    expect(body.issued_token_type).toBe("urn:ietf:params:oauth:token-type:access_token");
    expect(body.token_type).toBe("DPoP");

    const { payload, protectedHeader } = await jwtVerify(body.access_token, remoteJwks, { issuer: ISSUER, audience: RESOURCE });
    expect(protectedHeader.typ).toBe("at+jwt");
    expect(payload.sub).toBe(LOCAL_SUB);
    expect(payload.act).toEqual({ iss: ISSUER, sub: "ap-agent" }); // restarted act, local actor
    expect((payload.cnf as { jkt: string }).jkt).toBe(dpopJkt);
    expect(payload.mission).toMatchObject({
      id: missionId,
      issuer: ORIGIN_ISS,
      subject: ORIGIN_SUBJECT,
    });
    expect(payload.authorization_details).toEqual(body.authorization_details);

    // exp never outlives the leaf's own exp nor the configured local TTL.
    const leafPayload = JSON.parse(Buffer.from(chain[1]!.split(".")[1] as string, "base64url").toString()) as { exp: number };
    const iat = payload.iat as number;
    expect(payload.exp).toBe(Math.min(iat + crossOrgOptions.accessTokenTTL, leafPayload.exp));

    expect(evidence.length).toBe(before + 1);
    const record = evidence[evidence.length - 1] as CrossOrgDerivationRecord;
    expect(record.output_authority).toEqual(body.authorization_details);
    // FULL_CEILING covers everything the origin granted, so this call narrows
    // nothing (the narrowing case is covered separately, below).
    expect(record.input_authority).toEqual(record.output_authority);
    expect(record.lineage).toHaveLength(2);
    expect(record.lineage[0]?.named).toBe(true); // the root actor
    expect(record.lineage[1]?.named).toBe(false); // the key-only leaf
    expect(record.policy).toEqual({ id: "xorg-map", version: "v1" });
    expect(record.principal_mapping.local).toBe(LOCAL_SUB);
    expect(new Date(record.principal_mapping.observed_at).getTime()).not.toBeNaN();
    expect(new Date(record.principal_mapping.valid_until).getTime()).toBeGreaterThan(
      new Date(record.principal_mapping.observed_at).getTime(),
    );
  });
});

describe("error minimization on refusal (@spec cross-org-delegation#projection-exchange)", () => {
  it("returns byte-identical bodies for chain-verification failure, cnf mismatch, unmapped subject, and empty intersection", async () => {
    const { chain: chainA } = await buildChain(); // will be tampered to break verification
    const tampered = [chainA[0] as string, `${chainA[1]}x`]; // corrupt signature
    const resA = await exchange({ subjectToken: present(tampered), leafKeys: await newKeys() });

    const { chain: chainB } = await buildChain();
    const resB = await exchange({ subjectToken: present(chainB), leafKeys: await newKeys() }); // wrong key

    const { chain: chainC, leafKeys: leafC } = await buildChain({
      subject: { iss: "https://id.org1.test", sub: "unmapped-dana" },
    });
    const resC = await exchange({ subjectToken: present(chainC), leafKeys: leafC });

    crossOrgOptions.localCeiling = DISJOINT_CEILING;
    let resD: Response;
    try {
      const { chain: chainD, leafKeys: leafD } = await buildChain();
      resD = await exchange({ subjectToken: present(chainD), leafKeys: leafD });
    } finally {
      crossOrgOptions.localCeiling = FULL_CEILING;
    }

    const bodies = await Promise.all([resA, resB, resC, resD].map((r) => r.json()));
    for (const r of [resA, resB, resC, resD]) expect(r.status).toBe(400);
    for (const b of bodies) expect(b).toEqual({ error: "invalid_grant", error_description: "chain verification failed" });
  });
});

describe("origin-principal mapping hardening (@spec cross-domain#origin-principal-continuity, #539)", () => {
  const DEFAULT_MAPPING = crossOrgOptionsDefaultMapping();

  function crossOrgOptionsDefaultMapping() {
    return {
      id: "xorg-map",
      version: "v1",
      entries: [
        { origin: ORIGIN_SUBJECT, local_sub: LOCAL_SUB, observed_at: "2020-01-01T00:00:00Z", valid_until: "2099-01-01T00:00:00Z" },
      ],
    };
  }

  it("refuses an ambiguous (duplicate) mapping entry for the same origin (invalid_grant)", async () => {
    crossOrgOptions.mappingPolicy = {
      id: "xorg-map",
      version: "v1",
      entries: [
        { origin: ORIGIN_SUBJECT, local_sub: "dup-a", observed_at: "2020-01-01T00:00:00Z", valid_until: "2099-01-01T00:00:00Z" },
        { origin: ORIGIN_SUBJECT, local_sub: "dup-b", observed_at: "2020-01-01T00:00:00Z", valid_until: "2099-01-01T00:00:00Z" },
      ],
    };
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      const body = (await res.json()) as { error: string };
      expect(res.status).toBe(400);
      expect(body.error).toBe("invalid_grant");
    } finally {
      crossOrgOptions.mappingPolicy = DEFAULT_MAPPING;
    }
  });

  it("refuses a disabled mapping entry (invalid_grant)", async () => {
    crossOrgOptions.mappingPolicy = {
      id: "xorg-map",
      version: "v1",
      entries: [
        { origin: ORIGIN_SUBJECT, local_sub: LOCAL_SUB, disabled: true, observed_at: "2020-01-01T00:00:00Z", valid_until: "2099-01-01T00:00:00Z" },
      ],
    };
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_grant");
    } finally {
      crossOrgOptions.mappingPolicy = DEFAULT_MAPPING;
    }
  });

  it("refuses a mapping stale beyond its own valid_until (invalid_grant)", async () => {
    crossOrgOptions.mappingPolicy = {
      id: "xorg-map",
      version: "v1",
      entries: [{ origin: ORIGIN_SUBJECT, local_sub: LOCAL_SUB, observed_at: "2020-01-01T00:00:00Z", valid_until: "2021-01-01T00:00:00Z" }],
    };
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_grant");
    } finally {
      crossOrgOptions.mappingPolicy = DEFAULT_MAPPING;
    }
  });

  it("refuses a future-dated mapping observed_at (invalid_grant)", async () => {
    crossOrgOptions.mappingPolicy = {
      id: "xorg-map",
      version: "v1",
      entries: [{ origin: ORIGIN_SUBJECT, local_sub: LOCAL_SUB, observed_at: "2099-06-01T00:00:00Z", valid_until: "2099-07-01T00:00:00Z" }],
    };
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_grant");
    } finally {
      crossOrgOptions.mappingPolicy = DEFAULT_MAPPING;
    }
  });
});

describe("origin-principal entitlement (@spec cross-domain#dual-axis, #539)", () => {
  // Captured inside each test (not at describe-collection time, before
  // beforeAll has run and populated crossOrgOptions).

  it("refuses when the entitlement resolver returns undefined (invalid_grant)", async () => {
    const saved = crossOrgOptions.entitlement;
    crossOrgOptions.entitlement = { resolve: async () => undefined };
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_grant");
    } finally {
      crossOrgOptions.entitlement = saved;
    }
  });

  it("refuses when entitled is false (invalid_grant)", async () => {
    const saved = crossOrgOptions.entitlement;
    crossOrgOptions.entitlement = { resolve: async () => ({ entitled: false, observed_at: new Date().toISOString() }) };
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_grant");
    } finally {
      crossOrgOptions.entitlement = saved;
    }
  });

  it("refuses when the entitlement observation is stale beyond entitlementStalenessBoundSeconds (invalid_grant)", async () => {
    const savedEntitlement = crossOrgOptions.entitlement;
    const savedBound = crossOrgOptions.entitlementStalenessBoundSeconds;
    crossOrgOptions.entitlement = {
      resolve: async () => ({ entitled: true, observed_at: new Date(Date.now() - 3_600_000).toISOString() }),
    };
    crossOrgOptions.entitlementStalenessBoundSeconds = 60;
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_grant");
    } finally {
      crossOrgOptions.entitlement = savedEntitlement;
      crossOrgOptions.entitlementStalenessBoundSeconds = savedBound;
    }
  });

  it("refuses when the entitlement resolver throws (invalid_grant)", async () => {
    const saved = crossOrgOptions.entitlement;
    crossOrgOptions.entitlement = {
      resolve: async () => {
        throw new Error("resolver unavailable");
      },
    };
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_grant");
    } finally {
      crossOrgOptions.entitlement = saved;
    }
  });

  it("clamps the minted token's exp to the entitlement observation's freshness horizon when tighter than the leaf/TTL bound", async () => {
    const savedEntitlement = crossOrgOptions.entitlement;
    const savedBound = crossOrgOptions.entitlementStalenessBoundSeconds;
    const observedAt = new Date().toISOString();
    crossOrgOptions.entitlement = { resolve: async () => ({ entitled: true, observed_at: observedAt }) };
    crossOrgOptions.entitlementStalenessBoundSeconds = 20;
    try {
      const { chain, leafKeys } = await buildChain();
      const res = await exchange({ subjectToken: present(chain), leafKeys });
      const body = (await res.json()) as { access_token: string };
      expect(res.status, JSON.stringify(body)).toBe(200);
      const { payload } = await jwtVerify(body.access_token, remoteJwks, { issuer: ISSUER, audience: RESOURCE });
      expect(payload.exp).toBeLessThanOrEqual(Math.floor(Date.parse(observedAt) / 1000) + 20);
    } finally {
      crossOrgOptions.entitlement = savedEntitlement;
      crossOrgOptions.entitlementStalenessBoundSeconds = savedBound;
    }
  });
});
