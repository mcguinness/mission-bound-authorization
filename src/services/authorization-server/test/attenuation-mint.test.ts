/**
 * @spec attenuation#root-mapping, attenuation#request-discovery,
 * attenuation#root, attenuation#attenuation (#1756 slice B3, D882, D902,
 * D904): the Mission Issuer's attenuation root mint and the holder's offline
 * child mint on the -02 substrate wire. The mapped ceiling, a requested
 * narrowing within it and the request, the root's substrate token format,
 * and a child that only narrows. Each minted token is checked with the
 * substrate's own chain verification. Pure, in-memory, no network.
 */

import {
  AAT_DEFAULT_PARAMS,
  type AttenuationOperations,
  aatJwkThumbprintUri,
  aatToolId,
  parHash,
  verifyAatChain,
} from "@mission/core";
import { paymentsAttenuationOperations } from "@mission/mcp-payments";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { type CryptoKey, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, type JWK } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorityEntry,
  deriveAttenuationRoot,
  mapAuthorityToCeiling,
  MissionKernel,
  mintChildOffline,
  validateMissionIntent,
} from "../src/index.js";
import { holderKey } from "./attenuation.helper.js";
import { testAuthoritySourceCatalog } from "./authority-source.helper.js";

const ISS = "https://as.test";
const RES = "https://pay.example/mcp";
const SCHEDULE = aatToolId(RES, "pay.schedule");
const REPORT = aatToolId(RES, "report.read");
const CAP_500 = { max_amount: { amount: "500.00", currency: "USD" }, vendors: ["acme", "globex"] };
const CONTRACT = {
  id: "https://pay.example/contracts/payments",
  version: "1",
  digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};

const entry = (actions: string[], over: Partial<AuthorityEntry> = {}): AuthorityEntry => ({
  type: "mission_resource_access",
  resource: RES,
  actions,
  ...over,
});

/** The resource server's declaration for this suite: two operations at RES. */
const OPERATIONS: AttenuationOperations = (resource, action) => {
  if (resource !== RES) return undefined;
  if (action === "pay.schedule") {
    return [
      {
        name: "schedule_payment",
        arguments: { invoice_id: { required: true }, idempotency_key: { required: true } },
        establishes: ["vendors", "max_amount"],
      },
    ];
  }
  if (action === "report.read") {
    return [{ name: "read_report", arguments: { period: { required: false } }, establishes: ["vendors", "max_amount"] }];
  }
  if (action === "status.read") return [{ name: "read_status", arguments: {}, establishes: ["vendors", "max_amount"] }];
  return undefined;
};

const wildcard = { constraint_type: "wildcard" };
const optional = { constraint_type: "wildcard", optional: true };

describe("the mapped ceiling (@spec attenuation#root-mapping, #1756, D902, D904)", () => {
  it("names every argument the operations declare as an explicit wildcard, optional where not every operation requires it, with no \"*\"", () => {
    const ops: AttenuationOperations = () => [
      { name: "a", arguments: { invoice_id: { required: true }, idempotency_key: { required: true } }, establishes: [] },
      { name: "b", arguments: { invoice_id: { required: true }, note: { required: false } }, establishes: [] },
    ];
    const { tools } = mapAuthorityToCeiling([entry(["pay.execute"])], ops);
    expect(tools).toEqual({
      [aatToolId(RES, "pay.execute")]: { idempotency_key: optional, invoice_id: wildcard, note: optional },
    });
    // The shipped payments declaration: `payments:payment.execute` names the
    // preflight, prepare and commit tools; only the commit tool takes an
    // idempotency key, so it is optional in the map.
    const payments = mapAuthorityToCeiling(
      [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:payment.execute"] }],
      paymentsAttenuationOperations(),
    );
    expect(payments.tools).toEqual({
      [aatToolId(CANONICAL_RESOURCE, "payments:payment.execute")]: { idempotency_key: optional, invoice_id: wildcard },
    });
  });

  it("leaves out a tool whose operations declare no argument, so an empty argument map never stands for none (D932 ruling 2)", () => {
    const ops: AttenuationOperations = (_r, action) =>
      action === "status.read"
        ? [{ name: "status", arguments: {}, establishes: [] }]
        : [{ name: "a", arguments: { id: { required: false } }, establishes: [] }];
    const { tools, missionConstraints } = mapAuthorityToCeiling([entry(["status.read", "a.read"])], ops);
    expect(tools).toEqual({ [aatToolId(RES, "a.read")]: { id: optional } });
    expect(Object.keys(missionConstraints)).toEqual([aatToolId(RES, "a.read")]);
  });

  it("carries each entry's constraints and resource_contract unchanged as the tool's mission_constraints value", () => {
    const { tools, missionConstraints } = mapAuthorityToCeiling(
      [entry(["pay.schedule"], { constraints: CAP_500, resource_contract: CONTRACT } as Partial<AuthorityEntry>), entry(["report.read"])],
      OPERATIONS,
    );
    expect(Object.keys(tools).sort()).toEqual([SCHEDULE, REPORT].sort());
    expect(missionConstraints).toEqual({
      [SCHEDULE]: { constraints: CAP_500, resource_contract: CONTRACT },
      [REPORT]: { constraints: {} },
    });
    // The argument constraints never come from the entry's constraints.
    expect(tools[SCHEDULE]).toEqual({ idempotency_key: wildcard, invoice_id: wildcard });
  });

  it("maps no tool unless every operation it names establishes each fact the entry restricts", () => {
    const partial: AttenuationOperations = (_r, action) =>
      action === "a.read"
        ? [{ name: "a", arguments: { id: { required: true } }, establishes: ["vendors"] }]
        : action === "b.read"
          ? [
              { name: "b1", arguments: { id: { required: true } }, establishes: ["vendors", "max_amount"] },
              { name: "b2", arguments: { id: { required: true } }, establishes: ["vendors"] },
            ]
          : undefined;
    const capped = mapAuthorityToCeiling([entry(["a.read", "b.read", "c.read"], { constraints: CAP_500 })], partial);
    expect(capped.tools).toEqual({});
    // The same tools map once the entry restricts only what they establish.
    const vendorOnly = mapAuthorityToCeiling(
      [entry(["a.read", "b.read", "c.read"], { constraints: { vendors: ["acme"] } })],
      partial,
    );
    expect(Object.keys(vendorOnly.tools).sort()).toEqual([aatToolId(RES, "a.read"), aatToolId(RES, "b.read")]);
    // The shipped payments declaration: a list establishes no invoice amount,
    // so an amount-capped entry maps the read and not the list.
    const payments = mapAuthorityToCeiling(
      [
        {
          type: "mission_resource_access",
          resource: CANONICAL_RESOURCE,
          actions: ["payments:invoice.read", "payments:invoice.list"],
          constraints: CAP_500,
        },
      ],
      paymentsAttenuationOperations(),
    );
    expect(Object.keys(payments.tools)).toEqual([aatToolId(CANONICAL_RESOURCE, "payments:invoice.read")]);
  });

  it("leaves out a tool that two entries with different restrictions map to, never merging them, and maps identical restrictions once", () => {
    const two = mapAuthorityToCeiling(
      [entry(["pay.schedule", "report.read"], { constraints: CAP_500 }), entry(["pay.schedule"], { constraints: { vendors: ["acme"] } })],
      OPERATIONS,
    );
    expect(Object.keys(two.tools)).toEqual([REPORT]);
    expect(two.missionConstraints[SCHEDULE]).toBeUndefined();
    const same = mapAuthorityToCeiling(
      [entry(["pay.schedule"], { constraints: CAP_500 }), entry(["pay.schedule"], { constraints: { ...CAP_500 } })],
      OPERATIONS,
    );
    expect(same.missionConstraints).toEqual({ [SCHEDULE]: { constraints: CAP_500 } });
  });
});

describe("the issued root (@spec attenuation#request-discovery, attenuation#root, #1756, D904)", () => {
  let signKey: CryptoKey;
  let asJwk: JWK;
  let holder: Awaited<ReturnType<typeof holderKey>>;
  let seq = 0;
  beforeAll(async () => {
    const as = await generateKeyPair("ES256", { extractable: true });
    signKey = as.privateKey;
    asJwk = await exportJWK(as.publicKey);
    holder = await holderKey("Ed25519");
  });

  /** A kernel and an approved Mission whose Authority Set is `entries`. */
  function mission(entries: AuthorityEntry[]): { kernel: MissionKernel; id: string } {
    const policy = { policy_version: "t", ceiling: entries };
    const kernel = new MissionKernel({
      issuer: ISS,
      policy: policy as never,
      authoritySourceCatalog: testAuthoritySourceCatalog(entries, ["agent"], ["bob"]),
      statusKey: signKey,
      statusKid: "as-status",
    });
    const record = kernel.approve({
      intent: validateMissionIntent(JSON.stringify({ goal: "g", target_resources: [RES], expires_at: "2027-01-01T00:00:00Z" })),
      subject: { iss: ISS, sub: "alice" },
      approver: { iss: ISS, sub: "bob" },
      clientId: "agent",
      approvalEventId: `apev-mint-${seq++}`,
    });
    return { kernel, id: record.id };
  }

  const mint = (m: { kernel: MissionKernel; id: string }, over: Record<string, unknown> = {}) =>
    deriveAttenuationRoot(m.kernel, signKey, "as-attenuation", {
      missionId: m.id,
      aud: RES,
      clientId: "agent",
      cnfJwk: holder.jwk,
      operations: OPERATIONS,
      ...over,
    });

  const verifyRoot = (root: string) =>
    verifyAatChain({
      chain: [root],
      trustAnchors: [{ issuer: ISS, jwk: asJwk }],
      now: Math.floor(Date.now() / 1000),
      policy: { audiences: [RES] },
    });

  it("binds the holder's public key as cnf.jwk on an aat+jwt root with a UUIDv7 jti and integer iat and exp, which the substrate's chain verification admits", async () => {
    const m = mission([entry(["pay.schedule", "report.read"], { constraints: CAP_500 })]);
    const minted = await mint(m);
    const header = decodeProtectedHeader(minted.root);
    const claims = decodeJwt(minted.root);
    expect(header).toEqual({ alg: "ES256", kid: "as-attenuation", typ: "aat+jwt" });
    expect(claims.cnf).toEqual({ jwk: holder.jwk });
    expect(claims.jti).toBe(minted.jti);
    expect(minted.jti).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(Number.isInteger(claims.iat) && Number.isInteger(claims.exp)).toBe(true);
    expect(claims.authorization_details).toEqual([
      {
        type: "attenuating_agent_token",
        tools: minted.tools,
        mission_constraints: { [SCHEDULE]: { constraints: CAP_500 }, [REPORT]: { constraints: CAP_500 } },
      },
    ]);
    expect(verifyRoot(minted.root)).toMatchObject({ verdict: "PERMIT", anchorIssuer: ISS });
  });

  it("refuses a holder key carrying a private member or of a type the substrate does not take, before any count", async () => {
    const m = mission([entry(["report.read"])]);
    const { d } = await exportJWK(holder.privateKey);
    const rsa = await exportJWK((await generateKeyPair("RS256", { extractable: true })).publicKey);
    for (const cnfJwk of [{ ...holder.jwk, d }, rsa]) {
      await expect(mint(m, { cnfJwk })).rejects.toThrow(/not a supported public key/);
    }
    expect(m.kernel.get(m.id)?.derivation_count ?? 0).toBe(0);
  });

  it("issues exactly a requested narrowing within the ceiling: USD 100 under USD 500, and one period where the tool admits any", async () => {
    const m = mission([entry(["pay.schedule", "report.read"], { constraints: CAP_500 })]);
    const narrowed = { max_amount: { amount: "100", currency: "USD" }, vendors: ["acme"] };
    const onePeriod = { period: { constraint_type: "one_of", values: ["2026-Q3"] } };
    const minted = await mint(m, {
      requested: {
        tools: { [SCHEDULE]: { idempotency_key: wildcard, invoice_id: wildcard }, [REPORT]: onePeriod },
        missionConstraints: { [SCHEDULE]: { constraints: narrowed } },
      },
    });
    const detail = (decodeJwt(minted.root).authorization_details as Record<string, unknown>[])[0];
    expect(detail?.tools).toEqual({ [SCHEDULE]: { idempotency_key: wildcard, invoice_id: wildcard }, [REPORT]: onePeriod });
    // A tool the request names no value for takes the ceiling's.
    expect(detail?.mission_constraints).toEqual({
      [SCHEDULE]: { constraints: narrowed },
      [REPORT]: { constraints: CAP_500 },
    });
    expect(verifyRoot(minted.root)).toMatchObject({ verdict: "PERMIT" });
  });

  it("refuses a request beyond the ceiling rather than issuing a root for the rest", async () => {
    const m = mission([entry(["pay.schedule", "report.read", "status.read"], { constraints: CAP_500 })]);
    const scheduleArgs = { idempotency_key: wildcard, invoice_id: wildcard };
    const beyond: [string, Record<string, unknown>][] = [
      ["a tool the ceiling does not map", { tools: { [aatToolId(RES, "pay.refund")]: {} } }],
      ["a tool at another resource", { tools: { [aatToolId("https://other.example/mcp", "report.read")]: { period: optional } } }],
      ["an argument the ceiling does not name", { tools: { [REPORT]: { period: optional, region: optional } } }],
      ["a required argument made optional", { tools: { [SCHEDULE]: { idempotency_key: optional, invoice_id: wildcard } } }],
      ["an argument map widened to \"*\"", { tools: { [REPORT]: {} } }],
      [
        "a raised cap",
        { tools: { [SCHEDULE]: scheduleArgs }, missionConstraints: { [SCHEDULE]: { constraints: { ...CAP_500, max_amount: { amount: "501", currency: "USD" } } } } },
      ],
      ["a dropped restriction", { tools: { [SCHEDULE]: scheduleArgs }, missionConstraints: { [SCHEDULE]: { constraints: { vendors: ["acme"] } } } }],
      [
        "an added resource_contract",
        { tools: { [SCHEDULE]: scheduleArgs }, missionConstraints: { [SCHEDULE]: { constraints: CAP_500, resource_contract: CONTRACT } } },
      ],
      ["a tool whose operations declare no argument", { tools: { [aatToolId(RES, "status.read")]: {} } }],
      ["a value for a tool not requested", { tools: { [REPORT]: { period: optional } }, missionConstraints: { [SCHEDULE]: { constraints: CAP_500 } } }],
      ["an unknown member of a value", { tools: { [REPORT]: { period: optional } }, missionConstraints: { [REPORT]: { constraints: CAP_500, x: 1 } } }],
    ];
    for (const [label, requested] of beyond) {
      await expect(mint(m, { requested }), label).rejects.toThrow(/requested root exceeds the Mission Authority Set/);
    }
  });

  it("takes a tool two entries map to within one entry's restrictions when the request names it, never their merge", async () => {
    const m = mission([
      entry(["pay.schedule"], { constraints: CAP_500 }),
      entry(["pay.schedule"], { constraints: { max_amount: { amount: "50", currency: "USD" }, vendors: ["initech"] } }),
    ]);
    const args = { idempotency_key: wildcard, invoice_id: wildcard };
    // The derived ceiling carries neither entry's restrictions for the tool.
    expect((await mint(m)).tools).toEqual({});
    // A request with no value is ambiguous, and one spanning both entries is a merge.
    await expect(mint(m, { requested: { tools: { [SCHEDULE]: args } } })).rejects.toThrow(/more than one entry/);
    const merged = { max_amount: { amount: "50", currency: "USD" }, vendors: ["acme", "initech"] };
    await expect(
      mint(m, { requested: { tools: { [SCHEDULE]: args }, missionConstraints: { [SCHEDULE]: { constraints: merged } } } }),
    ).rejects.toThrow(/not within the mapping entry's/);
    // Within one entry: issued as requested.
    const within = { max_amount: { amount: "50", currency: "USD" }, vendors: ["initech"] };
    const minted = await mint(m, {
      requested: { tools: { [SCHEDULE]: args }, missionConstraints: { [SCHEDULE]: { constraints: within } } },
    });
    expect(minted.missionConstraints).toEqual({ [SCHEDULE]: { constraints: within } });
  });

  it("caps a derived del_max_depth at MAX_DELEGATION_DEPTH and refuses an explicit one beyond it", async () => {
    const deep = { max_depth: 20, allowed_delegates: [{ sub_profile: "ai_agent" }] };
    const m = mission([entry(["report.read"], { delegation: deep } as Partial<AuthorityEntry>)]);
    const minted = await mint(m);
    expect(decodeJwt(minted.root).del_max_depth).toBe(AAT_DEFAULT_PARAMS.maxDelegationDepth);
    expect(verifyRoot(minted.root)).toMatchObject({ verdict: "PERMIT" });
    await expect(mint(m, { delMaxDepth: AAT_DEFAULT_PARAMS.maxDelegationDepth + 1 })).rejects.toThrow(/del_max_depth exceeds/);
  });

  describe("mintChildOffline (@spec attenuation#attenuation, #1756)", () => {
    it("signs an Ed25519 holder's child under an ES256 root: iss the parent key's thumbprint URI, no header jwk, par_hash, a jti and iat, no sub or client_id", async () => {
      const m = mission([entry(["pay.schedule", "report.read"], { constraints: CAP_500 })]);
      const minted = await mint(m, { delMaxDepth: 2 });
      const delegate = await holderKey("ES256");
      const child = await mintChildOffline(minted.root, holder.privateKey, {
        tools: { [REPORT]: minted.tools[REPORT] as Record<string, unknown> },
        missionConstraints: { [REPORT]: { constraints: { ...CAP_500, vendors: ["acme"] } } },
      }, { cnfJwk: delegate.jwk });
      expect(decodeProtectedHeader(child)).toEqual({ alg: "Ed25519", typ: "aat+jwt" });
      const claims = decodeJwt(child);
      expect(claims.iss).toBe(aatJwkThumbprintUri(holder.jwk as Record<string, unknown>));
      expect(claims.par_hash).toBe(parHash(minted.root));
      expect(claims.cnf).toEqual({ jwk: delegate.jwk });
      expect(claims.del_depth).toBe(1);
      expect(typeof claims.jti === "string" && Number.isInteger(claims.iat)).toBe(true);
      expect(claims.sub).toBeUndefined();
      expect(claims.client_id).toBeUndefined();
      expect(claims.mission).toEqual(decodeJwt(minted.root).mission);
      expect(
        verifyAatChain({
          chain: [minted.root, child],
          trustAnchors: [{ issuer: ISS, jwk: asJwk }],
          now: Math.floor(Date.now() / 1000),
          policy: { audiences: [RES] },
        }),
      ).toMatchObject({ verdict: "PERMIT" });
    });

    it("refuses a child broader than its parent: a tool, an argument, mission_constraints, aud or exp", async () => {
      const m = mission([entry(["pay.schedule", "report.read"], { constraints: CAP_500 })]);
      const minted = await mint(m, { delMaxDepth: 2, requested: { tools: { [REPORT]: { period: optional } } } });
      const mc = { [REPORT]: { constraints: CAP_500 } };
      const report = { [REPORT]: { period: optional } };
      const broader: [string, Parameters<typeof mintChildOffline>[2], Record<string, unknown>][] = [
        ["a tool the parent lacks", { tools: { ...report, [SCHEDULE]: {} }, missionConstraints: { ...mc, [SCHEDULE]: { constraints: CAP_500 } } }, {}],
        ["an argument the parent does not name", { tools: { [REPORT]: { period: optional, region: optional } }, missionConstraints: mc }, {}],
        ["a raised cap", { tools: report, missionConstraints: { [REPORT]: { constraints: { ...CAP_500, max_amount: { amount: "900", currency: "USD" } } } } }, {}],
        ["a removed restriction", { tools: report, missionConstraints: { [REPORT]: { constraints: {} } } }, {}],
        ["no mission_constraints value", { tools: report, missionConstraints: {} }, {}],
        ["an aud beyond the parent's", { tools: report, missionConstraints: mc }, { aud: [RES, "https://other.example/mcp"] }],
        ["an exp after the parent's", { tools: report, missionConstraints: mc }, { exp: Number(decodeJwt(minted.root).exp) + 60 }],
      ];
      for (const [label, narrowed, opts] of broader) {
        await expect(mintChildOffline(minted.root, holder.privateKey, narrowed, opts), label).rejects.toThrow();
      }
      // Control: the parent's own authority, unchanged, mints.
      await expect(mintChildOffline(minted.root, holder.privateKey, { tools: report, missionConstraints: mc })).resolves.toBeTypeOf("string");
    });

    it("refuses to sign with a key other than the one the parent's cnf.jwk binds, and beyond the parent's del_max_depth", async () => {
      const m = mission([entry(["report.read"])]);
      const authority = { tools: { [REPORT]: { period: optional } }, missionConstraints: { [REPORT]: { constraints: {} } } };
      const stranger = await holderKey("Ed25519");
      const deep = await mint(m, { delMaxDepth: 1 });
      await expect(mintChildOffline(deep.root, stranger.privateKey, authority)).rejects.toThrow(/not the key the parent's cnf.jwk binds/);
      const flat = await mint(m, { delMaxDepth: 0 });
      await expect(mintChildOffline(flat.root, holder.privateKey, authority)).rejects.toThrow(/permits no further derivation/);
    });
  });
});
