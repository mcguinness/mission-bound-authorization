/**
 * The Mission layer of a Mission-bound Attenuating Agent Token chain
 * (@spec attenuation#mission-binding-check, attenuation#mission-constraints,
 * #1756, D902), over chains the -02 substrate verifier already verified.
 * The tokens here are verified-token values (claims as plain JSON), so each
 * case isolates one Mission-layer rule; the keyed, end-to-end presentation
 * is mcp-payments' attenuation.test.ts.
 */

import { describe, expect, it } from "vitest";
import {
  type AatVerifiedToken,
  aatToolId,
  aatUuidV7,
  credentialEntriesFromMissionAat,
  MissionAatError,
  type MissionConstraints,
  missionConstraintsNarrowingProblem,
  readMissionConstraints,
  verifyMissionAatChain,
} from "../src/index.js";

const RES = "https://pay.example/mcp";
const ISS = "https://as.example";
const READ = aatToolId(RES, "payments:invoice.read");
const SCHEDULE = aatToolId(RES, "payments:payment.schedule");
const MISSION = { id: "msn_1", issuer: ISS, authority_hash: "sha-256:H" };
const CONTRACT = {
  id: "https://pay.example/contracts/payments",
  version: "1",
  digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
};
const CAPPED = { max_amount: { amount: "500", currency: "USD" }, vendors: ["acme"] };

const ROOT_TOOLS = {
  [READ]: { invoice_id: { constraint_type: "wildcard" } },
  [SCHEDULE]: {
    idempotency_key: { constraint_type: "wildcard" },
    invoice_id: { constraint_type: "wildcard" },
  },
};
const ROOT_MC: MissionConstraints = {
  [READ]: { constraints: CAPPED },
  [SCHEDULE]: { constraints: CAPPED, resource_contract: CONTRACT },
};

function token(
  claims: Record<string, unknown>,
  tools: Record<string, Record<string, unknown>>,
  member: unknown,
): AatVerifiedToken {
  const entry: Record<string, unknown> = { type: "attenuating_agent_token", tools };
  if (member !== undefined) entry.mission_constraints = member;
  return {
    compact: "h.p.s",
    header: { alg: "ES256", typ: "aat+jwt" },
    claims: { ...claims, authorization_details: [entry] },
    tools,
  };
}

const root = (member: unknown, overrides: Record<string, unknown> = {}) =>
  token(
    { iss: ISS, aud: RES, sub: "alice", client_id: "agent", mission: MISSION, ...overrides },
    ROOT_TOOLS,
    member,
  );

const child = (
  member: unknown,
  tools: Record<string, Record<string, unknown>> = { [READ]: ROOT_TOOLS[READ] as never },
  overrides: Record<string, unknown> = {},
) =>
  token(
    {
      iss: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:x",
      aud: RES,
      mission: MISSION,
      ...overrides,
    },
    tools,
    member,
  );

const READ_ONLY_MC: MissionConstraints = { [READ]: { constraints: CAPPED } };

describe("verifyMissionAatChain: the Mission layer over a verified chain (@spec attenuation#mission-binding-check, #1756)", () => {
  it("returns the leaf's tools and mission_constraints as the credential authority", () => {
    const narrowed = {
      [READ]: {
        constraints: { max_amount: { amount: "100", currency: "USD" }, vendors: ["acme"] },
      },
    };
    const verified = verifyMissionAatChain([root(ROOT_MC), child(narrowed)], ISS);
    expect(verified.mission).toEqual(MISSION);
    expect(verified.credentialAuthority).toEqual([
      {
        type: "mission_resource_access",
        resource: RES,
        actions: ["payments:invoice.read"],
        constraints: { max_amount: { amount: "100", currency: "USD" }, vendors: ["acme"] },
      },
    ]);
  });

  it("refuses a child that changes the mission claim, and a root whose iss is not its mission.issuer and the anchor's issuer", () => {
    expect(() => verifyMissionAatChain([root(ROOT_MC), child(READ_ONLY_MC)], ISS)).not.toThrow();
    for (const mission of [
      { ...MISSION, id: "msn_2" },
      { ...MISSION, authority_hash: "sha-256:other" },
      undefined,
    ]) {
      expect(
        () =>
          verifyMissionAatChain([root(ROOT_MC), child(READ_ONLY_MC, undefined, { mission })], ISS),
        JSON.stringify(mission),
      ).toThrow(/mission claim unchanged/);
    }
    expect(() =>
      verifyMissionAatChain([root(ROOT_MC), child(READ_ONLY_MC)], "https://other.example"),
    ).toThrow(MissionAatError);
    expect(() =>
      verifyMissionAatChain([root(ROOT_MC, { iss: "https://other.example" })], ISS),
    ).toThrow(/iss is not its mission.issuer/);
  });

  it("refuses a child whose aud is not within its parent's, or that carries none", () => {
    expect(() =>
      verifyMissionAatChain(
        [root(ROOT_MC), child(READ_ONLY_MC, undefined, { aud: [RES, "https://other.example"] })],
        ISS,
      ),
    ).toThrow(/aud is not within/);
    expect(() =>
      verifyMissionAatChain(
        [root(ROOT_MC), child(READ_ONLY_MC, undefined, { aud: undefined })],
        ISS,
      ),
    ).toThrow(MissionAatError);
  });
});

describe("the invoked tool's authority alone (@spec attenuation#mission-binding-check, #1756, D932)", () => {
  it("with the invoked tool, the credential authority is that one leaf tool's, and a tool the leaf does not carry refuses", () => {
    const both = verifyMissionAatChain([root(ROOT_MC)], ISS);
    expect(both.credentialAuthority.map((e) => e.actions[0])).toEqual([
      "payments:invoice.read",
      "payments:payment.schedule",
    ]);
    const one = verifyMissionAatChain([root(ROOT_MC)], ISS, SCHEDULE);
    expect(one.credentialAuthority).toEqual([
      {
        type: "mission_resource_access",
        resource: RES,
        actions: ["payments:payment.schedule"],
        resource_contract: CONTRACT,
        constraints: CAPPED,
      },
    ]);
    expect(one.missionConstraints).toEqual(ROOT_MC);
    expect(() =>
      verifyMissionAatChain([root(ROOT_MC), child(READ_ONLY_MC)], ISS, SCHEDULE),
    ).toThrow(/does not carry the invoked tool/);
  });
});

describe("the mission_constraints member (@spec attenuation#mission-constraints, #1756, D902)", () => {
  it("refuses a token without the member, without a value for one of its tools, or with a value for a tool it does not carry", () => {
    // The root and the child, each without the member.
    expect(() => verifyMissionAatChain([root(undefined)], ISS)).toThrow(
      /mission_constraints is missing/,
    );
    expect(() => verifyMissionAatChain([root(ROOT_MC), child(undefined)], ISS)).toThrow(
      /mission_constraints is missing/,
    );
    // A tool with no value: removing it never yields unrestricted authority.
    expect(() => verifyMissionAatChain([root({ [READ]: { constraints: CAPPED } })], ISS)).toThrow(
      /no value for tool/,
    );
    // A value naming a tool the token does not carry.
    expect(() =>
      verifyMissionAatChain(
        [root(ROOT_MC), child({ ...READ_ONLY_MC, [SCHEDULE]: { constraints: CAPPED } })],
        ISS,
      ),
    ).toThrow(/which the entry's tools do not/);
    // A value without its constraints.
    expect(() => verifyMissionAatChain([root(ROOT_MC), child({ [READ]: {} })], ISS)).toThrow(
      /constraints is missing/,
    );
  });

  it("refuses a child whose constraints are not within its parent's, or whose resource_contract changed, and admits a narrowing", () => {
    const schedule = { [SCHEDULE]: ROOT_TOOLS[SCHEDULE] as never };
    const refused: [string, MissionConstraints][] = [
      [
        "a raised cap",
        { [READ]: { constraints: { ...CAPPED, max_amount: { amount: "501", currency: "USD" } } } },
      ],
      ["a removed cap", { [READ]: { constraints: { vendors: ["acme"] } } }],
      ["a removed vendor bound", { [READ]: { constraints: { max_amount: CAPPED.max_amount } } }],
      ["an added vendor", { [READ]: { constraints: { ...CAPPED, vendors: ["acme", "globex"] } } }],
      ["no constraints at all", { [READ]: { constraints: {} } }],
    ];
    for (const [label, member] of refused) {
      expect(() => verifyMissionAatChain([root(ROOT_MC), child(member)], ISS), label).toThrow(
        /not within its parent's/,
      );
    }
    // The contract travels unchanged (step 4): dropped or changed refuses.
    for (const mc of [
      { [SCHEDULE]: { constraints: CAPPED } },
      { [SCHEDULE]: { constraints: CAPPED, resource_contract: { ...CONTRACT, version: "2" } } },
    ]) {
      expect(() => verifyMissionAatChain([root(ROOT_MC), child(mc, schedule)], ISS)).toThrow(
        /not within its parent's/,
      );
    }
    // A narrowing (a lower cap, one vendor of one) with the contract kept is admitted.
    const narrowed = {
      [SCHEDULE]: {
        constraints: { ...CAPPED, max_amount: { amount: "100.00", currency: "USD" } },
        resource_contract: CONTRACT,
      },
    };
    expect(
      verifyMissionAatChain([root(ROOT_MC), child(narrowed, schedule)], ISS).credentialAuthority,
    ).toHaveLength(1);
    expect(missionConstraintsNarrowingProblem(ROOT_MC, narrowed)).toBeUndefined();
  });

  it("refuses a key the consumer does not understand or cannot enforce, and a malformed constraint, rather than ignoring it", () => {
    const refused: [string, unknown][] = [
      ["an unknown member of a value", { [READ]: { constraints: CAPPED, scope: "x" } }],
      ["an unknown constraint key", { [READ]: { constraints: { ...CAPPED, region: "eu" } } }],
      [
        "a currency that is not three upper-case letters",
        { [READ]: { constraints: { ...CAPPED, max_amount: { amount: "5", currency: "usd" } } } },
      ],
      [
        "an amount that is a JSON number",
        { [READ]: { constraints: { ...CAPPED, max_amount: { amount: 5, currency: "USD" } } } },
      ],
      [
        "a vendor bound that is not a list",
        { [READ]: { constraints: { ...CAPPED, vendors: "acme" } } },
      ],
      ["constraints that are an array", { [READ]: { constraints: [] } }],
      [
        "a malformed resource_contract",
        { [READ]: { constraints: CAPPED, resource_contract: { id: "x" } } },
      ],
    ];
    for (const [label, member] of refused) {
      expect(() => verifyMissionAatChain([root(ROOT_MC), child(member)], ISS), label).toThrow(
        MissionAatError,
      );
      const atRoot = { ...ROOT_MC, ...(member as MissionConstraints) };
      expect(() => verifyMissionAatChain([root(atRoot)], ISS), `${label} (root)`).toThrow(
        MissionAatError,
      );
    }
  });
});

describe("readMissionConstraints and credentialEntriesFromMissionAat (@spec attenuation#mission-constraints, #1756)", () => {
  it("keeps a tool identifier named __proto__ as a member, never a prototype", () => {
    const entry = JSON.parse(
      '{"tools":{"__proto__":{}},"mission_constraints":{"__proto__":{"constraints":{}}}}',
    ) as Record<string, unknown>;
    const mc = readMissionConstraints(entry);
    expect(Object.hasOwn(mc, "__proto__")).toBe(true);
    expect(Object.getPrototypeOf(mc)).toBe(Object.prototype);
  });

  it("refuses a max_amount currency that is not three upper-case letters rather than dropping it", () => {
    expect(() =>
      credentialEntriesFromMissionAat(
        { [READ]: {} },
        { [READ]: { constraints: { max_amount: { amount: "200", currency: "usd" } } } },
      ),
    ).toThrow(MissionAatError);
    expect(
      credentialEntriesFromMissionAat(
        { [READ]: {} },
        { [READ]: { constraints: { max_amount: { amount: "200", currency: "XYZ" } } } },
      )[0]?.constraints,
    ).toEqual({ max_amount: { amount: "200", currency: "XYZ" } });
  });
});

describe("aatUuidV7 (@spec AAT -02 Section 3.2)", () => {
  it("is a lowercase hyphenated version 7 UUID carrying the millisecond time", () => {
    const id = aatUuidV7(0x0123456789ab);
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    expect(id.slice(0, 13)).toBe("01234567-89ab");
    expect(aatUuidV7()).not.toBe(aatUuidV7());
  });
});
