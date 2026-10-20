/**
 * @spec resource-access#matching-allowed-delegates, child-delegation#fanout (issue #1373)
 *
 * A delegate matcher is `{ "sub" }`, `{ "sub_profile" }`, or both, in
 * `allowed_delegates` and `allowed_child_actors` alike. Before #1373 the
 * proposal schema admitted a matcher carrying any other member, and
 * derivation rebuilt it from `sub` and `sub_profile` alone:
 * `{"sub_profile": "ai_agent", "org": "A"}` derived to a bare
 * `{"sub_profile": "ai_agent"}`, which then admitted an `ai_agent` outside
 * organization A. Each admitting boundary now refuses, under the shared rule
 * (`delegateMatcherListViolation`), a matcher carrying an unrecognized member,
 * carrying neither member, or carrying an empty or non-string value:
 * proposal intake (`invalid_authorization_details`), configuration load (the
 * loader's configuration error) and direct derivation.
 */

import { type Server } from "node:http";
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { CANONICAL_RESOURCE, DERIVATION_POLICY } from "@mission/demo-data";
import { importJWK, SignJWT, type CryptoKey } from "jose";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type AuthorityEntry,
  buildAuthorizationServer,
  type BuiltAs,
  deriveAuthoritySet,
  IntentError,
  MISSION_RESOURCE_ACCESS_SCHEMA,
  MISSION_RESOURCE_ACCESS_TYPE,
  type MissionIntent,
  validateAuthorityProposal,
  validateMissionResourceAccessSchema,
} from "../src/index.js";

const REAL_CONFIG_DIR = fileURLToPath(new URL("../../../config", import.meta.url));
const OTHER_RESOURCE = "https://erp.example.com";

/** The reproduction: a matcher restricted to organization A by a member the AS does not define. */
const ORG_MATCHER = { sub_profile: "ai_agent", org: "A" };

/** Each malformed matcher shape and the violation the shared rule names for it, after the list's path. */
const MALFORMED: ReadonlyArray<readonly [string, Record<string, unknown>, string]> = [
  ["an unrecognized member", ORG_MATCHER, " entries carry no member 'org'"],
  ["neither sub nor sub_profile", {}, " entries must carry sub or sub_profile"],
  ["an empty sub", { sub: "" }, ".sub must not be empty"],
  ["an empty sub_profile", { sub_profile: "" }, ".sub_profile must not be empty"],
  ["a non-string sub", { sub: 7 }, ".sub must be a string"],
  ["a non-string sub_profile beside a valid sub", { sub: "subagent-1", sub_profile: ["ai_agent"] }, ".sub_profile must be a string"],
];

/** Valid matchers, which every boundary admits and derivation keeps unchanged. */
const VALID = [
  { sub: "subagent-1" },
  { sub_profile: "ai_agent" },
  { sub: "subagent-1", sub_profile: "ai_agent" },
  { sub_profile: "ai_agent client_instance" },
];

/** Where a matcher list sits in an entry's `delegation`, and the violation path it is named by. */
const LISTS = {
  allowed_delegates: {
    path: "delegation.allowed_delegates",
    delegation: (matchers: unknown[]) => ({ max_depth: 1, allowed_delegates: matchers, children: {} }),
    read: (e: AuthorityEntry | undefined) => e?.delegation?.allowed_delegates,
  },
  allowed_child_actors: {
    path: "delegation.children.allowed_child_actors",
    delegation: (matchers: unknown[]) => ({ max_depth: 1, children: { allowed_child_actors: matchers } }),
    read: (e: AuthorityEntry | undefined) =>
      (e?.delegation?.children as { allowed_child_actors?: unknown } | undefined)?.allowed_child_actors,
  },
} as const;

const entry = (delegation?: unknown, resource = CANONICAL_RESOURCE): AuthorityEntry =>
  ({
    type: MISSION_RESOURCE_ACCESS_TYPE,
    resource,
    actions: ["payments:invoice.read"],
    ...(delegation === undefined ? {} : { delegation }),
  }) as AuthorityEntry;

/** A ceiling entry granting delegation and children with no list of its own. */
const GRANTING_CEILING = entry({ max_depth: 2, children: { max_children: 3 } });

function refusal(fn: () => unknown): IntentError {
  try {
    fn();
  } catch (e) {
    if (e instanceof IntentError) return e;
    throw e;
  }
  throw new Error("expected an IntentError");
}

describe("the published schema closes the delegate matcher to sub and sub_profile (#1373)", () => {
  it("each matcher list's item admits only sub and sub_profile, at least one, each a non-empty string", () => {
    const delegation = (MISSION_RESOURCE_ACCESS_SCHEMA.properties as Record<string, Record<string, never>>)
      .delegation as Record<string, Record<string, Record<string, unknown>>>;
    const children = delegation.properties.children as unknown as {
      properties: Record<string, { items: unknown }>;
    };
    for (const items of [
      (delegation.properties.allowed_delegates as { items: unknown }).items,
      children.properties.allowed_child_actors?.items,
    ]) {
      expect(items).toEqual({
        type: "object",
        properties: { sub: { type: "string", minLength: 1 }, sub_profile: { type: "string", minLength: 1 } },
        minProperties: 1,
        additionalProperties: false,
      });
    }
  });
});

describe("proposal intake refuses a malformed delegate matcher (#1373)", () => {
  for (const [list, { path, delegation }] of Object.entries(LISTS)) {
    it(`validateMissionResourceAccessSchema refuses each malformed ${list} matcher, naming the violation`, () => {
      for (const [name, matcher, violation] of MALFORMED) {
        expect(validateMissionResourceAccessSchema(entry(delegation([matcher]))), name).toBe(`${path}${violation}`);
      }
    });

    it(`validateAuthorityProposal refuses the org reproduction in ${list} with invalid_authorization_details`, () => {
      const e = refusal(() => validateAuthorityProposal(JSON.stringify([entry(delegation([ORG_MATCHER]))]), [CANONICAL_RESOURCE]));
      expect(e.code).toBe("invalid_authorization_details");
      expect(e.message).toBe(`authorization_details entry fails its published schema: ${path} entries carry no member 'org'`);
    });
  }

  it("admits sub, sub_profile, both, and a multi-value sub_profile in either list (positive control)", () => {
    for (const { delegation } of Object.values(LISTS)) {
      const proposed = entry(delegation(VALID));
      expect(validateMissionResourceAccessSchema(proposed)).toBeUndefined();
      expect(validateAuthorityProposal(JSON.stringify([proposed]), [CANONICAL_RESOURCE])).toEqual([proposed]);
    }
  });
});

describe("direct derivation refuses a malformed delegate matcher before deriving any entry (#1373)", () => {
  const intent = {
    purpose: "Read invoices for the quarterly close",
    target_resources: [CANONICAL_RESOURCE, OTHER_RESOURCE],
  } as unknown as MissionIntent;
  const policy = (ceiling: AuthorityEntry[]) => ({ policy_version: "matcher-members-1373", ceiling });

  for (const [list, { path, delegation }] of Object.entries(LISTS)) {
    it(`refuses the org reproduction in a proposal's ${list}, so no matcher admitting an ai_agent outside organization A is derived`, () => {
      let derived: AuthorityEntry[] | undefined;
      let error: unknown;
      try {
        derived = deriveAuthoritySet(intent, policy([GRANTING_CEILING]), [entry(delegation([ORG_MATCHER]))]);
      } catch (e) {
        error = e;
      }
      // Before #1373 this derived the bare `{ "sub_profile": "ai_agent" }`.
      expect(derived).toBeUndefined();
      expect(error).toBeInstanceOf(IntentError);
      expect((error as IntentError).code).toBe("invalid_authorization_details");
      expect((error as IntentError).message).toBe(
        `authorization_details entry ${path} entries carry no member 'org'; refusing rather than silently dropping it`,
      );
    });

    it(`refuses each malformed ${list} matcher in a proposal or a ceiling entry, naming the violation`, () => {
      for (const [name, matcher, violation] of MALFORMED) {
        const named = `${path}${violation}`;
        const fromProposal = refusal(() => deriveAuthoritySet(intent, policy([GRANTING_CEILING]), [entry(delegation([matcher]))]));
        expect(fromProposal.code, name).toBe("invalid_authorization_details");
        expect(fromProposal.message, name).toContain(named);
        const fromCeiling = refusal(() => deriveAuthoritySet(intent, policy([entry(delegation([matcher]))])));
        expect(fromCeiling.code, name).toBe("invalid_authorization_details");
        expect(fromCeiling.message, name).toContain(named);
      }
    });

    it(`refuses an ${list} value that is not an array, which the matcher rebuild would read as absent`, () => {
      const notAList = entry(delegation("ai_agent" as unknown as unknown[]));
      const e = refusal(() => deriveAuthoritySet(intent, policy([GRANTING_CEILING]), [notAList]));
      expect(e.code).toBe("invalid_authorization_details");
      expect(e.message).toContain(`${path} must be an array`);
    });

    it(`refuses a malformed ${list} matcher in a ceiling entry no submitted proposal entry shares a resource with`, () => {
      const ceiling = [GRANTING_CEILING, entry(delegation([ORG_MATCHER]), OTHER_RESOURCE)];
      const e = refusal(() => deriveAuthoritySet(intent, policy(ceiling), [entry()]));
      expect(e.code).toBe("invalid_authorization_details");
      expect(e.message).toContain(`${path} entries carry no member 'org'`);
    });
  }

  it("derives sub, sub_profile, both, and a multi-value sub_profile unchanged in either list (positive control)", () => {
    for (const { delegation, read } of Object.values(LISTS)) {
      const proposed = validateAuthorityProposal(JSON.stringify([entry(delegation(VALID))]), [CANONICAL_RESOURCE]);
      // Taken from the proposal where the ceiling carries no list, and kept
      // where the ceiling carries the same list.
      for (const ceiling of [GRANTING_CEILING, entry(delegation(VALID))]) {
        const derived = deriveAuthoritySet(intent, policy([ceiling]), proposed);
        expect(derived).toHaveLength(1);
        expect(read(derived[0])).toEqual(VALID);
      }
    }
  });
});

describe("config loaders refuse a ceiling entry carrying a malformed delegate matcher at load (#1373)", () => {
  let previous: string | undefined;
  let dir: string | undefined;

  afterEach(() => {
    if (previous === undefined) delete process.env.MISSION_CONFIG_DIR;
    else process.env.MISSION_CONFIG_DIR = previous;
    if (dir) rmSync(dir, { recursive: true, force: true });
    dir = undefined;
    vi.resetModules();
  });

  /** A copy of the shipped config dir with the named file rewritten by `mutate`. */
  function configDirWith(file: string, mutate: (parsed: unknown) => void): void {
    dir = mkdtempSync(join(tmpdir(), "mission-config-1373-"));
    const configDir = join(dir, "config");
    cpSync(REAL_CONFIG_DIR, configDir, { recursive: true });
    const filePath = join(configDir, file);
    const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
    mutate(parsed);
    writeFileSync(filePath, JSON.stringify(parsed, null, 2));
    previous = process.env.MISSION_CONFIG_DIR;
    process.env.MISSION_CONFIG_DIR = configDir;
    vi.resetModules();
  }

  type Delegation = { allowed_delegates?: unknown; children: { allowed_child_actors?: unknown } };
  const firstDelegation = (ceiling: { delegation?: Delegation }[]): Delegation => {
    const delegation = ceiling[0]?.delegation;
    expect(delegation?.children).toBeDefined();
    return delegation as Delegation;
  };
  const refused = (file: string, ctx: string) => `[config:${file}] ${ctx} has malformed or unsupported authority`;

  it("parseCeilingEntry (policy.json) rejects the org reproduction in allowed_delegates, naming the entry", async () => {
    configDirWith("policy.json", (raw) => {
      firstDelegation((raw as { ceiling: { delegation?: Delegation }[] }).ceiling).allowed_delegates = [ORG_MATCHER];
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(refused("policy.json", "policy.ceiling[0]"));
  });

  it("parseCeilingEntry (policy.json) rejects the org reproduction in allowed_child_actors, naming the entry", async () => {
    configDirWith("policy.json", (raw) => {
      firstDelegation((raw as { ceiling: { delegation?: Delegation }[] }).ceiling).children.allowed_child_actors = [ORG_MATCHER];
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(refused("policy.json", "policy.ceiling[0]"));
  });

  it("loadCeilingEntries (governed-policy.json) rejects a governed ceiling matcher carrying neither member, in allowed_child_actors, naming the entry", async () => {
    configDirWith("governed-policy.json", (raw) => {
      firstDelegation((raw as { ceiling: { delegation?: Delegation }[] }[])[0]?.ceiling ?? []).children.allowed_child_actors = [{}];
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("governed-policy.json", "governed-policy[0].ceiling[0]"),
    );
  });

  it("loadCeilingEntries (governed-policy.json) rejects a governed ceiling matcher with an empty sub, in allowed_delegates, naming the entry", async () => {
    configDirWith("governed-policy.json", (raw) => {
      firstDelegation((raw as { ceiling: { delegation?: Delegation }[] }[])[0]?.ceiling ?? []).allowed_delegates = [{ sub: "" }];
    });
    await expect(import("@mission/demo-data")).rejects.toThrow(
      refused("governed-policy.json", "governed-policy[0].ceiling[0]"),
    );
  });

  it("loads sub, sub_profile, both, and a multi-value sub_profile in both lists unchanged (positive control)", async () => {
    configDirWith("policy.json", (raw) => {
      const delegation = firstDelegation((raw as { ceiling: { delegation?: Delegation }[] }).ceiling);
      delegation.allowed_delegates = VALID;
      delegation.children.allowed_child_actors = VALID;
    });
    const mod = await import("@mission/demo-data");
    const loaded = mod.DERIVATION_POLICY.ceiling[0];
    expect(LISTS.allowed_delegates.read(loaded)).toEqual(VALID);
    expect(LISTS.allowed_child_actors.read(loaded)).toEqual(VALID);
  });
});

// ---------------------------------------------------------------------------
// Wire level: the PAR intake answers invalid_authorization_details.
// ---------------------------------------------------------------------------

const PORT = 14937;
const ISSUER = `http://localhost:${PORT}`;
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource;
const TASK_INTENT = { goal: "Pay Acme invoices for Q3", target_resources: [RESOURCE], expires_at: "2027-01-01T00:00:00Z" };
const PKCE_VERIFIER = "matcher-members-verifier-0123456789-0123456789-0123";

let as: BuiltAs;
let asServer: Server;
let agentKey: CryptoKey;

async function pushPar(params: Record<string, string>): Promise<Response> {
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(PKCE_VERIFIER)),
  ).toString("base64url");
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(agentKey);
  return fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: "http://localhost:9999/cb",
      resource: RESOURCE,
      code_challenge: challenge,
      code_challenge_method: "S256",
      login_hint: "alice",
      mission_intent: JSON.stringify({ intent: TASK_INTENT }),
      ...params,
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
}

describe("PAR refuses a proposal carrying a malformed delegate matcher (#1373)", () => {
  beforeAll(async () => {
    as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
    asServer = as.provider.listen(PORT);
    agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
  });

  afterAll(() => {
    asServer?.close();
  });

  const proposal = (delegation: unknown) =>
    JSON.stringify([{ type: MISSION_RESOURCE_ACCESS_TYPE, resource: RESOURCE, actions: ["payments:invoice.read"], delegation }]);

  for (const [list, { path, delegation }] of Object.entries(LISTS)) {
    it(`refuses the org reproduction in ${list} with invalid_authorization_details, creating no Mission`, async () => {
      const before = as.kernel.allMissions().length;
      const res = await pushPar({ authorization_details: proposal(delegation([ORG_MATCHER])) });
      const body = (await res.json()) as { error: string; error_description?: string; request_uri?: string };
      expect(res.status).toBe(400);
      expect(body.error).toBe("invalid_authorization_details");
      expect(body.error_description).toBe(`${path} entries carry no member 'org'`);
      expect(body.request_uri).toBeUndefined();
      expect(as.kernel.allMissions().length).toBe(before);
    });
  }

  it("accepts sub, sub_profile, both, and a multi-value sub_profile in both lists (positive control)", async () => {
    const res = await pushPar({
      authorization_details: proposal({ max_depth: 1, allowed_delegates: VALID, children: { allowed_child_actors: VALID } }),
    });
    expect(res.status).toBe(201);
  });
});
