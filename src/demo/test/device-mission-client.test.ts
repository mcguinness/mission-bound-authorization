/**
 * @spec device-authorization#discovery, device-authorization#issuance (#1202):
 * the reference Mission Device Authorization client. Stub authorization
 * servers serve what the reference AS never does (device-grant metadata
 * without the profile, one support member alone, another device endpoint,
 * another issuer, a success response lacking a Mission member) and record
 * every request they receive. One Mission is then created end to end against
 * the real AS with the opt-in `device-authorization` capability on, and the
 * default assembly, which leaves it off, receives no device request.
 */

import { createServer, type IncomingHttpHeaders, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import {
  ALL_PROVIDER_CAPABILITIES,
  ApprovalSessionStore,
  buildAuthorizationServer,
  RENDER_REVISION_HEADER,
  type BuiltAs,
  type ProviderCapability,
} from "@mission/authorization-server";
import { DERIVATION_POLICY } from "@mission/demo-data";
import { generateKeyPair } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createMissionByDevice, type DeviceMissionClient, type DeviceUserInstruction } from "../src/device-mission-client.js";
import type { DpopKeys } from "../src/oauth-client.js";

const DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code";
const RESOURCE = DERIVATION_POLICY.ceiling[0].resource as string;
const READ = [{ type: "mission_resource_access", resource: RESOURCE, actions: ["payments:invoice.read"] }];
/** The suite's controlled clock (D1091): the Mission's expiry derives from it, never from the real date. */
const CLOCK_MS = Date.parse("2026-11-02T12:00:00Z");
const EXPIRES_AT = new Date(CLOCK_MS + 30 * 86_400_000).toISOString().replace(/\.\d{3}Z$/, "Z");
const REQUEST = {
  missionIntent: { intent: { goal: "Reconcile Q3 invoices.", target_resources: [RESOURCE], expires_at: EXPIRES_AT } },
  authorizationDetails: READ,
  resource: RESOURCE,
};
const ACCESS_TOKEN = "stub-access-token-1202";
const REFRESH_TOKEN = "stub-refresh-token-1202";
const METADATA_PATH = "/.well-known/openid-configuration";
const SUCCESS = {
  access_token: ACCESS_TOKEN,
  token_type: "DPoP",
  expires_in: 300,
  refresh_token: REFRESH_TOKEN,
  mission_id: "mis_stub",
  mission_expires_at: EXPIRES_AT,
  authorization_details: READ,
};

interface Seen {
  method: string;
  path: string;
  body: string;
  headers: IncomingHttpHeaders;
}
interface Stub {
  issuer: string;
  seen: Seen[];
  server: Server;
}
type Answer = { status: number; body: Record<string, unknown> };

const stubs: Stub[] = [];
afterAll(() => {
  for (const s of stubs) s.server.close();
  vi.useRealTimers();
});

/** Metadata advertising the profile at the stub's own endpoints. */
const advertised = (issuer: string): Record<string, unknown> => ({
  issuer,
  token_endpoint: `${issuer}/token`,
  device_authorization_endpoint: `${issuer}/device/auth`,
  grant_types_supported: [DEVICE_GRANT, "refresh_token"],
  mission_bound_authorization_supported: true,
  mission_device_authorization_supported: true,
});

/**
 * A stub AS that records every request: metadata from `meta`, a device
 * session at `/device/auth` whose members `opts.session` overrides, and the
 * token endpoint's `answers` in turn, running `opts.onToken` as each poll
 * arrives.
 */
async function stubAs(
  meta: (issuer: string) => unknown,
  answers: Answer[] = [{ status: 200, body: SUCCESS }],
  opts: { session?: Record<string, unknown>; onToken?: () => void } = {},
): Promise<Stub> {
  const seen: Seen[] = [];
  let issuer = "";
  let polls = 0;
  const server = createServer((req, res) => {
    let body = "";
    req.on("data", (chunk: Buffer) => (body += chunk.toString()));
    req.on("end", () => {
      seen.push({ method: req.method ?? "", path: req.url ?? "", body, headers: req.headers });
      const send = (status: number, json: unknown) => {
        res.writeHead(status, { "content-type": "application/json" });
        res.end(JSON.stringify(json));
      };
      if (req.url === METADATA_PATH) return send(200, meta(issuer));
      if (req.url === "/device/auth") {
        return send(200, {
          device_code: "stub-device-code",
          user_code: "WDJB-MJHT",
          verification_uri: `${issuer}/device`,
          expires_in: 600,
          interval: 5,
          ...opts.session,
        });
      }
      if (req.url === "/token") {
        opts.onToken?.();
        const answer = answers[Math.min(polls++, answers.length - 1)] as Answer;
        return send(answer.status, answer.body);
      }
      send(404, {});
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const stub = { issuer, seen, server };
  stubs.push(stub);
  return stub;
}

let dpopKeys: DpopKeys;
beforeAll(async () => {
  // Before the reference AS is composed, so every time it reads is on the clock.
  vi.useFakeTimers({ toFake: ["Date"], shouldAdvanceTime: true });
  vi.setSystemTime(CLOCK_MS);
  const pair = await generateKeyPair("ES256", { extractable: true });
  dpopKeys = { privateKey: pair.privateKey, publicKey: pair.publicKey };
});

/** The client's clock in milliseconds, advanced only by the test. */
type Clock = { ms: number };

/** A public client of `issuer` on its own clock: each wait is recorded and advances the clock, never sleeping. */
function clientOf(
  issuer: string,
  extra: Partial<DeviceMissionClient> = {},
  clock: Clock = { ms: 0 },
): { client: DeviceMissionClient; waits: number[]; clock: Clock } {
  const waits: number[] = [];
  const client: DeviceMissionClient = {
    issuer,
    authenticate: async () => ({ client_id: "cli-agent" }),
    dpopKeys,
    sleep: async (ms) => {
      waits.push(ms);
      clock.ms += ms;
    },
    now: () => clock.ms,
    ...extra,
  };
  return { client, waits, clock };
}

describe("the reference device client's discovery (@spec device-authorization#discovery, #1202)", () => {
  const cases: { name: string; meta: (issuer: string) => unknown; endpoint?: (issuer: string) => string; reason: RegExp }[] = [
    {
      name: "RFC 8628 device-grant metadata alone",
      meta: (i) => {
        const { mission_bound_authorization_supported: _b, mission_device_authorization_supported: _d, ...m } = advertised(i);
        return m;
      },
      reason: /does not advertise mission_bound_authorization_supported/,
    },
    {
      name: "the OAuth binding's member without the profile's",
      meta: (i) => ({ ...advertised(i), mission_device_authorization_supported: undefined }),
      reason: /does not advertise mission_device_authorization_supported/,
    },
    {
      name: "the profile's member without the OAuth binding's",
      meta: (i) => ({ ...advertised(i), mission_bound_authorization_supported: false }),
      reason: /does not advertise mission_bound_authorization_supported/,
    },
    {
      name: "a support member that is the string \"true\", not the boolean",
      meta: (i) => ({ ...advertised(i), mission_device_authorization_supported: "true" }),
      reason: /does not advertise mission_device_authorization_supported/,
    },
    {
      name: "both members true but another device_authorization_endpoint than the one the client uses",
      meta: (i) => ({ ...advertised(i), device_authorization_endpoint: `${i}/other/device` }),
      endpoint: (i) => `${i}/device/auth`,
      reason: /names the device_authorization_endpoint .*\/other\/device, not .*\/device\/auth/,
    },
    {
      name: "both members true and no device_authorization_endpoint",
      meta: (i) => ({ ...advertised(i), device_authorization_endpoint: undefined }),
      reason: /names no device_authorization_endpoint/,
    },
    {
      name: "metadata naming another issuer",
      meta: (i) => ({ ...advertised(i), issuer: "https://as.other.example" }),
      reason: /serves metadata for issuer https:\/\/as\.other\.example/,
    },
    {
      name: "a metadata document that is JSON null",
      meta: () => null,
      reason: /serves metadata that is not a JSON object/,
    },
    {
      name: "a metadata document that is a JSON array",
      meta: (i) => [advertised(i)],
      reason: /serves metadata that is not a JSON object/,
    },
  ];

  for (const c of cases) {
    it(`against ${c.name}, sends no request carrying mission_intent and no ordinary device authorization request, and reports the inability`, async () => {
      const stub = await stubAs(c.meta);
      const shown: DeviceUserInstruction[] = [];
      const { client } = clientOf(stub.issuer, c.endpoint ? { deviceAuthorizationEndpoint: c.endpoint(stub.issuer) } : {});
      const result = await createMissionByDevice(client, REQUEST, (i) => {
        shown.push(i);
      });
      expect(result.outcome).toBe("unsupported");
      expect(result.outcome === "unsupported" && result.reason).toMatch(c.reason);
      // Only the metadata was read: no device authorization request of any
      // kind, with mission_intent, scope or authorization_details, and no poll.
      expect(stub.seen.map((s) => `${s.method} ${s.path}`)).toEqual([`GET ${METADATA_PATH}`]);
      expect(shown).toEqual([]);
    });
  }

  it("against an AS advertising both members and naming the endpoint the client uses, sends one device authorization request carrying mission_intent", async () => {
    const stub = await stubAs(advertised);
    const { client } = clientOf(stub.issuer, { deviceAuthorizationEndpoint: `${stub.issuer}/device/auth` });
    const result = await createMissionByDevice(client, REQUEST, () => {});
    expect(result.outcome).toBe("created");
    const device = stub.seen.filter((s) => s.path === "/device/auth");
    expect(device).toHaveLength(1);
    const form = new URLSearchParams((device[0] as Seen).body);
    expect(JSON.parse(form.get("mission_intent") as string)).toEqual(REQUEST.missionIntent);
    expect(JSON.parse(form.get("authorization_details") as string)).toEqual(READ);
    expect(form.get("client_id")).toBe("cli-agent");
    expect(form.has("request")).toBe(false);
    expect(form.has("request_uri")).toBe(false);
  });
});

describe("the reference device client's use of a success response (@spec device-authorization#issuance, #1202)", () => {
  for (const member of ["mission_id", "mission_expires_at", "authorization_details"] as const) {
    it(`treats a success response lacking ${member} as a failed Mission creation and presents none of its tokens`, async () => {
      const { [member]: _dropped, ...lacking } = SUCCESS;
      const stub = await stubAs(advertised, [{ status: 200, body: lacking }]);
      const { client } = clientOf(stub.issuer);
      const result = await createMissionByDevice(client, REQUEST, () => {});
      expect(result).toEqual({
        outcome: "no_mission",
        error: "mission_members_missing",
        errorDescription: `the token response lacks ${member}`,
      });
      // The tokens never leave the client: not in its result, and in no
      // request after the token response.
      expect(JSON.stringify(result)).not.toContain(ACCESS_TOKEN);
      expect(JSON.stringify(result)).not.toContain(REFRESH_TOKEN);
      expect(stub.seen.at(-1)?.path).toBe("/token");
      const carrying = stub.seen.filter((s) => `${s.body} ${JSON.stringify(s.headers)}`.includes(ACCESS_TOKEN));
      expect(carrying).toEqual([]);
    });
  }

  it("returns the Mission members and tokens of a response carrying all three", async () => {
    const stub = await stubAs(advertised);
    const { client } = clientOf(stub.issuer);
    const result = await createMissionByDevice(client, REQUEST, () => {});
    expect(result).toEqual({
      outcome: "created",
      missionId: "mis_stub",
      missionExpiresAt: EXPIRES_AT,
      authorizationDetails: READ,
      accessToken: ACCESS_TOKEN,
      tokenType: "DPoP",
      expiresIn: 300,
      refreshToken: REFRESH_TOKEN,
    });
  });

  it("polls at the session's interval, adds 5 seconds on slow_down, proves its DPoP key on every poll, and stops at a terminal error", async () => {
    const pending = { status: 400, body: { error: "authorization_pending" } };
    const stub = await stubAs(advertised, [pending, { status: 400, body: { error: "slow_down" } }, pending, { status: 200, body: SUCCESS }]);
    const { client, waits } = clientOf(stub.issuer);
    expect((await createMissionByDevice(client, REQUEST, () => {})).outcome).toBe("created");
    expect(waits).toEqual([5000, 5000, 10000, 10000]);
    const polls = stub.seen.filter((s) => s.path === "/token");
    expect(polls).toHaveLength(4);
    for (const p of polls) {
      expect(typeof p.headers.dpop).toBe("string");
      expect(new URLSearchParams(p.body).get("grant_type")).toBe(DEVICE_GRANT);
    }

    const denied = await stubAs(advertised, [{ status: 400, body: { error: "access_denied", error_description: "declined" } }]);
    const refusal = await createMissionByDevice(clientOf(denied.issuer).client, REQUEST, () => {});
    expect(refusal).toEqual({ outcome: "no_mission", error: "access_denied", errorDescription: "declined" });
    expect(denied.seen.filter((s) => s.path === "/token")).toHaveLength(1);
  });
});

describe("the reference device client's polling deadline (@spec device-authorization#outcomes, #1202)", () => {
  const PENDING: Answer = { status: 400, body: { error: "authorization_pending" } };
  const EXPIRED = { outcome: "no_mission", error: "expired_token", errorDescription: "the device_code lifetime elapsed while polling" };

  /** A device session with these members on a stub that records the client's clock at each poll and spends `latencyMs` answering it. */
  async function session(members: Record<string, unknown>, answers: Answer[], latencyMs = 0) {
    const clock: Clock = { ms: 0 };
    const polledAt: number[] = [];
    const stub = await stubAs(advertised, answers, {
      session: members,
      onToken: () => {
        polledAt.push(clock.ms);
        clock.ms += latencyMs;
      },
    });
    return { ...clientOf(stub.issuer, {}, clock), polledAt };
  }

  it("sends no poll, and does not wait, when the session's lifetime is shorter than its interval", async () => {
    const s = await session({ expires_in: 2, interval: 5 }, [PENDING]);
    expect(await createMissionByDevice(s.client, REQUEST, () => {})).toEqual(EXPIRED);
    expect(s.polledAt).toEqual([]);
    expect(s.waits).toEqual([]);
  });

  it("counts the user's time with the code against the deadline: no poll after a display that outlasted the session", async () => {
    const s = await session({ expires_in: 10, interval: 5 }, [PENDING]);
    const result = await createMissionByDevice(s.client, REQUEST, () => {
      s.clock.ms += 11_000;
    });
    expect(result).toEqual(EXPIRED);
    expect(s.polledAt).toEqual([]);
  });

  it("never polls at the deadline: one poll at 5 seconds of a 10-second session, none at 10", async () => {
    const s = await session({ expires_in: 10, interval: 5 }, [PENDING]);
    expect(await createMissionByDevice(s.client, REQUEST, () => {})).toEqual(EXPIRED);
    expect(s.polledAt).toEqual([5000]);
    expect(s.waits).toEqual([5000]);
  });

  it("after slow_down near the deadline, neither waits for nor sends the poll the longer interval would place past it", async () => {
    const s = await session({ expires_in: 12, interval: 5 }, [{ status: 400, body: { error: "slow_down" } }]);
    expect(await createMissionByDevice(s.client, REQUEST, () => {})).toEqual(EXPIRED);
    expect(s.polledAt).toEqual([5000]);
    expect(s.waits).toEqual([5000]);
  });

  it("counts each poll's request time: a poll answered at 8 seconds of a 12-second session is the last", async () => {
    const s = await session({ expires_in: 12, interval: 5 }, [PENDING], 3000);
    expect(await createMissionByDevice(s.client, REQUEST, () => {})).toEqual(EXPIRED);
    expect(s.polledAt).toEqual([5000]);
  });

  it("rechecks the deadline immediately before each poll: a wait that overran it, or an authentication that reached it, sends nothing", async () => {
    const overrun = await session({ expires_in: 10, interval: 5 }, [PENDING]);
    overrun.client.sleep = async (ms) => {
      overrun.clock.ms += ms + 6000;
    };
    expect(await createMissionByDevice(overrun.client, REQUEST, () => {})).toEqual(EXPIRED);
    expect(overrun.polledAt).toEqual([]);

    const slowAuth = await session({ expires_in: 6, interval: 5 }, [PENDING]);
    slowAuth.client.authenticate = async () => {
      slowAuth.clock.ms += 1000;
      return { client_id: "cli-agent" };
    };
    expect(await createMissionByDevice(slowAuth.client, REQUEST, () => {})).toEqual(EXPIRED);
    expect(slowAuth.polledAt).toEqual([]);
  });
});

describe("the reference device client against the reference AS (@spec device-authorization#discovery, device-authorization#issuance, #1202)", () => {
  const PORT = 14966;
  const ISSUER = `http://localhost:${PORT}`;
  const OFF_PORT = 14968;
  const OFF_ISSUER = `http://localhost:${OFF_PORT}`;
  const sessions = new ApprovalSessionStore();
  const FORM = { "content-type": "application/x-www-form-urlencoded" };
  let as: BuiltAs;
  let off: BuiltAs;
  let server: Server;
  let offServer: Server;

  beforeAll(async () => {
    // agent-A1 is a client the shipped acme-people authority source names,
    // registered here as a public device client.
    const publicClient = {
      client_id: "agent-A1",
      token_endpoint_auth_method: "none",
      grant_types: [DEVICE_GRANT, "refresh_token"],
      response_types: [],
      redirect_uris: [],
      authorization_details_types: ["mission_resource_access"],
    };
    as = await buildAuthorizationServer({
      issuer: ISSUER,
      approvalSessions: sessions,
      capabilities: new Set<ProviderCapability>([...ALL_PROVIDER_CAPABILITIES, "device-authorization"]),
      testClients: [publicClient],
    });
    server = as.provider.listen(PORT);
    off = await buildAuthorizationServer({ issuer: OFF_ISSUER, approvalSessions: sessions, testClients: [publicClient] });
    offServer = off.provider.listen(OFF_PORT);
  });
  afterAll(() => {
    server?.close();
    offServer?.close();
  });

  /**
   * The Approver's user agent: Bob types the user code, confirms it, signs in
   * to approve for Alice, reviews the page and approves.
   */
  async function approveOnSecondDevice(instruction: DeviceUserInstruction): Promise<void> {
    const jar = new Map<string, string>();
    const cookie = () => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
    const keep = (res: Response) => {
      for (const line of res.headers.getSetCookie()) {
        const [pair] = line.split(";");
        const eq = (pair as string).indexOf("=");
        jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
      }
    };
    const xsrf = (html: string) => (/name="xsrf" value="([^"]*)"/.exec(html) as RegExpExecArray)[1] as string;
    let res = await fetch(instruction.verificationUri, { headers: { cookie: cookie() }, redirect: "manual" });
    keep(res);
    for (const more of [{}, { confirm: "yes" }]) {
      res = await fetch(`${ISSUER}/device`, {
        method: "POST",
        redirect: "manual",
        headers: { ...FORM, cookie: cookie() },
        body: new URLSearchParams({ xsrf: xsrf(await res.text()), user_code: instruction.userCode, ...more }).toString(),
      });
      keep(res);
    }
    const uid = (res.headers.get("location") ?? "").split("/interaction/")[1] as string;
    expect(uid).toBeTruthy();
    const login = sessions.establish(uid, { sub: "bob", acr: "password", auth_time: Math.floor(Date.now() / 1000), subject: "alice" });
    const headers = { cookie: `${cookie()}; ${login.cookie}`, "x-csrf-token": login.csrf };
    const page = await fetch(`${ISSUER}/interaction/${uid}`, { headers });
    expect(page.status).toBe(200);
    const decided = await fetch(`${ISSUER}/interaction/${uid}/decide`, {
      method: "POST",
      redirect: "manual",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({
        decision: "approve",
        confirm_user_code: true,
        confirm_started: true,
        render_revision: page.headers.get(RENDER_REVISION_HEADER),
      }),
    });
    expect(decided.status, await decided.text()).toBe(200);
  }

  it("creates a Mission through the device flow and uses its tokens only with mission_id, mission_expires_at and the granted authorization_details", async () => {
    const { client } = clientOf(ISSUER, { authenticate: async () => ({ client_id: "agent-A1" }) });
    const result = await createMissionByDevice(client, REQUEST, approveOnSecondDevice);
    expect(result.outcome, JSON.stringify(result)).toBe("created");
    if (result.outcome !== "created") return;
    const record = as.kernel.allMissions().find((m) => m.id === result.missionId);
    expect(record?.state).toBe("active");
    expect(record?.client_id).toBe("agent-A1");
    expect(result.missionExpiresAt).toBe(record?.expires_at);
    expect(result.authorizationDetails).toEqual([expect.objectContaining({ type: "mission_resource_access", resource: RESOURCE })]);
    expect(result.tokenType).toBe("DPoP");
  });

  it("refuses the default assembly, which leaves the profile off, before any device request, and creates no Mission", async () => {
    const before = off.kernel.allMissions().length;
    const shown: DeviceUserInstruction[] = [];
    const { client } = clientOf(OFF_ISSUER, { authenticate: async () => ({ client_id: "agent-A1" }) });
    const result = await createMissionByDevice(client, REQUEST, (i) => {
      shown.push(i);
    });
    expect(result).toEqual({ outcome: "unsupported", reason: `${OFF_ISSUER} does not advertise mission_device_authorization_supported` });
    expect(shown).toEqual([]);
    expect(off.kernel.allMissions().length).toBe(before);
  });
});
