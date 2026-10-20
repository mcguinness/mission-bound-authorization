/**
 * @spec authority-server#mission-submission, status#mission-lifecycle-endpoint (#818 slice 5B)
 *
 * The pilot launchers' operator console: a loopback HTTP listener that holds
 * the per-boot credentials the walkthrough's steps need, in memory, the way
 * the shared demo and the as-native target keep theirs in an in-process
 * trusted console. Nothing is written to disk. Every request presents the
 * console's per-boot bearer, which the launcher prints once.
 *
 * Its two halves live with the credentials they use:
 *
 * - The MAS half (in the MAS's process): approve a Mission through the
 *   reference authorization server's own flow (the submitting agent's PAR,
 *   the approval decided on the approval surface by the approval-service
 *   principal, and the token request that completes it, whose `mission`
 *   claim names the new Mission), and revoke or contain one at the advertised
 *   Mission Lifecycle endpoint as the Lifecycle client.
 * - The pilot half (in the pilot's process): obtain an estate credential (an
 *   estate client's authorization code flow, DPoP-bound, its key kept here),
 *   make a joined call over the gateway with a `Mission-Reference`, and read
 *   the evidence the PEP retained for a Mission.
 *
 * It is an operator convenience over those protocol steps, never a path
 * around them: approval and lifecycle reach the MAS over HTTP, and a call
 * reaches the gateway exactly as any client's does.
 */

import { timingSafeEqual } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { createHttpMediatedClient, type DpopKeys } from "@mission/mcp-payments";
import { generateKeyPair } from "jose";
import { resolveMissionApproval } from "../approval-console.js";
import { requestLifecycle } from "../lifecycle-client.js";
import { redeemMissionApproval, submitMissionApproval } from "../oauth-client.js";
import type { MasPilotParts } from "./compose.js";
import { obtainEstateToken } from "./estate-client.js";
import type { PilotMas } from "./mas-as.js";

type Json = Record<string, unknown>;
interface Answer {
  status: number;
  body: Json;
}
/** One half's routes: an answer, or `undefined` for a path it does not serve. */
export type ConsoleRoutes = (method: string, path: string, body: Json) => Promise<Answer | undefined>;

/** The reads a Mission is approved for when the operator names none. */
export const DEFAULT_ACTIONS = ["payments:invoice.read", "payments:invoice.list", "payments:vendor.read"];

const decodePayload = (jws: string): Json => {
  try {
    return JSON.parse(Buffer.from(jws.split(".")[1] ?? "", "base64url").toString("utf8")) as Json;
  } catch {
    return {};
  }
};

const stringArray = (v: unknown): string[] | undefined =>
  Array.isArray(v) && v.length > 0 && v.every((a) => typeof a === "string") ? (v as string[]) : undefined;

/** The MAS half: approve, revoke and contain, at the MAS over HTTP. */
export function masConsoleRoutes(mas: Pick<PilotMas, "issuer" | "operator">): ConsoleRoutes {
  const { issuer, operator } = mas;
  return async (method, path, body) => {
    if (method === "POST" && path === "/missions") {
      const subject = typeof body.subject === "string" ? body.subject : "alice";
      const actions = body.actions === undefined ? DEFAULT_ACTIONS : stringArray(body.actions);
      if (!actions) return { status: 400, body: { error: "actions must be a non-empty array of strings" } };
      const label = typeof body.label === "string" ? body.label : "operator";
      const pending = await submitMissionApproval(issuer, operator.agentClientJwk, {
        missionIntent: JSON.stringify({
          intent: { goal: `MAS pilot: ${label}`, target_resources: [CANONICAL_RESOURCE], expires_at: "2027-06-01T00:00:00Z" },
        }),
        authorizationDetails: JSON.stringify([
          { type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions, constraints: { vendors: ["acme"] } },
        ]),
      });
      const code = await resolveMissionApproval(issuer, operator.approvalToken, pending, "approve", subject);
      if (!code) return { status: 502, body: { error: "the approval yielded no code" } };
      const issued = await redeemMissionApproval(issuer, operator.agentClientJwk, { code, par: pending.par });
      const mission = decodePayload(issued.accessToken).mission as { id?: string; issuer?: string } | undefined;
      return { status: 201, body: { mission_id: mission?.id, issuer: mission?.issuer, subject, actions } };
    }
    const lifecycle = /^\/missions\/([^/]+)\/(revoke|contain)$/.exec(path);
    if (method === "POST" && lifecycle) {
      const [, missionId, operation] = lifecycle as unknown as [string, string, "revoke" | "contain"];
      const members: Record<string, string> = { mission_id: missionId, operation, nonce: crypto.randomUUID() };
      if (operation === "contain") {
        const actions = stringArray(body.actions);
        if (!actions) return { status: 400, body: { error: "contain needs actions, a non-empty array of strings" } };
        members.event = JSON.stringify({
          type: "anomaly.detected",
          source: "svc:mas-pilot-operator",
          observed_at: new Date().toISOString(),
          event_id: `evt-${crypto.randomUUID()}`,
        });
        members.remove = JSON.stringify([{ resource: CANONICAL_RESOURCE, actions }]);
      }
      const res = await requestLifecycle(issuer, operator.lifecycle, members);
      const signed = res.contentType.includes("jwt") ? (decodePayload(res.text).mission as Json | undefined) : undefined;
      return {
        status: res.status,
        body: signed ? { mission_id: missionId, state: signed.state, version: signed.version } : { lifecycle_response: res.text },
      };
    }
    return undefined;
  };
}

/** The pilot half: estate credentials, joined calls over the gateway, and the PEP's evidence. */
export function pilotConsoleRoutes(pilot: Pick<MasPilotParts, "estate" | "estateClients" | "gateway" | "missionIssuer" | "evidence">): ConsoleRoutes {
  const credentials = new Map<string, { token: string; dpopKeys: DpopKeys }>();
  return async (method, path, body) => {
    if (method === "POST" && path === "/estate-tokens") {
      const registration = typeof body.client_id === "string" ? pilot.estateClients.get(body.client_id) : undefined;
      if (!registration) return { status: 400, body: { error: "client_id names no estate client" } };
      if (typeof body.account !== "string" || typeof body.scope !== "string") {
        return { status: 400, body: { error: "account and scope are required" } };
      }
      const dpopKeys = await generateKeyPair("ES256", { extractable: true });
      const result = await obtainEstateToken({
        issuer: pilot.estate.issuer,
        clientId: registration.client_id,
        clientSecret: registration.client_secret,
        redirectUri: registration.redirect_uri,
        account: body.account,
        resource: CANONICAL_RESOURCE,
        scope: body.scope,
        dpopKeys,
      });
      if (!result.ok) return { status: 400, body: { error: "the estate refused the token request", detail: result as unknown as Json } };
      const credentialId = `cred-${crypto.randomUUID()}`;
      credentials.set(credentialId, { token: result.accessToken, dpopKeys });
      return { status: 201, body: { credential_id: credentialId, client_id: registration.client_id, token_format: registration.token_format } };
    }
    if (method === "POST" && path === "/calls") {
      const credential = typeof body.credential_id === "string" ? credentials.get(body.credential_id) : undefined;
      if (!credential) return { status: 400, body: { error: "credential_id names no credential this console obtained" } };
      if (typeof body.mission_id !== "string" || typeof body.tool !== "string") {
        return { status: 400, body: { error: "mission_id and tool are required" } };
      }
      const args = body.arguments !== undefined && typeof body.arguments === "object" ? (body.arguments as Json) : {};
      const { client, close } = await createHttpMediatedClient(pilot.gateway.url, credential.token, credential.dpopKeys, {
        "mission-reference": `id="${body.mission_id}", issuer="${pilot.missionIssuer}"`,
      });
      try {
        return { status: 200, body: (await client.callTool(body.tool, args)) as unknown as Json };
      } finally {
        await close();
      }
    }
    const evidence = /^\/missions\/([^/]+)\/evidence$/.exec(path);
    if (method === "GET" && evidence) {
      const records = pilot.evidence.forMission(evidence[1] as string).map((e) => {
        const content = (e as { content?: Json }).content ?? {};
        return {
          kind: e.kind,
          ...("at" in e ? { at: e.at } : {}),
          ...(content.decision !== undefined ? { decision: content.decision } : {}),
          ...(content.denial_reason !== undefined ? { denial_reason: content.denial_reason } : {}),
          ...(content.action !== undefined ? { action: (content.action as Json).name } : {}),
        };
      });
      return { status: 200, body: { mission_id: evidence[1], records } };
    }
    return undefined;
  };
}

export interface OperatorConsole {
  url: string;
  close: () => Promise<void>;
}

const readBody = (req: IncomingMessage): Promise<string> =>
  new Promise((resolve, reject) => {
    let data = "";
    req.setEncoding("utf8");
    req.on("data", (chunk: string) => {
      data += chunk;
      if (data.length > 65_536) req.destroy(new Error("body too large"));
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });

const send = (res: ServerResponse, status: number, body: Json) => {
  res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store" });
  res.end(`${JSON.stringify(body)}\n`);
};

/**
 * Serve `routes` on `127.0.0.1:{port}` (0: an ephemeral port) behind the
 * per-boot bearer `token`: a request without it is refused 401 before any
 * route runs.
 */
export async function startOperatorConsole(routes: ConsoleRoutes[], opts: { port: number; token: string }): Promise<OperatorConsole> {
  const expected = Buffer.from(`Bearer ${opts.token}`);
  const server: Server = createServer((req, res) => {
    void (async () => {
      const presented = Buffer.from(req.headers.authorization ?? "");
      if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) {
        send(res, 401, { error: "unauthorized" });
        return;
      }
      let body: Json = {};
      const raw = await readBody(req);
      if (raw.trim() !== "") {
        try {
          body = JSON.parse(raw) as Json;
        } catch {
          send(res, 400, { error: "the body is not JSON" });
          return;
        }
      }
      const path = new URL(req.url ?? "/", "http://console").pathname;
      for (const route of routes) {
        const answer = await route(req.method ?? "GET", path, body);
        if (answer) {
          send(res, answer.status, answer.body);
          return;
        }
      }
      send(res, 404, { error: "no such operator route" });
    })().catch((e: unknown) => send(res, 500, { error: e instanceof Error ? e.message : String(e) }));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(opts.port, "127.0.0.1", () => resolve());
  });
  return {
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    close: () => {
      server.closeAllConnections();
      return new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}
