/**
 * @spec status#lifecycle-operations, status#idempotency: the reference
 * Lifecycle client (src/lifecycle-client.ts) against a real reference AS.
 *
 * The client draws a fresh `nonce` for each new operation it requests on a
 * Mission and repeats it only to retransmit that request, from the request it
 * retained. Every request goes to the advertised `mission_lifecycle_endpoint`
 * under the console's own private-key-JWT credential. The AS runs on a key
 * ring and a kernel file, so it can be stopped and started again with its
 * retained responses intact.
 */
import { mkdtempSync, rmSync } from "node:fs";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  type BuiltAs,
  buildAuthorizationServer,
  initSigningKeyRing,
  type MissionRecord,
  validateMissionIntent,
} from "@mission/authorization-server";
import { CANONICAL_RESOURCE, TOPOLOGY } from "@mission/demo-data";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  type LifecycleConsoleCredentials,
  type LifecycleRequestRecord,
  newLifecycleConsole,
  newLifecycleRequest,
  transmitLifecycle,
} from "../src/lifecycle-client.js";

const PORT = 15411;
const ISSUER = `http://localhost:${PORT}`;
const ROLES = {
  asToken: TOPOLOGY.keys.asToken,
  asStatus: TOPOLOGY.keys.asStatus,
  asTxn: TOPOLOGY.keys.asTxn,
  asContinuation: TOPOLOGY.keys.asContinuation,
};

let dir: string;
let ring: string;
let kernelFile: string;
let as: BuiltAs | undefined;
let server: Server | undefined;
let registrations: Awaited<ReturnType<typeof newLifecycleConsole>>["registration"][];
/** The lifecycle console under test. */
let console1: LifecycleConsoleCredentials;
let approvals = 0;

/** Start the AS on the ring and the kernel file. */
async function start(): Promise<BuiltAs> {
  as = await buildAuthorizationServer({
    issuer: ISSUER,
    signingKeys: { ring },
    kernelStore: { file: kernelFile },
    lifecycleClients: registrations,
  });
  server = as.provider.listen(PORT);
  await new Promise<void>((r) => server?.once("listening", () => r()));
  return as;
}

/** Stop the AS, releasing its port and its kernel file. */
async function stop(): Promise<void> {
  if (server) await new Promise<void>((r) => server?.close(() => r()));
  as?.kernel.db.close();
  server = undefined;
  as = undefined;
}

function running(): BuiltAs {
  if (!as) throw new Error("the AS is not running");
  return as;
}

function approve(): MissionRecord {
  approvals += 1;
  return running().kernel.approve({
    intent: validateMissionIntent(
      JSON.stringify({ goal: "Read Acme invoices", target_resources: [CANONICAL_RESOURCE], expires_at: "2027-06-01T00:00:00Z" }),
    ),
    proposedAuthority: [{ type: "mission_resource_access", resource: CANONICAL_RESOURCE, actions: ["payments:invoice.read"] }],
    subject: { iss: ISSUER, sub: "alice" },
    approver: { iss: ISSUER, sub: "bob" },
    clientId: "ap-agent",
    approvalEventId: `apev-lifecycle-client-${approvals}`,
  });
}

const versionOf = (id: string): number => (running().kernel.get(id) as MissionRecord).version;

/** The form members of every Lifecycle request `spy` saw sent, client authentication removed. */
function sentForms(spy: { mock: { calls: unknown[][] } }): Record<string, string>[] {
  return spy.mock.calls
    .filter(([url, init]) => String(url).endsWith("/mission/lifecycle") && (init as RequestInit | undefined)?.method === "POST")
    .map(([, init]) => {
      const form = Object.fromEntries(new URLSearchParams(String((init as RequestInit).body)));
      delete form.client_assertion;
      delete form.client_assertion_type;
      return form;
    });
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "lifecycle-client-"));
  ring = join(dir, "keys", "as-signing-keys.json");
  kernelFile = join(dir, "kernel.db");
  await initSigningKeyRing(ring, ISSUER, ROLES);
  const first = await newLifecycleConsole("lifecycle-console-1");
  console1 = first.credentials;
  registrations = [first.registration];
  await start();
});

afterAll(async () => {
  await stop();
  rmSync(dir, { recursive: true, force: true });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("the reference Lifecycle client's nonces (@spec status#lifecycle-operations, status#idempotency)", () => {
  it("draws a fresh nonce for each new operation on a Mission and repeats it only to retransmit that request, so the AS replays the original response with no second transition", async () => {
    const m = approve();
    const fetches = vi.spyOn(globalThis, "fetch");
    const suspend: LifecycleRequestRecord = newLifecycleRequest(m.id, { operation: "suspend" });
    const first = await transmitLifecycle(ISSUER, console1, suspend);
    expect(first.status, first.text).toBe(200);
    // A second new operation on the same Mission: a reused nonce with other
    // members would be refused invalid_request, never performed.
    const resume = newLifecycleRequest(m.id, { operation: "resume" });
    expect(resume.nonce).not.toBe(suspend.nonce);
    const second = await transmitLifecycle(ISSUER, console1, resume);
    expect(second.status, second.text).toBe(200);
    const resumed = versionOf(m.id);
    expect(running().kernel.get(m.id)?.state).toBe("active");
    // The retransmit of the first request: its members and nonce, so the AS
    // replays the original suspend and does not suspend the resumed Mission.
    const retransmit = await transmitLifecycle(ISSUER, console1, suspend);
    expect(retransmit.status).toBe(200);
    expect(retransmit.text).toBe(first.text);
    expect(versionOf(m.id)).toBe(resumed);
    expect(running().kernel.get(m.id)?.state).toBe("active");
    const [sentFirst, sentSecond, sentRetransmit] = sentForms(fetches);
    expect(sentFirst).toEqual({ operation: "suspend", mission_id: m.id, nonce: suspend.nonce });
    expect(sentSecond).toEqual({ operation: "resume", mission_id: m.id, nonce: resume.nonce });
    expect(sentRetransmit).toEqual(sentFirst);
    // Unique among the console's nonces for the Mission, however many it draws.
    const drawn = new Set(Array.from({ length: 1000 }, () => newLifecycleRequest(m.id, { operation: "revoke" }).nonce));
    expect(drawn.size).toBe(1000);
  });
});
