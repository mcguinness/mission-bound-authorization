/**
 * @spec mission#approval-event (step 5), mission#authority-sources (#827) —
 * the approval RENDERING over a catalog where one agent registration serves
 * two sources: alice's and bob's delegated authority, and the organizational
 * policy, selected by Subject. The real AS assembly boots over a copy of the
 * shipped `config/` whose `authority-sources.json` shares `ap-agent` between
 * them, so the rendering under test is the one the provider serves.
 */

import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { importJWK, SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const PORT = 14627;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";

let dir: string;
let server: { close: () => void } | undefined;
let agentKey: CryptoKey;
let resource: string;
const original = process.env.MISSION_CONFIG_DIR;

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), "mission-config-827-"));
  cpSync(join(import.meta.dirname, "../../../config"), dir, { recursive: true });
  const file = join(dir, "authority-sources.json");
  const doc = JSON.parse(readFileSync(file, "utf8")) as { sources: Record<string, unknown>[] };
  const people = doc.sources.find((s) => s.id === "acme-people") as Record<string, unknown>;
  const governed = doc.sources.find((s) => s.type === "organizational") as Record<string, unknown>;
  // ap-agent serves the people source for alice and bob, and the governed
  // policy for its organizational principal: disjoint Subjects, one client.
  people.subjects = ["alice", "bob"];
  governed.clients = [...(governed.clients as string[]), "ap-agent"];
  governed.subjects = ["acme-accounts-payable"];
  writeFileSync(file, JSON.stringify(doc, null, 2));
  process.env.MISSION_CONFIG_DIR = dir;
  vi.resetModules();
  const { buildAuthorizationServer } = await import("../src/index.js");
  const { DERIVATION_POLICY } = await import("@mission/demo-data");
  resource = DERIVATION_POLICY.ceiling[0].resource as string;
  const as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
  server = as.provider.listen(PORT);
  agentKey = (await importJWK(as.agentClientJwk as never, "ES256")) as CryptoKey;
});

afterAll(() => {
  server?.close();
  if (original === undefined) delete process.env.MISSION_CONFIG_DIR;
  else process.env.MISSION_CONFIG_DIR = original;
  rmSync(dir, { recursive: true, force: true });
});

async function render(loginHint?: string): Promise<Response> {
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: "ES256", kid: "ap-agent-auth" })
    .setIssuer("ap-agent")
    .setSubject("ap-agent")
    .setAudience(ISSUER)
    .setIssuedAt()
    .setExpirationTime("2m")
    .setJti(crypto.randomUUID())
    .sign(agentKey);
  const verifier = "authority-source-render-verifier-0123456789-0123";
  const challenge = Buffer.from(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)),
  ).toString("base64url");
  const par = await fetch(`${ISSUER}/request`, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      resource,
      code_challenge: challenge,
      code_challenge_method: "S256",
      ...(loginHint ? { login_hint: loginHint } : {}),
      mission_intent: JSON.stringify({
        intent: { goal: "Read Acme invoices", target_resources: [resource], expires_at: "2027-01-01T00:00:00Z" },
      }),
      authorization_details: JSON.stringify([
        { type: "mission_resource_access", resource, actions: ["payments:invoice.read"] },
      ]),
      client_assertion: assertion,
      client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    }).toString(),
  });
  expect(par.status, await par.clone().text()).toBe(201);
  const { request_uri } = (await par.json()) as { request_uri: string };
  const auth = await fetch(`${ISSUER}/auth?${new URLSearchParams({ client_id: "ap-agent", request_uri })}`, {
    redirect: "manual",
  });
  const cookie = auth.headers
    .getSetCookie()
    .map((line) => line.split(";")[0])
    .join("; ");
  const uid = (auth.headers.get("location") as string).split("/interaction/")[1] as string;
  return fetch(`${ISSUER}/interaction/${uid}`, { headers: { cookie } });
}

describe("authority source rendering for a shared agent registration (@spec mission#approval-event, mission#authority-sources, #827)", () => {
  it("renders the source of the Subject login_hint names, and refuses to render one that depends on an unnamed Subject", async () => {
    const delegated = await render("alice");
    expect(delegated.status).toBe(200);
    const delegatedHtml = await delegated.text();
    expect(delegatedHtml).toContain("user_delegated");
    expect(delegatedHtml).not.toContain("acme-accounts-payable-controls");

    const organizational = await render("acme-accounts-payable");
    expect(organizational.status).toBe(200);
    const organizationalHtml = await organizational.text();
    expect(organizationalHtml).toContain("organizational");
    expect(organizationalHtml).toContain("acme-accounts-payable-controls");

    // No Subject named: the two sources differ in provenance, so no rendering
    // would be true for whichever Subject the decision binds.
    const unnamed = await render();
    expect(unnamed.status).toBe(400);
    expect(((await unnamed.json()) as { error_description: string }).error_description).toMatch(
      /depends on the Subject/,
    );
  });
});
