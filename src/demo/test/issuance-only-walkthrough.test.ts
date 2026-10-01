/**
 * The published issuance-only walkthrough (src/docs/issuance-only-deployment.md
 * § Run it), end to end over real HTTP, in both configurations: the launcher's
 * `startIssuanceOnly` and the walkthrough command's `runWalkthrough`, in
 * process. No OpenFGA, PDP or PEP is involved.
 */
import { describe, expect, it } from "vitest";
import { PLAIN_RS_AUDIENCE, runWalkthrough, startIssuanceOnly, type WalkthroughStep } from "../src/issuance-only.js";

const byStep = (steps: WalkthroughStep[]) => Object.fromEntries(steps.map((s) => [s.step.split(" ")[0], s]));

async function walk(introspection: boolean, asPort: number, rsPort: number) {
  const deployment = await startIssuanceOnly({ introspection, asPort, rsPort });
  try {
    return byStep(await runWalkthrough(deployment.credentials));
  } finally {
    await deployment.close();
  }
}

/** Steps 1-6a are identical in both configurations. */
function expectCommonPath(s: Record<string, WalkthroughStep>) {
  expect(s["1."]?.status).toBe(201);
  expect(s["2."]?.status, JSON.stringify(s["2."]?.result)).toBe(200);
  expect(s["3."]?.status, JSON.stringify(s["3."]?.result)).toBe(200);
  expect(s["3."]?.result.scope).toBe("reports.read");
  const claims = s["3."]?.result.access_token_claims as Record<string, unknown>;
  expect(claims.aud).toBe(PLAIN_RS_AUDIENCE);
  expect(claims.scope).toBe("reports.read");
  expect(s["4."]?.status).toBe(200);
  expect(s["5."]?.status).toBe(403);
  expect(s["5."]?.result.error).toBe("insufficient_scope");
  expect(s["6."]?.status).toBe(200);
  expect(s["6."]?.result.state).toBe("revoked");
  expect(s["6a."]?.status).toBe(400);
  expect(s["6a."]?.result.error).toBe("invalid_grant");
}

describe("the issuance-only walkthrough (#873)", () => {
  it("JWT only: reports.read is issued and served, reports.write is refused insufficient_scope, and after revocation refresh is refused while the access token is still honored until exp", async () => {
    const s = await walk(false, 14660, 14661);
    expectCommonPath(s);
    expect(s["6b."]?.status).toBe(200);
  });

  it("JWT plus introspection: the same path, and after revocation the next call is refused invalid_token", async () => {
    const s = await walk(true, 14662, 14663);
    expectCommonPath(s);
    expect(s["6b."]?.status).toBe(401);
    expect(s["6b."]?.result.error).toBe("invalid_token");
  });
});
