/**
 * @spec mission#submission-via-par — the front-channel authorization
 * endpoint's own refusal, real HTTP against the built AS.
 */

import type { Server } from "node:http";
import { CANONICAL_RESOURCE } from "@mission/demo-data";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildAuthorizationServer, type BuiltAs } from "../src/index.js";

const PORT = 14410;
const ISSUER = `http://localhost:${PORT}`;
const REDIRECT_URI = "http://localhost:9999/cb";

let as: BuiltAs;
let asServer: Server;

beforeAll(async () => {
  as = await buildAuthorizationServer({ issuer: ISSUER, allowHeadlessAdjudication: true });
  asServer = as.provider.listen(PORT);
});

afterAll(() => {
  asServer?.close();
});

describe("authorization endpoint: mission_intent requires a PAR-issued request_uri", () => {
  it("rejects a front-channel mission_intent with invalid_request, delivered via the registered redirect_uri", async () => {
    // The AS enforces this globally (oidc-provider's own
    // requirePushedAuthorizationRequests), not via a mission_intent-specific
    // branch: ANY front-channel authorization request lacking a PAR-issued
    // request_uri is refused before mission_intent is even inspected. That
    // still directly demonstrates this row's observable behavior, since a
    // mission_intent can never reach the extraParams handler by any other
    // path.
    const missionIntent = JSON.stringify({
      intent: {
        goal: "front-channel probe",
        target_resources: [CANONICAL_RESOURCE],
        expires_at: "2027-01-01T00:00:00Z",
      },
    });
    const authUrl = `${ISSUER}/auth?${new URLSearchParams({
      client_id: "ap-agent",
      response_type: "code",
      redirect_uri: REDIRECT_URI,
      scope: "payments",
      mission_intent: missionIntent,
    })}`;
    const res = await fetch(authUrl, { redirect: "manual" });
    expect(res.status).toBe(303);
    const location = res.headers.get("location") as string;
    expect(location).toBeTruthy();
    const redirected = new URL(location);
    expect(`${redirected.origin}${redirected.pathname}`).toBe(REDIRECT_URI);
    expect(redirected.searchParams.get("error")).toBe("invalid_request");
  });
});
