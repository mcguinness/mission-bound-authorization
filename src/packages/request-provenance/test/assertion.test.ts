// @spec request-provenance#assertion, request-provenance#signing, request-provenance#example
//
// capture then sign, against vectors/mission-request-provenance/assertion.json.

import { compactVerify, decodeProtectedHeader, jwtVerify } from "jose";
import { describe, expect, it } from "vitest";
import {
  ASSERTION_CLAIMS,
  createRequestIntake,
  REQUEST_PROVENANCE_JWT_TYP,
  REQUEST_PROVENANCE_TYPE,
  type SignRequest,
} from "../src/index.js";
import {
  decodeJws,
  publicKey,
  signingKey,
  assertionVector as V,
  vectorCapture,
  vectorIntake,
} from "./fixtures.js";

const KEY_HEADER_PARAMS = ["jku", "x5u", "jwk", "x5c"];

function signRequest(captureId: string, overrides: Partial<SignRequest> = {}): SignRequest {
  return {
    captureId,
    workflow: V.sign.workflow,
    audience: V.sign.audience,
    intent: V.sign.intent,
    presenter: V.capture.presenter,
    ...overrides,
  };
}

async function vectorAssertion(): Promise<string> {
  const intake = vectorIntake();
  const receipt = intake.capture(vectorCapture());
  const signed = await intake.sign(signRequest(receipt.captureId));
  return signed.entry.assertion;
}

/** An intake on the real clock and random source. */
function liveIntake() {
  return createRequestIntake({
    issuer: V.intake.iss,
    kid: V.key.kid,
    signingKey,
    assertionLifetimeSeconds: 300,
    maxCaptureAgeSeconds: 600,
  });
}

describe("the provenance assertion (@spec request-provenance#assertion, request-provenance#signing, #939)", () => {
  it("capture then sign reproduces the positive vector's protected header and claims", async () => {
    const intake = vectorIntake();
    const receipt = intake.capture(vectorCapture());
    expect(receipt).toEqual({
      captureId: V.capture.capture_id,
      workflow: V.capture.workflow,
      capturedAt: V.capture.captured_at,
      requestDigest: V.expected.claims.request_digest,
    });
    const signed = await intake.sign(signRequest(receipt.captureId));
    expect(signed.entry.type).toBe(REQUEST_PROVENANCE_TYPE);
    expect(Object.keys(signed.entry).sort()).toEqual(["assertion", "type"]);
    const { header, claims } = decodeJws(signed.entry.assertion);
    expect(header).toEqual(V.expected.protected_header);
    expect(claims).toEqual(V.expected.claims);
    expect(signed.jti).toBe(V.expected.claims.jti);
    expect(signed.intentHash).toBe(V.expected.claims.intent_hash);
  });

  it("the assertion verifies with jose under the public key, and so does the published sample", async () => {
    const currentDate = new Date((V.sign.iat + 60) * 1000);
    for (const jws of [await vectorAssertion(), V.expected.entry.assertion]) {
      const { payload, protectedHeader } = await jwtVerify(jws, publicKey, {
        algorithms: ["ES256"],
        typ: REQUEST_PROVENANCE_JWT_TYP,
        issuer: V.intake.iss,
        audience: V.sign.audience,
        currentDate,
      });
      expect(protectedHeader).toEqual(V.expected.protected_header);
      expect(payload).toEqual(V.expected.claims);
    }
    // The live intake's assertion verifies too, at the current time.
    const intake = liveIntake();
    const receipt = intake.capture(vectorCapture());
    const signed = await intake.sign(signRequest(receipt.captureId));
    await expect(compactVerify(signed.entry.assertion, publicKey)).resolves.toBeDefined();
  });

  it("the protected header is exactly typ, alg and kid: never jku, x5u, jwk or x5c", async () => {
    const intake = liveIntake();
    const receipt = intake.capture(vectorCapture());
    for (const audience of [V.sign.audience, "https://other-as.example.com"]) {
      const signed = await intake.sign(signRequest(receipt.captureId, { audience }));
      const header = decodeProtectedHeader(signed.entry.assertion);
      expect(header).toEqual({ typ: REQUEST_PROVENANCE_JWT_TYP, alg: "ES256", kid: V.key.kid });
      for (const param of KEY_HEADER_PARAMS) expect(header).not.toHaveProperty(param);
    }
  });

  it("aud is one string, and every required claim is present with its defined type", async () => {
    const intake = liveIntake();
    const receipt = intake.capture(vectorCapture());
    const signed = await intake.sign(signRequest(receipt.captureId));
    const { claims } = decodeJws(signed.entry.assertion);
    expect(typeof claims.aud).toBe("string");
    expect(claims.aud).toBe(V.sign.audience);
    for (const name of ["iss", "jti", "intent_hash", "request_digest", "capture_id"]) {
      expect(typeof claims[name], name).toBe("string");
    }
    for (const name of ["iat", "exp", "captured_at"]) {
      expect(Number.isSafeInteger(claims[name]), name).toBe(true);
    }
    expect(claims.exp).toBe((claims.iat as number) + 300);
    expect(claims.captured_at as number).toBeLessThanOrEqual(claims.iat as number);
    expect(claims.presenter).toEqual(V.capture.presenter);
    expect(claims.originator).toEqual(V.capture.originator);
    expect(claims.channel).toEqual(V.capture.channel);
    expect(claims.request_digest).toMatch(/^hmac-sha-256:[A-Za-z0-9_-]{43}$/);
    expect(claims.intent_hash).toMatch(/^sha-256:[A-Za-z0-9_-]{43}$/);
    expect(Object.keys(claims).sort()).toEqual([...ASSERTION_CLAIMS].sort());
  });
});
