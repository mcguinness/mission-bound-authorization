// Loads vectors/mission-request-provenance and builds intakes over them.

import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { importJWK, type JWK } from "jose";
import {
  type CaptureRequest,
  createRequestIntake,
  type JsonObject,
  type Presenter,
  type RequestIntake,
  type RequestIntakeConfig,
} from "../src/index.js";

const here = dirname(fileURLToPath(import.meta.url));
export const vectorsDir = resolve(here, "../../../../vectors/mission-request-provenance");

function readJson<T>(name: string): T {
  return JSON.parse(readFileSync(join(vectorsDir, name), "utf8")) as T;
}

export interface DigestCase {
  id: string;
  source: string;
  description: string;
  secret_hex: string;
  media_type: string;
  instruction_utf8: string;
  instruction_hex: string;
  hmac_input_hex: string;
  request_digest: string;
}

export interface AssertionVector {
  key: { kid: string; public_jwk: JWK; private_jwk_test_only: JWK };
  intake: {
    iss: string;
    assertion_lifetime_seconds: number;
    max_capture_age_seconds: number;
    emit_capture_id: boolean;
  };
  capture: {
    workflow: string;
    media_type: string;
    instruction_utf8: string;
    originator: { iss: string; sub: string };
    channel: { type: string; acr?: string; amr?: string[]; auth_time?: number };
    captured_at: number;
    secret_hex: string;
    capture_id: string;
    presenter: Presenter;
  };
  sign: {
    workflow: string;
    audience: string;
    intent: JsonObject;
    iat: number;
    jti: string;
  };
  expected: {
    protected_header: Record<string, unknown>;
    claims: Record<string, unknown>;
    entry: { type: string; assertion: string };
    recorded_facts: Record<string, unknown>;
  };
}

export interface AssertionCase {
  id: string;
  description: string;
  step: number | null;
  construction: Record<string, unknown>;
  token: string;
  expected: { outcome: "refuse" | "accept"; error?: string };
  producer: { status: "checked"; test: string } | { status: "not-applicable"; reason: string };
  verifier: { status: string };
}

export const digestVectors = readJson<{ cases: DigestCase[] }>("request-digest.json").cases;
export const assertionVector = readJson<AssertionVector>("assertion.json");
export const assertionCases = readJson<{ cases: AssertionCase[] }>("assertion-cases.json").cases;

export const signingKey = await importJWK(assertionVector.key.private_jwk_test_only, "ES256");
export const publicKey = await importJWK(assertionVector.key.public_jwk, "ES256");

const V = assertionVector;

/** The positive vector's capture request. */
export function vectorCapture(overrides: Partial<CaptureRequest> = {}): CaptureRequest {
  return {
    workflow: V.capture.workflow,
    instruction: Buffer.from(V.capture.instruction_utf8, "utf8"),
    mediaType: V.capture.media_type,
    originator: V.capture.originator,
    channel: V.capture.channel,
    presenter: V.capture.presenter,
    ...overrides,
  };
}

/**
 * A random source that returns the vector's fixed values, in the library's
 * draw order; `secretHex` replaces the capture secret.
 */
export function vectorRandom(secretHex = V.capture.secret_hex): (size: number) => Uint8Array {
  const draws = [
    Buffer.from(secretHex, "hex"),
    Buffer.from(V.capture.capture_id, "base64url"),
    Buffer.from(V.sign.jti, "base64url"),
  ];
  return (size) => {
    const next = draws.shift();
    if (next === undefined || next.length !== size) {
      throw new Error(`unexpected draw of ${size} bytes`);
    }
    return next;
  };
}

/** A clock that reads captured_at for the capture, then iat for the signature. */
export function vectorClock(): () => number {
  const reads = [V.capture.captured_at, V.sign.iat];
  return () => {
    const next = reads.length > 1 ? reads.shift() : reads[0];
    return (next as number) * 1000;
  };
}

/** An intake configured as the positive vector's producer. */
export function vectorIntake(overrides: Partial<RequestIntakeConfig> = {}): RequestIntake {
  return createRequestIntake({
    issuer: V.intake.iss,
    kid: V.key.kid,
    signingKey,
    assertionLifetimeSeconds: V.intake.assertion_lifetime_seconds,
    maxCaptureAgeSeconds: V.intake.max_capture_age_seconds,
    emitCaptureId: V.intake.emit_capture_id,
    now: vectorClock(),
    randomBytes: vectorRandom(),
    ...overrides,
  });
}

/** A random source over node:crypto that records every draw, so a test can hold the secret. */
export function recordingRandom(): { draws: Buffer[]; random: (size: number) => Uint8Array } {
  const draws: Buffer[] = [];
  return {
    draws,
    random: (size) => {
      const b = randomBytes(size);
      draws.push(Buffer.from(b));
      return b;
    },
  };
}

/** Decode a compact JWS's protected header and payload without verifying it. */
export function decodeJws(jws: string): {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
} {
  const [h, p] = jws.split(".");
  return {
    header: JSON.parse(Buffer.from(h as string, "base64url").toString("utf8")),
    claims: JSON.parse(Buffer.from(p as string, "base64url").toString("utf8")),
  };
}
