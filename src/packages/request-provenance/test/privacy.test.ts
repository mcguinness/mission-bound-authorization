// @spec request-provenance#assertion, request-provenance#capture,
// request-provenance#privacy-considerations
//
// What an assertion holder without the capture secret can learn about the
// instruction. These tests check this implementation's outputs over the
// inputs they try; no number of passing cases is a proof of secrecy. The
// draft's privacy claim covers request_digest alone, and intent_hash is
// outside it.

import { createHash, createHmac } from "node:crypto";
import { intentHash } from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  ASSERTION_CLAIMS,
  type CaptureRequest,
  createRequestIntake,
  type JsonObject,
  RequestProvenanceError,
  requestDigest,
  requestDigestInput,
} from "../src/index.js";
import {
  decodeJws,
  recordingRandom,
  signingKey,
  assertionVector as V,
  vectorCapture,
  vectorIntake,
} from "./fixtures.js";

const MEDIA_TYPE = "text/plain;charset=utf-8";
const INSTRUCTION = "Pay Acme.";
const CANDIDATES = [
  "Yes",
  "No",
  "Pay Acme",
  "Pay Acme.",
  "Pay Acme!",
  "pay acme.",
  "Pay Globex.",
  "Cancel it.",
  "Approve all.",
];

function liveIntake(random?: (size: number) => Uint8Array) {
  return createRequestIntake({
    issuer: V.intake.iss,
    kid: V.key.kid,
    signingKey,
    assertionLifetimeSeconds: 300,
    maxCaptureAgeSeconds: 600,
    ...(random ? { randomBytes: random } : {}),
  });
}

function captureOf(instruction: string, mediaType = MEDIA_TYPE): CaptureRequest {
  return vectorCapture({ instruction: Buffer.from(instruction, "utf8"), mediaType });
}

/** Every secretless encoding of a value a holder might test a guess against. */
function secretlessForms(bytes: Buffer): string[] {
  const sha = createHash("sha256").update(bytes).digest();
  return [
    bytes.toString("utf8"),
    bytes.toString("hex"),
    bytes.toString("base64"),
    bytes.toString("base64url"),
    sha.toString("hex"),
    sha.toString("base64"),
    sha.toString("base64url"),
    `sha-256:${sha.toString("base64url")}`,
  ].filter((s) => s.length > 0);
}

/** Secretless commitments to a candidate instruction under a media type. */
function candidateProbes(candidate: string, mediaType: string): string[] {
  const bytes = Buffer.from(candidate, "utf8");
  const input = requestDigestInput(mediaType, bytes);
  const probes = [...secretlessForms(bytes), ...secretlessForms(input)];
  // Guessed or published secrets: none is this capture's.
  for (const guess of [
    Buffer.alloc(32),
    Buffer.from(V.capture.secret_hex, "hex"),
    Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1)),
  ]) {
    probes.push(requestDigest(guess, mediaType, bytes));
  }
  probes.push(
    `hmac-sha-256:${createHmac("sha256", Buffer.alloc(0)).update(input).digest("base64url")}`,
  );
  return probes;
}

/** Every string in a JSON value, member names included, numbers as text. */
function stringLeaves(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (typeof value === "number" || typeof value === "boolean") return [String(value)];
  if (Array.isArray(value)) return value.flatMap(stringLeaves);
  if (value !== null && typeof value === "object") {
    return Object.entries(value).flatMap(([k, v]) => [k, ...stringLeaves(v)]);
  }
  return [];
}

function claimsWithout(claims: Record<string, unknown>, ...names: string[]) {
  const out = { ...claims };
  for (const n of names) delete out[n];
  return out;
}

describe("the assertion commits to no request content (@spec request-provenance#assertion, request-provenance#privacy-considerations, #939)", () => {
  it("the claim set is exactly the defined claims, and no public artifact carries the secret, the instruction, the media type or an unsalted digest of either", async () => {
    const { draws, random } = recordingRandom();
    const intake = liveIntake(random);
    const receipt = intake.capture(captureOf(INSTRUCTION));
    const signed = await intake.sign({
      captureId: receipt.captureId,
      workflow: V.capture.workflow,
      audience: V.sign.audience,
      intent: V.sign.intent,
      presenter: V.sign.presenter,
    });
    const { header, claims } = decodeJws(signed.entry.assertion);
    expect(Object.keys(claims).sort()).toEqual([...ASSERTION_CLAIMS].sort());

    const secret = draws[0] as Buffer;
    expect(secret.length).toBe(32);
    let refusal = "";
    try {
      await intake.sign({
        captureId: receipt.captureId,
        workflow: "another-workflow",
        audience: V.sign.audience,
        intent: V.sign.intent,
        presenter: V.sign.presenter,
      });
    } catch (e) {
      expect(e).toBeInstanceOf(RequestProvenanceError);
      refusal = `${(e as Error).message} ${(e as RequestProvenanceError).code}`;
    }
    expect(refusal).not.toBe("");

    const artifacts = [
      JSON.stringify(receipt),
      JSON.stringify(signed),
      signed.entry.assertion,
      JSON.stringify(header),
      JSON.stringify(claims),
      JSON.stringify(intake),
      Object.keys(intake).join(","),
      refusal,
    ].join("\n");
    const forbidden = [
      ...secretlessForms(secret),
      ...secretlessForms(Buffer.from(INSTRUCTION, "utf8")),
      ...secretlessForms(requestDigestInput(MEDIA_TYPE, Buffer.from(INSTRUCTION, "utf8"))),
      ...secretlessForms(Buffer.from(MEDIA_TYPE, "ascii")),
    ];
    for (const f of forbidden) expect(artifacts.includes(f), f).toBe(false);
  });

  it("changing only the instruction or the media type changes only request_digest", async () => {
    const emit = async (capture: CaptureRequest) => {
      const intake = vectorIntake();
      const receipt = intake.capture(capture);
      const signed = await intake.sign({
        captureId: receipt.captureId,
        workflow: V.sign.workflow,
        audience: V.sign.audience,
        intent: V.sign.intent,
        presenter: V.sign.presenter,
      });
      return { receipt, ...decodeJws(signed.entry.assertion) };
    };
    const base = await emit(vectorCapture());
    for (const variant of [
      captureOf("Pay Acme."),
      captureOf(V.capture.instruction_utf8, "text/markdown;charset=utf-8"),
    ]) {
      const other = await emit(variant);
      expect(other.header).toEqual(base.header);
      expect(other.claims.request_digest).not.toBe(base.claims.request_digest);
      expect(claimsWithout(other.claims, "request_digest")).toEqual(
        claimsWithout(base.claims, "request_digest"),
      );
      expect({ ...other.receipt, requestDigest: "" }).toEqual({
        ...base.receipt,
        requestDigest: "",
      });
    }
  });

  it("changing only the candidate Intent changes only intent_hash", async () => {
    const emit = async (intent: JsonObject) => {
      const intake = vectorIntake();
      const receipt = intake.capture(vectorCapture());
      const signed = await intake.sign({
        captureId: receipt.captureId,
        workflow: V.sign.workflow,
        audience: V.sign.audience,
        intent,
        presenter: V.sign.presenter,
      });
      return decodeJws(signed.entry.assertion);
    };
    const base = await emit(V.sign.intent);
    const other = await emit({ ...V.sign.intent, goal: "Pay every open Acme invoice." });
    expect(other.header).toEqual(base.header);
    expect(other.claims.intent_hash).not.toBe(base.claims.intent_hash);
    expect(claimsWithout(other.claims, "intent_hash")).toEqual(
      claimsWithout(base.claims, "intent_hash"),
    );
  });
});

describe("a dictionary probe over a low-entropy instruction (@spec request-provenance#privacy-considerations, #939)", () => {
  it("without the secret no member other than intent_hash confirms a candidate; with the secret request_digest does", async () => {
    const { draws, random } = recordingRandom();
    const intake = liveIntake(random);
    const receipt = intake.capture(captureOf(INSTRUCTION));
    const signed = await intake.sign({
      captureId: receipt.captureId,
      workflow: V.capture.workflow,
      audience: V.sign.audience,
      intent: V.sign.intent,
      presenter: V.sign.presenter,
    });
    const { claims } = decodeJws(signed.entry.assertion);
    const members = Object.entries(claimsWithout(claims, "intent_hash"));
    expect(CANDIDATES).toContain(INSTRUCTION);

    // Without the secret: no secretless commitment to any candidate, the true
    // one included, appears in any member. A probe shorter than 8 characters
    // (a bare word) is matched only as a whole value, since a random
    // identifier can contain two letters by chance.
    for (const candidate of CANDIDATES) {
      for (const probe of candidateProbes(candidate, MEDIA_TYPE)) {
        for (const [name, value] of members) {
          const hit = stringLeaves(value).some((leaf) =>
            probe.length >= 8 ? leaf.includes(probe) : leaf === probe,
          );
          expect(hit, `${candidate} via ${name}`).toBe(false);
        }
      }
    }

    // With the secret (an intake or an authorized audit holds it): exactly
    // the true instruction reproduces request_digest.
    const secret = draws[0] as Buffer;
    const confirmed = CANDIDATES.filter(
      (c) => requestDigest(secret, MEDIA_TYPE, Buffer.from(c, "utf8")) === claims.request_digest,
    );
    expect(confirmed).toEqual([INSTRUCTION]);
  });

  it("intent_hash confirms a candidate when the Intent copies the wording, as the draft states", async () => {
    const intake = liveIntake();
    const receipt = intake.capture(captureOf(INSTRUCTION));
    const predictable = {
      target_resources: ["https://erp.example.com"],
      expires_at: "2026-10-10T23:59:59Z",
    };
    const signed = await intake.sign({
      captureId: receipt.captureId,
      workflow: V.capture.workflow,
      audience: V.sign.audience,
      intent: { goal: INSTRUCTION, ...predictable },
      presenter: V.sign.presenter,
    });
    const { claims } = decodeJws(signed.entry.assertion);
    const confirmed = CANDIDATES.filter(
      (c) => intentHash(claims.aud as string, { goal: c, ...predictable }) === claims.intent_hash,
    );
    // The documented limitation: the request digest does not protect wording
    // shaping copies into the Intent.
    expect(confirmed).toEqual([INSTRUCTION]);
  });
});

describe("capture_id (@spec request-provenance#assertion, #939)", () => {
  it("two captures of the same instruction and media type yield distinct capture_id values of at least 128 bits", async () => {
    const ids: string[] = [];
    for (const intake of [liveIntake(), liveIntake()]) {
      for (let i = 0; i < 2; i += 1) {
        const receipt = intake.capture(captureOf(INSTRUCTION));
        const signed = await intake.sign({
          captureId: receipt.captureId,
          workflow: V.capture.workflow,
          audience: V.sign.audience,
          intent: V.sign.intent,
          presenter: V.sign.presenter,
        });
        expect(decodeJws(signed.entry.assertion).claims.capture_id).toBe(receipt.captureId);
        ids.push(receipt.captureId);
      }
    }
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of ids) {
      expect(id).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(Buffer.from(id, "base64url").length).toBeGreaterThanOrEqual(16);
    }
    const content = [
      ...secretlessForms(Buffer.from(INSTRUCTION, "utf8")),
      ...secretlessForms(requestDigestInput(MEDIA_TYPE, Buffer.from(INSTRUCTION, "utf8"))),
    ];
    for (const id of ids) {
      for (const form of content) expect(form.includes(id)).toBe(false);
    }
  });
});
