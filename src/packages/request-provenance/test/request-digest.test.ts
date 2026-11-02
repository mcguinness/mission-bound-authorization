// @spec request-provenance#request-digest, request-provenance#vectors
//
// The library's digest against vectors/mission-request-provenance/
// request-digest.json, and an independent computation written here from the
// draft's encoding. Two HMAC computations agreeing supports the vectors'
// correctness only; it is not an interoperability or secrecy claim (D1119 Q6).

import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { RequestProvenanceError, requestDigest, requestDigestInput } from "../src/index.js";
import { assertionVector, digestVectors, vectorCapture, vectorIntake } from "./fixtures.js";

/** The draft's encoding, written out without the library. */
function independentDigest(secretHex: string, mediaType: string, instructionHex: string): string {
  const label = Buffer.from("mission-request-provenance/v1", "ascii");
  const mt = Buffer.from(mediaType, "ascii");
  const instruction = Buffer.from(instructionHex, "hex");
  const mtLen = Buffer.alloc(4);
  mtLen.writeUInt32BE(mt.length, 0);
  const insLen = Buffer.alloc(8);
  insLen.writeUInt32BE(Math.floor(instruction.length / 2 ** 32), 0);
  insLen.writeUInt32BE(instruction.length % 2 ** 32, 4);
  const input = Buffer.concat([label, Buffer.alloc(1), mtLen, mt, insLen, instruction]);
  const mac = createHmac("sha256", Buffer.from(secretHex, "hex")).update(input).digest();
  return `hmac-sha-256:${mac.toString("base64url")}`;
}

const PUBLISHED = {
  "rd-01": "hmac-sha-256:-xVlEjxrMKqRGHbUOS2YvZhW7uN-RpRrfV-BsTIUDu0",
  "rd-02": "hmac-sha-256:DXLpPDrfm1W53Z-nniGK1j2NdqvUjPCL-ha82mt5pms",
  "rd-03": "hmac-sha-256:VTGuqTNNdu6Q780TwU9cVUVlMbJlzDa_M-iWMteLoi8",
  "rd-04": "hmac-sha-256:NGW2Oglh0SHnmQJaPUBHXG0LTjHwBoY67TokgLxS_g8",
} as const;

describe("request digest construction (@spec request-provenance#request-digest, #939)", () => {
  it("reproduces every published and low-entropy vector, HMAC input included", () => {
    // The draft appendix's four values, as the draft prints them.
    for (const [id, value] of Object.entries(PUBLISHED)) {
      expect(digestVectors.find((c) => c.id === id)?.request_digest).toBe(value);
    }
    expect(digestVectors.length).toBeGreaterThanOrEqual(8);
    for (const c of digestVectors) {
      const instruction = Buffer.from(c.instruction_hex, "hex");
      expect(instruction.toString("utf8"), c.id).toBe(c.instruction_utf8);
      expect(requestDigestInput(c.media_type, instruction).toString("hex"), c.id).toBe(
        c.hmac_input_hex,
      );
      expect(requestDigest(Buffer.from(c.secret_hex, "hex"), c.media_type, instruction), c.id).toBe(
        c.request_digest,
      );
    }
    // The appendix prints rd-01's 96-byte HMAC input.
    const rd01 = digestVectors.find((c) => c.id === "rd-01");
    expect(Buffer.from(rd01?.hmac_input_hex ?? "", "hex").length).toBe(96);
  });

  it("an independent HMAC computation from the encoding agrees on every vector", () => {
    for (const c of digestVectors) {
      expect(independentDigest(c.secret_hex, c.media_type, c.instruction_hex), c.id).toBe(
        c.request_digest,
      );
    }
  });

  it("changing the instruction, the media type or the secret changes the digest", () => {
    const secret = Buffer.from(assertionVector.capture.secret_hex, "hex");
    const mediaType = "text/plain;charset=utf-8";
    const instruction = Buffer.from("Pay Acme.", "utf8");
    const base = requestDigest(secret, mediaType, instruction);

    const otherInstruction = Buffer.from("Pay Acme!", "utf8");
    expect(requestDigest(secret, mediaType, otherInstruction)).not.toBe(base);
    expect(requestDigest(secret, "text/plain;charset=UTF-8", instruction)).not.toBe(base);
    const otherSecret = Buffer.from(secret);
    otherSecret[31] = (otherSecret[31] as number) ^ 0x01;
    expect(requestDigest(otherSecret, mediaType, instruction)).not.toBe(base);

    // Moving a byte across the media type / instruction boundary changes it too:
    // the lengths are part of the input.
    const a = requestDigest(secret, "text/plain", Buffer.from("xPay", "utf8"));
    const b = requestDigest(secret, "text/plainx", Buffer.from("Pay", "utf8"));
    expect(a).not.toBe(b);
  });

  it("the intake's captured request_digest is the published value under the vector secret", async () => {
    const intake = vectorIntake();
    const receipt = intake.capture(vectorCapture());
    expect(receipt.requestDigest).toBe(PUBLISHED["rd-01"]);
    const signed = await intake.sign({
      captureId: receipt.captureId,
      workflow: assertionVector.sign.workflow,
      audience: assertionVector.sign.audience,
      intent: assertionVector.sign.intent,
      presenter: assertionVector.sign.presenter,
    });
    const payload = JSON.parse(
      Buffer.from(signed.entry.assertion.split(".")[1] as string, "base64url").toString("utf8"),
    );
    expect(payload.request_digest).toBe(PUBLISHED["rd-01"]);
  });

  it("refuses a media type outside printable US-ASCII and a secret that is not 32 bytes", () => {
    const secret = Buffer.alloc(32, 7);
    const instruction = Buffer.from("Yes", "utf8");
    for (const mediaType of ["", "text/plain;charset=utf-8\n", "text/plaín"]) {
      expect(() => requestDigest(secret, mediaType, instruction)).toThrow(RequestProvenanceError);
    }
    expect(() => requestDigest(Buffer.alloc(31), "text/plain", instruction)).toThrow(
      RequestProvenanceError,
    );
    expect(() => requestDigest(Buffer.alloc(33), "text/plain", instruction)).toThrow(
      RequestProvenanceError,
    );
  });
});
