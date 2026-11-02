// @spec request-provenance#signing, request-provenance#capture
//
// The intake signs only from its own retained capture of the same workflow,
// computes intent_hash itself, and mints a fresh jti on every call. These are
// unit tests of the library: the inputs a test supplies stand in for the
// facts a deployment's isolated intake would establish, so they witness the
// library's guards, not intake isolation or authenticated origin (D1119 Q6).

import { createHash, generateKeyPairSync } from "node:crypto";
import { intentHash } from "@mission/core";
import { describe, expect, it } from "vitest";
import {
  createRequestIntake,
  type JsonObject,
  type RequestIntakeConfig,
  RequestProvenanceError,
  type SignRequest,
} from "../src/index.js";
import { decodeJws, signingKey, assertionVector as V, vectorCapture } from "./fixtures.js";

const MAX_AGE = 600;

/** A clock the test moves, in seconds. */
function testClock(start: number) {
  let t = start;
  return {
    now: () => t * 1000,
    set: (s: number) => {
      t = s;
    },
  };
}

function intake(overrides: Partial<RequestIntakeConfig> = {}) {
  return createRequestIntake({
    issuer: V.intake.iss,
    kid: V.key.kid,
    signingKey,
    assertionLifetimeSeconds: 300,
    maxCaptureAgeSeconds: MAX_AGE,
    ...overrides,
  });
}

function signRequest(captureId: string, overrides: Partial<SignRequest> = {}): SignRequest {
  return {
    captureId,
    workflow: V.capture.workflow,
    audience: V.sign.audience,
    intent: V.sign.intent,
    presenter: V.capture.presenter,
    ...overrides,
  };
}

async function refusal(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(RequestProvenanceError);
    return (e as RequestProvenanceError).code;
  }
  return "signed";
}

/** JCS (objects of strings, arrays and integers) and the integrity anchor, written out here. */
function jcs(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const o = v as Record<string, unknown>;
    return `{${Object.keys(o)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${jcs(o[k])}`)
      .join(",")}}`;
  }
  return JSON.stringify(v);
}
function independentIntentHash(iss: string, intent: JsonObject): string {
  const bytes = Buffer.from(jcs({ typ: "mission-intent", iss, value: intent }), "utf8");
  return `sha-256:${createHash("sha256").update(bytes).digest("base64url")}`;
}

describe("signing only from the intake's own capture (@spec request-provenance#signing, #939)", () => {
  it("refuses an unknown capture and yields no assertion", async () => {
    const a = intake();
    const b = intake();
    // The intake holds a capture of its own for this workflow, so a refusal
    // below is about the named capture, not an empty store.
    const own = a.capture(vectorCapture());
    // A capture identifier no capture produced.
    expect(await refusal(a.sign(signRequest("AAAAAAAAAAAAAAAAAAAAAA")))).toBe("unknown_capture");
    // A real capture, made by another intake: a request this intake did not capture.
    const elsewhere = b.capture(vectorCapture());
    expect(await refusal(a.sign(signRequest(elsewhere.captureId)))).toBe("unknown_capture");
    // The capturing intake signs it, and this intake signs its own.
    expect(await refusal(b.sign(signRequest(elsewhere.captureId)))).toBe("signed");
    expect(await refusal(a.sign(signRequest(own.captureId)))).toBe("signed");
  });

  it("refuses another workflow's capture and yields no assertion", async () => {
    const a = intake();
    const mine = a.capture(vectorCapture({ workflow: "wf-a" }));
    const theirs = a.capture(vectorCapture({ workflow: "wf-b" }));
    expect(await refusal(a.sign(signRequest(theirs.captureId, { workflow: "wf-a" })))).toBe(
      "workflow_mismatch",
    );
    expect(await refusal(a.sign(signRequest(mine.captureId, { workflow: "wf-b" })))).toBe(
      "workflow_mismatch",
    );
    // Each workflow signs its own capture.
    expect(await refusal(a.sign(signRequest(mine.captureId, { workflow: "wf-a" })))).toBe("signed");
    expect(await refusal(a.sign(signRequest(theirs.captureId, { workflow: "wf-b" })))).toBe(
      "signed",
    );
  });

  it("refuses a capture past the maximum capture age, and signs at the bound", async () => {
    const clock = testClock(V.capture.captured_at);
    const a = intake({ now: clock.now });
    const receipt = a.capture(vectorCapture());
    clock.set(V.capture.captured_at + MAX_AGE);
    const signed = await a.sign(signRequest(receipt.captureId));
    const { claims } = decodeJws(signed.entry.assertion);
    expect((claims.iat as number) - (claims.captured_at as number)).toBe(MAX_AGE);
    clock.set(V.capture.captured_at + MAX_AGE + 1);
    expect(await refusal(a.sign(signRequest(receipt.captureId)))).toBe("capture_too_old");
    // A new capture of the same request signs again.
    const fresh = a.capture(vectorCapture());
    expect(await refusal(a.sign(signRequest(fresh.captureId)))).toBe("signed");
  });

  it("refuses to sign while the clock reads earlier than captured_at", async () => {
    const clock = testClock(V.capture.captured_at);
    const a = intake({ now: clock.now });
    const receipt = a.capture(vectorCapture());
    clock.set(V.capture.captured_at - 1);
    expect(await refusal(a.sign(signRequest(receipt.captureId)))).toBe("clock_regressed");
    clock.set(V.capture.captured_at);
    const { claims } = decodeJws((await a.sign(signRequest(receipt.captureId))).entry.assertion);
    expect(claims.captured_at).toBe(claims.iat);
  });
});

describe("the intake computes intent_hash itself (@spec request-provenance#signing, #939)", () => {
  it("the emitted intent_hash is the integrity anchor over the candidate Intent for the AS aud names", async () => {
    const a = intake();
    const receipt = a.capture(vectorCapture());
    const here = await a.sign(signRequest(receipt.captureId));
    const hereClaims = decodeJws(here.entry.assertion).claims;
    // The vector's value, computed by the generator without this library.
    expect(hereClaims.intent_hash).toBe(V.expected.claims.intent_hash);
    expect(hereClaims.intent_hash).toBe(independentIntentHash(V.sign.audience, V.sign.intent));

    const otherAs = "https://other-as.example.com";
    const there = await a.sign(signRequest(receipt.captureId, { audience: otherAs }));
    const thereClaims = decodeJws(there.entry.assertion).claims;
    expect(thereClaims.aud).toBe(otherAs);
    expect(thereClaims.intent_hash).toBe(independentIntentHash(otherAs, V.sign.intent));
    expect(thereClaims.intent_hash).not.toBe(hereClaims.intent_hash);
  });

  it("refuses a sign request carrying an intent_hash, a digest, an originator or channel facts", async () => {
    const a = intake();
    const receipt = a.capture(vectorCapture());
    const injected: Record<string, unknown> = {
      intent_hash: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      intentHash: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      request_digest: "hmac-sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      requestDigest: "hmac-sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      originator: { iss: "https://idp.example.com", sub: "someone-else" },
      channel: { type: "https://shaper.example.com/ch/claimed" },
      captured_at: V.capture.captured_at - 3600,
      claims: { originator: { iss: "https://idp.example.com", sub: "someone-else" } },
      // Shaping Evidence, or a hash committing to it, has no way in either.
      shaping_evidence: { input_digest: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
      shaping_hash: "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    };
    for (const [member, value] of Object.entries(injected)) {
      const request = { ...signRequest(receipt.captureId), [member]: value } as SignRequest;
      expect(await refusal(a.sign(request)), member).toBe("invalid_sign_request");
    }
    const presenterExtra = {
      ...signRequest(receipt.captureId),
      presenter: { ...V.capture.presenter, originator: injected.originator },
    } as SignRequest;
    expect(await refusal(a.sign(presenterExtra))).toBe("invalid_sign_request");

    // A clean request carries the capture's facts, whatever was offered before.
    const { claims } = decodeJws((await a.sign(signRequest(receipt.captureId))).entry.assertion);
    expect(claims.originator).toEqual(V.capture.originator);
    expect(claims.channel).toEqual(V.capture.channel);
    expect(claims.request_digest).toBe(receipt.requestDigest);
    expect(claims.captured_at).toBe(receipt.capturedAt);
  });
});

describe("a fresh assertion per Intent (@spec request-provenance#signing, #939)", () => {
  it("every call mints a fresh jti, and a changed Intent gets its new intent_hash", async () => {
    const a = intake();
    const first = a.capture(vectorCapture());
    const second = a.capture(vectorCapture());
    const revised: JsonObject = { ...V.sign.intent, goal: "Pay the Acme invoices due by Friday." };
    const issued = [];
    for (const [captureId, intent] of [
      [first.captureId, V.sign.intent],
      [first.captureId, V.sign.intent],
      [first.captureId, revised],
      [first.captureId, revised],
      [second.captureId, V.sign.intent],
    ] as const) {
      const signed = await a.sign(signRequest(captureId, { intent }));
      const { claims } = decodeJws(signed.entry.assertion);
      expect(claims.jti).toBe(signed.jti);
      expect(Buffer.from(signed.jti, "base64url").length).toBeGreaterThanOrEqual(16);
      expect(claims.intent_hash).toBe(independentIntentHash(V.sign.audience, intent));
      issued.push(claims);
    }
    const jtis = issued.map((c) => c.jti);
    expect(new Set(jtis).size).toBe(jtis.length);
    expect(issued[2]?.intent_hash).not.toBe(issued[0]?.intent_hash);
    // The capture's request digest is reused for the same capture.
    expect(issued[2]?.request_digest).toBe(issued[0]?.request_digest);
  });

  it("refuses to issue a jti the intake has issued before, even from a repeating random source", async () => {
    const fixed = Buffer.alloc(32, 0x5a);
    const repeating = (size: number) => fixed.subarray(0, size);
    const clock = testClock(V.capture.captured_at);
    const a = intake({ randomBytes: repeating, now: clock.now });
    const receipt = a.capture(vectorCapture());
    expect(await refusal(a.sign(signRequest(receipt.captureId)))).toBe("signed");
    expect(await refusal(a.sign(signRequest(receipt.captureId)))).toBe("random_source_failure");
    expect(() => a.capture(vectorCapture())).toThrow(RequestProvenanceError);
  });
});

describe("intake configuration and capture input (@spec request-provenance#capture, request-provenance#assertion, #939)", () => {
  it("refuses a signing key other than a P-256 private key, and unbounded lifetimes", () => {
    const ed = generateKeyPairSync("ed25519").privateKey;
    const p384 = generateKeyPairSync("ec", { namedCurve: "secp384r1" }).privateKey;
    const p256pub = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey;
    for (const signingKey of [ed, p384, p256pub]) {
      expect(() => intake({ signingKey })).toThrow(RequestProvenanceError);
    }
    for (const bad of [0, -1, 1.5, Number.POSITIVE_INFINITY, Number.NaN]) {
      expect(() => intake({ assertionLifetimeSeconds: bad })).toThrow(RequestProvenanceError);
      expect(() => intake({ maxCaptureAgeSeconds: bad })).toThrow(RequestProvenanceError);
    }
  });

  it("refuses malformed capture input and a random source that returns too few bytes", () => {
    const a = intake();
    const bad: Record<string, unknown>[] = [
      { ...vectorCapture(), instruction: "Pay Acme." },
      { ...vectorCapture(), workflow: "" },
      { ...vectorCapture(), mediaType: "text/plaín" },
      { ...vectorCapture(), originator: { iss: "https://idp.example.com" } },
      { ...vectorCapture(), originator: { ...V.capture.originator, name: "Pat" } },
      { ...vectorCapture(), channel: { acr: "phr" } },
      { ...vectorCapture(), channel: { ...V.capture.channel, note: "Pay Acme." } },
      { ...vectorCapture(), channel: { ...V.capture.channel, amr: "pwd" } },
      { ...vectorCapture(), channel: { ...V.capture.channel, auth_time: "1791016100" } },
      { ...vectorCapture(), intent_hash: "sha-256:x" },
    ];
    for (const request of bad) {
      expect(() => a.capture(request as never), JSON.stringify(request)).toThrow(
        RequestProvenanceError,
      );
    }
    const short = intake({ randomBytes: (size) => Buffer.alloc(size - 1) });
    expect(() => short.capture(vectorCapture())).toThrow(RequestProvenanceError);
  });
});

/** The refusal code a synchronous call throws. */
function syncRefusal(f: () => unknown): string {
  try {
    f();
  } catch (e) {
    expect(e).toBeInstanceOf(RequestProvenanceError);
    return (e as RequestProvenanceError).code;
  }
  throw new Error("no refusal");
}

/**
 * @spec request-provenance#assertion, request-provenance#signing (#1971 review):
 * the presenter is the workflow's authenticated presenter, captured and
 * retained with the request; signing emits that presenter, and a presenter in
 * a signing request is only a cross-reference to it.
 */
describe("the presenter is bound at capture (@spec request-provenance#assertion, request-provenance#signing, #939)", () => {
  const captured = V.capture.presenter;

  it("emits the captured presenter whether or not the signing request names it", async () => {
    const a = intake();
    const { captureId } = a.capture(vectorCapture());
    const unnamed = await a.sign(signRequest(captureId, { presenter: undefined }));
    const named = await a.sign(signRequest(captureId));
    for (const signed of [unnamed, named])
      expect(decodeJws(signed.entry.assertion).claims.presenter).toEqual(captured);
  });

  it.each([
    ["a changed client", { ...captured, client_id: "other-agent" }],
    [
      "a changed confirmation key",
      { ...captured, cnf: { jkt: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" } },
    ],
    ["the confirmation binding removed", { client_id: captured.client_id }],
  ])(
    "refuses a signing request naming %s, after the same capture and workflow signed for the captured presenter",
    async (_case, presenter) => {
      const a = intake();
      const { captureId } = a.capture(vectorCapture());
      await a.sign(signRequest(captureId));
      expect(await refusal(a.sign(signRequest(captureId, { presenter })))).toBe(
        "presenter_mismatch",
      );
    },
  );

  it.each([
    ["an undefined thumbprint", { client_id: "ap-agent", cnf: { jkt: undefined } }],
    [
      "an undefined thumbprint beside a valid one",
      {
        client_id: "ap-agent",
        cnf: { jkt: undefined, "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" },
      },
    ],
    ["an empty confirmation object", { client_id: "ap-agent", cnf: {} }],
    ["an empty thumbprint", { client_id: "ap-agent", cnf: { jkt: "" } }],
    ["a confirmation that is not an object", { client_id: "ap-agent", cnf: "jkt" }],
  ])(
    "refuses at capture a presenter with %s, where the vector's presenter is accepted",
    (_case, presenter) => {
      const a = intake();
      expect(() => a.capture(vectorCapture())).not.toThrow();
      expect(syncRefusal(() => a.capture(vectorCapture({ presenter: presenter as never })))).toBe(
        "invalid_capture",
      );
    },
  );
});

/**
 * @spec request-provenance#signing (#1971 review): the candidate Intent is
 * validated before it is copied, and an accepted Intent is preserved exactly,
 * so `intent_hash` is computed over the Intent as given.
 */
describe("the Intent is validated before it is copied, and preserved exactly (@spec request-provenance#signing, #939)", () => {
  const sparse: unknown[] = [];
  sparse[1] = "https://erp.example.com";

  it.each([
    ["a non-finite number", { ...V.sign.intent, amount: JSON.parse("1e400") }],
    ["NaN", { ...V.sign.intent, amount: Number.NaN }],
    ["an undefined member", { ...V.sign.intent, note: undefined }],
    ["a Date", { ...V.sign.intent, not_before: new Date(0) }],
    ["a sparse array", { ...V.sign.intent, target_resources: sparse }],
  ])("refuses an Intent carrying %s and signs nothing", async (_case, intent) => {
    const a = intake();
    const { captureId } = a.capture(vectorCapture());
    expect(await refusal(a.sign(signRequest(captureId, { intent: intent as never })))).toBe(
      "invalid_sign_request",
    );
  });

  it("signs an exact-JSON Intent, nested values and a member named __proto__ included, over which intent_hash is unchanged", async () => {
    const intent = JSON.parse(
      '{"goal":"Pay the open Acme invoices.","limits":{"amount":"125.00","count":3,"ratio":0.5,"flags":[true,false,null]},"__proto__":{"x":1}}',
    ) as JsonObject;
    const a = intake();
    const { captureId } = a.capture(vectorCapture());
    const signed = await a.sign(signRequest(captureId, { intent }));
    expect(signed.intentHash).toBe(intentHash(V.sign.audience, intent));
    expect(decodeJws(signed.entry.assertion).claims.intent_hash).toBe(
      intentHash(V.sign.audience, intent),
    );
  });
});
