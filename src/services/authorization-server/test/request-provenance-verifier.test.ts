/**
 * @spec request-provenance#verification, request-provenance#trust-configuration,
 * request-provenance#entry, request-provenance#recorded-facts (#939 slice 2a-1)
 *
 * The AS verifier module for the `mission-request-provenance` evidence type,
 * unit level: every case of vectors/mission-request-provenance/assertion-cases.json
 * (each under its patched verifier context, whose trust configuration is
 * loaded through `@mission/demo-data`'s loader), the positive vector's exact
 * recorded facts, the strictness the draft implies, and assertions minted
 * live by `@mission/request-provenance`. The module does not reserve, so no
 * replay behavior is tested here, and no AS endpoint is: the PAR witness
 * lands with the wiring.
 */

import { createPrivateKey, sign as cryptoSign, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseRequestProvenanceConfig } from "@mission/demo-data";
import { createRequestIntake, type JsonObject, type Presenter } from "@mission/request-provenance";
import { CompactSign, calculateJwkThumbprint, exportJWK, generateKeyPair, importJWK, type JWK } from "jose";
import { describe, expect, it } from "vitest";
import { provisionalIntentHash } from "../src/kernel/intent.js";
import {
  type RequestProvenanceResult,
  type RequestProvenanceVerificationContext,
  verifyRequestProvenance,
} from "../src/kernel/request-provenance.js";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonRecord = { [key: string]: Json };

const VECTORS = resolve(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../vectors/mission-request-provenance",
);
const readVector = <T>(name: string): T =>
  JSON.parse(readFileSync(resolve(VECTORS, name), "utf8")) as T;

interface VerifierContextVector {
  issuer: string;
  now: number;
  clock_skew_seconds: number;
  max_assertion_lifetime_seconds: number;
  max_capture_age_seconds: number;
  trust: { signers: Json[] };
  intent: JsonRecord;
  presenter: { client_id: string; cnf?: { jkt: string } };
}

interface AssertionCase {
  id: string;
  step: number | null;
  construction: { verifier_context_patch?: JsonRecord };
  token: string;
  expected: { outcome: "refuse" | "accept"; error?: string; recorded_facts?: JsonRecord };
}

const V = readVector<{
  key: { kid: string; public_jwk: JWK; private_jwk_test_only: JWK };
  capture: { instruction_utf8: string; secret_hex: string; media_type: string };
  expected: {
    protected_header: JsonRecord;
    claims: JsonRecord;
    entry: { type: string; assertion: string };
    recorded_facts: JsonRecord;
  };
  verifier_context: VerifierContextVector;
}>("assertion.json");
const CASES = readVector<{ cases: AssertionCase[] }>("assertion-cases.json").cases;

const TYPE = "mission-request-provenance";
const entry = (assertion: unknown): Record<string, unknown> => ({ type: TYPE, assertion });

/** RFC 7386 JSON Merge Patch: null deletes, objects merge, anything else replaces. */
function mergePatch(target: Json, patch: Json): Json {
  if (patch === null || typeof patch !== "object" || Array.isArray(patch)) return patch;
  const out: JsonRecord =
    target !== null && typeof target === "object" && !Array.isArray(target) ? { ...target } : {};
  for (const [key, value] of Object.entries(patch)) {
    if (value === null) delete out[key];
    else out[key] = mergePatch(out[key] ?? null, value);
  }
  return out;
}

/**
 * The vector's verifier context after a merge patch, as this AS's context.
 * Its trust configuration goes through the same loader the shipped file does.
 */
function contextFor(patch: JsonRecord = {}): RequestProvenanceVerificationContext {
  const vc = mergePatch(structuredClone(V.verifier_context) as unknown as Json, patch) as unknown as VerifierContextVector;
  const trust = parseRequestProvenanceConfig({
    enabled: true,
    clock_skew_seconds: vc.clock_skew_seconds,
    max_assertion_lifetime_seconds: vc.max_assertion_lifetime_seconds,
    max_capture_age_seconds: vc.max_capture_age_seconds,
    signers: vc.trust.signers,
  });
  return {
    issuer: vc.issuer,
    now: new Date(vc.now * 1000),
    trust,
    intentHash: provisionalIntentHash(vc.issuer, vc.intent as never),
    presenter: {
      clientId: vc.presenter.client_id,
      ...(vc.presenter.cnf !== undefined ? { cnf: vc.presenter.cnf } : {}),
    },
  };
}

const vectorKey = await importJWK(V.key.private_jwk_test_only, "ES256");

/** Sign claims (or exact payload text) with the vector's test key, under the vector's header unless given. */
async function sign(
  claims: JsonRecord | string,
  header: JsonRecord = V.expected.protected_header,
): Promise<string> {
  const text = typeof claims === "string" ? claims : JSON.stringify(claims);
  return new CompactSign(new TextEncoder().encode(text)).setProtectedHeader(header as never).sign(vectorKey);
}

const vectorSigningKey = createPrivateKey({ key: V.key.private_jwk_test_only as never, format: "jwk" });

/** An ES256 signature over exactly these encoded segments, spelled as given (RFC 7515 Section 5.1). */
function signSegments(header: string, payload: string): string {
  const input = Buffer.from(`${header}.${payload}`, "ascii");
  const signature = cryptoSign("sha256", input, { key: vectorSigningKey, dsaEncoding: "ieee-p1363" });
  return `${header}.${payload}.${signature.toString("base64url")}`;
}

const BASE64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/** The same bytes spelled with non-zero trailing bits, which a lenient decoder reads unchanged. */
function nonCanonical(segment: string): string {
  expect(segment.length % 4, segment).not.toBe(0);
  const last = BASE64URL_ALPHABET.indexOf(segment.slice(-1));
  const spelled = `${segment.slice(0, -1)}${BASE64URL_ALPHABET[last | 1]}`;
  expect(spelled).not.toBe(segment);
  expect(Buffer.from(spelled, "base64url")).toEqual(Buffer.from(segment, "base64url"));
  return spelled;
}

const claimsWith = (set: JsonRecord = {}, drop: string[] = []): JsonRecord => {
  const c = { ...structuredClone(V.expected.claims), ...set };
  for (const k of drop) delete c[k];
  return c;
};

/** The verification resolves, never throws, to a refusal at exactly this step. */
async function refusedAt(pending: Promise<RequestProvenanceResult>, step: number): Promise<void> {
  await expect(pending).resolves.toMatchObject({ ok: false, step });
}

function accepted(result: RequestProvenanceResult): Extract<RequestProvenanceResult, { ok: true }> {
  expect(result.ok, JSON.stringify(result)).toBe(true);
  if (!result.ok) throw new Error(`refused at step ${result.step}: ${result.reason}`);
  return result;
}

const refusedCases = CASES.filter((c) => c.expected.outcome === "refuse").map(
  (c) => [c.id, c.step, c] as const,
);
const acceptedCases = CASES.filter((c) => c.expected.outcome === "accept").map(
  (c) => [c.id, c] as const,
);

describe("assertion-cases.json through the verifier (@spec request-provenance#verification, request-provenance#recorded-facts, #939)", () => {
  it.each(refusedCases)("%s: refused at step %s", async (_id, step, c) => {
    expect(c.expected.error).toBe("invalid_mission_intent_evidence");
    await refusedAt(
      verifyRequestProvenance(entry(c.token), contextFor(c.construction.verifier_context_patch)),
      step as number,
    );
  });

  it.each(acceptedCases)(
    "%s: accepted, recording exactly the positive vector's facts",
    async (_id, c) => {
      const result = accepted(
        await verifyRequestProvenance(entry(c.token), contextFor(c.construction.verifier_context_patch)),
      );
      expect(c.expected.recorded_facts).toStrictEqual(V.expected.recorded_facts);
      expect(result.facts).toStrictEqual(c.expected.recorded_facts);
    },
  );

  it("runs every case the vectors define, the new PAR presenter case among them", () => {
    expect(refusedCases.length + acceptedCases.length).toBe(CASES.length);
    expect(CASES.map((c) => c.id)).toContain("neg-presenter-cnf-unestablished");
  });
});

describe("the positive vector (@spec request-provenance#verification, request-provenance#recorded-facts, #939)", () => {
  it("accepts the sample entry, keying the reservation (iss, jti) to exp plus the skew allowance, and records exactly the vector's facts", async () => {
    const result = accepted(await verifyRequestProvenance(V.expected.entry, contextFor()));
    expect(result.reservation).toStrictEqual({
      iss: V.expected.claims.iss,
      jti: V.expected.claims.jti,
      expiresAt: (V.expected.claims.exp as number) + V.verifier_context.clock_skew_seconds,
    });
    expect(result.facts).toStrictEqual(V.expected.recorded_facts);
    expect(Object.keys(result.facts).sort()).toEqual(
      ["assertion_id", "capture_id", "captured_at", "channel", "originator", "request_digest", "signer"],
    );
    expect(result.facts.captured_at).toBe("2026-10-03T08:29:00Z");
  });
});

describe("step 1, the entry shape (@spec request-provenance#entry, request-provenance#verification, #939)", () => {
  const assertion = V.expected.entry.assertion;
  it.each([
    ["carrying a third member", { type: TYPE, assertion, note: "x" }],
    ["without assertion", { type: TYPE }],
    ["without type", { assertion }],
    ["whose assertion is a number", { type: TYPE, assertion: 7 }],
    ["whose assertion is an object", { type: TYPE, assertion: { jws: assertion } }],
    ["whose type is another evidence type", { type: "urn:example:other", assertion }],
    ["that is an array", [TYPE, assertion]],
    ["that is null", null],
  ])("refuses an entry %s at step 1", async (_what, value) => {
    await refusedAt(verifyRequestProvenance(value, contextFor()), 1);
  });

  it("passes an entry of exactly type and a string assertion on to the later steps", async () => {
    accepted(await verifyRequestProvenance({ type: TYPE, assertion }, contextFor()));
  });
});

describe("step 2, decoding the JWS (@spec request-provenance#verification, #939)", () => {
  it("refuses, at step 2 and without throwing, an assertion that is not a three-part compact JWS or whose header or claims set is not one JSON object", async () => {
    const [h, p, s] = V.expected.entry.assertion.split(".") as [string, string, string];
    const b64 = (text: string) => Buffer.from(text, "utf8").toString("base64url");
    for (const bad of [
      "",
      "not-a-jws",
      `${h}.${p}`,
      `${h}.${p}.${s}.${s}`,
      `${b64("[1]")}.${p}.${s}`,
      `${h}.${b64('"claims"')}.${s}`,
      `${h}.${b64("{")}.${s}`,
      `${h}.${p.slice(0, 5)}*${p.slice(6)}.${s}`,
      // A lenient decoder skips the stray characters and decodes the
      // vector's claims; the strict decoding refuses them here.
      `${h}.${p}****.${s}`,
    ]) {
      await refusedAt(verifyRequestProvenance(entry(bad), contextFor()), 2);
    }
  });

  it("refuses at step 2 a claims set with a duplicated member name, even when signed", async () => {
    const text = JSON.stringify(V.expected.claims).replace(
      '"aud":"https://as.example.com"',
      '"aud":"https://other-as.example.com","aud":"https://as.example.com"',
    );
    expect(text).toContain('"aud":"https://other-as.example.com","aud"');
    await refusedAt(verifyRequestProvenance(entry(await sign(text)), contextFor()), 2);
  });

  it("refuses at step 2 a protected header without alg", async () => {
    const header = { ...V.expected.protected_header };
    const signed = await sign(V.expected.claims, header);
    const [, p, s] = signed.split(".");
    delete header.alg;
    const noAlg = `${Buffer.from(JSON.stringify(header)).toString("base64url")}.${p}.${s}`;
    await refusedAt(verifyRequestProvenance(entry(noAlg), contextFor()), 2);
  });

  it("refuses at step 2 a signature segment that is padded, empty, or not the canonical spelling of its bytes, though its bytes verify (RFC 7515 Sections 2 and 5.2)", async () => {
    const token = V.expected.entry.assertion;
    // The control: the vector's own spelling verifies.
    accepted(await verifyRequestProvenance(entry(token), contextFor()));
    const [h, p, s] = token.split(".") as [string, string, string];
    for (const bad of [`${token}==`, `${token}=`, `${h}.${p}.${nonCanonical(s)}`, `${h}.${p}.`]) {
      await refusedAt(verifyRequestProvenance(entry(bad), contextFor()), 2);
    }
  });

  it("refuses at step 2 a header or claims segment spelled with non-zero trailing bits, though signed as spelled", async () => {
    const [h] = V.expected.entry.assertion.split(".") as [string, string, string];
    // Trailing whitespace keeps the claims set and leaves its last group partial.
    let text = JSON.stringify(V.expected.claims);
    while (Buffer.byteLength(text, "utf8") % 3 === 0) text += " ";
    const p = Buffer.from(text, "utf8").toString("base64url");
    // The control: signed over the canonical spellings, it verifies.
    accepted(await verifyRequestProvenance(entry(signSegments(h, p)), contextFor()));
    for (const bad of [signSegments(nonCanonical(h), p), signSegments(h, nonCanonical(p))]) {
      await refusedAt(verifyRequestProvenance(entry(bad), contextFor()), 2);
    }
  });
});

describe("step 3, the signer from configuration only (@spec request-provenance#verification, request-provenance#trust-configuration, #939)", () => {
  it("refuses at step 3 a validly signed assertion whose iss names no configured signer", async () => {
    const token = await sign(claimsWith({ iss: "https://other-intake.example.com" }));
    await refusedAt(verifyRequestProvenance(entry(token), contextFor()), 3);
  });
});

describe("step 4, the signature (@spec request-provenance#verification, #939)", () => {
  it("refuses at step 4 a JWS whose signed payload is not the claims set the later steps read (b64 false)", async () => {
    // Signed over the base64url text itself (RFC 7797): the signature is
    // valid, but over bytes other than the decoded claims.
    const encoded = Buffer.from(JSON.stringify(V.expected.claims), "utf8").toString("base64url");
    const detached = await new CompactSign(new TextEncoder().encode(encoded))
      .setProtectedHeader({ ...V.expected.protected_header, b64: false, crit: ["b64"] } as never)
      .sign(vectorKey);
    const [h, empty, s] = detached.split(".");
    expect(empty).toBe("");
    // The payload segment is the base64url text, so step 2 decodes the
    // vector's claims from it, while the signature covers the text.
    const token = `${h}.${encoded}.${s}`;
    await refusedAt(verifyRequestProvenance(entry(token), contextFor()), 4);
  });
});

describe("step 5, the required claims and their types (@spec request-provenance#assertion, request-provenance#verification, #939)", () => {
  it.each([
    ["an empty jti", { jti: "" }],
    ["a numeric intent_hash", { intent_hash: 7 }],
    ["a presenter.cnf that is not an object", { presenter: { client_id: "ap-agent", cnf: "jkt" } }],
    ["an originator without sub", { originator: { iss: "https://idp.example.com" } }],
    ["a channel without type", { channel: { acr: "phr" } }],
    ["a numeric channel.acr", { channel: { type: "https://intake.example.com/ch/web", acr: 2 } }],
    ["a channel.amr that is not an array of strings", { channel: { type: "https://intake.example.com/ch/web", amr: "pwd" } }],
    ["a string channel.auth_time", { channel: { type: "https://intake.example.com/ch/web", auth_time: "1791016100" } }],
    ["a string captured_at", { captured_at: "1791016140" }],
    ["a numeric capture_id", { capture_id: 7 }],
  ])("refuses at step 5 %s", async (_what, set) => {
    await refusedAt(verifyRequestProvenance(entry(await sign(claimsWith(set as JsonRecord))), contextFor()), 5);
  });

  it("refuses at step 5, without throwing, a signed presenter.cnf holding a number no JSON value represents (1e400)", async () => {
    for (const member of ['"extra":1e400,', '"extra":[1,-1e400],', '"extra":{"n":1e400},']) {
      const text = JSON.stringify(V.expected.claims).replace('"cnf":{', `"cnf":{${member}`);
      expect(text).toContain(member);
      await refusedAt(verifyRequestProvenance(entry(await sign(text)), contextFor()), 5);
    }
  });

  it("accepts, recording nothing from them, an undefined claim and undefined members of originator and channel holding 1e400", async () => {
    const text = JSON.stringify(V.expected.claims)
      .replace('"originator":{', '"originator":{"extra":1e400,')
      .replace('"channel":{', '"channel":{"extra":1e400,')
      .replace(/}$/, ',"extra":1e400}');
    expect(text.match(/"extra":1e400/g)).toHaveLength(3);
    const result = accepted(await verifyRequestProvenance(entry(await sign(text)), contextFor()));
    expect(result.facts).toStrictEqual(V.expected.recorded_facts);
  });

  const digest = V.expected.claims.request_digest as string;
  const value = digest.slice("hmac-sha-256:".length);
  it.each([
    ["the integrity-anchor prefix sha-256:", `sha-256:${value}`],
    ["no prefix", value],
    ["padding", `${digest}=`],
    ["31 bytes", `hmac-sha-256:${Buffer.alloc(31, 7).toString("base64url")}`],
    ["33 bytes", `hmac-sha-256:${Buffer.alloc(33, 7).toString("base64url")}`],
    ["standard base64 characters", `hmac-sha-256:${Buffer.alloc(32, 0xfb).toString("base64")}`.replace(/=+$/, "")],
    ["non-canonical trailing bits", `hmac-sha-256:${value.slice(0, -1)}${value.endsWith("1") ? "2" : "1"}`],
  ])("refuses at step 5 a request_digest with %s (strictness the draft implies)", async (_what, bad) => {
    // The control: the vector's own digest has the form.
    expect(digest).toMatch(/^hmac-sha-256:[A-Za-z0-9_-]{43}$/);
    await refusedAt(
      verifyRequestProvenance(entry(await sign(claimsWith({ request_digest: bad }))), contextFor()),
      5,
    );
  });
});

describe("step 7, the time window (@spec request-provenance#verification, #939)", () => {
  const iat = V.expected.claims.iat as number;
  const exp = V.expected.claims.exp as number;
  const capturedAt = V.expected.claims.captured_at as number;
  const skew = V.verifier_context.clock_skew_seconds;

  it.each([
    ["exp equal to iat", iat],
    ["exp ten seconds before iat", iat - 10],
  ])(
    "refuses at step 7 %s, though exp minus iat does not exceed the maximum lifetime and neither iat nor exp is outside the skew allowance (strictness the draft implies)",
    async (_what, badExp) => {
      // now lies within the allowance of both iat and exp, so only the
      // ordering of exp after iat can refuse.
      const now = iat - 5;
      expect(iat <= now + skew && now < badExp + skew).toBe(true);
      const token = await sign(claimsWith({ exp: badExp }));
      await refusedAt(verifyRequestProvenance(entry(token), contextFor({ now })), 7);
    },
  );

  it("refuses at step 7 captured_at one second after iat: the signer's own claims take no clock-skew allowance", async () => {
    const token = await sign(claimsWith({ captured_at: iat + 1 }));
    await refusedAt(verifyRequestProvenance(entry(token), contextFor()), 7);
  });

  it("accepts at each edge of the window: iat at the skew allowance ahead, exp just inside the allowance, lifetime and capture age at their maxima, captured_at at iat", async () => {
    const sample = entry(V.expected.entry.assertion);
    accepted(await verifyRequestProvenance(sample, contextFor({ now: iat - skew })));
    accepted(await verifyRequestProvenance(sample, contextFor({ now: exp + skew - 1 })));
    accepted(
      await verifyRequestProvenance(sample, contextFor({ max_assertion_lifetime_seconds: exp - iat })),
    );
    accepted(
      await verifyRequestProvenance(sample, contextFor({ max_capture_age_seconds: iat - capturedAt })),
    );
    const atIat = await sign(claimsWith({ captured_at: iat }));
    accepted(await verifyRequestProvenance(entry(atIat), contextFor()));
  });

  it("refuses at step 7 once now reaches exp plus the skew allowance", async () => {
    await refusedAt(
      verifyRequestProvenance(entry(V.expected.entry.assertion), contextFor({ now: exp + skew })),
      7,
    );
  });
});

describe("step 8, a user-device signer (@spec request-provenance#trust-configuration, request-provenance#verification, #939)", () => {
  const signer = (V.verifier_context.trust.signers[0] ?? {}) as JsonRecord;
  const bound = (sub: string): JsonRecord => ({
    trust: { signers: [{ ...signer, originators: [{ iss: "https://idp.example.com", sub }] }] },
  });

  it("accepts the originator the AS bound the signer's key to, and refuses any other at step 8", async () => {
    const sample = entry(V.expected.entry.assertion);
    accepted(await verifyRequestProvenance(sample, contextFor(bound("248289761001"))));
    await refusedAt(verifyRequestProvenance(sample, contextFor(bound("248289761002"))), 8);
  });
});

// Assertions minted by the intake library, verified by the AS module.
const AS = "https://as.example.org";
const INTAKE = "https://intake.example.org";
const KID = "intake-live-1";
const T0 = 1_800_000_000;
const intent: JsonObject = {
  goal: "Pay the Acme invoices due this week.",
  target_resources: ["https://erp.example.com"],
  expires_at: "2027-01-31T23:59:59Z",
};
const livePair = await generateKeyPair("ES256", { extractable: true });
const livePublicJwk = await exportJWK(livePair.publicKey);
const otherPair = await generateKeyPair("ES256", { extractable: true });
const liveJkt = await calculateJwkThumbprint(await exportJWK(otherPair.publicKey));

const liveTrust = (sub?: string) =>
  parseRequestProvenanceConfig({
    enabled: true,
    clock_skew_seconds: 30,
    max_assertion_lifetime_seconds: 300,
    max_capture_age_seconds: 600,
    signers: [
      {
        iss: INTAKE,
        keys: [
          {
            kid: KID,
            public_jwk: livePublicJwk as unknown as Json,
            evidence_types: [TYPE],
            algs: ["ES256"],
          },
        ],
        originators: [sub === undefined ? { iss: "https://idp.example.org" } : { iss: "https://idp.example.org", sub }],
        channel_types: ["https://intake.example.org/ch/app"],
      },
    ],
  });

const INSTRUCTION = "Pay the Acme invoices due this week, nothing else.";

/** Capture and sign through the intake library, recording every random draw so a test can hold the secret. */
async function mint(presenter: Presenter, opts: { emitCaptureId?: boolean } = {}) {
  const draws: Buffer[] = [];
  let clock = T0;
  const intake = createRequestIntake({
    issuer: INTAKE,
    kid: KID,
    signingKey: livePair.privateKey,
    assertionLifetimeSeconds: 120,
    maxCaptureAgeSeconds: 600,
    ...(opts.emitCaptureId !== undefined ? { emitCaptureId: opts.emitCaptureId } : {}),
    now: () => clock * 1000,
    randomBytes: (size) => {
      const b = randomBytes(size);
      draws.push(Buffer.from(b));
      return b;
    },
  });
  const receipt = intake.capture({
    workflow: "wf-live-1",
    instruction: Buffer.from(INSTRUCTION, "utf8"),
    mediaType: "text/plain;charset=utf-8",
    originator: { iss: "https://idp.example.org", sub: "user-17" },
    channel: { type: "https://intake.example.org/ch/app", amr: ["pwd", "otp"], auth_time: T0 - 20 },
    presenter,
  });
  clock = T0 + 10;
  const signed = await intake.sign({
    captureId: receipt.captureId,
    workflow: "wf-live-1",
    audience: AS,
    intent,
  });
  return { signed, secret: draws[0] as Buffer, receipt };
}

const liveContext = (
  presenter: RequestProvenanceVerificationContext["presenter"],
  sub?: string,
): RequestProvenanceVerificationContext => ({
  issuer: AS,
  now: new Date((T0 + 15) * 1000),
  trust: liveTrust(sub),
  intentHash: provisionalIntentHash(AS, intent as never),
  presenter,
});

describe("step 9, cnf compared exactly as signed (@spec request-provenance#verification, #939)", () => {
  const jkt = V.verifier_context.presenter.cnf?.jkt as string;
  const cnf = JSON.stringify({ jkt });

  it.each([
    ["null", "null"],
    ["a scalar", "7"],
    ["an empty object", "{}"],
    ["an object naming the established key", cnf],
  ])("refuses at step 9 a signed cnf carrying a __proto__ member valued %s beside the established key", async (_what, value) => {
    const text = JSON.stringify(V.expected.claims).replace('"cnf":{', `"cnf":{"__proto__":${value},`);
    expect(text).toContain(`"__proto__":${value},"jkt"`);
    await expect(verifyRequestProvenance(entry(await sign(text)), contextFor())).resolves.toMatchObject({
      ok: false,
      step: 9,
      reason: "presenter.cnf is not the confirmation key the exchange established",
    });
  });

  it("refuses at step 9 a signed cnf naming the established key only inside a __proto__ member", async () => {
    const text = JSON.stringify(V.expected.claims).replace(`"cnf":${cnf}`, `"cnf":{"__proto__":${cnf}}`);
    expect(text).toContain(`"cnf":{"__proto__":${cnf}}`);
    await refusedAt(verifyRequestProvenance(entry(await sign(text)), contextFor()), 9);
  });
});

describe("assertions minted live by @mission/request-provenance (@spec request-provenance#verification, request-provenance#recorded-facts, #939)", () => {
  it("accepts an assertion without cnf where the exchange established the client alone, as a PAR does, and records its facts", async () => {
    const { signed, receipt } = await mint({ client_id: "agent-7" });
    const result = accepted(await verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7" })));
    expect(result.reservation).toStrictEqual({ iss: INTAKE, jti: signed.jti, expiresAt: signed.exp + 30 });
    expect(result.facts).toStrictEqual({
      signer: { iss: INTAKE, kid: KID },
      originator: { iss: "https://idp.example.org", sub: "user-17" },
      channel: { type: "https://intake.example.org/ch/app", amr: ["pwd", "otp"], auth_time: T0 - 20 },
      captured_at: new Date(T0 * 1000).toISOString().replace(".000Z", "Z"),
      request_digest: receipt.requestDigest,
      assertion_id: signed.jti,
      capture_id: receipt.captureId,
    });
  });

  it("accepts an assertion whose cnf is exactly the confirmation key the exchange established", async () => {
    const { signed } = await mint({ client_id: "agent-7", cnf: { jkt: liveJkt } });
    accepted(
      await verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7", cnf: { jkt: liveJkt } })),
    );
  });

  it("refuses at step 9 an assertion without cnf where the exchange established a confirmation key (cnf is REQUIRED under proof of possession)", async () => {
    const { signed } = await mint({ client_id: "agent-7" });
    await refusedAt(
      verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7", cnf: { jkt: liveJkt } })),
      9,
    );
  });

  it("refuses at step 9 an assertion carrying cnf where the exchange established no confirmation key: no key is inferred (D1119 Q3)", async () => {
    const { signed } = await mint({ client_id: "agent-7", cnf: { jkt: liveJkt } });
    await refusedAt(verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7" })), 9);
  });

  it("refuses at step 9 a cnf that carries a member beyond the established key, compared exactly", async () => {
    const { signed } = await mint({
      client_id: "agent-7",
      cnf: { jkt: liveJkt, "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2" },
    });
    await refusedAt(
      verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7", cnf: { jkt: liveJkt } })),
      9,
    );
  });

  it("refuses at step 9 an assertion presented by another client, or for another Intent", async () => {
    const { signed } = await mint({ client_id: "agent-7" });
    await refusedAt(verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-8" })), 9);
    const other = { ...liveContext({ clientId: "agent-7" }) };
    other.intentHash = provisionalIntentHash(AS, { ...intent, goal: "Pay every Acme invoice." } as never);
    await refusedAt(verifyRequestProvenance(signed.entry, other), 9);
  });

  it("accepts a user-device signer's assertion for its bound originator and refuses one bound to another at step 8", async () => {
    const { signed } = await mint({ client_id: "agent-7" });
    accepted(await verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7" }, "user-17")));
    await refusedAt(
      verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7" }, "user-18")),
      8,
    );
  });

  it("records no capture_id when the assertion carries none", async () => {
    const { signed } = await mint({ client_id: "agent-7" }, { emitCaptureId: false });
    const result = accepted(await verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7" })));
    expect(Object.hasOwn(result.facts, "capture_id")).toBe(false);
    expect(Object.keys(result.facts).sort()).toEqual(
      ["assertion_id", "captured_at", "channel", "originator", "request_digest", "signer"],
    );
  });

  it("records facts that carry neither the instruction nor the capture secret", async () => {
    const { signed, secret } = await mint({ client_id: "agent-7" });
    const result = accepted(await verifyRequestProvenance(signed.entry, liveContext({ clientId: "agent-7" })));
    const recorded = JSON.stringify(result.facts);
    expect(secret.length).toBe(32);
    for (const forbidden of [
      INSTRUCTION,
      Buffer.from(INSTRUCTION, "utf8").toString("base64url"),
      secret.toString("hex"),
      secret.toString("base64url"),
      secret.toString("base64"),
    ]) {
      expect(recorded.includes(forbidden), forbidden).toBe(false);
    }
  });
});

describe("recorded facts are exactly the defined members (@spec request-provenance#recorded-facts, request-provenance#assertion, #939)", () => {
  it("records nothing from claims the draft does not define, nor from members of originator and channel it does not define", async () => {
    const token = await sign(
      claimsWith({
        originator: { iss: "https://idp.example.com", sub: "248289761001", email: "a@example.com" },
        channel: {
          type: "https://intake.example.com/ch/web",
          acr: "phr",
          auth_time: 1791016100,
          ip: "192.0.2.7",
        },
        presenter: { client_id: "ap-agent", cnf: V.verifier_context.presenter.cnf as Json, label: "x" },
        nbf: 1791016100,
        instruction_media_type: "text/plain",
      }),
    );
    const result = accepted(await verifyRequestProvenance(entry(token), contextFor()));
    expect(result.facts).toStrictEqual(V.expected.recorded_facts);
  });

  it("records no value of the vector's content-committing claim, nor the instruction, its media type or the capture secret", async () => {
    const c = CASES.find((x) => x.id === "ign-extra-content-claim") as AssertionCase;
    const result = accepted(await verifyRequestProvenance(entry(c.token), contextFor()));
    const recorded = JSON.stringify(result.facts);
    const committed = JSON.parse(
      Buffer.from(c.token.split(".")[1] as string, "base64url").toString("utf8"),
    ).instruction_sha256 as string;
    for (const forbidden of [
      committed,
      "instruction_sha256",
      V.capture.instruction_utf8,
      V.capture.media_type,
      V.capture.secret_hex,
      Buffer.from(V.capture.secret_hex, "hex").toString("base64url"),
    ]) {
      expect(recorded.includes(forbidden), forbidden).toBe(false);
    }
  });
});
