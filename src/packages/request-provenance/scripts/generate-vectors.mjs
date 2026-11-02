// Generates vectors/mission-request-provenance/ from the draft's encoding,
// independently of this package's src/: the HMAC input, JCS and the
// integrity anchor are written out here, and tokens are built with jose
// directly. The package's tests then check that the library reproduces them.
//
// Run from src/: node packages/request-provenance/scripts/generate-vectors.mjs
//
// The ES256 key pair is test-only. It is generated once and then read back
// from assertion.json, so regenerating keeps the key. ECDSA signatures are
// randomized, so each run produces different signature bytes over the same
// header and claims; a consumer checks validity, never bytes.

import { createHash, createHmac, createPublicKey } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CompactSign, exportJWK, generateKeyPair, importJWK } from "jose";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = resolve(here, "../../../../vectors/mission-request-provenance");
const SPEC = "draft-mcguinness-oauth-mission-request-provenance";

// ---- the request digest, from the draft's #request-digest text ----------

function hmacInput(mediaType, instruction) {
  const mt = Buffer.from(mediaType, "ascii");
  const mtLen = Buffer.alloc(4);
  mtLen.writeUInt32BE(mt.length);
  const insLen = Buffer.alloc(8);
  insLen.writeBigUInt64BE(BigInt(instruction.length));
  return Buffer.concat([
    Buffer.from("mission-request-provenance/v1", "ascii"),
    Buffer.from([0]),
    mtLen,
    mt,
    insLen,
    instruction,
  ]);
}

function digest(secret, mediaType, instruction) {
  const mac = createHmac("sha256", secret).update(hmacInput(mediaType, instruction)).digest();
  return `hmac-sha-256:${mac.toString("base64url")}`;
}

const SECRET_A = Buffer.from(Array.from({ length: 32 }, (_, i) => i));
const SECRET_B = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
const PLAIN = "text/plain;charset=utf-8";
const INSTRUCTION = "Pay this week's Acme invoices.";

const digestCases = [
  {
    id: "rd-01",
    source: "draft Appendix (#vectors), first vector",
    description: "the published vector, HMAC input included",
    secret: SECRET_A,
    media_type: PLAIN,
    instruction: INSTRUCTION,
    published: "hmac-sha-256:-xVlEjxrMKqRGHbUOS2YvZhW7uN-RpRrfV-BsTIUDu0",
  },
  {
    id: "rd-02",
    source: "draft Appendix (#vectors)",
    description: "one character removed from the instruction",
    secret: SECRET_A,
    media_type: PLAIN,
    instruction: "Pay this week's Acme invoice.",
    published: "hmac-sha-256:DXLpPDrfm1W53Z-nniGK1j2NdqvUjPCL-ha82mt5pms",
  },
  {
    id: "rd-03",
    source: "draft Appendix (#vectors)",
    description: "media type text/markdown;charset=utf-8",
    secret: SECRET_A,
    media_type: "text/markdown;charset=utf-8",
    instruction: INSTRUCTION,
    published: "hmac-sha-256:VTGuqTNNdu6Q780TwU9cVUVlMbJlzDa_M-iWMteLoi8",
  },
  {
    id: "rd-04",
    source: "draft Appendix (#vectors)",
    description: "secret bytes 01 through 20",
    secret: SECRET_B,
    media_type: PLAIN,
    instruction: INSTRUCTION,
    published: "hmac-sha-256:NGW2Oglh0SHnmQJaPUBHXG0LTjHwBoY67TokgLxS_g8",
  },
  {
    id: "rd-05",
    source: "#939 slice 1, low entropy",
    description: "a one-word instruction",
    secret: SECRET_A,
    media_type: PLAIN,
    instruction: "Yes",
  },
  {
    id: "rd-06",
    source: "#939 slice 1, low entropy",
    description: "a two-word instruction",
    secret: SECRET_A,
    media_type: PLAIN,
    instruction: "Pay Acme.",
  },
  {
    id: "rd-07",
    source: "#939 slice 1, low entropy",
    description: "a two-word instruction under the other secret",
    secret: SECRET_B,
    media_type: PLAIN,
    instruction: "Pay Acme.",
  },
  {
    id: "rd-08",
    source: "#939 slice 1, low entropy",
    description: "a two-word instruction, media type without parameters",
    secret: SECRET_A,
    media_type: "text/plain",
    instruction: "Cancel it.",
  },
  {
    id: "rd-09",
    source: "#939 slice 1, edge",
    description: "an empty instruction: the 8-byte length is zero",
    secret: SECRET_A,
    media_type: PLAIN,
    instruction: "",
  },
  {
    id: "rd-10",
    source: "#939 slice 1, edge",
    description: "a short instruction with non-ASCII UTF-8 bytes, hashed as received",
    secret: SECRET_A,
    media_type: PLAIN,
    instruction: "Zahle 50 € an Acme.",
  },
];

const digestFile = {
  format: "mission-request-provenance-digest-vectors/1",
  spec: SPEC,
  description:
    "Request digest vectors: the draft appendix's four, then short low-entropy and edge instructions. Every secret here is a fixed test value; an intake never uses one.",
  cases: digestCases.map((c) => {
    const instruction = Buffer.from(c.instruction, "utf8");
    const value = digest(c.secret, c.media_type, instruction);
    if (c.published !== undefined && value !== c.published) {
      throw new Error(`${c.id}: computed ${value}, the draft publishes ${c.published}`);
    }
    return {
      id: c.id,
      source: c.source,
      description: c.description,
      secret_hex: c.secret.toString("hex"),
      media_type: c.media_type,
      instruction_utf8: c.instruction,
      instruction_hex: instruction.toString("hex"),
      hmac_input_hex: hmacInput(c.media_type, instruction).toString("hex"),
      request_digest: value,
    };
  }),
};

// ---- the integrity anchor (OAuth binding #integrity-anchors) --------------

function jcs(v) {
  if (v === null || typeof v === "boolean" || typeof v === "string") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("non-finite");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return `[${v.map(jcs).join(",")}]`;
  const keys = Object.keys(v).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${jcs(v[k])}`).join(",")}}`;
}

function intentHash(iss, intent) {
  const bytes = Buffer.from(jcs({ typ: "mission-intent", iss, value: intent }), "utf8");
  return `sha-256:${createHash("sha256").update(bytes).digest("base64url")}`;
}

// ---- the positive assertion vector ----------------------------------------

const assertionPath = join(outDir, "assertion.json");
let publicJwk;
let privateJwk;
if (existsSync(assertionPath)) {
  const prior = JSON.parse(readFileSync(assertionPath, "utf8"));
  publicJwk = prior.key.public_jwk;
  privateJwk = prior.key.private_jwk_test_only;
} else {
  const pair = await generateKeyPair("ES256", { extractable: true });
  publicJwk = await exportJWK(pair.publicKey);
  privateJwk = await exportJWK(pair.privateKey);
}
const KID = "intake-2026-10";
const privateKey = await importJWK(privateJwk, "ES256");

const ISS = "https://intake.example.com";
const AUD = "https://as.example.com";
const CAPTURED_AT = 1791016140;
const IAT = 1791016200;
const LIFETIME = 300;
const CAPTURE_ID_BYTES = Buffer.from("a0a1a2a3a4a5a6a7a8a9aaabacadaeaf", "hex");
const JTI_BYTES = Buffer.from("b0b1b2b3b4b5b6b7b8b9babbbcbdbebf", "hex");

const capture = {
  workflow: "wf-2026-10-03-0001",
  media_type: PLAIN,
  instruction_utf8: INSTRUCTION,
  originator: { iss: "https://idp.example.com", sub: "248289761001" },
  channel: { type: "https://intake.example.com/ch/web", acr: "phr", auth_time: 1791016100 },
  captured_at: CAPTURED_AT,
  secret_hex: SECRET_A.toString("hex"),
  capture_id: CAPTURE_ID_BYTES.toString("base64url"),
  presenter: {
    client_id: "ap-agent",
    cnf: { jkt: "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I" },
  },
};
const sign = {
  workflow: capture.workflow,
  audience: AUD,
  intent: {
    goal: "Pay the open Acme invoices due this week.",
    target_resources: ["https://erp.example.com"],
    expires_at: "2026-10-10T23:59:59Z",
  },
  iat: IAT,
  jti: JTI_BYTES.toString("base64url"),
};

const header = { typ: "mission-request-provenance+jwt", alg: "ES256", kid: KID };
const requestDigest = digest(SECRET_A, PLAIN, Buffer.from(INSTRUCTION, "utf8"));
const claims = {
  iss: ISS,
  aud: AUD,
  iat: IAT,
  exp: IAT + LIFETIME,
  jti: sign.jti,
  intent_hash: intentHash(AUD, sign.intent),
  presenter: capture.presenter,
  originator: capture.originator,
  channel: capture.channel,
  captured_at: CAPTURED_AT,
  request_digest: requestDigest,
  capture_id: capture.capture_id,
};

const enc = (o) => Buffer.from(JSON.stringify(o), "utf8");
const b64 = (o) => enc(o).toString("base64url");

async function es256(h, c) {
  return new CompactSign(enc(c)).setProtectedHeader(h).sign(privateKey);
}

const sample = await es256(header, claims);

const recordedFacts = {
  signer: { iss: ISS, kid: KID },
  originator: capture.originator,
  channel: capture.channel,
  captured_at: new Date(CAPTURED_AT * 1000).toISOString().replace(".000Z", "Z"),
  request_digest: requestDigest,
  assertion_id: sign.jti,
  capture_id: capture.capture_id,
};

const verifierContext = {
  issuer: AUD,
  now: IAT + 60,
  clock_skew_seconds: 30,
  max_assertion_lifetime_seconds: 600,
  max_capture_age_seconds: 600,
  trust: {
    signers: [
      {
        iss: ISS,
        keys: [
          {
            kid: KID,
            public_jwk: publicJwk,
            evidence_types: ["mission-request-provenance"],
            algs: ["ES256"],
          },
        ],
        originators: [{ iss: "https://idp.example.com" }],
        channel_types: ["https://intake.example.com/ch/web"],
      },
    ],
  },
  intent: sign.intent,
  presenter: capture.presenter,
};

const assertionFile = {
  format: "mission-request-provenance-assertion-vector/1",
  spec: SPEC,
  description:
    "One positive assertion: fixed inputs, fixed times, fixed random values and a test-only ES256 key. The protected header and claims are exact; the sample JWS verifies under the public key, and its signature bytes are not reproducible.",
  key: {
    kid: KID,
    public_jwk: publicJwk,
    private_jwk_test_only: privateJwk,
    note: "Test only. Never configure this key as a signer outside tests.",
  },
  intake: {
    iss: ISS,
    assertion_lifetime_seconds: LIFETIME,
    max_capture_age_seconds: 600,
    emit_capture_id: true,
  },
  capture,
  sign,
  expected: {
    protected_header: header,
    claims,
    entry: { type: "mission-request-provenance", assertion: sample },
    recorded_facts: recordedFacts,
  },
  verifier_context: verifierContext,
};

// ---- negative cases ---------------------------------------------------------

const REFUSE = { outcome: "refuse", error: "invalid_mission_intent_evidence" };
const PENDING = { status: "pending", tracking: "#939 slice 2 (AS verifier)" };
const T = "src/packages/request-provenance/test";
const producerHeader = {
  status: "checked",
  test: `${T}/assertion.test.ts > the provenance assertion (@spec request-provenance#assertion, request-provenance#signing, #939) > the protected header is exactly typ, alg and kid: never jku, x5u, jwk or x5c`,
};
const producerClaims = {
  status: "checked",
  test: `${T}/assertion.test.ts > the provenance assertion (@spec request-provenance#assertion, request-provenance#signing, #939) > aud is one string, and every required claim is present with its defined type`,
};
const producerContent = {
  status: "checked",
  test: `${T}/privacy.test.ts > the assertion commits to no request content (@spec request-provenance#assertion, request-provenance#privacy-considerations, #939) > the claim set is exactly the defined claims, and no public artifact carries the secret, the instruction, the media type or an unsalted digest of either`,
};
const producerAge = {
  status: "checked",
  test: `${T}/signing.test.ts > signing only from the intake's own capture (@spec request-provenance#signing, #939) > refuses a capture past the maximum capture age, and signs at the bound`,
};
const producerClock = {
  status: "checked",
  test: `${T}/signing.test.ts > signing only from the intake's own capture (@spec request-provenance#signing, #939) > refuses to sign while the clock reads earlier than captured_at`,
};
const na = (reason) => ({ status: "not-applicable", reason });

const without = (o, k) => {
  const c = structuredClone(o);
  delete c[k];
  return c;
};

const negatives = [];
const add = (c) => negatives.push(c);

add({
  id: "neg-typ-jwt",
  description: "protected typ is JWT",
  step: 2,
  construction: { header_set: { typ: "JWT" } },
  token: await es256({ ...header, typ: "JWT" }, claims),
  expected: REFUSE,
  producer: producerHeader,
  verifier: PENDING,
});
add({
  id: "neg-typ-absent",
  description: "protected header carries no typ",
  step: 2,
  construction: { header_delete: ["typ"] },
  token: await es256(without(header, "typ"), claims),
  expected: REFUSE,
  producer: producerHeader,
  verifier: PENDING,
});
add({
  id: "neg-alg-none",
  description: "alg none, an unsecured JWS with an empty signature",
  step: 2,
  construction: { header_set: { alg: "none" }, signature: "empty" },
  token: `${b64({ ...header, alg: "none" })}.${b64(claims)}.`,
  expected: REFUSE,
  producer: producerHeader,
  verifier: PENDING,
});
{
  const pem = createPublicKey({ key: publicJwk, format: "jwk" }).export({
    type: "spki",
    format: "pem",
  });
  const h = { ...header, alg: "HS256" };
  const input = `${b64(h)}.${b64(claims)}`;
  const mac = createHmac("sha256", Buffer.from(pem, "utf8")).update(input).digest("base64url");
  add({
    id: "neg-alg-hs256",
    description:
      "alg HS256, MACed with the signer's public key PEM as the secret (algorithm confusion); the key permits only ES256",
    step: 3,
    construction: {
      header_set: { alg: "HS256" },
      signature: "HMAC-SHA-256 keyed with the SPKI PEM",
    },
    token: `${input}.${mac}`,
    expected: REFUSE,
    producer: producerHeader,
    verifier: PENDING,
  });
}
add({
  id: "neg-kid-absent",
  description: "protected header carries no kid",
  step: 2,
  construction: { header_delete: ["kid"] },
  token: await es256(without(header, "kid"), claims),
  expected: REFUSE,
  producer: producerHeader,
  verifier: PENDING,
});
for (const [param, value] of [
  ["jku", "https://intake.example.com/jwks.json"],
  ["x5u", "https://intake.example.com/cert.pem"],
  ["jwk", publicJwk],
  ["x5c", ["MIIBfake0certificate0placeholder0for0the0presence0check0only0AAAA"]],
]) {
  add({
    id: `neg-header-${param}`,
    description: `protected header carries ${param}; the signature is valid under the configured key, so presence alone refuses`,
    step: 2,
    construction: { header_set: { [param]: value } },
    token: await es256({ ...header, [param]: value }, claims),
    expected: REFUSE,
    producer: producerHeader,
    verifier: PENDING,
  });
}
add({
  id: "neg-kid-unmapped",
  description: "kid names no key the configuration maps to this signer",
  step: 3,
  construction: { header_set: { kid: "intake-2026-09" } },
  token: await es256({ ...header, kid: "intake-2026-09" }, claims),
  expected: REFUSE,
  producer: na("the intake signs under its configured kid; the mapping is AS configuration"),
  verifier: PENDING,
});
add({
  id: "neg-key-not-mapped-to-type",
  description:
    "the configured key is mapped to another evidence type only, though its JWK carries use sig",
  step: 3,
  construction: {
    verifier_context_patch: {
      trust: {
        signers: [
          {
            iss: ISS,
            keys: [
              {
                kid: KID,
                public_jwk: { ...publicJwk, use: "sig", key_ops: ["verify"] },
                evidence_types: ["urn:example:intent-evidence:admission"],
                algs: ["ES256"],
              },
            ],
            originators: [{ iss: "https://idp.example.com" }],
            channel_types: ["https://intake.example.com/ch/web"],
          },
        ],
      },
    },
  },
  token: sample,
  expected: REFUSE,
  producer: na("AS trust configuration"),
  verifier: PENDING,
});
{
  const [h, p, s] = sample.split(".");
  const altered = { ...JSON.parse(Buffer.from(p, "base64url").toString("utf8")) };
  altered.originator = { ...altered.originator, sub: "248289761002" };
  add({
    id: "neg-altered-claim",
    description: "originator.sub altered after signing; the original signature is kept",
    step: 4,
    construction: { payload_set: { "originator.sub": "248289761002" }, signature: "original" },
    token: `${h}.${b64(altered)}.${s}`,
    expected: REFUSE,
    producer: na("a property of the token in transit"),
    verifier: PENDING,
  });
}
for (const claim of [
  "iss",
  "aud",
  "iat",
  "exp",
  "jti",
  "intent_hash",
  "presenter",
  "originator",
  "channel",
  "captured_at",
  "request_digest",
]) {
  add({
    id: `neg-missing-${claim.replaceAll("_", "-")}`,
    description: `required claim ${claim} is absent`,
    step: 5,
    construction: { claims_delete: [claim] },
    token: await es256(header, without(claims, claim)),
    expected: REFUSE,
    producer: producerClaims,
    verifier: PENDING,
  });
}
add({
  id: "neg-iat-string",
  description: "iat is a string, not a NumericDate",
  step: 5,
  construction: { claims_set: { iat: String(IAT) } },
  token: await es256(header, { ...claims, iat: String(IAT) }),
  expected: REFUSE,
  producer: producerClaims,
  verifier: PENDING,
});
add({
  id: "neg-presenter-no-client-id",
  description: "presenter lacks client_id",
  step: 5,
  construction: { claims_set: { presenter: { cnf: capture.presenter.cnf } } },
  token: await es256(header, { ...claims, presenter: { cnf: capture.presenter.cnf } }),
  expected: REFUSE,
  producer: producerClaims,
  verifier: PENDING,
});
add({
  id: "neg-aud-array",
  description: "aud is an array holding the AS's issuer identifier",
  step: 5,
  construction: { claims_set: { aud: [AUD] } },
  token: await es256(header, { ...claims, aud: [AUD] }),
  expected: REFUSE,
  producer: producerClaims,
  verifier: PENDING,
});
add({
  id: "neg-aud-other-as",
  description: "aud names another AS",
  step: 6,
  construction: { claims_set: { aud: "https://other-as.example.com" } },
  token: await es256(header, { ...claims, aud: "https://other-as.example.com" }),
  expected: REFUSE,
  producer: na("the intake signs for the audience its caller names"),
  verifier: PENDING,
});
add({
  id: "neg-expired",
  description: "verified after exp plus the clock-skew allowance",
  step: 7,
  construction: { verifier_context_patch: { now: IAT + LIFETIME + 31 } },
  token: sample,
  expected: REFUSE,
  producer: na("expiry is judged at verification"),
  verifier: PENDING,
});
add({
  id: "neg-iat-future",
  description: "verified before iat minus the clock-skew allowance",
  step: 7,
  construction: { verifier_context_patch: { now: IAT - 31 } },
  token: sample,
  expected: REFUSE,
  producer: na("judged at verification"),
  verifier: PENDING,
});
add({
  id: "neg-lifetime-over-max",
  description: "exp minus iat (300) exceeds the declared maximum assertion lifetime (299)",
  step: 7,
  construction: { verifier_context_patch: { max_assertion_lifetime_seconds: 299 } },
  token: sample,
  expected: REFUSE,
  producer: na("the AS's declared bound"),
  verifier: PENDING,
});
add({
  id: "neg-captured-after-iat",
  description: "captured_at is later than iat",
  step: 7,
  construction: { claims_set: { captured_at: IAT + 120 } },
  token: await es256(header, { ...claims, captured_at: IAT + 120 }),
  expected: REFUSE,
  producer: producerClock,
  verifier: PENDING,
});
add({
  id: "neg-capture-age-over-max",
  description: "iat minus captured_at (60) exceeds the declared maximum capture age (59)",
  step: 7,
  construction: { verifier_context_patch: { max_capture_age_seconds: 59 } },
  token: sample,
  expected: REFUSE,
  producer: producerAge,
  verifier: PENDING,
});
add({
  id: "neg-originator-out-of-scope",
  description: "the signer is not authorized for the originator's issuer",
  step: 8,
  construction: {
    verifier_context_patch: {
      trust: {
        signers: [
          {
            ...verifierContext.trust.signers[0],
            originators: [{ iss: "https://other-idp.example.com" }],
          },
        ],
      },
    },
  },
  token: sample,
  expected: REFUSE,
  producer: na("AS trust configuration"),
  verifier: PENDING,
});
add({
  id: "neg-channel-out-of-scope",
  description: "the signer is not authorized for channel.type",
  step: 8,
  construction: {
    verifier_context_patch: {
      trust: {
        signers: [
          {
            ...verifierContext.trust.signers[0],
            channel_types: ["https://intake.example.com/ch/voice"],
          },
        ],
      },
    },
  },
  token: sample,
  expected: REFUSE,
  producer: na("AS trust configuration"),
  verifier: PENDING,
});
add({
  id: "neg-intent-mismatch",
  description: "the submitted Intent differs from the one intent_hash commits",
  step: 9,
  construction: {
    verifier_context_patch: {
      intent: { ...sign.intent, goal: "Pay every open Acme invoice." },
    },
  },
  token: sample,
  expected: REFUSE,
  producer: na("the AS's comparison"),
  verifier: PENDING,
});
add({
  id: "neg-presenter-client-mismatch",
  description: "the exchange established another client_id",
  step: 9,
  construction: { verifier_context_patch: { presenter: { client_id: "other-agent" } } },
  token: sample,
  expected: REFUSE,
  producer: na("the AS's comparison"),
  verifier: PENDING,
});
add({
  id: "neg-presenter-cnf-mismatch",
  description:
    "the exchange established the same client_id under another key: an unmatched presenter.cnf is a presenter mismatch, and no key is inferred (D1119 Q3)",
  step: 9,
  construction: {
    verifier_context_patch: {
      presenter: { cnf: { jkt: "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" } },
    },
  },
  token: sample,
  expected: REFUSE,
  producer: na("the AS's comparison"),
  verifier: PENDING,
});
{
  const instructionSha256 = `sha-256:${createHash("sha256").update(Buffer.from(INSTRUCTION, "utf8")).digest("base64url")}`;
  add({
    id: "ign-extra-content-claim",
    description:
      "an undefined claim carrying an unsalted SHA-256 of the instruction. A producer MUST NOT emit it; a verifier ignores claims the draft does not define (RFC 7519) and records no fact from them, so this case is accepted, not refused",
    step: null,
    construction: { claims_set: { instruction_sha256: instructionSha256 } },
    token: await es256(header, { ...claims, instruction_sha256: instructionSha256 }),
    expected: { outcome: "accept", recorded_facts: recordedFacts },
    producer: producerContent,
    verifier: PENDING,
  });
}

const negativeFile = {
  format: "mission-request-provenance-assertion-cases/1",
  spec: SPEC,
  description:
    "Assertion-level cases for the AS verifier, each derived from assertion.json's positive vector. Each case runs alone, against a fresh replay store, with assertion.json's verifier_context after applying the case's verifier_context_patch (RFC 7386).",
  base: "assertion.json",
  cases: negatives,
};

mkdirSync(outDir, { recursive: true });
const write = (name, value) =>
  writeFileSync(join(outDir, name), `${JSON.stringify(value, null, 2)}\n`, "utf8");
write("request-digest.json", digestFile);
write("assertion.json", assertionFile);
write("assertion-cases.json", negativeFile);
console.log(`wrote ${outDir}`);
