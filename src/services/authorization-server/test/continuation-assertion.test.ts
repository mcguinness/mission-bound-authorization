/**
 * Unit tests for the ICA subject-token validator
 * (@spec draft-mcguinness-oauth-id-continuation-assertion-00). Key-free: mint
 * assertions with jose against an ephemeral ES256 key and exercise every
 * rejection path. `audience` is the AS issuer identifier (NOT `${iss}/token`).
 */

import { calculateJwkThumbprint, exportJWK, generateKeyPair, SignJWT } from "jose";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type ContinuationIssuer,
  ContinuationAssertionError,
  IDENTITY_CONTINUATION_JWT_TYP,
  validateContinuationAssertion,
} from "../src/kernel/continuation-assertion.js";
import { newReplayCache } from "../src/kernel/instance-assertion.js";

const AS = "https://as.test";
const CA = "https://chain-authority.example";
const HANDLE = "ich_0123456789abcdefABCD"; // 24 chars, base64url

let keys: { privateKey: CryptoKey; publicKey: CryptoKey };
let jkt: string;
let issuers: ContinuationIssuer[];

beforeAll(async () => {
  keys = await generateKeyPair("ES256", { extractable: true });
  const pub = await exportJWK(keys.publicKey);
  pub.kid = "ca-key";
  jkt = await calculateJwkThumbprint(pub);
  issuers = [{ iss: CA, jwks: { keys: [pub] } }];
});

interface MintOpts {
  over?: Record<string, unknown>;
  omit?: string[];
  typ?: string;
  aud?: string;
  iss?: string;
  iatSec?: number;
  expSec?: number;
}

async function mintICA(opts: MintOpts = {}): Promise<string> {
  const nowSec = Math.floor(Date.now() / 1000);
  const iat = opts.iatSec ?? nowSec;
  const exp = opts.expSec ?? nowSec + 120;
  const base: Record<string, unknown> = {
    identity_continuation_handle: HANDLE,
    cnf: { jkt },
    act: { iss: CA, sub: "agent-7" },
    ...opts.over,
  };
  for (const k of opts.omit ?? []) delete base[k];
  return new SignJWT(base)
    .setProtectedHeader({ alg: "ES256", kid: "ca-key", typ: opts.typ ?? IDENTITY_CONTINUATION_JWT_TYP })
    .setIssuer(opts.iss ?? CA)
    .setAudience(opts.aud ?? AS)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .setJti(crypto.randomUUID())
    .sign(keys.privateKey);
}

const ctx = () => ({ audience: AS, issuers, presenterJkt: jkt, replay: newReplayCache() });

describe("validateContinuationAssertion — accepts", () => {
  it("validates a well-formed ICA and surfaces handle/act/cnf", async () => {
    const v = await validateContinuationAssertion(await mintICA(), ctx());
    expect(v.iss).toBe(CA);
    expect(v.aud).toBe(AS);
    expect(v.handle).toBe(HANDLE);
    expect(v.act).toEqual({ iss: CA, sub: "agent-7" });
    expect(v.cnf.jkt).toBe(jkt);
    expect(v.jti).toBeTruthy();
  });

  it("accepts a lifetime of exactly 300s (boundary inclusive)", async () => {
    const now = Math.floor(Date.now() / 1000);
    const v = await validateContinuationAssertion(
      await mintICA({ iatSec: now, expSec: now + 300 }),
      ctx(),
    );
    expect(v.exp - v.iat).toBe(300);
  });
});

describe("validateContinuationAssertion — rejects", () => {
  it("unknown issuer", async () => {
    await expect(
      validateContinuationAssertion(await mintICA(), { ...ctx(), issuers: [] }),
    ).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("wrong typ header", async () => {
    await expect(
      validateContinuationAssertion(await mintICA({ typ: "jwt" }), ctx()),
    ).rejects.toBeInstanceOf(ContinuationAssertionError);
  });

  it("audience = token endpoint instead of the AS issuer identifier", async () => {
    // Fails inside jwtVerify -> invalid_grant (assert the code, not a message).
    await expect(
      validateContinuationAssertion(await mintICA({ aud: `${AS}/token` }), ctx()),
    ).rejects.toMatchObject({ code: "invalid_grant" });
  });

  it("lifetime exceeding 300s", async () => {
    const now = Math.floor(Date.now() / 1000);
    await expect(
      validateContinuationAssertion(await mintICA({ iatSec: now, expSec: now + 301 }), ctx()),
    ).rejects.toThrow(/lifetime exceeds/);
  });

  it("exp not strictly greater than iat", async () => {
    // Both in the future so jose's own expiry check passes; step 4 catches exp==iat.
    const future = Math.floor(Date.now() / 1000) + 120;
    await expect(
      validateContinuationAssertion(await mintICA({ iatSec: future, expSec: future }), ctx()),
    ).rejects.toThrow(/lifetime/);
  });

  it("cnf carrying an extra member", async () => {
    await expect(
      validateContinuationAssertion(await mintICA({ over: { cnf: { jkt, extra: 1 } } }), ctx()),
    ).rejects.toThrow(/cnf MUST contain exactly jkt/);
  });

  it("cnf missing entirely", async () => {
    await expect(
      validateContinuationAssertion(await mintICA({ omit: ["cnf"] }), ctx()),
    ).rejects.toThrow(/cnf MUST contain exactly jkt/);
  });

  it("cnf.jkt not matching the presenter key", async () => {
    await expect(
      validateContinuationAssertion(await mintICA(), { ...ctx(), presenterJkt: "different-jkt" }),
    ).rejects.toMatchObject({ code: "invalid_request" });
  });

  it("handle too short", async () => {
    await expect(
      validateContinuationAssertion(
        await mintICA({ over: { identity_continuation_handle: "tooshort" } }),
        ctx(),
      ),
    ).rejects.toThrow(/identity_continuation_handle/);
  });

  it("handle with a non-base64url character", async () => {
    await expect(
      validateContinuationAssertion(
        await mintICA({ over: { identity_continuation_handle: "ich_0123456789abcdefAB+D" } }),
        ctx(),
      ),
    ).rejects.toThrow(/identity_continuation_handle/);
  });

  it("each forbidden top-level claim", async () => {
    const forbidden: Record<string, unknown> = {
      sub: "alice",
      auth_time: 1,
      acr: "urn:acr",
      amr: ["pwd"],
      sid: "sess-1",
      scope: "read",
      resource: "https://rs",
      authorization_details: [{ type: "x" }],
      audience: "https://rs",
      requested_token_type: "urn:x",
    };
    for (const [claim, value] of Object.entries(forbidden)) {
      await expect(
        validateContinuationAssertion(await mintICA({ over: { [claim]: value } }), ctx()),
      ).rejects.toThrow(new RegExp(`MUST NOT carry ${claim}`));
    }
  });

  it("act carrying a nested act", async () => {
    await expect(
      validateContinuationAssertion(
        await mintICA({ over: { act: { iss: CA, sub: "agent-7", act: { iss: CA, sub: "inner" } } } }),
        ctx(),
      ),
    ).rejects.toThrow(/act MUST NOT carry act/);
  });

  it("act carrying a per-hop cnf", async () => {
    await expect(
      validateContinuationAssertion(
        await mintICA({ over: { act: { iss: CA, sub: "agent-7", cnf: { jkt } } } }),
        ctx(),
      ),
    ).rejects.toThrow(/act MUST NOT carry cnf/);
  });

  it("act missing sub", async () => {
    await expect(
      validateContinuationAssertion(await mintICA({ over: { act: { iss: CA } } }), ctx()),
    ).rejects.toThrow(/act missing non-empty sub/);
  });

  it("act missing entirely", async () => {
    await expect(
      validateContinuationAssertion(await mintICA({ omit: ["act"] }), ctx()),
    ).rejects.toThrow(/missing act/);
  });

  it("a jti the redeeming caller already consumed", async () => {
    // @spec issuance-grant#effective-set-projection (#617 review 1) — the
    // validator CHECKS single-use and records nothing: consumption is the
    // caller's, atomic with successful issuance (continuation-grant.ts step
    // 11). So a first validation does NOT burn the assertion; recordOnce does.
    const shared = ctx();
    const assertion = await mintICA();
    const first = await validateContinuationAssertion(assertion, shared);
    expect(shared.replay.seen(first.iss, first.jti)).toBe(false);
    expect(shared.replay.recordOnce(first.iss, first.jti)).toBe(true);
    expect(shared.replay.recordOnce(first.iss, first.jti)).toBe(false); // the atomic loser
    await expect(validateContinuationAssertion(assertion, shared)).rejects.toThrow(/replay/);
  });
});
