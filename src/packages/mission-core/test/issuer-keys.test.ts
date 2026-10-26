import { generateKeyPairSync, type KeyObject } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  explicitFreshnessSeconds,
  IssuerKeyError,
  IssuerKeys,
  type IssuerKeysFetch,
  keyThumbprint,
} from "../src/index.js";

// #831 C1: an issuer's keys as a consumer holds them. Trust from
// configuration, freshness only from the response, revalidation before
// reuse with no stale fallback, replacement on every fetch, and a bounded
// refresh for an unknown trusted key.

const JWKS_URI = "https://as.example/jwks";

/** A public EC key under `kid`, with its algorithm. */
function key(kid: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const jwk = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey.export({
    format: "jwk",
  });
  return { ...jwk, kid, alg: "ES256", use: "sig", ...extra };
}

type Answer =
  | { status?: number; keys?: Record<string, unknown>[]; headers?: Record<string, string> }
  | Error
  | "hang";

/** A fetch that answers `answers` in turn (the last repeats), recording each request's headers. */
function issuer(...answers: Answer[]): {
  fetch: IssuerKeysFetch;
  requests: Record<string, string>[];
} {
  const requests: Record<string, string>[] = [];
  let i = 0;
  const fetch: IssuerKeysFetch = (_url, init) => {
    requests.push(init.headers);
    const answer = answers[Math.min(i++, answers.length - 1)] as Answer;
    if (answer instanceof Error) return Promise.reject(answer);
    if (answer === "hang") {
      return new Promise((_resolve, reject) =>
        init.signal.addEventListener("abort", () => reject(new Error("aborted"))),
      );
    }
    const status = answer.status ?? 200;
    return Promise.resolve(
      new Response(status === 304 ? null : JSON.stringify({ keys: answer.keys ?? [] }), {
        status,
        headers: answer.headers ?? {},
      }),
    );
  };
  return { fetch, requests };
}

const fresh = (seconds: number, etag?: string) => ({
  "cache-control": `max-age=${seconds}`,
  ...(etag ? { etag } : {}),
});

function clock(start = 1_000_000): { now: () => number; advance: (s: number) => void } {
  let t = start;
  return {
    now: () => t,
    advance: (s) => {
      t += s * 1000;
    },
  };
}

const refusal = (code: string) => expect.objectContaining({ name: "IssuerKeyError", code });
const material = (k: KeyObject) => JSON.stringify(k.export({ format: "jwk" }));
const publicOf = (jwk: Record<string, unknown>) => {
  const { kid: _k, alg: _a, use: _u, ...rest } = jwk;
  return JSON.stringify(rest);
};

describe("an issuer's freshness, as the response declares it (RFC 9111 4.2.1, 4.2.2)", () => {
  it("is max-age less Age, and nothing when the response declares none, forbids reuse, or conflicts", () => {
    const h = (v: Record<string, string>) => new Headers(v);
    expect(explicitFreshnessSeconds(h({ "cache-control": "max-age=300" }))).toBe(300);
    expect(
      explicitFreshnessSeconds(h({ "cache-control": "public, max-age=300", age: "100" })),
    ).toBe(200);
    expect(explicitFreshnessSeconds(h({ "cache-control": 'max-age="60"' }))).toBe(60);
    expect(explicitFreshnessSeconds(h({ "cache-control": "max-age=30", age: "45" }))).toBe(0);
    expect(explicitFreshnessSeconds(h({}))).toBe(0);
    expect(explicitFreshnessSeconds(h({ expires: "Wed, 21 Oct 2099 07:28:00 GMT" }))).toBe(0);
    expect(explicitFreshnessSeconds(h({ "cache-control": "max-age=300, no-store" }))).toBe(0);
    expect(explicitFreshnessSeconds(h({ "cache-control": "no-cache, max-age=300" }))).toBe(0);
    expect(explicitFreshnessSeconds(h({ "cache-control": "max-age=300, max-age=60" }))).toBe(0);
    expect(explicitFreshnessSeconds(h({ "cache-control": "max-age=five" }))).toBe(0);
  });
});

describe("an issuer's keys under a consumer's trusted roles (@spec #831 C1)", () => {
  const roles = {
    accessToken: { kids: ["as-token", "as-token-2"], algs: ["ES256"] },
    status: { kids: ["as-status"], algs: ["ES256"] },
  };

  it("resolves a trusted kid to its key, and refuses an untrusted kid, no kid or another algorithm without fetching", async () => {
    const t1 = key("as-token");
    const { fetch, requests } = issuer({
      keys: [t1, key("as-status"), key("as-txn")],
      headers: fresh(300),
    });
    const keys = new IssuerKeys({ jwksUri: JWKS_URI, roles, fetch, now: clock().now });
    const access = keys.resolver("accessToken");
    // Published, but trusted only for another role, or not at all: never this role's key.
    await expect(access({ kid: "as-status", alg: "ES256" })).rejects.toEqual(
      refusal("untrusted_kid"),
    );
    await expect(access({ kid: "as-txn", alg: "ES256" })).rejects.toEqual(refusal("untrusted_kid"));
    await expect(access({ alg: "ES256" })).rejects.toEqual(refusal("no_kid"));
    await expect(access({ kid: "as-token", alg: "RS256" })).rejects.toEqual(refusal("algorithm"));
    expect(requests).toHaveLength(0);
    expect(
      material(
        await access({
          kid: "as-token",
          alg: "ES256",
          jku: "https://attacker.example/jwks",
        } as never),
      ),
    ).toBe(publicOf(t1));
    expect(requests).toHaveLength(1);
    expect(() => keys.resolver("transaction")).toThrow(/no role transaction/);
  });

  it("refuses a key published for another algorithm than the header's", async () => {
    const { fetch } = issuer({ keys: [key("as-token", { alg: "ES384" })], headers: fresh(300) });
    const keys = new IssuerKeys({
      jwksUri: JWKS_URI,
      roles: { accessToken: { kids: ["as-token"], algs: ["ES256", "ES384"] } },
      fetch,
    });
    await expect(keys.resolver("accessToken")({ kid: "as-token", alg: "ES256" })).rejects.toEqual(
      refusal("algorithm"),
    );
  });

  it("uses the set for the declared lifetime, then revalidates with its ETag before reuse; a 304 keeps it, a 200 replaces it", async () => {
    const t1 = key("as-token");
    const t2 = key("as-token-2");
    const c = clock();
    const { fetch, requests } = issuer(
      { keys: [t1], headers: fresh(300, '"7"') },
      { status: 304, headers: fresh(300, '"7"') },
      { keys: [t2], headers: fresh(300, '"8"') },
    );
    const access = new IssuerKeys({ jwksUri: JWKS_URI, roles, fetch, now: c.now }).resolver(
      "accessToken",
    );
    await access({ kid: "as-token", alg: "ES256" });
    c.advance(299);
    await access({ kid: "as-token", alg: "ES256" });
    expect(requests).toEqual([{}]);
    c.advance(1);
    expect(material(await access({ kid: "as-token", alg: "ES256" }))).toBe(publicOf(t1));
    expect(requests).toEqual([{}, { "if-none-match": '"7"' }]);
    c.advance(300);
    // Replaced, not added to: the withdrawn key stops verifying, the new one verifies.
    expect(material(await access({ kid: "as-token-2", alg: "ES256" }))).toBe(publicOf(t2));
    await expect(access({ kid: "as-token", alg: "ES256" })).rejects.toEqual(refusal("unknown_kid"));
  });

  it("treats a response that declares no freshness as stale when received: every later use revalidates", async () => {
    const { fetch, requests } = issuer({ keys: [key("as-token")], headers: { etag: '"1"' } });
    const access = new IssuerKeys({ jwksUri: JWKS_URI, roles, fetch, now: clock().now }).resolver(
      "accessToken",
    );
    for (let i = 0; i < 3; i++) await access({ kid: "as-token", alg: "ES256" });
    expect(requests).toHaveLength(3);
  });

  it("refuses current reliance when a stale set's revalidation fails, and never falls back to the stale set", async () => {
    const c = clock();
    const { fetch } = issuer(
      { keys: [key("as-token")], headers: fresh(60) },
      new Error("connection refused"),
      { status: 503 },
      { keys: [key("as-token")], headers: fresh(60) },
    );
    const access = new IssuerKeys({ jwksUri: JWKS_URI, roles, fetch, now: c.now }).resolver(
      "accessToken",
    );
    await access({ kid: "as-token", alg: "ES256" });
    c.advance(60);
    await expect(access({ kid: "as-token", alg: "ES256" })).rejects.toEqual(refusal("unavailable"));
    await expect(access({ kid: "as-token", alg: "ES256" })).rejects.toEqual(refusal("unavailable"));
    await access({ kid: "as-token", alg: "ES256" });
  });

  it("refreshes for an unknown trusted kid at most once per interval, and a failed refresh never admits it", async () => {
    const c = clock();
    const t2 = key("as-token-2");
    const { fetch, requests } = issuer(
      { keys: [key("as-token")], headers: fresh(300) },
      { keys: [key("as-token")], headers: fresh(300) },
      new Error("timeout"),
      { keys: [key("as-token"), t2], headers: fresh(300) },
    );
    const access = new IssuerKeys({
      jwksUri: JWKS_URI,
      roles,
      fetch,
      now: c.now,
      minRefreshIntervalMs: 10_000,
    }).resolver("accessToken");
    await access({ kid: "as-token", alg: "ES256" });
    // Not yet published: one refresh, then refused.
    await expect(access({ kid: "as-token-2", alg: "ES256" })).rejects.toEqual(
      refusal("unknown_kid"),
    );
    expect(requests).toHaveLength(2);
    // Within the interval: refused with no fetch.
    await expect(access({ kid: "as-token-2", alg: "ES256" })).rejects.toEqual(
      refusal("unknown_kid"),
    );
    expect(requests).toHaveLength(2);
    c.advance(10);
    await expect(access({ kid: "as-token-2", alg: "ES256" })).rejects.toEqual(
      refusal("unavailable"),
    );
    c.advance(10);
    expect(material(await access({ kid: "as-token-2", alg: "ES256" }))).toBe(publicOf(t2));
    expect(requests).toHaveLength(4);
  });

  it("shares one fetch among concurrent uses", async () => {
    const { fetch, requests } = issuer({
      keys: [key("as-token"), key("as-status")],
      headers: fresh(300),
    });
    const keys = new IssuerKeys({ jwksUri: JWKS_URI, roles, fetch, now: clock().now });
    await Promise.all([
      keys.resolver("accessToken")({ kid: "as-token", alg: "ES256" }),
      keys.resolver("status")({ kid: "as-status", alg: "ES256" }),
      keys.refresh(),
    ]);
    expect(requests).toHaveLength(1);
  });

  it("fails a fetch that does not complete in time", async () => {
    const { fetch } = issuer("hang");
    const access = new IssuerKeys({ jwksUri: JWKS_URI, roles, fetch, timeoutMs: 20 }).resolver(
      "accessToken",
    );
    await expect(access({ kid: "as-token", alg: "ES256" })).rejects.toEqual(refusal("unavailable"));
  });

  it("refuses a set that publishes one key for two roles, and a configuration that trusts one kid for two", async () => {
    const shared = key("as-token");
    const { fetch } = issuer({
      keys: [shared, { ...shared, kid: "as-status" }],
      headers: fresh(300),
    });
    const access = new IssuerKeys({ jwksUri: JWKS_URI, roles, fetch }).resolver("accessToken");
    await expect(access({ kid: "as-token", alg: "ES256" })).rejects.toThrow(
      /publishes one key for both accessToken and status/,
    );
    expect(
      () =>
        new IssuerKeys({
          jwksUri: JWKS_URI,
          roles: { a: { kids: ["k"], algs: ["ES256"] }, b: { kids: ["k"], algs: ["ES256"] } },
        }),
    ).toThrow(/kid k is trusted for both a and b/);
    expect(
      () => new IssuerKeys({ jwksUri: JWKS_URI, roles: { a: { kids: ["k"], algs: [] } } }),
    ).toThrow(/role a accepts no algorithm/);
    expect(new IssuerKeyError("unknown_kid", "x").code).toBe("unknown_kid");
  });
});

describe("a consumer's trusted roles, changed while it runs (@spec #831 C2 review)", () => {
  it("takes effect at the next resolution: a kid added verifies, a kid removed is refused, a resolver made earlier follows", async () => {
    const t1 = key("as-token");
    const t2 = key("as-token-2");
    const { fetch, requests } = issuer({ keys: [t1, t2], headers: fresh(300) });
    const keys = new IssuerKeys({
      jwksUri: JWKS_URI,
      roles: { accessToken: { kids: ["as-token"] } },
      fetch,
      now: clock().now,
    });
    const access = keys.resolver("accessToken");
    await access({ kid: "as-token", alg: "ES256" });
    // Published, but not yet trusted.
    await expect(access({ kid: "as-token-2", alg: "ES256" })).rejects.toEqual(
      refusal("untrusted_kid"),
    );
    keys.setRoles({ accessToken: { kids: ["as-token", "as-token-2"] } });
    expect(material(await access({ kid: "as-token-2", alg: "ES256" }))).toBe(publicOf(t2));
    keys.setRoles({ accessToken: { kids: ["as-token-2"] } });
    await expect(access({ kid: "as-token", alg: "ES256" })).rejects.toEqual(
      refusal("untrusted_kid"),
    );
    expect(material(await access({ kid: "as-token-2", alg: "ES256" }))).toBe(publicOf(t2));
    // Re-selected from the set already held: no fetch for a change of trust.
    expect(requests).toHaveLength(1);
  });

  it("refuses a replacement that would give one key to two roles, keeping the roles in force; a kid moved to another role stops resolving for the first", async () => {
    const shared = key("as-token");
    const { fetch } = issuer({
      keys: [shared, { ...shared, kid: "as-status" }, key("as-txn")],
      headers: fresh(300),
    });
    const keys = new IssuerKeys({
      jwksUri: JWKS_URI,
      roles: { accessToken: { kids: ["as-token"] }, status: { kids: ["as-txn"] } },
      fetch,
      now: clock().now,
    });
    const access = keys.resolver("accessToken");
    const status = keys.resolver("status");
    await access({ kid: "as-token", alg: "ES256" });
    expect(() =>
      keys.setRoles({ accessToken: { kids: ["as-token"] }, status: { kids: ["as-status"] } }),
    ).toThrow(/publishes one key for both accessToken and status/);
    expect(() => keys.setRoles({ accessToken: { kids: ["k"] }, status: { kids: ["k"] } })).toThrow(
      /kid k is trusted for both/,
    );
    // The roles in force are unchanged.
    await access({ kid: "as-token", alg: "ES256" });
    await expect(status({ kid: "as-status", alg: "ES256" })).rejects.toEqual(
      refusal("untrusted_kid"),
    );
    keys.setRoles({ accessToken: { kids: [] }, status: { kids: ["as-txn", "as-token"] } });
    await expect(access({ kid: "as-token", alg: "ES256" })).rejects.toEqual(
      refusal("untrusted_kid"),
    );
    await status({ kid: "as-token", alg: "ES256" });
  });
});

describe("a role's algorithms, from the consumer's policy or the published key (@spec #831 C2 review)", () => {
  it("accepts whatever the published key admits when the role lists none, and only the listed algorithms when it does", async () => {
    const p521 = generateKeyPairSync("ec", { namedCurve: "P-521" }).publicKey.export({
      format: "jwk",
    });
    const es512 = { ...p521, kid: "as-token", alg: "ES512", use: "sig" };
    const { fetch } = issuer({ keys: [es512], headers: fresh(300) });
    const open = new IssuerKeys({
      jwksUri: JWKS_URI,
      roles: { accessToken: { kids: ["as-token"] } },
      fetch,
    });
    expect(material(await open.resolver("accessToken")({ kid: "as-token", alg: "ES512" }))).toBe(
      publicOf(es512),
    );
    // The published key names its algorithm: another is refused even with no policy.
    await expect(open.resolver("accessToken")({ kid: "as-token", alg: "ES256" })).rejects.toEqual(
      refusal("algorithm"),
    );
    const narrow = new IssuerKeys({
      jwksUri: JWKS_URI,
      roles: { accessToken: { kids: ["as-token"], algs: ["ES256"] } },
      fetch,
    });
    await expect(narrow.resolver("accessToken")({ kid: "as-token", alg: "ES512" })).rejects.toEqual(
      refusal("algorithm"),
    );
  });
});

describe("the trusted keys' thumbprints, for keeping two sources apart (@spec #831 C2 review)", () => {
  it("are the fresh set's trusted keys with their roles, and refuse when the set cannot be revalidated", async () => {
    const c = clock();
    const t1 = key("as-token");
    const { fetch } = issuer(
      { keys: [t1, key("as-txn"), key("other")], headers: fresh(60) },
      new Error("down"),
    );
    const keys = new IssuerKeys({
      jwksUri: JWKS_URI,
      roles: { accessToken: { kids: ["as-token"] }, transactionToken: { kids: ["as-txn"] } },
      fetch,
      now: c.now,
    });
    const prints = await keys.trustedThumbprints();
    expect([...prints.values()].sort()).toEqual(["accessToken", "transactionToken"]);
    const t1Print = keyThumbprint(
      await keys.resolver("accessToken")({ kid: "as-token", alg: "ES256" }),
    );
    expect(prints.get(t1Print as string)).toBe("accessToken");
    c.advance(60);
    await expect(keys.trustedThumbprints()).rejects.toEqual(refusal("unavailable"));
  });
});
