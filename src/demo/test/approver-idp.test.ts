/**
 * @spec mission#approval-authentication (#1320, D496) — the reference
 * upstream OpenID Provider authenticates the Approver for real: a password
 * checked against its stored hash, then a one-time code it delivers to the
 * account's enrolled device. The `acr` in its ID Token is what that
 * authentication established: `mfa` only after both factors, `pwd` after the
 * password alone. A wrong password or code completes no login, and a code
 * completes at most one.
 *
 * The relying party here is the test, over the provider's own endpoints: an
 * authorization code request with PKCE and a nonce, the login, and the token
 * request with the client's credentials.
 */
import { createHash, randomBytes } from "node:crypto";
import { decodeJwt } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type ApproverAccount, type ApproverIdp, startApproverIdp } from "../src/approver-idp.js";

const REDIRECT_URI = "http://localhost:9/approver-login/callback";
let idp: ApproverIdp;
let bob: ApproverAccount;

beforeAll(async () => {
  idp = await startApproverIdp({ redirectUri: REDIRECT_URI, accounts: [{ sub: "idp-bob", username: "bob@acme.example" }] });
  bob = idp.accounts.get("bob@acme.example") as ApproverAccount;
});
afterAll(() => idp?.close());

type Jar = Map<string, string>;
const cookieOf = (jar: Jar) => [...jar].map(([k, v]) => `${k}=${v}`).join("; ");
const keep = (jar: Jar, res: Response) => {
  for (const line of res.headers.getSetCookie()) {
    const [pair] = line.split(";");
    const eq = (pair as string).indexOf("=");
    jar.set((pair as string).slice(0, eq), (pair as string).slice(eq + 1));
  }
};

/** One login in its own user agent: the authorization request, then the provider's login page. */
async function begin() {
  const jar: Jar = new Map();
  const verifier = randomBytes(32).toString("base64url");
  const nonce = randomBytes(16).toString("base64url");
  const meta = (await (await fetch(`${idp.issuer}/.well-known/openid-configuration`)).json()) as Record<string, string>;
  const auth = new URL(meta.authorization_endpoint as string);
  for (const [k, v] of Object.entries({
    client_id: idp.client.clientId,
    response_type: "code",
    scope: "openid",
    redirect_uri: REDIRECT_URI,
    state: randomBytes(16).toString("base64url"),
    nonce,
    code_challenge: createHash("sha256").update(verifier).digest("base64url"),
    code_challenge_method: "S256",
    prompt: "login",
    acr_values: "mfa",
  })) {
    auth.searchParams.set(k, v);
  }
  const res = await fetch(auth, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
  keep(jar, res);
  const page = new URL(res.headers.get("location") as string, idp.issuer);
  const post = async (step: string, body: Record<string, string>) => {
    const r = await fetch(new URL(`${page.pathname}/${step}`, idp.issuer), {
      method: "POST",
      redirect: "manual",
      headers: { "content-type": "application/x-www-form-urlencoded", cookie: cookieOf(jar) },
      body: new URLSearchParams(body).toString(),
    });
    keep(jar, r);
    return r;
  };
  /** Follow the provider's redirects to the client's redirect URI, then redeem the code: the ID Token's claims. */
  const finish = async (res0: Response) => {
    let r = res0;
    let location = r.headers.get("location") ?? "";
    while (location.startsWith(idp.issuer)) {
      r = await fetch(location, { redirect: "manual", headers: { cookie: cookieOf(jar) } });
      keep(jar, r);
      location = r.headers.get("location") ?? "";
    }
    const back = new URL(location);
    if (!back.searchParams.get("code")) return { error: back.searchParams.get("error") };
    const token = await fetch(meta.token_endpoint as string, {
      method: "POST",
      headers: {
        authorization: `Basic ${Buffer.from(`${idp.client.clientId}:${idp.client.clientSecret}`).toString("base64")}`,
        "content-type": "application/x-www-form-urlencoded",
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code: back.searchParams.get("code") as string,
        redirect_uri: REDIRECT_URI,
        code_verifier: verifier,
      }).toString(),
    });
    const body = (await token.json()) as { id_token: string };
    return { claims: decodeJwt(body.id_token), nonce };
  };
  return { post, finish };
}

describe("the reference upstream OpenID Provider authenticates the Approver (@spec mission#approval-authentication, #1320, D496)", () => {
  it("asserts mfa only after the password and the one-time code its device received: the ID Token carries acr mfa and the auth_time of that login", async () => {
    const before = idp.logins.length;
    const login = await begin();
    expect((await login.post("password", { username: bob.username, password: bob.password })).status).toBe(200);
    const code = bob.device.latest() as string;
    expect(code).toMatch(/^\d{6}$/);
    const done = await login.finish(await login.post("code", { code }));
    expect(idp.logins.slice(before)).toEqual([{ sub: "idp-bob", factors: ["pwd", "otp"], acr: "mfa", auth_time: done.claims?.auth_time }]);
    expect(done.claims).toMatchObject({ iss: idp.issuer, sub: "idp-bob", aud: idp.client.clientId, acr: "mfa", nonce: done.nonce });
    expect(Math.abs((done.claims?.auth_time as number) - Math.floor(Date.now() / 1000))).toBeLessThanOrEqual(2);
  });

  it("asserts pwd for a password-only login, never mfa", async () => {
    const before = idp.logins.length;
    const login = await begin();
    expect((await login.post("password", { username: bob.username, password: bob.password })).status).toBe(200);
    const done = await login.finish(await login.post("skip", {}));
    expect(done.claims?.acr).toBe("pwd");
    expect(idp.logins.slice(before)).toEqual([{ sub: "idp-bob", factors: ["pwd"], acr: "pwd", auth_time: done.claims?.auth_time }]);
  });

  it("refuses a wrong password: no code is delivered, the second factor is not reachable, and no login completes", async () => {
    const before = idp.logins.length;
    const delivered = bob.device.latest();
    const login = await begin();
    expect((await login.post("password", { username: bob.username, password: `${bob.password}x` })).status).toBe(401);
    expect(bob.device.latest()).toBe(delivered);
    expect((await login.post("skip", {})).status).toBe(401);
    expect(idp.logins.length).toBe(before);
  });

  it("refuses a wrong one-time code and ends the login after the third, completing no login", async () => {
    const before = idp.logins.length;
    const login = await begin();
    await login.post("password", { username: bob.username, password: bob.password });
    const right = bob.device.latest() as string;
    const wrong = right === "000000" ? "000001" : "000000";
    expect((await login.post("code", { code: wrong })).status).toBe(401);
    expect((await login.post("code", { code: wrong })).status).toBe(401);
    const ended = await login.finish(await login.post("code", { code: wrong }));
    expect(ended).toEqual({ error: "access_denied" });
    expect(idp.logins.length).toBe(before);
  });

  it("completes at most one login with a one-time code: the same code presented again completes nothing", async () => {
    const before = idp.logins.length;
    const login = await begin();
    await login.post("password", { username: bob.username, password: bob.password });
    const code = bob.device.latest() as string;
    expect((await login.post("code", { code })).status).toBe(303);
    expect((await login.post("code", { code })).status).toBe(401);
    expect(idp.logins.length).toBe(before + 1);
  });
});
