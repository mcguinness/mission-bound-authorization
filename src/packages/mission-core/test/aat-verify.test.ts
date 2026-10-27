/**
 * @spec AAT -02 Sections 3.4, 3.5 and 8 (#1756, D882): substrate verifier
 * cases the published vectors do not cover. The suite signs everything with
 * Ed25519; the reference AS signs roots with ES256, so these mint an ES256
 * trust anchor over Ed25519 holders. The vectors already prove the Ed25519
 * forms of the owner's D882 items: a header `jwk` is ignored (J.7.13, J.7.14)
 * and never trusted (J.14.c), unrecognized claims are ignored (J.27.1), and an
 * unsupported constraint type is refused (J.8.3, J.8.5).
 */

import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  type AatPolicy,
  aatJwkThumbprintUri,
  verifyAatChain,
  verifyAatPresentation,
} from "../src/index.js";

const NOW = 1_800_000_000;
const EP = "https://tools.example.com";
const ISSUER = "https://as.example.com";

type Keys = { privateKey: KeyObject; jwk: Record<string, unknown> };
const ed = (): Keys => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, jwk: publicKey.export({ format: "jwk" }) as Record<string, unknown> };
};
const ec = (): Keys => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  return { privateKey, jwk: publicKey.export({ format: "jwk" }) as Record<string, unknown> };
};
const b64 = (o: unknown): string => Buffer.from(JSON.stringify(o)).toString("base64url");

function jws(
  signer: Keys,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): string {
  const input = `${b64(header)}.${b64(payload)}`;
  const data = Buffer.from(input, "ascii");
  const sig =
    signer.jwk.kty === "EC"
      ? sign("sha256", data, { key: signer.privateKey, dsaEncoding: "ieee-p1363" })
      : sign(null, data, signer.privateKey);
  return `${input}.${sig.toString("base64url")}`;
}
const alg = (k: Keys): string => (k.jwk.kty === "EC" ? "ES256" : "Ed25519");
const hash = (token: string): string =>
  createHash("sha256").update(token.split(".").slice(0, 2).join("."), "ascii").digest("base64url");

const anchor = ec();
const holder = ed();
const worker = ed();
const attacker = ec();
const TOOLS = { read_file: { path: { constraint_type: "one_of", values: ["/a", "/b"] } } };
const LEAF_TOOLS = { read_file: { path: { constraint_type: "exact", value: "/a" } } };

function rootClaims(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    jti: "root-1",
    iss: ISSUER,
    iat: NOW - 60,
    exp: NOW + 600,
    aud: EP,
    del_depth: 0,
    del_max_depth: 2,
    cnf: { jwk: holder.jwk },
    authorization_details: [{ type: "attenuating_agent_token", tools: TOOLS }],
    ...extra,
  };
}
function childOf(root: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    jti: "child-1",
    iss: aatJwkThumbprintUri(holder.jwk),
    iat: NOW - 30,
    exp: NOW + 300,
    del_depth: 1,
    del_max_depth: 2,
    par_hash: hash(root),
    cnf: { jwk: worker.jwk },
    authorization_details: [{ type: "attenuating_agent_token", tools: LEAF_TOOLS }],
    ...extra,
  };
}
function popFor(leaf: string, signer: Keys = worker): string {
  const claims = {
    jti: `pop-${Math.random()}`,
    iat: NOW,
    aat_id: JSON.parse(Buffer.from(leaf.split(".")[1] as string, "base64url").toString()).jti,
    aat_hash: hash(leaf),
    aat_tool: "read_file",
    aat_aud: EP,
    hta: { path: "/a" },
  };
  return jws(signer, { alg: alg(signer), typ: "aat-pop+jwt" }, claims);
}

const anchors = [{ issuer: ISSUER, jwk: anchor.jwk }];
const policy: AatPolicy = { audiences: [EP] };
const present = (chain: string[], pop: string) =>
  verifyAatPresentation({
    chain,
    pop,
    tool: "read_file",
    argsJson: '{"path":"/a"}',
    trustAnchors: anchors,
    now: NOW,
    policy,
  });

const ROOT_HEADER = { alg: "ES256", typ: "aat+jwt" };
const CHILD_HEADER = { alg: "Ed25519", typ: "aat+jwt" };

describe("the substrate verifier with an ES256 trust anchor over Ed25519 holders (@spec AAT -02 Section 8, #1756)", () => {
  it("permits a two-token chain and returns its claims, including ones the substrate does not define", () => {
    const root = jws(
      anchor,
      ROOT_HEADER,
      rootClaims({ mission: { id: "msn_1", issuer: ISSUER }, sub: "alice" }),
    );
    const child = jws(holder, CHILD_HEADER, childOf(root));
    const r = present([root, child], popFor(child));
    expect(r).toMatchObject({ verdict: "PERMIT", anchorIssuer: ISSUER });
    // Unrecognized claims are ignored by the substrate and handed to the profile layer.
    expect(r.verdict === "PERMIT" && r.root.claims.mission).toEqual({
      id: "msn_1",
      issuer: ISSUER,
    });
    expect(r.verdict === "PERMIT" && r.leaf.tools).toEqual(LEAF_TOOLS);
  });

  it("ignores a header jwk on a validly signed ES256 root, and never verifies under it", () => {
    const withHeaderKey = jws(anchor, { ...ROOT_HEADER, jwk: attacker.jwk }, rootClaims());
    expect(present([withHeaderKey], popFor(withHeaderKey, holder))).toMatchObject({
      verdict: "PERMIT",
    });
    const forged = jws(attacker, { ...ROOT_HEADER, jwk: attacker.jwk }, rootClaims());
    expect(present([forged], popFor(forged, holder))).toMatchObject({
      verdict: "DENY",
      step: "3b",
    });
  });

  it("refuses a child verifiable only under the key its own header carries (I1)", () => {
    const root = jws(anchor, ROOT_HEADER, rootClaims());
    const child = jws(worker, { ...CHILD_HEADER, jwk: worker.jwk }, childOf(root));
    expect(present([root, child], popFor(child))).toMatchObject({ verdict: "DENY", step: "4b" });
  });

  it("refuses an ES256 alg on a child whose parent holds an Ed25519 key", () => {
    const root = jws(anchor, ROOT_HEADER, rootClaims());
    const child = jws(holder, { alg: "ES256", typ: "aat+jwt" }, childOf(root));
    expect(present([root, child], popFor(child))).toMatchObject({ verdict: "DENY", step: "4a" });
  });
});

describe("verifyAatChain: a chain with no invocation (@spec AAT -02 Section 8 steps 1 to 5 and 6c, #1756)", () => {
  const root = jws(anchor, ROOT_HEADER, rootClaims());
  const child = jws(holder, CHILD_HEADER, childOf(root));

  it("permits a valid chain and refuses one whose audience does not name this verifier", () => {
    expect(
      verifyAatChain({ chain: [root, child], trustAnchors: anchors, now: NOW, policy }),
    ).toMatchObject({ verdict: "PERMIT" });
    expect(
      verifyAatChain({
        chain: [root, child],
        trustAnchors: anchors,
        now: NOW,
        policy: { audiences: ["https://other.example"] },
      }),
    ).toMatchObject({ verdict: "DENY", step: "6c" });
  });

  it("refuses a child narrowed to another audience even though its parent names this verifier", () => {
    const elsewhere = jws(holder, CHILD_HEADER, childOf(root, { aud: "https://other.example" }));
    expect(
      verifyAatChain({ chain: [root, elsewhere], trustAnchors: anchors, now: NOW, policy }),
    ).toMatchObject({
      verdict: "DENY",
      step: "6c",
    });
  });

  it("refuses a chain with no aud anywhere when chain audience is required", () => {
    const { aud: _aud, ...noAud } = rootClaims();
    const unscoped = jws(anchor, ROOT_HEADER, noAud);
    expect(
      verifyAatChain({ chain: [unscoped], trustAnchors: anchors, now: NOW, policy }),
    ).toMatchObject({ verdict: "PERMIT" });
    expect(
      verifyAatChain({
        chain: [unscoped],
        trustAnchors: anchors,
        now: NOW,
        policy: { audiences: [EP], requireChainAud: true },
      }),
    ).toMatchObject({ verdict: "DENY", step: "6c" });
  });
});
