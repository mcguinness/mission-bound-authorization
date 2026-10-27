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

describe("step 7i: one atomic admit, after every other check (@spec AAT -02 Section 7.3 and Section 8 step 7i, #1756)", () => {
  const root = jws(anchor, ROOT_HEADER, rootClaims());
  const child = jws(holder, CHILD_HEADER, childOf(root));
  const presentTracked = (
    pop: string,
    argsJson: string,
    calls: [string, number][],
    answer: boolean,
  ) =>
    verifyAatPresentation({
      chain: [root, child],
      pop,
      tool: "read_file",
      argsJson,
      trustAnchors: anchors,
      now: NOW,
      policy: {
        audiences: [EP],
        replay: {
          trackJti: true,
          admit: (jti, iat) => {
            calls.push([jti, iat]);
            return answer;
          },
        },
      },
    });

  it("offers a verified proof to admit once, with its jti and iat, and denies when admit refuses it", () => {
    const pop = popFor(child);
    const popJti = JSON.parse(Buffer.from(pop.split(".")[1] as string, "base64url").toString()).jti;
    const calls: [string, number][] = [];
    expect(presentTracked(pop, '{"path":"/a"}', calls, true)).toMatchObject({ verdict: "PERMIT" });
    expect(calls).toEqual([[popJti, NOW]]);
    expect(presentTracked(pop, '{"path":"/a"}', [], false)).toMatchObject({
      verdict: "DENY",
      step: "7i",
    });
  });

  it("never offers a refused proof to admit", () => {
    const calls: [string, number][] = [];
    // The leaf allows only "/a", so the invocation is refused before step 7i.
    expect(presentTracked(popFor(child), '{"path":"/b"}', calls, true)).toMatchObject({
      verdict: "DENY",
    });
    expect(calls).toEqual([]);
  });
});

describe("hardening from the owner's review of #1775 (@spec AAT -02 Section 3.4, RFC 8785 Section 3.2.2.2, #1756)", () => {
  const rootWith = (tools: Record<string, unknown>) =>
    jws(
      anchor,
      ROOT_HEADER,
      rootClaims({ authorization_details: [{ type: "attenuating_agent_token", tools }] }),
    );
  const chainOnly = (chain: string[]) =>
    verifyAatChain({ chain, trustAnchors: anchors, now: NOW, policy });
  /** A PoP by the root's holder for `read_file` over `hta`, presented with `argsJson`. */
  const presentRoot = (root: string, hta: Record<string, unknown>, argsJson: string) =>
    verifyAatPresentation({
      chain: [root],
      pop: jws(
        holder,
        { alg: "Ed25519", typ: "aat-pop+jwt" },
        {
          jti: `pop-${Math.random()}`,
          iat: NOW,
          aat_id: "root-1",
          aat_hash: hash(root),
          aat_tool: "read_file",
          aat_aud: EP,
          hta,
        },
      ),
      tool: "read_file",
      argsJson,
      trustAnchors: anchors,
      now: NOW,
      policy,
    });

  it.each(["constructor", "__proto__", "toString", "hasOwnProperty"])(
    "refuses a %s constraint_type, with or without members, rather than resolving it through Object.prototype",
    (type) => {
      expect(
        chainOnly([rootWith({ read_file: { path: { constraint_type: type } } })]),
      ).toMatchObject({
        verdict: "DENY",
        step: "3n",
      });
      expect(
        chainOnly([rootWith({ read_file: { path: { constraint_type: type, value: "/a" } } })]),
      ).toMatchObject({ verdict: "DENY", step: "3n" });
      // A holder adds it under a wildcard parent, which would subsume any supported type.
      const root = rootWith({ read_file: { path: { constraint_type: "wildcard" } } });
      const child = jws(
        holder,
        CHILD_HEADER,
        childOf(root, {
          authorization_details: [
            {
              type: "attenuating_agent_token",
              tools: { read_file: { path: { constraint_type: type } } },
            },
          ],
        }),
      );
      expect(chainOnly([root, child])).toMatchObject({ verdict: "DENY", step: "4o" });
    },
  );

  it("refuses a lone surrogate in an argument value or property name even when hta carries the same one", () => {
    const wildcardPath = rootWith({ read_file: { path: { constraint_type: "wildcard" } } });
    expect(presentRoot(wildcardPath, { path: "\ud800" }, '{"path":"\\ud800"}')).toMatchObject({
      verdict: "DENY",
      step: "7f",
    });
    const anyArgument = rootWith({ read_file: { "*": { constraint_type: "wildcard" } } });
    expect(presentRoot(anyArgument, { "\udc00": "x" }, '{"\\udc00":"x"}')).toMatchObject({
      verdict: "DENY",
      step: "7f",
    });
    // An exact constraint compares by JCS too, so the argument check refuses first.
    const exactPath = rootWith({
      read_file: { path: { constraint_type: "exact", value: "\ud800" } },
    });
    expect(presentRoot(exactPath, { path: "\ud800" }, '{"path":"\\ud800"}')).toMatchObject({
      verdict: "DENY",
      step: "6b",
    });
    // A well-formed surrogate pair is ordinary text and still permits.
    expect(presentRoot(wildcardPath, { path: "😀" }, '{"path":"\\ud83d\\ude00"}')).toMatchObject({
      verdict: "PERMIT",
    });
  });

  it("refuses a lone surrogate in an exact constraint at the subsumption check", () => {
    const exact = { read_file: { path: { constraint_type: "exact", value: "\ud800" } } };
    const root = rootWith(exact);
    const child = jws(
      holder,
      CHILD_HEADER,
      childOf(root, { authorization_details: [{ type: "attenuating_agent_token", tools: exact }] }),
    );
    expect(chainOnly([root, child])).toMatchObject({ verdict: "DENY", step: "4p4" });
  });
});
