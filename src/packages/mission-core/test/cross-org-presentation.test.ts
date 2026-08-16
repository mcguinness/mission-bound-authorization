/**
 * @spec cross-org-delegation#chain-presentation — the Chain Presentation
 * parser (closure, bounds, hop alignment) and the chain digest determinism.
 */
import { describe, expect, it } from "vitest";
import { ChainPresentationError, chainDigest, parseChainPresentation } from "../src/index.js";

const BOUNDS = { maxHops: 4, maxBytes: 100_000 };
const JWS = "aaa.bbb.ccc";
function enc(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj), "utf8").toString("base64url");
}

describe("Chain Presentation parsing (@spec cross-org-delegation#chain-presentation)", () => {
  it("parses a well-formed presentation with aligned actor credentials", () => {
    const p = parseChainPresentation(
      enc({
        chain: [JWS, JWS],
        actor_credentials: [{ hop: 1, type: "workload-attestation+jwt", credential: "x.y.z" }],
      }),
      BOUNDS,
    );
    expect(p.chain.length).toBe(2);
    expect(p.actor_credentials?.[0]?.hop).toBe(1);
  });

  it("refuses an unknown top-level member (closed envelope)", () => {
    expect(() => parseChainPresentation(enc({ chain: [JWS], extra: 1 }), BOUNDS)).toThrow(
      /unknown top-level member/,
    );
  });

  it("refuses an unknown actor_credentials member", () => {
    expect(() =>
      parseChainPresentation(
        enc({
          chain: [JWS],
          actor_credentials: [{ hop: 0, type: "t", credential: "c", who: "x" }],
        }),
        BOUNDS,
      ),
    ).toThrow(/unknown actor_credentials member/);
  });

  it("refuses a misaligned hop index", () => {
    expect(() =>
      parseChainPresentation(
        enc({ chain: [JWS], actor_credentials: [{ hop: 5, type: "t", credential: "c" }] }),
        BOUNDS,
      ),
    ).toThrow(/misaligned/);
  });

  it("refuses a typeless actor credential", () => {
    expect(() =>
      parseChainPresentation(
        enc({ chain: [JWS], actor_credentials: [{ hop: 0, credential: "c" }] }),
        BOUNDS,
      ),
    ).toThrow(/require a type/);
  });

  it("refuses a chain over the hop bound before parsing further", () => {
    expect(() => parseChainPresentation(enc({ chain: [JWS, JWS, JWS, JWS, JWS] }), BOUNDS)).toThrow(
      /hop bound/,
    );
  });

  it("refuses a presentation over the size bound", () => {
    expect(() =>
      parseChainPresentation(enc({ chain: [JWS] }), { maxHops: 4, maxBytes: 10 }),
    ).toThrow(/size bound/);
  });

  it("refuses a non-compact-JWS chain element", () => {
    expect(() => parseChainPresentation(enc({ chain: ["not-a-jws"] }), BOUNDS)).toThrow(
      /compact JWS/,
    );
  });

  it("refuses an empty chain", () => {
    expect(() => parseChainPresentation(enc({ chain: [] }), BOUNDS)).toThrow(/non-empty/);
  });

  it("refuses duplicate hop entries", () => {
    expect(() =>
      parseChainPresentation(
        enc({
          chain: [JWS],
          actor_credentials: [
            { hop: 0, type: "t", credential: "a" },
            { hop: 0, type: "t", credential: "b" },
          ],
        }),
        BOUNDS,
      ),
    ).toThrow(/duplicate hop/);
  });

  it("is a ChainPresentationError on malformed input", () => {
    expect(() => parseChainPresentation("!!!not-base64-json", BOUNDS)).toThrow(
      ChainPresentationError,
    );
  });
});

describe("chain digest (@spec cross-org-delegation#chain-presentation)", () => {
  it("is deterministic and order-sensitive", () => {
    const a = chainDigest([JWS, "d.e.f"]);
    expect(chainDigest([JWS, "d.e.f"])).toBe(a);
    expect(chainDigest(["d.e.f", JWS])).not.toBe(a);
    expect(a.startsWith("sha-256:")).toBe(true);
  });
});
