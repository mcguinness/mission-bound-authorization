/**
 * @spec AAT -02 Section 8 (#1756): the published -02 test vector suite run
 * through the substrate verifier. Each vector's presentation (`aat_chain`,
 * `aat_pop`) is verified for its tool and `args_json` at its `now`, under the
 * suite's trust anchors and params with the vector's own params and policy
 * over them. Verdicts are compared, not failing steps: Section 8 permits some
 * steps to be reordered (the suite's INTEROP.md). Provenance and license are
 * in test/vectors/aat/README.md.
 */

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { type AatParams, type AatPolicy, verifyAatPresentation } from "../src/index.js";

interface Vector {
  id: string;
  title: string;
  now: number;
  tool: string;
  args_json: string;
  policy: {
    require_pop_aud?: boolean;
    require_chain_aud?: boolean;
    nonce?: string;
    track_pop_jti?: boolean;
  };
  params: Record<string, number>;
  replay_state: { before: string[]; after: string[] } | null;
  presentation: { aat_chain: string[]; aat_pop: string };
  expected: { verdict: "PERMIT" | "DENY"; step: string | null };
}
interface Suite {
  spec: string;
  params: Record<string, number | string>;
  trust_anchors: { iss: string; jwk: Record<string, unknown> }[];
  vectors: Vector[];
}

const suite = JSON.parse(
  readFileSync(new URL("./vectors/aat/aat-jws-vectors.json", import.meta.url), "utf8"),
) as Suite;

/** Vectors not run, by id, with the reason. None: every vector of the pinned suite applies. */
const EXCLUDED: Readonly<Record<string, string>> = {};

function paramsOf(v: Vector): Partial<AatParams> {
  const s = { ...suite.params, ...v.params } as Record<string, number>;
  return {
    maxIatSkew: s.max_iat_skew as number,
    maxTokenLifetime: s.max_token_lifetime as number,
    maxDelegationDepth: s.max_delegation_depth as number,
    maxConstraintDepth: s.max_constraint_depth as number,
    maxTokenSize: s.max_token_size as number,
    maxChainSize: s.max_chain_size as number,
    popWindow: s.pop_window as number,
  };
}

function run(v: Vector): {
  verdict: string;
  step?: string;
  reason?: string;
  replayAfter: string[] | undefined;
} {
  const accepted = new Set(v.replay_state?.before ?? []);
  const policy: AatPolicy = {
    audiences: [suite.params.audience as string],
    ...(v.policy.require_pop_aud ? { requirePopAud: true } : {}),
    ...(v.policy.require_chain_aud ? { requireChainAud: true } : {}),
    ...(v.policy.nonce !== undefined ? { acceptNonce: (n: string) => n === v.policy.nonce } : {}),
    ...(v.policy.track_pop_jti
      ? {
          replay: {
            trackJti: true,
            seen: (jti: string) => accepted.has(jti),
            record: (jti: string) => void accepted.add(jti),
          },
        }
      : {}),
  };
  const r = verifyAatPresentation({
    chain: v.presentation.aat_chain,
    pop: v.presentation.aat_pop,
    tool: v.tool,
    argsJson: v.args_json,
    trustAnchors: suite.trust_anchors.map((a) => ({ issuer: a.iss, jwk: a.jwk })),
    now: v.now,
    params: paramsOf(v),
    policy,
  });
  return {
    verdict: r.verdict,
    ...(r.verdict === "DENY" ? { step: r.step, reason: r.reason } : {}),
    replayAfter: v.policy.track_pop_jti ? [...accepted].sort() : undefined,
  };
}

describe(`AAT -02 vector suite (${suite.spec}, ${suite.vectors.length} vectors) through verifyAatPresentation (@spec AAT -02 Section 8, #1756)`, () => {
  it("pins the suite: 229 vectors, 54 PERMIT and 175 DENY", () => {
    expect(suite.spec).toBe("draft-niyikiza-oauth-attenuating-agent-tokens-02");
    expect(suite.vectors).toHaveLength(229);
    expect(suite.vectors.filter((v) => v.expected.verdict === "PERMIT")).toHaveLength(54);
  });

  it.each(suite.vectors.filter((v) => !(v.id in EXCLUDED)).map((v) => [v.id, v.title, v] as const))(
    "%s %s",
    (_id, _title, v) => {
      const got = run(v);
      expect({
        verdict: got.verdict,
        ...(got.verdict === "DENY" ? { step: got.step, reason: got.reason } : {}),
      }).toMatchObject({
        verdict: v.expected.verdict,
      });
      if (v.replay_state) expect(got.replayAfter).toEqual([...v.replay_state.after].sort());
    },
  );
});
