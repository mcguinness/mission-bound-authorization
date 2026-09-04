/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity; draft-mcguinness-mission-runtime.md#agent-isolated-evidence-emission
 * (issue #741, PR #753 review).
 *
 * The same boundary regression as
 * `services/mcp-payments/test/pep-emission-boundary.test.ts`, run against the
 * dependency object THIS deployment's real wiring supplies: `composeStack`
 * builds the decision point, hands the PEP its decision function and the
 * store's verification resolver, and keeps the emission path closed over
 * inside the decision point. A future wiring change that put an emitter back
 * on the enforcement side would pass every unit test and fail here.
 *
 * Needs a live OpenFGA (`composeStack` connects one), and skips when it is
 * unreachable, matching the other OpenFGA-dependent suites.
 */

import { describe, expect, it } from "vitest";
import type { Pep, PepDeps } from "@mission/mcp-payments";
import { composeStack } from "../src/stack.js";

const API_URL = process.env.OPENFGA_HTTP_URL ?? "https://localhost:8080";
const KEY = process.env.OPENFGA_PRESHARED_KEY ?? "dev-preshared-key-change-me";
const CA = process.env.OPENFGA_CA_CERT;

async function reachable(): Promise<boolean> {
  try {
    if (CA) process.env.NODE_EXTRA_CA_CERTS = CA;
    return (await fetch(`${API_URL}/healthz`, { headers: { authorization: `Bearer ${KEY}` } })).ok;
  } catch {
    return false;
  }
}
const up = await reachable();
const d = up ? describe : describe.skip;
if (!up) console.warn("OpenFGA unreachable; skipping the composed-stack emission-boundary test");

/** Values reachable from `root` that expose an `emit` function, by path; plain objects and arrays only. */
function reachableEmitters(root: unknown): string[] {
  const found: string[] = [];
  const seen = new WeakSet<object>();
  const visit = (value: unknown, path: string): void => {
    if (value === null || (typeof value !== "object" && typeof value !== "function")) return;
    const obj = value as Record<string, unknown>;
    if (seen.has(obj)) return;
    seen.add(obj);
    if (typeof obj.emit === "function") found.push(path);
    if (Array.isArray(value)) {
      value.forEach((v, i) => visit(v, `${path}[${i}]`));
      return;
    }
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) return;
    for (const [k, v] of Object.entries(obj)) visit(v, `${path}.${k}`);
  };
  visit(root, "deps");
  return found;
}

d("the composed stack hands its PEP no PDP emission capability (#741, PR #753 review)", () => {
  it("no value at any depth of the real PepDeps exposes an `emit` function, and there is no `decisionEvidence` member", async () => {
    const stack = await composeStack({ openfgaUrl: API_URL, presharedKey: KEY, ...(CA ? { caCertPath: CA } : {}) });
    const deps = (stack.pep as unknown as Pep & { deps: PepDeps }).deps;
    expect(reachableEmitters(deps)).toEqual([]);
    expect("decisionEvidence" in deps).toBe(false);
    // What it does hold: a decision function, and a store whose resolver
    // carries the decision point's PUBLIC key.
    expect(typeof deps.decide).toBe("function");
  });
});
