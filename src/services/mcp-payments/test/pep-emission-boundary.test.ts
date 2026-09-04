/**
 * @spec draft-mcguinness-mission-runtime-evidence.md#decision-evidence-object,
 * #decision-evidence-integrity; draft-mcguinness-mission-runtime.md#agent-isolated-evidence-emission
 * (issue #741, PR #753 review).
 *
 * The regression for the boundary itself: the enforcement-side dependency
 * graph exposes no reachable PDP emission capability. Holding an emitter is a
 * signing capability even without the raw key, because `emit` takes the
 * Mission, subject, resource, action, audience, decision, conditions, and
 * denial reason from its caller and signs them under the decision point's
 * identity. So it is not enough that the PEP does not CALL one; it must not
 * be able to reach one.
 *
 * Three independent checks, because each catches what the others cannot: a
 * walk of the dependency object the PEP actually retained (a value handed in
 * at wiring), the enforcement package's own runtime export surface, and a
 * static scan of every enforcement source file (the only one of the three
 * that sees TYPE-only imports, which leave no runtime trace).
 *
 * Unconditional: no OpenFGA, no network. `src/demo/test/pep-emission-boundary.test.ts`
 * runs the same walk against the real composed stack.
 */

import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Fga } from "@mission/pdp";
import * as api from "../src/index.js";
import {
  CANONICAL_RESOURCE,
  createEphemeralEvidenceKeys,
  EvidenceStore,
  PaymentsStore,
  Pep,
  type PepDeps,
  sourceDigestOf,
} from "../src/index.js";

/**
 * Every value reachable from `root` that exposes an `emit` function, by path.
 * Recurses through plain objects and arrays only: a class instance is CHECKED
 * (an emitter handed in under any name is caught) but not descended into, so
 * an unrelated event emitter buried inside a client library is not reported as
 * a boundary violation. Functions are checked too: a closure carrying an
 * `emit` property is exactly the shape this test exists to reject.
 */
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
    const isPlain = proto === Object.prototype || proto === null;
    if (!isPlain) return;
    for (const [k, v] of Object.entries(obj)) visit(v, `${path}.${k}`);
  };
  visit(root, "deps");
  return found;
}

/** The dependencies this deployment's PEP is wired with, as the stack wires them. */
function pepDeps(): PepDeps {
  const keys = createEphemeralEvidenceKeys();
  return {
    payments: new PaymentsStore(),
    evidence: new EvidenceStore(keys.signing, keys.resolver),
    decide: keys.decide,
    fga: { checkWithContext: async () => true } as unknown as Fga,
    modelId: "unit-test-model",
    loadView: () => undefined,
    instanceEpoch: "epoch-1",
    sourceDigest: sourceDigestOf({ name: "payments" }),
    allowedFreshnessSources: new Set(["load_view"]),
    requiresActionApproval: (action) => action === "payments:remittance.send",
    observe: () => {},
  };
}

describe("the enforcement-side dependency graph has no reachable PDP emission capability (#741, PR #753 review)", () => {
  it("no value at any depth of the PEP's retained dependencies exposes an `emit` function", () => {
    const pep = new Pep(pepDeps());
    // The object the PEP itself holds, not a copy built for the assertion.
    const retained = (pep as unknown as { deps: PepDeps }).deps;
    expect(reachableEmitters(retained)).toEqual([]);
  });

  it("the dependency surface has no `decisionEvidence` seam to pass an emitter through", () => {
    const deps = pepDeps();
    expect("decisionEvidence" in deps).toBe(false);
    // The decision capability it DOES hold is a function that answers a
    // request, with no properties to reach an emission path through.
    expect(typeof deps.decide).toBe("function");
    expect(reachableEmitters(deps.decide)).toEqual([]);
  });

  it("the enforcement package's runtime exports include no emitter constructor", () => {
    const exported = Object.keys(api);
    expect(exported).not.toContain("createDecisionEvidenceEmitter");
    for (const name of exported) {
      const value = (api as Record<string, unknown>)[name];
      const isEmitterShaped =
        value !== null && typeof value === "object" && typeof (value as { emit?: unknown }).emit === "function";
      expect(isEmitterShaped, `export "${name}" exposes emit()`).toBe(false);
    }
  });

  it("no enforcement source file imports an emitter symbol from the PDP package", () => {
    // Static, so it also catches a TYPE-only import: `type DecisionEvidenceEmitter`
    // is erased at runtime, so neither check above would ever see it, and a
    // dependency typed as an emitter is a dependency that can be handed one.
    const banned = [
      "createDecisionEvidenceEmitter",
      "DecisionEvidenceEmitter",
      "DecisionEvidenceEmitterConfig",
      "DecisionEvidenceEmissionInput",
    ];
    const root = fileURLToPath(new URL("../src", import.meta.url));
    const files: string[] = [];
    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name);
        if (entry.isDirectory()) walk(full);
        else if (entry.name.endsWith(".ts")) files.push(full);
      }
    };
    walk(root);
    expect(files.length).toBeGreaterThan(5);

    const offenders: string[] = [];
    for (const file of files) {
      const source = readFileSync(file, "utf8");
      // Named imports and re-exports: `import { X } from "..."`, `export { X } from "..."`.
      for (const m of source.matchAll(/(?:import|export)\s+(?:type\s+)?\{([^}]*)\}\s*from\s*["']([^"']+)["']/g)) {
        const names = (m[1] ?? "").split(",").map((n) => n.trim().replace(/^type\s+/, "").split(/\s+as\s+/)[0]);
        for (const name of names) {
          if (name && banned.includes(name)) offenders.push(`${file}: imports ${name} from ${m[2]}`);
        }
      }
      // A namespace import would reach every one of them by property access.
      for (const m of source.matchAll(/import\s+\*\s+as\s+\w+\s+from\s*["']@mission\/pdp["']/g)) {
        offenders.push(`${file}: namespace-imports @mission/pdp (${m[0]})`);
      }
    }
    expect(offenders).toEqual([]);
  });
});
