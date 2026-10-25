/**
 * @spec control-plane#deployment-declaration, control-plane#conformance (#250
 * step 4): the reference deployment's Deployment Declaration, the "Deployment
 * declaration" section of src/docs/control-plane-deployment.md.
 *
 * These tests check that each declared item is present and that the residual
 * risks match the conformance ledger. They do not check the prose against the
 * running code; the sections each item points to carry that.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = new URL("../../../../", import.meta.url);
const DOC = fileURLToPath(new URL("src/docs/control-plane-deployment.md", ROOT));
const MANIFEST = fileURLToPath(new URL("conformance-manifest.json", ROOT));

/** The declaration's subsections, by heading, each with its body. */
function declaration(): { intro: string; items: Map<string, string> } {
  const doc = readFileSync(DOC, "utf8");
  const start = doc.indexOf("\n## Deployment declaration\n");
  expect(start, "the Deployment declaration section").toBeGreaterThan(-1);
  const rest = doc.slice(start + 1);
  const end = rest.indexOf("\n## ", 1);
  const section = end === -1 ? rest : rest.slice(0, end);
  const [intro, ...parts] = section.split("\n### ");
  const items = new Map<string, string>();
  for (const part of parts) {
    const newline = part.indexOf("\n");
    items.set(part.slice(0, newline).trim(), part.slice(newline + 1).trim());
  }
  return { intro: intro ?? "", items };
}

describe("the control-plane deployment declaration (@spec control-plane#deployment-declaration, control-plane#conformance, #250 step 4)", () => {
  it("documents each item the declaration requires under its own heading: serialization domains, authoritative observation mechanism, replication and recovery model, recovery objectives, tenant isolation and residual risks", () => {
    const { items } = declaration();
    for (const heading of [
      "Serialization domains",
      "Authoritative observation mechanism",
      "Replication and recovery model",
      "Recovery objectives",
      "Tenant isolation",
      "Residual risks",
    ]) {
      expect(items.get(heading)?.length ?? 0, heading).toBeGreaterThan(0);
    }
    const objectives = items.get("Recovery objectives") ?? "";
    expect(objectives).toContain("**Recovery point:**");
    expect(objectives).toContain("**Recovery time:**");
  });

  it("makes no claim, and lists as residual risks exactly the control-plane rows the ledger has not marked tested", () => {
    const { intro, items } = declaration();
    expect(intro).toContain("The reference does not claim Mission Control-Plane Consistency");
    const listed = [...(items.get("Residual risks") ?? "").matchAll(/^- `(control-plane\.[a-z0-9.-]+)`/gm)].map((m) => m[1]);
    const manifest = JSON.parse(readFileSync(MANIFEST, "utf8")) as {
      requirements: Array<{ id: string; coverage: string }>;
    };
    const untested = manifest.requirements
      .filter((r) => r.id.startsWith("control-plane.") && r.coverage !== "tested")
      .map((r) => r.id);
    expect(untested.length).toBeGreaterThan(0);
    expect([...listed].sort()).toEqual([...untested].sort());
  });
});
