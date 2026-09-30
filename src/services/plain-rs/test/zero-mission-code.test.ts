/**
 * @spec mission#scope-projection — the evidence that this Resource Server is
 * Mission-unaware: its source never names the `mission` claim, the
 * `authorization_details` member, or a Mission workspace package (every one
 * of which contains the string "mission"), and its manifest depends on no
 * workspace package.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const p = join(dir, name);
    return statSync(p).isDirectory() ? files(p) : [p];
  });
}

describe("plain-rs carries zero Mission code", () => {
  it("no source file under src/ contains `mission` or `authorization_details` (case-insensitive)", () => {
    const sources = files(join(ROOT, "src"));
    expect(sources.length).toBeGreaterThan(0);
    const hits = sources.flatMap((f) =>
      readFileSync(f, "utf8")
        .split("\n")
        .map((line, i) => ({ f, i: i + 1, line }))
        .filter(({ line }) => /mission|authorization_details/i.test(line)),
    );
    expect(hits).toEqual([]);
  });

  it("depends on no workspace package", () => {
    const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    expect(Object.values(deps).filter((v) => v.startsWith("workspace:"))).toEqual([]);
  });
});
