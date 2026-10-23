// This consumer is independent of the reference implementation: it declares
// no @mission/* dependency, and no source or test file imports a @mission/*
// module or a relative path outside this package. Vectors are read with fs.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = resolve(here, "..");

function filesUnder(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

// Static imports and re-exports (import or export with a from clause, and a
// side-effect import of a bare specifier), dynamic import calls and require
// calls.
const SPECIFIER = /(?:\bfrom\s*|\bimport\s*\(\s*|\bimport\s+|\brequire\s*\(\s*)(['"`])([^'"`]+)\1/g;

function specifiers(source: string): string[] {
  return [...source.matchAll(SPECIFIER)].map((m) => m[2] ?? "");
}

describe("independence", () => {
  it("declares no @mission/* dependency of any kind", () => {
    const pkg = JSON.parse(readFileSync(join(packageRoot, "package.json"), "utf8")) as Record<
      string,
      unknown
    >;
    const fields = [
      "dependencies",
      "devDependencies",
      "peerDependencies",
      "optionalDependencies",
      "bundleDependencies",
      "bundledDependencies",
    ];
    for (const field of fields) {
      const value = pkg[field];
      if (value === undefined) continue;
      const names = Array.isArray(value) ? value : Object.keys(value as object);
      expect(
        names.filter((n) => String(n).startsWith("@mission/")),
        field,
      ).toEqual([]);
    }
  });

  const files = ["src", "test"].flatMap((d) => filesUnder(join(packageRoot, d)));
  const sources = files.filter((f) => /\.(?:[cm]?[jt]s|tsx|jsx)$/.test(f));

  it("finds the source and test files it scans", () => {
    expect(sources.some((f) => f.includes(`${sep}src${sep}`))).toBe(true);
    expect(sources.some((f) => f.includes(`${sep}test${sep}`))).toBe(true);
  });

  for (const file of sources) {
    const name = relative(packageRoot, file);
    it(`${name} imports nothing from @mission/ or outside the package`, () => {
      const found = specifiers(readFileSync(file, "utf8"));
      for (const spec of found) {
        expect(spec.startsWith("@mission/"), `${name} imports ${spec}`).toBe(false);
        if (spec.startsWith(".") || spec.startsWith("/")) {
          const target = resolve(dirname(file), spec);
          const rel = relative(packageRoot, target);
          expect(rel === ".." || rel.startsWith(`..${sep}`), `${name} imports ${spec}`).toBe(false);
        }
      }
    });
  }
});
