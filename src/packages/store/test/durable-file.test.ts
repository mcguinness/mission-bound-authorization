/**
 * @spec #1815: `writeDurableFile` replaces a file through a flushed temporary
 * file renamed into place. A write, flush or rename that fails leaves the
 * file as it was and no temporary file behind. `createDurableFile` (#1833)
 * links one into place instead, so it never replaces a file.
 */
import { existsSync, mkdtempSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";

/** The one `node:fs` call to fail next, once. */
const fault = vi.hoisted(() => ({ on: undefined as string | undefined }));

vi.mock("node:fs", async (importOriginal) => {
  const fs = await importOriginal<typeof import("node:fs")>();
  const failing =
    (name: "writeSync" | "fsyncSync" | "renameSync" | "linkSync") =>
    (...args: unknown[]) => {
      if (fault.on === name) {
        fault.on = undefined;
        throw Object.assign(new Error(`injected ${name} failure`), { code: "EIO" });
      }
      return (fs[name] as (...a: unknown[]) => unknown)(...args);
    };
  return {
    ...fs,
    default: fs,
    writeSync: failing("writeSync"),
    fsyncSync: failing("fsyncSync"),
    renameSync: failing("renameSync"),
    linkSync: failing("linkSync"),
  };
});

const { createDurableFile, writeDurableFile } = await import("../src/durable-file.js");

describe("writeDurableFile on a failure (@spec #1815)", () => {
  for (const step of ["writeSync", "fsyncSync", "renameSync"] as const) {
    it(`leaves the file as it was and no temporary file when ${step} fails`, () => {
      const dir = mkdtempSync(join(tmpdir(), "durable-file-"));
      const file = join(dir, "record.json");
      writeFileSync(file, "before\n");
      fault.on = step;
      expect(() => writeDurableFile(file, "after\n")).toThrow(`injected ${step} failure`);
      expect(fault.on).toBeUndefined();
      expect(readFileSync(file, "utf8")).toBe("before\n");
      expect(readdirSync(dir)).toEqual(["record.json"]);
      writeDurableFile(file, "after\n");
      expect(readFileSync(file, "utf8")).toBe("after\n");
      expect(readdirSync(dir)).toEqual(["record.json"]);
    });
  }
});

describe("createDurableFile (@spec #1833)", () => {
  it("creates the file once and refuses an existing one with EEXIST, leaving it as it was and no temporary file", () => {
    const dir = mkdtempSync(join(tmpdir(), "durable-file-"));
    const file = join(dir, "record.json");
    createDurableFile(file, "first\n");
    expect(readFileSync(file, "utf8")).toBe("first\n");
    expect(() => createDurableFile(file, "second\n")).toThrow(
      expect.objectContaining({ code: "EEXIST" }),
    );
    expect(readFileSync(file, "utf8")).toBe("first\n");
    expect(readdirSync(dir)).toEqual(["record.json"]);
  });

  for (const step of ["writeSync", "fsyncSync", "linkSync"] as const) {
    it(`leaves no file and no temporary file when ${step} fails`, () => {
      const dir = mkdtempSync(join(tmpdir(), "durable-file-"));
      const file = join(dir, "record.json");
      fault.on = step;
      expect(() => createDurableFile(file, "first\n")).toThrow(`injected ${step} failure`);
      expect(fault.on).toBeUndefined();
      expect(existsSync(file)).toBe(false);
      expect(readdirSync(dir)).toEqual([]);
      createDurableFile(file, "first\n");
      expect(readFileSync(file, "utf8")).toBe("first\n");
      expect(readdirSync(dir)).toEqual(["record.json"]);
    });
  }
});
