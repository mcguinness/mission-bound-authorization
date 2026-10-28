/**
 * Durable files beside a store: an external recovery witness is a small file
 * kept outside the store's restore unit (#250 step 3 for the kernel, #1749 for
 * the Signals receiver), and so is the AS's key binding record (#1815). These
 * helpers are shared by all three.
 */

import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  openSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";

/** `p`, absolute, through any symbolic links of its nearest existing ancestor. */
export function canonicalPath(p: string): string {
  let existing = resolve(p);
  const rest: string[] = [];
  while (!existsSync(existing)) {
    const parent = dirname(existing);
    if (parent === existing) break;
    rest.unshift(basename(existing));
    existing = parent;
  }
  return join(realpathSync(existing), ...rest);
}

/**
 * True when the witness's directory is the store's directory or inside it, or
 * the store's is inside the witness's: a restore of either directory tree would
 * then roll both back together. Paths are compared canonically.
 */
export function witnessSharesStoreTree(storeFile: string, witnessFile: string): boolean {
  const storeDir = canonicalPath(dirname(resolve(storeFile)));
  const witnessDir = canonicalPath(dirname(resolve(witnessFile)));
  const within = (inner: string, outer: string) =>
    inner === outer || inner.startsWith(outer.endsWith(sep) ? outer : outer + sep);
  return within(witnessDir, storeDir) || within(storeDir, witnessDir);
}

/** Remove `tmp`, which may never have been created or may already be gone. */
function removeTemp(tmp: string): void {
  try {
    unlinkSync(tmp);
  } catch {
    // Never created, or already gone.
  }
}

/** A flushed sibling temporary file holding `contents`; removed again if the write or flush fails. */
function flushedTemp(file: string, contents: string): string {
  const tmp = join(dirname(file), `.${randomBytes(6).toString("hex")}.witness.tmp`);
  try {
    const fd = openSync(tmp, "w", 0o600);
    try {
      writeSync(fd, contents);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch (e) {
    removeTemp(tmp);
    throw e;
  }
  return tmp;
}

function fsyncDir(dir: string): void {
  const fd = openSync(dir, "r");
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

/**
 * Replace a file durably: write a sibling temporary file, flush it, rename it
 * over the file, and flush the directory, so a crash leaves the old contents
 * or the new, never a torn file. A write, flush or rename that fails removes
 * the temporary file (#1815) and leaves the file as it was.
 */
export function writeDurableFile(file: string, contents: string): void {
  const tmp = flushedTemp(file, contents);
  try {
    renameSync(tmp, file);
  } catch (e) {
    removeTemp(tmp);
    throw e;
  }
  fsyncDir(dirname(file));
}

/**
 * Create a file durably, never replacing one: a flushed sibling temporary file
 * is linked into place, so of two creators one is refused with `EEXIST`, and a
 * crash leaves no file or the whole one (#1833). The temporary file is removed
 * either way.
 */
export function createDurableFile(file: string, contents: string): void {
  const tmp = flushedTemp(file, contents);
  try {
    linkSync(tmp, file);
  } finally {
    removeTemp(tmp);
  }
  fsyncDir(dirname(file));
}
