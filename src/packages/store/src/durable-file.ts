/**
 * Durable files beside a store: an external recovery witness is a small file
 * kept outside the store's restore unit (#250 step 3 for the kernel, #1749 for
 * the Signals receiver). These two helpers are shared by both.
 */

import { randomBytes } from "node:crypto";
import {
  closeSync,
  existsSync,
  fsyncSync,
  openSync,
  realpathSync,
  renameSync,
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

/**
 * Replace a file durably: write a sibling temporary file, flush it, rename it
 * over the file, and flush the directory, so a crash leaves the old contents
 * or the new, never a torn file.
 */
export function writeDurableFile(file: string, contents: string): void {
  const tmp = join(dirname(file), `.${randomBytes(6).toString("hex")}.witness.tmp`);
  const fd = openSync(tmp, "w", 0o600);
  try {
    writeSync(fd, contents);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, file);
  const dir = openSync(dirname(file), "r");
  try {
    fsyncSync(dir);
  } finally {
    closeSync(dir);
  }
}
