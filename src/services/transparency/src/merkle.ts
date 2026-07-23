/**
 * @spec RFC 9162-style binary Merkle tree, the append-only log under the
 * SCITT Transparency Service (draft-mcguinness-mission-audit / RFC 9943).
 *
 * Leaves are SHA-256 leaf hashes (0x00 prefix); interior nodes are SHA-256
 * over (0x01 || left || right), per RFC 6962/9162 domain separation. The log
 * produces a root (tree head) and inclusion proofs a verifier checks offline.
 */

import { createHash } from "node:crypto";

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export function leafHash(data: Buffer): Buffer {
  return createHash("sha256").update(LEAF_PREFIX).update(data).digest();
}

function nodeHash(left: Buffer, right: Buffer): Buffer {
  return createHash("sha256").update(NODE_PREFIX).update(left).update(right).digest();
}

/** RFC 6962 Merkle Tree Hash over a list of leaf hashes. */
function mth(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) return createHash("sha256").digest();
  if (leaves.length === 1) return leaves[0] as Buffer;
  const k = largestPowerOfTwoBelow(leaves.length);
  return nodeHash(mth(leaves.slice(0, k)), mth(leaves.slice(k)));
}

/** RFC 6962 inclusion proof for leaf index m in a tree of n leaves. */
function inclusionProof(m: number, leaves: Buffer[]): Buffer[] {
  const n = leaves.length;
  if (n <= 1) return [];
  const k = largestPowerOfTwoBelow(n);
  if (m < k) {
    return [...inclusionProof(m, leaves.slice(0, k)), mth(leaves.slice(k))];
  }
  return [...inclusionProof(m - k, leaves.slice(k)), mth(leaves.slice(0, k))];
}

/** Verify an inclusion proof: recompute the root from the leaf + audit path. */
export function verifyInclusion(
  leaf: Buffer,
  index: number,
  treeSize: number,
  proof: Buffer[],
  root: Buffer,
): boolean {
  if (index >= treeSize) return false;
  let hash = leaf;
  let fn = index;
  let sn = treeSize - 1;
  let p = 0;
  while (sn > 0) {
    if (p >= proof.length) return false;
    const sibling = proof[p] as Buffer;
    p += 1;
    if (fn % 2 === 1 || fn === sn) {
      hash = nodeHash(sibling, hash);
      while (fn % 2 === 0 && fn !== 0) {
        fn = Math.floor(fn / 2);
        sn = Math.floor(sn / 2);
      }
    } else {
      hash = nodeHash(hash, sibling);
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  return p === proof.length && hash.equals(root);
}

function largestPowerOfTwoBelow(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

/** The append-only log: holds leaf hashes, computes root and proofs. */
export class MerkleLog {
  private readonly leaves: Buffer[] = [];

  append(leaf: Buffer): number {
    this.leaves.push(leaf);
    return this.leaves.length - 1;
  }

  size(): number {
    return this.leaves.length;
  }

  root(): Buffer {
    return mth(this.leaves);
  }

  proof(index: number): Buffer[] {
    return inclusionProof(index, this.leaves);
  }
}
