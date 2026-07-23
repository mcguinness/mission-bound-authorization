/**
 * @spec draft-mcguinness-mission-audit (SCITT profile of RFC 9943)
 *
 * In-memory Transparency Service. A producer registers Mission evidence as a
 * Signed Statement that commits to the evidence BY HASH (the evidence itself
 * stays out of the log; feed-driven distributed retention, D32). The service
 * appends the commitment to an append-only Merkle log and returns a Receipt
 * (inclusion proof + signed tree head). Signed Statement + Receipt = a
 * Transparent Statement any party verifies offline (five steps). The Mission
 * is the statement subject, so all of a Mission's evidence forms one feed.
 *
 * Deviation (O-16): the draft mandates COSE hash-envelope Signed Statements;
 * this reference uses JWS over the same hash commitment to stay in the JOSE
 * stack. The SCITT semantics (commit-by-hash, Merkle inclusion, receipts,
 * offline verification, tamper detection) are faithful. Logged for S-log.
 */

import { createHash } from "node:crypto";
import { canonicalize, type JsonValue } from "@mission/core";
import { createLocalJWKSet, jwtVerify, SignJWT, type CryptoKey, type JWK } from "jose";
import { leafHash, MerkleLog, verifyInclusion } from "./merkle.js";

export const SIGNED_STATEMENT_TYP = "mission-signed-statement+jwt";
export const RECEIPT_TYP = "mission-receipt+jwt";

/** SHA-256 over the JCS-canonical evidence bytes the evidence type fixes. */
export function evidenceDigest(evidence: JsonValue): string {
  const bytes = canonicalize(evidence);
  return `sha-256:${createHash("sha256").update(bytes, "utf8").digest("base64url")}`;
}

export interface ProducerKey {
  iss: string;
  key: CryptoKey;
  kid: string;
}

export interface SignedStatement {
  jws: string;
  digest: string;
  missionId: string;
  producer: string;
}

export interface Receipt {
  jws: string;
  index: number;
  treeSize: number;
}

export interface TransparentStatement {
  statement: SignedStatement;
  receipt: Receipt;
}

/** A producer signs a Statement committing to evidence by hash. */
export async function signStatement(
  producer: ProducerKey,
  input: { missionId: string; evidenceType: string; evidence: JsonValue },
): Promise<SignedStatement> {
  const digest = evidenceDigest(input.evidence);
  const jws = await new SignJWT({ digest, evidence_type: input.evidenceType })
    .setProtectedHeader({ alg: "ES256", kid: producer.kid, typ: SIGNED_STATEMENT_TYP })
    .setIssuer(producer.iss)
    .setSubject(input.missionId) // the Mission is the statement subject
    .setIssuedAt()
    .sign(producer.key);
  return { jws, digest, missionId: input.missionId, producer: producer.iss };
}

export class TransparencyService {
  private readonly log = new MerkleLog();
  private readonly entries: Array<{ statement: SignedStatement; leaf: Buffer }> = [];

  constructor(
    private readonly opts: { key: CryptoKey; kid: string; issuer: string },
  ) {}

  /** Register a Signed Statement: append its commitment, return a Receipt. */
  async register(statement: SignedStatement): Promise<Receipt> {
    const leaf = leafHash(Buffer.from(statement.jws, "utf8"));
    const index = this.log.append(leaf);
    this.entries.push({ statement, leaf });
    const treeSize = this.log.size();
    const proof = this.log.proof(index).map((b) => b.toString("base64url"));
    // The Receipt: a signed inclusion proof against the current tree head.
    const jws = await new SignJWT({
      root: this.log.root().toString("base64url"),
      index,
      tree_size: treeSize,
      inclusion_proof: proof,
    })
      .setProtectedHeader({ alg: "ES256", kid: this.opts.kid, typ: RECEIPT_TYP })
      .setIssuer(this.opts.issuer)
      .setIssuedAt()
      .sign(this.opts.key);
    return { jws, index, treeSize };
  }

  /** The per-mission feed: every Transparent Statement whose subject is the Mission. */
  feed(missionId: string): SignedStatement[] {
    return this.entries.filter((e) => e.statement.missionId === missionId).map((e) => e.statement);
  }

  /** Current signed tree head (for auditors reconciling the whole log). */
  treeHead(): { root: string; size: number } {
    return { root: this.log.root().toString("base64url"), size: this.log.size() };
  }

  /** Test/tamper hook: the raw leaf for an index (to prove inclusion offline). */
  leafAt(index: number): Buffer | undefined {
    return this.entries[index]?.leaf;
  }
}

export interface VerifyInput {
  statement: SignedStatement;
  receipt: Receipt;
  /** The evidence retrieved separately, under access control, for rehashing. */
  evidence: JsonValue;
  producerJwks: { keys: JWK[] };
  serviceJwks: { keys: JWK[] };
  expectedMissionId: string;
}

export type VerifyResult =
  | { ok: true }
  | { ok: false; step: 1 | 2 | 3 | 4 | 5; reason: string };

/**
 * @spec audit#receipts — the five-step offline verification. A relying party
 * MUST complete all five before relying on a record as transparent.
 */
export async function verifyTransparentStatement(input: VerifyInput): Promise<VerifyResult> {
  // 1. Verify the Signed Statement against the producer trust anchor.
  let stmtPayload: Record<string, unknown>;
  try {
    const jwks = createLocalJWKSet({ keys: input.producerJwks.keys } as never);
    const { payload } = await jwtVerify(input.statement.jws, jwks, { typ: SIGNED_STATEMENT_TYP });
    stmtPayload = payload as Record<string, unknown>;
  } catch (e) {
    return { ok: false, step: 1, reason: (e as Error).message };
  }

  // 2. Verify the Receipt against the Transparency Service key.
  let receiptPayload: Record<string, unknown>;
  try {
    const jwks = createLocalJWKSet({ keys: input.serviceJwks.keys } as never);
    const { payload } = await jwtVerify(input.receipt.jws, jwks, { typ: RECEIPT_TYP });
    receiptPayload = payload as Record<string, unknown>;
  } catch (e) {
    return { ok: false, step: 2, reason: (e as Error).message };
  }

  // 3. Verify the inclusion proof binds the Signed Statement to the log.
  const leaf = leafHash(Buffer.from(input.statement.jws, "utf8"));
  const proof = (receiptPayload.inclusion_proof as string[]).map((s) => Buffer.from(s, "base64url"));
  const root = Buffer.from(receiptPayload.root as string, "base64url");
  const included = verifyInclusion(
    leaf,
    receiptPayload.index as number,
    receiptPayload.tree_size as number,
    proof,
    root,
  );
  if (!included) return { ok: false, step: 3, reason: "inclusion proof does not bind statement to log" };

  // 4. Confirm the subject is the expected Mission's feed.
  if (stmtPayload.sub !== input.expectedMissionId) {
    return { ok: false, step: 4, reason: "statement subject is not the expected Mission" };
  }

  // 5. Rehash the retrieved evidence and compare to the committed digest.
  if (evidenceDigest(input.evidence) !== stmtPayload.digest) {
    return { ok: false, step: 5, reason: "evidence digest does not match the committed digest" };
  }
  return { ok: true };
}

export { MerkleLog, verifyInclusion, leafHash } from "./merkle.js";
