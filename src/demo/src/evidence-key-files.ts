/**
 * @spec runtime-evidence#evidence-integrity-signing-keys, runtime#record-integrity
 * (#831 scope inventory) — durable evidence signing keys.
 *
 * The PEP's Execution Evidence and Refusal Record keys and the PDP's Decision
 * Evidence key sign records the deployment retains for the audit horizon in a
 * durable store. Generated per boot, a restart strands every record the
 * earlier boot signed: it no longer verifies. These files give each holder
 * the same keys at every boot.
 *
 * - **One file per holder.** The PEP's file holds `pep`, `executor` and
 *   `receipt_issuer`; the PDP's holds `pdp`. The PEP never holds the PDP's
 *   private key (#741), so the two never share a file.
 * - **Created once, never regenerated.** `initEvidenceKeyFile` writes 0600 in
 *   a directory that grants no group or other access, and fails if the file
 *   exists; loading refuses a missing file, wider permissions, another
 *   format or holder, or a key under another role or `kid`. A lost file is
 *   not silently replaced: the durable key-set store would refuse the new
 *   material under the old `kid` (append-only publication).
 * - **Ephemeral by default.** `composeStack` generates per-boot keys unless
 *   it is handed both files (`evidenceKeysFromEnv` for the launchers).
 *
 * The file hygiene is the AS key ring's; its format and lifecycle are not:
 * evidence keys rotate by a new `kid` and `retireKey` in the retention store,
 * not by generations.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject, randomBytes } from "node:crypto";
import {
  closeSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  statSync,
  unlinkSync,
  writeSync,
} from "node:fs";
import { dirname, isAbsolute, join } from "node:path";
import { TOPOLOGY } from "@mission/demo-data";
import type { EvidenceSigningConfig, EvidenceVerificationKey } from "@mission/mcp-payments";

export const EVIDENCE_KEY_FILE_FORMAT = "mission-evidence-keys/1";

export type EvidenceKeyHolder = "pep" | "pdp";
export type EvidenceKeyRole = "pep" | "executor" | "receipt_issuer" | "pdp";

/**
 * Each holder's roles, under the `kid`s this deployment's statement and
 * topology declare. The `ephemeral-*` identifiers are retained for the PEP's
 * keys, durable or not (D887): renaming them would change the boundary
 * declaration and every record that names them, so the word no longer
 * describes every deployment.
 */
export const EVIDENCE_KEY_ROLES: Record<EvidenceKeyHolder, readonly { role: EvidenceKeyRole; kid: string }[]> = {
  pep: [
    { role: "pep", kid: "ephemeral-pep" },
    { role: "executor", kid: "ephemeral-executor" },
    { role: "receipt_issuer", kid: "ephemeral-receipt_issuer" },
  ],
  pdp: [{ role: "pdp", kid: TOPOLOGY.keys.pdpDecisionEvidence.kid }],
};

/** One loaded key. */
export interface DurableEvidenceKey {
  role: EvidenceKeyRole;
  kid: string;
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export class EvidenceKeyFileError extends Error {}

const openToOthers = (path: string): number => statSync(path).mode & 0o077;

function fsyncDir(dir: string): void {
  try {
    const dfd = openSync(dir, "r");
    try {
      fsyncSync(dfd);
    } finally {
      closeSync(dfd);
    }
  } catch {
    // Directory fsync is not supported on every platform; the file itself is flushed.
  }
}

/**
 * Create `holder`'s key file at `file`, once: one fresh P-256 key per role
 * under its declared `kid`. The directory is created 0700 when missing and
 * must otherwise grant no group or other access; the file is written 0600 to
 * a temporary name, flushed, and linked into place, which fails if the file
 * exists, so an existing file is never replaced.
 */
export function initEvidenceKeyFile(file: string, holder: EvidenceKeyHolder): void {
  if (!isAbsolute(file)) throw new EvidenceKeyFileError(`an evidence key file is named by an absolute path, not ${file}`);
  const dir = dirname(file);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (openToOthers(dir) !== 0) {
    throw new EvidenceKeyFileError(`${dir} grants group or other access; use a directory with mode 0700`);
  }
  const keys = EVIDENCE_KEY_ROLES[holder].map(({ role, kid }) => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    return { role, kid, alg: "ES256", private_jwk: privateKey.export({ format: "jwk" }) };
  });
  const content = `${JSON.stringify({ format: EVIDENCE_KEY_FILE_FORMAT, holder, keys }, null, 2)}\n`;
  const tmp = join(dir, `.evidence-keys-${process.pid}-${randomBytes(6).toString("hex")}.tmp`);
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, content);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    linkSync(tmp, file);
  } catch (e) {
    unlinkSync(tmp);
    if ((e as NodeJS.ErrnoException).code === "EEXIST") {
      throw new EvidenceKeyFileError(`${file} already exists; an evidence key file is created once`);
    }
    throw new EvidenceKeyFileError(`cannot write ${file}: ${(e as Error).message}`);
  }
  unlinkSync(tmp);
  fsyncDir(dir);
}

/** `holder`'s keys from `file`, refused unless the file is exactly what `initEvidenceKeyFile` wrote for it. */
export function loadEvidenceKeyFile(file: string, holder: EvidenceKeyHolder): DurableEvidenceKey[] {
  let raw: string;
  try {
    if (openToOthers(file) !== 0) {
      throw new EvidenceKeyFileError(`${file} grants group or other access; it must be mode 0600`);
    }
    raw = readFileSync(file, "utf8");
  } catch (e) {
    if (e instanceof EvidenceKeyFileError) throw e;
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      throw new EvidenceKeyFileError(`no evidence key file at ${file}; create it once with \`pnpm evidence-keys init --${holder} ${file}\``);
    }
    throw new EvidenceKeyFileError(`cannot read ${file}: ${(e as Error).message}`);
  }
  let parsed: { format?: unknown; holder?: unknown; keys?: unknown };
  try {
    parsed = JSON.parse(raw) as typeof parsed;
  } catch {
    throw new EvidenceKeyFileError(`${file} is not valid JSON`);
  }
  if (parsed.format !== EVIDENCE_KEY_FILE_FORMAT) throw new EvidenceKeyFileError(`${file} is not a ${EVIDENCE_KEY_FILE_FORMAT} file`);
  if (parsed.holder !== holder) throw new EvidenceKeyFileError(`${file} holds the ${String(parsed.holder)} keys, not the ${holder} keys`);
  const stored = Array.isArray(parsed.keys) ? (parsed.keys as Record<string, unknown>[]) : [];
  const expected = EVIDENCE_KEY_ROLES[holder];
  if (stored.length !== expected.length) {
    throw new EvidenceKeyFileError(`${file} holds ${stored.length} keys; the ${holder} holds ${expected.length}`);
  }
  return expected.map(({ role, kid }) => {
    const entry = stored.find((k) => k.role === role);
    if (!entry || entry.kid !== kid || entry.alg !== "ES256" || typeof entry.private_jwk !== "object" || entry.private_jwk === null) {
      throw new EvidenceKeyFileError(`${file} has no ES256 ${role} key under ${kid}`);
    }
    const privateKey = createPrivateKey({ key: entry.private_jwk as never, format: "jwk" });
    return { role, kid, privateKey, publicKey: createPublicKey(privateKey) };
  });
}

/**
 * @spec #831: where a launcher's evidence keys come from. Both
 * `MISSION_PEP_EVIDENCE_KEYS` and `MISSION_PDP_EVIDENCE_KEYS` (absolute paths)
 * select durable keys; neither leaves them per boot. One without the other is
 * refused: the PDP's and the PEP's records live in one retention store.
 */
export function evidenceKeysFromEnv(env: NodeJS.ProcessEnv): { pep: string; pdp: string } | undefined {
  const pep = env.MISSION_PEP_EVIDENCE_KEYS;
  const pdp = env.MISSION_PDP_EVIDENCE_KEYS;
  if (pep === undefined && pdp === undefined) return undefined;
  if (!pep || !pdp) {
    throw new EvidenceKeyFileError("set both MISSION_PEP_EVIDENCE_KEYS and MISSION_PDP_EVIDENCE_KEYS, or neither");
  }
  for (const [name, path] of [["MISSION_PEP_EVIDENCE_KEYS", pep], ["MISSION_PDP_EVIDENCE_KEYS", pdp]] as const) {
    if (!isAbsolute(path)) throw new EvidenceKeyFileError(`${name} must be an absolute path, not ${path}`);
  }
  if (pep === pdp) throw new EvidenceKeyFileError("the PEP's and the PDP's evidence keys are two files (#741)");
  return { pep, pdp };
}

/** Where a deployment's evidence keys come from: the two key files, or keys generated at each boot. */
export type EvidenceKeySource = { pep: string; pdp: string } | { ephemeral: true };

/**
 * @spec #831 (D901): a deployment launcher's evidence keys, chosen as its
 * signing keys are (`signingKeysFromEnv`, D499): both
 * `MISSION_PEP_EVIDENCE_KEYS` and `MISSION_PDP_EVIDENCE_KEYS` select the key
 * files ({@link evidenceKeysFromEnv}), and `MISSION_EPHEMERAL_EVIDENCE_KEYS=1`
 * keys generated at each boot, whose records stop verifying after a restart.
 * Neither, or both, refuses: a deployment says which it runs.
 */
export function evidenceKeySourceFromEnv(env: NodeJS.ProcessEnv): EvidenceKeySource {
  const files = evidenceKeysFromEnv(env);
  const ephemeral = env.MISSION_EPHEMERAL_EVIDENCE_KEYS === "1";
  if (files && ephemeral) {
    throw new EvidenceKeyFileError(
      "set MISSION_PEP_EVIDENCE_KEYS and MISSION_PDP_EVIDENCE_KEYS, or MISSION_EPHEMERAL_EVIDENCE_KEYS=1, not both",
    );
  }
  if (files) return files;
  if (ephemeral) return { ephemeral: true };
  throw new EvidenceKeyFileError(
    "choose the evidence keys: MISSION_PEP_EVIDENCE_KEYS=<path> and MISSION_PDP_EVIDENCE_KEYS=<path> (create them once with `pnpm evidence-keys init`), or MISSION_EPHEMERAL_EVIDENCE_KEYS=1 for keys that change at every restart",
  );
}

/**
 * The PEP's loaded keys as the signing and verification bundle the stack
 * wires, the shape `createEphemeralEvidenceKeys` gives per-boot keys: each
 * enforcement-point key bound to its emitter and audience, the receipt
 * issuer's unbound.
 */
export function evidenceKeyBundle(
  keys: readonly DurableEvidenceKey[],
  emitterId: string,
  audience: string,
): { signing: EvidenceSigningConfig; verification: EvidenceVerificationKey[] } {
  const signing: EvidenceSigningConfig = {};
  const verification: EvidenceVerificationKey[] = [];
  for (const { role, kid, privateKey, publicKey } of keys) {
    if (role === "pdp") continue;
    signing[role] = { kid, key: privateKey };
    verification.push(
      role === "receipt_issuer" ? { kid, publicKey, role, emitterId } : { kid, publicKey, role, emitterId, audience },
    );
  }
  return { signing, verification };
}

/**
 * `pnpm evidence-keys init [--pep <path>] [--pdp <path>]`: create either
 * holder's file, or both, once. Returns the lines it prints.
 */
export function evidenceKeysAdmin(args: readonly string[]): string {
  const usage = "usage: pnpm evidence-keys init [--pep <absolute path>] [--pdp <absolute path>]";
  const [command, ...rest] = args;
  if (command !== "init") throw new EvidenceKeyFileError(usage);
  const files: Partial<Record<EvidenceKeyHolder, string>> = {};
  for (let i = 0; i < rest.length; i += 2) {
    const flag = rest[i];
    const value = rest[i + 1];
    if ((flag !== "--pep" && flag !== "--pdp") || value === undefined) throw new EvidenceKeyFileError(usage);
    files[flag.slice(2) as EvidenceKeyHolder] = value;
  }
  if (files.pep === undefined && files.pdp === undefined) throw new EvidenceKeyFileError(usage);
  const lines: string[] = [];
  for (const holder of ["pep", "pdp"] as const) {
    const file = files[holder];
    if (file === undefined) continue;
    initEvidenceKeyFile(file, holder);
    lines.push(`created the ${holder} evidence keys at ${file} (${EVIDENCE_KEY_ROLES[holder].map((k) => k.kid).join(", ")})`);
  }
  lines.push("start the stack with MISSION_PEP_EVIDENCE_KEYS and MISSION_PDP_EVIDENCE_KEYS naming the two files");
  return lines.join("\n");
}
