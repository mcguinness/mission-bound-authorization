/**
 * @spec cross-domain#validation-at-resource-as (one-time use), #1767 (D887):
 * the RAS's single-use claims on the ID-JAGs it redeems.
 *
 * A grant's `jti`, scoped to its issuer, is claimed once, atomically, before
 * the local token is released. In memory the claims die with the process, so
 * a grant redeemed before a restart redeems again after it while its
 * signature still verifies: a durable issuer key, or an independent RAS
 * restart under an unchanged one, makes that possible. Persistent keys
 * require persistent consumption records (D366), so a deployment gives the
 * RAS a durable store:
 *
 * - **Created once.** `initRasRedemptionStore` creates the file and records
 *   that it did; opening refuses a missing file, and a file `init` did not
 *   create (an empty or truncated one), so lost state is refused at boot and
 *   never read as an empty history.
 * - **Single writer.** The store is `openDurableStore`'s: exclusive, WAL,
 *   `synchronous=FULL`, owned by the RAS.
 * - **Kept through the grant's acceptance period.** Each claim is retained
 *   until the grant's `exp` plus a margin for clock adjustment, and only then
 *   pruned.
 *
 * Recovery restores the store's complete history. A replacement is safe only
 * once every grant the lost history could have recorded has expired or been
 * invalidated (for example, by no longer trusting the keys that signed it):
 * an empty store would redeem each of those grants again (D901).
 *
 * A known limitation (D901): a restored older copy of the store loses the
 * claims made after it was taken, and nothing detects it. It applies wherever
 * issuer keys survive a restart, the composed stack included, not only a RAS
 * deployed on its own; detecting it needs a witness outside the store, as
 * #250 step 3 gave the kernel.
 */

import { existsSync } from "node:fs";
import { isAbsolute } from "node:path";
import { type Database, openDurableStore, openStore } from "@mission/store";

/** The store's owner, recorded on first open. */
export const RAS_REDEMPTION_STORE_OWNER = "ras-grant-redemptions";

/** How long past a grant's `exp` its claim is kept: a margin for clock adjustment. */
export const REDEMPTION_RETENTION_MARGIN_S = 300;

const SCHEMA = `CREATE TABLE IF NOT EXISTS grant_redemptions (
  issuer TEXT NOT NULL,
  jti TEXT NOT NULL,
  redeemed_at INTEGER NOT NULL,
  retain_until INTEGER NOT NULL,
  PRIMARY KEY (issuer, jti)
) STRICT;
CREATE TABLE IF NOT EXISTS redemption_store_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL) STRICT;`;

export class RasRedemptionStoreError extends Error {}

const LOST =
  "if a store existed, restore its complete history: a replacement is safe only once every grant it could have recorded has expired or been invalidated, since an empty store redeems each of them again";

/** Create the durable store at `file`, once; an existing file is refused. */
export function initRasRedemptionStore(file: string, now: Date = new Date()): void {
  if (existsSync(file)) throw new RasRedemptionStoreError(`${file} already exists; a redemption store is created once`);
  const db = openDurableStore({ file, migrations: [SCHEMA], owner: RAS_REDEMPTION_STORE_OWNER });
  try {
    db.prepare("INSERT INTO redemption_store_meta (k, v) VALUES ('created_at', ?)").run(now.toISOString());
  } finally {
    db.close();
  }
}

/**
 * Open the durable store at `file`. A missing file is refused, never created,
 * and so is a file `initRasRedemptionStore` did not create: an empty or
 * truncated store is lost history, which is restored, never replaced while a
 * grant it could have recorded is still acceptable.
 */
export function openRasRedemptionStore(file: string): Database {
  if (!existsSync(file)) {
    throw new RasRedemptionStoreError(
      `no redemption store at ${file}. A new deployment creates it once with \`pnpm ras-redemptions init --file ${file}\`; ${LOST}`,
    );
  }
  const db = openDurableStore({ file, migrations: [SCHEMA], owner: RAS_REDEMPTION_STORE_OWNER });
  if (!db.prepare("SELECT v FROM redemption_store_meta WHERE k = 'created_at'").get()) {
    db.close();
    throw new RasRedemptionStoreError(
      `${file} is not a redemption store \`pnpm ras-redemptions init\` created: its history is lost. ${LOST}`,
    );
  }
  return db;
}

/**
 * @spec #1767 (D901): a launcher's redemption store, from its environment.
 * `MISSION_RAS_REDEMPTIONS` names the store file, an absolute path created once
 * with `pnpm ras-redemptions init`. It is required whenever `MISSION_KEY_RING`
 * is set: issuer keys that survive a restart let an ID-JAG the RAS redeemed
 * before it verify after it, so persistent keys require persistent
 * consumption records (D366). Without a key ring and without the variable,
 * the claims stay in memory. Nothing here creates a store.
 */
export function rasRedemptionsFromEnv(env: Readonly<Record<string, string | undefined>>): { file: string } | undefined {
  const file = env.MISSION_RAS_REDEMPTIONS?.trim();
  if (!file) {
    if (env.MISSION_KEY_RING?.trim()) {
      throw new RasRedemptionStoreError(
        "MISSION_KEY_RING requires MISSION_RAS_REDEMPTIONS: with issuer keys that survive a restart, an ID-JAG the RAS redeemed before it would redeem again (create the store once with `pnpm ras-redemptions init --file <path>`)",
      );
    }
    return undefined;
  }
  if (!isAbsolute(file)) throw new RasRedemptionStoreError(`MISSION_RAS_REDEMPTIONS must be an absolute path, not ${file}`);
  return { file };
}

/** An in-memory store, for a RAS whose claims may die with it. */
export function openInMemoryRedemptionStore(): Database {
  return openStore(SCHEMA);
}

/**
 * Claim `(issuer, jti)` once: true for the first claim, false for any later
 * one. Claims past their retention are pruned first; a live claim never is.
 */
export function claimRedemption(db: Database, issuer: string, jti: string, exp: number, nowS: number): boolean {
  return db
    .transaction(() => {
      db.prepare("DELETE FROM grant_redemptions WHERE retain_until < ?").run(nowS);
      return (
        db
          .prepare(
            "INSERT INTO grant_redemptions (issuer, jti, redeemed_at, retain_until) VALUES (?, ?, ?, ?) ON CONFLICT(issuer, jti) DO NOTHING",
          )
          .run(issuer, jti, nowS, Math.ceil(exp) + REDEMPTION_RETENTION_MARGIN_S).changes === 1
      );
    })
    .immediate();
}
