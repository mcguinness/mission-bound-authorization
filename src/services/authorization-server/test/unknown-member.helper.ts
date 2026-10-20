/**
 * @spec mission#subset (#1399, D538): the shared cases of the requested-
 * authority exchange witnesses for a top-level entry member outside the
 * supported set. The candidate case is a requested entry carrying the member;
 * the exchange names it in `invalid_authorization_details`. The ceiling case
 * is the Mission's own approved entry carrying it: derivation rebuilds every
 * approved entry member by member, so no intake produces that state, and the
 * witness writes it into the stored record (as an inconsistent store could
 * hold it) to show the exchange still refuses rather than issuing without it.
 */

/** The part of the kernel's store the witness reads and writes. */
interface Store {
  prepare(sql: string): { get(...params: unknown[]): unknown; run(...params: unknown[]): unknown };
}

/** The reproduction: a restriction-shaped member no specification defines for this type. */
export const UNSUPPORTED_MEMBER = "invoice_ids";

/** The entry carrying it. */
export function withUnsupportedMember<T extends object>(entry: T): T & Record<string, unknown> {
  return { ...entry, [UNSUPPORTED_MEMBER]: ["INV-7"] };
}

/** The `error_description` the shared validator answers for it. */
export const UNSUPPORTED_MEMBER_DESCRIPTION = `${UNSUPPORTED_MEMBER} is not a supported member of the mission_resource_access type; refusing rather than dropping it`;

/**
 * Run `fn` while every entry of the stored Mission's approved Authority Set
 * carries the member, then restore the stored set byte for byte.
 */
export async function withStoredUnsupportedMember<R>(
  db: Store,
  missionId: string,
  fn: () => Promise<R>,
): Promise<R> {
  const row = db.prepare("SELECT authority_set_json FROM missions WHERE id = ?").get(missionId) as
    | { authority_set_json: string }
    | undefined;
  if (!row) throw new Error(`no stored Mission ${missionId}`);
  const entries = JSON.parse(row.authority_set_json) as object[];
  db.prepare("UPDATE missions SET authority_set_json = ? WHERE id = ?").run(
    JSON.stringify(entries.map(withUnsupportedMember)),
    missionId,
  );
  try {
    return await fn();
  } finally {
    db.prepare("UPDATE missions SET authority_set_json = ? WHERE id = ?").run(row.authority_set_json, missionId);
  }
}
