/**
 * A short-lived record of signed requests already accepted, keyed by
 * (signing-key thumbprint, created, @method, @authority, @path). An entry
 * lives for the signature validity window.
 *
 * @spec aauth#section-11.3.4.2
 */
export interface ReplayCache {
  /** Record `key` until `expiresAtMs`; false when it was already present. */
  checkAndRecord(key: string, expiresAtMs: number, nowMs: number): boolean;
}

export class InMemoryReplayCache implements ReplayCache {
  private readonly seen = new Map<string, number>();

  checkAndRecord(key: string, expiresAtMs: number, nowMs: number): boolean {
    for (const [k, expires] of this.seen) if (expires <= nowMs) this.seen.delete(k);
    if (this.seen.has(key)) return false;
    this.seen.set(key, expiresAtMs);
    return true;
  }
}
