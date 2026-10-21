/**
 * #818 slice 5B review: a launch's cleanup stack, and its cancellation.
 *
 * Every resource a launch acquires (a listener, a store, a child process) is
 * registered in its scope the moment it exists, in acquisition order.
 * `release()` disposes them in reverse, once; it is the launch's `close()`,
 * and a startup that fails runs it before the failure propagates.
 *
 * `cancel()` (a signal during startup) aborts `signal`, which the launch's own
 * awaits observe, and releases at once: it never waits for a blocked startup
 * await to return. After that nothing is kept. A step that was waiting throws
 * `StartupCancelled`; a resource that arrives late is disposed as it arrives,
 * and the step that acquired it throws.
 *
 * A child scope (a composition inside a launch) is registered in its parent
 * when it is created, so the parent's release disposes it in place, and it is
 * cancelled with its parent.
 */

export class StartupCancelled extends Error {
  constructor() {
    super("startup was cancelled");
    this.name = "StartupCancelled";
  }
}

type Dispose = () => Promise<void> | void;

export class StartupScope {
  readonly #controller = new AbortController();
  readonly #stack: Dispose[] = [];
  #released: Promise<void> | undefined;

  constructor(parent?: StartupScope) {
    if (parent) {
      parent.register(() => this.release());
      if (parent.signal.aborted) this.#controller.abort();
      else parent.signal.addEventListener("abort", () => this.#controller.abort(), { once: true });
    }
  }

  /** Aborted when the scope is cancelled or released; startup's fetches and waits observe it. */
  get signal(): AbortSignal {
    return this.#controller.signal;
  }

  get cancelled(): boolean {
    return this.#controller.signal.aborted || this.#released !== undefined;
  }

  /** Throws `StartupCancelled` once the scope is cancelled or released. */
  check(): void {
    if (this.cancelled) throw new StartupCancelled();
  }

  /**
   * Keep `dispose` for release. Once the scope is cancelled or released, it
   * runs `dispose` at once instead and throws `StartupCancelled`.
   */
  register(dispose: Dispose): void {
    if (this.cancelled) {
      void settle(dispose);
      throw new StartupCancelled();
    }
    this.#stack.push(dispose);
  }

  /** Await `p`, unless the scope is cancelled first: then throw `StartupCancelled` at once. */
  step<T>(p: Promise<T>): Promise<T> {
    if (this.cancelled) {
      p.catch(() => {});
      return Promise.reject(new StartupCancelled());
    }
    const signal = this.signal;
    return new Promise<T>((resolve, reject) => {
      const onAbort = () => reject(new StartupCancelled());
      signal.addEventListener("abort", onAbort, { once: true });
      p.then(
        (v) => {
          signal.removeEventListener("abort", onAbort);
          resolve(v);
        },
        (e: unknown) => {
          signal.removeEventListener("abort", onAbort);
          reject(e);
        },
      );
    });
  }

  /**
   * Await a resource and register its `dispose`. A resource that arrives
   * after the scope is cancelled is disposed as it arrives.
   */
  async acquire<T>(p: Promise<T>, dispose: (resource: T) => Promise<void> | void): Promise<T> {
    let kept = false;
    p.then(
      (resource) => {
        if (!kept && this.cancelled) void settle(() => dispose(resource));
      },
      () => {},
    );
    const resource = await this.step(p);
    kept = true;
    this.register(() => dispose(resource));
    return resource;
  }

  /** Abort startup's awaits and release everything registered so far. */
  cancel(): Promise<void> {
    this.#controller.abort();
    return this.release();
  }

  /**
   * Dispose everything registered, last first, once. A disposal that throws
   * does not stop the rest; the first error is rethrown at the end.
   */
  release(): Promise<void> {
    this.#controller.abort();
    this.#released ??= (async () => {
      let first: unknown;
      for (const dispose of this.#stack.splice(0).reverse()) {
        try {
          await dispose();
        } catch (e) {
          first ??= e;
        }
      }
      if (first !== undefined) throw first;
    })();
    return this.#released;
  }
}

async function settle(dispose: Dispose): Promise<void> {
  try {
    await dispose();
  } catch {
    // A late resource's disposal has no caller to report to.
  }
}
