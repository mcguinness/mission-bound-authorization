import type { IncomingMessage, ServerResponse } from "node:http";

/**
 * How a switched endpoint answers:
 *
 * - `available`: the wrapped handler answers, as if no switch were there;
 * - `error`: a 5xx response (default 503), the handler never called;
 * - `reset`: the connection is closed with no response;
 * - `malformed`: 200 with a non-empty body that is not JSON.
 *
 * AAuth -11 Section 11.12.3 reads each of the last three as
 * `revocation_unavailable` ("did not respond, timed out, or returned a 5xx
 * or a malformed response"). A refused connection cannot be switched per
 * path; {@link LoopbackNetwork.refuse} refuses a whole host.
 */
export type OutageMode = "available" | "error" | "reset" | "malformed";

export interface EndpointSwitchOptions {
  /** Default `POST`. */
  method?: string;
  /** The exact path switched, without the query. */
  path: string;
  /** The status `error` answers with. Default 503. */
  status?: number;
}

/** A request the switch saw for its endpoint, and how it was answered. */
export interface SwitchedRequest {
  method: string;
  path: string;
  mode: OutageMode;
}

export type Handler = (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;

/**
 * A switch in front of one endpoint of a server, for tests that need it
 * unavailable: {@link wrap} the server's handler, then set {@link mode}.
 * Every other method and path reaches the handler unchanged. Each request
 * to the endpoint is recorded in {@link attempts}, whatever the mode, so a
 * test can count a caller's attempts and retries.
 */
export class EndpointSwitch {
  mode: OutageMode = "available";
  readonly method: string;
  readonly path: string;
  status: number;
  readonly attempts: SwitchedRequest[] = [];

  constructor(options: EndpointSwitchOptions) {
    this.method = options.method ?? "POST";
    this.path = options.path;
    this.status = options.status ?? 503;
    if (this.status < 500 || this.status > 599) {
      throw new RangeError(`status ${this.status} is not a 5xx`);
    }
  }

  /** The handler with this switch in front of its endpoint. */
  wrap(handler: Handler): (req: IncomingMessage, res: ServerResponse) => Promise<void> {
    return async (req, res) => {
      const method = req.method ?? "GET";
      const path = (req.url ?? "/").split("?")[0] ?? "/";
      if (method !== this.method || path !== this.path) {
        await handler(req, res);
        return;
      }
      const mode = this.mode;
      this.attempts.push({ method, path, mode });
      switch (mode) {
        case "available":
          await handler(req, res);
          return;
        case "error":
          res.writeHead(this.status, { "content-type": "application/problem+json" });
          res.end(
            JSON.stringify({ error: "server_error", detail: "the endpoint is switched off" }),
          );
          return;
        case "reset":
          req.socket.destroy();
          return;
        case "malformed":
          res.writeHead(200, { "content-type": "application/json" });
          res.end('{"downstream": [');
          return;
      }
    };
  }
}
