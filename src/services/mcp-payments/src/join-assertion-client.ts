/**
 * @spec authority-server#join-assertion-request, authority-server#join-authzen (#1454)
 *
 * The PEP's side of the Mission Join Assertion request: "The PEP, or the
 * client acting for it, sends a POST request" to the MAS's
 * `mission_join_assertion_endpoint`. Here the PEP sends it, in the
 * interoperable `access_token` form, for the credential it authenticated, so
 * the acting client needs no MAS registration and the digest and thumbprint
 * the PEP reports beside the assertion are computed from the same credential
 * it verified.
 *
 * The caller authenticates by private-key JWT exactly as at Mission Status:
 * its client assertion's `aud` is the MAS's issuer identifier as its sole
 * value (D685, D690), never the endpoint. This client builds that assertion
 * itself, so no caller can name another audience.
 *
 * Any refusal or failure yields no assertion; the decision request then
 * carries none, and the PDP applies its declared requirement.
 */

import type { KeyObject } from "node:crypto";
import { privateKeyJwtClient } from "@mission/pdp";

/** Where the PEP obtains a Join Assertion for one joined request. */
export interface JoinAssertionSource {
  obtain(input: { mission: { id: string; issuer: string }; accessToken: string }): Promise<string | undefined>;
}

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface JoinAssertionClientOptions {
  /** The MAS's advertised `mission_join_assertion_endpoint`. */
  endpoint: string;
  /** The MAS's issuer identifier: the sole `aud` of the caller's client assertion. */
  issuer: string;
  /** The consuming PDP, as the MAS's enrollment identifies it. */
  audience: string;
  /** The caller's private-key JWT credential at the MAS. */
  caller: { clientId: string; privateKey: CryptoKey | KeyObject | Uint8Array; kid: string; alg?: string; now?: () => Date };
  /** Upper bound on one request, milliseconds. */
  timeoutMs: number;
}

/** A Join Assertion source that asks the MAS's endpoint over HTTP. */
export function joinAssertionClient(opts: JoinAssertionClientOptions): JoinAssertionSource {
  const credential = privateKeyJwtClient({ ...opts.caller, issuer: opts.issuer });
  return {
    obtain: async ({ mission, accessToken }) => {
      try {
        const res = await fetch(opts.endpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            mission_id: mission.id,
            audience: opts.audience,
            access_token: accessToken,
            client_assertion_type: CLIENT_ASSERTION_TYPE,
            client_assertion: await credential.assertion(),
          }),
          signal: AbortSignal.timeout(opts.timeoutMs),
        });
        const body = (await res.json().catch(() => undefined)) as { assertion?: unknown } | undefined;
        return res.status === 200 && typeof body?.assertion === "string" ? body.assertion : undefined;
      } catch {
        return undefined;
      }
    },
  };
}
