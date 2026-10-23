/**
 * @spec authority-server#join-assertion-request, authority-server#join-authzen (#1454)
 *
 * The PEP's side of the Mission Join Assertion request: "The PEP, or the
 * client acting for it, sends a POST request" to the MAS's
 * `mission_join_assertion_endpoint`. Here the PEP sends it, in the
 * interoperable `access_token` form, for the credential it authenticated, so
 * the acting client needs no MAS registration and the digest and thumbprint
 * the PEP reports beside the assertion are computed from the same credential
 * it verified. The caller authenticates by private-key JWT, the assertion's
 * `aud` naming the endpoint.
 *
 * Any refusal or failure yields no assertion; the decision request then
 * carries none, and the PDP applies its declared requirement.
 */

/** Where the PEP obtains a Join Assertion for one joined request. */
export interface JoinAssertionSource {
  obtain(input: { mission: { id: string; issuer: string }; accessToken: string }): Promise<string | undefined>;
}

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface JoinAssertionClientOptions {
  /** The MAS's advertised `mission_join_assertion_endpoint`. */
  endpoint: string;
  /** The consuming PDP, as the MAS's enrollment identifies it. */
  audience: string;
  /** The caller's credential at the MAS: a fresh client assertion whose `aud` is `endpoint`. */
  clientAssertion: () => Promise<string>;
  /** Upper bound on one request, milliseconds. */
  timeoutMs: number;
}

/** A Join Assertion source that asks the MAS's endpoint over HTTP. */
export function joinAssertionClient(opts: JoinAssertionClientOptions): JoinAssertionSource {
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
            client_assertion: await opts.clientAssertion(),
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
