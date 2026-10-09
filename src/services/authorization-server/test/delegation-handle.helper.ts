/**
 * @spec continuation#transport-async (#1157, D358): the token-endpoint
 * parameters of a delegation-handle request: an RFC 8693 exchange of the
 * agent's own Mission access token for an access token audienced to the agent
 * itself, which the async-delegation transport takes as its subject_token.
 * Each test file sends them with its own client authentication and a DPoP
 * proof over the presented token's key (the handle keeps that key).
 */
export function delegationHandleParams(subjectToken: string, clientId: string): Record<string, string> {
  return {
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    subject_token: subjectToken,
    subject_token_type: "urn:ietf:params:oauth:token-type:access_token",
    requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
    audience: clientId,
  };
}
