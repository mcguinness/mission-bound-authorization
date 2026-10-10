/**
 * @spec mission#issuance-gating (#1154, D369): the token endpoint's Mission
 * gate refusal by grant. A lifecycle refusal (the Mission is not `active`) on
 * a Token Exchange is `invalid_request` (RFC 8693 Section 2.2.2); a limit or
 * empty-authority refusal, and every refusal on any other grant, is
 * `invalid_grant`. Both carry `mission_error` where a value applies.
 */

import { describe, expect, it } from "vitest";
import { TOKEN_EXCHANGE_GRANT_TYPE } from "../src/adapters/continuation-grant.js";
import {
  childErrorCode,
  isTokenExchangeRequest,
  MissionExchangeError,
  MissionGrantError,
  tokenEndpointGateRefusal,
} from "../src/adapters/provider.js";

const request = (grantType: string) => ({ oidc: { params: { grant_type: grantType } } });
const errorOf = (e: Error) => (e as Error & { error?: string }).error;

describe("token-endpoint Mission gate refusal by grant (@spec mission#issuance-gating, #1154)", () => {
  it("identifies a Token Exchange request by its grant_type alone", () => {
    expect(isTokenExchangeRequest(request(TOKEN_EXCHANGE_GRANT_TYPE))).toBe(true);
    for (const grantType of [
      "authorization_code",
      "refresh_token",
      "urn:ietf:params:oauth:grant-type:jwt-bearer",
    ]) {
      expect(isTokenExchangeRequest(request(grantType)), grantType).toBe(false);
    }
    expect(isTokenExchangeRequest(undefined)).toBe(false);
  });

  it("a lifecycle refusal is invalid_request on a Token Exchange and invalid_grant on every other grant, with mission_error kept", () => {
    for (const reason of ["mission_not_active", "mission_expired"] as const) {
      const exchange = tokenEndpointGateRefusal(reason, "refused", "revoked", true);
      expect(exchange, reason).toBeInstanceOf(MissionExchangeError);
      expect(errorOf(exchange), reason).toBe("invalid_request");
      expect((exchange as MissionExchangeError).missionError).toBe("revoked");
      const other = tokenEndpointGateRefusal(reason, "refused", "revoked", false);
      expect(other, reason).toBeInstanceOf(MissionGrantError);
      expect(errorOf(other), reason).toBe("invalid_grant");
      expect((other as MissionGrantError).missionError).toBe("revoked");
    }
  });

  it("a limit or empty-authority refusal stays invalid_grant on a Token Exchange", () => {
    for (const reason of ["derivation_cap_exhausted", "authority_contained", "authority_exhausted"] as const) {
      const missionError = reason === "derivation_cap_exhausted" ? "derivations_exhausted" : undefined;
      const refusal = tokenEndpointGateRefusal(reason, "refused", missionError, true);
      expect(refusal, reason).toBeInstanceOf(MissionGrantError);
      expect(errorOf(refusal), reason).toBe("invalid_grant");
      expect((refusal as MissionGrantError).missionError).toBe(missionError);
    }
  });

  it("child creation: parent_not_active rides invalid_request and parent_mismatch keeps invalid_grant (@spec child-delegation#denial-reasons)", () => {
    expect(childErrorCode("parent_not_active")).toBe("invalid_request");
    expect(childErrorCode("parent_mismatch")).toBe("invalid_grant");
    expect(childErrorCode("policy_denied")).toBe("access_denied");
    expect(childErrorCode("not_strict_subset")).toBe("invalid_request");
  });
});
