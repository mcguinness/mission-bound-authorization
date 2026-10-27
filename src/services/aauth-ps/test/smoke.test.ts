import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  type Agent,
  approve,
  claims,
  makeAgent,
  personToken,
  RS,
  requestAuthToken,
  resourceTokenFor,
  type World,
  world,
} from "./helpers.js";

let w: World;
let agent: Agent;

beforeEach(async () => {
  w = await world();
  agent = await makeAgent(w.ap, w.clock);
});
afterEach(async () => {
  await w.close();
});

describe("smoke", () => {
  it("runs the three-party route end to end", async () => {
    const { s256 } = await approve(w, agent);
    const pt = await personToken(w, agent, RS, s256);
    const rt = await resourceTokenFor(w, agent, pt);
    const r = await requestAuthToken(w, agent, { resource_token: rt, presented_token: pt });
    expect(r.status, JSON.stringify(r.body)).toBe(200);
    expect(claims(r.body.auth_token as string).mission_s256).toBe(s256);
  });
});
