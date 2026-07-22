import { describe, expect, it } from "vitest";
import {
  type ActObject,
  ActorChainError,
  buildContextActor,
  extendChain,
  flattenActChain,
  validateActChain,
  validateContextActor,
} from "../src/index.js";

/**
 * Golden flattening vectors (S-2 contribution: normative nested->root-to-leaf
 * transform). Nested `act` is outermost-first; the array is root-to-leaf.
 */
describe("flattenActChain golden vectors (@spec authzen#context-actor)", () => {
  it("single actor -> one-element array", () => {
    const act: ActObject = { iss: "https://as", sub: "agent-1", sub_profile: "ai_agent" };
    expect(flattenActChain(act)).toEqual([
      { iss: "https://as", sub: "agent-1", sub_profile: "ai_agent" },
    ]);
  });

  it("user -> orchestrator -> tool nests outermost-first, flattens root-to-leaf", () => {
    // Token: outermost (leaf/current) = tool; innermost = orchestrator (first
    // actor authorized by the user subject).
    const act: ActObject = {
      iss: "https://as",
      sub: "tool",
      sub_profile: "ai_agent client_instance",
      act: { iss: "https://as", sub: "orchestrator", sub_profile: "ai_agent" },
    };
    expect(flattenActChain(act)).toEqual([
      { iss: "https://as", sub: "orchestrator", sub_profile: "ai_agent" },
      { iss: "https://as", sub: "tool", sub_profile: "ai_agent client_instance" },
    ]);
  });

  it("empty when there is no act claim", () => {
    expect(flattenActChain(undefined)).toEqual([]);
  });

  it("rejects a cyclic chain", () => {
    const a: ActObject = { iss: "i", sub: "s" };
    a.act = a;
    expect(() => flattenActChain(a)).toThrow(ActorChainError);
  });
});

describe("validateActChain (@spec actor-profile#actor-object-structure)", () => {
  it("requires iss and sub on every hop", () => {
    expect(() => validateActChain({ sub: "x" } as ActObject)).toThrow(/missing required iss/);
    expect(() => validateActChain({ iss: "i" } as ActObject)).toThrow(/missing required sub/);
  });

  it("enforces the local maximum depth (default 4), never truncating", () => {
    const deep: ActObject = {
      iss: "i",
      sub: "a",
      act: {
        iss: "i",
        sub: "b",
        act: { iss: "i", sub: "c", act: { iss: "i", sub: "d", act: { iss: "i", sub: "e" } } },
      },
    };
    expect(() => validateActChain(deep)).toThrow(/exceeds local maximum/);
    expect(validateActChain(deep, { maxDepth: 5 })).toHaveLength(5);
  });

  it("rejects client_profile inside an act node", () => {
    expect(() =>
      validateActChain({ iss: "i", sub: "s", client_profile: "web_app" } as ActObject),
    ).toThrow(/client_profile MUST NOT/);
  });

  it("preserves unknown-but-syntactically-valid sub_profile tokens", () => {
    expect(() =>
      validateActChain({
        iss: "i",
        sub: "s",
        sub_profile: "ai_agent acme.verified_robot",
      } as ActObject),
    ).not.toThrow();
  });

  it("rejects a syntactically invalid sub_profile token", () => {
    expect(() =>
      validateActChain({ iss: "i", sub: "s", sub_profile: "bad token!" } as ActObject),
    ).toThrow(/invalid sub_profile token/);
  });
});

describe("buildContextActor / validateContextActor (@spec authzen#context-actor, D31)", () => {
  it("omits act when self-acting; includes client identity", () => {
    const actor = buildContextActor({ clientId: "ap-agent" });
    expect(actor).toEqual({ client_id: "ap-agent" });
    expect(actor.act).toBeUndefined();
  });

  it("produces the root-to-leaf array with client identity", () => {
    const actor = buildContextActor({
      clientId: "ap-agent",
      clientInstanceId: "inst-9",
      act: {
        iss: "https://as",
        sub: "inst-9",
        sub_profile: "ai_agent client_instance",
        act: { iss: "https://as", sub: "orchestrator", sub_profile: "ai_agent" },
      },
    });
    expect(actor.act?.map((e) => e.sub)).toEqual(["orchestrator", "inst-9"]);
    expect(() => validateContextActor(actor, { subject: "alice" })).not.toThrow();
  });

  it("PDP rejects a leaf inconsistent with client_instance_id", () => {
    const actor = buildContextActor({
      clientInstanceId: "inst-9",
      act: { iss: "https://as", sub: "different", sub_profile: "client_instance" },
    });
    expect(() => validateContextActor(actor)).toThrow(/inconsistent with client_instance_id/);
  });
});

describe("extendChain (@spec actor-profile delegation construction)", () => {
  it("installs the new actor as outermost, preserving the inbound chain beneath", () => {
    const inbound: ActObject = { iss: "https://as", sub: "orchestrator", sub_profile: "ai_agent" };
    const extended = extendChain(
      { iss: "https://as", sub: "tool", sub_profile: "ai_agent client_instance" },
      inbound,
    );
    expect(extended.sub).toBe("tool");
    expect(extended.act).toEqual(inbound);
    // Flattening the extended chain yields root-to-leaf order.
    expect(flattenActChain(extended).map((e) => e.sub)).toEqual(["orchestrator", "tool"]);
  });

  it("with no inbound chain, the new actor is a depth-1 chain", () => {
    const extended = extendChain({ iss: "https://as", sub: "agent" }, undefined);
    expect(extended.act).toBeUndefined();
    expect(flattenActChain(extended)).toHaveLength(1);
  });
});
