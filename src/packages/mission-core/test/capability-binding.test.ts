import { describe, expect, it } from "vitest";
import {
  CapabilityBindingError,
  capabilitySourceDigest,
  catalogDigest,
  DuplicateMemberError,
  extractMcpToolDefinition,
  normalizeCapabilitySources,
} from "../src/index.js";

// @spec draft-mcguinness-mission-capability-binding.md#capability-extraction:
// the published `write_document` worked value. Pinned as an EXTERNAL vector:
// a buggy canonicalizer or an accidental switch to the anchor envelope
// round-trips clean against itself, so only a value computed outside this
// codebase catches the drift.
const WRITE_DOCUMENT = {
  name: "write_document",
  description: "Create or update a document",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string" },
      content: { type: "string" },
    },
    required: ["path", "content"],
  },
};
const WRITE_DOCUMENT_DIGEST = "sha-256:OAbEIh2DTYUVP7DjRhHct4aapsT8PybZq2ILdut9UP0";

/** A catalog whose tool list carries the vector's tool plus unrelated ones. */
function catalogText(tools: unknown[]): string {
  return JSON.stringify({ tools }, null, 2);
}

const OTHER_TOOL = {
  name: "read_document",
  description: "Read a document",
  inputSchema: { type: "object" },
};

describe("capabilitySourceDigest: spec vector (capability-binding.md)", () => {
  it("reproduces the published write_document source_digest", () => {
    expect(capabilitySourceDigest(WRITE_DOCUMENT)).toBe(WRITE_DOCUMENT_DIGEST);
  });

  it("is invariant under member order (JCS sorts member names)", () => {
    const reordered = {
      inputSchema: {
        required: ["path", "content"],
        properties: { content: { type: "string" }, path: { type: "string" } },
        type: "object",
      },
      description: "Create or update a document",
      name: "write_document",
    };
    expect(capabilitySourceDigest(reordered)).toBe(WRITE_DOCUMENT_DIGEST);
  });

  it("is NOT the anchor envelope digest (no {typ, iss, value} wrapper)", () => {
    const enveloped = {
      typ: "mission-authority-entry",
      iss: "https://as.example.com",
      value: WRITE_DOCUMENT,
    };
    expect(capabilitySourceDigest(enveloped)).not.toBe(WRITE_DOCUMENT_DIGEST);
  });

  it("changes on any byte change inside the selected definition", () => {
    const mutated = { ...WRITE_DOCUMENT, description: "Create or update a document." };
    expect(capabilitySourceDigest(mutated)).not.toBe(WRITE_DOCUMENT_DIGEST);
    const widened = {
      ...WRITE_DOCUMENT,
      inputSchema: { ...WRITE_DOCUMENT.inputSchema, required: ["path"] },
    };
    expect(capabilitySourceDigest(widened)).not.toBe(WRITE_DOCUMENT_DIGEST);
  });

  it("different tools yield different digests", () => {
    expect(capabilitySourceDigest(OTHER_TOOL)).not.toBe(WRITE_DOCUMENT_DIGEST);
  });
});

describe("extractMcpToolDefinition: per-capability scope", () => {
  it("selects the tool list member whose name is the capability's", () => {
    const text = catalogText([OTHER_TOOL, WRITE_DOCUMENT]);
    expect(capabilitySourceDigest(extractMcpToolDefinition(text, "write_document"))).toBe(
      WRITE_DOCUMENT_DIGEST,
    );
  });

  it("adding, removing, or renaming an unrelated tool leaves the digest unchanged", () => {
    const digestOf = (tools: unknown[]) =>
      capabilitySourceDigest(extractMcpToolDefinition(catalogText(tools), "write_document"));
    const added = {
      name: "delete_document",
      description: "Delete",
      inputSchema: { type: "object" },
    };
    expect(digestOf([WRITE_DOCUMENT])).toBe(WRITE_DOCUMENT_DIGEST);
    expect(digestOf([OTHER_TOOL, WRITE_DOCUMENT, added])).toBe(WRITE_DOCUMENT_DIGEST);
    expect(digestOf([{ ...OTHER_TOOL, name: "fetch_document" }, WRITE_DOCUMENT])).toBe(
      WRITE_DOCUMENT_DIGEST,
    );
  });

  it("any byte change to the selected definition changes the digest", () => {
    const text = catalogText([OTHER_TOOL, { ...WRITE_DOCUMENT, description: "Create a document" }]);
    expect(capabilitySourceDigest(extractMcpToolDefinition(text, "write_document"))).not.toBe(
      WRITE_DOCUMENT_DIGEST,
    );
  });

  it("accepts a bare tool-list array as well as a tools object", () => {
    const text = JSON.stringify([OTHER_TOOL, WRITE_DOCUMENT]);
    expect(capabilitySourceDigest(extractMcpToolDefinition(text, "write_document"))).toBe(
      WRITE_DOCUMENT_DIGEST,
    );
  });

  it("refuses a catalog with no tool list", () => {
    expect(() =>
      extractMcpToolDefinition(JSON.stringify({ name: "payments" }), "write_document"),
    ).toThrow(CapabilityBindingError);
  });

  it("refuses a missing definition rather than returning nothing", () => {
    expect(() => extractMcpToolDefinition(catalogText([OTHER_TOOL]), "write_document")).toThrow(
      /no tool named/,
    );
  });

  it("refuses duplicate tool names rather than picking one", () => {
    const text = catalogText([WRITE_DOCUMENT, { ...WRITE_DOCUMENT, description: "Impostor" }]);
    expect(() => extractMcpToolDefinition(text, "write_document")).toThrow(/ambiguous tool name/);
  });

  it("refuses duplicate JSON member names before canonicalization", () => {
    const text = '{"tools":[{"name":"write_document","name":"read_document"}]}';
    expect(() => extractMcpToolDefinition(text, "write_document")).toThrow(DuplicateMemberError);
  });

  it("refuses malformed JSON", () => {
    expect(() => extractMcpToolDefinition('{"tools":[', "write_document")).toThrow(SyntaxError);
  });
});

describe("catalogDigest: exact retrieved octets", () => {
  it("hashes the served bytes, not a canonicalization of them", () => {
    const pretty = catalogText([WRITE_DOCUMENT]);
    const compact = JSON.stringify({ tools: [WRITE_DOCUMENT] });
    expect(catalogDigest(pretty)).not.toBe(catalogDigest(compact));
    // ... while the per-capability digest is unmoved by the same reformat.
    expect(capabilitySourceDigest(extractMcpToolDefinition(pretty, "write_document"))).toBe(
      capabilitySourceDigest(extractMcpToolDefinition(compact, "write_document")),
    );
  });

  it("moves on any raw-octet change, including an unrelated tool", () => {
    const before = catalogDigest(catalogText([WRITE_DOCUMENT]));
    expect(catalogDigest(catalogText([WRITE_DOCUMENT, OTHER_TOOL]))).not.toBe(before);
    expect(catalogDigest(`${catalogText([WRITE_DOCUMENT])}\n`)).not.toBe(before);
  });

  it("agrees between a UTF-8 string and its bytes", () => {
    const text = catalogText([WRITE_DOCUMENT]);
    expect(catalogDigest(new TextEncoder().encode(text))).toBe(catalogDigest(text));
  });
});

describe("normalizeCapabilitySources: committed-array validation", () => {
  const binding = {
    action: "payments:payment.schedule",
    tool_id: "mcp://payments.example.com/tools/schedule_payment",
    source_uri: "https://payments.example.com/.well-known/mcp",
    source_digest: WRITE_DOCUMENT_DIGEST,
    operation_ref: "schedule_payment",
  };

  it("permits several tool_id values for one action", () => {
    const out = normalizeCapabilitySources([
      binding,
      { ...binding, tool_id: "mcp://payments.example.com/tools/schedule_payment_v2" },
    ]);
    expect(out).toHaveLength(2);
    expect(out.map((b) => b.action)).toEqual([binding.action, binding.action]);
  });

  it("refuses a repeated (action, tool_id) pair", () => {
    expect(() =>
      normalizeCapabilitySources([binding, { ...binding, operation_ref: "other" }]),
    ).toThrow(/duplicate capability source/);
  });

  it("refuses an unrecognized digest algorithm prefix on source_digest", () => {
    expect(() =>
      normalizeCapabilitySources([{ ...binding, source_digest: "sha-512:AAAA" }]),
    ).toThrow(/unrecognized source_digest algorithm prefix: sha-512/);
  });

  it("refuses an unrecognized digest algorithm prefix on catalog_digest", () => {
    expect(() =>
      normalizeCapabilitySources([{ ...binding, catalog_digest: "blake3:AAAA" }]),
    ).toThrow(/unrecognized catalog_digest algorithm prefix: blake3/);
  });

  it("refuses a malformed member", () => {
    expect(() => normalizeCapabilitySources([{ ...binding, tool_id: "" }])).toThrow(
      /tool_id must be a non-empty string/,
    );
  });

  it("orders the committed array reproducibly, whatever the resolution order", () => {
    const a = binding;
    const b = {
      ...binding,
      action: "payments:payment.execute",
      operation_ref: "execute_wire_transfer",
    };
    expect(normalizeCapabilitySources([a, b])).toEqual(normalizeCapabilitySources([b, a]));
  });

  it("drops nothing and keeps catalog_digest when recorded", () => {
    const withCatalog = { ...binding, catalog_digest: WRITE_DOCUMENT_DIGEST };
    expect(normalizeCapabilitySources([withCatalog])[0]).toEqual(withCatalog);
  });
});
