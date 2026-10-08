/**
 * @spec operation-profile-payments-v1 "Parameter schemas and normalization"
 * and D34 (D316, #1106): the PEP's tool-boundary intake.
 *
 * Every argument string is NFC-normalized first, and the normalized object is
 * then validated against the tool's served input schema, read as a CLOSED
 * schema: a member the schema does not declare (an authoritative field such
 * as `amount` included, since no served schema declares one) is refused, as
 * are a missing required member, a non-string value and a pattern miss. The
 * caller passes the normalized object, never the raw arguments, to target
 * lookup, effective-parameter construction and execution, so two encodings of
 * one string resolve one target and digest identically.
 *
 * The validator implements exactly the JSON Schema subset the served catalog
 * uses. A schema keyword outside it is a configuration fault and throws: a
 * constraint the served schema declares is never silently left unenforced.
 */

/** Why intake refused; operator-facing only, never a wire value. */
export type IntakeViolation =
  | "arguments_not_object"
  | "unknown_member"
  | "missing_member"
  | "member_not_string"
  | "pattern_mismatch";

export type IntakeOutcome =
  | { ok: true; args: Record<string, string> }
  | { ok: false; violation: IntakeViolation; member?: string };

interface ClosedSchema {
  properties: Record<string, { pattern?: RegExp }>;
  required: readonly string[];
}

const SCHEMA_KEYWORDS = new Set(["type", "properties", "required", "additionalProperties", "description"]);
const PROPERTY_KEYWORDS = new Set(["type", "pattern", "description"]);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

/** Parse a served input schema into the closed form intake enforces, or throw. */
export function closedSchema(inputSchema: unknown): ClosedSchema {
  if (!isPlainObject(inputSchema) || inputSchema.type !== "object") {
    throw new Error("intake: a served input schema must be an object schema");
  }
  for (const keyword of Object.keys(inputSchema)) {
    if (!SCHEMA_KEYWORDS.has(keyword)) throw new Error(`intake: unsupported schema keyword ${keyword}`);
  }
  if (inputSchema.additionalProperties !== undefined && inputSchema.additionalProperties !== false) {
    throw new Error("intake: a served input schema must be closed (additionalProperties: false)");
  }
  const declared = inputSchema.properties ?? {};
  if (!isPlainObject(declared)) throw new Error("intake: schema properties must be an object");
  const properties: ClosedSchema["properties"] = {};
  for (const [name, property] of Object.entries(declared)) {
    if (!isPlainObject(property) || property.type !== "string") {
      throw new Error(`intake: property ${name} must be a string schema`);
    }
    for (const keyword of Object.keys(property)) {
      if (!PROPERTY_KEYWORDS.has(keyword)) throw new Error(`intake: unsupported keyword ${keyword} on ${name}`);
    }
    if (property.pattern !== undefined && typeof property.pattern !== "string") {
      throw new Error(`intake: pattern on ${name} must be a string`);
    }
    properties[name] = property.pattern !== undefined ? { pattern: new RegExp(property.pattern, "u") } : {};
  }
  const required = inputSchema.required ?? [];
  if (!Array.isArray(required) || required.some((r) => typeof r !== "string" || !(r in properties))) {
    throw new Error("intake: required must name declared properties");
  }
  return { properties, required: required as string[] };
}

/**
 * NFC-normalize, then validate against the closed schema. On success the
 * returned `args` is the normalized object every later step uses.
 */
export function admitArguments(inputSchema: unknown, args: unknown): IntakeOutcome {
  const schema = closedSchema(inputSchema);
  if (!isPlainObject(args)) return { ok: false, violation: "arguments_not_object" };
  const normalized: Record<string, string> = {};
  for (const [member, value] of Object.entries(args)) {
    const property = Object.hasOwn(schema.properties, member) ? schema.properties[member] : undefined;
    if (!property) return { ok: false, violation: "unknown_member", member };
    if (typeof value !== "string") return { ok: false, violation: "member_not_string", member };
    const nfc = value.normalize("NFC");
    if (property.pattern && !property.pattern.test(nfc)) return { ok: false, violation: "pattern_mismatch", member };
    normalized[member] = nfc;
  }
  for (const member of schema.required) {
    if (!Object.hasOwn(normalized, member)) return { ok: false, violation: "missing_member", member };
  }
  return { ok: true, args: normalized };
}
