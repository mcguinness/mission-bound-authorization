/**
 * @spec fga-hygiene (docs/fga-hygiene.md), decision D26
 *
 * OpenFGA integration. Stored tuples hold ONLY the durable domain substrate
 * (invoice ownership, vendor status, roles). Mission authority is injected
 * per check as contextual tuples derived from the Mission Record; nothing
 * mission-scoped is ever written to the store. Every check pins an explicit
 * authorization_model_id.
 */

import { readFileSync } from "node:fs";
import { getTracer } from "@mission/telemetry";
import { CredentialsMethod, OpenFgaClient, type TupleKey } from "@openfga/sdk";

/**
 * Domain model: the substrate only. Mission authority ("who may pay what")
 * arrives as contextual tuples of relation `payer`/`reader` on invoices and
 * vendors, keyed by a per-check ephemeral `mission:<id>` object.
 */
export const DOMAIN_MODEL = {
  schema_version: "1.1",
  type_definitions: [
    { type: "user" },
    { type: "client" },
    {
      type: "vendor",
      relations: { approved: { this: {} }, reader: { this: {} } },
      metadata: {
        relations: {
          approved: { directly_related_user_types: [{ type: "mission" }] },
          reader: { directly_related_user_types: [{ type: "mission" }] },
        },
      },
    },
    {
      type: "invoice",
      relations: { payer: { this: {} }, reader: { this: {} } },
      metadata: {
        relations: {
          payer: { directly_related_user_types: [{ type: "mission" }] },
          reader: { directly_related_user_types: [{ type: "mission" }] },
        },
      },
    },
    { type: "mission" },
  ],
} as const;

export interface FgaConfig {
  apiUrl: string;
  storeId: string;
  authorizationModelId: string;
  presharedKey: string;
  caCertPath?: string;
}

export class Fga {
  private constructor(
    readonly client: OpenFgaClient,
    readonly modelId: string,
  ) {}

  static async connect(cfg: {
    apiUrl: string;
    presharedKey: string;
    caCertPath?: string;
  }): Promise<{ fga: Fga; storeId: string; modelId: string }> {
    if (cfg.caCertPath) {
      // Trust the dev CA for the TLS edge (channel matrix D39).
      process.env.NODE_EXTRA_CA_CERTS = cfg.caCertPath;
    }
    const bootstrap = new OpenFgaClient({
      apiUrl: cfg.apiUrl,
      credentials: { method: CredentialsMethod.ApiToken, config: { token: cfg.presharedKey } },
    });
    const store = await bootstrap.createStore({ name: "mission-payments" });
    const client = new OpenFgaClient({
      apiUrl: cfg.apiUrl,
      storeId: store.id,
      credentials: { method: CredentialsMethod.ApiToken, config: { token: cfg.presharedKey } },
    });
    const model = await client.writeAuthorizationModel(DOMAIN_MODEL as never);
    return {
      fga: new Fga(client, model.authorization_model_id),
      storeId: store.id as string,
      modelId: model.authorization_model_id as string,
    };
  }

  /** Seed durable domain-substrate tuples (batched under the 100-tuple limit). */
  async seedDomain(tuples: TupleKey[]): Promise<void> {
    for (let i = 0; i < tuples.length; i += 100) {
      await this.client.write(
        { writes: tuples.slice(i, i + 100) },
        { authorizationModelId: this.modelId },
      );
    }
  }

  /**
   * Authority check with contextual tuples (D26): mission-scoped tuples are
   * supplied per check, never stored. Higher consistency is used when the
   * caller just wrote substrate (fga-hygiene).
   */
  async checkWithContext(
    check: { user: string; relation: string; object: string },
    contextualTuples: TupleKey[],
    opts: { higherConsistency?: boolean } = {},
  ): Promise<boolean> {
    return getTracer("pdp").startActiveSpan("fga.check", async (span) => {
      span.setAttribute("fga.relation", check.relation);
      span.setAttribute("fga.object", check.object);
      try {
        return await this.doCheck(check, contextualTuples, opts);
      } finally {
        span.end();
      }
    });
  }

  private async doCheck(
    check: { user: string; relation: string; object: string },
    contextualTuples: TupleKey[],
    opts: { higherConsistency?: boolean } = {},
  ): Promise<boolean> {
    const res = await this.client.check(
      {
        user: check.user,
        relation: check.relation,
        object: check.object,
        ...(contextualTuples.length ? { contextualTuples } : {}),
      },
      {
        authorizationModelId: this.modelId,
        consistency: opts.higherConsistency ? "HIGHER_CONSISTENCY" : "MINIMIZE_LATENCY",
      } as never,
    );
    return res.allowed === true;
  }
}

export function loadCa(path: string | undefined): string | undefined {
  if (!path) return undefined;
  try {
    readFileSync(path);
    return path;
  } catch {
    return undefined;
  }
}
