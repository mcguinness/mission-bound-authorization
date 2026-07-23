/**
 * @spec draft-mcguinness-svc-connectivity-disco
 *
 * The Service Connectivity Catalog, co-located in the AS (D8). Produces a
 * per-user catalog of reachable services; per-connection `status` is derived
 * from Mission state (D9): an active covering mission -> `connected`,
 * approvable issuance -> `consent_required`, revoked/none -> `unavailable`.
 * An out-of-reach service carries a `request-access` link into the ARS (D10).
 */

import type { MissionKernel } from "./kernel.js";
import type { AuthorityEntry } from "./types.js";

export type ConnectionStatus = "connected" | "available" | "consent_required" | "unavailable";

export interface ServiceSeed {
  id: string;
  display_name: string;
  type: "mcp" | "http" | "a2a";
  endpoint: string;
  categories?: string[];
  tags?: string[];
  server_card_uri?: string;
  /** The resource URI a covering mission's authority entry must match. */
  resource: string;
  connection: { profile: "oauth"; type: "authorization_code" | "token_exchange" | "id_jag" };
  /** True if the user can obtain authority by approval (else out of reach). */
  approvable: boolean;
}

export interface CatalogConnection {
  profile: "oauth";
  type: string;
  status: ConnectionStatus;
  authorization_server: string;
}

export interface CatalogService {
  id: string;
  display_name: string;
  type: string;
  endpoint: string;
  categories?: string[];
  tags?: string[];
  links?: Array<{ rel: string; href: string }>;
  server_card_uri?: string;
  connections: CatalogConnection[];
}

export interface CatalogFilter {
  category?: string;
  type?: string;
  status?: ConnectionStatus;
  profile?: string;
  tag?: string;
}

export class CatalogProvider {
  constructor(
    private readonly kernel: MissionKernel,
    private readonly services: ServiceSeed[],
    private readonly opts: { arsIntakeUrl: string; issuer: string },
  ) {}

  /**
   * Produce the catalog for a user, scoped by optional filters. Status is
   * computed from the user's current missions -- no per-service token needed.
   */
  catalog(user: string, filter: CatalogFilter = {}): { services: CatalogService[] } {
    const missions = this.kernel.activeMissionsForSubject(user);
    let services = this.services.map((s) => this.toService(s, missions));
    if (filter.category) services = services.filter((s) => s.categories?.includes(filter.category as string));
    if (filter.type) services = services.filter((s) => s.type === filter.type);
    if (filter.tag) services = services.filter((s) => s.tags?.includes(filter.tag as string));
    if (filter.profile) services = services.filter((s) => s.connections.some((c) => c.profile === filter.profile));
    if (filter.status) services = services.filter((s) => s.connections.some((c) => c.status === filter.status));
    return { services };
  }

  private toService(seed: ServiceSeed, missions: { authority_set: AuthorityEntry[] }[]): CatalogService {
    const covered = missions.some((m) => m.authority_set.some((e) => e.resource === seed.resource));
    const status: ConnectionStatus = covered
      ? "connected"
      : seed.approvable
        ? "consent_required"
        : "unavailable";
    const service: CatalogService = {
      id: seed.id,
      display_name: seed.display_name,
      type: seed.type,
      endpoint: seed.endpoint,
      ...(seed.categories ? { categories: seed.categories } : {}),
      ...(seed.tags ? { tags: seed.tags } : {}),
      ...(seed.server_card_uri ? { server_card_uri: seed.server_card_uri } : {}),
      connections: [
        {
          profile: seed.connection.profile,
          type: seed.connection.type,
          status,
          authorization_server: this.opts.issuer,
        },
      ],
    };
    const links: Array<{ rel: string; href: string }> = [];
    if (seed.server_card_uri) links.push({ rel: "mcp-server-card", href: seed.server_card_uri });
    // @spec disco#link-object: out-of-reach services carry a request-access
    // link into the ARS intake (D10).
    if (status === "unavailable") {
      links.push({ rel: "request-access", href: `${this.opts.arsIntakeUrl}?service=${encodeURIComponent(seed.id)}` });
    }
    if (links.length) service.links = links;
    return service;
  }
}
