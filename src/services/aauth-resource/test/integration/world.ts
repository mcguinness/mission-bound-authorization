/**
 * The three-party route on one loopback network, every party real: the
 * testkit's agent provider and agent client, the AAuth Person Server
 * (`@mission/aauth-ps`, its durable SQLite store on a temporary file) and
 * this package's Resource. Both servers load the shipped configuration
 * (`src/config/aauth-ps.json`, `src/config/aauth-resource.json`), whose
 * agents are the provider's `assistant` and `planner` (alice, under
 * mission governance) and `helper` (bob, admitted missionless).
 *
 * Topology (the slice's composition contract): identifiers carry no port
 * (`https://ap.test`, `https://ps.test`, `https://resource.test`); each
 * party is real HTTP on an ephemeral port of 127.0.0.1, and an
 * `https://host/path` URL travels as plain HTTP to that port with `Host`
 * the identifier's host. There is no TLS. Key discovery goes through the
 * library's resolver, egress admission and pinned fetch, admitting only
 * the hosts registered here. One clock drives every party.
 *
 * The Resource's revoked set is durable SQLite on a temporary file, and
 * its revocation endpoint sits behind the testkit's switch
 * (`revocationSwitch`), so a test can make revocation unavailable.
 *
 * The PS serves the mission control plane of AAuth Mission Management
 * (#836 slice 3): `management` gets the same durable store, the network as
 * its outbound transport and the shared clock's sleep. Revocation work
 * runs when a termination commits and when a test calls
 * `ps.revocations.runDue()`; a restarted PS can also run it on an
 * interval. The shipped administrator's private key is held by no one, so
 * the world enrolls two administrators of its own under the shipped
 * policy: alice's (`ADMIN`) and bob's (`ADMIN_BOB`).
 */
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createPersonServer,
  type IssuedTokenRecord,
  type MissionLogEntry,
  type MissionRecord,
  type PersonServer,
  type PsConfig,
  type PsStore,
  parsePsConfig,
  SqlitePsStore,
} from "@mission/aauth-ps";
import {
  type AgentClient,
  AgentError,
  type AgentProvider,
  createAgent,
  createAgentProvider,
  decodeClaims,
  EndpointSwitch,
  LoopbackNetwork,
  type LoopbackResponse,
  ManagementClient,
  ManualClock,
  type Misbehavior,
} from "@mission/aauth-testkit";
import {
  type AAuthTokenType,
  generateSigningKey,
  mintToken,
  type SigningKey,
} from "@mission/aauth-wire";
import { expect } from "vitest";
import {
  createResource,
  listen,
  loadResourceConfig,
  mintResourceToken,
  REVOCATION_PATH,
  type Resource,
  SqliteRevocationStore,
} from "../../src/index.js";

export const AP = "https://ap.test";
export const PS = "https://ps.test";
export const RESOURCE = "https://resource.test";

const CONFIG_DIR = join(dirname(fileURLToPath(import.meta.url)), "../../../../config");

/** The shipped PS configuration document, for a test to derive its own from. */
export function shippedPsConfig(): Record<string, unknown> {
  return JSON.parse(readFileSync(join(CONFIG_DIR, "aauth-ps.json"), "utf8"));
}

/** The shipped administrator's identifier, governing alice's missions. */
export const ADMIN = "https://admin.ps.test";
/** A second administrator, governing bob's missions only. */
export const ADMIN_BOB = "https://admin-bob.ps.test";

/**
 * A statically configured administrator with the private half of its
 * enrolled key: it signs control-plane requests under Signature-Key
 * `jwks_uri` with `id`, `dwk` and `kid`, and the PS takes the public key
 * from its configuration, never by fetching.
 */
export interface Administrator {
  id: string;
  dwk: string;
  kid: string;
  key: SigningKey;
}

function administrator(id: string): Administrator {
  return {
    id,
    dwk: "mission-admin.json",
    kid: "admin-1",
    key: generateSigningKey("Ed25519", "admin-1"),
  };
}

/**
 * The shipped configuration with the world's own administrators enrolled
 * in place of the shipped one, under the shipped actions: alice's missions
 * for `ADMIN`, bob's for `ADMIN_BOB`. Everything else, the revocation
 * retry policy included, is as shipped.
 */
function worldPsConfig(admins: {
  alice: Administrator;
  bob: Administrator;
}): Record<string, unknown> {
  const doc = shippedPsConfig();
  const management = doc.management as Record<string, unknown>;
  const entry = (admin: Administrator, persons: string[]) => ({
    id: admin.id,
    dwk: admin.dwk,
    key: admin.key.publicJwk,
    persons,
    actions: ["status", "terminate"],
  });
  management.administrators = [entry(admins.alice, ["alice"]), entry(admins.bob, ["bob"])];
  return doc;
}

/**
 * The PS's durable store with one switch and one counter: a mission read
 * that cannot establish state (V12), and the number of mission reads, so
 * a test can show a refusal came before any mission state was used.
 */
export class ObservedStore implements PsStore {
  failMissionReads = false;
  missionReads = 0;

  constructor(
    public inner: SqlitePsStore,
    private readonly file: string,
  ) {}

  /** Close the durable store and open another on the same file, as a process restart does. */
  reopen(): void {
    this.inner.close();
    this.inner = new SqlitePsStore(this.file);
  }

  findOwnedMission(agent: string, s256: string): MissionRecord | undefined {
    this.missionReads += 1;
    if (this.failMissionReads) throw new Error("mission state is unavailable");
    return this.inner.findOwnedMission(agent, s256);
  }
  approve(...args: Parameters<PsStore["approve"]>): void {
    this.inner.approve(...args);
  }
  recordIssued(...args: Parameters<PsStore["recordIssued"]>): void {
    this.inner.recordIssued(...args);
  }
  terminate(...args: Parameters<PsStore["terminate"]>): boolean {
    return this.inner.terminate(...args);
  }
  issuedTokens(): IssuedTokenRecord[] {
    return this.inner.issuedTokens();
  }
  missionLog(s256: string): MissionLogEntry[] {
    return this.inner.missionLog(s256);
  }
  pairwiseKey(): Buffer {
    return this.inner.pairwiseKey();
  }
  close(): void {
    this.inner.close();
  }
}

/** What the PS has recorded: every issued-token record and each known mission's log. */
export interface PsRecords {
  issued: IssuedTokenRecord[];
  logs: Record<string, MissionLogEntry[]>;
}

export interface World {
  net: LoopbackNetwork;
  clock: ManualClock;
  provider: AgentProvider;
  ps: PersonServer;
  store: ObservedStore;
  resource: Resource;
  /** The enrolled administrators, with their private keys. */
  admins: { alice: Administrator; bob: Administrator };
  /** The switch in front of the Resource's revocation endpoint. */
  revocationSwitch: EndpointSwitch;
  /** Every mission `s256` a test approved or named, for {@link World.records}. */
  missions: Set<string>;
  seconds(): number;
  /** An agent of the provider, whose PS is this world's PS. */
  agent(local?: string, misbehavior?: Misbehavior): Promise<AgentClient>;
  /** Propose a mission as `agent`, and remember its `s256`. */
  approve(agent: AgentClient, proposal?: Record<string, unknown>): Promise<string>;
  records(): PsRecords;
  /** A token signed with the PS's own key: one the PS itself would never mint. */
  psMint(typ: AAuthTokenType, claims: Record<string, unknown>): Promise<string>;
  /** The PS configuration document this world started with, for a test to derive its own from. */
  psConfigDoc(): Record<string, unknown>;
  /**
   * The control-plane client of `caller`: the owning agent signing with
   * its agent token, or an administrator with its enrolled key. One client
   * per caller, on the shared clock, so that two of its requests to one
   * mission URL are signed in different seconds (the PS's replay key
   * keeps the library default).
   */
  manager(caller: AgentClient | Administrator): ManagementClient;
  /**
   * Stop the PS, close its store, and start another PS on the same store
   * file and signing key under `config` (default: the world's own): a
   * restart, which can apply a changed deployment policy. With
   * `pollIntervalMs`, the new PS runs revocation work on that interval.
   */
  restartPs(config?: PsConfig, options?: { pollIntervalMs?: number }): Promise<void>;
  /**
   * Stop the Resource, close its revoked set, and start another Resource
   * on the same file and signing key behind the same switch: a restart.
   * Its in-memory state (effects, person records, the replay cache) is lost.
   */
  restartResource(): Promise<void>;
  close(): Promise<void>;
}

export async function world(): Promise<World> {
  const net = new LoopbackNetwork();
  const clock = new ManualClock();
  const provider = createAgentProvider({ issuer: AP, now: clock.now });
  const dir = mkdtempSync(join(tmpdir(), "aauth-three-party-"));
  const psFile = join(dir, "ps.db");
  const resourceFile = join(dir, "resource.db");
  const store = new ObservedStore(new SqlitePsStore(psFile), psFile);
  const admins = { alice: administrator(ADMIN), bob: administrator(ADMIN_BOB) };
  const configDoc = worldPsConfig(admins);
  const config = parsePsConfig(configDoc);
  const bootPs = (next: PsConfig, signingKey?: SigningKey, pollIntervalMs = 0) =>
    createPersonServer({
      config: next,
      store,
      ...(signingKey ? { signingKey } : {}),
      resolver: net.resolver({ now: clock.now }),
      now: clock.now,
      management: {
        store: store.inner,
        transport: (request) => net.request(request),
        sleep: clock.sleep,
        pollIntervalMs,
      },
    });
  const bootResource = (key?: Resource["key"]) =>
    createResource({
      config: loadResourceConfig(CONFIG_DIR),
      resolver: net.resolver({ now: clock.now }),
      now: clock.now,
      ...(key ? { key } : {}),
      revocations: new SqliteRevocationStore(resourceFile),
    });
  let ps = bootPs(config);
  let resource = bootResource();
  const revocationSwitch = new EndpointSwitch({ path: REVOCATION_PATH });
  await net.serve(AP, provider.handler);
  let running = await ps.listen();
  net.attach(PS, running.server);
  let resourceServer = await listen(revocationSwitch.wrap(resource.handler));
  net.attach(RESOURCE, resourceServer);
  const missions = new Set<string>();
  const managers = new Map<string, ManagementClient>();

  const w: World = {
    net,
    clock,
    provider,
    get ps() {
      return ps;
    },
    store,
    get resource() {
      return resource;
    },
    admins,
    revocationSwitch,
    missions,
    seconds: () => Math.floor(clock.now() / 1000),
    agent: (local = "assistant", misbehavior) =>
      createAgent({
        provider,
        transport: net,
        ps: PS,
        local,
        now: clock.now,
        sleep: clock.sleep,
        ...(misbehavior ? { misbehavior } : {}),
      }),
    approve: async (agent, proposal = { description: "Summarize the quarterly report" }) => {
      const { s256 } = await agent.proposeMission(proposal);
      missions.add(s256);
      return s256;
    },
    records: () => {
      const logs: Record<string, MissionLogEntry[]> = {};
      for (const s256 of missions) logs[s256] = store.missionLog(s256);
      return { issued: store.issuedTokens(), logs };
    },
    psMint: (typ, claims) => {
      const key = ps.signingKey;
      return mintToken(typ, claims, {
        alg: key.alg,
        privateKey: key.privateKey,
        kid: key.publicJwk.kid as string,
      });
    },
    psConfigDoc: () => structuredClone(configDoc),
    manager: (caller) => {
      let client = managers.get(caller.id);
      if (!client) {
        const options = { now: clock.now, sleep: clock.sleep };
        client =
          "agentToken" in caller
            ? ManagementClient.forAgent(caller, net, options)
            : ManagementClient.forAdministrator({
                transport: net,
                ps: PS,
                key: caller.key,
                signatureKey: {
                  scheme: "jwks_uri",
                  id: caller.id,
                  dwk: caller.dwk,
                  kid: caller.kid,
                },
                ...options,
              });
        managers.set(caller.id, client);
      }
      return client;
    },
    restartPs: async (next = config, options = {}) => {
      await running.close();
      store.reopen();
      ps = bootPs(next, ps.signingKey, options.pollIntervalMs ?? 0);
      running = await ps.listen();
      net.attach(PS, running.server);
    },
    restartResource: async () => {
      const old = resourceServer;
      await new Promise<void>((resolve) => {
        old.closeAllConnections();
        old.close(() => resolve());
      });
      resource.revocations.close();
      resource = bootResource(resource.key);
      resourceServer = await listen(revocationSwitch.wrap(resource.handler));
      net.attach(RESOURCE, resourceServer);
    },
    close: async () => {
      await running.close();
      await net.close();
      store.close();
      resource.revocations.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
  return w;
}

/** The refusal an agent call ended in. */
export async function refusal(promise: Promise<unknown>): Promise<AgentError> {
  const err = await promise.then(
    () => undefined,
    (e: unknown) => e,
  );
  expect(err).toBeInstanceOf(AgentError);
  return err as AgentError;
}

/**
 * The PS refused with exactly `status` and `error`, and its response
 * carries no token.
 */
export function expectRefused(err: AgentError, status: number, error: string): void {
  expect(err.code, err.message).toBe("refused");
  expect(err.response?.status).toBe(status);
  const body = err.response?.body as Record<string, unknown>;
  expect(body.error).toBe(error);
  expect(body.person_token).toBeUndefined();
  expect(body.auth_token).toBeUndefined();
}

/** The `detail` of the error response a refusal carries. */
export const detailOf = (err: AgentError): unknown =>
  (err.response?.body as { detail?: unknown } | undefined)?.detail;

/** The agent's requests, one line each: method, URL, token presented, status. */
export const trail = (agent: AgentClient): string[] =>
  agent.sent.map((s) => `${s.method} ${s.url} ${s.presented} ${s.status}`);

/** The agent's requests to the PS's token endpoints. */
export const psTokenRequests = (agent: AgentClient) =>
  agent.sent.filter((s) => s.url === `${PS}/person` || s.url === `${PS}/token`);

/**
 * Everything an observer of a response can compare: status, the exact
 * body bytes, and every header with its value. `date` is the wall clock
 * at the moment of sending, so only its presence is compared.
 */
export function observable(res: LoopbackResponse): {
  status: number;
  body: string;
  headers: [string, string][];
} {
  const headers = Object.entries(res.headers)
    .map(([name, value]): [string, string] => [name, name === "date" ? "<present>" : value])
    .sort(([a], [b]) => a.localeCompare(b));
  return { status: res.status, body: res.text(), headers };
}

/**
 * A resource token re-signed by the Resource with `edit` applied: what a
 * faulty or compromised Resource would issue.
 */
export const tamperedBy =
  (resource: Resource, edit: (claims: Record<string, unknown>) => void) =>
  async (token: string): Promise<string> => {
    const claims = decodeClaims(token);
    edit(claims);
    return mintResourceToken(resource.key, claims);
  };
