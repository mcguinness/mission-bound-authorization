/**
 * The `pnpm as-native` launcher (D284, D315, D332): its configuration, its
 * startup and its shutdown. `as-native-serve.ts` is the process around these
 * three functions (printing, signals, exit status), and the tests drive the
 * same functions, so what they show is what the launcher runs.
 */
import { existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { kernelStoreFromEnv, loadSigningKeyRing, signingKeysFromEnv } from "@mission/authorization-server";
import { TOPOLOGY } from "@mission/demo-data";
import { resourcePolicyStoreFromEnv } from "./resource-policy-store.js";
import { type ComposeStackOptions, composeStack, type DemoStack } from "./stack.js";

/**
 * The launcher's composition options, from its environment: the `as-native`
 * target, the OpenFGA connection (`OPENFGA_HTTP_URL`, `OPENFGA_PRESHARED_KEY`,
 * `OPENFGA_CA_CERT`), the Resource-policy store (#828: attach to
 * `OPENFGA_STORE_ID` and `OPENFGA_MODEL_ID` when both are set, else bootstrap
 * a development store; `resourcePolicyStoreFromEnv`) and the PDP mode
 * (`MISSION_PDP_MODE`), the signing keys (`MISSION_KEY_RING` or
 * `MISSION_EPHEMERAL_KEYS`) and the kernel's file (`MISSION_KERNEL_STORE`,
 * which requires the key ring), and nothing else, so never the test-only
 * ordinary-token minting fixture. A value that is set but unusable refuses
 * startup with an error naming it, before anything connects or listens.
 */
export function asNativeLaunchOptions(env: Readonly<Record<string, string | undefined>>): ComposeStackOptions {
  const openfgaUrl = env.OPENFGA_HTTP_URL ?? TOPOLOGY.openfga.url;
  let url: URL;
  try {
    url = new URL(openfgaUrl);
  } catch {
    throw new Error(`OPENFGA_HTTP_URL is not a URL: ${openfgaUrl}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`OPENFGA_HTTP_URL is not an http or https URL: ${openfgaUrl}`);
  }
  const ca = env.OPENFGA_CA_CERT;
  if (ca && !existsSync(ca)) {
    throw new Error(`OPENFGA_CA_CERT names ${ca}, which does not exist; run \`pnpm setup\` first`);
  }
  const pdpMode = env.MISSION_PDP_MODE;
  if (pdpMode !== undefined && pdpMode !== "co-resident" && pdpMode !== "remote") {
    throw new Error(`MISSION_PDP_MODE must be co-resident or remote, not ${pdpMode}`);
  }
  const resourcePolicyStore = resourcePolicyStoreFromEnv(env);
  // @spec #831: the deployment says where its signing keys come from.
  const signingKeys = signingKeysFromEnv(env);
  // @spec #250: a kernel kept across restarts, only with a key ring.
  const kernelStore = kernelStoreFromEnv(env);
  return {
    openfgaUrl,
    presharedKey: env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey,
    ...(ca ? { caCertPath: ca } : {}),
    ...(pdpMode ? { pdpMode } : {}),
    resourcePolicyStore,
    signingKeys,
    ...(kernelStore ? { kernelStore } : {}),
    target: "as-native",
  };
}

/** A running as-native target. */
export interface AsNativeLaunch {
  stack: DemoStack;
  /** The lines the launcher prints once the target is ready. */
  summary: string[];
  /**
   * Stop the outcome reconciler, close every listener the target opened (the
   * resource endpoint, the AS, the txn-challenge discovery listener and, in
   * remote mode, the PDP hop) and release both single-writer store files,
   * and the kernel's file when the target keeps one.
   * Resolves once every port is free. Idempotent.
   */
  close: () => Promise<void>;
}

/**
 * Start the as-native target from `options`. Refuses any composition but the
 * target itself: another target, or the test-only ordinary-token minting
 * fixture, which the launcher never enables (D332). A taken AS or audience
 * port refuses with all it opened released; the launcher exits on others.
 */
export async function launchAsNative(options: ComposeStackOptions): Promise<AsNativeLaunch> {
  if (options.target !== "as-native") {
    throw new Error("the as-native launcher composes only the as-native target");
  }
  if (options.testOrdinaryTokenMinting) {
    throw new Error("the as-native launcher never enables the test-only ordinary-token minting fixture (D332)");
  }
  // @spec #831: an unusable key ring refuses before anything connects or
  // listens; composeStack loads it again when it builds the AS.
  if (options.signingKeys && "ring" in options.signingKeys) {
    const { asToken, asStatus, asTxn, asContinuation } = TOPOLOGY.keys;
    await loadSigningKeyRing(options.signingKeys.ring, `http://localhost:${options.asPort ?? TOPOLOGY.ports.as}`, {
      asToken,
      asStatus,
      asTxn,
      asContinuation,
    });
  }
  // @spec #250: the kernel file's directory exists before anything connects.
  if (options.kernelStore) mkdirSync(dirname(options.kernelStore.file), { recursive: true });
  const stack = await composeStack(options);
  const { authServer, resourceChannel } = stack;
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> =>
    (closing ??= (async () => {
      await stack.reconciler.stop();
      await resourceChannel?.close();
      await stack.masGovernedChannel?.close();
      await authServer?.closeAuthServer();
      await stack.decisionChannel.close();
      stack.pdpClaims.close();
      stack.writeReservations.close();
      // Last: everything above may still read the kernel while it stops.
      if (options.kernelStore) stack.kernel.close();
    })());
  if (!authServer?.capabilities || !resourceChannel) {
    await close();
    throw new Error("the as-native target assembles the AS with its capability set and the resource endpoint");
  }
  // @spec runtime#evidence (outcome reconciliation) (#1103): the declared
  // reconciler runs for the target's lifetime, once now and then every third
  // of the declared window; `close` stops it before anything it reads closes.
  stack.reconciler.start();
  return {
    stack,
    summary: [
      "as-native payments target (D284, D315, D332)",
      `  issuer             ${stack.issuer}  (JWKS ${authServer.asUrl}/jwks)`,
      `  AS capabilities    issuance profile + ${[...authServer.capabilities].join(", ")}`,
      `  dev ordinary token ${authServer.devOrdinaryIssuance ? "served" : "not served"}`,
      `  signing keys       ${authServer.signingKeyMode === "ring" ? "key ring (kept across restarts)" : "ephemeral (new at every restart)"}`,
      `  kernel store       ${options.kernelStore ? `${options.kernelStore.file} (kept across restarts)` : "in memory (lost at restart)"}`,
      `  resource audience  ${resourceChannel.url}  (HTTP MCP, DPoP verified on every request)`,
      `  PDP mode           ${stack.pdpMode}`,
      `  MAS join route     ${stack.masGovernedChannel ? "mounted" : "not mounted"}`,
      `  reconciliation     every ${stack.reconciler.intervalMs / 1000} s (window ${stack.reconciler.windowMs / 1000} s), operator alerts on stderr`,
      "  ready. Ctrl-C to stop.",
    ],
    close,
  };
}
