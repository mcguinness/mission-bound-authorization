/**
 * The `pnpm as-native` launcher (D284, D315, D332): its configuration, its
 * startup and its shutdown. `as-native-serve.ts` is the process around these
 * three functions (printing, signals, exit status), and the tests drive the
 * same functions, so what they show is what the launcher runs.
 */
import { existsSync } from "node:fs";
import { TOPOLOGY } from "@mission/demo-data";
import { type ComposeStackOptions, composeStack, type DemoStack } from "./stack.js";

/**
 * The launcher's composition options, from its environment: the `as-native`
 * target, the OpenFGA connection (`OPENFGA_HTTP_URL`, `OPENFGA_PRESHARED_KEY`,
 * `OPENFGA_CA_CERT`) and the PDP mode (`MISSION_PDP_MODE`), and nothing else,
 * so never the test-only ordinary-token minting fixture. A value that is set
 * but unusable refuses startup with an error naming it, before anything
 * connects or listens.
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
  return {
    openfgaUrl,
    presharedKey: env.OPENFGA_PRESHARED_KEY ?? TOPOLOGY.openfga.presharedKey,
    ...(ca ? { caCertPath: ca } : {}),
    ...(pdpMode ? { pdpMode } : {}),
    target: "as-native",
  };
}

/** A running as-native target. */
export interface AsNativeLaunch {
  stack: DemoStack;
  /** The lines the launcher prints once the target is ready. */
  summary: string[];
  /**
   * Close every listener the target opened (the resource endpoint, the AS,
   * the txn-challenge discovery listener and, in remote mode, the PDP hop) and
   * release both single-writer store files. Resolves once every port is free.
   * Idempotent.
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
  const stack = await composeStack(options);
  const { authServer, resourceChannel } = stack;
  let closing: Promise<void> | undefined;
  const close = (): Promise<void> =>
    (closing ??= (async () => {
      await resourceChannel?.close();
      await stack.masGovernedChannel?.close();
      await authServer?.closeAuthServer();
      await stack.decisionChannel.close();
      stack.pdpClaims.close();
      stack.writeReservations.close();
    })());
  if (!authServer?.capabilities || !resourceChannel) {
    await close();
    throw new Error("the as-native target assembles the AS with its capability set and the resource endpoint");
  }
  return {
    stack,
    summary: [
      "as-native payments target (D284, D315, D332)",
      `  issuer             ${stack.issuer}  (JWKS ${authServer.asUrl}/jwks)`,
      `  AS capabilities    issuance profile + ${[...authServer.capabilities].join(", ")}`,
      `  dev ordinary token ${authServer.devOrdinaryIssuance ? "served" : "not served"}`,
      `  resource audience  ${resourceChannel.url}  (HTTP MCP, DPoP verified on every request)`,
      `  PDP mode           ${stack.pdpMode}`,
      `  MAS join route     ${stack.masGovernedChannel ? "mounted" : "not mounted"}`,
      "  ready. Ctrl-C to stop.",
    ],
    close,
  };
}
