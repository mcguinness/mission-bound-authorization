/**
 * AAuth test kit for the three-party route: a loopback network that
 * carries real HTTP between parties addressed by their server identifiers,
 * a signing-server stub, the agent-provider stub, and an agent client that
 * signs with the Signature-Key `jwt` scheme, follows a resource's
 * requirements through its PS, and can be told to misbehave for negative
 * vectors. For status and termination: a client of the PS's mission
 * control plane, acting as the owning agent or an administrator, and a
 * switch that makes one endpoint unavailable (or, on the network, refuses
 * a whole host).
 *
 * Builds on `@mission/aauth-wire`; nothing here re-implements RFC 9421,
 * Signature-Key, key discovery or token verification.
 */
export {
  AgentClient,
  type AgentClientOptions,
  AgentError,
  type AgentErrorCode,
  type AgentTransport,
  type CreateAgentOptions,
  createAgent,
  decodeClaims,
  type Misbehavior,
  type MissionApproval,
  parseRequirement,
  type SentRequest,
  tokenType,
} from "./agent-client.js";
export {
  type AgentProvider,
  type AgentProviderOptions,
  type AgentTokenRequest,
  createAgentProvider,
} from "./agent-provider.js";
export { type Clock, ManualClock, realSleep, type Sleep } from "./clock.js";
export {
  createIssuerStub,
  type IssuerStub,
  type IssuerStubOptions,
  readBody,
  type StubRequest,
  type StubResponse,
  type StubRoute,
  writeResponse,
} from "./issuer-stub.js";
export {
  agentSigner,
  type ControlPlane,
  keySigner,
  ManagementClient,
  type ManagementClientOptions,
  ManagementError,
  type ManagementErrorCode,
  type ManagementResult,
  type ManagementRole,
  type ManagementSigner,
  newRequestId,
  type SentManagementRequest,
  type TerminateOptions,
} from "./management-client.js";
export {
  LoopbackNetwork,
  type LoopbackRequest,
  type LoopbackResponse,
} from "./network.js";
export {
  EndpointSwitch,
  type EndpointSwitchOptions,
  type Handler,
  type OutageMode,
  type SwitchedRequest,
} from "./outage.js";
