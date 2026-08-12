export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export interface JsonObject {
  [key: string]: JsonValue | undefined;
}

export type GovernanceDecision = "allow" | "review" | "block";
export type ActionType = "shell" | "file_read" | "file_write" | "http" | "db_query" | "email" | "custom";
export type ReviewStatus = "not_required" | "pending" | "approved" | "rejected";
export type ProtocolKind = "mcp" | "acp" | "a2a" | "http-function" | "unknown";

export interface ActionDetail {
  type: ActionType;
  toolName: string;
  payload: JsonObject;
}

export interface InspectRequest {
  agentId: string;
  framework: string;
  action: ActionDetail;
  tenantId?: string;
  workspaceId?: string;
  protocol?: ProtocolKind | string;
  requestedSecrets?: string[];
  metadata?: JsonObject;
  sessionId?: string;
}

export interface RiskScore {
  score: number;
  decision: GovernanceDecision;
  reasons: string[];
}

export interface SchemaValidation {
  toolName: string;
  valid: boolean;
  findings: string[];
}

export interface SecretPlan {
  approved: string[];
  denied: string[];
}

export interface PluginResult {
  riskScore: number;
  findings: string[];
  decisionHint?: string;
}

export interface PluginOutput {
  pluginName: string;
  pluginVersion: string;
  executionMs: number;
  result: PluginResult;
}

export interface GovernanceResult {
  traceId: string;
  decision: GovernanceDecision;
  reviewStatus: ReviewStatus;
  risk: RiskScore;
  policyFindings: string[];
  protocol: ProtocolKind | string;
  reviewRequestId?: string;
  normalizedPayload: JsonObject;
  schemaValidation: SchemaValidation;
  secretPlan: SecretPlan;
  pluginResults?: PluginOutput[];
  auditEvent?: JsonObject;
  profile?: JsonObject;
  workspacePolicy?: JsonObject;
  /**
   * The role each layer plays in a verdict: `veto` (can decide on its own),
   * `scoring` (contributes to the composite), or `advisory` (reported, never
   * decisive). Present so a consumer is not left to infer that four of the ten
   * layer blocks — `sandboxResult`, the behavioural fingerprint,
   * `telemetrySpan` and `policyVerification` — cannot move a decision, and
   * neither can the session graph's `advisoryScore` sub-field; counting them as
   * active defences overstates coverage.
   * Note the session graph's signed `anomalyScore` is a different field and IS
   * decisive: it is a term in the composite and escalates to review on its own
   * at 50. Absent against an older server that does not send it.
   */
  layerRoles?: Record<string, LayerRole>;
}

export interface LayerRole {
  role: "veto" | "scoring" | "advisory";
  note?: string;
}

export interface AuditEvent {
  eventId: string;
  agentId: string;
  framework: string;
  actionType: ActionType;
  toolName: string;
  decision: GovernanceDecision;
  timestamp: string;
  reasons: string[];
  reviewStatus: ReviewStatus;
  riskScore: number;
}

export interface ReviewRequest {
  id: string;
  agentId: string;
  workspaceId: string;
  toolName: string;
  decision: GovernanceDecision;
  status: string;
  riskScore: number;
  reasons: string[];
  createdAt: string;
  updatedAt: string;
}

export interface HealthResponse {
  ok: boolean;
  service: string;
  mode: string;
  version: string;
  authRequired: boolean;
  openMode: boolean;
  apiKeysConfigured: boolean;
}

export interface SentinelClientOptions {
  baseUrl?: string;
  apiKey?: string;
  timeout?: number;
}

export interface OpenAIAdapterOptions extends SentinelClientOptions {
  agentId: string;
  framework?: string;
  tenantId?: string;
  workspaceId?: string;
  sessionId?: string;
  metadata?: JsonObject;
  /** Deny when the sidecar is unreachable. Default: fail-open (action proceeds). */
  failClosed?: boolean;
}

export interface SentinelMiddlewareOptions extends OpenAIAdapterOptions {
  toolName?: string;
  actionType?: ActionType;
}
