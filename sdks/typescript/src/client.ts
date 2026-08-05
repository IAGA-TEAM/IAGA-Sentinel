import type {
  SentinelClientOptions,
  AuditEvent,
  GovernanceResult,
  HealthResponse,
  InspectRequest,
  JsonObject,
  ReviewRequest,
} from "./types";

function cleanQuery(query: Record<string, unknown>): Record<string, string> {
  return Object.fromEntries(
    Object.entries(query)
      .filter(([, value]) => value !== undefined && value !== null)
      .map(([key, value]) => [key, String(value)])
  );
}

function normalizeInspectRequest(request: InspectRequest): JsonObject {
  const { sessionId, metadata, ...rest } = request;
  const normalized: JsonObject = { ...(rest as unknown as JsonObject) };
  const nextMetadata: JsonObject = { ...(metadata ?? {}) };
  if (sessionId) {
    nextMetadata.sessionId = sessionId;
  }
  if (Object.keys(nextMetadata).length > 0) {
    normalized.metadata = nextMetadata;
  }
  return normalized;
}

export class SentinelClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeout: number;

  constructor(options: SentinelClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? "http://localhost:4010").replace(/\/$/, "");
    this.timeout = options.timeout ?? 10000;
    this.headers = { "Content-Type": "application/json" };
    if (options.apiKey) {
      this.headers.Authorization = `Bearer ${options.apiKey}`;
    }
  }

  async inspect(request: InspectRequest): Promise<GovernanceResult> {
    return this.request<GovernanceResult>("/v1/inspect", {
      method: "POST",
      body: JSON.stringify(normalizeInspectRequest(request)),
    });
  }

  async listAudit(): Promise<AuditEvent[]> {
    return this.request<AuditEvent[]>("/v1/audit");
  }

  async exportAudit(query: {
    format?: "json" | "csv";
    tenantId?: string;
    agentId?: string;
    decision?: string;
    fromDate?: string;
    toDate?: string;
    limit?: number;
  } = {}): Promise<AuditEvent[] | string> {
    const format = query.format ?? "json";
    const response = await this.fetchResponse("/v1/audit/export", undefined, {
      format,
      tenant_id: query.tenantId,
      agent_id: query.agentId,
      decision: query.decision,
      from_date: query.fromDate,
      to_date: query.toDate,
      limit: query.limit,
    });
    if (format === "csv") {
      return response.text();
    }
    return (await response.json()) as AuditEvent[];
  }

  async getStats(): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/audit/stats");
  }

  async getAnalytics(agentId?: string): Promise<JsonObject[]> {
    if (agentId) {
      return this.request<JsonObject[]>(`/v1/analytics/agents/${agentId}`);
    }
    return this.request<JsonObject[]>("/v1/analytics/agents");
  }

  async listReviews(): Promise<ReviewRequest[]> {
    return this.request<ReviewRequest[]>("/v1/reviews");
  }

  async resolveReview(
    reviewId: string,
    status: "approved" | "rejected"
  ): Promise<ReviewRequest> {
    return this.request<ReviewRequest>(`/v1/reviews/${reviewId}`, {
      method: "POST",
      body: JSON.stringify({ status }),
    });
  }

  async listProfiles(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/profiles");
  }

  async getProfile(agentId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/profiles/${agentId}`);
  }

  async createProfile(profile: JsonObject): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/profiles", {
      method: "POST",
      body: JSON.stringify(profile),
    });
  }

  async updateProfile(profile: JsonObject): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/profiles/${String(profile.agentId)}`, {
      method: "PUT",
      body: JSON.stringify(profile),
    });
  }

  async deleteProfile(agentId: string): Promise<void> {
    await this.request<void>(`/v1/profiles/${agentId}`, { method: "DELETE" });
  }

  async listWorkspaces(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/workspaces");
  }

  async getWorkspace(workspaceId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/workspaces/${workspaceId}`);
  }

  async createWorkspace(workspace: JsonObject): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/workspaces", {
      method: "POST",
      body: JSON.stringify(workspace),
    });
  }

  async updateWorkspace(workspace: JsonObject): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/workspaces/${String(workspace.workspaceId)}`, {
      method: "PUT",
      body: JSON.stringify(workspace),
    });
  }

  async deleteWorkspace(workspaceId: string): Promise<void> {
    await this.request<void>(`/v1/workspaces/${workspaceId}`, { method: "DELETE" });
  }

  async listKeys(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/auth/keys");
  }

  async createKey(label: string): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/auth/keys", {
      method: "POST",
      body: JSON.stringify({ label }),
    });
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.request<void>(`/v1/auth/keys/${keyId}`, { method: "DELETE" });
  }

  async listWebhooks(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/webhooks");
  }

  async registerWebhook(
    url: string,
    secret: string,
    eventFilter: string[] = []
  ): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/webhooks", {
      method: "POST",
      body: JSON.stringify({ url, secret, eventFilter }),
    });
  }

  async deleteWebhook(webhookId: string): Promise<void> {
    await this.request<void>(`/v1/webhooks/${webhookId}`, { method: "DELETE" });
  }

  async getDlq(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/webhooks/dlq");
  }

  async retryDlq(entryId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/webhooks/dlq/${entryId}/retry`, {
      method: "POST",
    });
  }

  async deleteDlq(entryId: string): Promise<void> {
    await this.request<void>(`/v1/webhooks/dlq/${entryId}`, { method: "DELETE" });
  }

  async listSessions(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/sessions");
  }

  async getSessionMetrics(sessionId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/sessions/${sessionId}/metrics`);
  }

  async listIdentities(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/nhi/identities");
  }

  async registerIdentity(input: {
    agentId: string;
    workspaceId?: string;
    capabilities?: string[];
  }): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/nhi/identities", {
      method: "POST",
      body: JSON.stringify({
        agentId: input.agentId,
        workspaceId: input.workspaceId,
        capabilities: input.capabilities ?? [],
      }),
    });
  }

  async attest(agentId: string, challenge: string): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/nhi/attest", {
      method: "POST",
      body: JSON.stringify({ agentId, challenge }),
    });
  }

  async createChallenge(agentId: string): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/nhi/challenge", {
      method: "POST",
      body: JSON.stringify({ agentId }),
    });
  }

  async verifyAttestation(input: {
    agentId: string;
    challengeId: string;
    signature: string;
  }): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/nhi/verify", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async issueToken(input: {
    agentId: string;
    capabilities: string[];
    ttlSeconds?: number;
  }): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/nhi/tokens", {
      method: "POST",
      body: JSON.stringify({
        agentId: input.agentId,
        capabilities: input.capabilities,
        ttlSeconds: input.ttlSeconds ?? 3600,
      }),
    });
  }

  async getRiskWeights(): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/risk/weights");
  }

  async submitFeedback(feedback: string): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/risk/feedback", {
      method: "POST",
      body: JSON.stringify({ feedback }),
    });
  }

  async listPendingSandbox(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/sandbox/pending");
  }

  async approveSandbox(sandboxId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/sandbox/${sandboxId}/approve`, {
      method: "POST",
    });
  }

  async rejectSandbox(sandboxId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/sandbox/${sandboxId}/reject`, {
      method: "POST",
    });
  }

  async verifyPolicy(workspaceId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/policy/verify/${workspaceId}`);
  }

  async scanResponse(request: JsonObject): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/response/scan", {
      method: "POST",
      body: JSON.stringify(request),
    });
  }

  async getPatterns(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/response/patterns");
  }

  async scanFirewall(text: string): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/firewall/scan", {
      method: "POST",
      body: JSON.stringify({ text }),
    });
  }

  async getFirewallStats(): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/firewall/stats");
  }

  async listSpans(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/telemetry/spans");
  }

  async getMetrics(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/telemetry/metrics");
  }

  async exportTelemetry(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/telemetry/export");
  }

  async listFingerprints(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/fingerprint");
  }

  async getFingerprint(agentId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/fingerprint/${agentId}`);
  }

  async getStatus(agentId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/rate-limit/status/${agentId}`);
  }

  async getConfig(): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/rate-limit/config");
  }

  async setConfig(config: JsonObject): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/rate-limit/config", {
      method: "POST",
      body: JSON.stringify(config),
    });
  }

  async listIndicators(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/threat-intel/indicators");
  }

  async addIndicator(indicator: JsonObject): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/threat-intel/indicators", {
      method: "POST",
      body: JSON.stringify(indicator),
    });
  }

  async deleteIndicator(indicatorId: string): Promise<void> {
    await this.request<void>(`/v1/threat-intel/indicators/${indicatorId}`, {
      method: "DELETE",
    });
  }

  async getThreatIntelStats(): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/threat-intel/stats");
  }

  async checkThreats(content: string): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/threat-intel/check", {
      method: "POST",
      body: JSON.stringify({ content }),
    });
  }

  async listTemplates(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/templates");
  }

  async getTemplate(templateId: string): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/templates/${templateId}`);
  }

  async listWorkspaceRules(workspaceId: string): Promise<JsonObject[]> {
    return this.request<JsonObject[]>(`/v1/workspaces/${workspaceId}/rules`);
  }

  async addWorkspaceRule(workspaceId: string, rule: JsonObject): Promise<JsonObject> {
    return this.request<JsonObject>(`/v1/workspaces/${workspaceId}/rules`, {
      method: "POST",
      body: JSON.stringify(rule),
    });
  }

  async listPlugins(): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/plugins");
  }

  async reloadPlugins(): Promise<JsonObject> {
    return this.request<JsonObject>("/v1/plugins/reload", { method: "POST" });
  }

  async listDemoScenarios(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/demo/scenarios");
  }

  async runDemoAdapter(): Promise<JsonObject[]> {
    return this.request<JsonObject[]>("/v1/demo/run-adapter", { method: "POST" });
  }

  async health(): Promise<HealthResponse> {
    return this.request<HealthResponse>("/health");
  }

  eventStream(): EventSource {
    return new EventSource(this.buildUrl("/v1/events/stream"));
  }

  private buildUrl(path: string, query?: Record<string, unknown>): string {
    const url = new URL(path, `${this.baseUrl}/`);
    if (query) {
      for (const [key, value] of Object.entries(cleanQuery(query))) {
        url.searchParams.set(key, value);
      }
    }
    return url.toString();
  }

  private async fetchResponse(
    path: string,
    init?: RequestInit,
    query?: Record<string, unknown>
  ): Promise<Response> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    try {
      const response = await globalThis.fetch(this.buildUrl(path, query), {
        ...init,
        headers: { ...this.headers, ...(init?.headers as Record<string, string> | undefined) },
        signal: controller.signal,
        // Never follow a redirect to the sidecar. `fetch` follows by default, and
        // measured, that was a complete bypass: a 307 from the configured URL to
        // an attacker-controlled server made this client return that server's
        // `decision: "allow"` — with no evidence anywhere, because the real
        // sidecar was never reached. The Python SDK (httpx, follow_redirects
        // off) already refuses; this brings the TypeScript client in line.
        //
        // `manual` rather than `error` so the status is surfaced as a normal
        // SentinelApiError below and the caller's fail-open/fail-closed policy
        // decides, instead of a transport exception bypassing that logic.
        redirect: "manual",
      });

      if (!response.ok) {
        const body = await response.text().catch(() => "");
        throw new SentinelApiError(response.status, body, path);
      }

      return response;
    } finally {
      clearTimeout(timer);
    }
  }

  private async request<T>(
    path: string,
    init?: RequestInit,
    query?: Record<string, unknown>
  ): Promise<T> {
    const response = await this.fetchResponse(path, init, query);
    if (response.status === 204) {
      return undefined as T;
    }
    return (await response.json()) as T;
  }
}

export class SentinelApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    public readonly path: string
  ) {
    super(`IAGA Sentinel API error ${status} on ${path}: ${body}`);
    this.name = "SentinelApiError";
  }
}

export interface GovernedOptions {
  /** Deny (throw) when the sidecar is unreachable. Default: fail-open. */
  failClosed?: boolean;
}

export async function governed<T>(
  client: SentinelClient,
  request: InspectRequest,
  fn: () => T | Promise<T>,
  options: GovernedOptions = {}
): Promise<T> {
  const result = await inspectWithPolicy(client, request, options);

  if (result.decision === "block") {
    throw new SentinelBlockedError(result);
  }
  if (result.decision === "review") {
    throw new SentinelReviewError(result);
  }

  return await fn();
}

export class SentinelBlockedError extends Error {
  constructor(public readonly result: GovernanceResult) {
    super(
      `Tool blocked by IAGA Sentinel (risk=${result.risk.score}): ${result.risk.reasons.join(", ")}`
    );
    this.name = "SentinelBlockedError";
  }
}

export class SentinelReviewError extends Error {
  constructor(public readonly result: GovernanceResult) {
    super(
      `Tool requires review (reviewId=${result.reviewRequestId}, risk=${result.risk.score})`
    );
    this.name = "SentinelReviewError";
  }
}

function failOpenResult(reason: string): GovernanceResult {
  return {
    traceId: "",
    decision: "allow",
    reviewStatus: "not_required",
    risk: { score: 0, decision: "allow", reasons: [reason] },
    policyFindings: [],
    protocol: "unknown",
    normalizedPayload: {},
    schemaValidation: { toolName: "", valid: false, findings: [] },
    secretPlan: { approved: [], denied: [] },
  };
}

function unreachableBlockResult(reason: string): GovernanceResult {
  return {
    ...failOpenResult(reason),
    decision: "block",
    risk: { score: 100, decision: "block", reasons: [reason] },
  };
}

/**
 * Inspect an action, applying the transport-error policy. Fail-open by default
 * (returns an allow result so the action proceeds),
 * or fail-closed (throws SentinelBlockedError) when options.failClosed is set.
 * 4xx responses are genuine client errors and are rethrown unchanged.
 */
export async function inspectWithPolicy(
  client: SentinelClient,
  request: InspectRequest,
  options: GovernedOptions = {}
): Promise<GovernanceResult> {
  try {
    return await client.inspect(request);
  } catch (err) {
    if (err instanceof SentinelApiError && err.status < 500) {
      throw err;
    }
    const reason = `IAGA Sentinel unreachable (${String(err)})`;
    if (options.failClosed) {
      throw new SentinelBlockedError(unreachableBlockResult(`${reason}; fail-closed`));
    }
    return failOpenResult(`${reason}; failing open`);
  }
}
