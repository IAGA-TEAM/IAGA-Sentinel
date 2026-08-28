import type {
  FirewallResult,
  GovernanceResult,
  InspectRequest,
  ResponseScanRequest,
  ResponseScanResult,
} from "./types.js";

export class SentinelApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    public readonly path: string,
  ) {
    super(`IAGA Sentinel API error ${status} on ${path}: ${body}`);
    this.name = "SentinelApiError";
  }
}

export interface SentinelClientConfig {
  baseUrl: string;
  apiKey?: string;
  timeoutMs: number;
  fetch?: typeof fetch;
}

/**
 * Dependency-free client over the three sidecar endpoints a plugin uses.
 * Uses global fetch (Node 18+); an injectable fetch is accepted for older
 * runtimes. Mirrors the shape of @iaga-sentinel/sdk's SentinelClient.
 */
export class SentinelClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;
  private readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(config: SentinelClientConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, "");
    this.timeoutMs = config.timeoutMs;
    this.headers = { "Content-Type": "application/json" };
    if (config.apiKey) {
      this.headers.Authorization = `Bearer ${config.apiKey}`;
    }
    const f = config.fetch ?? globalThis.fetch;
    if (typeof f !== "function") {
      throw new Error(
        "global fetch is unavailable; pass options.fetch (Node 18+ has it built in)",
      );
    }
    this.fetchImpl = f;
  }

  inspect(request: InspectRequest): Promise<GovernanceResult> {
    return this.post<GovernanceResult>("/v1/inspect", request);
  }

  firewallScan(text: string): Promise<FirewallResult> {
    return this.post<FirewallResult>("/v1/firewall/scan", { text });
  }

  responseScan(request: ResponseScanRequest): Promise<ResponseScanResult> {
    return this.post<ResponseScanResult>("/v1/response/scan", request);
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(body),
        signal: controller.signal,
        // Never follow a redirect to the sidecar. `fetch` follows by default,
        // and measured on the SDK that was a complete bypass: a 307 from the
        // configured URL to an attacker-controlled server made the client
        // return that server's `decision: "allow"`, with no evidence anywhere,
        // because the real sidecar was never reached. This client shipped with
        // the same hole the SDK closed in 2.0.2; `manual` surfaces the 3xx as a
        // SentinelApiError so the caller's fail-closed policy decides.
        redirect: "manual",
      });
      if (!response.ok) {
        const text = await response.text().catch(() => "");
        throw new SentinelApiError(response.status, text, path);
      }
      return (await response.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }
}
