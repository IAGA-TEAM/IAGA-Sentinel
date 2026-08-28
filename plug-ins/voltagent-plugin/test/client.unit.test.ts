import { test } from "node:test";
import assert from "node:assert/strict";
import { SentinelClient, SentinelApiError } from "../dist/index.js";
import { makeFetch } from "./helpers.mjs";

const cfg = (fetchImpl: unknown, extra: Record<string, unknown> = {}) =>
  ({ baseUrl: "http://localhost:4010", timeoutMs: 5000, fetch: fetchImpl, ...extra }) as never;

test("inspect posts /v1/inspect and returns parsed JSON", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: { decision: "allow" } } });
  const client = new SentinelClient(cfg(fetchImpl));
  const r = await client.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } });
  assert.deepEqual(r, { decision: "allow" });
  assert.equal(calls[0].method, "POST");
  assert.ok(calls[0].url.endsWith("/v1/inspect"));
});

test("baseUrl trailing slash is stripped", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: {} } });
  const client = new SentinelClient(cfg(fetchImpl, { baseUrl: "http://localhost:4010/" }));
  await client.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } });
  assert.equal(calls[0].url, "http://localhost:4010/v1/inspect");
});

test("Authorization Bearer header present only when apiKey is set", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/inspect": { json: {} } });
  const withKey = new SentinelClient(cfg(fetchImpl, { apiKey: "secret" }));
  await withKey.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } });
  assert.equal((calls[0].headers as Record<string, string>).Authorization, "Bearer secret");

  const { fetchImpl: f2, calls: c2 } = makeFetch({ "/v1/inspect": { json: {} } });
  const noKey = new SentinelClient(cfg(f2));
  await noKey.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } });
  assert.equal((c2[0].headers as Record<string, string>).Authorization, undefined);
});

test("Content-Type is always application/json", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/firewall/scan": { json: { blocked: false } } });
  const client = new SentinelClient(cfg(fetchImpl));
  await client.firewallScan("hello");
  assert.equal((calls[0].headers as Record<string, string>)["Content-Type"], "application/json");
});

test("firewallScan posts { text }", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/firewall/scan": { json: { blocked: true, summary: "x" } } });
  const client = new SentinelClient(cfg(fetchImpl));
  const r = await client.firewallScan("evil input");
  assert.deepEqual(calls[0].body, { text: "evil input" });
  assert.equal(r.blocked, true);
});

test("responseScan posts the full request body", async () => {
  const { fetchImpl, calls } = makeFetch({ "/v1/response/scan": { json: { requestId: "r", decision: "allow", riskScore: 0, findings: [] } } });
  const client = new SentinelClient(cfg(fetchImpl));
  await client.responseScan({ requestId: "r", agentId: "a", toolName: "t", responsePayload: "out" });
  assert.deepEqual(calls[0].body, { requestId: "r", agentId: "a", toolName: "t", responsePayload: "out" });
});

test("non-ok response throws SentinelApiError with status/body/path", async () => {
  const { fetchImpl } = makeFetch({ "/v1/inspect": { status: 404, json: "agent not found" } });
  const client = new SentinelClient(cfg(fetchImpl));
  await assert.rejects(
    client.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } }),
    (e: unknown) =>
      e instanceof SentinelApiError &&
      (e as SentinelApiError).status === 404 &&
      (e as SentinelApiError).path === "/v1/inspect",
  );
});

test("timeout aborts the request (AbortController wired)", async () => {
  const slow = (_url: string, init: { signal: AbortSignal }) =>
    new Promise((_resolve, reject) => {
      init.signal.addEventListener("abort", () => reject(new Error("aborted")));
    });
  const client = new SentinelClient(cfg(slow, { timeoutMs: 20 }));
  await assert.rejects(
    client.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } }),
    /aborted/,
  );
});

test("every request sets redirect: manual", async () => {
  // `fetch` follows redirects by default, and measured on the SDK that was a
  // complete governance bypass: a 307 from the configured URL to an
  // attacker-controlled server made the client return that server's
  // `decision: "allow"`, with no evidence anywhere. This plugin's client
  // shipped with the same hole after the SDK closed it in 2.0.2.
  const { fetchImpl, calls } = makeFetch({
    "/v1/inspect": { json: {} },
    "/v1/firewall/scan": { json: {} },
    "/v1/response/scan": { json: {} },
  });
  const client = new SentinelClient(cfg(fetchImpl));
  await client.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } });
  await client.firewallScan("hello");
  await client.responseScan({ requestId: "r", agentId: "a", toolName: "t", responsePayload: {} } as never);
  assert.equal(calls.length, 3);
  for (const call of calls) {
    assert.equal(call.redirect, "manual", `${call.url} must not follow redirects`);
  }
});

test("a redirect surfaces as SentinelApiError rather than a verdict", async () => {
  // With redirect: "manual" the 307 is returned as-is, so `response.ok` is
  // false and the client raises instead of parsing a hostile body as a verdict.
  const { fetchImpl } = makeFetch({ "/v1/inspect": { status: 307, json: { decision: "allow" } } });
  const client = new SentinelClient(cfg(fetchImpl));
  await assert.rejects(
    client.inspect({ agentId: "a", framework: "f", action: { type: "custom", toolName: "t", payload: {} } }),
    (err: unknown) => err instanceof SentinelApiError && err.status === 307,
  );
});

test("constructor throws when no fetch is available", () => {
  const saved = globalThis.fetch;
  // @ts-expect-error force-remove global fetch
  globalThis.fetch = undefined;
  try {
    assert.throws(() => new SentinelClient({ baseUrl: "http://x", timeoutMs: 1 } as never), /fetch/);
  } finally {
    globalThis.fetch = saved;
  }
});
