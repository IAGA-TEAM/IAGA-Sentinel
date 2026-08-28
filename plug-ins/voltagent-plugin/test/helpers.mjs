// Shared test helpers: a stub fetch that records calls, and fake VoltAgent hook
// arg builders. Kept tiny on purpose (ponytail: one place, no test framework).

// routes: { "/v1/inspect": { status?, json?, throws? }, ... } matched by suffix.
export function makeFetch(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    const body = init?.body ? JSON.parse(init.body) : undefined;
    calls.push({
      url: String(url),
      method: init?.method,
      headers: init?.headers,
      body,
      redirect: init?.redirect,
    });
    const key = Object.keys(routes).find((k) => String(url).endsWith(k));
    const route = key ? routes[key] : undefined;
    if (!route || route.throws) throw new Error("ECONNREFUSED (stub)");
    const status = route.status ?? 200;
    return {
      ok: status >= 200 && status < 300,
      status,
      json: async () => route.json,
      text: async () => (typeof route.json === "string" ? route.json : JSON.stringify(route.json ?? "")),
    };
  };
  return { fetchImpl, calls };
}

export const startArgs = (name = "shell", args = { command: "ls" }) => ({
  tool: name === null ? undefined : { name },
  args,
});

export const endArgs = (name = "shell", output = "out", error = undefined) => ({
  tool: { name },
  output,
  error,
});

export const verdict = (decision, extra = {}) => ({
  traceId: "t",
  decision,
  risk: { score: decision === "block" ? 95 : decision === "review" ? 40 : 5, decision, reasons: [`${decision} reason`] },
  ...extra,
});
