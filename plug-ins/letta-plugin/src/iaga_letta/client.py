"""Tiny stdlib client over the three IAGA Sentinel endpoints the plugin uses.

ponytail: stdlib ``urllib.request`` instead of httpx. These are three JSON POSTs;
they do not justify a dependency. ``letta-client`` is then the plugin's only real
requirement. Mirrors the request-shaping of plug-ins/voltagent-plugin/src/client.ts.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse to follow a redirect to the sidecar.

    ``urlopen`` uses the default opener, which follows 301/302/303 (re-issuing a
    POST as a GET) and 307/308. Measured on the TypeScript SDK, that was a
    complete governance bypass: a 307 from the configured URL to an
    attacker-controlled server made the client return that server's
    ``decision: "allow"`` with no evidence anywhere, because the real sidecar was
    never reached. Returning ``None`` is urllib's documented "do not follow"
    signal; the original 3xx then surfaces as an ``HTTPError``, which ``_post``
    already converts to ``SentinelApiError`` and the handler already treats as a
    transport failure subject to the fail-closed policy.

    Overriding ``redirect_request`` covers every 3xx in one place -- 307 in
    particular, which is the code the demonstrated bypass used.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# A private opener, not `install_opener`: this is a library imported into
# someone else's agent process and must not mutate global urllib state.
_OPENER = urllib.request.build_opener(_NoRedirect)


class SentinelApiError(RuntimeError):
    """Non-2xx response from the sidecar."""

    def __init__(self, status: int, body: str, path: str):
        super().__init__(f"IAGA Sentinel API error {status} on {path}: {body}")
        self.status = status
        self.body = body
        self.path = path


class SentinelClient:
    """Dependency-free client for /v1/inspect, /v1/firewall/scan, /v1/response/scan."""

    def __init__(self, base_url: str, api_key: "str | None" = None, timeout_ms: int = 5000):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_ms / 1000.0
        self.headers = {"Content-Type": "application/json"}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"

    def _post(self, path: str, body: dict) -> dict:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.base_url + path, data=data, headers=self.headers, method="POST")
        try:
            with _OPENER.open(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:  # 4xx/5xx -> typed error
            raise SentinelApiError(exc.code, exc.read().decode("utf-8", "replace"), path) from exc
        # urllib.error.URLError (connection refused / timeout) propagates; the handler
        # treats it as "sidecar unreachable" and applies the fail-closed/open policy.

    def inspect(self, request: dict) -> dict:
        return self._post("/v1/inspect", request)

    def firewall_scan(self, text: str) -> dict:
        return self._post("/v1/firewall/scan", {"text": text})

    def response_scan(self, request: dict) -> dict:
        return self._post("/v1/response/scan", request)
