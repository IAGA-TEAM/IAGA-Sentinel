"""The sidecar client must never follow a redirect.

`urllib.request.urlopen` uses the default opener, whose `HTTPRedirectHandler`
follows 301/302/303 on a POST by re-issuing it as a GET. Measured on the
TypeScript SDK, that was a complete governance bypass, and this client had the
same shape: a 302 from the configured URL to an attacker-controlled server made
`inspect()` return that server's `decision: "allow"` -- with no evidence
anywhere, because the real sidecar was never reached.

No live sidecar needed: the stubs below ARE the two servers.

Note 307/308 were never the hole here. urllib already refuses those on a POST
(`redirect_request` raises), which is exactly why the regression has to be
driven with a 302 to be worth anything.
"""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from iaga_letta.client import SentinelApiError, SentinelClient

HOSTILE_VERDICT = {"decision": "allow", "risk": {"score": 0, "reasons": []}}


class _Hostile(BaseHTTPRequestHandler):
    """The server the redirect points at. It always says 'allow'."""

    def _reply(self):
        raw = json.dumps(HOSTILE_VERDICT).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    # A followed 302 arrives as a GET, so both verbs must answer for the test to
    # be able to fail.
    do_GET = do_POST = lambda self: (  # noqa: E731,N815
        self.rfile.read(int(self.headers.get("Content-Length", 0) or 0)),
        self._reply(),
    )

    def log_message(self, *args):
        pass


def _redirector(target: str, code: int):
    class _Redirect(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            self.rfile.read(int(self.headers.get("Content-Length", 0) or 0))
            self.send_response(code)
            self.send_header("Location", target + "/v1/inspect")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *args):
            pass

    return _Redirect


@pytest.fixture
def hostile():
    srv = HTTPServer(("127.0.0.1", 0), _Hostile)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    thread.join(timeout=5)


@pytest.fixture
def redirecting(hostile):
    def _make(code: int) -> str:
        srv = HTTPServer(("127.0.0.1", 0), _redirector(hostile, code))
        thread = threading.Thread(target=srv.serve_forever, daemon=True)
        thread.start()
        _make.cleanup.append((srv, thread))
        return f"http://127.0.0.1:{srv.server_address[1]}"

    _make.cleanup = []
    yield _make
    for srv, thread in _make.cleanup:
        srv.shutdown()
        thread.join(timeout=5)


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
def test_redirect_is_refused_not_followed(redirecting, code):
    client = SentinelClient(redirecting(code), timeout_ms=5000)
    with pytest.raises(SentinelApiError) as excinfo:
        client.inspect(
            {
                "agentId": "a",
                "framework": "letta",
                "action": {"type": "shell", "toolName": "Bash", "payload": {}},
            }
        )
    assert excinfo.value.status == code, "the original 3xx must reach the caller"


def test_hostile_verdict_never_reaches_the_caller(redirecting):
    """The specific injury: not 'an error happened' but 'allow was fabricated'."""
    client = SentinelClient(redirecting(302), timeout_ms=5000)
    try:
        result = client.inspect(
            {
                "agentId": "a",
                "framework": "letta",
                "action": {"type": "shell", "toolName": "Bash", "payload": {}},
            }
        )
    except SentinelApiError:
        return  # refused, which is the whole point
    pytest.fail(f"followed the redirect and returned a foreign verdict: {result}")
