from iaga_sentinel.client import SentinelClient


def test_create_agent_key_sends_identity_binding() -> None:
    client = SentinelClient.__new__(SentinelClient)
    captured = {}

    def post(path, body):
        captured.update(path=path, body=body)
        return {"ok": True}

    client._post = post
    assert client.create_key("worker", "agent", "agent-7") == {"ok": True}
    assert captured == {
        "path": "/v1/auth/keys",
        "body": {"label": "worker", "scope": "agent", "agentId": "agent-7"},
    }
