"""Govern an OpenAI client's tool/LLM calls with IAGA Sentinel.

    pip install openai iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register the agent (see README.md), then:
    # set OPENAI_API_KEY in your shell, then:
    python plug-ins/openai-adapter/python_example.py

`sentinel_wrap_openai` returns a drop-in proxy of your OpenAI client: every
`chat.completions.create` / `responses.create` is inspected through IAGA before
the request is sent. allow -> sends; block/review -> both raise PermissionError
(a dangerous prompt is blocked by the firewall before any spend).
"""
from openai import OpenAI

from iaga_sentinel.adapters import sentinel_wrap_openai

client = sentinel_wrap_openai(
    OpenAI(),
    agent_id="openai-demo",
    base_url="http://localhost:4010",
    # fail_closed=True,  # deny if the sidecar is unreachable (default: fail-open)
)


if __name__ == "__main__":
    resp = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "Summarize the README."}],
    )
    print(resp.choices[0].message.content)
