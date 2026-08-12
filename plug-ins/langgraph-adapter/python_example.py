"""Govern a LangGraph agent's tools with IAGA Sentinel.

Setup:
    pip install langgraph langchain-openai langchain-core iaga-sentinel
    IAGA_SENTINEL_HOST=127.0.0.1 IAGA_SENTINEL_OPEN_MODE=true ./target/release/iaga serve --seed-demo
    # register an agent that allows your tools (see README.md), then:
    python plug-ins/langgraph-adapter/python_example.py

`GovernedToolNode` is a drop-in replacement for langgraph's `ToolNode`: it
inspects every tool call through IAGA Sentinel before running it. Allowed calls
run and are receipted; blocked/review calls raise PermissionError. Pure LLM
nodes produce no action and stay untouched.
"""
import os
import subprocess

from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, MessagesState, StateGraph

from iaga_sentinel.adapters import GovernedToolNode


@tool
def filesystem_read(path: str) -> str:
    """Read a UTF-8 text file."""
    with open(path, encoding="utf-8") as fh:
        return fh.read()


@tool
def shell(cmd: str) -> str:
    """Run a shell command."""
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


TOOLS = [filesystem_read, shell]
model = ChatOpenAI(model="gpt-4o").bind_tools(TOOLS)

# The only IAGA-specific change: swap ToolNode -> GovernedToolNode.
governed_tools = GovernedToolNode(
    TOOLS,
    agent_id=os.environ.get("IAGA_AGENT_ID", "langgraph-demo"),
    base_url=os.environ.get("IAGA_BASE_URL", "http://localhost:4010"),
    # fail_closed=True,  # deny if the sidecar is unreachable (default: fail-open)
)


def call_model(state: MessagesState):
    return {"messages": [model.invoke(state["messages"])]}


def should_continue(state: MessagesState):
    last = state["messages"][-1]
    return "tools" if getattr(last, "tool_calls", None) else END


graph = StateGraph(MessagesState)
graph.add_node("model", call_model)
graph.add_node("tools", governed_tools)  # <- governed
graph.add_edge(START, "model")
graph.add_conditional_edges("model", should_continue, {"tools": "tools", END: END})
graph.add_edge("tools", "model")
app = graph.compile()


if __name__ == "__main__":
    # A dangerous tool call (e.g. "curl ... | sh") is blocked before it runs.
    result = app.invoke(
        {"messages": [("user", "Read ./README.md and summarize it.")]}
    )
    print(result["messages"][-1].content)
