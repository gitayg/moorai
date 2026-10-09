# moorai_client — Python client for `moorai serve`

`moorai serve` runs MoorAI's detection engine and policy as a localhost sidecar. This client is one
file, standard library only (`urllib`); tested on Python 3.14.

```sh
moorai-serve                         # 127.0.0.1:8790, server-mode semantics, no token
MOORAI_SERVE_TOKEN=... moorai-serve  # require "Authorization: Bearer ..."
```

```python
from moorai_client import MoorAIClient, Blocked

moorai = MoorAIClient()          # MOORAI_SERVE_URL / MOORAI_SERVE_TOKEN, else http://127.0.0.1:8790

v = moorai.scan(user_text, stage="prompt")       # stages: prompt, file, output, index, tool
# {"decision": "allow"|"deny", "configuredDecision": ..., "threatIds": [54], "categories": [...],
#  "reasons": ["#54 ..."], "alternatives": [...], "findings": [...], "policyId": "..."}

v = moorai.tool_call("Bash", {"command": cmd})   # the decision MoorAI's hook makes for this call
moorai.tool_call_or_raise("WebFetch", {"url": url, "prompt": "summarise"})   # raises Blocked
```

The response never contains the submitted text. A `tool_call` response also carries `message`, the
same sentence the hook shows the agent, which can name a file or a host from the call.

**Decisions.** `deny` means stop. An `ask` (a threat the policy says needs sign-off) is settled the way
server mode settles it: denied, because no approver is present, unless the operator configured
`--headless-ask allow-with-report`. `configuredDecision` keeps what the policy asked for.

**Tool names.** `tool_call` takes Claude Code's tool names, because those are what the hook's checks are
written for. Map your framework's tools onto them:

| Your tool does | Send as | What runs |
| --- | --- | --- |
| runs a shell command | `Bash` / `PowerShell`, `{"command": ...}` | command scan, files the command reads, endpoint and secret-egress checks |
| reads a file | `Read`, `{"file_path": ...}` | file content, credential-path and metadata checks |
| writes a file | `Write`, `{"file_path": ..., "content": ...}` | output-stage scan of the bytes being written |
| fetches a URL | `WebFetch`, `{"url": ..., "prompt": ...}` | outbound request scan, endpoint allow-list, secret egress |
| anything else | `mcp__<app>__<tool>`, the arguments as a dict | argument scan, MCP allow-list and argument rules, files named in the arguments |

Paths in `Read`, `Bash` and MCP arguments are read **on the sidecar's filesystem** (relative to `cwd`),
so run the sidecar where the agent's files are: the same container or pod.

**The model's call id.** Pass `tool_call_id=` (the id the model gave the call: Anthropic `toolu_…`,
OpenAI `call_…`). When the sidecar runs with `--model-proxy-url` next to `moorai-model-proxy
--unchecked-window-ms`, the proxy then knows this call was checked. Any call the model returned that no
check matched raises a content-free "unchecked tool call" alert. Without those flags the id is ignored.

## LangGraph

A guard node between the model and the `ToolNode`: every tool call the model proposes is checked
first, and a denied one is answered with a `ToolMessage` instead of being run. (Not executed in this
repository; check it against your LangGraph version.)

```python
from langchain_core.messages import ToolMessage
from langgraph.graph import StateGraph, MessagesState, START, END
from langgraph.prebuilt import ToolNode
from moorai_client import MoorAIClient

moorai = MoorAIClient()
AS_HOOK_TOOL = {"run_shell": ("Bash", lambda a: {"command": a["command"]}),
                "read_file": ("Read", lambda a: {"file_path": a["path"]})}

def moorai_guard(state: MessagesState):
    calls = getattr(state["messages"][-1], "tool_calls", None) or []
    verdicts = []
    for call in calls:
        tool, shape = AS_HOOK_TOOL.get(call["name"], ("mcp__app__" + call["name"], lambda a: a))
        verdicts.append((call, moorai.tool_call(tool, shape(call["args"]), tool_call_id=call["id"])))
    if all(v["decision"] == "allow" for _, v in verdicts):
        return {"messages": []}
    # Every tool call needs an answer: the denied ones get MoorAI's reason, the rest are not run.
    return {"messages": [ToolMessage(content=v["message"] if v["decision"] != "allow" else
                                     "Not run: another tool call in this step was blocked by MoorAI.",
                                     tool_call_id=c["id"]) for c, v in verdicts]}

def route(state: MessagesState):
    last = state["messages"][-1]
    if isinstance(last, ToolMessage):   # the guard answered every call: back to the model
        return "agent"
    return "tools" if getattr(last, "tool_calls", None) else END

graph = StateGraph(MessagesState)
graph.add_node("agent", call_model)              # your model node
graph.add_node("moorai_guard", moorai_guard)
graph.add_node("tools", ToolNode(tools))
graph.add_edge(START, "agent")
graph.add_edge("agent", "moorai_guard")
graph.add_conditional_edges("moorai_guard", route, ["tools", "agent", END])
graph.add_edge("tools", "agent")
app = graph.compile()
```

Scan untrusted inputs too:
`moorai.scan(retrieved_doc, stage="file")` before a retrieved document enters the context.

## CrewAI

Wrap the tool itself, so the check runs whichever agent calls it. (Not executed in this repository;
check it against your CrewAI version.)

```python
import subprocess
from crewai.tools import BaseTool
from moorai_client import MoorAIClient, Blocked

moorai = MoorAIClient()

class ShellTool(BaseTool):
    name: str = "run_shell"
    description: str = "Run a shell command in the workspace."

    def _run(self, command: str) -> str:
        try:
            moorai.tool_call_or_raise("Bash", {"command": command})
        except Blocked as b:
            return b.verdict["message"]          # the agent sees why, and does not retry
        # A shell tool runs the model's command by design; MoorAI's check above is what stands in front of it.
        return subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60).stdout
```

For a task's final output, scan it before it is used: `moorai.scan(output_text, stage="output")`.

## Tests

`python3 -m unittest discover -s clients/python -p 'test_*.py' -v` starts a live `moorai serve`
(`node cli/moorai-serve.mjs --port 0`) in a throwaway HOME and runs the client against it.
