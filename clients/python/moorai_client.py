"""Tiny, dependency-free client for `moorai serve` (the MoorAI localhost sidecar).

    from moorai_client import MoorAIClient
    moorai = MoorAIClient()                      # MOORAI_SERVE_URL / MOORAI_SERVE_TOKEN, else 127.0.0.1:8790
    v = moorai.scan(user_text, stage="prompt")    # {"decision": "allow"|"ask"|"deny", "threatIds": [...], ...}
    v = moorai.tool_call("Bash", {"command": cmd})
    if v["decision"] != "allow": raise PermissionError(v["message"])

Standard library only (urllib). The server never echoes the submitted text, and neither does this client.
"""

import json
import os
import urllib.error
import urllib.request

__all__ = ["MoorAIClient", "MoorAIError", "Blocked", "scan", "tool_call", "DEFAULT_URL"]

DEFAULT_URL = "http://127.0.0.1:8790"
STAGES = ("prompt", "file", "output", "index", "tool")


class MoorAIError(Exception):
    """The sidecar could not be reached or rejected the request (status is None when unreachable)."""

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class Blocked(Exception):
    """Raised by the `*_or_raise` helpers when MoorAI's decision is not "allow"."""

    def __init__(self, verdict):
        super().__init__(verdict.get("message") or "MoorAI: " + "; ".join(verdict.get("reasons") or ["blocked"]))
        self.verdict = verdict


class MoorAIClient:
    def __init__(self, base_url=None, token=None, timeout=5.0):
        self.base_url = (base_url or os.environ.get("MOORAI_SERVE_URL") or DEFAULT_URL).rstrip("/")
        self.token = token if token is not None else os.environ.get("MOORAI_SERVE_TOKEN", "")
        self.timeout = timeout

    def _request(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        req = urllib.request.Request(self.base_url + path, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            try:
                msg = json.loads(e.read().decode("utf-8")).get("error", "")
            except ValueError:
                msg = ""
            raise MoorAIError("moorai serve returned %d: %s" % (e.code, msg or e.reason), e.code) from None
        except (urllib.error.URLError, OSError) as e:
            raise MoorAIError("moorai serve unreachable at %s: %s" % (self.base_url, getattr(e, "reason", e))) from None

    def health(self):
        return self._request("GET", "/healthz")

    def scan(self, text, stage="prompt", ctx=None):
        """Content-free verdict on one string: decision, threatIds, categories, reasons, findings."""
        if stage not in STAGES:
            raise ValueError("stage must be one of " + ", ".join(STAGES))
        body = {"text": text, "stage": stage}
        if ctx:
            body["ctx"] = ctx
        return self._request("POST", "/v1/scan", body)

    def tool_call(self, tool, input=None, cwd=None):
        """The decision MoorAI's hook makes for this tool call (tool names as Claude Code's: Bash, Read,
        Write, WebFetch, mcp__<server>__<tool>, ...)."""
        body = {"tool": tool, "input": input or {}}
        if cwd:
            body["cwd"] = cwd
        return self._request("POST", "/v1/tool-call", body)

    def scan_or_raise(self, text, stage="prompt", ctx=None):
        v = self.scan(text, stage, ctx)
        if v.get("decision") != "allow":
            raise Blocked(v)
        return v

    def tool_call_or_raise(self, tool, input=None, cwd=None):
        v = self.tool_call(tool, input, cwd)
        if v.get("decision") != "allow":
            raise Blocked(v)
        return v


_default = None


def _client():
    global _default
    if _default is None:
        _default = MoorAIClient()
    return _default


def scan(text, stage="prompt", ctx=None):
    return _client().scan(text, stage, ctx)


def tool_call(tool, input=None, cwd=None):
    return _client().tool_call(tool, input, cwd)
