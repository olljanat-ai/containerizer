"""Self-hosted LLM backend: OpenAI-compatible chat completions, against a fake local server."""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from containerizer import ai

SCHEMA = {"type": "object", "additionalProperties": False, "required": ["verdict", "confidence"],
          "properties": {"verdict": {"type": "string", "enum": ["info", "blocker"]},
                         "confidence": {"type": "number"}}}


class FakeServer:
    """Answers /v1/chat/completions with queued replies; records requests."""

    def __init__(self):
        self.requests, self.replies = [], []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append({"path": self.path, "body": body, "auth": self.headers.get("Authorization")})
                code, payload = outer.replies.pop(0)
                if callable(payload):
                    code, payload = payload(body)
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/v1"

    def answer(self, content, code=200, finish="stop"):
        self.replies.append((code, {"choices": [{"message": {"role": "assistant", "content": content},
                                                 "finish_reason": finish}],
                                    "usage": {"prompt_tokens": 11, "completion_tokens": 7}}))


@pytest.fixture
def server(monkeypatch, tmp_path):
    s = FakeServer()
    for k in ("CONTAINERIZER_AI_BACKEND", "CONTAINERIZER_LLM_API_KEY", "CONTAINERIZER_LLM_JSON_MODE",
              "CONTAINERIZER_LLM_ALLOW_HTTP", "ANTHROPIC_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CONTAINERIZER_LLM_BASE_URL", s.url + "/")
    monkeypatch.setenv("CONTAINERIZER_MODEL", "qwen3:32b")
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    monkeypatch.setattr(ai, "CACHE", tmp_path / "cache")
    yield s
    s.httpd.shutdown()


def test_backend_selected_by_base_url(server):
    assert ai._backend() == "openai"
    assert ai.model_name() == "qwen3:32b"
    assert ai.model_name("llama3.3:70b") == "llama3.3:70b"


def test_structured_answer_and_usage(server):
    server.answer('{"verdict": "blocker", "confidence": 0.9}')
    assert ai.ask_json("p", SCHEMA) == {"verdict": "blocker", "confidence": 0.9}
    req = server.requests[0]
    assert req["path"] == "/v1/chat/completions"
    assert req["body"]["model"] == "qwen3:32b"
    assert req["body"]["response_format"]["type"] == "json_schema"
    assert req["body"]["response_format"]["json_schema"]["schema"] == SCHEMA
    assert req["body"]["messages"][0] == {"role": "system", "content": ai.SYSTEM}
    assert req["auth"] is None
    u = ai.USAGE_LOG[-1]
    assert (u["backend"], u["model"], u["input_tokens"], u["output_tokens"], u["cost_usd"]) == \
        ("openai", "qwen3:32b", 11, 7, 0)
    # cached: a second call does not reach the server
    assert ai.ask_json("p", SCHEMA)["verdict"] == "blocker"
    assert len(server.requests) == 1


def test_falls_back_when_server_lacks_json_schema(server):
    server.replies.append((400, {"error": "response_format json_schema not supported"}))
    server.answer('```json\n{"verdict": "info", "confidence": 1}\n```')
    assert ai.ask_json("p2", SCHEMA)["verdict"] == "info"
    assert server.requests[1]["body"]["response_format"] == {"type": "json_object"}


def test_reasoning_and_invalid_answers_are_retried_then_rejected(server):
    server.answer('<think>maybe {"verdict": "x"}</think>{"verdict": "maybe", "confidence": 1}')
    server.answer('{"verdict": "info"}')
    with pytest.raises(RuntimeError, match="no valid JSON"):
        ai.ask_json("p3", SCHEMA)
    assert "did not match the schema" in server.requests[1]["body"]["messages"][1]["content"]


def test_think_block_is_skipped(server):
    server.answer('<think>{"verdict": "blocker", "confidence": 0}</think>\n{"verdict": "info", "confidence": 0.5}')
    assert ai.ask_json("p4", SCHEMA) == {"verdict": "info", "confidence": 0.5}


def test_api_key_and_http_policy(server, monkeypatch):
    monkeypatch.setenv("CONTAINERIZER_LLM_API_KEY", "s3cret")
    server.answer('{"verdict": "info", "confidence": 1}')
    ai.ask_json("p5", SCHEMA)                                   # loopback over http is fine
    assert server.requests[0]["auth"] == "Bearer s3cret"
    monkeypatch.setenv("CONTAINERIZER_LLM_BASE_URL", "http://llm.example.internal:8000/v1")
    with pytest.raises(RuntimeError, match="plain http"):
        ai.ask_json("p6", SCHEMA)
    monkeypatch.setenv("CONTAINERIZER_LLM_BASE_URL", "http://user:pw@llm.example.internal/v1")
    with pytest.raises(RuntimeError, match="credentials"):
        ai.ask_json("p7", SCHEMA)
    monkeypatch.setenv("CONTAINERIZER_LLM_BASE_URL", "file:///etc/passwd")
    with pytest.raises(RuntimeError, match="http"):
        ai.ask_json("p8", SCHEMA)


def test_model_required_and_backend_validated(server, monkeypatch):
    monkeypatch.delenv("CONTAINERIZER_MODEL")
    with pytest.raises(RuntimeError, match="needs a model"):
        ai.ask_json("p9", SCHEMA)
    monkeypatch.setenv("CONTAINERIZER_AI_BACKEND", "gpt")
    with pytest.raises(RuntimeError, match="must be one of"):
        ai._backend()


def test_claude_default_unchanged(monkeypatch):
    for k in ("CONTAINERIZER_LLM_BASE_URL", "CONTAINERIZER_MODEL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CONTAINERIZER_AI_BACKEND", "api")
    assert ai.model_name() == "claude-opus-5-5"


def test_schema_validator():
    from containerizer.ai import REVIEW_SCHEMA, _schema_errors
    ok = {"verdict": "config", "confidence": 0.8, "reasoning": "r", "packages": [],
          "findings": [{"severity": "refactor", "title": "t", "why": "w", "fix": "f", "evidence_regex": "",
                        "agrees_with_rule": False}]}
    assert _schema_errors(ok, REVIEW_SCHEMA) == []
    bad = json.loads(json.dumps(ok))
    bad["findings"][0]["severity"] = "huge"
    bad["confidence"] = "high"
    del bad["packages"]
    errs = _schema_errors(bad, REVIEW_SCHEMA)
    assert len(errs) == 3


@pytest.fixture
def no_sleep(monkeypatch):
    slept = []
    monkeypatch.setattr(ai.time, "sleep", slept.append)
    return slept


def test_loading_model_is_retried_with_backoff(server, no_sleep):
    loading = {"error": {"code": 503, "message": "Loading model", "type": "unavailable_error"}}
    server.replies += [(503, loading), (503, loading)]
    server.answer('{"verdict": "blocker", "confidence": 0.9}')
    assert ai.ask_json("p-retry", SCHEMA)["verdict"] == "blocker"
    assert len(server.requests) == 3
    assert no_sleep == [5.0, 10.0]


def test_server_errors_that_are_not_transient_are_not_retried(server, no_sleep):
    server.replies.append((500, {"error": "boom"}))
    with pytest.raises(RuntimeError, match="answered HTTP 500"):
        ai.ask_json("p-500", SCHEMA)
    assert len(server.requests) == 1 and no_sleep == []


def test_unreachable_server_gives_up_after_the_retry_budget(server, no_sleep, monkeypatch):
    port = server.httpd.server_port
    server.httpd.shutdown()
    server.httpd.server_close()             # nothing listens: connection refused
    monkeypatch.setenv("CONTAINERIZER_LLM_BASE_URL", f"http://127.0.0.1:{port}/v1")
    monkeypatch.setenv("CONTAINERIZER_LLM_RETRY_SECONDS", "0")
    with pytest.raises(RuntimeError, match="cannot reach LLM server"):
        ai.ask_json("p-down", SCHEMA)
    assert no_sleep == []
    # with a budget it keeps trying, with growing waits capped at 30 s
    clock = iter(range(0, 10_000, 1))
    monkeypatch.setattr(ai.time, "monotonic", lambda: next(clock))
    monkeypatch.setenv("CONTAINERIZER_LLM_RETRY_SECONDS", "100")
    with pytest.raises(RuntimeError, match="cannot reach LLM server"):
        ai.ask_json("p-down2", SCHEMA)
    assert no_sleep[:4] == [5.0, 10.0, 20.0, 30.0] and set(no_sleep[3:]) == {30.0}


def test_timeouts_are_not_retried(server, no_sleep, monkeypatch):
    def timeout(*a, **k):
        raise TimeoutError("timed out")
    monkeypatch.setattr(ai, "_post_json", timeout)
    with pytest.raises(RuntimeError, match="cannot reach LLM server"):
        ai.ask_json("p-slow", SCHEMA)
    assert no_sleep == []
