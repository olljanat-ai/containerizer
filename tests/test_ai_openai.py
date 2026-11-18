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


def test_short_answers_are_capped_and_a_ramble_is_reported(server, monkeypatch):
    server.answer('{"verdict": "blocker", "confidence": 0.9}')
    ai.ask_json("p-cap", SCHEMA, max_tokens=ai.SHORT_ANSWER_TOKENS)
    assert server.requests[-1]["body"]["max_tokens"] == ai.SHORT_ANSWER_TOKENS
    server.answer('{"verdict": "info", "confidence": 1}')
    ai.ask_json("p-nocap", SCHEMA)
    assert server.requests[-1]["body"]["max_tokens"] == 16000
    monkeypatch.setenv("CONTAINERIZER_LLM_MAX_TOKENS", "2000")         # the environment's cap still wins
    server.answer('{"verdict": "info", "confidence": 1}')
    ai.ask_json("p-env", SCHEMA, max_tokens=ai.SHORT_ANSWER_TOKENS)
    assert server.requests[-1]["body"]["max_tokens"] == 2000
    # cut off at the environment's cap (no bigger budget to retry with): a clear error, the component keeps the
    # rules' verdict
    server.answer('{"verdict": "info", "reasoning": "and so on and so on', finish="length")
    n = len(server.requests)
    with pytest.raises(RuntimeError, match="cut off at 2000 tokens: the model rambled"):
        ai.ask_json("p-ramble", SCHEMA, max_tokens=ai.SHORT_ANSWER_TOKENS)
    assert len(server.requests) == n + 1 and server.requests[-1]["body"]["max_tokens"] == 2000


def test_a_reasoning_model_cut_off_by_the_short_cap_is_asked_again_with_the_whole_budget(server):
    """gpt-oss-20b on llama.cpp: its thinking (reasoning_content) used the 4096 tokens of a short answer and the
    content was empty. Asked again with the same cap it ended the same way; now with CONTAINERIZER_LLM_MAX_TOKENS."""
    def thinking(content, finish):
        return (200, {"choices": [{"message": {"role": "assistant", "content": content,
                                               "reasoning_content": "We need to look at the build log. " * 300},
                                   "finish_reason": finish}], "usage": {"prompt_tokens": 11, "completion_tokens": 4096}})
    server.replies.append(thinking("", "length"))
    server.replies.append(thinking('{"verdict": "info", "confidence": 1}', "stop"))
    assert ai.ask_json("p-think", SCHEMA, max_tokens=ai.SHORT_ANSWER_TOKENS)["verdict"] == "info"
    assert [r["body"]["max_tokens"] for r in server.requests[-2:]] == [ai.SHORT_ANSWER_TOKENS, 16000]
    # cut off with the whole budget too: the error says the reasoning took it
    server.replies.append(thinking("", "length"))
    server.replies.append(thinking("", "length"))
    with pytest.raises(RuntimeError, match=r"cut off at 16000 tokens, \d+ characters of them the model's reasoning"):
        ai.ask_json("p-think-more", SCHEMA, max_tokens=ai.SHORT_ANSWER_TOKENS)


def test_reviews_ask_for_a_short_answer(monkeypatch):
    seen = {}
    monkeypatch.setattr(ai, "ask_json", lambda *a, **k: seen.update(k) or {"verdict": "info", "confidence": 1})
    monkeypatch.setattr(ai, "review_prompt", lambda a, c: "p")
    ai.ai_review_component(object(), object())
    assert seen["max_tokens"] == ai.SHORT_ANSWER_TOKENS


def test_cancelled_run_stops_the_llm_call(server, monkeypatch):
    """A cancelled scan run: a call not started yet never reaches the server, and one the server is still
    answering has its connection closed at once (which stops a self-hosted server generating)."""
    import time
    monkeypatch.setattr(ai, "CANCEL_POLL", 0.1)
    with ai.cancel_when(lambda: True):
        with pytest.raises(ai.Cancelled):
            ai.ask_json("p", SCHEMA)
    assert server.requests == []

    stop = threading.Event()

    def slow(body):
        time.sleep(3)                   # a long answer; the client goes away meanwhile
        return 200, {"choices": [{"message": {"content": '{"verdict": "info", "confidence": 1}'}}]}
    server.replies.append((200, slow))
    threading.Timer(0.3, stop.set).start()
    t0 = time.monotonic()
    with ai.cancel_when(stop.is_set):
        with pytest.raises(ai.Cancelled, match="while the LLM was answering"):
            ai.ask_json("q", SCHEMA)
    assert time.monotonic() - t0 < 2 and len(server.requests) == 1
    assert ai._CANCEL["check"] is None              # the run's check is gone after it
    time.sleep(3)                                   # let the fake server finish before the next test


def test_cancelled_run_kills_the_claude_cli(monkeypatch):
    import time
    monkeypatch.setattr(ai, "CANCEL_POLL", 0.1)
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    t0 = time.monotonic()
    with ai.cancel_when(stop.is_set):
        with pytest.raises(ai.Cancelled):
            ai._run_cancellable(["sleep", "30"], "", 900)
    assert time.monotonic() - t0 < 3
    p = ai._run_cancellable(["cat"], "hello", 10)
    assert p.returncode == 0 and p.stdout == "hello"


def test_a_question_bigger_than_the_context_window_is_cut_to_fit(server):
    """vLLM with --max-model-len 32768 answered HTTP 400 "Input length (57989) exceeds model's maximum context length
    (32768)" (and the JSON modes were tried in turn as if it lacked them). Now: asked once more, the middle cut out."""
    seen = []

    def too_long(body):
        seen.append(body)
        n = sum(len(m["content"]) for m in body["messages"]) // 3
        if n > 32768 - body["max_tokens"]:
            return 400, {"error": {"message": f"Input length ({n}) exceeds model's maximum context length (32768).",
                                   "type": "BadRequestError", "param": None, "code": 400}}
        return 200, {"choices": [{"message": {"role": "assistant", "content": '{"verdict": "info", "confidence": 1}'},
                                  "finish_reason": "stop"}], "usage": {"prompt_tokens": n, "completion_tokens": 9}}
    server.replies += [(200, too_long), (200, too_long)]
    prompt = "TASK: rate it.\n" + "log line\n" * 20000 + "END: answer now."
    assert ai.ask_json(prompt, SCHEMA)["verdict"] == "info"
    assert len(seen) == 2                                   # not retried in the other JSON modes
    fitted = seen[1]["messages"][1]["content"]
    assert fitted.startswith("TASK: rate it.") and "END: answer now." in fitted and "left out to fit" in fitted
    assert seen[1]["max_tokens"] == 32768 // 4

    # too big even cut down: a clear error that says what to change
    server.replies += [(400, {"error": {"message": "Input length (40000) exceeds model's maximum context length "
                                                   "(32768)."}})] * 2
    with pytest.raises(RuntimeError, match="context window of 32768 tokens even cut down"):
        ai.ask_json("p2 " + "x" * 100000, SCHEMA)


def test_context_errors_of_other_servers_are_recognised():
    e = ai._context_error("This model's maximum context length is 8192 tokens. However, you requested 9000 tokens "
                          "(8000 in the messages, 1000 in the completion).")
    assert (e.limit, e.used) == (8192, 8000)
    e = ai._context_error('{"error":{"code":400,"message":"the request exceeds the available context size, try '
                          'increasing it","type":"exceed_context_size_error","n_prompt_tokens":40000,"n_ctx":32768}}')
    assert (e.limit, e.used) == (32768, 40000)
    assert ai._context_error("response_format json_schema is not supported") is None


def test_a_scan_sends_questions_too_big_for_its_llm_to_the_built_in_one(server):
    """vLLM with --max-model-len 32768 (no memory for more): the questions bigger than its "Calls up to", or refused as
    bigger than its context window, go to the built-in LLM, uncut; the others stay with it."""
    big = FakeServer()
    try:
        builtin = {"CONTAINERIZER_LLM_BASE_URL": big.url + "/", "CONTAINERIZER_MODEL": "built-in-model"}
        ok = '{"verdict": "info", "confidence": 1}'
        with ai.overflow(1000, builtin, "built-in-model"):
            server.answer(ok)
            ai.ask_json("small question", SCHEMA)
            assert len(server.requests) == 1 and not big.requests
            big.answer(ok)
            ai.ask_json("big question " + "x" * 5000, SCHEMA)          # about 1,600 tokens: over 1000
            assert len(server.requests) == 1 and big.requests[-1]["body"]["model"] == "built-in-model"
            assert "x" * 5000 in big.requests[-1]["body"]["messages"][1]["content"]
        with ai.overflow(0, builtin, "built-in-model"):                 # no limit set: only what it refuses
            server.replies.append((400, {"error": {"message": "Input length (40000) exceeds model's maximum context "
                                                              "length (32768)."}}))
            big.answer(ok)
            assert ai.ask_json("refused question", SCHEMA)["verdict"] == "info"
            assert big.requests[-1]["body"]["messages"][1]["content"].startswith("refused question")
            assert "left out to fit" not in big.requests[-1]["body"]["messages"][1]["content"]
    finally:
        big.httpd.shutdown()
