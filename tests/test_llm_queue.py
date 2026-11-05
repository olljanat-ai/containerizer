"""The LLM queue (llmqueue.py): which component reviews are queued and in what order, queued mode asking the
LLM nothing during a scan, answers applying at the next scan through the answer cache, the runner, the
schedule window and idle check, the learned token and time estimates, and the admin page (fake database
connections). The SQL Server end of it (cz.QueueLlmJob, the grants and triggers) is tested with
CONTAINERIZER_TEST_SQL."""
import json
import os
import re
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from containerizer import admin_llmqueue, admin_scans, ai, assess, llmqueue as lq, worker

UTC = timezone.utc


def comp(name="Api", tier="server", confidence=0.7, verdict="config", stateless=True, uncertain=()):
    """A component as apply_ai sees it."""
    return SimpleNamespace(name=name, tier=tier, confidence=confidence, rule_verdict=verdict, verdict=verdict,
                           stateless=stateless, uncertain=list(uncertain), ai={}, override="",
                           project=SimpleNamespace(rel=f"src/{name}/{name}.csproj"))


def app(*components, name="shop", root="/nonexistent"):
    return SimpleNamespace(name=name, components=list(components), repo=SimpleNamespace(root=root))


@pytest.fixture
def llm(tmp_path, monkeypatch):
    """A fake Claude API: answers every review, counts the calls; the answer cache in tmp_path."""
    calls = []
    monkeypatch.setattr(ai, "CACHE", tmp_path / "cache")
    for k in ("CONTAINERIZER_LLM_BASE_URL", "CONTAINERIZER_MODEL"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("CONTAINERIZER_AI_BACKEND", "api")
    monkeypatch.setattr(ai, "review_prompt", lambda a, c: f"review {a.name}/{c.name}")

    def answer(prompt, schema, model, effort, system):
        calls.append(prompt)
        return ({"verdict": "info", "confidence": 0.9, "reasoning": "only used by an optional command",
                 "findings": [], "packages": []}, {"input_tokens": 1000, "output_tokens": 200})
    monkeypatch.setattr(ai, "_ask_api", answer)
    return calls


# --------------------------------------------------------------------------- what is queued, in what order

def test_review_kind_and_priority():
    assert lq.review_kind(comp(confidence=0.7)) == "uncertain"
    assert lq.review_kind(comp(confidence=0.9, verdict="blocker")) == "second-opinion"
    assert lq.review_kind(comp(confidence=0.9, verdict="rewrite", tier="platform")) == "second-opinion"
    assert lq.review_kind(comp(confidence=0.9, verdict="refactor")) is None
    assert lq.review_kind(comp(confidence=0.5, tier="client")) is None
    # uncertain always before second opinions, whatever else
    worst_uncertain = lq.priority(comp(confidence=1.0, tier="platform", stateless=False, verdict="info"), "uncertain")
    best_second = lq.priority(comp(confidence=0.2, verdict="blocker"), "second-opinion")
    assert worst_uncertain == 1000 and best_second == 0 + 320 + 300 + 100 and worst_uncertain > best_second
    # less sure first; a component only its verdict keeps from A first
    assert lq.priority(comp(confidence=0.4), "uncertain") > lq.priority(comp(confidence=0.8), "uncertain")
    a = comp(confidence=0.8, verdict="refactor")
    assert lq.a_candidate(a) and not lq.a_candidate(comp(verdict="refactor", stateless=False))
    assert not lq.a_candidate(comp(verdict="config"))
    assert lq.priority(a, "uncertain") - lq.priority(comp(confidence=0.8, verdict="refactor", stateless=False),
                                                     "uncertain") == 300


def test_reorder_moves_exactly_one_place_with_ties():
    rows = [{"JobId": 1, "Priority": 1500, "AdminRank": None}, {"JobId": 2, "Priority": 1200, "AdminRank": None},
            {"JobId": 3, "Priority": 1200, "AdminRank": None}, {"JobId": 4, "Priority": 300, "AdminRank": None}]

    def apply(rows, ranks):
        return [r["JobId"] for r in lq.ordered([{**r, "AdminRank": ranks.get(r["JobId"], r["AdminRank"])} for r in rows])]
    assert [r["JobId"] for r in lq.ordered(rows)] == [1, 2, 3, 4]
    assert apply(rows, lq.reorder(rows, 3, "up")) == [1, 3, 2, 4]          # past its tie
    assert apply(rows, lq.reorder(rows, 2, "down")) == [1, 3, 2, 4]
    assert apply(rows, lq.reorder(rows, 4, "top")) == [4, 1, 2, 3]
    assert apply(rows, lq.reorder(rows, 1, "bottom")) == [2, 3, 4, 1]
    assert lq.reorder(rows, 1, "up") == {} and lq.reorder(rows, 4, "bottom") == {}
    # an administrator's position stays, new jobs still go in by their priority
    moved = [{**r, "AdminRank": lq.reorder(rows, 1, "bottom").get(r["JobId"], r["AdminRank"])} for r in rows]
    moved.append({"JobId": 5, "Priority": 1100, "AdminRank": None})
    assert [r["JobId"] for r in lq.ordered(moved)] == [2, 3, 5, 4, 1]
    with pytest.raises(ValueError):
        lq.reorder(rows, 1, "sideways")


# --------------------------------------------------------------------------- queued mode

def test_queued_reviews_enqueue_dedupe_and_apply_at_the_next_scan(tmp_path, llm):
    q = lq.FileJobQueue(tmp_path / "llm-queue.json")
    first = [comp("Api", confidence=0.7), comp("Legacy", confidence=0.95, verdict="blocker"), comp("Ok", confidence=0.95)]
    assess.apply_ai(app(*first), queue=q)
    assert llm == []                                            # nothing asked during the scan
    jobs = q.load()
    assert [(j["Component"], j["Reason"], j["Status"]) for j in jobs] == [("Api", "uncertain", "queued"),
                                                                         ("Legacy", "second-opinion", "queued")]
    assert first[0].ai["queue"] == "queued" and first[0].override == "" and first[2].ai == {}
    j = jobs[0]
    assert j["Kind"] == "review" and j["RequestedBy"] == "command line" and j["Payload"]["prompt"] == "review shop/Api"
    assert j["DedupeKey"] == ai.cache_key("review shop/Api", ai.REVIEW_SCHEMA)
    assert j["InputChars"] > len("review shop/Api") and j["EstInputTokens"] == lq.estimate_tokens("x" * j["InputChars"])
    # the same question again: not queued twice; first pass of a scan (enqueue=False): not queued at all
    assess.apply_ai(app(comp("Api", confidence=0.7)), queue=q)
    assess.apply_ai(app(comp("New", confidence=0.7)), queue=q, enqueue=False)
    assert len(q.load()) == 2
    # the runner answers the stored question: the answer lands in the cache
    assert lq.run_file(q.path, log=lambda m: None) == 0
    assert len(llm) == 2 and {j["Status"] for j in q.load()} == {"answered"}
    assert q.load()[0]["InputTokens"] == 1000 and q.load()[0]["OutputTokens"] == 200
    # the next scan: answers apply at once, without asking the LLM again
    nxt = [comp("Api", confidence=0.7), comp("Legacy", confidence=0.95, verdict="blocker")]
    applied = assess.apply_ai(app(*nxt), queue=q)
    assert len(llm) == 2 and len(applied) == 2 and len(q.load()) == 2
    assert nxt[0].override == "info" and nxt[0].ai["verdict"] == "info" and nxt[0].ai["queue"] == "answered"
    # a second opinion must be as sure as the rules were (0.85): 0.9 is, so the blocker is overridden
    assert nxt[1].override == "info"


def test_answer_in_the_queue_applies_when_the_cache_does_not_have_it(tmp_path, llm):
    q = lq.FileJobQueue(tmp_path / "q.json")
    assess.apply_ai(app(comp("Api")), queue=q)
    items = q.load()
    items[0].update(Status="answered", Result={"verdict": "refactor", "confidence": 0.5, "reasoning": "x",
                                               "findings": [], "packages": []})
    q.save(items)
    c = comp("Api")
    assess.apply_ai(app(c), queue=q)
    assert llm == [] and c.ai["verdict"] == "refactor" and c.override == ""     # below 0.6: the rules keep it
    assert ai.cached_answer("review shop/Api", ai.REVIEW_SCHEMA)["verdict"] == "refactor"   # now cached too


def test_second_opinion_needs_a_sure_answer(tmp_path, llm, monkeypatch):
    monkeypatch.setattr(ai, "_ask_api", lambda *a: ({"verdict": "config", "confidence": 0.7, "reasoning": "r",
                                                     "findings": [], "packages": []}, {}))
    ai.ask_json("review shop/Legacy", ai.REVIEW_SCHEMA, feature="assessment")
    c = comp("Legacy", confidence=0.95, verdict="blocker")
    assess.apply_ai(app(c), queue=lq.FileJobQueue(tmp_path / "q.json"))
    assert c.ai["verdict"] == "config" and c.override == ""


def test_superseded_review_is_skipped(tmp_path, llm, monkeypatch):
    q = lq.FileJobQueue(tmp_path / "q.json")
    assess.apply_ai(app(comp("Api")), queue=q)
    monkeypatch.setattr(ai, "review_prompt", lambda a, c: "the code changed")
    assess.apply_ai(app(comp("Api")), queue=q)
    assert [(j["Status"], j.get("Note")) for j in q.load()] == [("skipped", "superseded by a newer scan"),
                                                               ("queued", None)]


def test_queued_mode_asks_the_llm_nothing_during_analyze(tmp_path, monkeypatch):
    from containerizer import analyze, rulereview, verify, generate

    def no_llm(*a, **k):
        raise AssertionError("the LLM was asked during a queued scan")
    monkeypatch.setattr(ai, "ask_json", no_llm)
    monkeypatch.setattr(ai, "CACHE", tmp_path / "cache")
    monkeypatch.setattr(ai, "review_prompt", lambda a, c: f"review {c.name}")
    monkeypatch.setenv("CONTAINERIZER_AI_BACKEND", "api")
    monkeypatch.delenv("CONTAINERIZER_LLM_BASE_URL", raising=False)

    class Session:
        def __init__(self, **k):
            self.app = None

        def __enter__(self):
            return self

        def __exit__(self, *e):
            pass

        def add_results(self, r):
            pass
    seen = {}
    monkeypatch.setattr(rulereview, "LearningSession", Session)
    monkeypatch.setattr(analyze, "assess", lambda path, rules: app(comp("Api")))
    monkeypatch.setattr(verify, "verify_app", lambda a, out, **k: seen.update(verify_ai=k["ai"]) or [])
    monkeypatch.setattr(generate, "generate_app", lambda *a, **k: [])
    q = lq.FileJobQueue(tmp_path / "q.json")
    a = analyze.analyze_app(tmp_path, tmp_path / "out", ai=True, review_queue=q)
    assert seen == {"verify_ai": False}                         # no failure diagnosis by the LLM
    assert [j["Component"] for j in q.load()] == ["Api"]        # queued once, from the final assessment
    assert a.components[0].ai["queue"] == "queued"
    # inline mode still diagnoses failures
    monkeypatch.setattr(assess, "apply_ai", lambda *a, **k: [])
    monkeypatch.setattr(analyze, "apply_ai", lambda *a, **k: [])
    analyze.analyze_app(tmp_path, tmp_path / "out", ai=True)
    assert seen == {"verify_ai": True}


def test_queued_scan_has_no_llm_heavy_mode():
    on = {"CONTAINERIZER_LLM_HEAVY": "1"}
    scan = {"UseAi": True, "LlmHeavy": True, "LlmMode": "inline"}
    assert worker.llm_heavy(scan, on) and not worker.llm_queued(scan)
    assert not worker.llm_heavy({**scan, "LlmMode": "queued"}, on) and worker.llm_queued({**scan, "LlmMode": "queued"})
    assert not worker.llm_queued({**scan, "UseAi": False, "LlmMode": "queued"})
    w = worker.Worker(lambda: None, "/tmp/cz-test-data", log=lambda m: None)
    o = w.options({"ScanId": 3, "Name": "Acme", "Provider": "github", "ApiUrl": None, "Organization": "acme",
                   "OutputRepo": None, "Registry": "r", "OutputBranch": "main", "PushImages": False,
                   "ImagePullSecret": None, "IncludeRegex": None, "ExcludeRegex": None, "SkipForks": True,
                   "StaleDays": 0, "UseAi": True, "Verify": True, "Gate": True, "LlmHeavy": True, "LlmMode": "queued"},
                  None, None)
    assert o.llm_heavy is False and isinstance(o.review_queue, lq.SqlJobQueue)
    assert o.review_queue.scan_id == 3 and o.review_queue.requested_by == "scan Acme"
    rq = o.review_queue.for_repo("Billing", "api", "Billing/api")
    assert (rq.project, rq.repo, rq.label, rq.scan_id) == ("Billing", "api", "Billing/api", 3)


def test_scan_form_llm_mode():
    from test_worker import _form
    v, errors = admin_scans.validate_scan(_form(UseAi="1", LlmMode="queued"))
    assert errors == [] and v["LlmMode"] == "queued"
    assert admin_scans.validate_scan(_form())[0]["LlmMode"] == "inline"
    _, errors = admin_scans.validate_scan(_form(UseAi="1", LlmHeavy="1", LlmMode="queued"))
    assert any("LLM-heavy mode needs inline LLM reviews" in x for x in errors)
    _, errors = admin_scans.validate_scan(_form(UseAi="1", LlmMode="later"))
    assert any("inline or queued" in x for x in errors)
    assert "LlmMode" in admin_scans.SCAN_COLS


def test_cli_ai_queue_without_sql_writes_a_queue_file(tmp_path, monkeypatch, capsys):
    from containerizer import cli
    monkeypatch.delenv("CONTAINERIZER_SQL", raising=False)
    args = SimpleNamespace(ai_queue=True, ai=True, sql=None)
    q = cli._job_queue(args, tmp_path)
    assert isinstance(q, lq.FileJobQueue) and q.path == tmp_path / "llm-queue.json"
    assert "containerizer llm-queue --file" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        cli._job_queue(SimpleNamespace(ai_queue=True, ai=False, sql=None), tmp_path)
    with pytest.raises(SystemExit):
        cli._job_queue(args, None)
    assert cli._job_queue(SimpleNamespace(ai_queue=False, ai=True, sql=None), tmp_path) is None


# --------------------------------------------------------------------------- the runner

class FakeCursor:
    def __init__(self, conn, as_dict=False):
        self.conn, self.as_dict, self.rowcount, self._rows = conn, as_dict, 1, []

    def execute(self, sql, params=None):
        self.conn.log.append((" ".join(sql.split()), params))
        self._rows = self.conn.answer(sql, params, self.as_dict)

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return list(self._rows)


class FakeConn:
    """Answers queries by the first matching pattern of `answers` (regex -> rows as dicts); others get []."""

    def __init__(self, answers=None):
        self.answers, self.log, self.commits = answers or {}, [], 0

    def answer(self, sql, params, as_dict):
        for pat, rows in self.answers.items():
            if re.search(pat, sql):
                rows = rows(params) if callable(rows) else rows
                return [r if as_dict else tuple(r.values()) for r in rows]
        return []

    def cursor(self, as_dict=False):
        return FakeCursor(self, as_dict)

    def commit(self):
        self.commits += 1

    def rollback(self):
        pass

    def close(self):
        pass

    def set_user(self, *a, **k):
        pass

    def sql(self, pattern):
        return [(s, p) for s, p in self.log if re.search(pattern, s)]


def test_runner_replays_the_prompt_into_the_cache_and_learns(tmp_path, llm):
    conn = FakeConn({r"SELECT \* FROM cz.LlmSpeed": []})
    m = lq.QueueMetrics("r1")
    try:
        r = lq.Runner(lambda: conn, name="r1", metrics=m, log=lambda msg: None, load=lambda: 0.0)
        key = ai.cache_key("review shop/Api", ai.REVIEW_SCHEMA)
        row = {"JobId": 7, "Kind": "review", "Repository": "shop", "Component": "Api", "Model": ai.model_name(),
               "InputChars": 3500, "Attempts": 1, "_endpoint": ai.endpoint(), "_parallel": 1,
               "Payload": json.dumps({"prompt": "review shop/Api", "model": ai.model_name(), "cache_key": key})}
        assert r.process(row) == "answered" and llm == ["review shop/Api"]
        (sql, params), = conn.sql(r"SET Status = N'answered'")
        assert params[1] == "info (0.90)" and params[2] is None and params[4:6] == (1000, 200)
        assert params[6] == "api claude-opus-5-5"
        # the next scan's lookup hits the cache
        c = comp("Api")
        assess.apply_ai(app(c), queue=lq.FileJobQueue(tmp_path / "q.json"))
        assert c.override == "info" and llm == ["review shop/Api"]
        # the endpoint's figures and the kind's were learned
        ins = conn.sql(r"INSERT cz.LlmSpeed")
        assert [p[1] for _, p in ins] == ["*", "review"] and ins[0][1][3] == 3.5   # 3500 chars / 1000 tokens
        text = m.registry.render()
        assert 'containerizer_llm_queue_jobs_finished_total{kind="review",result="answered"} 1' in text
        assert 'feature="assessment-queued"' in text
    finally:
        ai.LISTENERS.remove(m.llm)


def test_runner_retries_then_fails(llm, monkeypatch):
    def down(*a):
        raise RuntimeError("cannot reach LLM server")
    monkeypatch.setattr(ai, "_ask_api", down)
    conn = FakeConn()
    m = lq.QueueMetrics("r1")
    try:
        r = lq.Runner(lambda: conn, name="r1", metrics=m, log=lambda msg: None)
        row = {"JobId": 8, "Kind": "review", "Attempts": 1, "Payload": {"prompt": "p"}}
        assert r.process(row) == "retried"
        assert conn.sql("SET Status = %s")[-1][1][0] == "queued"
        assert r.process({**row, "Attempts": lq.MAX_ATTEMPTS}) == "failed"
        assert conn.sql("SET Status = %s")[-1][1][0] == "failed"
    finally:
        ai.LISTENERS.remove(m.llm)


def test_job_kinds_are_a_registry(tmp_path):
    got = []
    lq.register("echo", "Echo", lambda job: got.append(job["Payload"]) or {"result": {"ok": 1}, "summary": "ok"})
    try:
        q = lq.FileJobQueue(tmp_path / "q.json")
        assert q.add({"Kind": "echo", "Priority": 5, "DedupeKey": "k", "Payload": {"x": 1}}) == 1
        assert q.add({"Kind": "echo", "Priority": 5, "DedupeKey": "k", "Payload": {"x": 1}}) == 0
        assert lq.run_file(q.path, log=lambda m: None) == 0
        assert got == [{"x": 1}] and q.result("echo", "k") == {"ok": 1}
    finally:
        del lq.JOB_KINDS["echo"]


# --------------------------------------------------------------------------- when the queue may run

def test_window_and_idle_gate():
    mon = datetime(2026, 11, 2, tzinfo=UTC)            # a Monday
    at = lambda day, h, m=0: mon.replace(day=2 + day, hour=h, minute=m)  # noqa: E731
    assert lq.window_open(0, None, None, at(3, 12))                     # every day, all day
    assert lq.window_open(1, None, None, at(0, 12)) and not lq.window_open(1, None, None, at(1, 12))
    assert lq.window_open(127, 9 * 60, 17 * 60, at(0, 9)) and not lq.window_open(127, 540, 1020, at(0, 17))
    # Mondays 22:00-06:00: wraps midnight, and the night belongs to the day it started
    w = (1, 22 * 60, 6 * 60)
    assert lq.window_open(*w, at(0, 23)) and lq.window_open(*w, at(1, 3)) and not lq.window_open(*w, at(1, 6))
    assert not lq.window_open(*w, at(0, 3)) and not lq.window_open(*w, at(1, 23)) and not lq.window_open(*w, at(0, 21))
    assert lq.window_open(1, 600, 600, at(0, 3))                        # equal: all day
    s = dict(lq.DEFAULTS)
    assert lq.gate(s, at(0, 12), 0, 0.1) == (True, "")
    assert lq.gate({**s, "Paused": True}, at(0, 12), 0, 0.1)[1] == "paused"
    assert "scan" in lq.gate(s, at(0, 12), 1, 0.1)[1]
    assert "busy" in lq.gate(s, at(0, 12), 0, 0.8)[1]
    assert lq.gate({**s, "OnlyWhenIdle": False}, at(0, 12), 1, 9.0)[0]
    assert lq.gate({**s, "MaxLoadPerCpu": 0}, at(0, 12), 0, 9.0)[0]             # 0: the load is not looked at
    assert "hours" in lq.gate({**s, "WindowDays": 2}, at(0, 12), 0, 0)[1]
    assert lq.settings_text({**s, "WindowDays": 31, "WindowStart": 1320, "WindowEnd": 360}) == (
        "Mondays to Fridays 22:00-06:00 UTC, only when idle (no scan running, load below 0.50 per CPU), "
        "1 request at a time")


def test_settings_validation():
    v, errors = admin_llmqueue.validate_settings({"day": ["0", "4"], "From": ["22:00"], "To": ["06:00"],
                                                  "OnlyWhenIdle": ["1"], "MaxLoadPerCpu": ["0.75"], "Parallel": ["2"]})
    assert errors == [] and v == {"Paused": False, "OnlyWhenIdle": True, "WindowDays": 1 | 16, "WindowStart": 1320,
                                  "WindowEnd": 360, "MaxLoadPerCpu": 0.75, "Parallel": 2, "ApproveKinds": None, "ApproveMinTokens": 0,
                                  "ApproveMaxQueued": 0, "RejectAfterHours": 0, "LocalOrder": None, "LocalMaxTokens": 0,
                                  "JobsAtOnce": 0}
    v, errors = admin_llmqueue.validate_settings({"From": [""], "To": [""]})
    assert errors == [] and v["WindowStart"] is None and v["WindowEnd"] is None and v["Parallel"] == 1
    assert admin_llmqueue.validate_settings({"JobsAtOnce": ["4"]})[0]["JobsAtOnce"] == 4
    for bad, msg in (({"From": ["22:00"]}, "both"), ({"From": ["25:00"], "To": ["01:00"]}, "HH:MM"),
                     ({"From": ["08:00"], "To": ["08:00"]}, "same"), ({"Parallel": ["0"]}, "1 to 16"),
                     ({"MaxLoadPerCpu": ["x"]}, "0 to 16"), ({"JobsAtOnce": ["33"]}, "Jobs at once: 0 (automatic) to 32"),
                     ({"JobsAtOnce": ["-1"]}, "Jobs at once")):
        _, errors = admin_llmqueue.validate_settings(bad)
        assert any(msg in x for x in errors), (bad, errors)


# --------------------------------------------------------------------------- estimates

def test_estimate_tokens_and_ewma():
    assert lq.estimate_tokens("") == 0 and lq.estimate_tokens("x" * 7) == 2 and lq.estimate_tokens("x" * 8) == 3
    assert lq.estimate_tokens("x" * 100, chars_per_token=4) == 25
    assert lq.ewma(None, 10) == 10 and lq.ewma(10, 20) == pytest.approx(12) and lq.ewma(10, 20, alpha=0.5) == 15


def test_learned_figures_and_estimates():
    # no history: the defaults, and no time
    est = lq.Estimator([])
    x = est.job({"Kind": "review", "Model": "m", "InputChars": 7000})
    assert x == {"in": 2000, "out": lq.OUTPUT_TOKENS, "seconds": None, "basis": None}
    assert lq.duration_text(None) == "time: learning"
    # one CPU answer: 4000 chars were 1000 tokens (4 chars a token), 200 out, 100 s with no timings
    e, k = lq.observe(None, None, chars=4000, input_tokens=1000, output_tokens=200, seconds=100)
    assert e["CharsPerToken"] == 4 and e["TokensPerSecond"] == 12 and k["OutputTokens"] == 200 and e["Samples"] == 1
    assert "PromptTokensPerSecond" not in e
    # the next one moves each figure by ALPHA
    e2, k2 = lq.observe(e, k, chars=3000, input_tokens=1000, output_tokens=400, seconds=100)
    assert e2["CharsPerToken"] == pytest.approx(4 - 0.2 * 1) and k2["OutputTokens"] == pytest.approx(240)
    assert e2["Samples"] == 2
    # a server that reports timings: prompt and generation speed apart
    g, gk = lq.observe(None, None, chars=4000, input_tokens=1000, output_tokens=500, seconds=12, prompt_seconds=2,
                       generate_seconds=10, parallel=2)
    assert g["PromptTokensPerSecond"] == 500 and g["GenTokensPerSecond"] == 50 and g["Parallel"] == 2
    rows = [{**e, "Endpoint": "openai http://cpu:8080/v1 qwen", "Kind": "*", "Model": "qwen", "UpdatedAt": "2026-11-01"},
            {**k, "Endpoint": "openai http://cpu:8080/v1 qwen", "Kind": "review", "UpdatedAt": "2026-11-01"},
            {**g, "Endpoint": "openai https://gpu/v1 llama", "Kind": "*", "Model": "llama", "UpdatedAt": "2026-11-02"},
            {**gk, "Endpoint": "openai https://gpu/v1 llama", "Kind": "review", "UpdatedAt": "2026-11-02"}]
    est = lq.Estimator(rows)
    cpu = est.job({"Kind": "review", "Model": "qwen", "InputChars": 8000})
    assert cpu["in"] == 2000 and cpu["out"] == 200 and cpu["seconds"] == pytest.approx(2200 / 12)
    gpu = est.job({"Kind": "review", "Model": "llama", "InputChars": 8000})
    assert gpu["in"] == 2000 and gpu["out"] == 500 and gpu["seconds"] == pytest.approx(2000 / 500 + 500 / 50)
    # a model nothing was learned on: the newest endpoint's figures
    other = est.job({"Kind": "review", "Model": "new-model", "InputChars": 8000})
    assert other["basis"]["Model"] == "llama"
    # a kind with no history: the default output length
    assert est.job({"Kind": "refactor", "Model": "qwen", "InputChars": 8000})["out"] == lq.OUTPUT_TOKENS
    # the queue: sum over the parallel requests
    jobs = [{"Kind": "review", "Model": "qwen", "InputChars": 8000}] * 4
    assert est.queue(jobs, 1)["seconds"] == pytest.approx(4 * 2200 / 12)
    assert est.queue(jobs, 2)["seconds"] == pytest.approx(2 * 2200 / 12)
    assert est.queue(jobs, 2)["in"] == 8000 and est.queue([], 1)["seconds"] is None
    assert lq.Estimator([]).queue(jobs, 1)["seconds"] is None


def test_queue_totals_and_summary():
    now = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)               # a Monday, noon
    e, k = lq.observe(None, None, chars=4000, input_tokens=1000, output_tokens=200, seconds=100)
    speed = lq.Estimator([{**e, "Endpoint": "cpu", "Kind": "*", "Model": "qwen3:32b", "UpdatedAt": "1"},
                          {**k, "Endpoint": "cpu", "Kind": "review", "UpdatedAt": "1"}])
    job = {"Kind": "review", "Model": "qwen3:32b", "InputChars": 8000, "Status": "queued"}
    active = [{**job, "Reason": "uncertain"}] * 2 + [{**job, "Reason": "second-opinion"},
                                                     {**job, "Reason": "uncertain", "Status": "running"}]
    settings = {**lq.DEFAULTS, "Parallel": 3}
    t = admin_llmqueue.totals(active, speed, settings, now)
    assert t["waiting"] == 3 and t["running"] == 1 and t["by"] == {"Uncertain": 2, "Second opinion": 1}
    assert t["in"] == 6000 and t["out"] == 600
    assert t["seconds"] == pytest.approx(3 * 2200 / 12 / 3) and t["parallel"] == 3
    assert t["done"] == now + __import__("datetime").timedelta(seconds=t["seconds"]) and t["next_open"] == now
    assert t["basis"].startswith("learned from 1 answers on qwen3:32b")
    html = admin_llmqueue.summary_html(t, now)
    assert "<b>3 jobs waiting</b> (2 uncertain, 1 second opinion) · 1 running now" in html
    assert "~6,000 tokens in, ~600 tokens out" in html and "<b>~3 min of LLM time</b> (3 in parallel)" in html
    assert "all done around 2026-11-02 12:03 UTC" in html and "not included" in html
    # nothing learned yet; the hours start in the evening
    t = admin_llmqueue.totals(active, lq.Estimator([]), {**settings, "WindowStart": 22 * 60, "WindowEnd": 6 * 60}, now)
    html = admin_llmqueue.summary_html(t, now)
    assert t["seconds"] is None and t["done"] is None and "Time: learning" in html and "Learning: no answers yet" in html
    assert "The hours next allow it from 2026-11-02 22:00 UTC." in html
    assert lq.next_open({**settings, "Paused": True}, now) is None
    assert "Nothing is waiting" in admin_llmqueue.summary_html(admin_llmqueue.totals([], speed, settings, now), now)
    assert lq.duration_long(7 * 3600 + 20 * 60) == "7 h 20 min" and lq.duration_long(20) == "under a minute"
    assert lq.duration_long(3600) == "1 h" and lq.duration_long(45 * 60) == "45 min"


def test_queue_gauges():
    from containerizer.metrics import Registry
    e, k = lq.observe(None, None, chars=4000, input_tokens=1000, output_tokens=200, seconds=100)
    conn = FakeConn({r"GROUP BY Status, Kind": [{"Status": "queued", "Kind": "review", "Reason": "uncertain", "N": 2}],
                     r"MIN\(QueuedAt\)": [{"Kind": "review", "Age": 600}],
                     r"SELECT Kind, Model, InputChars": [{"Kind": "review", "Model": "q", "InputChars": 8000}] * 2,
                     r"FROM cz.LlmSpeed": [{**e, "Endpoint": "cpu", "Kind": "*", "Model": "q", "UpdatedAt": "1"},
                                           {**k, "Endpoint": "cpu", "Kind": "review", "UpdatedAt": "1"}],
                     r"FROM cz.LlmQueueSettings": [{**lq.DEFAULTS, "Parallel": 2}]})
    r = Registry()
    g = lq.QueueGauges(r)
    g.refresh(conn)
    text = r.render()
    assert 'containerizer_llm_queue_jobs{status="queued",kind="review",reason="uncertain"} 2' in text
    assert 'containerizer_llm_queue_oldest_waiting_seconds{kind="review"} 600' in text
    assert 'containerizer_llm_queue_estimated_tokens{kind="review",direction="in"} 4000' in text
    assert f"containerizer_llm_queue_estimated_seconds {2 * 2200 / 12 / 2}" in text or \
        "containerizer_llm_queue_estimated_seconds 183.3" in text


def test_page_texts():
    r = {"Status": "answered", "InputTokens": 9812, "OutputTokens": 1204, "Seconds": 240, "EstInputTokens": 10000}
    assert admin_llmqueue.actual(r) == "9,812 in / 1,204 out tokens in 4 min (estimated ~10,000 in)"


# --------------------------------------------------------------------------- the admin page

@pytest.fixture
def adm():
    pytest.importorskip("jwt")
    from containerizer import admin as adminmod
    from containerizer.oidc import OidcConfig
    c = OidcConfig(issuer="https://idp.example.com", client_id="cz", client_secret="s", public_url="https://cz.example.com",
                   admins=["group:a"])
    conn = FakeConn()
    a = adminmod.Admin(c, lambda: conn, provider=object())
    a.route_scans = lambda *x, **k: None
    a.conn = conn
    return a


QUEUED = [{"JobId": 1, "Kind": "review", "Reason": "uncertain", "Status": "queued", "Priority": 1500, "AdminRank": None,
           "Repository": "Billing/api", "Component": "Api", "RuleVerdict": "refactor", "Confidence": 0.7,
           "Model": "qwen", "InputChars": 7000, "EstInputTokens": 2000, "RequestedBy": "scan Acme",
           "QueuedAt": datetime(2026, 11, 1, 2, 0), "StartedAt": None, "NotBefore": None, "Error": None, "Runner": None},
          {"JobId": 2, "Kind": "review", "Reason": "second-opinion", "Status": "queued", "Priority": 400, "AdminRank": None,
           "Repository": "Billing/web", "Component": "Web", "RuleVerdict": "blocker", "Confidence": 0.95,
           "Model": "qwen", "InputChars": 3500, "EstInputTokens": 1000, "RequestedBy": "scan Acme",
           "QueuedAt": datetime(2026, 11, 1, 2, 1), "StartedAt": None, "NotBefore": None, "Error": None, "Runner": None}]
ANSWERED = [{"JobId": 3, "Kind": "review", "Reason": "uncertain", "Status": "answered", "Priority": 1200, "AdminRank": None,
             "Repository": "Billing/old", "Component": "Old", "RuleVerdict": "rewrite", "Confidence": 0.6, "Model": "qwen",
             "Summary": "config (0.80)", "InputTokens": 900, "OutputTokens": 300, "Seconds": 300, "EstInputTokens": 1000,
             "FinishedAt": datetime(2026, 11, 1, 3, 0), "QueuedAt": datetime(2026, 11, 1, 1, 0), "Error": None, "Note": None}]


def _get(adm, sid, path):
    return adm.handle("GET", path, "" if "?" not in path else path.split("?", 1)[1],
                      {"Cookie": f"{adm.cookie}={sid}"}, b"")


def _post(adm, sid, path, **form):
    s = adm.sessions.get(sid)
    return adm.handle("POST", path, "", {"Cookie": f"{adm.cookie}={sid}"},
                      urlencode({"csrf": s.csrf, **form}, doseq=True).encode())


def test_admin_page_gate_and_listing(adm):
    adm.conn.answers = {r"FROM cz.LlmQueueSettings": [dict(lq.DEFAULTS)],
                        r"FROM cz.LlmSpeed": [],
                        r"COUNT\(\*\) FROM cz.OrgScanRun": [{"N": 0}],
                        r"Status IN \(N'approval', N'queued', N'running'\)\s+ORDER BY": QUEUED,
                        r"FROM cz.LlmJob WHERE Status IN \(N'approval', N'queued', N'running'\)": QUEUED,
                        r"Status IN \(N'answered', N'failed', N'skipped'\)": ANSWERED,
                        r"JOIN cz.OrgRepository r": [{"RepositoryId": 9, "Repository": "Billing/old", "Answered": 1,
                                                      "LastAnswer": datetime(2026, 11, 1, 3, 0), "LastScannedAt": None}]}
    viewer = adm.sessions.create("v@example.com", "V", False, True)
    assert _get(adm, viewer, "/admin/llm-queue").status == 403
    operator = adm.sessions.create("o@example.com", "O", False, True, True, [])
    r = _get(adm, operator, "/admin/llm-queue")
    assert r.status == 200, r.body
    assert "Billing/api / Api" in r.body and "Second opinion" in r.body and "rules: blocker" in r.body
    assert "~2,000 in / ~1,500 out tokens · time: learning" in r.body
    assert "<b>2 jobs waiting</b> (1 uncertain, 1 second opinion)" in r.body
    assert "~3,000 tokens in, ~3,000 tokens out" in r.body and "Learning: no answers yet" in r.body
    assert r.body.index("2 jobs waiting") < r.body.index("<h2 id='queue'>Queue</h2>")  # the summary is above the list
    assert "config (0.80)" in r.body and "900 in / 300 out tokens in 5 min (estimated ~1,000 in)" in r.body
    assert "Re-scan now" in r.body and "value='9'" in r.body and "All kinds" in r.body
    assert "/admin/llm-queue/2/up" in r.body and "/admin/llm-queue/1/up" not in r.body   # the first cannot go up
    assert re.findall(r"<script[^>]*>", r.body) == ["<script src='/static/app.js'>"]    # no inline script
    assert ("llm-queue", "LLM queue") in adm._tabs(adm.sessions.get(operator), __import__(
        "containerizer.roles", fromlist=["Access"]).Access(False, True))


def test_admin_page_actions(adm):
    a = adm.sessions.create("a@example.com", "A", True)
    adm.conn.answers = {r"SELECT j.JobId, j.Priority, j.AdminRank, h.EndsAt AS HeavyUntil FROM cz.LlmJob": QUEUED,
                        r"FROM cz.OrgRepository WHERE RemovedAt IS NULL AND RepositoryId IN": [
                            {"ScanId": 4, "Name": "Billing/old"}],
                        r"EXEC cz.QueueOrgScanRun": [{"RunId": 12}]}
    r = _post(adm, a, "/admin/llm-queue/2/up")
    assert r.status == 303 and "moved+up" in dict(r.headers)["Location"]
    ups = adm.conn.sql(r"UPDATE cz.LlmJob SET AdminRank")
    assert {p[1] for _, p in ups} == {1, 2} and dict((p[1], p[0]) for _, p in ups)[2] > dict((p[1], p[0]) for _, p in ups)[1]
    r = _post(adm, a, "/admin/llm-queue/5/top")
    assert "no+longer+queued" in dict(r.headers)["Location"]
    r = _post(adm, a, "/admin/llm-queue/2/skip", at="job-3")
    assert adm.conn.sql(r"SET Status = N'skipped'.*Status = N'queued'")[-1][1] == (2,)
    assert dict(r.headers)["Location"].endswith("#job-3")             # the page opens at the next row, not the top
    r = _post(adm, a, "/admin/llm-queue/2/down", at="job-2")
    assert dict(r.headers)["Location"].endswith("#job-2")
    r = _post(adm, a, "/admin/llm-queue/2/skip", at="javascript:alert(1)")
    assert "#" not in dict(r.headers)["Location"]                        # only a row or the queue
    _post(adm, a, "/admin/llm-queue/3/requeue")
    sql, params = adm.conn.sql(r"SET Status = N'queued', Attempts = 0")[-1]
    assert params == (3,) and "QueuedAt = SYSUTCDATETIME()" in sql      # its wait starts again
    r = _post(adm, a, "/admin/llm-queue/rescan", RepositoryId="9")
    assert r.status == 303 and "%2312" in dict(r.headers)["Location"]
    (sql, params), = adm.conn.sql(r"EXEC cz.QueueOrgScanRun")
    assert params[0] == 4 and json.loads(params[1]) == {"projects": [], "repositories": ["Billing/old"]}
    r = _post(adm, a, "/admin/llm-queue/settings", day=["5", "6"], From="22:00", To="06:00", OnlyWhenIdle="1",
              MaxLoadPerCpu="0.5", Parallel="2", JobsAtOnce="4")
    assert "Saved" in dict(r.headers)["Location"]
    (sql, params), = adm.conn.sql(r"UPDATE cz.LlmQueueSettings")
    assert params == (False, 96, 1320, 360, True, 0.5, 2, None, 0, 0, 0, None, 0, 4)  # no approval; 4 jobs at once
    assert "JobsAtOnce = %s" in sql
    r = _post(adm, a, "/admin/llm-queue/settings", From="22:00")
    assert "both" in dict(r.headers)["Location"] and len(adm.conn.sql(r"UPDATE cz.LlmQueueSettings")) == 1
    # the form needs the session's CSRF token
    r = adm.handle("POST", "/admin/llm-queue/2/skip", "", {"Cookie": f"{adm.cookie}={a}"}, b"csrf=wrong")
    assert r.status == 403


def test_results_page_shows_the_review():
    from containerizer import webui
    r = {"Status": "answered", "Verdict": "config", "LlmConfidence": 0.8, "Reasoning": "the COM call is never reached",
         "FinishedAt": datetime(2026, 11, 2), "QueuedAt": datetime(2026, 11, 1)}
    html = webui._llm_review(r, datetime(2026, 11, 1, 12))
    assert "LLM review answered" in html and "(0.80)" in html and "next scan applies it" in html
    assert "LLM review queued" in webui._llm_review({"Status": "queued"}, None)
    assert webui._llm_review({"Status": "failed"}, None) == "" and webui._llm_review(None, None) == ""


# --------------------------------------------------------------------------- SQL Server

ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")
needs_sql = pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")


@needs_sql
def test_queue_in_sql_server(tmp_path, llm):
    """cz.QueueLlmJob dedupes and supersedes, the writer login runs the queue, the admin login reorders it,
    and the changes are in the audit log."""
    import uuid
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czllmq_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    for login, role in (("cz_q_writer", "writer"), ("cz_q_admin", "admin")):
        sqlstore.create_login(conn, login, pw, role)
    conn.close()

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    writer = lambda: sqlstore.connect(as_("cz_q_writer"), pw)  # noqa: E731
    q = lq.SqlJobQueue(writer)
    assess.apply_ai(app(comp("Api"), comp("Legacy", confidence=0.95, verdict="blocker")), queue=q)
    assess.apply_ai(app(comp("Api")), queue=q)                          # the same question: not twice
    c = writer()
    cur = c.cursor(as_dict=True)
    cur.execute("SELECT JobId, Component, Reason, Status, RequestedBy, EstInputTokens FROM cz.LlmJob ORDER BY JobId")
    rows = cur.fetchall()
    # approval is on for every job by default (schema 22): both wait until an administrator approves them
    assert [(r["Component"], r["Reason"], r["Status"]) for r in rows] == [("Api", "uncertain", "approval"),
                                                                          ("Legacy", "second-opinion", "approval")]
    assert rows[0]["EstInputTokens"] > 0
    c.close()
    m = lq.QueueMetrics("t")
    try:
        r = lq.Runner(writer, name="t", metrics=m, poll=1, log=lambda msg: None, load=lambda: 0.0)
        assert r.run(once=True) == 0                                    # nothing approved yet
        adm = sqlstore.connect(as_("cz_q_admin"), pw)
        cur = adm.cursor()
        cur.execute("UPDATE cz.LlmJob SET Status = N'queued', ApprovedBy = N'alice@example.com', "
                    "ApprovedAt = SYSUTCDATETIME() WHERE Status = N'approval'")
        assert cur.rowcount == 2
        adm.commit()
        adm.close()
        assert r.run(once=True) == 2
    finally:
        ai.LISTENERS.remove(m.llm)
    assert len(llm) == 2 and q.result("review", ai.cache_key("review shop/Api", ai.REVIEW_SCHEMA))["verdict"] == "info"
    c = sqlstore.connect(as_("cz_q_admin"), pw)
    cur = c.cursor(as_dict=True)
    cur.execute("SELECT COUNT(*) AS N FROM cz.AuditLog WHERE TableName = N'LlmJob'")
    assert cur.fetchone()["N"] >= 4                                  # two queued, two answered
    cur.execute("SELECT * FROM cz.LlmSpeed")
    assert {x["Kind"] for x in cur.fetchall()} == {"*", "review"}
    c.close()


def test_runner_uses_the_built_in_llm_when_none_is_registered(tmp_path, monkeypatch):
    import json as _json
    from pathlib import Path as _Path
    from containerizer import credentials, local_llm
    status = tmp_path / "local-llm-status.json"
    status.write_text(_json.dumps({"enabled": True, "state": "running"}))
    monkeypatch.setenv(local_llm.STATUS_ENV, str(status))
    monkeypatch.delenv(credentials.PRIVATE_KEY_ENV, raising=False)
    runner = object.__new__(lq.Runner)
    runner.key, runner.log = None, lambda msg: None
    s = lq.Runner.llm_settings(runner, conn=None)
    assert s["CONTAINERIZER_LLM_BASE_URL"] == "http://127.0.0.1:8090/v1" and s["CONTAINERIZER_MODEL"] == local_llm.MODEL.alias
    status.write_text(_json.dumps({"enabled": False, "state": "off"}))
    assert lq.Runner.llm_settings(runner, conn=None) is None          # the environment's
    unit = (_Path(__file__).resolve().parent.parent / "appliance/rootfs/usr/lib/systemd/system/"
            "containerizer-llm-queue.service").read_text()
    assert "CONTAINERIZER_LOCAL_LLM=/run/containerizer/system/local-llm-status.json" in unit


@needs_sql
def test_approval_rules_in_sql_server():
    """Approval for every kind, automatic approval of small jobs while the queue has room (cz.QueueLlmJob,
    cz.AutoApproveLlmJobs), and the upgrade that adds link and egress reviews to the default policy."""
    import uuid
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czappr_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    for login, role in (("cz_a_writer", "writer"), ("cz_a_admin", "admin")):
        sqlstore.create_login(conn, login, pw, role)

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    try:
        cur = conn.cursor()
        cur.execute("SELECT ApproveKinds FROM cz.LlmQueueSettings")
        assert cur.fetchone()[0] == "egress,link,refactor,review"         # a new install: every kind waits
        adm = sqlstore.connect(as_("cz_a_admin"), pw)
        adm.cursor().execute("UPDATE cz.LlmQueueSettings SET ApproveKinds = N'link,review', ApproveMinTokens = 1000, "
                             "ApproveMaxQueued = 2")
        adm.commit()
        w = sqlstore.connect(as_("cz_a_writer"), pw)
        wc = w.cursor()

        def queue(kind, prio, tokens):
            wc.execute("EXEC cz.QueueLlmJob @Kind = %s, @Priority = %s, @DedupeKey = %s, @EstInputTokens = %s, "
                       "@Payload = N'{}'", (kind, prio, uuid.uuid4().hex, tokens))
            jid = wc.fetchone()[0]
            w.commit()
            return jid

        def status(jid):
            wc.execute("SELECT Status, ApprovedBy FROM cz.LlmJob WHERE JobId = %s", (jid,))
            return tuple(wc.fetchone())
        small1, small2 = queue("review", 10, 100), queue("review", 9, 100)
        link_small = queue("link", 8, 100)        # small, but the queue already has 2
        big = queue("review", 50, 5000)           # over the size limit: always an administrator
        egress = queue("egress", 1, 99999)        # egress needs no approval here: starts at once, whatever its size
        assert [status(j)[0] for j in (small1, small2, link_small, big, egress)] == \
            ["queued", "queued", "approval", "approval", "queued"]
        # two answered: room for one more, the small link review (the big one still waits for an administrator)
        wc.execute("UPDATE cz.LlmJob SET Status = N'answered', FinishedAt = SYSUTCDATETIME() WHERE JobId IN (%s, %s)",
                   (small1, small2))
        w.commit()
        assert lq.auto_approve(w) == 1
        assert status(link_small) == ("queued", "automatic: estimated under 1,000 tokens and the queue had room")
        assert status(big)[0] == "approval" and lq.auto_approve(w) == 0
        # component reviews need no approval any more: the big one waiting is let go too
        adm.cursor().execute("UPDATE cz.LlmQueueSettings SET ApproveKinds = N'link'")
        adm.commit()
        assert lq.auto_approve(adm) == 1 and status(big) == ("queued", "automatic: its kind needs no approval")
        # jobs that waited too long are rejected; a running one never, an approved one counts from its approval
        w2 = sqlstore.connect(as_("cz_a_writer"), pw)
        c2 = w2.cursor()
        old_q, fresh = queue("review", 3, 100), queue("review", 2, 100)
        c2.execute("UPDATE cz.LlmJob SET Status = N'running' WHERE JobId = %s", (big,))
        w2.commit()
        conn.cursor().execute("UPDATE cz.LlmJob SET QueuedAt = DATEADD(hour, -30, SYSUTCDATETIME()), ApprovedAt = NULL "
                              "WHERE JobId IN (%s, %s); UPDATE cz.LlmJob SET QueuedAt = DATEADD(hour, -30, SYSUTCDATETIME()) "
                              "WHERE JobId = %s", (old_q, big, link_small))
        conn.commit()
        assert lq.auto_reject(w2) == 0                                  # off by default
        adm.cursor().execute("UPDATE cz.LlmQueueSettings SET RejectAfterHours = 24")
        adm.commit()
        assert lq.apply_rules(w2)[1] == 1
        assert status(old_q)[0] == "skipped" and status(fresh)[0] != "skipped"
        assert status(big)[0] == "running" and status(link_small)[0] == "queued"     # approved a moment ago
        c2.execute("SELECT Note FROM cz.LlmJob WHERE JobId = %s", (old_q,))
        assert c2.fetchone()[0] == "rejected automatically: waited more than 24 hours"
        # approved long ago, queued again since (Requeue, or the runner put it back): its wait starts again; before,
        # it was rejected at once (the lab's product-returns, after a restart, and its Requeue)
        conn.cursor().execute("UPDATE cz.LlmJob SET ApprovedAt = DATEADD(hour, -30, SYSUTCDATETIME()), "
                              "QueuedAt = SYSUTCDATETIME() WHERE JobId = %s", (link_small,))
        conn.commit()
        assert lq.auto_reject(w2) == 0 and status(link_small)[0] == "queued"
        # the runner (the writer login) restarts the wait of a job it puts back in the queue
        c2.execute("UPDATE cz.LlmJob SET QueuedAt = SYSUTCDATETIME() WHERE JobId = %s", (big,))
        w2.commit()
        adm.cursor().execute("UPDATE cz.LlmQueueSettings SET RejectAfterHours = 1")
        adm.commit()
        conn.cursor().execute("UPDATE cz.LlmJob SET QueuedAt = DATEADD(hour, -2, SYSUTCDATETIME()), ApprovedAt = NULL "
                              "WHERE JobId = %s", (fresh,))
        conn.commit()
        assert lq.auto_reject(w2) == 1
        c2.execute("SELECT Note FROM cz.LlmJob WHERE JobId = %s", (fresh,))
        assert c2.fetchone()[0] == "rejected automatically: waited more than 1 hour"
        w2.close()
        adm.close()
        w.close()
        # the upgrade: settings still at the old default get link and egress reviews; changed ones are kept
        cur.execute("UPDATE cz.LlmQueueSettings SET ApproveKinds = N'refactor,review'; "
                    "DELETE cz.SchemaVersion WHERE Version = 29")
        conn.commit()
        sqlstore.init_schema(conn)
        cur.execute("SELECT ApproveKinds FROM cz.LlmQueueSettings")
        assert cur.fetchone()[0] == "egress,link,refactor,review"
        cur.execute("SELECT COUNT(*) FROM cz.AuditLog WHERE TableName = N'LlmQueueSettings' AND NewValues LIKE N'%ApproveMaxQueued%'")
        assert cur.fetchone()[0] >= 1
    finally:
        conn.close()
        m = sqlstore.connect(re.sub(r"(?i)Database=\w+", "Database=master", cs), sa_pw, autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.close()


# --------------------------------------------------------------------------- several LLMs at once

def _llm(cid, order, max_tokens=0, parallel=1, model="m"):
    from containerizer.credentials import Credential
    return Credential(id=cid, purpose="llm", provider="openai", api_url=f"http://llm{cid}.example.com/v1", scope="llm",
                      model=model, llm_order=order, llm_max_tokens=max_tokens, llm_parallel=parallel, token="")


BUILTIN = {"CONTAINERIZER_AI_BACKEND": "openai", "CONTAINERIZER_LLM_BASE_URL": "http://127.0.0.1:8090/v1",
           "CONTAINERIZER_MODEL": "qwen3-coder-30b-a3b"}


SERVERS = [{"index": 0, "node": 0, "ready": True, "settings": BUILTIN},          # two NUMA nodes
           {"index": 1, "node": 1, "ready": True, "settings": {**BUILTIN, "CONTAINERIZER_LLM_BASE_URL": "http://127.0.0.1:8091/v1"}}]


def test_lanes_follow_the_order_sizes_and_requests_at_once():
    gpu, cpu = _llm(1, 30, 0, 4, "big"), _llm(2, 20, 15000, 1, "small")
    lanes = lq.plan_lanes([cpu, gpu], SERVERS, {"LocalOrder": 10, "LocalMaxTokens": 4000})
    assert [(ln["name"], ln["max_tokens"], ln["parallel"]) for ln in lanes] == \
        [("built-in-0", 4000, 1), ("built-in-1", 4000, 1), ("llm-2", 15000, 1), ("llm-1", 0, 4)]
    assert lanes[2]["settings"]["CONTAINERIZER_MODEL"] == "small"
    assert lanes[1]["settings"]["CONTAINERIZER_LLM_BASE_URL"] == "http://127.0.0.1:8091/v1"
    # no place in the order: the built-in LLM is not used beside registered ones (as before)
    assert [ln["name"] for ln in lq.plan_lanes([gpu], SERVERS, {})] == ["llm-1"]
    # alone, it takes every job, Parallel shared out between its servers
    assert [(ln["max_tokens"], ln["parallel"]) for ln in lq.plan_lanes([], SERVERS[:1], {"Parallel": 3})] == [(0, 3)]
    assert [ln["parallel"] for ln in lq.plan_lanes([], SERVERS, {"Parallel": 3})] == [2, 2]
    assert lq.plan_lanes([], None, {"Parallel": 2})[0] | {"label": ""} == {
        "name": "environment", "label": "", "settings": None, "max_tokens": 0, "parallel": 2, "order": 0}


def _fill_runner(monkeypatch, lanes, jobs, settings=None, conn=None):
    """A runner whose fill sees `lanes` and claims `jobs` in their order (the size limit as cz.LlmJob's claim)."""
    conn = conn or FakeConn()
    r = lq.Runner(lambda: conn, name="r1", metrics=lq.QueueMetrics("r1"), log=lambda msg: None, load=lambda: 0.0)
    monkeypatch.setattr(lq, "apply_rules", lambda conn: (0, 0))
    monkeypatch.setattr(lq, "load_settings", lambda conn: dict(lq.DEFAULTS, OnlyWhenIdle=False, **(settings or {})))
    monkeypatch.setattr(lq, "scans_running", lambda conn: 0)
    monkeypatch.setattr(r, "lanes", lambda conn, settings: lanes)
    monkeypatch.setattr(r, "_enter_llm", lambda conn: None)
    r.limits = []

    def claim(conn, max_tokens=None, min_tokens=None):
        r.limits.append(max_tokens)
        for j in jobs:
            if max_tokens is None or int(j.get("EstInputTokens") or 0) <= max_tokens:
                jobs.remove(j)
                return dict(j)
        return None
    monkeypatch.setattr(r, "claim", claim)
    return r


def test_fill_starts_jobs_in_order_while_an_llm_takes_them_and_job_slots_are_free(monkeypatch):
    jobs = [{"JobId": 1, "Kind": "review", "EstInputTokens": 20000}, {"JobId": 2, "Kind": "review", "EstInputTokens": 3000},
            {"JobId": 3, "Kind": "review", "EstInputTokens": 9000}, {"JobId": 4, "Kind": "review", "EstInputTokens": 2000},
            {"JobId": 5, "Kind": "review", "EstInputTokens": 50000}, {"JobId": 6, "Kind": "refactor", "EstInputTokens": 0},
            {"JobId": 7, "Kind": "refactor", "EstInputTokens": 0}]
    lanes = [{"name": "built-in", "settings": BUILTIN, "max_tokens": 4000, "parallel": 1, "order": 10},
             {"name": "llm-2", "settings": {"CONTAINERIZER_MODEL": "small"}, "max_tokens": 15000, "parallel": 1, "order": 20},
             {"name": "llm-1", "settings": {"CONTAINERIZER_MODEL": "big"}, "max_tokens": 0, "parallel": 2, "order": 30}]
    r = _fill_runner(monkeypatch, lanes, jobs)
    try:
        submitted = []
        pool = SimpleNamespace(submit=lambda fn, row: submitted.append(row) or row)
        r.fill(pool)
        # 4 LLM requests at once: 5 jobs at once (automatic). Jobs in the queue's order, each with its own LLM (the
        # first free one that takes its size); once every request is spoken for, only a job without LLM work starts
        assert [(x["JobId"], x["_lane"]) for x in submitted] == [(1, "llm-1"), (2, "built-in"), (3, "llm-2"),
                                                                 (4, "llm-1"), (6, "built-in")]
        assert r.limits == [None, None, None, None, 0]
        assert [x["JobId"] for x in jobs] == [5, 7]                    # no LLM free for 5; no job slot left for 7
        assert submitted[1]["_llm"] is BUILTIN and submitted[2]["_parallel"] == 1 and submitted[0]["_calls"] == []
        assert r.metrics.llm_jobs._values == {("built-in", "built-in"): 0, ("llm-2", "llm-2"): 0, ("llm-1", "llm-1"): 0}
        assert all(x.get("_reserve_until") for x in submitted[:4]) and not submitted[4].get("_reserve_until")
        # the setting: 2 jobs at once
        jobs[:] = [{"JobId": 8, "Kind": "refactor", "EstInputTokens": 0}, {"JobId": 9, "Kind": "refactor", "EstInputTokens": 0},
                   {"JobId": 10, "Kind": "review", "EstInputTokens": 10}]
        r2 = _fill_runner(monkeypatch, lanes, jobs, {"JobsAtOnce": 2})
        try:
            submitted.clear()
            r2.fill(pool)
            assert [x["JobId"] for x in submitted] == [8, 9]
        finally:
            ai.LISTENERS.remove(r2.metrics.llm)
    finally:
        ai.LISTENERS.remove(r.metrics.llm)


def test_jobs_at_once_default():
    lanes = [{"name": "built-in-0", "parallel": 1}, {"name": "built-in-1", "parallel": 1}]
    assert lq.jobs_at_once(lq.DEFAULTS, lanes) == 3                 # every LLM request at once, plus one
    assert lq.jobs_at_once({"JobsAtOnce": 5}, lanes) == 5
    assert lq.jobs_at_once({}, [{"name": "built-in-0", "parallel": 0}]) == 2       # loading its model: still a job
    assert lq.jobs_at_once({}, [{"name": "llm-1", "parallel": 40}]) == lq.JOBS_AT_ONCE_MAX


SMALL = {"name": "small", "label": "small LLM", "settings": {"CONTAINERIZER_MODEL": "small"}, "max_tokens": 4000,
         "parallel": 1, "order": 10}
BIG = {"name": "big", "label": "big LLM", "settings": {"CONTAINERIZER_MODEL": "big"}, "max_tokens": 0, "parallel": 1,
       "order": 20}


def test_each_call_goes_to_the_first_free_llm_that_takes_its_size():
    s = lq.Slots()
    s.update([SMALL, BIG])
    assert [ln["name"] for ln in s.candidates(3000)] == ["small", "big"]
    assert [ln["name"] for ln in s.candidates(10000)] == ["big"]
    assert s.acquire(1, 10000)["name"] == "big"                     # too big for the small one, even while it is free
    assert s.acquire(2, 3000)["name"] == "small"
    assert s.in_progress() == {"big": 1, "small": 1} and s.spare() == {"small": 0, "big": 0}
    s.release(BIG)
    s.release(SMALL)
    assert s.acquire(3, 2000)["name"] == "small" and s.acquire(4, 2000)["name"] == "big"   # the small one busy
    # every LLM has a limit and the call is bigger than all of them: the one with the biggest limit
    s.update([SMALL, {**BIG, "max_tokens": 8000}])
    assert [ln["name"] for ln in s.candidates(50000)] == ["big"]
    # an LLM still loading its model (no request at once) takes no call
    s.update([{**SMALL, "parallel": 0}, BIG])
    assert [ln["name"] for ln in s.candidates(10)] == ["big"]
    assert s.spare([10]) == {"small": -1, "big": 0}     # both in use (calls 3 and 4): nothing spare for a new job


def test_calls_that_wait_are_answered_in_the_queues_order():
    import threading
    s = lq.Slots()
    s.update([SMALL])
    first = s.acquire(1, 100)
    got, waits = [], []

    def call(order):
        ln = s.acquire(order, 100, on_wait=lambda: waits.append(order))
        got.append(order)
        s.release(ln)
    late = threading.Thread(target=call, args=(9,))
    late.start()
    while s.waiting_calls() < 1:
        pass
    early = threading.Thread(target=call, args=(3,))              # started later, but its job is older
    early.start()
    while s.waiting_calls() < 2:
        pass
    s.release(first)
    late.join(5)
    early.join(5)
    assert got == [3, 9] and sorted(waits) == [3, 9] and s.waiting_calls() == 0 and s.in_progress() == {"small": 0}


def test_a_waiting_call_gives_up_on_cancel_and_leaves_no_slot_behind():
    s = lq.Slots()
    s.update([SMALL])
    held = s.acquire(1, 100)
    stop = {"n": 0}

    def check():
        stop["n"] += 1
        if stop["n"] >= 2:
            raise ai.Cancelled("cancelled")
    with pytest.raises(ai.Cancelled):
        s.acquire(2, 100, check)
    assert s.waiting_calls() == 0 and s.in_progress() == {"small": 1}
    s.release(held)
    assert s.in_progress() == {"small": 0}


def _api_answers(monkeypatch, tmp_path, answer=None):
    """A fake Claude API that tells which model (LLM) answered; the answer cache in tmp_path."""
    monkeypatch.setattr(ai, "CACHE", tmp_path / "cache")
    asked = []

    def ask(prompt, schema, model, effort, system):
        asked.append((prompt, model))
        if answer:
            answer(prompt, model)
        return ({"verdict": "info", "confidence": 0.9, "reasoning": "r", "findings": [], "packages": []},
                {"input_tokens": 1000, "output_tokens": 200, "prompt_seconds": 1.0, "generate_seconds": 4.0})
    monkeypatch.setattr(ai, "_ask_api", ask)
    return asked


API = {"CONTAINERIZER_AI_BACKEND": "api", "ANTHROPIC_API_KEY": "k"}


def test_a_job_takes_an_llm_request_only_while_its_call_is_answered(monkeypatch, tmp_path):
    """Two lanes of one request each; two jobs that asked once and then build (no LLM) do not keep a third job from
    asking: before, each held its lane until it finished."""
    import threading
    from concurrent.futures import ThreadPoolExecutor
    import time
    asked = _api_answers(monkeypatch, tmp_path)
    lanes = [{**SMALL, "max_tokens": 0, "settings": {**API, "CONTAINERIZER_MODEL": "m-a"}},
             {**BIG, "settings": {**API, "CONTAINERIZER_MODEL": "m-b"}}]
    built = threading.Event()
    building = []

    def make_it_a(job):                                  # asks once, then builds and verifies for a long time
        ai.ask_json(f"file of {job['JobId']}", ai.REVIEW_SCHEMA)
        building.append(job["JobId"])
        assert built.wait(10)
        return {"result": {}, "summary": "verified"}
    monkeypatch.setitem(lq.JOB_KINDS, "refactor", SimpleNamespace(name="refactor", feature="refactor-queued",
                                                                    handler=make_it_a))

    def review(job):                                     # asks once both others build
        while len(building) < 2:
            time.sleep(0.01)
        return lq.review_handler(job)
    monkeypatch.setitem(lq.JOB_KINDS, "review", SimpleNamespace(name="review", feature="assessment-queued",
                                                                  handler=review))
    jobs = [{"JobId": 1, "Kind": "refactor", "EstInputTokens": 0, "Attempts": 1, "Payload": "{}"},
            {"JobId": 2, "Kind": "refactor", "EstInputTokens": 0, "Attempts": 1, "Payload": "{}"},
            {"JobId": 3, "Kind": "review", "EstInputTokens": 3000, "Attempts": 1, "InputChars": 10500,
             "Payload": json.dumps({"prompt": "review shop/Api"})}]
    conn = FakeConn({r"SELECT \* FROM cz.LlmSpeed": []})
    r = _fill_runner(monkeypatch, lanes, jobs, conn=conn)
    pool = ThreadPoolExecutor(4)
    try:
        started = r.fill(pool)
        assert [x["JobId"] for x in r.active.values()] == [1, 2, 3]       # 3 jobs at once: 2 requests + 1
        assert started[2].result(10) == "answered"                       # the review asked while the others build
        assert sorted(building) == [1, 2] and not started[0].done() and not started[1].done()
        assert not any(r.slots.in_progress().values())                    # nobody holds an LLM while building
        assert len(asked) == 3 and asked[-1] == ("review shop/Api", "m-a")    # both LLMs free: the first
        built.set()
        assert [f.result(10) for f in started[:2]] == ["answered", "answered"]
    finally:
        built.set()
        pool.shutdown(wait=True)
        ai.LISTENERS.remove(r.metrics.llm)
    # the page sees each call: asking, then nothing (the job builds)
    states = [p[0] for _, p in conn.sql(r"SET CallState = %s") if p[3] == 3]
    assert states == [None, "asking", None]
    (sql, params), = [x for x in conn.sql(r"SET Status = N'answered'") if x[1][-2] == 3]
    assert params[6] == "api m-a" and params[7] == 1                  # the endpoint that answered, 1 request on it
    assert [p[1] for _, p in conn.sql(r"INSERT cz.LlmSpeed") if p[1] == "review"] == ["review"]


def test_an_llm_job_waiting_for_a_request_does_not_keep_other_jobs_from_starting(monkeypatch, tmp_path):
    import threading
    from concurrent.futures import ThreadPoolExecutor
    inside, go = threading.Event(), threading.Event()

    def slow(prompt, model):
        if prompt == "review first":
            inside.set()
            assert go.wait(10)
    _api_answers(monkeypatch, tmp_path, slow)
    lanes = [{**BIG, "settings": {**API, "CONTAINERIZER_MODEL": "m"}}]          # one LLM, one request at once
    jobs = [{"JobId": 1, "Kind": "review", "EstInputTokens": 3000, "Attempts": 1, "Payload": json.dumps({"prompt": "review first"})},
            {"JobId": 2, "Kind": "review", "EstInputTokens": 3000, "Attempts": 1, "Payload": json.dumps({"prompt": "review second"})},
            {"JobId": 3, "Kind": "refactor", "EstInputTokens": 0, "Attempts": 1, "Payload": "{}"}]
    ran = []
    monkeypatch.setitem(lq.JOB_KINDS, "refactor", SimpleNamespace(
        name="refactor", feature="refactor-queued", handler=lambda job: ran.append(job["JobId"]) or {"result": {}}))
    conn = FakeConn()
    r = _fill_runner(monkeypatch, lanes, jobs, {"JobsAtOnce": 3}, conn=conn)
    pool = ThreadPoolExecutor(4)
    try:
        started = r.fill(pool)
        # job 1 will ask: the only request is spoken for; job 2 (LLM) waits in the queue, job 3 (no LLM) starts
        assert [x["JobId"] for x in r.active.values()][:1] == [1] and r.limits == [None, 0, 0]
        assert started[1].result(10) == "answered" and ran == [3] and [j["JobId"] for j in jobs] == [2]
        assert inside.wait(10)
        # while job 1 asks, the next job without LLM work starts too; job 2 still waits for the LLM in the queue
        jobs.append({"JobId": 4, "Kind": "refactor", "EstInputTokens": 0, "Attempts": 1, "Payload": "{}"})
        more = r.fill(pool)
        assert len(more) == 1 and more[0].result(10) == "answered" and ran == [3, 4]
        assert [j["JobId"] for j in jobs] == [2] and r.slots.in_progress() == {"big": 1}
        go.set()
        assert started[0].result(10) == "answered"
        # the LLM is free again: job 2 starts
        last = r.fill(pool)
        assert len(last) == 1 and last[0].result(10) == "answered" and jobs == []
    finally:
        go.set()
        pool.shutdown(wait=True)
        ai.LISTENERS.remove(r.metrics.llm)


def test_a_call_waits_for_a_request_and_gives_it_back_on_error_cancel_and_stop(monkeypatch, tmp_path):
    import threading
    _api_answers(monkeypatch, tmp_path)
    conn = FakeConn()
    r = lq.Runner(lambda: conn, name="r1", metrics=lq.QueueMetrics("r1"), log=lambda msg: None, load=lambda: 0.0)
    try:
        r.slots.update([{**BIG, "settings": {**API, "CONTAINERIZER_MODEL": "m"}}])
        row = {"JobId": 5, "Kind": "review", "_order": 1, "_calls": []}
        calls = lq._JobCalls(r, row)
        # an error inside the call: the request is given back, the call recorded, the page told
        with pytest.raises(RuntimeError):
            with calls.take(3500):
                assert r.slots.in_progress() == {"big": 1}
                raise RuntimeError("the LLM server went away")
        assert r.slots.in_progress() == {"big": 0} and len(row["_calls"]) == 1 and row["_calls"][0]["endpoint"] == "api m"
        assert [p[:2] for _, p in conn.sql(r"SET CallState")] == [("asking", "big LLM"), (None, None)]
        # waiting while another job asks; Cancel on the job: it gives up waiting
        held = r.slots.acquire(0, 10)
        with ai.cancel_thread_when(lambda: True), pytest.raises(ai.Cancelled):
            with calls.take(3500):
                pass
        assert [p[0] for _, p in conn.sql(r"SET CallState")][-1] == "waiting" and r.slots.waiting_calls() == 0
        # the runner stops: a job waiting for a request goes back to the queue, its attempt not counted
        out = {}
        monkeypatch.setitem(lq.JOB_KINDS, "review", SimpleNamespace(
            name="review", feature="assessment-queued", handler=lambda job: ai.ask_json("q", ai.REVIEW_SCHEMA)))
        t = threading.Thread(target=lambda: out.setdefault("r", r._run({"JobId": 6, "Kind": "review", "Attempts": 1,
                                                                        "Payload": "{}", "_order": 2, "_calls": []})))
        t.start()
        while r.slots.waiting_calls() < 1:
            pass
        r.stopping.set()
        t.join(10)
        assert out["r"] == "released" and r.slots.waiting_calls() == 0
        assert conn.sql(r"SET Status = N'queued', Runner = NULL.*Attempts - 1")[-1][1] == ("r1", 6)
        r.slots.release(held)
    finally:
        ai.LISTENERS.remove(r.metrics.llm)


def test_an_answer_in_the_cache_needs_no_llm_request(monkeypatch, tmp_path):
    asked = _api_answers(monkeypatch, tmp_path)
    lane = {**BIG, "settings": {**API, "CONTAINERIZER_MODEL": "m"}}
    s = lq.Slots()
    s.update([lane])
    took = []

    class Calls:
        def choices(self, chars):
            return [ln["settings"] for ln in s.candidates(lq.call_tokens(chars))]

        def take(self, chars):
            took.append(chars)
            import contextlib
            return contextlib.nullcontext(lane["settings"])
    with ai.llm_slots(Calls()):
        ai.ask_json("review shop/Api", ai.REVIEW_SCHEMA)
        key = ai.last_cache_key()
        ai.ask_json("review shop/Api", ai.REVIEW_SCHEMA)          # answered from the cache: no request taken
    assert len(asked) == 1 and len(took) == 1 and ai.last_cache_key() == key
    with ai.configured(lane["settings"]):
        assert ai.cache_key("review shop/Api", ai.REVIEW_SCHEMA) == key
    assert took[0] == len(ai.SYSTEM) + len("review shop/Api") + len(json.dumps(ai.REVIEW_SCHEMA))


def test_speed_is_learned_per_llm_from_the_calls_only():
    saved = []
    r = object.__new__(lq.Runner)
    r.log = lambda msg: None
    r.connect = lambda: FakeConn()
    import containerizer.llmqueue as mod
    orig = mod.save_speed
    mod.save_speed = lambda conn, ep, model, kind, obs: saved.append((ep, obs))
    try:
        entry = {"input_tokens": 1000, "output_tokens": 100, "prompt_seconds": 2.0, "generate_seconds": 8.0}
        row = {"Kind": "refactor", "_calls": [
            {"endpoint": "openai a m", "parallel": 1, "chars": 3500, "seconds": 10, "entries": [entry]},
            {"endpoint": "openai b m", "parallel": 2, "chars": 7000, "seconds": 30, "entries": [entry, entry]},
            {"endpoint": "openai a m", "parallel": 1, "chars": 3500, "seconds": 10, "entries": [entry]}]}
        used = lq._usage()
        used.entries = [entry] * 4
        r.learn(row, used, 3600)                          # an hour of building and verifying is not LLM time
    finally:
        mod.save_speed = orig
    got = {ep: (o["chars"], o["input_tokens"], o["seconds"], o["parallel"]) for ep, o in saved}
    assert got == {"openai a m": (7000, 2000, 20, 1), "openai b m": (7000, 2000, 30, 2)}
    assert lq.Runner.answered_by(row) == {"_endpoint": "openai a m", "_parallel": 1}
    assert lq.Runner.answered_by({"_calls": []}) == {"_endpoint": None, "_parallel": 1}
    assert lq.Runner.answered_by({"_endpoint": "x"}) == {}


def test_the_queue_page_says_asking_only_while_a_call_is_answered(adm):
    base = {**QUEUED[0], "Status": "running", "StartedAt": datetime(2026, 11, 3, 13, 0), "Runner": "containerizer-llm-queue",
            "CancelRequestedAt": None, "CancelRequestedBy": None}
    running = [{**base, "JobId": 4, "Kind": "refactor", "Summary": "verifying: building the image", "CallState": None},
               {**base, "JobId": 5, "CallState": "asking", "CallLlm": "built-in LLM (qwen), server 1 (NUMA node 1)",
                "CallSince": datetime(2026, 11, 3, 13, 2)},
               {**base, "JobId": 6, "CallState": "waiting", "CallSince": datetime(2026, 11, 3, 13, 3)}]
    adm.conn.answers = {r"FROM cz.LlmQueueSettings": [dict(lq.DEFAULTS)], r"FROM cz.LlmSpeed": [],
                        r"COUNT\(\*\) FROM cz.OrgScanRun": [{"N": 0}],
                        r"Status IN \(N'approval', N'queued', N'running'\)\s+ORDER BY": running}
    from containerizer import admin_llmqueue as page
    lanes = [{"name": "built-in-0", "label": "built-in LLM (qwen), server 0 (NUMA node 0)", "settings": {}, "max_tokens": 0,
              "parallel": 1, "order": 0},
             {"name": "built-in-1", "label": "built-in LLM (qwen), server 1 (NUMA node 1)", "settings": {}, "max_tokens": 0,
              "parallel": 1, "order": 0}]
    orig = page.lanes
    page.lanes = lambda conn, settings: lanes
    try:
        operator = adm.sessions.create("o@example.com", "O", False, True, True, [])
        body = _get(adm, operator, "/admin/llm-queue").body
    finally:
        page.lanes = orig
    rows = {int(m[1]): m[2] for m in re.finditer(r"<tr id='job-(\d+)'>(.*?)</tr>", body, re.S)}
    assert ">Running</span>" in rows[4] and "verifying: building the image" in rows[4] and "Asking" not in rows[4]
    assert ">Asking</span>" in rows[5] and "asking built-in LLM (qwen), server 1 (NUMA node 1) since" in rows[5]
    assert ">Waiting for an LLM</span>" in rows[6]
    llms = body.split("<h2>LLMs</h2>")[1].split("</table>")[0]
    assert "<th class='num'>Asking now</th>" in llms
    assert re.findall(r"<td class='num'>(\d+)</td></tr>", llms) == ["0", "1"]
    assert "1 LLM call waits for a free request" in body and "3 jobs at once (automatic)" in body


def test_each_job_thread_asks_its_own_llm():
    import threading
    seen = {}
    with ai.configured({"CONTAINERIZER_AI_BACKEND": "openai", "CONTAINERIZER_LLM_BASE_URL": "https://gpu.example.com/v1",
                        "CONTAINERIZER_MODEL": "big"}):
        def job():
            with ai.configured(BUILTIN, local=True):
                seen["thread"] = (ai._llm_base_url(), ai.model_name())
        t = threading.Thread(target=job)
        t.start()
        t.join()
        seen["main"] = (ai._llm_base_url(), ai.model_name())
    assert seen["thread"] == ("http://127.0.0.1:8090/v1", "qwen3-coder-30b-a3b")
    assert seen["main"] == ("https://gpu.example.com/v1", "big")


def test_the_page_shows_the_llms_in_order_and_warns_when_none_takes_big_jobs():
    ls = [{"name": "built-in", "label": "built-in LLM (qwen)", "settings": {}, "max_tokens": 4000, "parallel": 2, "order": 10},
          {"name": "llm-7", "label": "OpenAI-compatible big (gpu)", "settings": {}, "max_tokens": 30000, "parallel": 4, "order": 20}]
    html = admin_llmqueue.lanes_html(ls)
    assert html.index("built-in LLM") < html.index("big (gpu)") and "/admin/source-control/7" in html
    assert "4,000 tokens" in html and "Jobs over 30,000 estimated tokens wait" in html
    assert "wait" not in admin_llmqueue.lanes_html([ls[0], {**ls[1], "max_tokens": 0}]).split("</table>")[1]
    v, errors = admin_llmqueue.validate_settings({"LocalOrder": ["5"], "LocalMaxTokens": ["4000"]})
    assert v["LocalOrder"] == 5 and v["LocalMaxTokens"] == 4000
    v, errors = admin_llmqueue.validate_settings({"LocalOrder": ["x"]})
    assert "Built-in LLM order: 0 to 1,000, or empty" in errors


# --------------------------------------------------------------------------- LLM-heavy windows

class HeavyQueue(lq.JobQueue):
    def __init__(self, heavy):
        super().__init__(scan_name="nightly")
        self.jobs, self._windows = [], heavy

    def heavy(self, key):
        return self._windows.get(key)

    def add(self, job):
        self.jobs.append(self._job(job))
        return len(self.jobs)

    def result(self, kind, key):
        return None


def test_an_llm_heavy_window_reviews_every_component(llm):
    a = app(comp("Api", confidence=0.95, verdict="config"), comp("Web", confidence=0.99, verdict="info"),
            comp("Old", confidence=0.5))
    q = HeavyQueue({})
    lq.queue_reviews(a, q)
    assert [(j["Component"], j["Reason"]) for j in q.jobs] == [("Old", "uncertain")]      # no window: as before
    q = HeavyQueue({"shop": lq.ALL})                     # the whole application ("shop": its key without git)
    lq.queue_reviews(a, q)
    assert [(j["Component"], j["Reason"]) for j in q.jobs] == [("Api", "heavy"), ("Web", "heavy"), ("Old", "uncertain")]
    q = HeavyQueue({"shop": {"src/Web/Web.csproj"}})     # one component
    lq.queue_reviews(a, q)
    assert [(j["Component"], j["Reason"]) for j in q.jobs] == [("Web", "heavy"), ("Old", "uncertain")]
    assert lq.REASON_TEXT["heavy"] == "LLM-heavy" and lq.OVERRIDE_CONFIDENCE["heavy"] == 0.85
    assert not llm                                       # still nothing asked while the scan runs


def test_jobs_in_an_llm_heavy_window_go_first():
    rows = [{"JobId": 1, "Priority": 1500, "AdminRank": None}, {"JobId": 2, "Priority": 10, "AdminRank": None,
            "HeavyUntil": "2026-11-03T12:00:00"}, {"JobId": 3, "Priority": 900, "AdminRank": 2000.0}]
    assert [r["JobId"] for r in lq.ordered(rows)] == [2, 3, 1]
    assert "fnLlmJobHeavy" in lq.HEAVY_APPLY and lq.HEAVY_FIRST.startswith("CASE WHEN h.WindowId IS NULL")
    conn = FakeConn({r"FROM cz.vLlmHeavyActive": [{"SourceKey": "a", "ProjectPath": "x.csproj"},
                                                  {"SourceKey": "a", "ProjectPath": "y.csproj"},
                                                  {"SourceKey": "b", "ProjectPath": None},
                                                  {"SourceKey": "b", "ProjectPath": "z.csproj"}]})
    assert lq.heavy_windows(conn) == {"a": ["x.csproj", "y.csproj"], "b": ["*"]}
    q = lq.SqlJobQueue(lambda: conn)
    assert q.heavy("a") == {"x.csproj", "y.csproj"} and q.heavy("b") is lq.ALL and q.heavy("c") is None
    assert lq.heavy_covers(lq.ALL, "any") and lq.heavy_covers({"x"}, "x") and not lq.heavy_covers(None, "x")


def test_scans_run_llm_heavy_for_the_applications_in_a_window():
    from containerizer import org, sandbox
    o = org.OrgOptions(provider="github", org="acme", registry="r", ai=True, heavy_windows={"k1": ["*"]})
    assert org.heavy_for(o, "k1") and not org.heavy_for(o, "k2")
    assert not org.heavy_for(org.OrgOptions(provider="github", org="acme", registry="r", ai=False, heavy_windows={"k1": ["*"]}), "k1")
    assert sandbox.SandboxOptions().llm_keys == set()


def test_admin_turns_llm_heavy_on_and_ends_it(adm):
    a = adm.sessions.create("a@example.com", "Alice", True)
    po = adm.sessions.create("p@example.com", "Pat", False)
    adm.conn.answers = {r"FROM cz.Application WHERE ApplicationId": [{"ApplicationId": 5, "RepositoryUrl": None, "Name": "shop"}],
                        r"FROM cz.Component WHERE ComponentId": [{"ProjectPath": "src/Api/Api.csproj", "Name": "Api"}],
                        r"SELECT EndsAt FROM cz.LlmHeavyWindow": [{"EndsAt": "2026-11-03 20:00"}],
                        r"EXEC cz.AutoApproveLlmJobs": [{"Approved": 3}]}
    r = _post(adm, a, "/admin/applications/5/heavy", Scope="7", Hours="8")
    loc = dict(r.headers)["Location"]
    assert r.status == 303 and "LLM-heavy+mode+on+for+Api+of+shop" in loc and "3+waiting+jobs+approved" in loc
    (sql, params), = adm.conn.sql(r"INSERT cz.LlmHeavyWindow")
    assert params == (5, "src/Api/Api.csproj", "Api", 8, 8, "a@example.com", "Alice")
    assert "OUTPUT" not in sql                                   # the table has an audit trigger
    assert "Choose+for+how+many+hours" in dict(_post(adm, a, "/admin/applications/5/heavy", Hours="999").headers)["Location"]
    _post(adm, po, "/admin/applications/5/heavy", Hours="8")
    assert len(adm.conn.sql(r"INSERT cz.LlmHeavyWindow")) == 1   # administrators only
    r = _post(adm, a, "/admin/llm-queue/heavy/4/end", back="/admin/applications/5")
    (sql, params), = adm.conn.sql(r"UPDATE cz.LlmHeavyWindow SET EndsAt")
    assert params == ("a@example.com", "Alice", 4) and dict(r.headers)["Location"].startswith("/admin/applications/5?")
    r = _post(adm, a, "/admin/llm-queue/heavy/4/end", back="https://evil.example.com")
    assert dict(r.headers)["Location"].startswith("/admin/llm-queue?")


@needs_sql
def test_llm_heavy_windows_in_sql_server():
    """A window approves its application's jobs (new and waiting) and puts them first; one of a component only its
    own; an ended window none (cz.QueueLlmJob, cz.AutoApproveLlmJobs, cz.fnLlmJobHeavy, the runner's order)."""
    import uuid
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czheavy_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    sqlstore.init_schema(conn)
    sqlstore.init_schema(conn)
    for login, role in (("cz_h_writer", "writer"), ("cz_h_admin", "admin")):
        sqlstore.create_login(conn, login, pw, role)

    def as_(login):
        return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
    try:
        cur = conn.cursor()
        cur.execute("INSERT cz.Application (SourceKey, Name) VALUES (N'shop', N'shop'), (N'other', N'other')")
        conn.commit()
        w = sqlstore.connect(as_("cz_h_writer"), pw)
        q = lq.SqlJobQueue(lambda: sqlstore.connect(as_("cz_h_writer"), pw))

        def add(key, path, prio):
            return q.add_with(w, {"Kind": "review", "Priority": prio, "DedupeKey": uuid.uuid4().hex, "SourceKey": key,
                                  "ProjectPath": path, "Payload": {}})

        def status(jid):
            c = w.cursor()
            c.execute("SELECT Status, ApprovedBy FROM cz.LlmJob WHERE JobId = %s", (jid,))
            return tuple(c.fetchone())
        waiting = add("shop", "src/Web/Web.csproj", 5)
        other = add("other", "a.csproj", 1000)
        assert status(waiting)[0] == "approval"                              # every job waits by default
        adm = sqlstore.connect(as_("cz_h_admin"), pw)
        ac = adm.cursor()
        ac.execute("INSERT cz.LlmHeavyWindow (ApplicationId, ProjectPath, EndsAt, Hours, CreatedBy) "
                   "SELECT ApplicationId, NULL, DATEADD(hour, 8, SYSUTCDATETIME()), 8, N'alice@example.com' "
                   "FROM cz.Application WHERE SourceKey = N'shop'")
        adm.commit()
        assert lq.auto_approve(adm) == 1                                    # the one waiting, not the other app's
        assert status(waiting)[0] == "queued" and status(waiting)[1].startswith("automatic: LLM-heavy until ")
        assert status(other)[0] == "approval"
        new = add("shop", "src/Api/Api.csproj", 1)
        assert status(new)[0] == "queued"                                   # queued approved
        assert q.heavy("shop") is lq.ALL and lq.heavy_windows(w) == {"shop": ["*"]}
        # the runner takes them first, whatever their priority
        ac.execute("UPDATE cz.LlmJob SET Status = N'queued' WHERE JobId = %s", (other,))
        adm.commit()
        r = lq.Runner(lambda: sqlstore.connect(as_("cz_h_writer"), pw), name="t", metrics=lq.QueueMetrics("t"),
                      log=lambda msg: None, load=lambda: 0.0)
        try:
            first = r.claim(w)
            assert first["JobId"] == waiting and first["HeavyUntil"] is not None
            assert r.claim(w)["JobId"] == new and r.claim(w)["JobId"] == other
        finally:
            ai.LISTENERS.remove(r.metrics.llm)
        # a window of one component; ended early: no longer
        # a second ago: datetime2(0) rounds SYSUTCDATETIME() to the nearest second, maybe up into the future
        ac.execute("UPDATE cz.LlmHeavyWindow SET EndsAt = DATEADD(second, -1, SYSUTCDATETIME()), "
                   "EndedAt = SYSUTCDATETIME(), EndedBy = N'alice@example.com'")
        ac.execute("INSERT cz.LlmHeavyWindow (ApplicationId, ProjectPath, Component, EndsAt, Hours) "
                   "SELECT ApplicationId, N'src/Api/Api.csproj', N'Api', DATEADD(hour, 1, SYSUTCDATETIME()), 1 "
                   "FROM cz.Application WHERE SourceKey = N'shop'")
        adm.commit()
        assert status(add("shop", "src/Api/Api.csproj", 1))[0] == "queued"
        assert status(add("shop", "src/Web/Web.csproj", 1))[0] == "approval"
        assert q.heavy("shop") is lq.ALL                                    # the scan's copy: read again after a minute
        assert lq.heavy_windows(w) == {"shop": ["src/Api/Api.csproj"]}
        cur.execute("SELECT COUNT(*) FROM cz.AuditLog WHERE TableName = N'LlmHeavyWindow'")
        assert cur.fetchone()[0] == 3                                       # two windows, one ended
        w.close()
        adm.close()
    finally:
        conn.close()


# --------------------------------------------------------------------------- Cancel on a job being asked

def test_cancel_stops_only_the_cancelled_jobs_llm_calls():
    import threading
    stop = {"a": False}
    inside, other = threading.Event(), {}

    def neighbour():                                     # another job, asking while job "a" is cancelled
        inside.wait(5)
        with ai.cancel_thread_when(lambda: False):
            other["cancelled"] = ai.cancelled()
    t = threading.Thread(target=neighbour)
    t.start()
    with ai.cancel_thread_when(lambda: stop["a"]):
        before = ai.cancelled()
        stop["a"] = True
        inside.set()
        t.join()
        after = ai.cancelled()
    assert (before, after, other["cancelled"]) == (False, True, False) and not ai.cancelled()


def test_the_runner_records_a_cancelled_job_and_drops_its_result(monkeypatch):
    conn = FakeConn({r"SELECT JobId, CancelRequestedBy FROM cz.LlmJob": [{"JobId": 7, "CancelRequestedBy": "a@x"}]})
    r = lq.Runner(lambda: conn, name="r1", metrics=lq.QueueMetrics("r1"), log=lambda msg: None, load=lambda: 0.0)
    row = {"JobId": 7, "Kind": "refactor", "Repository": "shop", "Attempts": 1, "Payload": "{}"}
    r.active[7] = row
    calls = []

    def handler(job):
        calls.append(ai.cancelled())
        r.check_cancel()                                  # what the heartbeat thread does every few seconds
        calls.append(ai.cancelled())
        raise ai.Cancelled("cancelled: the order was cancelled")
    monkeypatch.setitem(lq.JOB_KINDS, "refactor", SimpleNamespace(name="refactor", feature="refactor-queued",
                                                                    handler=handler))
    assert r._run(row) == "skipped" and calls == [False, True]
    sql, params = conn.sql(r"SET Status = N'skipped'.*Runner = %s")[-1]
    assert params == ("cancelled by a@x", 7, "r1") and not conn.sql(r"SET Status = N'failed'")
    assert 7 not in r.cancelling and 7 not in r.active
    # put back in the queue while cancelling (the runner stopped): cancelled when it is taken again, never run
    calls.clear()
    assert r.process({**row, "CancelRequestedAt": datetime(2026, 11, 3), "CancelRequestedBy": "b@x"}) == "skipped"
    assert calls == [] and conn.sql(r"SET Status = N'skipped'")[-1][1][0] == "cancelled by b@x"


def test_cancel_on_the_queue_page(adm):
    running = [{**QUEUED[0], "JobId": 4, "Status": "running", "StartedAt": datetime(2026, 11, 3, 13, 0),
                "Runner": "containerizer-llm-queue", "CancelRequestedAt": None, "CancelRequestedBy": None}]
    adm.conn.answers = {r"FROM cz.LlmQueueSettings": [dict(lq.DEFAULTS)], r"FROM cz.LlmSpeed": [],
                        r"COUNT\(\*\) FROM cz.OrgScanRun": [{"N": 0}],
                        r"Status IN \(N'approval', N'queued', N'running'\)\s+ORDER BY": running,
                        r"FROM cz.LlmJob WHERE Status IN \(N'approval', N'queued', N'running'\)": running}
    operator = adm.sessions.create("o@example.com", "O", False, True, True, [])
    body = _get(adm, operator, "/admin/llm-queue").body
    assert "action='/admin/llm-queue/4/cancel'" in body and ">Cancel</button>" in body
    r = _post(adm, operator, "/admin/llm-queue/4/cancel", at="job-4")
    sql, params = adm.conn.sql(r"SET CancelRequestedAt = SYSUTCDATETIME\(\)")[-1]
    assert "Status = N'running'" in sql and params == ("o@example.com", 4) and "cancelling" in dict(r.headers)["Location"]
    cancelling = [{**running[0], "CancelRequestedAt": datetime(2026, 11, 3, 13, 5), "CancelRequestedBy": "o@example.com"}]
    adm.conn.answers[r"Status IN \(N'approval', N'queued', N'running'\)\s+ORDER BY"] = cancelling
    adm.conn.answers[r"FROM cz.LlmJob WHERE Status IN \(N'approval', N'queued', N'running'\)"] = cancelling
    body = _get(adm, operator, "/admin/llm-queue").body
    assert "cancelling: requested by o@example.com" in body and "/4/cancel" not in body
    _post(adm, operator, "/admin/llm-queue/4/requeue")
    assert "CancelRequestedAt = NULL" in adm.conn.sql(r"SET Status = N'queued', Attempts = 0")[-1][0]


@needs_sql
def test_jobs_at_once_and_the_call_state_in_sql_server():
    """Schema 41: the Jobs at once setting (default 0: automatic) that an administrator edits on the page, audited,
    and the state of a running job's LLM call that the runner (writer login) records for the page."""
    import uuid
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czllms_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    try:
        sqlstore.init_schema(conn)
        sqlstore.init_schema(conn)
        for login, role in (("cz_s_writer", "writer"), ("cz_s_admin", "admin")):
            sqlstore.create_login(conn, login, pw, role)
        cur = conn.cursor()
        cur.execute("SELECT MAX(Version) FROM cz.SchemaVersion")
        assert cur.fetchone()[0] >= 41

        def as_(login):
            return re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", f"User Id={login}", cs)
        writer = lambda: sqlstore.connect(as_("cz_s_writer"), pw)  # noqa: E731
        adm = sqlstore.connect(as_("cz_s_admin"), pw)
        assert lq.load_settings(adm)["JobsAtOnce"] == 0
        admin_llmqueue.save_settings(adm, {"JobsAtOnce": ["4"], "Parallel": ["2"]})
        assert lq.load_settings(adm)["JobsAtOnce"] == 4
        ac = adm.cursor()
        ac.execute("SELECT TOP (1) NewValues FROM cz.AuditLog WHERE TableName = N'LlmQueueSettings' ORDER BY AuditId DESC")
        assert json.loads(ac.fetchone()[0])["JobsAtOnce"] == 4
        adm.commit()
        with pytest.raises(Exception):
            ac.execute("UPDATE cz.LlmQueueSettings SET JobsAtOnce = 33")
        adm.rollback()
        # the runner records what its job's LLM call does; the page reads it
        lq.SqlJobQueue(writer).add({"Kind": "review", "Priority": 5, "DedupeKey": "k1", "Payload": {"prompt": "p"}})
        ac.execute("UPDATE cz.LlmJob SET Status = N'queued' WHERE Status = N'approval'")
        adm.commit()
        r = lq.Runner(writer, name="t", metrics=lq.QueueMetrics("t"), log=lambda msg: None, load=lambda: 0.0)
        try:
            w = writer()
            row = r.claim(w)
            w.close()
            r.call_state(row, "asking", "built-in LLM (qwen), server 1")
            ac.execute("SELECT CallState, CallLlm, CallSince FROM cz.LlmJob WHERE JobId = %s", (row["JobId"],))
            state, llm, since = ac.fetchone()
            assert (state, llm) == ("asking", "built-in LLM (qwen), server 1") and since is not None
            adm.commit()
            r.call_state(row, None)
            ac.execute("SELECT CallState, CallLlm, CallSince FROM cz.LlmJob WHERE JobId = %s", (row["JobId"],))
            assert tuple(ac.fetchone()) == (None, None, None) and r._call_state
            adm.commit()
            ac.execute("SELECT Action, NewValues FROM cz.AuditLog WHERE TableName = N'LlmJob' AND RowId = %s",
                       (row["JobId"],))
            assert [a for a, _ in ac.fetchall()] == ["insert"]          # not the runner's call states
            adm.commit()
        finally:
            ai.LISTENERS.remove(r.metrics.llm)
        adm.close()
    finally:
        conn.close()


def test_an_app_update_drains_the_runner(monkeypatch):
    """SIGUSR1 (sysagent.restart_services, an app update): no new job starts and housekeeping stops; the LLM answer in
    progress is not lost: once no call is answered, the running jobs go back to the queue (the new code continues them
    with the answers from the cache) and the runner leaves (DRAINED_EXIT: systemd starts the new code). Since 0.12.5
    it waited for whole jobs, and an LLM-heavy order held the queue for hours."""
    import threading
    from types import SimpleNamespace
    started, hold = threading.Event(), threading.Event()

    def make_it_a(job):                     # a long job: it would build and ask for a long time
        started.set()
        hold.wait(30)
        return {"result": {}, "summary": "verified"}
    monkeypatch.setitem(lq.JOB_KINDS, "refactor", SimpleNamespace(name="refactor", feature="refactor-queued",
                                                                    handler=make_it_a))
    jobs = [{"JobId": 1, "Kind": "refactor", "EstInputTokens": 0, "Attempts": 1, "Payload": "{}"},
            {"JobId": 2, "Kind": "refactor", "EstInputTokens": 0, "Attempts": 1, "Payload": "{}"}]
    conn = FakeConn({r"SELECT \* FROM cz.LlmSpeed": []})
    lanes = [{"name": "built-in", "settings": None, "max_tokens": 0, "parallel": 1, "order": 10}]
    r = _fill_runner(monkeypatch, lanes, jobs, settings={"JobsAtOnce": 1}, conn=conn)
    logs, housekept = [], []
    r.log = logs.append
    asking = {"built-in": 1}                # the job's LLM call is being answered
    monkeypatch.setattr(r.slots, "in_progress", lambda: dict(asking))
    monkeypatch.setattr(r, "recover", lambda own=False: None)
    monkeypatch.setattr(r, "housekeep", lambda force=False: housekept.append(1) or 0)
    out = {}
    t = threading.Thread(target=lambda: out.update(n=r.run()), daemon=True)
    try:
        t.start()
        assert started.wait(10)
        r.draining.set()
        r.wake.set()
        n = len(housekept)
        for _ in range(50):                 # the runner looks at the queue again: draining, it takes nothing
            if any("app update: waiting for the LLM call in progress" in (m or "") for m in logs):
                break
            r.wake.set()
            threading.Event().wait(0.05)
        assert [j["JobId"] for j in jobs] == [2] and len(housekept) == n and t.is_alive()
        asking["built-in"] = 0              # the answer came: the job goes back to the queue, the runner leaves
        r.wake.set()
        t.join(10)
        assert not t.is_alive() and out["n"] == 0
        (sql, params), = conn.sql(r"SET Status = N'queued'")
        assert 1 in params and "Attempts - 1" in sql                    # the attempt does not count
        assert any("no LLM call in progress: 1 job(s) go back to the queue" in m for m in logs)
    finally:
        hold.set()
        r.stopping.set()
        r.wake.set()
        ai.LISTENERS.remove(r.metrics.llm)


def test_the_runner_imports_all_its_code_at_start():
    import sys
    assert lq.preload() >= 0
    assert {"containerizer.variant", "containerizer.refactor", "containerizer.sandbox"} <= set(sys.modules)
