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
                                  "WindowEnd": 360, "MaxLoadPerCpu": 0.75, "Parallel": 2}
    v, errors = admin_llmqueue.validate_settings({"From": [""], "To": [""]})
    assert errors == [] and v["WindowStart"] is None and v["WindowEnd"] is None and v["Parallel"] == 1
    for bad, msg in (({"From": ["22:00"]}, "both"), ({"From": ["25:00"], "To": ["01:00"]}, "HH:MM"),
                     ({"From": ["08:00"], "To": ["08:00"]}, "same"), ({"Parallel": ["0"]}, "1 to 16"),
                     ({"MaxLoadPerCpu": ["x"]}, "0 to 16")):
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
    assert "<b>3 jobs waiting</b> (2 uncertain, 1 second opinion) · 1 being asked now" in html
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
                        r"Status IN \(N'queued', N'running'\)\s+ORDER BY": QUEUED,
                        r"FROM cz.LlmJob WHERE Status IN \(N'queued', N'running'\)": QUEUED,
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
    assert r.body.index("2 jobs waiting") < r.body.index("<h2>Queue</h2>")          # the summary is above the list
    assert "config (0.80)" in r.body and "900 in / 300 out tokens in 5 min (estimated ~1,000 in)" in r.body
    assert "Re-scan now" in r.body and "value='9'" in r.body and "All kinds" in r.body
    assert "/admin/llm-queue/2/up" in r.body and "/admin/llm-queue/1/up" not in r.body   # the first cannot go up
    assert "<script" not in r.body
    assert ("llm-queue", "LLM queue") in adm._tabs(adm.sessions.get(operator), __import__(
        "containerizer.roles", fromlist=["Access"]).Access(False, True))


def test_admin_page_actions(adm):
    a = adm.sessions.create("a@example.com", "A", True)
    adm.conn.answers = {r"SELECT JobId, Priority, AdminRank FROM cz.LlmJob": QUEUED,
                        r"FROM cz.OrgRepository WHERE RemovedAt IS NULL AND RepositoryId IN": [
                            {"ScanId": 4, "Name": "Billing/old"}],
                        r"EXEC cz.QueueOrgScanRun": [{"RunId": 12}]}
    r = _post(adm, a, "/admin/llm-queue/2/up")
    assert r.status == 303 and "moved+up" in dict(r.headers)["Location"]
    ups = adm.conn.sql(r"UPDATE cz.LlmJob SET AdminRank")
    assert {p[1] for _, p in ups} == {1, 2} and dict((p[1], p[0]) for _, p in ups)[2] > dict((p[1], p[0]) for _, p in ups)[1]
    r = _post(adm, a, "/admin/llm-queue/5/top")
    assert "no+longer+queued" in dict(r.headers)["Location"]
    _post(adm, a, "/admin/llm-queue/2/skip")
    assert adm.conn.sql(r"SET Status = N'skipped'.*Status = N'queued'")[-1][1] == (2,)
    _post(adm, a, "/admin/llm-queue/3/requeue")
    assert adm.conn.sql(r"SET Status = N'queued', Attempts = 0")[-1][1] == (3,)
    r = _post(adm, a, "/admin/llm-queue/rescan", RepositoryId="9")
    assert r.status == 303 and "%2312" in dict(r.headers)["Location"]
    (sql, params), = adm.conn.sql(r"EXEC cz.QueueOrgScanRun")
    assert params[0] == 4 and json.loads(params[1]) == {"projects": [], "repositories": ["Billing/old"]}
    r = _post(adm, a, "/admin/llm-queue/settings", day=["5", "6"], From="22:00", To="06:00", OnlyWhenIdle="1",
              MaxLoadPerCpu="0.5", Parallel="2")
    assert "Saved" in dict(r.headers)["Location"]
    (sql, params), = adm.conn.sql(r"UPDATE cz.LlmQueueSettings")
    assert params == (False, 96, 1320, 360, True, 0.5, 2)
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
    assert [(r["Component"], r["Reason"], r["Status"]) for r in rows] == [("Api", "uncertain", "queued"),
                                                                          ("Legacy", "second-opinion", "queued")]
    assert rows[0]["EstInputTokens"] > 0
    c.close()
    m = lq.QueueMetrics("t")
    try:
        r = lq.Runner(writer, name="t", metrics=m, poll=1, log=lambda msg: None, load=lambda: 0.0)
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
