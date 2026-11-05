"""LLM token usage for the long run (docs/llm.md#token-usage): every call an LLM answered, with the tokens it reported
in its answer, written to cz.LlmUsage (schema 43) by the process that asked it: the scan worker and the LLM queue
runner register a Recorder as an ai.LISTENERS entry. A cached answer and a failed call cost nothing and are not
written; estimates are never written. The application comes from the call's usage_scope (source_key, the
organization scan's assess_tree; application_id, the LLM queue's jobs), as do the component, the job and the scan.
cz.vLlmUsage adds the application's name, product and business unit; Grafana's "LLM token usage" dashboard reads
it (role usage)."""
from __future__ import annotations

import threading

INSERT = ("INSERT INTO cz.LlmUsage (SourceKey, ApplicationId, Component, Repository, Feature, Backend, Model, InputTokens, "
          "OutputTokens, CostUsd, CostKnown, Seconds, JobId, ScanName, Runner) "
          "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)")


def _int(v) -> int | None:
    try:
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


def _cut(v, n: int) -> str | None:
    return str(v)[:n] if v not in (None, "") else None


def row(entry: dict, runner: str) -> tuple | None:
    """The cz.LlmUsage values of an ai.record_usage entry; None for one that is not an answer (cached, failed, no
    tokens reported)."""
    if entry.get("cached") or entry.get("error"):
        return None
    tin, tout = _int(entry.get("input_tokens")) or 0, _int(entry.get("output_tokens")) or 0
    if not (tin or tout):
        return None
    cost = entry.get("cost_usd")
    try:
        cost = round(float(cost), 5) if cost is not None else None
    except (TypeError, ValueError):
        cost = None
    known = entry.get("cost_known")
    seconds = entry.get("seconds")
    try:
        seconds = round(float(seconds), 1) if seconds is not None else None
    except (TypeError, ValueError):
        seconds = None
    return (_cut(entry.get("source_key"), 400), _int(entry.get("application_id")), _cut(entry.get("component"), 200),
            _cut(entry.get("repo"), 400), _cut(entry.get("feature") or "other", 60), _cut(entry.get("backend"), 20),
            _cut(entry.get("model"), 200), tin, tout, cost, None if known is None else bool(known), seconds,
            _int(entry.get("job")), _cut(entry.get("scan"), 200), _cut(runner, 256))


class Recorder:
    """An ai.LISTENERS entry that writes each answered call to cz.LlmUsage, with its own connection (made when
    first needed, made again after an error). It never fails the call: an error is logged once per kind and the
    row is dropped (the answer is in the answer cache; the LLM queue's job keeps its own token counts)."""

    def __init__(self, connect, runner: str, log=print):
        self.connect, self.runner, self.log = connect, runner, log
        self.conn = None
        self.lock = threading.Lock()
        self.failed: set[str] = set()
        self.written = 0

    def __call__(self, entry: dict) -> None:
        values = row(entry, self.runner)
        if values is None:
            return
        with self.lock:
            for attempt in (1, 2):
                try:
                    if self.conn is None:
                        self.conn = self.connect()
                    cur = self.conn.cursor()
                    cur.execute(INSERT, values)
                    self.conn.commit()
                    self.written += 1
                    return
                except Exception as ex:  # noqa: BLE001 - usage records must never break an LLM call
                    try:
                        if self.conn is not None:
                            self.conn.close()
                    except Exception:  # noqa: BLE001
                        pass
                    self.conn = None
                    if attempt == 2:
                        kind = type(ex).__name__
                        if kind not in self.failed:
                            self.failed.add(kind)
                            self.log(f"LLM usage not recorded: {kind}: {str(ex)[:200]}")

    def close(self) -> None:
        with self.lock:
            if self.conn is not None:
                try:
                    self.conn.close()
                except Exception:  # noqa: BLE001
                    pass
                self.conn = None
