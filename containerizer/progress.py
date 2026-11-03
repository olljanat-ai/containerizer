"""What a repository of an organization scan is doing right now, for the run's progress page (Admin → Organization
scans → a run → Progress, docs/scheduled-scans.md#progress-of-a-run).

The scan calls `step()` when a repository moves to its next step (cloning, assessing, LLM review, verifying, the
security gate, pushing images, ...) and `detail()` for what happens inside a step (the LLM call it waits for). The
run sets the reporter: the worker's hooks when one repository is scanned at a time, the pipe back to the run when a
repository has its own process (org._child). Without a reporter (the CLI, tests) both do nothing.
"""
from __future__ import annotations

_reporter = None
_llm_calls = 0

# the steps, in the order a repository goes through them; the progress page sums the time spent in each
CLONE = "Cloning"
PULL = "Pulling"
CODE = "Looking for application code"
REPLATFORM = "Moving from its platform"
ASSESS = "Assessing (rules)"
LLM = "LLM review"
VERIFY = "Verifying: build and run"
REASSESS = "Assessing again"
GENERATE = "Generating files"
DEVDB = "Development database"
GATE = "Security gate: build, scan, run"
BUILD = "Building images"
PUSH = "Pushing images"
OUTPUT = "Writing the output files"


def set_reporter(fn) -> None:
    """fn(kind, text): kind "step" or "detail"; None stops reporting. Resets the LLM call count."""
    global _reporter, _llm_calls
    _reporter, _llm_calls = fn, 0


def _send(kind: str, text: str) -> None:
    fn = _reporter
    if fn is None:
        return
    try:
        fn(kind, text)
    except Exception:           # progress is never worth failing a repository for
        pass


def step(text: str) -> None:
    _send("step", text)


def detail(text: str) -> None:
    """Inside the current step; "" clears it."""
    _send("detail", text)


def llm_call(feature: str | None) -> None:
    """An LLM call that is not answered from the cache starts (ai.ask_json)."""
    global _llm_calls
    _llm_calls += 1
    detail(f"waiting for LLM call {_llm_calls}" + (f" ({feature})" if feature else ""))
