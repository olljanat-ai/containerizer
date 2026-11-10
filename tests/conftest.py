"""Shared test setup: the providers' token variables of the machine running the tests (a developer's
GITHUB_TOKEN, a CI job's) never reach the code under test, so local runs behave like CI."""
import pytest

from containerizer.orgsource import TOKEN_ENVS


@pytest.fixture(autouse=True)
def _no_provider_tokens(monkeypatch):
    for names in TOKEN_ENVS.values():
        for n in names:
            monkeypatch.delenv(n, raising=False)
    monkeypatch.delenv("OUTPUT_GIT_TOKEN", raising=False)


@pytest.fixture(autouse=True)
def _no_llm_settings(monkeypatch):
    """The LLM settings of the machine running the tests (ANTHROPIC_BASE_URL in an agent's sandbox, a developer's
    API key or model) never reach the code under test: the tests that need them set their own."""
    import os
    from containerizer.ai import configured
    for n in list(os.environ):
        if n in configured.KEYS or n.startswith(("ANTHROPIC_", "OPENAI_", "CONTAINERIZER_LLM_", "CONTAINERIZER_AI_")):
            monkeypatch.delenv(n, raising=False)


@pytest.fixture(autouse=True)
def _own_refactor_share(monkeypatch, tmp_path):
    """Each test has its own store of refactoring answers shared between orders (refactor.shared_dir)."""
    monkeypatch.setenv("CONTAINERIZER_REFACTOR_SHARED", str(tmp_path / "refactor-shared"))


@pytest.fixture(autouse=True)
def _no_restart_plan(monkeypatch):
    """A planned restart of the machine running the tests (an appliance's status file) never holds their work."""
    from containerizer import restartplan
    monkeypatch.setattr(restartplan, "STATUS", restartplan.Path("/nonexistent/status.json"))
