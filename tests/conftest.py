"""Shared test setup: the providers' token variables of the machine running the tests (a developer's
GITHUB_TOKEN, a CI job's) never reach the code under test, so local runs behave like CI."""
import pytest


def pytest_configure(config):
    # pytest-xdist's own mark (--dist loadgroup); declared so runs without xdist do not warn about it
    config.addinivalue_line("markers", "xdist_group(name): tests that run on the same pytest-xdist worker")

from containerizer.orgsource import TOKEN_ENVS


@pytest.fixture(autouse=True)
def _no_provider_tokens(monkeypatch):
    for names in TOKEN_ENVS.values():
        for n in names:
            monkeypatch.delenv(n, raising=False)
    monkeypatch.delenv("OUTPUT_GIT_TOKEN", raising=False)


@pytest.fixture(autouse=True)
def _own_refactor_share(monkeypatch, tmp_path):
    """Each test has its own store of refactoring answers shared between orders (refactor.shared_dir)."""
    monkeypatch.setenv("CONTAINERIZER_REFACTOR_SHARED", str(tmp_path / "refactor-shared"))


@pytest.fixture(autouse=True)
def _no_restart_plan(monkeypatch):
    """A planned restart of the machine running the tests (an appliance's status file) never holds their work."""
    from containerizer import restartplan
    monkeypatch.setattr(restartplan, "STATUS", restartplan.Path("/nonexistent/status.json"))


# The AI endpoint and model settings of the machine running the tests (a sandbox's ANTHROPIC_BASE_URL,
# a developer's OPENAI_API_KEY) never reach the code under test either; a test that needs one sets it.
_AI_ENV_PREFIXES = ("ANTHROPIC_", "OPENAI_", "CLAUDE_CODE_")
_AI_ENV_NAMES = ("CONTAINERIZER_MODEL", "CONTAINERIZER_AI_BACKEND", "CONTAINERIZER_LLM_API_KEY",
                 "CONTAINERIZER_LLM_BASE_URL", "CONTAINERIZER_LLM_TIMEOUT", "CONTAINERIZER_LLM_HEAVY_ROUNDS",
                 "CONTAINERIZER_AI_CACHE")


@pytest.fixture(autouse=True)
def _no_ai_endpoint(monkeypatch):
    import os
    for n in list(os.environ):
        if n.startswith(_AI_ENV_PREFIXES) or n in _AI_ENV_NAMES:
            monkeypatch.delenv(n, raising=False)
