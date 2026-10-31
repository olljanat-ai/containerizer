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
