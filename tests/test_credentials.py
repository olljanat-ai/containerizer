"""Source control tokens: sealing for the worker's key, what a token covers, which token goes where
(read-only token for the organization's repositories only, write token for the output repository only),
no anonymous access, and the API client keeping tokens on their host."""
import os
import shutil
import subprocess
from datetime import date
from pathlib import Path

import pytest

from containerizer import credentials as cr
from containerizer import org as orgmod
from containerizer import admin_credentials
from containerizer.org import OrgOptions, run_org
from containerizer.orgsource import NO_PROJECT, SourceError, SourceRepo, provider

from test_org import DEMO, _commit, api  # noqa: F401  (fixture)


# --------------------------------------------------------------------------- sealing

@pytest.fixture
def keys(tmp_path):
    kid = cr.keygen(tmp_path / "k", tmp_path / "k.pub")
    return cr.load_private(tmp_path / "k"), cr.load_public(tmp_path / "k.pub"), kid


def test_keygen_private_key_is_private_and_never_overwritten(tmp_path, keys):
    assert (tmp_path / "k").stat().st_mode & 0o777 == 0o600
    with pytest.raises(cr.CredentialError, match="exists"):
        cr.keygen(tmp_path / "k", tmp_path / "other.pub")
    priv, pub, kid = keys
    assert cr.key_id(priv.public_key()) == kid == cr.key_id(pub) and len(kid) == 16
    os.chmod(tmp_path / "k", 0o644)
    with pytest.raises(cr.CredentialError, match="readable by others"):
        cr.load_private(tmp_path / "k")
    with pytest.raises(cr.CredentialError, match="not a PEM"):
        (tmp_path / "bad").write_text("nope")
        os.chmod(tmp_path / "bad", 0o600)
        cr.load_private(tmp_path / "bad")


def test_sealed_token_opens_only_for_its_purpose_and_scope(keys, tmp_path):
    priv, pub, _ = keys
    aad = cr.binding("read", "github", None, "Acme")
    sealed = cr.seal(pub, "github_pat_abc123", aad)
    assert "github_pat_abc123" not in sealed
    assert cr.seal(pub, "github_pat_abc123", aad) != sealed                      # fresh ephemeral key and nonce
    # the same organization written differently, and the explicit cloud API URL, open it
    assert cr.unseal(priv, sealed, cr.binding("read", "github", "https://api.github.com/", "acme/")) == "github_pat_abc123"
    for other in (cr.binding("write", "github", None, "Acme"), cr.binding("read", "github", None, "acme-labs"),
                  cr.binding("read", "gitlab", None, "Acme"), cr.binding("read", "github", "https://ghe.example/api/v3", "Acme")):
        with pytest.raises(cr.CredentialError, match="enter it again"):
            cr.unseal(priv, sealed, other)
    cr.keygen(tmp_path / "k2", tmp_path / "k2.pub")
    with pytest.raises(cr.CredentialError, match="enter it again"):
        cr.unseal(cr.load_private(tmp_path / "k2"), sealed, aad)
    with pytest.raises(cr.CredentialError, match="damaged"):
        cr.unseal(priv, "not base64!", aad)


def test_token_text():
    assert cr.check_token_text("") and cr.check_token_text("short") and cr.check_token_text("has a space in it")
    assert cr.check_token_text("glpat-0123456789abcdef") is None


# --------------------------------------------------------------------------- what a token covers

@pytest.mark.parametrize("url,provider,org,api,ok", [
    ("https://github.com/Acme/shop.git", "github", "acme", None, True),
    ("https://github.com/acme-labs/shop.git", "github", "acme", None, False),
    ("https://github.com/acme", "github", "acme", None, False),                      # the organization, not a repository
    ("https://evil.example/acme/shop.git", "github", "acme", None, False),
    ("http://github.com/acme/shop.git", "github", "acme", None, False),              # never over plain http
    ("https://ghe.example.com/acme/shop.git", "github", "acme", "https://ghe.example.com/api/v3", True),
    ("https://github.com/acme/shop.git", "github", "acme", "https://ghe.example.com/api/v3", False),
    ("https://gitlab.com/grp/sub/app.git", "gitlab", "grp", None, True),
    ("https://gitlab.com/grp/sub/app.git", "gitlab", "grp/sub", None, True),
    ("https://gitlab.com/grp/app.git", "gitlab", "grp/sub", None, False),
    ("https://git.example.com/gitlab/grp/app.git", "gitlab", "grp", "https://git.example.com/gitlab", True),
    ("https://org@dev.azure.com/Contoso/Shop%20Floor/_git/App", "azure-devops", "contoso", None, True),
    ("https://contoso.visualstudio.com/Shop/_git/App", "azure-devops", "Contoso", None, True),
    ("https://dev.azure.com/Fabrikam/Shop/_git/App", "azure-devops", "contoso", None, False),
    ("https://tfs.example.com/tfs/Coll/P/_git/R", "azure-devops", "coll", "https://tfs.example.com/tfs", True),
    ("https://tfs.example.com/tfs/Other/P/_git/R", "azure-devops", "coll", "https://tfs.example.com/tfs", False),
])
def test_in_org(url, provider, org, api, ok):
    assert cr.in_org(url, provider, org, api) is ok


def test_same_repo_and_matching():
    assert cr.same_repo("https://github.com/acme/sandbox.git", "https://GitHub.com/Acme/sandbox/")
    assert not cr.same_repo("https://github.com/acme/sandbox", "https://github.com/acme/sandbox-api")
    creds = cr.Credentials([
        cr.Credential(1, "read", "github", None, "acme"),
        cr.Credential(2, "write", "github", None, "https://github.com/acme/sandbox.git"),
        cr.Credential(3, "read", "gitlab", None, "grp", enabled=False),
    ])
    assert creds.read_for("github", None, "ACME").id == 1
    assert creds.read_for("github", None, "sandbox") is None
    assert creds.write_for("https://github.com/acme/sandbox").id == 2
    assert creds.write_for("https://github.com/acme/shop") is None          # same organization, another repository
    assert creds.read_for("gitlab", None, "grp") is None                      # disabled
    expired = cr.Credentials([cr.Credential(1, "read", "github", None, "acme", expires_on=date(2020, 1, 1))])
    assert "expired on 2020-01-01" in expired.problems({"Provider": "github", "Organization": "acme"})[0]
    other_key = cr.Credentials([cr.Credential(1, "read", "github", None, "acme", key_id="aaaa")])
    assert "another worker key" in other_key.problems({"Provider": "github", "Organization": "acme"}, "bbbb")[0]


# --------------------------------------------------------------------------- the API client

def test_no_anonymous_access(tmp_path, monkeypatch):
    monkeypatch.setattr(orgmod, "provider", lambda *a, **k: pytest.fail("must not list anonymously"))
    o = OrgOptions(provider="github", org="acme", registry="r", output_dir=str(tmp_path / "o"), work_dir=str(tmp_path / "w"))
    with pytest.raises(SourceError, match="never read anonymously"):
        run_org(o, log=lambda *a: None)
    o.token = ""                                     # the worker found no registered token
    with pytest.raises(SourceError, match="no read-only token"):
        run_org(o, log=lambda *a: None)


def test_pagination_link_to_another_host_does_not_get_the_token(api):
    def repos(path, base):
        return 200, [{"name": "a", "clone_url": "https://github.com/acme/a.git"}], \
            {"Link": '<https://evil.example/orgs/acme/repos?page=2>; rel="next"'}
    a = api([("/orgs/acme/repos", repos)])
    with pytest.raises(SourceError, match="refusing to send the token to evil.example"):
        list(provider("github", "acme", "tok123", a.url).repos())


def test_redirect_to_another_host_drops_the_token(api):
    other = api([("/orgs/acme/repos", lambda p, b: (200, [], {}))])
    a = api([("/orgs/acme/repos", lambda p, b: (302, {}, {"Location": f"http://localhost:{other.port}/orgs/acme/repos"}))])
    assert list(provider("github", "acme", "tok123", a.url).repos()) == []
    assert a.seen[0][1].get("Authorization") == "Bearer tok123"
    assert "Authorization" not in other.seen[0][1]                               # 127.0.0.1 -> localhost: another host


def test_classic_github_token_with_write_scopes_is_reported(api):
    a = api([("/orgs/acme/repos", lambda p, b: (200, [], {"X-OAuth-Scopes": "repo, read:org"}))])
    p = provider("github", "acme", "ghp_x", a.url)
    list(p.repos())
    assert "classic token with scopes that can write (repo)" in p.token_warnings()[0]
    a = api([("/orgs/acme/repos", lambda p, b: (200, [], {}))])
    p = provider("github", "acme", "github_pat_x", a.url)
    list(p.repos())
    assert p.token_warnings() == []


def test_gitlab_token_scopes_are_reported(api):
    a = api([("/api/v4/personal_access_tokens/self", lambda p, b: (200, {"scopes": ["api", "read_repository"]}, {}))])
    assert "(api)" in provider("gitlab", "grp", "glpat-x", a.url).token_warnings()[0]
    a = api([("/api/v4/personal_access_tokens/self", lambda p, b: (200, {"scopes": ["read_api", "read_repository"]}, {}))])
    assert provider("gitlab", "grp", "glpat-x", a.url).token_warnings() == []


# --------------------------------------------------------------------------- which token goes where

class _Prov:
    def __init__(self, repos):
        self.list = repos

    def repos(self):
        return iter(self.list)

    def last_commit(self, r):
        return None

    def git_header(self):
        import base64
        return "Authorization: Basic " + base64.b64encode(b"x-access-token:READ-TOKEN").decode()


def test_output_repository_in_the_scanned_organization(tmp_path, monkeypatch):
    """The output repository lives in the scanned organization: it is not scanned, the read-only token
    is only sent with the scanned repositories' URLs and the write token only with the output's."""
    import base64
    src = tmp_path / "shop"
    shutil.copytree(DEMO, src)
    _commit(src)
    out_url = "https://github.com/acme/sandbox-deployments.git"
    repos = [SourceRepo("github", "acme", NO_PROJECT, "shop", "https://github.com/acme/shop.git", default_branch="main"),
             SourceRepo("github", "acme", NO_PROJECT, "sandbox-deployments", out_url, default_branch="main")]
    monkeypatch.setattr(orgmod, "provider", lambda name, org, token, api: (_seen_tokens.append(token), _Prov(repos))[1])
    _seen_tokens = []
    sent = []
    real_git = orgmod.git

    def fake_clone(url, dest, branch="", header="", depth=1):
        sent.append(("clone", url, header))
        if url == out_url:
            Path(dest).mkdir(parents=True)
            subprocess.run(["git", "init", "-q", "-b", "main", str(dest)], check=True)
        else:
            shutil.copytree(src, dest)

    def fake_git(args, cwd=None, url=None, header="", **kw):
        if args and args[0] in ("push", "pull"):
            sent.append((args[0], url, header))
            return ""
        return real_git(args, cwd=cwd, url=url, header=header, **kw)
    monkeypatch.setattr(orgmod, "clone", fake_clone)
    monkeypatch.setattr(orgmod, "git", fake_git)
    o = OrgOptions(provider="github", org="acme", registry="r", output_repo=out_url, token="READ-TOKEN",
                   output_token="WRITE-TOKEN", verify=False, gate=False, push_images=False, work_dir=str(tmp_path / "w"))
    res = {r.repo: r for r in run_org(o, log=lambda *a: None)}
    assert _seen_tokens == ["READ-TOKEN"]
    assert res["sandbox-deployments"].status == "skipped-output"
    assert res["shop"].status == "deployed", res["shop"]
    write = "Authorization: Basic " + base64.b64encode(b"x-access-token:WRITE-TOKEN").decode()
    for op, url, header in sent:
        if url == out_url:
            assert header == write, (op, url)
        else:
            assert "WRITE-TOKEN" not in base64.b64decode(header.split()[-1]).decode() and op == "clone", (op, url)
    assert ("push", out_url, write) in sent
    assert [u for op, u, _ in sent if op == "clone" and u != out_url] == ["https://github.com/acme/shop.git"]
    # the same token for both is refused before anything is listed
    o.output_token = "READ-TOKEN"
    with pytest.raises(SourceError, match="separate read-only token"):
        run_org(o, log=lambda *a: None)


# --------------------------------------------------------------------------- admin form validation

def _f(**kw):
    return {k: [v] for k, v in kw.items()}


def test_admin_validation():
    v, errors = admin_credentials.validate("read", _f(Provider="github", Organization=" acme ", Token="github_pat_0123456789"))
    assert errors == [] and v["Scope"] == "acme" and v["Host"] == "github.com" and v["ApiUrl"] is None
    v, errors = admin_credentials.validate("read", _f(Provider="github", Organization="acme", ApiUrl="https://api.github.com",
                                                      Token="github_pat_0123456789"))
    assert errors == [] and v["ApiUrl"] is None                                  # the cloud API is the default
    v, errors = admin_credentials.validate("read", _f(Provider="gitlab", Organization="grp/sub",
                                                      ApiUrl="https://git.example.com/", Token="glpat-0123456789"))
    assert errors == [] and v["Host"] == "git.example.com" and v["ApiUrl"] == "https://git.example.com"
    for purpose, form, msg in [
            ("read", _f(Provider="github", Organization="acme", Token="x"), "8 to 1000"),
            ("read", _f(Provider="github", Organization="<script>", Token="t" * 10), "Organization"),
            ("read", _f(Provider="github", Organization="a", ApiUrl="http://x", Token="t" * 10), "https"),
            ("read", _f(Provider="svn", Organization="a", Token="t" * 10), "provider"),
            ("write", _f(Provider="github", Scope="https://u:p@github.com/a/b", Token="t" * 10), "user name"),
            ("write", _f(Provider="gitlab", Scope="https://github.com/a/b", Token="t" * 10), "is on GitHub"),
            ("write", _f(Provider="github", Scope="https://github.com/a/b", Token="t" * 10, ExpiresOn="31.12.2026"), "YYYY")]:
        _, errors = admin_credentials.validate(purpose, form)
        assert any(msg.lower() in x.lower() for x in errors), (form, errors)
    v, errors = admin_credentials.validate("write", _f(Provider="azure-devops", Scope="https://dev.azure.com/c/p/_git/out/",
                                                       Token="t" * 10, ExpiresOn="2027-01-31"))
    assert errors == [] and v["Scope"] == "https://dev.azure.com/c/p/_git/out" and v["ExpiresOn"] == date(2027, 1, 31)


# --------------------------------------------------------------------------- the LLM

def test_llm_settings_apply_for_the_run_only(monkeypatch):
    from containerizer import ai
    monkeypatch.setenv("CONTAINERIZER_LLM_BASE_URL", "http://localhost:11434/v1")
    monkeypatch.setenv("CONTAINERIZER_MODEL", "env-model")
    c = cr.Credential(1, "llm", "openai", "https://llm.example.internal/v1", cr.LLM_SCOPE, model="qwen3:32b", token="k-123")
    with ai.configured(c.ai_settings()):
        assert ai._backend() == "openai" and ai.model_name() == "qwen3:32b"
        assert ai._llm_base_url() == "https://llm.example.internal/v1" and ai._env("CONTAINERIZER_LLM_API_KEY") == "k-123"
        assert "k-123" not in os.environ.values()                                # never through the environment
    assert ai.model_name() == "env-model" and ai._llm_base_url() == "http://localhost:11434/v1"
    claude = cr.Credential(2, "llm", "anthropic", None, cr.LLM_SCOPE, model="claude-sonnet-5-5", token="sk-ant-x")
    with ai.configured(claude.ai_settings()):
        assert ai._backend() == "api" and ai._env("CONTAINERIZER_LLM_BASE_URL") == ""   # the env's server is not used
    with ai.configured(None):                                                      # no registered LLM: the env
        assert ai.model_name() == "env-model"
    # the LLM is not a source control host, and its key is bound to its server, not the model
    assert cr.Credentials([c]).hosts() == set() and cr.Credentials([c]).llm() is c
    assert cr.binding("llm", "openai", c.api_url, "x") == cr.binding("llm", "openai", c.api_url, "y")
    assert cr.binding("llm", "openai", c.api_url, "x") != cr.binding("llm", "openai", "https://other/v1", "x")


def test_llm_validation():
    v, errors = admin_credentials.validate("llm", _f(Provider="anthropic", Model="claude-sonnet-5-5", Token="sk-ant-0123456789"))
    assert errors == [] and v["ApiUrl"] is None and v["Host"] == "api.anthropic.com" and v["Scope"] == "llm"
    v, errors = admin_credentials.validate("llm", _f(Provider="openai", ApiUrl="http://localhost:11434/v1/", Model="qwen3:32b",
                                                     Token=""))
    assert errors == [] and v["ApiUrl"] == "http://localhost:11434/v1" and v["Host"] == "localhost:11434"
    for form, msg in [
            (_f(Provider="anthropic", Model="claude-sonnet-5-5", Token=""), "API key"),
            (_f(Provider="openai", Model="m", Token=""), "Server is required"),
            (_f(Provider="openai", ApiUrl="http://10.0.0.5:8000/v1", Model="m", Token="secret-key-1"), "only sent over https"),
            (_f(Provider="anthropic", ApiUrl="http://gw.example", Model="m", Token="sk-ant-0123456789"), "https"),
            (_f(Provider="openai", ApiUrl="https://u:p@llm.example/v1", Model="m", Token=""), "user name"),
            (_f(Provider="openai", ApiUrl="https://llm.example/v1", Model="<x>", Token=""), "Model"),
            (_f(Provider="github", Model="m", Token="t" * 10), "kind of LLM")]:
        _, errors = admin_credentials.validate("llm", form)
        assert any(msg.lower() in x.lower() for x in errors), (form, errors)
    # plain http to a LAN server is fine without a key
    assert admin_credentials.validate("llm", _f(Provider="openai", ApiUrl="http://10.0.0.5:8000/v1", Model="m", Token=""))[1] == []
