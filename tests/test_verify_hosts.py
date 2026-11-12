"""Build-and-run verification resolves the host names the application's configuration and code connect to
(connection strings, URLs) to 127.0.0.1, so a missing service fails fast as "connection refused"."""
import json

from containerizer import verify
from containerizer.assess import assess


def _app(tmp_path):
    p = tmp_path / "app" / "src" / "Api"
    p.mkdir(parents=True)
    (p / "Api.csproj").write_text('<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><TargetFramework>net8.0'
                                  '</TargetFramework></PropertyGroup></Project>')
    (p / "Program.cs").write_text('var orders = "http://orders.corp.example:8081/api";\n'
                                  'var app = WebApplication.CreateBuilder(args).Build(); app.Run();\n')
    (p / "appsettings.json").write_text(json.dumps({
        "ConnectionStrings": {"Db": "Server=sql.corp.example;Database=x;Trusted_Connection=True",
                              "Pg": "Host=pg.corp.example;Port=5433;Database=y",
                              "Ip": "Server=10.1.2.3,1433;Database=z"},
        "Rabbit": "amqps://mq.corp.example", "GitHub": "https://api.github.com/repos",
        "Self": "http://localhost:5000", "Schema": "http://www.w3.org/2001/XMLSchema",
        "Template": "https://{tenant}.corp.example/"}))
    (p / "appsettings.Development.json").write_text(json.dumps({"Cache": "redis://cache.dev.example:6379"}))
    a = assess(tmp_path / "app")
    c, = [c for c in a.components if c.role == "web"]
    return a, c


def _docker_run_cmd(monkeypatch, a, c, tmp_path, env=None):
    seen = []

    def fake_run(cmd, timeout, cwd=None):
        seen.append(cmd)
        return 1, "refused"                      # `docker run` fails: run() returns at once
    monkeypatch.setattr(verify, "_run", fake_run)
    hosts = verify.hosts_to_map(a, c)
    (tmp_path / "w").mkdir()
    _, _, details = verify.run(c, {"port": 8080, "add_writable": [], "uid": 1654}, "img:verify", tmp_path / "w", env,
                               hosts=hosts)
    cmd, = seen
    mapped = [cmd[i + 1] for i, x in enumerate(cmd) if x == "--add-host"]
    return hosts, mapped, details


def test_add_host_list_comes_from_connection_strings_and_urls(tmp_path, monkeypatch):
    a, c = _app(tmp_path)
    hosts, mapped, details = _docker_run_cmd(monkeypatch, a, c, tmp_path)
    # a connection string without a port has its provider's default (SQL Server: 1433)
    assert hosts == {"sql.corp.example": [1433], "pg.corp.example": [5433], "mq.corp.example": [5671],
                     "orders.corp.example": [8081]}
    assert sorted(mapped) == sorted(f"{h}:127.0.0.1" for h in hosts)
    assert details["mapped_hosts"] == sorted(hosts)
    # IP addresses, loopback, documentation, placeholders, public services and Development settings stay out
    assert not any(x in " ".join(mapped) for x in ("10.1.2.3", "localhost", "w3.org", "github", "{", "cache.dev"))


def test_development_smoke_run_maps_the_development_settings_too(tmp_path, monkeypatch):
    a, c = _app(tmp_path)
    _, mapped, details = _docker_run_cmd(monkeypatch, a, c, tmp_path, {"ASPNETCORE_ENVIRONMENT": "Development"})
    assert "cache.dev.example:127.0.0.1" in mapped and "sql.corp.example:127.0.0.1" in mapped
    assert "cache.dev.example" in details["mapped_hosts"]


def test_only_valid_host_names_reach_add_host():
    got = verify._mappable([("db.corp.example", 1433), ("10.0.0.1", 1433), ("[::1]", 1), ("a;b", 1), ("x:1", 1),
                            ("-bad.example", 1), ("bad-.example", 1), ("db\n--privileged", 1), ("WORKER", 80),
                            ("a" * 64 + ".example", 1), ("login.microsoftonline.com", 443), ("${HOST}", 1)])
    assert got == {"db.corp.example": [1433], "worker": [80]}


def test_verify_module_has_no_host_name_literal():
    src = (verify.__file__ and open(verify.__file__).read())
    assert "corp.local" not in src and "--add-host\", \"" not in src


def test_a_run_stopped_by_external_services_names_what_it_needs(tmp_path, monkeypatch):
    a, c = _app(tmp_path)
    monkeypatch.setattr(verify, "build", lambda *x: (True, "", "img:verify"))
    monkeypatch.setattr(verify, "_run", lambda *x, **k: (0, ""))
    seen = []
    monkeypatch.setattr(verify, "run", lambda c, plan, tag, workdir, env=None, hosts=None, **k:
                        seen.append(hosts) or ("exited", "Connection refused", {"exit_code": "1",
                                                                                "mapped_hosts": sorted(hosts)}))
    monkeypatch.setattr(verify, "diagnose", lambda *x: ({"id": "run-sql-unreachable", "outcome": "external"}, {}))
    monkeypatch.setattr(c.project, "kind_hint", "java")        # no Development retry
    r = verify.verify_component(a, c, [], work=tmp_path / "work")
    assert r["status"] == "ok-external" and seen == [verify.hosts_to_map(a, c)]
    assert r["attempts"][0]["mapped_hosts"] == sorted(seen[0])
    assert sorted(r["needs"]) == ["mq.corp.example:5671", "orders.corp.example:8081", "pg.corp.example:5433",
                                  "sql.corp.example:1433"]


def test_code_that_reads_a_setting_names_no_host():
    """`var address = configuration["Proxy:Address"];` is code, not a connection string: no host `configuration`."""
    from containerizer.connectivity import line_hosts
    assert line_hosts('var address = configuration["Proxy:Address"];') == []
    assert line_hosts("var server = GetServer(name);") == []
    # Db2 puts the port after a colon
    assert line_hosts('"Main": "Server=db2.example.com:50000;Database=APP;UID=a;PWD=b"') == [
        ("db2.example.com", 50000, "connection-string")]
    assert [h for h, *_ in line_hosts('"Server=sql.corp.local\\INST,1433;Database=x"')] == ["sql.corp.local"]
    assert [h for h, *_ in line_hosts("Data Source=db01;Initial Catalog=x")] == ["db01"]


def test_development_retry_only_when_development_reaches_dependencies_another_way(tmp_path, monkeypatch):
    """Development settings that only name another server end at the same missing services: no second run."""
    a, c = _app(tmp_path)
    d = c.project.dir
    assert verify.development_helps(c) is False                # only adds a cache host
    monkeypatch.setattr(verify, "build", lambda *x: (True, "", "img:verify"))
    monkeypatch.setattr(verify, "_run", lambda *x, **k: (0, ""))
    envs = []
    monkeypatch.setattr(verify, "run", lambda c, plan, tag, workdir, env=None, hosts=None, **k:
                        envs.append(dict(env or {})) or ("exited", "Connection refused", {"exit_code": "1"}))
    monkeypatch.setattr(verify, "diagnose", lambda *x: ({"id": "run-sql-unreachable", "outcome": "external"}, {}))
    r = verify.verify_component(a, c, [], work=tmp_path / "work")
    assert r["status"] == "ok-external" and envs == [{}]
    # a developer's own SQL Server: still an external host
    (d / "appsettings.Development.json").write_text(json.dumps(
        {"ConnectionStrings": {"Db": "Server=devsql.corp.example;Database=x"}}))
    assert verify.development_helps(c) is False
    # a local file database, a stand-in switched on, or code that branches on the environment
    (d / "appsettings.Development.json").write_text(json.dumps({"ConnectionStrings": {"Db": "Data Source=app.db"}}))
    assert verify.development_helps(c) is True
    envs.clear()
    verify.verify_component(a, c, [], work=tmp_path / "work2")
    assert [e.get("ASPNETCORE_ENVIRONMENT") for e in envs] == [None, "Development"]
    (d / "appsettings.Development.json").write_text(json.dumps({"Carrier": {"UseSimulator": True}}))
    assert verify.development_helps(c) is True
    (d / "appsettings.Development.json").unlink()
    assert verify.development_helps(c) is False
    (d / "Program.cs").write_text("if (app.Environment.IsDevelopment()) o.UseInMemoryDatabase(\"x\");")
    assert verify.development_helps(c) is True
