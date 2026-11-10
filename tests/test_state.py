"""Stateful components: a server component that keeps its own data (local SQLite or Lucene files, uploads under
the app folder, in-memory session or Hangfire storage) is reported as stateful and still rates A: it runs as it
is with a persistent volume and one replica. Only local data in a folder the generator cannot find (so no volume
can hold it) keeps it at B. Data kept in managed services (SQL Server, PostgreSQL, Redis, blob storage, ...) is
stateless."""
import json

from containerizer.assess import assess
from tests.test_engine import web_app, write
from tests.test_round7 import RULES, rating, sev


def pkg(name, version="8.0.0"):
    return f'<PackageReference Include="{name}" Version="{version}" />'


def comp(root):
    a = assess(root, RULES)
    return a, next(c for c in a.components if c.name == "Web")


def test_plain_web_is_stateless_and_a(tmp_path):
    web_app(tmp_path)
    a, c = comp(tmp_path)
    assert c.stateless and a.rating == "A"
    assert c.to_dict()["stateless"] is True and c.to_dict()["state"] == []
    assert a.to_dict()["stateless"] is True


def test_sqlite_without_a_known_file_is_stateful_b(tmp_path):
    """No connection string or folder names the database file: no volume can hold it, so B."""
    web_app(tmp_path, packages=pkg("Microsoft.EntityFrameworkCore.Sqlite"))
    a, c = comp(tmp_path)
    assert sev(tmp_path, "sqlite-local") == "config"
    assert not c.stateless and a.rating == "B"
    assert [s["id"] for s in c.to_dict()["state"]] == ["sqlite-local"]
    assert a.to_dict()["stateless"] is False
    assert "not stateless" in a.summary()


def test_sqlite_next_to_a_server_database_is_optional(tmp_path):
    web_app(tmp_path, packages=pkg("Microsoft.EntityFrameworkCore.Sqlite")
            + pkg("Microsoft.EntityFrameworkCore.SqlServer"))
    a, c = comp(tmp_path)
    assert sev(tmp_path, "sqlite-local") is None
    assert sev(tmp_path, "sqlite-optional") == "info"
    assert c.stateless and a.rating == "A"


def test_sqlite_with_server_database_in_another_project(tmp_path):
    web_app(tmp_path, packages=pkg("Microsoft.Data.Sqlite"))
    write(tmp_path, "src/Data/Data.csproj", f"""
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup>{pkg("Npgsql")}</ItemGroup>
        </Project>""")
    write(tmp_path, "src/Data/Db.cs", "public class Db { }")
    assert sev(tmp_path, "sqlite-local") is None


def test_uploads_under_webroot_are_stateful(tmp_path):
    web_app(tmp_path, code="""
        class Upload {
            void Save(IWebHostEnvironment env, IFormFile f) {
                var path = Path.Combine(env.WebRootPath, "uploads", f.FileName);
                using var s = new FileStream(path, FileMode.Create);
                f.CopyTo(s);
            }
        }""")
    a, c = comp(tmp_path)
    assert sev(tmp_path, "state-local-files") == "config"
    assert not c.stateless and a.rating == "A"
    assert "persistent volume" in a.summary()


def test_temp_files_are_stateless(tmp_path):
    web_app(tmp_path, code="""
        class Export {
            void Save(byte[] data) {
                var path = Path.Combine(Path.GetTempPath(), "export.pdf");
                File.WriteAllBytes(path, data);
            }
        }""")
    assert sev(tmp_path, "state-local-files") is None
    assert rating(tmp_path) == "A"


def test_blob_uploads_are_stateless(tmp_path):
    web_app(tmp_path, code="""
        class Upload {
            void Save(IWebHostEnvironment env, BlobContainerClient blobs, IFormFile f) {
                var local = Path.Combine(env.ContentRootPath, "cache.txt");
                File.WriteAllText(local, "x");
                blobs.UploadBlob(f.FileName, f.OpenReadStream());
            }
        }""")
    assert sev(tmp_path, "state-local-files") is None


def test_reading_app_files_is_stateless(tmp_path):
    web_app(tmp_path, code="""
        class Templates {
            string Load(IWebHostEnvironment env) => File.ReadAllText(Path.Combine(env.ContentRootPath, "t.html"));
        }""")
    assert sev(tmp_path, "state-local-files") is None


def test_in_memory_session_is_stateful(tmp_path):
    web_app(tmp_path, code="builder.Services.AddSession();")
    a, c = comp(tmp_path)
    assert sev(tmp_path, "state-session-in-memory") == "config"
    assert not c.stateless and a.rating == "A"                   # in memory: one replica, no volume needed


def test_redis_backed_session_is_stateless(tmp_path):
    web_app(tmp_path, packages=pkg("Microsoft.Extensions.Caching.StackExchangeRedis"),
            code="builder.Services.AddStackExchangeRedisCache(o => { }); builder.Services.AddSession();")
    assert sev(tmp_path, "state-session-in-memory") is None
    assert rating(tmp_path) == "A"


def test_hangfire_memory_storage_is_stateful(tmp_path):
    web_app(tmp_path, packages=pkg("Hangfire.MemoryStorage", "1.8.0"))
    a, c = comp(tmp_path)
    assert sev(tmp_path, "state-hangfire-memory") == "config"
    assert a.rating == "A" and not c.stateless


def test_state_rules_have_valid_flags():
    states = {r.id: r.state for r in RULES if r.state}
    assert set(states) >= {"sqlite-local", "lucene-local-index", "state-local-files",
                           "state-session-in-memory", "state-hangfire-memory"}
    assert set(states.values()) <= {"local", "memory"}


def test_read_only_sqlite_reference_data_is_stateless(tmp_path):
    web_app(tmp_path, packages=pkg("Microsoft.Data.Sqlite"), code="""
        class Dict {
            string cs = new SqliteConnectionStringBuilder("Data Source=Data/dict.db") { Mode = SqliteOpenMode.ReadOnly }.ToString();
        }""")
    assert sev(tmp_path, "sqlite-local") is None
    assert sev(tmp_path, "sqlite-readonly") == "info"
    assert rating(tmp_path) == "A"


def test_read_only_flag_with_writes_is_still_stateful(tmp_path):
    web_app(tmp_path, packages=pkg("Microsoft.Data.Sqlite"), code="""
        class Store {
            string ro = "Data Source=a.db;Mode=ReadOnly";
            void Add(SqliteCommand c) { c.CommandText = "INSERT INTO t VALUES (1)"; c.ExecuteNonQuery(); }
        }""")
    assert sev(tmp_path, "sqlite-local") == "config"


def test_lucene_query_parser_only_is_not_an_index(tmp_path):
    web_app(tmp_path, packages=pkg("Lucene.Net.QueryParser", "4.8.0-beta00017"),
            code="class Q { object P(string s) => new QueryParser(LuceneVersion.LUCENE_48, \"f\", null).Parse(s); }")
    assert sev(tmp_path, "lucene-local-index") is None
    assert sev(tmp_path, "lucene-text-analysis") == "info"
    assert rating(tmp_path) == "A"


def test_lucene_fs_index_is_stateful(tmp_path):
    web_app(tmp_path, packages=pkg("Lucene.Net", "4.8.0-beta00017"),
            code="class I { object D(string p) => FSDirectory.Open(p); }")
    assert sev(tmp_path, "lucene-local-index") == "config"
    assert rating(tmp_path) == "B"


def test_app_data_media_folder_is_stateful(tmp_path):
    web_app(tmp_path, code="""
        static class Perms { static string[] Dirs = { "App_Data", $"App_Data/Tenants/{Name}/Media" }; static string Name = "Default"; }""")
    assert sev(tmp_path, "state-app-data-folders") == "config"
    assert rating(tmp_path) == "A"                               # App_Data on a persistent volume


def test_projects_in_top_level_build_folder_are_tools(tmp_path):
    from tests.test_round11 import role_of, sdk_proj
    sdk_proj(tmp_path, "build/smoke/Probe/Probe.csproj", props="<OutputType>Exe</OutputType>")
    write(tmp_path, "build/smoke/Probe/Program.cs", "class P { static void Main() { } }")
    assert role_of(tmp_path, "Probe") == "tool"


def test_report_says_whether_the_app_is_stateless(tmp_path):
    from containerizer.report import migration_markdown
    web_app(tmp_path, packages=pkg("Microsoft.EntityFrameworkCore.Sqlite"))
    md = migration_markdown(assess(tmp_path, RULES))
    assert "Stateless: no - Web: Embedded file database (SQLite/LiteDB)" in md


# --------------------------------------------------------------------------- deployed as it is, with a volume

def _deployed(root):
    """The component's manifests, as an organization scan writes them, and the lint errors of the security gate."""
    from containerizer import org
    from containerizer.generate import dockerfile_dotnet, k8s_manifests, make_plan
    from containerizer.harden import lint_dockerfile, lint_manifests
    a = assess(root)
    keep, excluded = org.select_components(a, verified=False)
    assert [c.name for c in keep] == ["Web"] and excluded == []
    c = keep[0]
    plan = make_plan(a, c)
    docs = k8s_manifests(a, c, plan, "reg.example/app/web:1.0.0")
    errors = [v for v in lint_manifests(docs) + lint_dockerfile(dockerfile_dotnet(plan)) if v.severity == "error"]
    dep = next(d for d in docs if d["kind"] == "Deployment")
    return a, plan, docs, dep["spec"], errors


def _mounts(spec):
    pod = spec["template"]["spec"]
    claims = {v["name"]: v["persistentVolumeClaim"]["claimName"] for v in pod["volumes"] if "persistentVolumeClaim" in v}
    return {m["mountPath"]: claims[m["name"]] for m in pod["containers"][0]["volumeMounts"] if m["name"] in claims}


def test_sqlite_app_is_deployed_with_a_volume_and_one_replica(tmp_path):
    """The app's only obstacle is a SQLite file in its folder: it runs as it is. The file moves to /data (a
    PersistentVolumeClaim) by an environment variable over its connection string; nothing in the app changes."""
    web_app(tmp_path, packages=pkg("Microsoft.EntityFrameworkCore.Sqlite"))
    write(tmp_path, "src/Web/appsettings.json", '{"ConnectionStrings": {"Default": "Data Source=app.db"}}')
    before = {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()}
    a, plan, docs, spec, errors = _deployed(tmp_path)
    assert a.rating == "A" and a.to_dict()["stateless"] is False   # runs as it is; marked stateful
    assert errors == []
    assert spec["replicas"] == 1 and spec["strategy"] == {"type": "Recreate"}
    assert _mounts(spec) == {"/data": "web-w0-data"}
    pod = spec["template"]["spec"]
    ct = pod["containers"][0]
    assert ct["securityContext"]["readOnlyRootFilesystem"] is True and ct["securityContext"]["runAsNonRoot"] is True
    assert pod["securityContext"]["fsGroup"] == 1654 and pod["securityContext"]["fsGroupChangePolicy"] == "OnRootMismatch"
    env = {e["name"]: e for e in ct["env"]}
    assert env["ConnectionStrings__Default"] == {"name": "ConnectionStrings__Default", "value": "Data Source=/data/app.db"}
    pvc = next(d for d in docs if d["kind"] == "PersistentVolumeClaim")
    assert pvc["metadata"]["name"] == "web-w0-data" and pvc["spec"]["accessModes"] == ["ReadWriteOnce"]
    assert "back it up" in pvc["_comment"]
    assert not any(d["kind"] == "ExternalSecret" and "ConnectionStrings__Default" in json.dumps(d) for d in docs)
    assert any(r["rule"] == "state-volume" for r in plan["reasons"])
    assert {p: p.read_bytes() for p in tmp_path.rglob("*") if p.is_file()} == before     # no file of the app changed


def test_uploads_app_is_deployed_with_a_volume_on_the_uploads_folder(tmp_path):
    web_app(tmp_path, code="""
        class Upload {
            void Save(IWebHostEnvironment env, IFormFile f) {
                var path = Path.Combine(env.WebRootPath, "uploads", f.FileName);
                using var s = new FileStream(path, FileMode.Create);
                f.CopyTo(s);
            }
        }""")
    a, plan, docs, spec, errors = _deployed(tmp_path)
    assert a.rating == "A" and errors == []
    assert spec["replicas"] == 1 and spec["strategy"] == {"type": "Recreate"}
    assert _mounts(spec) == {"/app/wwwroot/uploads": "web-w0-uploads"}
    assert plan["state_dirs"] == ["/app/wwwroot/uploads"]


def test_in_memory_session_runs_with_one_replica_and_no_volume(tmp_path):
    web_app(tmp_path, code="builder.Services.AddSession();")
    a, plan, docs, spec, errors = _deployed(tmp_path)
    assert errors == [] and spec["replicas"] == 1 and spec["strategy"] == {"type": "Recreate"}
    assert _mounts(spec) == {} and not any(d["kind"] == "PersistentVolumeClaim" for d in docs)


def test_local_state_in_an_unknown_folder_stays_out(tmp_path):
    from containerizer import org
    web_app(tmp_path, packages=pkg("Lucene.Net", "4.8.0-beta00016"),
            code="class I { void M() { var d = FSDirectory.Open(\"idx\"); } }")
    a = assess(tmp_path)
    keep, excluded = org.select_components(a, verified=False)
    assert keep == [] and "could not find" in excluded[0]["reason"]


def test_stateless_app_keeps_rolling_updates(tmp_path):
    from containerizer.generate import k8s_manifests, make_plan
    web_app(tmp_path)
    a = assess(tmp_path)
    c = a.components[0]
    docs = k8s_manifests(a, c, make_plan(a, c), "reg.example/app/web:1.0.0")
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert dep["spec"]["strategy"] == {"type": "RollingUpdate"} and not any(d["kind"] == "PersistentVolumeClaim" for d in docs)


def test_hardening_and_migration_notes_name_the_volumes(tmp_path):
    from containerizer.harden import hardening_markdown
    from containerizer.report import migration_markdown
    web_app(tmp_path, packages=pkg("Microsoft.EntityFrameworkCore.Sqlite"))
    write(tmp_path, "src/Web/appsettings.json", '{"ConnectionStrings": {"Default": "Data Source=app.db"}}')
    a, plan, docs, spec, errors = _deployed(tmp_path)
    md = hardening_markdown("app", {"web": docs})
    assert "## Application data (persistent volumes)" in md and "| web | `web-w0-data` |" in md
    assert "backup" in md
    mig = migration_markdown(a)
    assert "## Application data on persistent volumes" in mig and "the operator owns their backup" in mig


def test_stateful_label_storage_class_and_node_pool(tmp_path, monkeypatch):
    from containerizer import generate
    web_app(tmp_path, packages=pkg("Microsoft.EntityFrameworkCore.Sqlite"))
    write(tmp_path, "src/Web/appsettings.json", '{"ConnectionStrings": {"Default": "Data Source=app.db"}}')
    a, plan, docs, spec, errors = _deployed(tmp_path)
    # default: the label on the workload, its pods and the volume, never in the (immutable) selector
    dep = next(d for d in docs if d["kind"] == "Deployment")
    assert dep["metadata"]["labels"]["stateful"] == "true" and spec["template"]["metadata"]["labels"]["stateful"] == "true"
    assert "stateful" not in spec["selector"]["matchLabels"]
    pvc = next(d for d in docs if d["kind"] == "PersistentVolumeClaim")
    assert pvc["metadata"]["labels"]["stateful"] == "true" and "storageClassName" not in pvc["spec"]
    assert "nodeSelector" not in spec["template"]["spec"]
    monkeypatch.setattr(generate, "stateful_settings", lambda: {
        "labels": {"stateful": "true"}, "storage_class": "backed-up", "size": "5Gi",
        "node_selector": {"node-pool": "stateful"}, "tolerations": [{"key": "stateful", "operator": "Exists"}]})
    a, plan, docs, spec, errors = _deployed(tmp_path)
    pvc = next(d for d in docs if d["kind"] == "PersistentVolumeClaim")
    assert pvc["spec"]["storageClassName"] == "backed-up" and pvc["spec"]["resources"]["requests"]["storage"] == "5Gi"
    assert spec["template"]["spec"]["nodeSelector"] == {"node-pool": "stateful"}
    assert spec["template"]["spec"]["tolerations"] == [{"key": "stateful", "operator": "Exists"}]
    assert errors == []
    # a stateless component gets none of it
    from containerizer.generate import k8s_manifests, make_plan
    plain = tmp_path / "plain"
    web_app(plain)
    b = assess(plain)
    docs = k8s_manifests(b, b.components[0], make_plan(b, b.components[0]), "reg.example/app/web:1.0.0")
    assert "stateful" not in next(d for d in docs if d["kind"] == "Deployment")["metadata"]["labels"]


# ---- #273: three false-positive patterns

def test_config_read_from_the_base_directory_is_not_a_local_write(tmp_path):
    """AddJsonFile/SetBasePath(AppContext.BaseDirectory) loads configuration; an export to a path the operator
    passes, in the same file, is not application data under the app folder."""
    web_app(tmp_path, code="""
        class Export {
            static async Task Run(string outFile, string script) {
                var cfg = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).Build();
                var b = WebApplication.CreateBuilder();
                b.Configuration.AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.json"), optional: true);
                await File.WriteAllTextAsync(outFile, script);
            }
        }""")
    assert sev(tmp_path, "state-local-files") is None
    a, c = comp(tmp_path)
    assert c.stateless


def test_write_under_the_base_directory_next_to_a_config_read_is_still_stateful(tmp_path):
    web_app(tmp_path, code="""
        class Store {
            void Save(string json) {
                var cfg = new ConfigurationBuilder().SetBasePath(AppContext.BaseDirectory).Build();
                File.WriteAllText(Path.Combine(AppContext.BaseDirectory, "data", "state.json"), json);
            }
        }""")
    assert sev(tmp_path, "state-local-files") == "config"


def _shared_library_app(root):
    """Two web apps on a shared hosting library that references a documents library with a Lucene index.
    Its registration class has two extension methods side by side: AddDocuments (no index), called by the
    hosting library for every app, and AddSearchIndex (opens the index), called only by the Search app."""
    def proj(name, sdk, refs="", packages=""):
        write(root, f"src/{name}/{name}.csproj", f"""
            <Project Sdk="{sdk}">
              <PropertyGroup><TargetFramework>net8.0</TargetFramework></PropertyGroup>
              <ItemGroup>{refs}{packages}</ItemGroup>
            </Project>""")
    ref = lambda n: f'<ProjectReference Include="../{n}/{n}.csproj" />'
    proj("Docs", "Microsoft.NET.Sdk", packages=pkg("Lucene.Net", "4.8.0-beta00016"))
    write(root, "src/Docs/Registration.cs", """
        public static class DocsRegistration {
            public static IServiceCollection AddDocuments(this IServiceCollection services) {
                services.AddSingleton<ILetters, Letters>();
                return services;
            }
            public static IServiceCollection AddSearchIndex(this IServiceCollection services, string folder) {
                services.AddSingleton<IDocumentIndex>(_ => new LuceneDocumentIndex(folder));
                return services;
            }
        }""")
    write(root, "src/Docs/Letters.cs", "public interface ILetters { }\npublic class Letters : ILetters { }")
    write(root, "src/Docs/LuceneDocumentIndex.cs", """
        public interface IDocumentIndex { }
        public class LuceneDocumentIndex : IDocumentIndex {
            private readonly FSDirectory _directory;
            public LuceneDocumentIndex(string folder) { _directory = FSDirectory.Open(new DirectoryInfo(folder)); }
            public static string Snippet(string text) => text;
        }""")
    proj("Hosting", "Microsoft.NET.Sdk", refs=ref("Docs"))
    write(root, "src/Hosting/Core.cs", """
        public static class CoreRegistration {
            public static IServiceCollection AddCore(this IServiceCollection services) => services.AddDocuments();
        }""")
    for name, call in (("Portal", "builder.Services.AddCore();"),
                       ("Search", 'builder.Services.AddCore(); builder.Services.AddSearchIndex("/data/index");')):
        proj(name, "Microsoft.NET.Sdk.Web", refs=ref("Hosting"))
        write(root, f"src/{name}/Program.cs", f"""
            var builder = WebApplication.CreateBuilder(args);
            {call}
            var app = builder.Build();
            app.MapGet("/healthz", () => "ok");
            app.Run();
            class Hit {{ public string Snippet {{ get; set; }} }}""")


def test_library_lucene_index_counts_only_for_components_that_reach_it(tmp_path):
    _shared_library_app(tmp_path)
    a = assess(tmp_path)
    by = {c.name: c for c in a.components}
    search = [f for f in by["Search"].findings if f.rule.id == "lucene-local-index"]
    assert search and not search[0].dormant and search[0].via == "Docs"
    assert not by["Search"].stateless
    # the Portal reaches the registration class only through AddDocuments, and a property named like the
    # index's static Snippet method is not a call of it: the finding is in the library, not reached
    portal = [f for f in by["Portal"].findings if f.rule.id == "lucene-local-index"]
    assert all(f.dormant for f in portal)
    assert by["Portal"].stateless


def test_state_findings_point_at_code_not_at_package_lines(tmp_path):
    _shared_library_app(tmp_path)
    a = assess(tmp_path)
    search = next(c for c in a.components if c.name == "Search")
    f = next(f for f in search.findings if f.rule.id == "lucene-local-index")
    assert f.evidence and all(e.file == "src/Docs/LuceneDocumentIndex.cs" and e.line for e in f.evidence)
    assert "FSDirectory.Open" in str(f.evidence[0])


def test_sqlite_and_hangfire_evidence_is_the_code_that_opens_the_storage(tmp_path):
    web_app(tmp_path, packages=pkg("Microsoft.EntityFrameworkCore.Sqlite") + pkg("Hangfire.MemoryStorage", "1.8.0"),
            code="""
        class Setup {
            void Configure(IServiceCollection s) {
                s.AddDbContext<AppDb>(o => o.UseSqlite("Data Source=app.db"));
                s.AddHangfire(c => c.UseMemoryStorage());
            }
        }""")
    a, c = comp(tmp_path)
    ev = {f.rule.id: [str(e) for e in f.evidence] for f in c.findings}
    assert len(ev["sqlite-local"]) == 1 and "UseSqlite(" in ev["sqlite-local"][0] and "Program.cs" in ev["sqlite-local"][0]
    assert len(ev["state-hangfire-memory"]) == 1 and "UseMemoryStorage()" in ev["state-hangfire-memory"][0]


def test_package_evidence_stays_when_no_code_opens_the_storage(tmp_path):
    """Where the code does not tell (the storage is set up by a framework or by configuration), the package
    line stays the evidence and the finding stays, also for a component that gets it through a library."""
    web_app(tmp_path, packages=pkg("Hangfire.MemoryStorage", "1.8.0"))
    a, c = comp(tmp_path)
    f = next(f for f in c.findings if f.rule.id == "state-hangfire-memory")
    assert [str(e) for e in f.evidence] == ["src/Web/Web.csproj: package Hangfire.MemoryStorage 1.8.0"]
    assert not c.stateless
