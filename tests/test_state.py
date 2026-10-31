"""Stateless scoring: an app is only rated A when no server component keeps its own data (local
SQLite or Lucene files, uploads under the app folder, in-memory session or Hangfire storage).
Data kept in managed services (SQL Server, PostgreSQL, Redis, blob storage, ...) is stateless."""
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


def test_sqlite_only_is_stateful_b(tmp_path):
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
    assert not c.stateless and a.rating == "B"


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
    assert not c.stateless and a.rating == "B"


def test_redis_backed_session_is_stateless(tmp_path):
    web_app(tmp_path, packages=pkg("Microsoft.Extensions.Caching.StackExchangeRedis"),
            code="builder.Services.AddStackExchangeRedisCache(o => { }); builder.Services.AddSession();")
    assert sev(tmp_path, "state-session-in-memory") is None
    assert rating(tmp_path) == "A"


def test_hangfire_memory_storage_is_stateful(tmp_path):
    web_app(tmp_path, packages=pkg("Hangfire.MemoryStorage", "1.8.0"))
    a, c = comp(tmp_path)
    assert sev(tmp_path, "state-hangfire-memory") == "config"
    assert a.rating == "B"


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
    assert rating(tmp_path) == "B"


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
