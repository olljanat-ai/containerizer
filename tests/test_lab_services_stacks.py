"""Lab services and the dev database for Java, Node.js, Python and Go components: found by their own client
packages and pointed at the lab through the variables their framework binds or their code reads."""
import pytest
import yaml

from containerizer import devdb, generate, labservices as L
from containerizer.assess import assess
from tests.test_engine import write
from tests.test_java_node import EXPRESS, SERVER, WEB, boot_app, dep, node

LAB = "containerizer-lab.svc.cluster.local"


def _env(tmp_path, component: str, lab: set) -> tuple[dict, dict, str, list[dict]]:
    """(env by name, the lab report, lab/README.md, the component's documents) of the app generated at tmp_path."""
    a = assess(tmp_path / "app")
    out, rep = tmp_path / "out", {}
    generate.generate_app(a, out, lab=lab, lab_report=rep)
    docs = [d for d in yaml.safe_load_all((out / component / "k8s.yaml").read_text()) if d]
    work = next(d for d in docs if d["kind"] == "Deployment")
    env = work["spec"]["template"]["spec"]["containers"][0]["env"]
    return {e["name"]: e for e in env}, rep, (out / "lab" / "README.md").read_text(), docs


def _ref(e: dict) -> tuple[str, str]:
    r = e["valueFrom"]["secretKeyRef"]
    return r["name"], r["key"]


@pytest.mark.parametrize("name,hit", [
    ("DATABASE_URL", ("db", "url")), ("SQLALCHEMY_DATABASE_URI", ("db", "url")), ("DB_HOST", ("db", "host")),
    ("DB_NAME", ("db", "database")), ("DB_PASS", ("db", "password")), ("POSTGRES_DB", ("postgres", "database")),
    ("PGPASSWORD", ("postgres", "password")), ("MYSQL_USER", ("mysql", "username")),
    ("MSSQL_CONNECTION_STRING", ("sqlserver", "url")), ("REDIS_URL", ("redis", "url")),
    ("REDIS_ADDR", ("redis", "hostport")), ("MONGO_URI", ("mongodb", "url")), ("AMQP_URL", ("rabbitmq", "url")),
    ("RABBITMQ_VHOST", ("rabbitmq", "vhost")), ("KAFKA_BROKERS", ("kafka", "bootstrap")),
    ("SMTP_HOST", ("smtp", "host")), ("EMAIL_PORT", ("smtp", "port")),
    # names that say no service, or no part of its settings
    ("PORT", None), ("DATABASE", None), ("MAIL_FROM", None), ("SESSION_SECRET", None), ("API_URL", None),
    ("REDIS_BROKERS", None),
])
def test_what_a_variable_name_says(name, hit):
    assert L.env_part(name) == hit


def test_spring_boot_gets_the_variables_spring_binds(tmp_path):
    boot_app(tmp_path / "app", WEB + dep("org.postgresql", "postgresql")
             + dep("org.springframework.boot", "spring-boot-starter-amqp")
             + dep("org.springframework.boot", "spring-boot-starter-data-redis")
             + dep("org.springframework.kafka", "spring-kafka") + dep("com.h2database", "h2", "test"))
    a = assess(tmp_path / "app")
    c = a.components[0]
    assert list(L.needs(a.repo, c)) == ["postgres", "redis", "rabbitmq", "kafka"]
    env, rep, readme, docs = _env(tmp_path, "orders", {"postgres", "redis", "rabbitmq", "kafka"})
    assert rep["provided"] == ["postgres", "redis", "rabbitmq", "kafka"]
    assert env["SPRING_DATASOURCE_URL"]["value"] == f"jdbc:postgresql://postgres.{LAB}:5432/app"
    assert _ref(env["SPRING_DATASOURCE_USERNAME"]) == ("lab-postgres", "username")
    assert _ref(env["SPRING_DATASOURCE_PASSWORD"]) == ("lab-postgres", "password")
    assert _ref(env["SPRING_RABBITMQ_HOST"]) == ("lab-rabbitmq", "host")
    assert _ref(env["SPRING_RABBITMQ_VIRTUAL_HOST"]) == ("lab-rabbitmq", "vhost")
    assert _ref(env["SPRING_DATA_REDIS_PASSWORD"]) == _ref(env["SPRING_REDIS_PASSWORD"]) == ("lab-redis", "password")
    assert _ref(env["SPRING_KAFKA_BOOTSTRAP_SERVERS"]) == ("lab-kafka", "bootstrap-servers")
    assert not any("__" in n for n in env)                  # nothing in .NET's form
    policy = next(d for d in docs if d["kind"] == "NetworkPolicy")
    assert L.egress_rule("postgres", "app") in policy["spec"]["egress"]
    assert "`SPRING_DATASOURCE_URL`" in readme and "## Notes" not in readme


def test_node_gets_the_variables_its_code_reads(tmp_path):
    node(tmp_path / "app", "", {**EXPRESS, "dependencies": {**EXPRESS["dependencies"], "ioredis": "^5.0.0"}},
         {"server.js": SERVER + "\nconst db = new (require('pg').Pool)({connectionString: process.env.DATABASE_URL});\n"
                               "const r = new (require('ioredis'))({host: process.env['REDIS_HOST'], "
                               "password: process.env.REDIS_PASSWORD});\n"})
    env, rep, readme, _ = _env(tmp_path, "api", {"postgres", "redis"})
    assert rep["provided"] == ["postgres", "redis"]
    assert env["DATABASE_URL"]["value"] == ("postgresql://$(CZ_LAB_POSTGRES_USERNAME):$(CZ_LAB_POSTGRES_PASSWORD)"
                                            f"@postgres.{LAB}:5432/app")
    names = list(env)
    # the secret references a value uses come before it ($(VAR) expands only what is defined earlier)
    assert names.index("CZ_LAB_POSTGRES_PASSWORD") < names.index("DATABASE_URL")
    assert _ref(env["CZ_LAB_POSTGRES_PASSWORD"]) == ("lab-postgres", "password")
    assert _ref(env["REDIS_HOST"]) == ("lab-redis", "host") and _ref(env["REDIS_PASSWORD"]) == ("lab-redis", "password")
    assert "## Notes" not in readme


def test_python_without_a_variable_gets_a_common_name_and_a_note(tmp_path):
    write(tmp_path / "app", "requirements.txt", "flask\nwaitress\npymongo\n")
    write(tmp_path / "app", "app.py", "from flask import Flask\nimport pymongo\napp = Flask(__name__)\n"
                                      "client = pymongo.MongoClient('mongodb://mongo01/shop')\n")
    a = assess(tmp_path / "app")
    env, rep, readme, _ = _env(tmp_path, generate.k8s_name(a.components[0].name), {"mongodb"})
    assert _ref(env["MONGODB_URI"]) == ("lab-mongodb", "connection-string")
    assert "No environment variable for MongoDB was found in the code: MONGODB_URI set (a common name)" in readme
    assert "the Secret lab-mongodb (keys: " in readme


def test_go_with_two_databases_says_it_is_not_wired(tmp_path):
    write(tmp_path / "app", "go.mod", "module example.com/web\n\ngo 1.22\n\nrequire (\n\tgithub.com/jackc/pgx/v5 v5.6.0\n"
                                      "\tgithub.com/go-sql-driver/mysql v1.8.1\n)\n")
    write(tmp_path / "app", "main.go", 'package main\n\nimport (\n\t"net/http"\n\t"os"\n\t_ "github.com/jackc/pgx/v5"\n'
                                       '\t_ "github.com/go-sql-driver/mysql"\n)\n\nfunc main() {\n'
                                       '\t_ = os.Getenv("DB_HOST")\n\t_ = os.Getenv("MYSQL_DSN")\n'
                                       '\thttp.ListenAndServe(":8080", nil)\n}\n')
    a = assess(tmp_path / "app")
    c = a.components[0]
    assert list(L.needs(a.repo, c)) == ["postgres", "mysql"]
    env, rep, readme, _ = _env(tmp_path, generate.k8s_name(c.name), {"postgres", "mysql"})
    # MYSQL_DSN names its database; DB_HOST does not say which of the two it is
    assert env["MYSQL_DSN"]["value"] == f"$(CZ_LAB_MYSQL_USERNAME):$(CZ_LAB_MYSQL_PASSWORD)@tcp(mysql.{LAB}:3306)/app"
    assert "DB_HOST" not in env
    assert "PostgreSQL is not wired for this component (it uses more than one database (PostgreSQL, MySQL) and its " \
           "variables do not say which is which): point its settings at the Secret lab-postgres" in readme


def test_database_urls_per_stack(tmp_path):
    def c(kind, *packages):
        return type("C", (), {"facts": {}, "project": type("P", (), {"kind_hint": kind, "packages": dict.fromkeys(packages, "")})()})()
    args = ("h", 1, "d", "u", "p")
    assert L.db_url("sqlserver", c("java"), *args, jdbc=True) == \
        "jdbc:sqlserver://h:1;databaseName=d;encrypt=true;trustServerCertificate=true"
    assert L.db_url("mysql", c("java", "org.mariadb.jdbc:mariadb-java-client"), *args) == "jdbc:mariadb://h:1/d?user=u&password=p"
    assert L.db_url("postgres", c("go"), *args) == "postgresql://u:p@h:1/d?sslmode=disable"
    assert L.db_url("mysql", c("python", "pymysql"), *args) == "mysql+pymysql://u:p@h:1/d"
    assert L.db_url("sqlserver", c("python", "pymssql"), *args) == "mssql+pymssql://u:p@h:1/d"
    assert L.db_url("sqlserver", c("node", "mssql"), *args) == "mssql://u:p@h:1/d?encrypt=true&trustServerCertificate=true"
    assert L.db_url("sqlserver", c("go"), *args) == "sqlserver://u:p@h:1?database=d&encrypt=true&TrustServerCertificate=true"


def test_dev_database_settings_follow_the_stack(tmp_path, monkeypatch):
    boot_app(tmp_path / "app", WEB + dep("com.microsoft.sqlserver", "mssql-jdbc"))
    a = assess(tmp_path / "app")
    c = a.components[0]
    row = {"Engine": "sqlserver", "DatabaseName": "Shop"}
    env, source, notes = devdb.connection_env(a, [c], row, ai=False, model=None)
    assert source == "default" and env[c.name] == [
        {"name": "SPRING_DATASOURCE_URL",
         "value": "jdbc:sqlserver://{host}:{port};databaseName={database};encrypt=true;trustServerCertificate=true"},
        {"name": "SPRING_DATASOURCE_USERNAME", "value": "{user}"},
        {"name": "SPRING_DATASOURCE_PASSWORD", "value": "{password}"}]
    db = devdb.SandboxDb(engine="sqlserver", database="Shop", image="r/app/devdb:1", env=env)
    rendered = {e["name"]: e.get("value") for e in devdb.render_env(db, env[c.name])}
    assert rendered["SPRING_DATASOURCE_PASSWORD"] == "$(CZ_DEVDB_PASSWORD)" and "devdb:1433" in rendered["SPRING_DATASOURCE_URL"]
    # the LLM is told the component's own conventions, and a password written into a URL is dropped
    seen = {}

    def ask(q, schema, model=None):
        seen["q"] = q
        return {"components": [{"component": c.name, "env": [
            {"name": "DATABASE_URL", "value": "postgresql://{user}:{password}@{host}:{port}/{database}"},
            {"name": "LEAK_URL", "value": "postgresql://app:hunter2@{host}/{database}"},
            {"name": "LEAK_JDBC", "value": "jdbc:postgresql://{host}/{database}?user=app&password=hunter2"}]}], "notes": []}
    monkeypatch.setattr("containerizer.ai.ask_json", ask)
    env, _ = devdb.ai_env(a, [c], "sqlserver", "Shop", "", None)
    assert [e["name"] for e in env[c.name]] == ["DATABASE_URL"]
    assert "SPRING_DATASOURCE_URL" in seen["q"] and "jdbc:sqlserver://{host}:{port}" in seen["q"]
    assert "ConnectionStrings__" not in seen["q"] and "(java, role web" in seen["q"]
