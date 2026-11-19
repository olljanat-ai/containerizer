"""The inventory (inventory.py, schema 60): binaries of A-rated builds, databases from connection strings, external
services and NServiceBus transports, kept per application with when each was first and last found."""
import os
import re
import uuid

import pytest

from containerizer import inventory
from containerizer.assess import assess
from tests.test_engine import write
from tests.test_vb_fsharp_references_and_heads import RULES


@pytest.mark.parametrize("value,kind,want", [
    ("Server=tcp:sql01.corp.local,1433;Initial Catalog=Orders;User Id=app;Password=secret;", None,
     {"server": "sql01.corp.local", "port": 1433, "database": "Orders"}),
    (r"Data Source=SQL02\PROD;Database=Billing;Integrated Security=true", "sqlserver",
     {"kind": "sqlserver", "server": r"SQL02\PROD", "port": None, "database": "Billing"}),
    ("Host=pg.example.com;Port=5433;Database=shop;Username=u;Password=p", "postgres",
     {"server": "pg.example.com", "port": 5433, "database": "shop"}),
    ("postgresql://u:p@pg2:5432/catalog?sslmode=require", None,
     {"kind": "postgres", "server": "pg2", "port": 5432, "database": "catalog"}),
    ("mongodb://user:pw@mongo1:27017/inventory", None, {"kind": "mongodb", "server": "mongo1", "database": "inventory"}),
    ("jdbc:sqlserver://db3:1433;databaseName=Payroll;user=x;password=y", None,
     {"kind": "sqlserver", "server": "db3", "port": 1433, "database": "Payroll"}),
    ("cache01:6379,password=x,ssl=False", "redis", {"kind": "redis", "server": "cache01", "port": 6379, "database": None}),
    ("Data Source=app.db", "sqlite", {"kind": "sqlite", "server": None, "database": "app.db"}),
])
def test_connection_strings_name_the_server_and_database_never_the_credentials(value, kind, want):
    got = inventory.parse_connection(value, kind)
    assert {k: got[k] for k in want} == want
    assert "secret" not in str(got) and "pw" not in str(got).replace("pwd", "")
    assert inventory.parse_connection("not a connection string") is None


def test_database_facts_take_connection_strings_and_lab_classified_settings():
    got = inventory.database_facts([
        ("ConnectionStrings:Default", "Server=sql01;Database=Orders;User Id=a;Password=b", "sqlserver"),
        ("ConnectionStrings:Bus", "host=rabbit01;username=u;password=p", "rabbitmq"),        # a broker: a service
        ("Mongo:ConnectionString", "mongodb://m1/catalog", "mongodb"),
        ("Upstream:Url", "https://api.example.com", None),
        ("ConnectionStrings:Default", "Server=other;Database=X", "sqlserver")])               # a key once
    assert got == [{"key": "ConnectionStrings:Default", "kind": "sqlserver", "server": "sql01", "port": None, "database": "Orders"},
                   {"key": "Mongo:ConnectionString", "kind": "mongodb", "server": "m1", "port": None, "database": "catalog"}]


def endpoint(root, packages, code="", appsettings=None, web_config=None):
    refs = "".join(f'<PackageReference Include="{n}" Version="{v}" />' for n, v in packages)
    write(root, "src/Billing/Billing.csproj", f"""\
        <Project Sdk="Microsoft.NET.Sdk">
          <PropertyGroup><OutputType>Exe</OutputType><TargetFramework>net8.0</TargetFramework></PropertyGroup>
          <ItemGroup>{refs}</ItemGroup>
        </Project>
        """)
    write(root, "src/Billing/Program.cs", f"""\
        class Program {{
            static async Task Main() {{
                var config = new EndpointConfiguration("Billing.Endpoint");
                {code}
                var endpoint = await Endpoint.Start(config);
                await Task.Delay(-1);
            }}
        }}
        """)
    if appsettings:
        write(root, "src/Billing/appsettings.json", appsettings)
    if web_config:
        write(root, "src/Billing/app.config", web_config)
    return assess(root, RULES)


def comp(a):
    return next(c for c in a.components if c.name == "Billing")


def test_nservicebus_endpoints_and_their_transport(tmp_path):
    a = endpoint(tmp_path / "a", [("NServiceBus", "8.1.6"), ("NServiceBus.Transport.SqlServer", "7.0.5")],
                 'config.UseTransport(new SqlServerTransport(cs));',
                 appsettings='{"ConnectionStrings": {"NServiceBus": "Server=sql01;Database=Bus;User Id=u;Password=p"}}')
    f = comp(a).facts
    assert f["nservicebus"] == {"transport": "sqlserver", "endpoint": "Billing.Endpoint", "version": "8.1.6"}
    assert not {"nsb_transport", "nsb_transport_code", "nsb_endpoint"} & set(f)
    assert f["databases"] == [{"key": "ConnectionStrings:NServiceBus", "kind": "sqlserver", "server": "sql01", "port": None,
                               "database": "Bus"}]
    assert any(x.rule.id == "nservicebus" for x in comp(a).findings)
    # the transport in code only (NServiceBus 7)
    b = endpoint(tmp_path / "b", [("NServiceBus", "7.8.4")], "config.UseTransport<LearningTransport>();")
    assert comp(b).facts["nservicebus"]["transport"] == "learning"
    # NServiceBus 6 without a transport: MSMQ, its default; .NET Framework connection strings from app.config
    c = endpoint(tmp_path / "c", [("NServiceBus", "6.5.0")], web_config="""\
        <configuration><connectionStrings>
          <add name="Orders" connectionString="Data Source=SQL02;Initial Catalog=Orders;Integrated Security=SSPI" />
        </connectionStrings></configuration>
        """)
    assert comp(c).facts["nservicebus"]["transport"] == "msmq"
    assert comp(c).facts["databases"][0]["database"] == "Orders"
    # RabbitMQ: the lab's RabbitMQ takes its connection string
    d = endpoint(tmp_path / "d", [("NServiceBus", "9.0.0"), ("NServiceBus.RabbitMQ", "9.0.0")],
                 appsettings='{"ConnectionStrings": {"NServiceBus/Transport": "host=rabbit01;username=u;password=p"}}')
    assert comp(d).facts["nservicebus"]["transport"] == "rabbitmq"
    assert comp(d).facts["lab_settings"] == {"ConnectionStrings:NServiceBus/Transport": "rabbitmq"}
    assert "databases" not in comp(d).facts


DOC = {"name": "billing", "rating": "A", "score": 95, "confidence": 0.9, "summary": "", "components": [
    {"name": "Billing.Api", "project": "src/Billing.Api/Billing.Api.csproj", "role": "web", "tfm": ["net8.0"],
     "verdict": "info", "score": 95, "facts": {
        "entry": "Billing.Api.dll",
        "databases": [{"key": "ConnectionStrings:Default", "kind": "sqlserver", "server": "sql01", "port": 1433,
                       "database": "Billing"}],
        "nservicebus": {"transport": "msmq", "endpoint": "Billing", "version": "6.5.0"}}}],
    "network": {"components": [{"name": "Billing.Api", "destinations": [
        {"host": "api.payments.example.com", "port": 443, "scheme": "https", "file": "appsettings.json", "line": 4},
        {"host": "sql01", "port": 1433, "protocol": "TCP"},                       # the database: not a service
        {"host": "localhost", "port": 5000, "scheme": "http"},
        {"host": "orders.orders.svc.cluster.local", "port": 80, "scheme": "http"}]}]}}


def test_items_of_an_assessment():
    got = {(i["kind"], i["name"], i["server"], i["port"]) for i in inventory.items(DOC)}
    assert got == {("binary", "Billing.Api.dll", None, None), ("database", "Billing", "sql01", 1433),
                   ("service", "NServiceBus: MSMQ", "Billing", None),
                   ("service", "api.payments.example.com", None, 443)}
    assert not [i for i in inventory.items({**DOC, "rating": "B"}) if i["kind"] == "binary"]   # A-rated builds only


def test_the_inventory_page():
    from datetime import datetime
    rows = [{"ApplicationId": 7, "ApplicationName": "billing", "ProductName": "Payments", "ComponentName": "Billing.Api",
             "Name": "Billing", "Server": "sql01", "Port": 1433, "Detail": "sqlserver", "Source": "ConnectionStrings:Default",
             "RepositoryUrl": "https://git.example.com/acme/billing", "FirstSeenAt": datetime(2026, 11, 1),
             "LastSeenAt": datetime(2026, 11, 19), "RemovedAt": None}]
    body = inventory.render(rows, {"binary": 3, "database": 1}, "database", "sql<01>", False)
    assert "<code>sql01,1433</code>" in body and "href='/app/7'" in body and "Databases <span class='muted'>1</span>" in body
    assert "value='sql&lt;01&gt;'" in body and "2026-11-01" in body and "<script>" not in body.split("</head>")[1]
    assert inventory.parse_query({"kind": ["evil"], "q": ["  a   b "], "removed": ["1"]}) == ("binary", "a b", True)


ADMIN_SQL = os.environ.get("CONTAINERIZER_TEST_SQL")


@pytest.mark.skipif(not ADMIN_SQL, reason="set CONTAINERIZER_TEST_SQL to run against SQL Server")
def test_the_inventory_follows_the_assessments():
    """store_assessment keeps the inventory: new items, seen again, removed; binaries only from A-rated assessments;
    the reader role reads vInventory; Forget application deletes them; init_schema fills it from older assessments."""
    from containerizer import sqlstore
    pw, sa_pw = "Test-Passw0rd!x", os.environ["CONTAINERIZER_SQL_PASSWORD"]
    name = "czinv_" + uuid.uuid4().hex[:8]
    cs = re.sub(r"(?i)(database|initial\s*catalog)\s*=[^;]*", f"Database={name}", ADMIN_SQL)
    sqlstore.create_database(cs, sa_pw)
    conn = sqlstore.connect(cs, sa_pw)
    try:
        sqlstore.init_schema(conn)
        sqlstore.create_login(conn, "cz_i_reader", pw, "reader")
        src = {"key": "https://git.example.com/acme/billing#", "repository_url": "https://git.example.com/acme/billing",
               "path": "."}
        sqlstore.store_assessment(conn, DOC, src)
        cur = conn.cursor(as_dict=True)
        cur.execute("SELECT Kind, Name, RemovedAt FROM cz.InventoryItem ORDER BY Kind, Name")
        assert [(r["Kind"], r["Name"], r["RemovedAt"]) for r in cur.fetchall()] == [
            ("binary", "Billing.Api.dll", None), ("database", "Billing", None),
            ("service", "api.payments.example.com", None), ("service", "NServiceBus: MSMQ", None)]
        # rated B, the API and NServiceBus gone: those are removed, the binary of the A-rated build stays
        doc = {**DOC, "rating": "B", "network": {"components": []},
               "components": [{**DOC["components"][0], "facts": {"entry": "Billing.Api.dll",
                                                                 "databases": DOC["components"][0]["facts"]["databases"]}}]}
        sqlstore.store_assessment(conn, doc, src)
        cur.execute("SELECT Kind, Name, CASE WHEN RemovedAt IS NULL THEN 0 ELSE 1 END AS Gone FROM cz.InventoryItem "
                    "ORDER BY Kind, Name")
        assert [(r["Kind"], r["Name"], r["Gone"]) for r in cur.fetchall()] == [
            ("binary", "Billing.Api.dll", 0), ("database", "Billing", 0),
            ("service", "api.payments.example.com", 1), ("service", "NServiceBus: MSMQ", 1)]
        r = sqlstore.connect(re.sub(r"(?i)(user\s*id|uid)\s*=[^;]*", "User Id=cz_i_reader", cs), pw)
        try:
            rows, counts = inventory.load(r, "database", "sql0", False)
            assert [(x["Name"], x["Server"], x["ApplicationName"]) for x in rows] == [("Billing", "sql01", "billing")]
            assert counts == {"binary": 1, "database": 1}
            assert inventory.load(r, "service", "", True)[0][0]["RemovedAt"] is not None
        finally:
            r.close()
        # init_schema fills an empty inventory from the assessments
        cur.execute("DELETE cz.InventoryItem")
        conn.commit()
        sqlstore.init_schema(conn)
        cur.execute("SELECT COUNT(*) AS N FROM cz.InventoryItem WHERE RemovedAt IS NULL")
        assert cur.fetchone()["N"] == 2
        cur.execute("SELECT ApplicationId FROM cz.Application")
        conn.cursor().execute("EXEC cz.ForgetApplication @ApplicationId = %s", (cur.fetchone()["ApplicationId"],))
        conn.commit()
        cur.execute("SELECT COUNT(*) AS N FROM cz.InventoryItem")
        assert cur.fetchone()["N"] == 0
    finally:
        conn.close()
        m = sqlstore.connect(re.sub(r"(?i)Database=\w+", "Database=master", cs), sa_pw, autocommit=True)
        m.cursor().execute(f"ALTER DATABASE [{name}] SET SINGLE_USER WITH ROLLBACK IMMEDIATE; DROP DATABASE [{name}]")
        m.cursor().execute("IF SUSER_ID(N'cz_i_reader') IS NOT NULL DROP LOGIN [cz_i_reader]")
        m.close()
