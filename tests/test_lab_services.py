"""Lab services: detection, the generated overrides, the lab-side manifests and the lab agent's
reconcile loop (against a fake kubectl). tests/test_lab_cluster.py runs the same against a real cluster."""
import base64
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))

from containerizer import generate, labagent, labservices as L
from containerizer.assess import assess
from containerizer.harden import lint_manifests
from test_engine import web_app, write

ROOT = Path(__file__).resolve().parent.parent
PKGS = ('<PackageReference Include="Npgsql.EntityFrameworkCore.PostgreSQL" Version="8.0.0" />'
        '<PackageReference Include="StackExchange.Redis" Version="2.8.0" />'
        '<PackageReference Include="AWSSDK.S3" Version="3.7.400" />'
        '<PackageReference Include="Azure.Storage.Blobs" Version="12.20.0" />'
        '<PackageReference Include="Microsoft.Data.SqlClient" Version="5.2.0" />')
SETTINGS = {"ConnectionStrings": {"Shop": "Host=db;Database=shop;Username=u;Password=p",
                                  "Legacy": "Server=sql,1433;Database=L;User Id=x;Password=y",
                                  "Cache": "localhost:6379,abortConnect=false", "Files": "UseDevelopmentStorage=true"},
            "AWS": {"ServiceURL": "http://minio:9000", "Region": "eu-west-1"}}


@pytest.mark.parametrize("key,value,kind", [
    ("ConnectionStrings:Db", "Server=tcp:db,1433;Initial Catalog=x", "sqlserver"),
    ("ConnectionStrings:Db", "Server=.;Database=Shop;Trusted_Connection=True", "sqlserver"),
    ("ConnectionStrings:Db", "Data Source=(localdb)\\MSSQLLocalDB;Database=x", "sqlserver"),
    ("ConnectionStrings:Pg", "Host=db;Database=x;Username=u", "postgres"),
    ("ConnectionStrings:Pg", "postgresql://u@db/x", "postgres"),
    ("Redis:Configuration", "localhost:6379", "redis"),
    ("ConnectionStrings:Redis", "cache:6380,ssl=true,password=x", "redis"),
    ("ConnectionStrings:Blob", "UseDevelopmentStorage=true", "azure-blob"),
    ("Storage", "DefaultEndpointsProtocol=https;AccountName=a;AccountKey=k;EndpointSuffix=core.windows.net", "azure-blob"),
    ("AWS:ServiceURL", "http://minio:9000", "s3:endpoint"),
    ("S3:AccessKey", "minio", "s3:access-key"),
    ("ConnectionStrings:Lite", "Data Source=app.db", None),
    ("ConnectionStrings:My", "Server=x;Port=3306;Database=a;Uid=r", "mysql"),
    ("ConnectionStrings:My2", "Server=db;Database=a;Uid=u;Pwd=p", "mysql"),
    ("ConnectionStrings:Odbc", "Driver={ODBC Driver 18 for SQL Server};Server=db;Database=a;Uid=u;Pwd=p", None),
    ("ConnectionStrings:Mongo", "mongodb://u:p@db:27017/x", "mongodb"),
    ("Mongo:ConnectionString", "mongodb+srv://u:p@cluster0.example.net/x", "mongodb"),
    ("MongoDbSettings:DatabaseName", "Shop", "mongodb:database"),
    ("ConnectionStrings:Bus", "amqp://guest:guest@rabbit:5672/", "rabbitmq"),
    ("ConnectionStrings:EasyNetQ", "host=rabbit;username=u;password=p", "rabbitmq"),
    ("RabbitMQ:HostName", "rabbit", "rabbitmq:host"),
    ("RabbitMq:Port", 5672, "rabbitmq:port"),
    ("RabbitMq:VirtualHost", "/", "rabbitmq:vhost"),
    ("Kafka:BootstrapServers", "kafka:9092", "kafka:bootstrap-servers"),
    ("Producer:bootstrap.servers", "kafka:9092", "kafka:bootstrap-servers"),
    ("Kafka:SecurityProtocol", "SaslSsl", "kafka:security-protocol"),
    ("Sftp:Host", "files.example.com", "sftp:host"),
    ("Sftp:Password", "x", "sftp:password"),
    ("Smtp:Port", 25, None),
    ("Api:Url", "http://localhost:5000", None),
    ("Kestrel:Endpoints:Http:Url", "http://0.0.0.0:8080", None),
])
def test_classify(key, value, kind):
    assert L.classify(key, value) == kind


def _app(tmp_path, packages=PKGS, settings=SETTINGS):
    web_app(tmp_path / "app", packages=packages)
    write(tmp_path / "app", "src/Web/appsettings.json", json.dumps(settings))
    return assess(tmp_path / "app")


def _docs(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text()) if d]


def test_generate_points_the_app_at_the_lab(tmp_path):
    a = _app(tmp_path)
    out, rep = tmp_path / "out", {}
    generate.generate_app(a, out, lab={"sqlserver", "postgres", "redis", "s3"}, lab_report=rep)
    assert rep["provided"] == ["sqlserver", "postgres", "redis", "s3"]
    assert rep["missing"] == ["azure-blob"] and rep["needed"]["azure-blob"] == ["Web"]
    docs = _docs(out / "web" / "k8s.yaml")
    env = {e["name"]: e for e in next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["ConnectionStrings__Shop"]["valueFrom"]["secretKeyRef"] == {"name": "lab-postgres", "key": "connection-string"}
    assert env["ConnectionStrings__Legacy"]["valueFrom"]["secretKeyRef"] == {"name": "lab-sqlserver", "key": "connection-string"}
    assert env["ConnectionStrings__Cache"]["valueFrom"]["secretKeyRef"] == {"name": "lab-redis", "key": "connection-string"}
    assert env["AWS_SECRET_ACCESS_KEY"]["valueFrom"]["secretKeyRef"]["name"] == "lab-s3"
    assert env["AWS_ENDPOINT_URL_S3"]["value"] == env["AWS__ServiceURL"]["value"] == \
        "http://s3-app.containerizer-lab.svc.cluster.local:7070"
    # Azure Blob is off: the component keeps its own (secret) setting
    assert env["ConnectionStrings__Files"]["valueFrom"]["secretKeyRef"]["name"] == "web-secrets"
    pol = next(d for d in docs if d["kind"] == "NetworkPolicy")
    lab_rules = [r for r in pol["spec"]["egress"] if r["to"][0].get("namespaceSelector", {}).get("matchLabels") ==
                 {"kubernetes.io/metadata.name": L.LAB_NS}]
    assert {r["ports"][0]["port"] for r in lab_rules} == {1433, 5432, 6379, 7070}
    assert {"containerizer.io/lab-service": "redis", "containerizer.io/lab-app": "app"} in \
        [r["to"][0]["podSelector"]["matchLabels"] for r in lab_rules]
    es = _docs(out / "lab" / "k8s.yaml")
    assert [d["metadata"]["name"] for d in es] == ["lab-sqlserver", "lab-postgres", "lab-redis", "lab-s3"]
    assert es[1]["spec"]["dataFrom"] == [{"extract": {"key": "app--cz-lab-postgres"}}]
    assert es[1]["metadata"]["labels"][L.LABEL] == "postgres"
    assert "lab/k8s.yaml" in yaml.safe_load((out / "kustomization.yaml").read_text())["resources"]
    # the namespace's reader may get exactly these keys
    access = _docs(out / "cluster" / "secret-store.yaml")
    role = next(d for d in access if d["kind"] == "Role")
    assert {f"app--cz-lab-{s}" for s in rep["provided"]} <= set(role["rules"][0]["resourceNames"])
    everything = [d for f in out.rglob("k8s.yaml") for d in _docs(f)]
    assert [v for v in lint_manifests(everything) if v.severity == "error"] == []
    readme = (out / "lab" / "README.md").read_text()
    assert "Needed but turned off" in readme and "Azure Blob storage" in readme


def test_without_lab_nothing_changes(tmp_path):
    a = _app(tmp_path)
    generate.generate_app(a, tmp_path / "out")
    assert not (tmp_path / "out" / "lab").exists()
    assert "containerizer-lab" not in (tmp_path / "out" / "web" / "k8s.yaml").read_text()


def test_unclassified_connection_string_goes_to_the_only_database(tmp_path):
    a = _app(tmp_path, packages='<PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="8.0.0" />',
             settings={"ConnectionStrings": {"Main": "Name=Main"}})
    out, rep = tmp_path / "out", {}
    generate.generate_app(a, out, lab={"sqlserver"}, lab_report=rep)
    dep = next(d for d in _docs(out / "web" / "k8s.yaml") if d["kind"] == "Deployment")
    env = [e["name"] for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]]
    assert "ConnectionStrings__Main" in env and rep["provided"] == ["sqlserver"]


def test_dev_database_backup_wins_over_the_lab_sql_server(tmp_path):
    from containerizer import devdb
    a = _app(tmp_path, packages='<PackageReference Include="Microsoft.Data.SqlClient" Version="5.2.0" />',
             settings={"ConnectionStrings": {"Shop": "Server=sql,1433;Database=L;User Id=x;Password=y"}})
    db = devdb.SandboxDb(engine="sqlserver", database="Shop", image="registry.local/app/devdb:t1",
                         env={"Web": devdb.default_env("sqlserver", ["Shop"])})
    rep = {}
    generate.generate_app(a, tmp_path / "out", devdb=db, lab={"sqlserver"}, lab_report=rep)
    assert rep["provided"] == [] and rep["missing"] == []
    assert "lab-sqlserver" not in (tmp_path / "out" / "web" / "k8s.yaml").read_text()


# -- the lab side ---------------------------------------------------------------------------------

SHARED = [s for s in L.ORDER if L.SERVICES[s].shared]
PER_APP = [s for s in L.ORDER if not L.SERVICES[s].shared]


def _lab_docs() -> list[dict]:
    docs = L.namespace_docs()
    for svc in SHARED:
        docs += L.shared_manifests(svc, f"registry.example/{svc}:1@sha256:{'a' * 64}") + [L.ingress_policy(svc, "shop")]
    for svc in PER_APP:
        docs += L.per_app_manifests(svc, "shop", f"registry.example/{svc}:1@sha256:{'a' * 64}", L.new_credentials(svc, "shop"))
    return docs


def test_lab_manifests_are_hardened():
    docs = _lab_docs()
    # the lab agent writes these Secrets itself (admin passwords, per-app config); they never come from Git
    agent = {L.admin_secret_name(s) for s in L.ADMIN_PASSWORD} | {L.instance(svc, "shop") for svc in PER_APP}
    bad = [v for v in lint_manifests(docs, provided=agent) if v.severity == "error"
           and not (v.target.startswith("Secret/") and v.check in ("plain-secret", "secret-literals"))]
    assert bad == []
    for d in docs:
        if d["kind"] != "Deployment":
            continue
        pod = d["spec"]["template"]["spec"]
        assert pod["automountServiceAccountToken"] is False and pod["securityContext"]["runAsNonRoot"] is True
        c = pod["containers"][0]
        sc = c["securityContext"]
        assert sc["readOnlyRootFilesystem"] and not sc["allowPrivilegeEscalation"] and sc["capabilities"]["drop"] == ["ALL"]
        assert sc["capabilities"].get("add", []) in ([], ["NET_BIND_SERVICE"])
        assert c["resources"]["limits"]["memory"]
        assert any("persistentVolumeClaim" in v for v in pod["volumes"])
        # no secret value in the pod spec
        assert all("value" not in e or not any(w in e["name"] for w in ("PASSWORD", "SECRET", "ACCOUNTS")) for e in c.get("env") or [])
    ns = docs[0]
    assert ns["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    assert docs[1]["spec"] == {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}


def test_ingress_only_from_the_apps_namespace():
    p = L.ingress_policy("redis", "shop")
    assert p["spec"]["podSelector"]["matchLabels"] == {L.LABEL: "redis", L.APP_LABEL: "shop"}
    src = p["spec"]["ingress"][0]["from"][0]
    assert src["namespaceSelector"]["matchLabels"] == {"kubernetes.io/metadata.name": "shop"}
    assert p["spec"]["ingress"][0]["ports"] == [{"port": 6379, "protocol": "TCP"}]


def test_redis_config_holds_no_usable_password():
    cred = L.new_credentials("redis", "shop")
    sec = L.per_app_manifests("redis", "shop", "img@sha256:" + "a" * 64, cred)[0]
    assert cred["password"] not in sec["stringData"]["redis.conf"]
    assert "#" + __import__("hashlib").sha256(cred["password"].encode()).hexdigest() in sec["stringData"]["redis.conf"]


def test_credentials_are_kept_and_derived_again():
    c = L.new_credentials("postgres", "shop")
    assert L.complete("postgres", "shop", c)
    again = L.new_credentials("postgres", "shop", {"password": c["password"], "connection-string": "old"})
    assert again == c
    assert not L.complete("postgres", "shop", {**c, "host": "elsewhere"})
    az = L.new_credentials("azure-blob", "shop")
    assert base64.b64decode(az["account-key"]) and f"/{az['account-name']};" in az["connection-string"]


def test_provisioning_scripts_refuse_unsafe_values():
    c = L.new_credentials("sqlserver", "shop")
    sql = L.provision_sql("sqlserver", "shop", c)
    assert "ALTER AUTHORIZATION ON DATABASE::[shop] TO [shop]" in sql and "DENY VIEW ANY DATABASE TO [shop]" in sql
    pg = L.provision_sql("postgres", "my-app", L.new_credentials("postgres", "my-app"))
    assert 'CREATE DATABASE "my_app" OWNER "my_app"' in pg and 'REVOKE ALL ON DATABASE "my_app" FROM PUBLIC' in pg
    with pytest.raises(L.LabError):
        L.provision_sql("postgres", "shop", {**c, "password": "x'; DROP ROLE postgres; --"})


def test_names_fit_kubernetes():
    long = "a" * 63
    for svc in L.ORDER:
        assert len(L.instance(svc, long)) <= 63 and L.instance(svc, long) != L.instance(svc, long[:-1] + "b")
    with pytest.raises(L.LabError):
        L.check_namespace("kube-system")


def test_images_are_pinned():
    images = labagent.load_images(ROOT / "appliance/rootfs/usr/lib/containerizer/images.env", env={})
    for s in L.SERVICES.values():
        assert "@sha256:" in images[s.image_var], s.image_var


def test_config_is_validated(tmp_path):
    p = tmp_path / "lab.json"
    assert L.load_config(p)["services"] == L.defaults() and L.defaults()["sqlserver"] is True
    data = labagent.apply_request({"services": {**L.defaults(), "redis": True}, "requested_by": "ann@example.com"}, p)
    assert L.load_config(p)["services"]["redis"] is True and data["changed_by"] == "ann@example.com"
    assert oct(p.stat().st_mode & 0o777) == "0o644"
    for bad in ({"redis": True}, {**L.defaults(), "oracle": True}, {**L.defaults(), "redis": "yes"}):
        with pytest.raises(L.LabError):
            labagent.apply_request({"services": bad}, p)
    assert L.enabled_from_env({L.CONFIG_ENV: str(p)}) == {"sqlserver", "redis"}
    assert L.enabled_from_env({}) is None


# -- the lab agent against a fake kubectl -----------------------------------------------------------

class FakeKube(labagent.Kubectl):
    """Records every call; answers `get` from `objects` ({(ns, kind, name): doc}) and keeps applied docs."""

    def __init__(self, es: list[dict], ready: bool = True):
        super().__init__(cmd="kubectl")
        self.calls: list[tuple[list[str], str | None]] = []
        self.store: dict[str, dict] = {}
        self.es = es
        self.ready = ready
        self.applied: list[dict] = []

    def run(self, args, input=None, check=True, timeout=None, redact=()):
        self.calls.append((list(args), input))
        out = ""
        if args[:2] == ["get", "crd"]:
            out = ""
        elif args[0] == "apply":
            body = json.loads(input)  # JSON only: a YAML body lets kubectl read "Y" as a boolean
            assert body["kind"] == "List"
            for d in body["items"]:
                self.applied.append(d)
                if d["kind"] == "Secret":
                    self.store[f"{d['metadata']['namespace']}/{d['metadata']['name']}"] = d
        elif args[0] == "get":
            out = json.dumps(self._get(args))
            if out == "null":
                return subprocess.CompletedProcess(args, 1, "", "Error from server (NotFound): not found")
        return subprocess.CompletedProcess(args, 0, out, "")

    def _get(self, args):
        if labagent.ES_CRD in args:
            return {"items": self.es}
        if "secret" in args:
            ns = args[args.index("-n") + 1]
            name = args[args.index("secret") + 1]
            return self.store.get(f"{ns}/{name}")
        if "pods" in args:
            sel = args[args.index("-l") + 1]
            name = sel.split("app.kubernetes.io/name=")[1]
            return {"items": [{"metadata": {"name": f"{name}-0", "uid": "u1"},
                               "status": {"conditions": [{"type": "Ready", "status": "True" if self.ready else "False"}]}}]}
        return None


def _es(ns, svc, key=None):
    return {"metadata": {"namespace": ns, "name": f"lab-{svc}", "labels": {L.LABEL: svc}},
            "spec": {"dataFrom": [{"extract": {"key": key or L.remote_key(ns, svc)}}]}}


def test_reconcile_provisions_each_app_and_keeps_secrets_off_the_command_line(tmp_path):
    kube = FakeKube([_es("shop", "postgres"), _es("shop", "redis"), _es("crm", "postgres"),
                     _es("evil", "postgres", key=L.remote_key("shop", "postgres")), _es("kube-system", "redis")])
    cfg = {"services": {**L.defaults(), "postgres": True, "redis": True}}
    images = {s.image_var: f"img/{s.id}@sha256:{'b' * 64}" for s in L.SERVICES.values()}
    st = labagent.reconcile(kube, cfg, images, state_path=tmp_path / "state.json", status_path=tmp_path / "status.json")
    assert st["error"] is None
    assert st["services"]["postgres"]["apps"] == ["crm", "shop"] and st["services"]["postgres"]["state"] == "running"
    assert st["services"]["redis"]["apps"] == ["shop"]
    assert len(st["ignored"]) == 2          # another namespace's key, a reserved namespace
    store = {k.split("/", 1)[1]: v for k, v in kube.store.items() if k.startswith("containerizer-secrets/")}
    assert set(store) == {"shop--cz-lab-postgres", "crm--cz-lab-postgres", "shop--cz-lab-redis"}
    pw = base64.b64decode(store["shop--cz-lab-postgres"]["data"]["password"]).decode()
    execs = [(a, i) for a, i in kube.calls if "exec" in a]
    assert len(execs) == 2 and any(pw in (i or "") for _, i in execs)
    secrets_ = [base64.b64decode(v).decode() for s in store.values() for v in s["data"].values()]
    for args, _ in kube.calls:
        assert not any(sec in " ".join(args) for sec in secrets_ if len(sec) > 8), args
    # a second run changes nothing: same credentials, no provisioning again
    kube.calls.clear()
    labagent.reconcile(kube, cfg, images, state_path=tmp_path / "state.json", status_path=None)
    assert not [a for a, _ in kube.calls if "exec" in a]
    assert base64.b64decode(kube.store["containerizer-secrets/shop--cz-lab-postgres"]["data"]["password"]).decode() == pw
    status = json.loads((tmp_path / "status.json").read_text())
    assert pw not in json.dumps(status)


def test_reconcile_stops_what_is_off_and_keeps_data(tmp_path):
    kube = FakeKube([_es("shop", "redis")])
    st = labagent.reconcile(kube, {"services": L.defaults()}, {}, state_path=tmp_path / "s.json", status_path=None)
    assert st["services"]["redis"]["state"] == "off" and "ask for it" in st["services"]["redis"]["message"]
    deletes = [a for a, _ in kube.calls if "delete" in a]
    assert any("deployment,service,networkpolicy" in a and f"{L.LABEL}=redis" in a for a in deletes)
    assert not any("persistentvolumeclaim" in " ".join(a) for a in deletes)


def test_reconcile_waits_for_eso(tmp_path):
    kube = FakeKube([])
    kube.run = lambda args, **kw: subprocess.CompletedProcess(args, 1, "", "NotFound")
    st = labagent.reconcile(kube, {"services": L.defaults()}, {}, state_path=tmp_path / "s.json", status_path=None)
    assert "External Secrets Operator" in st["error"]


MORE_PKGS = ('<PackageReference Include="MongoDB.Driver" Version="2.28.0" />'
             '<PackageReference Include="RabbitMQ.Client" Version="6.8.1" />'
             '<PackageReference Include="Confluent.Kafka" Version="2.5.0" />'
             '<PackageReference Include="SSH.NET" Version="2024.1.0" />'
             '<PackageReference Include="MySqlConnector" Version="2.3.7" />')
MORE_SETTINGS = {"ConnectionStrings": {"Orders": "Server=mysql;Database=orders;Uid=u;Pwd=p"},
                 "MongoDbSettings": {"ConnectionString": "mongodb://localhost:27017", "DatabaseName": "catalog"},
                 "RabbitMQ": {"HostName": "localhost", "UserName": "guest", "Password": "guest", "Port": 5672},
                 "Kafka": {"BootstrapServers": "localhost:9092", "SecurityProtocol": "SaslSsl"},
                 "Sftp": {"Host": "files.example.com", "Username": "u", "Password": "p"}}
MORE = ["mysql", "mongodb", "rabbitmq", "kafka", "sftp"]


def test_generate_points_the_app_at_brokers_document_stores_and_sftp(tmp_path):
    a = _app(tmp_path, MORE_PKGS, MORE_SETTINGS)
    out, rep = tmp_path / "out", {}
    generate.generate_app(a, out, lab=set(MORE), lab_report=rep)
    assert rep["provided"] == [s for s in L.ORDER if s in MORE] and rep["missing"] == []
    docs = _docs(out / "web" / "k8s.yaml")
    env = {e["name"]: e for e in next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"]}

    def ref(name):
        return env[name]["valueFrom"]["secretKeyRef"]
    assert ref("ConnectionStrings__Orders") == {"name": "lab-mysql", "key": "connection-string"}
    assert ref("MongoDbSettings__ConnectionString") == {"name": "lab-mongodb", "key": "connection-string"}
    assert ref("MongoDbSettings__DatabaseName") == {"name": "lab-mongodb", "key": "database"}
    assert ref("RabbitMQ__HostName") == {"name": "lab-rabbitmq", "key": "host"}
    assert ref("RabbitMQ__Password") == {"name": "lab-rabbitmq", "key": "password"}
    assert ref("RabbitMQ__Port") == {"name": "lab-rabbitmq", "key": "port"}
    assert ref("Kafka__BootstrapServers") == {"name": "lab-kafka", "key": "bootstrap-servers"}
    assert env["Kafka__SecurityProtocol"]["value"] == "Plaintext"
    assert ref("Sftp__Host") == {"name": "lab-sftp", "key": "host"} and ref("Sftp__Password")["key"] == "password"
    pol = next(d for d in docs if d["kind"] == "NetworkPolicy")
    ports = {r["ports"][0]["port"] for r in pol["spec"]["egress"]
             if r["to"][0].get("namespaceSelector", {}).get("matchLabels") == {"kubernetes.io/metadata.name": L.LAB_NS}}
    assert ports == {3306, 27017, 5672, 9092, 2022}
    everything = [d for f in out.rglob("k8s.yaml") for d in _docs(f)]
    assert [v for v in lint_manifests(everything) if v.severity == "error"] == []


def test_every_secret_key_an_override_uses_exists():
    for svc, (_, leaves) in L.PARTS.items():
        keys = set(L.secret_keys(svc))
        for k in set(leaves.values()):
            assert f"{svc}:{k}" in L._PLAIN_PARTS or k in keys, (svc, k)


def test_new_services_credentials_and_provisioning():
    for svc in ("mysql", "mongodb", "rabbitmq"):
        c = L.new_credentials(svc, "my-shop")
        assert L.complete(svc, "my-shop", c) and c["password"] in c["connection-string"]
        script = L.provision_sql(svc, "my-shop", c)
        assert "my_shop" in script and c["password"] in script
        with pytest.raises(L.LabError):
            L.provision_sql(svc, "my-shop", {**c, "password": "x'; drop"})
    rmq = L.provision_sql("rabbitmq", "my-shop", L.new_credentials("rabbitmq", "my-shop"))
    # the password goes to rabbitmqctl through a pipe from the shell's printf builtin, never as an argument
    assert "add_user 'my_shop'\n" in rmq and "delete_user guest" in rmq and "</dev/null" in rmq
    assert L.new_credentials("rabbitmq", "my-shop")["connection-string"].endswith(":5672/my-shop")
    assert L.new_credentials("kafka", "shop") == {"bootstrap-servers": "kafka-shop.containerizer-lab.svc.cluster.local:9092"}
    sftp = L.new_credentials("sftp", "shop")
    assert sftp["port"] == "22"
    svc_doc = next(d for d in L.per_app_manifests("sftp", "shop", "i@sha256:" + "a" * 64, sftp) if d["kind"] == "Service")
    assert svc_doc["spec"]["ports"][0]["port"] == 22 and svc_doc["spec"]["ports"][0]["targetPort"] == 2022


def test_kafka_and_sftp_listen_only_where_they_should():
    props = L.kafka_properties("shop")
    assert "advertised.listeners=PLAINTEXT://kafka-shop.containerizer-lab.svc.cluster.local:9092" in props
    assert "CONTROLLER://localhost:9093" in props
    assert len(L.kafka_cluster_id("shop")) == 22 and L.kafka_cluster_id("shop") == L.kafka_cluster_id("shop")
    dep = next(d for d in L.per_app_manifests("sftp", "shop", "i@sha256:" + "a" * 64, L.new_credentials("sftp", "shop"))
               if d["kind"] == "Deployment")
    env = {e["name"]: e["value"] for e in dep["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["SFTPGO_HTTPD__BINDINGS__0__PORT"] == "0" and env["SFTPGO_DATA_PROVIDER__DRIVER"] == "memory"
    rmq = L.shared_manifests("rabbitmq", "i@sha256:" + "a" * 64)
    conf = next(d for d in rmq if d["kind"] == "ConfigMap")["data"]["10-lab.conf"]
    assert "loopback_users.guest = true" in conf


def test_reconcile_runs_every_service(tmp_path):
    kube = FakeKube([_es("shop", s) for s in L.ORDER])
    cfg = {"services": {s: True for s in L.ORDER}}
    images = labagent.load_images(ROOT / "appliance/rootfs/usr/lib/containerizer/images.env", env={})
    st = labagent.reconcile(kube, cfg, images, state_path=tmp_path / "state.json", status_path=None)
    assert st["error"] is None
    assert {s: x["state"] for s, x in st["services"].items()} == {s: "running" for s in L.ORDER}
    assert all(x["ready"] == ["shop"] for x in st["services"].values())
    execs = [a for a, _ in kube.calls if "exec" in a]
    assert len(execs) == len(SHARED)
    secrets_ = [base64.b64decode(v).decode() for k, s in kube.store.items() if k.startswith("containerizer-secrets/")
                for v in s["data"].values()]
    for args, _ in kube.calls:
        assert not any(sec in " ".join(args) for sec in secrets_ if len(sec) > 8), args
    admins = {k.split("/", 1)[1] for k in kube.store if k.startswith(f"{L.LAB_NS}/") and k.endswith("-admin")}
    assert admins == {L.admin_secret_name(s) for s in L.ADMIN_PASSWORD}


def test_pod_problem_names_eviction():
    from containerizer import labagent

    class K:
        def get(self, args):
            return {"items": [{"status": {"phase": "Failed", "reason": "Evicted",
                                          "message": "The node was low on resource: ephemeral-storage."}}]}
    assert labagent._pod_problem(K(), "redis", "redis") == \
        "Failed (Evicted): The node was low on resource: ephemeral-storage."
