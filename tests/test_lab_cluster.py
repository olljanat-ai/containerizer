"""Lab services against a real cluster (kind in CI, with External Secrets Operator installed with the
appliance's chart and values): the lab agent runs every service with the appliance's pinned images,
two app namespaces ask for them through the generated ExternalSecrets, and each app

- gets working credentials from the secret store (ESO), and its own database / instance;
- cannot use another app's database with its own login;
- cannot reach another app's instance at all (NetworkPolicy).

Set CONTAINERIZER_TEST_KUBE to an admin kubeconfig of a disposable cluster that runs ESO.
"""
import base64
import json
import os
import subprocess
import time
from pathlib import Path

import pytest
import yaml

from containerizer import eso, labagent, labservices as L

ADMIN = os.environ.get("CONTAINERIZER_TEST_KUBE")
ROOT = Path(__file__).resolve().parent.parent
A, B = "cz-e2e-lab-a", "cz-e2e-lab-b"
SERVICES = list(L.ORDER)


def kubectl(*args, input=None, check=True, timeout=300):
    p = subprocess.run(["kubectl", f"--kubeconfig={ADMIN}", *args], input=input, capture_output=True, text=True,
                       timeout=timeout)
    if check and p.returncode:
        raise AssertionError(f"kubectl {' '.join(args)}: {p.stderr}")
    return p


def _eso_installed() -> bool:
    return bool(ADMIN) and kubectl("get", "crd", "externalsecrets.external-secrets.io", check=False).returncode == 0


pytestmark = pytest.mark.skipif(not _eso_installed(),
                                reason="set CONTAINERIZER_TEST_KUBE to a test cluster with External Secrets Operator")


def apply(docs):
    docs = [{k: v for k, v in d.items() if k != "_comment"} for d in docs]
    kubectl("apply", "-f", "-", input="---\n".join(yaml.safe_dump(d) for d in docs))


def secret(ns: str, name: str, timeout: int = 180) -> dict:
    end = time.time() + timeout
    while time.time() < end:
        p = kubectl("-n", ns, "get", "secret", name, "-o", "json", check=False)
        if p.returncode == 0:
            return {k: base64.b64decode(v).decode() for k, v in json.loads(p.stdout)["data"].items()}
        time.sleep(3)
    raise AssertionError(f"{ns}/{name} was not created by External Secrets Operator")


def run_pod(ns: str, name: str, image: str, script: str, env: dict | None = None, timeout: int = 300) -> tuple[str, str]:
    """A one-off client pod in the app's namespace (labelled as the app's own); (phase, log)."""
    kubectl("-n", ns, "delete", "pod", name, "--ignore-not-found", "--wait=true")
    apply([{"apiVersion": "v1", "kind": "Pod",
            "metadata": {"name": name, "namespace": ns, "labels": {"app.kubernetes.io/part-of": ns}},
            "spec": {"restartPolicy": "Never", "automountServiceAccountToken": False,
                     "containers": [{"name": "c", "image": image, "command": ["/bin/sh", "-c", script],
                                     "env": [{"name": k, "value": v} for k, v in (env or {}).items()]}]}}])
    end = time.time() + timeout
    phase = ""
    while time.time() < end:
        phase = kubectl("-n", ns, "get", "pod", name, "-o", "jsonpath={.status.phase}", check=False).stdout
        if phase in ("Succeeded", "Failed"):
            break
        time.sleep(3)
    log = kubectl("-n", ns, "logs", name, check=False).stdout
    return phase, log


@pytest.fixture(scope="module")
def lab(tmp_path_factory):
    images = labagent.load_images(ROOT / "appliance/rootfs/usr/lib/containerizer/images.env", env={})
    apply(eso.secret_store())
    for ns in (A, B):
        apply([{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}},
               eso.reader_service_account(ns, set_namespace=True)]
              + eso.store_access(ns, [L.remote_key(ns, s) for s in SERVICES]))
        apply([{**d, "metadata": {**d["metadata"], "namespace": ns}} for d in L.app_docs(ns, SERVICES)])
    kube = labagent.Kubectl(cmd="kubectl", kubeconfig=ADMIN, timeout=120)
    cfg = {"services": {s: True for s in SERVICES}}
    state = tmp_path_factory.mktemp("lab") / "state.json"
    end, st = time.time() + 900, {}
    while time.time() < end:
        st = labagent.reconcile(kube, cfg, images, state_path=state, status_path=None)
        assert st["error"] is None, st["error"]
        states = {s: x["state"] for s, x in st["services"].items()}
        print("lab:", states, {s: x["message"] for s, x in st["services"].items() if x["message"]})
        assert "error" not in states.values(), st
        if all(v == "running" and set(st["services"][s]["ready"]) == {A, B} for s, v in states.items()):
            break
        time.sleep(15)
    else:
        kubectl("-n", L.LAB_NS, "get", "pods", "-o", "wide", check=False)
        raise AssertionError(f"lab services did not start: {json.dumps(st, indent=1)}")
    yield {"images": images, "kube": kube, "cfg": cfg, "state": state}
    kubectl("delete", "namespace", A, B, L.LAB_NS, "--wait=false", check=False)
    kubectl("-n", eso.remote_namespace(), "delete", "secret", "-l", L.LABEL, check=False)


def test_each_app_gets_its_own_credentials(lab):
    for svc in SERVICES:
        a, b = secret(A, L.secret_name(svc)), secret(B, L.secret_name(svc))
        assert a != b and set(a) == set(L.new_credentials(svc, A)), svc
    # nothing secret in the lab's pod specs
    pods = kubectl("-n", L.LAB_NS, "get", "deployments", "-o", "json").stdout
    for ns in (A, B):
        for svc in SERVICES:
            c = secret(ns, L.secret_name(svc))
            for k in ("password", "secret-access-key", "account-key"):
                if k in c:
                    assert c[k] not in pods


def test_postgres_database_per_app(lab):
    a, b = secret(A, "lab-postgres"), secret(B, "lab-postgres")
    image = lab["images"]["CZ_IMAGE_LAB_POSTGRES"]
    phase, log = run_pod(A, "pg", image, 'psql -v ON_ERROR_STOP=1 -h "$H" -U "$U" -d "$D" -c "CREATE TABLE t (i int); '
                         'INSERT INTO t VALUES (42); SELECT i FROM t;" && echo OWN-OK; '
                         'psql -h "$H" -U "$U" -d "$OTHER" -c "SELECT 1" && echo OTHER-OPEN || echo OTHER-REFUSED',
                         {"H": a["host"], "U": a["username"], "D": a["database"], "PGPASSWORD": a["password"],
                          "OTHER": b["database"]})
    assert "42" in log and "OWN-OK" in log and "OTHER-REFUSED" in log, log


def test_sqlserver_database_per_app(lab):
    a, b = secret(A, "lab-sqlserver"), secret(B, "lab-sqlserver")
    image = lab["images"]["CZ_IMAGE_MSSQL"]
    q = ("/opt/mssql-tools18/bin/sqlcmd -C -S \"$H,1433\" -U \"$U\" -b -h -1 -W ")
    phase, log = run_pod(A, "mssql", image,
                         q + '-d "$D" -Q "SET NOCOUNT ON; CREATE TABLE t (i int); INSERT t VALUES (42); SELECT i FROM t;" '
                         '&& echo OWN-OK; ' + q + '-Q "SET NOCOUNT ON; SELECT COUNT(*) FROM sys.databases WHERE name = N\'$OTHER\'"; '
                         + q + '-d "$OTHER" -Q "SELECT 1" && echo OTHER-OPEN || echo OTHER-REFUSED',
                         {"H": a["host"], "U": a["username"], "D": a["database"], "SQLCMDPASSWORD": a["password"],
                          "OTHER": b["database"]}, timeout=600)
    assert "42" in log and "OWN-OK" in log and "OTHER-REFUSED" in log, log


def test_redis_instance_per_app(lab):
    a, b = secret(A, "lab-redis"), secret(B, "lab-redis")
    image = lab["images"]["CZ_IMAGE_LAB_REDIS"]
    phase, log = run_pod(A, "redis", image,
                         'redis-cli -h "$H" --no-auth-warning -a "$P" SET k v && redis-cli -h "$H" --no-auth-warning -a "$P" GET k; '
                         'redis-cli -h "$H" --no-auth-warning -a wrong PING; '
                         'timeout 10 redis-cli -h "$OTHER" PING && echo OTHER-OPEN || echo OTHER-BLOCKED',
                         {"H": a["host"], "P": a["password"], "OTHER": b["host"]})
    assert "OK" in log and "\nv" in log and ("WRONGPASS" in log or "invalid" in log.lower()), log
    assert "OTHER-BLOCKED" in log, log


PY_CLIENT = r"""
import os, sys, subprocess
subprocess.run([sys.executable, "-m", "pip", "install", "-q", "--disable-pip-version-check", "boto3", "azure-storage-blob"], check=True)
import boto3, botocore
s3 = boto3.client("s3", endpoint_url=os.environ["S3"], aws_access_key_id=os.environ["AK"],
                  aws_secret_access_key=os.environ["SK"], region_name="us-east-1",
                  config=botocore.config.Config(s3={"addressing_style": "path"}))
s3.create_bucket(Bucket="uploads")
s3.put_object(Bucket="uploads", Key="a.txt", Body=b"hello")
print("S3", s3.get_object(Bucket="uploads", Key="a.txt")["Body"].read().decode())
try:
    boto3.client("s3", endpoint_url=os.environ["S3"], aws_access_key_id="nope", aws_secret_access_key="nope",
                 region_name="us-east-1").list_buckets()
    print("S3-ANON-OPEN")
except Exception as ex:
    print("S3-REFUSED", type(ex).__name__)
from azure.storage.blob import BlobServiceClient
svc = BlobServiceClient.from_connection_string(os.environ["AZ"])
c = svc.create_container("files")
c.upload_blob("b.txt", b"world")
print("AZ", c.download_blob("b.txt").readall().decode())
import socket
try:
    socket.create_connection((os.environ["OTHER"], 7070), timeout=8).close()
    print("OTHER-OPEN")
except OSError:
    print("OTHER-BLOCKED")
"""


def test_object_storage_per_app(lab):
    s3, az = secret(A, "lab-s3"), secret(A, "lab-azure-blob")
    other = secret(B, "lab-s3")["endpoint"].split("//", 1)[1].split(":")[0]
    phase, log = run_pod(A, "objects", "python:3.12-alpine", "python - <<'EOF'\n" + PY_CLIENT + "\nEOF",
                         {"S3": s3["endpoint"], "AK": s3["access-key-id"], "SK": s3["secret-access-key"],
                          "AZ": az["connection-string"], "OTHER": other}, timeout=600)
    assert "S3 hello" in log and "S3-REFUSED" in log and "AZ world" in log, log
    assert "OTHER-BLOCKED" in log, log


def test_turning_off_keeps_the_data(lab):
    kube, cfg = lab["kube"], {"services": {**lab["cfg"]["services"], "redis": False}}
    st = labagent.reconcile(kube, cfg, lab["images"], state_path=lab["state"], status_path=None)
    assert st["services"]["redis"]["state"] == "off"
    deps = kubectl("-n", L.LAB_NS, "get", "deployments", "-l", f"{L.LABEL}=redis", "-o", "name").stdout.strip()
    assert deps == ""
    pvcs = kubectl("-n", L.LAB_NS, "get", "pvc", "-l", f"{L.LABEL}=redis", "-o", "name").stdout.split()
    assert len(pvcs) == 2
    # on again: same password, the data is back
    end = time.time() + 300
    while time.time() < end:
        st = labagent.reconcile(kube, lab["cfg"], lab["images"], state_path=lab["state"], status_path=None)
        if set(st["services"]["redis"]["ready"]) == {A, B}:
            break
        time.sleep(10)
    a = secret(A, "lab-redis")
    phase, log = run_pod(A, "redis2", lab["images"]["CZ_IMAGE_LAB_REDIS"],
                         'redis-cli -h "$H" --no-auth-warning -a "$P" GET k', {"H": a["host"], "P": a["password"]})
    assert log.strip().endswith("v"), log
