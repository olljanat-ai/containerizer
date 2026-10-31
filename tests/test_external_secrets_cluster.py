"""Generated ExternalSecrets against a real cluster with External Secrets Operator (kind in CI, installed
with the appliance's chart and values).

Set CONTAINERIZER_TEST_KUBE to an admin kubeconfig of a disposable cluster that runs ESO. The test
applies the store containerizer generates (kubernetes provider over containerizer-secrets), two app
namespaces with their reader ServiceAccount and access Role, and checks that each namespace gets its own
values (plain keys, every key, a dockerconfigjson pull secret) and cannot read the other's.
"""
import base64
import json
import os
import subprocess
import time

import pytest
import yaml

from containerizer import eso

ADMIN = os.environ.get("CONTAINERIZER_TEST_KUBE")


def kubectl(*args, input=None, check=True):
    p = subprocess.run(["kubectl", f"--kubeconfig={ADMIN}", *args], input=input, capture_output=True, text=True,
                       timeout=180)
    if check and p.returncode:
        raise AssertionError(f"kubectl {' '.join(args)}: {p.stderr}")
    return p


def _eso_installed() -> bool:
    return bool(ADMIN) and kubectl("get", "crd", "externalsecrets.external-secrets.io", check=False).returncode == 0


pytestmark = pytest.mark.skipif(not _eso_installed(),
                                reason="set CONTAINERIZER_TEST_KUBE to a test cluster with External Secrets Operator")
A, B = "cz-e2e-eso-a", "cz-e2e-eso-b"


def apply(docs):
    docs = [{k: v for k, v in d.items() if k != "_comment"} for d in docs]
    kubectl("apply", "-f", "-", input="---\n".join(yaml.safe_dump(d) for d in docs))


def remote(name: str, data: dict) -> dict:
    return {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": eso.remote_namespace()},
            "data": {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}}


def secret(ns: str, name: str, timeout: int = 120) -> dict | None:
    end = time.time() + timeout
    while time.time() < end:
        p = kubectl("-n", ns, "get", "secret", name, "-o", "json", check=False)
        if p.returncode == 0:
            return json.loads(p.stdout)
        time.sleep(3)
    return None


def ready_reason(ns: str, name: str) -> str:
    p = kubectl("-n", ns, "get", "externalsecret", name, "-o",
                'jsonpath={.status.conditions[?(@.type=="Ready")].reason}', check=False)
    return p.stdout.strip()


@pytest.fixture(scope="module")
def store():
    apply(eso.secret_store())
    docs = [remote(f"{A}--web", {"ConnectionStrings__Db": "Server=db;Password=a-only", "Other": "x"}),
            remote(f"{A}--{eso.REGISTRY}", {".dockerconfigjson": json.dumps({"auths": {"reg.example": {"auth": "eDp5"}}})}),
            remote(f"{B}--web", {"ConnectionStrings__Db": "Server=db;Password=b-only"})]
    for ns in (A, B):
        docs += [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": ns}},
                 eso.reader_service_account(ns, set_namespace=True)]
        docs += eso.store_access(ns, [eso.remote_key(ns, "web"), eso.remote_key(ns, eso.REGISTRY)])
    apply(docs)
    yield
    kubectl("delete", "namespace", A, B, "--wait=false", check=False)
    for d in docs:
        if d["kind"] in ("Secret", "Role", "RoleBinding"):
            kubectl("-n", eso.remote_namespace(), "delete", d["kind"].lower(), d["metadata"]["name"], check=False)


def test_each_namespace_reads_only_its_own_keys(store):
    for ns in (A, B):
        apply([eso.external_secret("web-secrets", ns, eso.remote_key(ns, "web"), ["ConnectionStrings__Db"],
                                   set_namespace=True)])
    a = secret(A, "web-secrets")
    assert a and base64.b64decode(a["data"]["ConnectionStrings__Db"]).decode() == "Server=db;Password=a-only"
    assert set(a["data"]) == {"ConnectionStrings__Db"}            # only the keys asked for
    b = secret(B, "web-secrets")
    assert b and base64.b64decode(b["data"]["ConnectionStrings__Db"]).decode() == "Server=db;Password=b-only"

    # namespace B asks for A's remote key: its reader has no access, so nothing is created
    apply([eso.external_secret("stolen", B, eso.remote_key(A, "web"), set_namespace=True)])
    assert secret(B, "stolen", timeout=45) is None
    assert ready_reason(B, "stolen") == "SecretSyncedError"


def test_every_key_and_pull_secret_type(store):
    apply([eso.external_secret("all", A, eso.remote_key(A, "web"), set_namespace=True),
           eso.external_secret("regcred", A, eso.remote_key(A, eso.REGISTRY), secret_type=eso.DOCKERCONFIG,
                               set_namespace=True)])
    every = secret(A, "all")
    assert every and set(every["data"]) == {"ConnectionStrings__Db", "Other"}
    pull = secret(A, "regcred")
    assert pull and pull["type"] == "kubernetes.io/dockerconfigjson"
    assert json.loads(base64.b64decode(pull["data"][".dockerconfigjson"]))["auths"]["reg.example"]
