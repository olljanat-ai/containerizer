"""The appliance's secret store: ESO install, store definition and the shell helpers that fill it."""
import base64
import re
import subprocess
from pathlib import Path

import yaml

from containerizer import eso

ROOT = Path(__file__).resolve().parent.parent
ROOTFS = ROOT / "appliance" / "rootfs"
LIB = ROOTFS / "usr/lib/containerizer/lib/secret-store.sh"
HELMCHART = ROOTFS / "var/lib/rancher/k3s/server/manifests/external-secrets.yaml"


def test_eso_chart_and_images_are_pinned():
    chart = yaml.safe_load(HELMCHART.read_text())
    tgz = chart["spec"]["chart"].rsplit("/", 1)[1]
    df = (ROOT / "appliance" / "Dockerfile").read_text()
    assert f"static/charts/{tgz}" in df                       # the image ships the chart the HelmChart names
    assert re.search(r"ESO_CHART_DIGEST=sha256:[0-9a-f]{64}", df) and "sha256sum -c" in df
    values = yaml.safe_load(chart["spec"]["valuesContent"])
    for part in (values, values["webhook"], values["certController"]):
        assert re.fullmatch(r"v[\d.]+@sha256:[0-9a-f]{64}", part["image"]["tag"])
        assert part["resources"]["limits"]["memory"]
    assert tgz == f"external-secrets-{values['image']['tag'].split('@')[0][1:]}.tgz"
    # features the sandbox does not use are off, with their CRDs
    for kind in ("PushSecret", "ClusterPushSecret", "ClusterExternalSecret", "ClusterGenerator"):
        assert values[f"process{kind}"] is False and values["crds"][f"create{kind}"] is False


def _run(script: str) -> subprocess.CompletedProcess:
    """Source the helpers with a fake kubectl that records its arguments and stdin (the helpers discard
    kubectl's output); the record is returned as stdout."""
    p = subprocess.run(["bash", "-c", f"""set -euo pipefail
cap=$(mktemp)
k() {{ {{ echo "ARGS: $*"; cat; echo "---END"; }} >> "$cap"; }}
. {LIB}
{script}
cat "$cap"; rm -f "$cap" """], capture_output=True, text=True)
    p.stdout = p.stdout.removeprefix("ARGS: ") if p.stdout.startswith("ARGS: ") else p.stdout
    return p


def test_store_setup_matches_the_generated_store():
    out = _run("cz_store_setup").stdout
    docs = [d for d in yaml.safe_load_all(out.split("\n", 1)[1].split("---END")[0]) if d]
    store = next(d for d in docs if d["kind"] == "ClusterSecretStore")
    want = next(d for d in eso.secret_store() if d["kind"] == "ClusterSecretStore")
    assert store["metadata"]["name"] == want["metadata"]["name"]
    assert store["spec"] == want["spec"]
    quota = next(d for d in docs if d["kind"] == "ResourceQuota")
    assert quota["spec"]["hard"] == {"pods": "0"}


def test_store_put_keeps_values_off_the_command_line():
    p = _run("cz_store_put shop--web --manager ci 'ConnectionStrings__Main=Server=db;Password=s3cret' Other=x")
    assert p.returncode == 0, p.stderr
    args, body = p.stdout.split("\n", 1)
    assert "s3cret" not in args and "--server-side" in args and "--field-manager=ci" in args
    doc = yaml.safe_load(body.split("---END")[0])
    assert doc["metadata"] == {"name": "shop--web", "namespace": "containerizer-secrets",
                               "labels": {"app.kubernetes.io/managed-by": "containerizer-appliance"}}
    assert base64.b64decode(doc["data"]["ConnectionStrings__Main"]).decode() == "Server=db;Password=s3cret"
    assert "s3cret" not in body                                  # base64 only
    for bad in ("'Bad/Name' a=b", "shop--web 'a b=c'", "shop--web"):
        assert _run(f"cz_store_put {bad}").returncode != 0


def test_store_grant_names_exact_keys(tmp_path):
    out = _run("cz_store_grant kube-system containerizer-sandbox-tls other").stdout
    docs = [d for d in yaml.safe_load_all(out.split("\n", 1)[1].split("---END")[0]) if d]
    sa, role, rb = docs
    assert sa["metadata"]["namespace"] == "kube-system" and sa["automountServiceAccountToken"] is False
    assert role["metadata"] == {"name": "app-secrets-reader-kube-system", "namespace": "containerizer-secrets",
                                "labels": {"app.kubernetes.io/managed-by": "containerizer-appliance"}}
    assert role["rules"] == [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"],
                              "resourceNames": ["containerizer-sandbox-tls", "other"]}]
    # the same Role the generator would write for that namespace
    gen = eso.store_access("kube-system", ["containerizer-sandbox-tls", "other"])
    assert (gen[0]["metadata"]["name"], gen[0]["rules"]) == (role["metadata"]["name"], role["rules"])
    assert rb["subjects"] == gen[1]["subjects"]


def test_store_put_keys_that_look_like_yaml_booleans_stay_strings():
    p = _run("cz_store_put shop--web n=1 yes=2 on=3 off=4")
    assert p.returncode == 0, p.stderr
    doc = yaml.safe_load(p.stdout.split("\n", 1)[1].split("---END")[0])
    assert sorted(doc["data"]) == ["n", "off", "on", "yes"]          # unquoted, YAML read them as true/false
