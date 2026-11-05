"""Platform techniques (containerizer/techniques.py, rules/40-plan.yaml `resolves`): findings that the generated
configuration satisfies count as `config`, so the application's rating goes up while its code stays untouched."""
import hashlib
import json
from pathlib import Path

import yaml

from containerizer.assess import assess
from containerizer.generate import X509_STORE_DIR, generate_app
from containerizer.refactor import skip_reason
from containerizer.rules import load_rules
from tests.test_engine import web_app

EXAMPLE = Path(__file__).resolve().parent.parent / "examples" / "platform-techniques"
TECHNIQUES = {"plan-machine-hostname", "plan-x509-user-store", "plan-special-folder-workdir"}


def _tree_hash(root: Path) -> str:
    h = hashlib.sha256()
    for p in sorted(root.rglob("*")):
        if p.is_file():
            h.update(str(p.relative_to(root)).encode() + b"\0" + p.read_bytes())
    return h.hexdigest()


def _found(root, rules=None):
    return {f.rule.id: f for c in assess(root, rules=rules).components for f in c.findings}


def test_example_is_rated_a_with_techniques_and_b_without():
    without = [r for r in load_rules() if r.id not in TECHNIQUES]
    assert assess(EXAMPLE, rules=without).rating == "B"
    a = assess(EXAMPLE)
    assert a.rating == "A"
    f = {x.rule.id: x for x in a.components[0].findings}
    assert f["os-machine-name-switch"].resolved_by == "plan-machine-hostname"
    assert f["os-special-folder-windows"].resolved_by == "plan-special-folder-workdir"
    assert f["cert-store"].resolved_by == "plan-x509-user-store"
    assert {f[k].severity for k in ("os-machine-name-switch", "os-special-folder-windows")} == {"config"}
    d = f["os-machine-name-switch"].to_dict()
    assert d["severity"] == "config" and d["rule_severity"] == "refactor" and d["resolved_by"] == "plan-machine-hostname"
    # never sent to a code-changing refactoring
    assert "generated configuration" in skip_reason(d)


def test_generated_configuration_and_untouched_code(tmp_path):
    before = _tree_hash(EXAMPLE)
    generate_app(assess(EXAMPLE), tmp_path)
    assert _tree_hash(EXAMPLE) == before                 # nothing written into the application
    comp = tmp_path / "legacy-web"
    plan = json.loads((comp / "plan.json").read_text())
    assert TECHNIQUES <= set(plan["applied"])
    assert plan["resolved"]["plan-machine-hostname"] == ["os-machine-name-switch"]
    assert TECHNIQUES <= {r["rule"] for r in plan["reasons"]}
    assert all(r.get("refs") for r in plan["reasons"] if r["rule"] in TECHNIQUES)
    header = (comp / "Dockerfile").read_text().split("\nFROM ", 1)[0]
    for t in TECHNIQUES:
        assert f"# - {t}:" in header
    docs = [d for d in yaml.safe_load_all((comp / "k8s.yaml").read_text()) if d]
    pod = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]
    assert pod["hostname"] == "prodweb01"
    mounts = {m["mountPath"]: m for m in pod["containers"][0]["volumeMounts"]}
    assert mounts[f"{X509_STORE_DIR}/my"]["readOnly"] is True
    assert "/app/Acme" in mounts
    vols = {v["name"]: v for v in pod["volumes"]}
    assert vols["x509-my"]["secret"] == {"secretName": "legacy-web-x509-my", "optional": True, "defaultMode": 0o440}
    # the certificate comes from the secret store, never from Git
    assert any(d["kind"] == "ExternalSecret" and d["metadata"]["name"] == "legacy-web-x509-my" for d in docs)


def test_machine_name_case_sensitive_upper_case_stays_refactor(tmp_path):
    # Kubernetes host names are lower-case: "PRODWEB01" == MachineName can never match in a pod
    web_app(tmp_path, '''
        class A { bool P() => Environment.MachineName == "PRODWEB01"; }''')
    f = _found(tmp_path)["os-machine-name-switch"]
    assert not f.resolved_by and f.severity == "refactor"


def test_machine_name_case_insensitive_and_switch(tmp_path):
    web_app(tmp_path, '''
        class A { bool P() => Environment.MachineName.Equals("PRODWEB01", StringComparison.OrdinalIgnoreCase); }''')
    assert _found(tmp_path)["os-machine-name-switch"].resolved_by == "plan-machine-hostname"
    other = tmp_path / "b"
    web_app(other, '''
        class A { string P() { switch (Environment.MachineName.ToUpper()) {
            case "TESTWEB01": return "test"; case "PRDWEB01": return "prod"; default: return "dev"; } } }''')
    a = assess(other)
    assert a.components[0].findings and a.rating == "A"
    from containerizer.generate import make_plan
    plan = make_plan(a, a.components[0])
    assert plan["hostname"] == "prdweb01"                 # the production-looking name
    assert "testweb01" in next(r["why"] for r in plan["reasons"] if r["rule"] == "plan-machine-hostname")


def test_local_machine_certificate_store_is_not_resolved(tmp_path):
    # LocalMachine\\My does not exist on Linux: no folder makes that lookup work
    web_app(tmp_path, '''
        class A { void P() { var s = new X509Store(StoreName.My, StoreLocation.LocalMachine); s.Open(OpenFlags.ReadOnly); } }''')
    f = _found(tmp_path)
    assert "cert-store-localmachine-code" in f
    assert not f["cert-store"].resolved_by


def test_special_folder_in_a_variable_stays_refactor(tmp_path):
    web_app(tmp_path, r'''
        class A { string P() { var pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
                               return Path.Combine(pf, "Acme", "x.xml"); } }''')
    f = _found(tmp_path)["os-special-folder-windows"]
    assert not f.resolved_by and f.severity == "refactor"


def test_special_folder_backslash_literal_stays_refactor(tmp_path):
    # "Acme\\x.xml" is one file name with a backslash on Linux, not a folder a volume can provide
    web_app(tmp_path, r'''
        class A { string P() => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Acme\\x.xml"); }''')
    assert not _found(tmp_path)["os-special-folder-windows"].resolved_by
