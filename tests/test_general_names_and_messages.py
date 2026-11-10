"""Names and messages that are not those of the sample applications the rules were first written against:
projects called Lab or Simulator are applications, failure diagnoses read the framework's own messages and any
host name, and a README's prose alone does not make a refactoring finding."""
from containerizer import verify
from containerizer.assess import assess, classify_role
from containerizer.rules import load_rules
from containerizer.scan import scan
from tests.test_engine import web_app, write
from tests.test_role_false_positives import proj

RULES = load_rules()
WEB = "Microsoft.NET.Sdk.Web"
PROGRAM = "var app = WebApplication.CreateBuilder(args).Build(); app.Run();"


def test_lab_and_simulator_are_applications_and_stubs_are_tools(tmp_path):
    for name in ("Clinic.Lab", "Pricing.Simulator", "Acme.PaymentStubs", "Acme.CarrierMocks"):
        proj(tmp_path, f"src/{name}/{name}.csproj", sdk=WEB)
        write(tmp_path, f"src/{name}/Program.cs", PROGRAM)
    repo = scan(tmp_path)
    roles = {p.name: classify_role(repo, p, RULES)[0] for p in repo.projects}
    assert roles == {"Clinic.Lab": "web", "Pricing.Simulator": "web", "Acme.PaymentStubs": "tool",
                     "Acme.CarrierMocks": "tool"}


def _run_rule(log: str):
    hit = verify.diagnose(log, "run", verify.load_failures())
    return hit[0]["id"] if hit else None


def test_missing_setting_is_read_from_the_frameworks_messages():
    for log in ("System.InvalidOperationException: Connection string 'Default' not found.",
                "System.InvalidOperationException: Section 'Smtp' not found in configuration.",
                "System.InvalidOperationException: No connection string named 'Shop' could be found in the "
                "application config file.",
                "System.InvalidOperationException: Storage:AccountName is required."):
        assert _run_rule(log) == "run-missing-config-value", log
    # not about configuration: not counted as "only a setting is missing"
    for log in ("System.InvalidOperationException: The Body is required for this request.",
                "System.InvalidOperationException: Type 'Shop.Order' not found in assembly 'Shop'."):
        assert _run_rule(log) != "run-missing-config-value", log


def test_unreachable_host_and_certificate_store_of_any_name():
    assert _run_rule("SocketException (11): Resource temporarily unavailable (db.intra.example.com:1433)") \
        == "run-dns-unreachable"
    assert _run_rule("Unhandled exception. Signing certificate with thumbprint AB12 was not found in "
                     "CurrentUser\\My") == "run-cert-store"


def test_readme_prose_alone_is_not_a_distributed_transaction(tmp_path):
    web_app(tmp_path)
    write(tmp_path, "src/Web/README.md", "The new version no longer needs MSDTC or FILESTREAM. Service account: "
                                         "svc-web$. Run Install-Database.ps1 first.")
    ids = {f.rule.id for c in assess(tmp_path).components for f in c.findings}
    assert not ids & {"msdtc", "sql-filestream", "gmsa", "vendor-install-required"}
