"""Lab mail: the lab's Mail (SMTP) service (labservices.py `smtp`), the overrides of an app's SMTP settings, the
system agent's mailbox reader (labmail.py) and Admin -> Lab mail (admin_labmail.py)."""
import json
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).parent))

from containerizer import admin_labmail, generate, labmail, labservices as L
from containerizer.assess import assess
from containerizer.harden import lint_manifests
from test_engine import web_app, write

MAILER = """
public sealed class Mailer
{
    public void Send(MailOptions o, System.Net.Mail.MailMessage m)
    {
        using var client = new System.Net.Mail.SmtpClient(o.Host, o.Port) { EnableSsl = o.EnableSsl };
        if (!string.IsNullOrEmpty(o.PickupFolder))
        {
            client.DeliveryMethod = System.Net.Mail.SmtpDeliveryMethod.SpecifiedPickupDirectory;
            client.PickupDirectoryLocation = o.PickupFolder;
        }
        client.Send(m);
    }
}
"""


@pytest.mark.parametrize("key,value,kind", [
    ("Mail:Host", "smtp.corp.local", "smtp:host"),
    ("Smtp:Port", 587, "smtp:port"),
    ("EmailSettings:SmtpServer", "mx.corp.local", "smtp:host"),
    ("DocControl:Packager:Mail:Host", "smtp.corp.local", "smtp:host"),
    ("Worker:SmtpHost", "smtp.corp.local", "smtp:host"),
    ("Worker:MailPickupFolder", "D:\\Mail\\Pickup", "smtp:pickup"),
    ("Mail:PickupFolder", "App_Data/mail", "smtp:pickup"),
    ("Smtp:EnableSsl", True, "smtp:tls"),
    ("Mail:DeliveryMethod", "SpecifiedPickupDirectory", "smtp:delivery"),
    ("Mail:Mode", "Pickup", "smtp:mode"),
    ("Mail:Mode", "Smtp", None),
    ("Mail:SecureSocketOptions", "StartTls", "smtp:secure"),
    ("Mail:From", "Shop <noreply@example.com>", None),
    ("Mail:UseDefaultCredentials", True, None),
    ("Mail:Password", "x", None),
    ("Worker:MailFrom", "a@example.com", None),
    ("SendGrid:Host", "api.sendgrid.com", None),
    ("Mail:Host", "https://mail.example.com/api", None),
])
def test_classify_smtp_settings(key, value, kind):
    assert L.classify(key, value) == kind


def _app(tmp_path, settings, code=MAILER):
    web_app(tmp_path / "app", code=code)
    write(tmp_path / "app", "src/Web/appsettings.json", json.dumps(settings))
    return assess(tmp_path / "app")


def _docs(path: Path) -> list[dict]:
    return [d for d in yaml.safe_load_all(path.read_text()) if d]


def test_generate_points_the_apps_mail_at_the_lab_mailbox(tmp_path):
    a = _app(tmp_path, {"Mail": {"Host": "smtp.corp.local", "Port": 587, "EnableSsl": True, "PickupFolder": "App_Data/mail",
                                 "From": "Shop <noreply@example.com>"}})
    out, rep = tmp_path / "out", {}
    generate.generate_app(a, out, lab={"smtp"}, lab_report=rep)
    assert rep["provided"] == ["smtp"]
    docs = _docs(out / "web" / "k8s.yaml")
    env = {e["name"]: e for e in next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]["env"]}
    assert env["Mail__Host"]["valueFrom"]["secretKeyRef"] == {"name": "lab-smtp", "key": "host"}
    assert env["Mail__Port"]["valueFrom"]["secretKeyRef"] == {"name": "lab-smtp", "key": "port"}
    assert env["Mail__EnableSsl"]["value"] == "false"
    assert env["Mail__PickupFolder"]["value"] == ""            # an empty folder: the app sends over SMTP
    assert "Mail__From" not in env
    pol = next(d for d in docs if d["kind"] == "NetworkPolicy" and "Egress" in d["spec"]["policyTypes"])
    lab = [r for r in pol["spec"]["egress"] if r["to"][0].get("namespaceSelector", {}).get("matchLabels") ==
           {"kubernetes.io/metadata.name": L.LAB_NS}]
    assert lab == [L.egress_rule("smtp", generate.app_ns(a.name))] and lab[0]["ports"][0]["port"] == 1025
    es = _docs(out / "lab" / "k8s.yaml")
    assert [d["metadata"]["name"] for d in es] == ["lab-smtp"]
    everything = [d for f in out.rglob("k8s.yaml") for d in _docs(f)]
    assert [v for v in lint_manifests(everything) if v.severity == "error"] == []


def test_mail_without_settings_is_noted(tmp_path):
    a = _app(tmp_path, {"Logging": {"LogLevel": {"Default": "Information"}}})
    out, rep = tmp_path / "out", {}
    generate.generate_app(a, out, lab={"smtp"}, lab_report=rep)
    assert rep["provided"] == ["smtp"]
    readme = (out / "lab" / "README.md").read_text()
    assert "No SMTP host setting found" in readme and "pickup folder" in readme


def test_the_mailbox_is_hardened_and_sends_nothing_on():
    docs = L.per_app_manifests("smtp", "shop", "i@sha256:" + "a" * 64, L.new_credentials("smtp", "shop"))
    assert [d["kind"] for d in docs] == ["PersistentVolumeClaim", "Deployment", "Service", "NetworkPolicy"]
    c = next(d for d in docs if d["kind"] == "Deployment")["spec"]["template"]["spec"]["containers"][0]
    args = " ".join(c["args"])
    assert f"--listen 127.0.0.1:{L.MAIL_API_PORT}" in args and "relay" not in args and "forward" not in args
    assert c["securityContext"]["readOnlyRootFilesystem"] and c["securityContext"]["runAsNonRoot"]
    svc = next(d for d in docs if d["kind"] == "Service")["spec"]["ports"][0]
    assert (svc["port"], svc["targetPort"]) == (25, 1025)
    pol = next(d for d in docs if d["kind"] == "NetworkPolicy")["spec"]["ingress"][0]
    assert pol["ports"] == [{"port": 1025, "protocol": "TCP"}]      # SMTP only: the API stays on the loopback
    assert L.new_credentials("smtp", "shop") == {"host": "smtp-shop.containerizer-lab.svc.cluster.local", "port": "25"}
    assert L.complete("smtp", "shop", L.new_credentials("smtp", "shop"))


def test_a_config_from_before_the_service_gets_its_default(tmp_path):
    p = tmp_path / "lab.json"
    old = {k: v for k, v in L.defaults().items() if k != "smtp"}
    p.write_text(json.dumps({"services": {**old, "redis": True}}))
    got = L.load_config(p)["services"]
    assert got["smtp"] is L.SERVICES["smtp"].default and got["redis"] is True


# ------------------------------------------------------------------------------- the agent's mailbox reader

class Kube:
    cmd = ["kubectl"]
    kubeconfig = ""

    def get(self, args):
        name = args[-1].split("app.kubernetes.io/name=")[1]
        return {"items": [{"metadata": {"name": f"{name}-pod"}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}}]}


def _agent(tmp_path, ready=("shop", "crm")):
    st = tmp_path / "lab-status.json"
    st.write_text(json.dumps({"services": {"smtp": {"ready": list(ready) + ["kube-system"]}}}))
    calls = []

    def runner(argv, stdin, timeout=0, cap=0):
        calls.append(argv)
        url = argv[-1]
        ns = argv[argv.index("exec") + 2].removeprefix("smtp-").removesuffix("-pod")
        if url.endswith("/api/v1/messages?limit=100"):
            msgs = [{"ID": f"{ns}Msg0000{i}", "Subject": f"{ns} {i}", "Created": f"2026-11-0{i + 1}T10:00:00Z",
                     "From": {"Address": "noreply@example.com"}, "To": [{"Name": "John Doe", "Address": "john@example.com"}]}
                    for i in range(2)]
            return 0, json.dumps({"total": 2, "messages": msgs}), "", ""
        return 0, json.dumps({"ID": url.rsplit("/", 1)[1], "Subject": "Hi", "Text": "hello", "HTML": "<p>hello</p>",
                              "Attachments": [{"FileName": "a.pdf", "ContentType": "application/pdf", "Size": 3}]}), "", ""
    return labmail.Agent(kube=Kube(), lab_status=st, runner=runner), calls


def test_the_agent_lists_every_mailbox_newest_first(tmp_path):
    agent, calls = _agent(tmp_path)
    got = agent.list({})
    assert {b["namespace"] for b in got["mailboxes"]} == {"shop", "crm"}          # never a system namespace
    assert [m["created"][:10] for m in got["messages"]] == ["2026-11-02", "2026-11-02", "2026-11-01", "2026-11-01"]
    for argv in calls:                                      # wget on the pod's loopback, no shell
        assert argv[argv.index("--") + 1] == "wget" and argv[-1].startswith(f"http://127.0.0.1:{L.MAIL_API_PORT}/api/v1/")
        assert "sh" not in argv and "-c" in argv and argv[argv.index("-c") + 1] == "smtp"
    with pytest.raises(labmail.MailError):
        agent.list({"namespace": "kube-system"})


def test_the_agent_shows_one_message_and_checks_the_id(tmp_path):
    agent, calls = _agent(tmp_path)
    m = agent.show({"namespace": "shop", "message": "shopMsg00001"})["message"]
    assert m["text"] == "hello" and m["files"][0]["name"] == "a.pdf" and m["attachments"] == 1
    for bad in ({"namespace": "shop", "message": "../../api/v1/info"}, {"namespace": "other", "message": "shopMsg00001"}):
        with pytest.raises(labmail.MailError):
            agent.show(bad)


def test_agent_request_answers(tmp_path):
    agent, _ = _agent(tmp_path)
    answers = tmp_path / "answers"
    ident = "a" * 32
    labmail.agent_request({"id": ident, "op": "list", "expires_at": time.time() + 30}, answers, agent)
    assert len(json.loads((answers / f"{ident}.json").read_text())["messages"]) == 4
    labmail.agent_request({"id": ident, "op": "list", "expires_at": time.time() - 1}, answers, agent)
    assert "expired" in json.loads((answers / f"{ident}.json").read_text())["error"]


# ------------------------------------------------------------------------------- the page

class Conn:
    def cursor(self, as_dict=False):
        return self

    def execute(self, *a):
        pass

    def fetchall(self):
        return [{"Namespace": "shop", "ApplicationId": 7, "Name": "Web Shop"}]

    def rollback(self):
        pass


def _adm(tmp_path):
    agent, _ = _agent(tmp_path)

    def ask(action, user, name, wait=0, **args):
        assert action == "labmail"
        try:
            return agent.list(args) if args["op"] == "list" else agent.show(args)
        except labmail.MailError as ex:
            return {"error": str(ex)}
    views = []
    return SimpleNamespace(system=SimpleNamespace(ask=ask), log_access=lambda *a, **k: views.append(a),
                           _shell=lambda s, a, title, tab, body, flash="": body, views=views)


def test_the_page_shows_the_inbox_and_a_message_as_text(tmp_path):
    adm, s, a = _adm(tmp_path), SimpleNamespace(user="john@example.com", name="John Doe"), SimpleNamespace(admin=False, operator=True)
    assert admin_labmail.enabled(adm, a) and not admin_labmail.enabled(adm, SimpleNamespace(admin=False, operator=False))
    r = admin_labmail.route(adm, Conn(), s, a, "GET", ["lab-mail"], {}, {})
    assert r.status == 200 and "Web Shop" in r.body and "/admin/lab-mail/shop/shopMsg00001" in r.body
    r = admin_labmail.route(adm, Conn(), s, a, "GET", ["lab-mail", "shop", "shopMsg00001"], {}, {})
    assert r.status == 200 and "hello" in r.body and "<p>hello</p>" not in r.body and "&lt;p&gt;hello" in r.body
    assert admin_labmail.route(adm, Conn(), s, a, "GET", ["lab-mail", "shop", "x/../y"], {}, {}).status == 404
    assert admin_labmail.route(adm, Conn(), s, a, "POST", ["lab-mail"], {}, {}).status == 405
    assert len(adm.views) == 2


def test_html_text_drops_scripts_and_keeps_links():
    t = admin_labmail.html_text("<html><head><style>p{}</style></head><body><script>alert(1)</script>"
                                "<p>Hi <a href='https://example.com/x'>there</a></p></body></html>")
    assert "alert" not in t and "p{}" not in t and "Hi there [https://example.com/x]" in t
