"""Links between applications (links.py, docs/egress.md#links-between-applications): the deterministic match, the
observed calls, the LLM's proposals, confirming, the NetworkPolicies of both sides, connectivity.yaml, the
results page and the portfolio view."""
import json
from datetime import datetime
from urllib.parse import urlencode

import pytest
import yaml

from containerizer import connectivity as cy
from containerizer import links as lk

from test_llm_queue import FakeConn

EGRESS_NET = {"components": [{"name": "Egress.Demo", "k8s": "egress-demo", "role": "web", "port": 8080, "service_port": 80,
                              "egress": [], "lab_services": {}, "destinations": [
                                  {"host": "orders-demo.orders-demo", "port": 80, "source": "config", "file": "appsettings.json",
                                   "line": 5, "quote": '"Orders": { "Url": "http://orders-demo.orders-demo/api/orders" }'},
                                  {"host": "billing.corp.local", "port": 443, "source": "config", "file": "appsettings.json",
                                   "line": 6, "quote": '"BillingApi": { "BaseUrl": "https://billing.corp.local" }'},
                                  {"host": "api.github.com", "port": 443, "source": "config", "file": "appsettings.json",
                                   "line": 4, "quote": "x"}]}]}
ORDERS_NET = {"components": [{"name": "Orders.Demo", "k8s": "orders-demo", "role": "web", "port": 8080, "service_port": 80,
                              "egress": [], "lab_services": {}, "destinations": []}]}


def test_identities_and_internal_looking_names():
    assert lk.identities("orders-demo", "orders-demo", "https://orders-demo.sandbox.example/") == {
        "orders-demo.orders-demo", "orders-demo.orders-demo.svc", "orders-demo.orders-demo.svc.cluster.local",
        "orders-demo.sandbox.example"}
    for h in ("billing", "billing.corp.local", "x.internal", "erp.intranet"):
        assert lk.internal_looking(h), h
    for h in ("api.github.com", "localhost", "10.1.2.3", ""):
        assert not lk.internal_looking(h), h


def _conn(links=(), flows=()):
    apps = [{"ApplicationId": 1, "ApplicationName": "egress-demo", "ProductName": "Shop", "RepositoryUrl": None,
             "NetworkJson": json.dumps(EGRESS_NET)},
            {"ApplicationId": 2, "ApplicationName": "orders-demo", "ProductName": "Orders", "RepositoryUrl": None,
             "NetworkJson": json.dumps(ORDERS_NET)}]
    return FakeConn({r"FROM cz.vNetworkLatest n JOIN": apps,
                     r"FROM cz.vSandboxNamespace WHERE Own = 1": [{"Namespace": "egress-demo", "ApplicationId": 1},
                                                                       {"Namespace": "orders-demo", "ApplicationId": 2}],
                     r"FROM cz.vSandboxLatest WHERE Url": [],
                     r"SELECT FromApplicationId, FromComponent, Destination, Port FROM cz.ComponentLink": list(links),
                     r"FROM cz.vEgressFlow f": list(flows)})


def test_find_links_matches_configured_names_and_records_internal_ones():
    conn = _conn()
    out = lk.find_links(conn, log=lambda m: None)
    ins = [p for _, p in conn.sql(r"INSERT cz.ComponentLink")]
    got = {(p[7], p[10], p[11], p[12], p[13]) for p in ins}
    assert ("orders-demo.orders-demo", 2, "orders-demo", "config", "proposed") in got
    assert ("billing.corp.local", None, None, "config", "unresolved") in got
    assert not any(p[7] == "api.github.com" for p in ins)                       # public: egress, not a link
    assert out["config"] == 1 and out["unresolved"] == 1
    # already known: nothing new
    conn = _conn(links=[{"FromApplicationId": 1, "FromComponent": "egress-demo", "Destination": "orders-demo.orders-demo",
                         "Port": 80}, {"FromApplicationId": 1, "FromComponent": "egress-demo",
                                       "Destination": "billing.corp.local", "Port": 443}])
    lk.find_links(conn, log=lambda m: None)
    assert not conn.sql(r"INSERT cz.ComponentLink")


def test_an_observed_call_to_another_applications_pod_is_a_link_unless_configured():
    flow = {"ApplicationId": 1, "Component": "egress-demo", "Destination": "orders-demo.orders-demo.svc.cluster.local",
            "Port": 8080, "Protocol": "TCP", "Packets": 4, "LastSeen": datetime(2026, 11, 2, 4)}
    known = [{"FromApplicationId": 1, "FromComponent": "egress-demo", "Destination": "orders-demo.orders-demo", "Port": 80},
             {"FromApplicationId": 1, "FromComponent": "egress-demo", "Destination": "billing.corp.local", "Port": 443}]
    conn = _conn(links=known, flows=[flow])
    lk.find_links(conn, log=lambda m: None)
    assert not conn.sql(r"INSERT cz.ComponentLink")                             # the configured link covers it
    conn = _conn(links=known[1:], flows=[flow])
    net = json.loads(conn.answers[r"FROM cz.vNetworkLatest n JOIN"][0]["NetworkJson"])
    net["components"][0]["destinations"] = net["components"][0]["destinations"][1:]
    conn.answers[r"FROM cz.vNetworkLatest n JOIN"][0]["NetworkJson"] = json.dumps(net)
    lk.find_links(conn, log=lambda m: None)
    (sql, p), = conn.sql(r"INSERT cz.ComponentLink")
    assert (p[7], p[10], p[11], p[12], p[13]) == ("orders-demo.orders-demo.svc.cluster.local", 2, "orders-demo",
                                                  "observed", "proposed")


def test_shortlist_and_the_llm_answer_is_checked():
    cands = [{"ApplicationId": 3, "ApplicationName": "billing-service", "ComponentName": "Billing.Api", "ProjectPath": "src/Billing.Api",
              "Role": "web", "ProductName": "Finance"},
             {"ApplicationId": 2, "ApplicationName": "orders-demo", "ComponentName": "Orders.Demo", "ProjectPath": "x", "Role": "web"}]
    d = {"link_id": 9, "from": "egress-demo", "destination": "billing.corp.local", "port": 443,
         "evidence": [{"file": "appsettings.json", "line": 6, "quote": "BillingApi"}], "quote": "BillingApi"}
    d["candidates"] = lk.shortlist(d, cands)
    assert d["candidates"][0]["ApplicationName"] == "billing-service"
    prompts = []
    conn = FakeConn()

    def ask(p):
        prompts.append(p)
        return {"links": [{"destination": "billing.corp.local", "port": 443, "candidate": 1, "confidence": 0.8,
                           "reasoning": "BillingApi names the billing service"}]}
    out = lk.handler({"JobId": 5, "Payload": {"app": "egress-demo", "destinations": [d]}, "_connect": lambda: conn}, ask=ask)
    assert "billing.corp.local" in prompts[0] and "Never guess" in prompts[0]
    assert out["summary"] == "1 destination(s): 1 linked, 0 not matched"
    (sql, p), = conn.sql(r"UPDATE cz.ComponentLink SET ToApplicationId")
    assert p[:3] == (3, "billing-api", 0.8) and p[-1] == 9
    # a candidate out of range, or low confidence: not linked
    for bad in ({"candidate": 7, "confidence": 0.9}, {"candidate": 1, "confidence": 0.2}, {"candidate": 0, "confidence": 0.9}):
        conn = FakeConn()
        lk.handler({"JobId": 5, "Payload": {"app": "a", "destinations": [d]}, "_connect": lambda: conn},
                   ask=lambda p: {"links": [{"destination": "billing.corp.local", "port": 443, "reasoning": "r", **bad}]})
        assert not conn.sql(r"SET ToApplicationId") and conn.sql(r"UPDATE cz.ComponentLink SET Reason")


def _policy(name, part):
    from containerizer.harden import network_policy
    return network_policy(name, {"app.kubernetes.io/name": name, "app.kubernetes.io/part-of": part}, 8080, [])


def test_both_sides_networkpolicies():
    caller, callee = _policy("egress-demo", "egress-demo"), _policy("orders-demo", "orders-demo")
    out = [{"component": "egress-demo", "status": "linked", "target": {"namespace": "orders-demo", "component": "orders-demo",
                                                                       "port": 8080}}]
    inn = [{"component": "orders-demo", "source": "link", "namespace": "egress-demo", "from_component": "egress-demo",
            "target_port": 8080}]
    assert lk.apply_links([caller], "egress-demo", out, []) and not lk.apply_links([caller], "egress-demo", out, [])
    assert caller["spec"]["egress"][-1] == {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "orders-demo"}},
                                                    "podSelector": {"matchLabels": {"app.kubernetes.io/name": "orders-demo"}}}],
                                            "ports": [{"port": 8080, "protocol": "TCP"}]}
    assert lk.apply_links([callee], "orders-demo", [], inn)
    assert callee["spec"]["ingress"][-1]["from"][0]["namespaceSelector"]["matchLabels"] == {"kubernetes.io/metadata.name": "egress-demo"}


LINK = {"LinkId": 4, "FromApplicationId": 1, "FromApplication": "egress-demo", "FromComponent": "egress-demo",
        "Destination": "orders-demo.orders-demo", "Port": 80, "Protocol": "TCP", "ToApplicationId": 2,
        "ToApplication": "orders-demo", "ToComponent": "orders-demo", "ToNamespace": "orders-demo", "FromNamespace": "egress-demo",
        "Method": "config", "Status": "confirmed", "Confidence": 0.95, "Reason": "the configuration names it",
        "Evidence": json.dumps([{"file": "appsettings.json", "line": 5, "quote": "q"}]), "DecidedBy": "john.doe@example.com",
        "DecidedAt": datetime(2026, 11, 2, 5)}


def test_connectivity_names_the_other_application_on_both_sides():
    flows = [{"Namespace": "egress-demo", "Component": "egress-demo", "Destination": "orders-demo.orders-demo.svc.cluster.local",
              "Named": True, "DestinationIp": "10.42.0.40", "Port": 8080, "Protocol": "TCP", "Packets": 3,
              "FirstSeen": datetime(2026, 11, 2, 4), "LastSeen": datetime(2026, 11, 2, 4), "Pods": "[]"}]
    doc = cy.model("egress-demo", EGRESS_NET, flows, [], links_out=[LINK, {**LINK, "LinkId": 5, "Destination": "billing.corp.local",
                                                                           "Port": 443, "Status": "unresolved",
                                                                           "ToApplicationId": None, "Reason": "no match"}])
    e, = [x for x in doc["outbound"] if x["destination"] == "orders-demo.orders-demo"]
    assert (e["type"], e["status"], e["target"]["application"], e["target"]["service"], e["target"]["port"]) == \
        ("component", "linked", "orders-demo", "orders-demo.orders-demo.svc.cluster.local", 8080)
    assert "link-config" in e["sources"] and e["linked_by"] == "john.doe@example.com"
    assert e["observed"]["packets"] == 3                                        # the blocked call, folded into the link
    assert not any(x["destination"].endswith(".svc.cluster.local") for x in doc["outbound"])
    b, = [x for x in doc["outbound"] if x["destination"] == "billing.corp.local"]
    assert b["link"]["status"] == "unresolved" and any(f["kind"] == "link" for f in doc["findings"])
    callee = cy.model("orders-demo", ORDERS_NET, links_in=[LINK])
    i, = [x for x in callee["inbound"] if x["source"] == "link"]
    assert (i["from"], i["namespace"], i["from_component"], i["port"]) == ("egress-demo/egress-demo", "egress-demo", "egress-demo", 8080)
    # later scans: both kept, the generator opens them
    out, inn = cy.linked_entries(doc)
    assert len(out) == 1 and cy.linked_entries(callee)[1] == [i]
    again = cy.model("egress-demo", EGRESS_NET, existing={"outbound": out})
    assert [x for x in again["outbound"] if x["destination"] == "orders-demo.orders-demo"][0] == out[0]
    assert out[0]["sandbox"]["reachable"] is True
    again = cy.model("orders-demo", ORDERS_NET, existing={"inbound": [i]})
    assert i in again["inbound"]
    assert "cf-linked" in cy.svg(doc) and "orders-demo / orders-demo :8080" in cy.svg(doc)


def test_generate_opens_confirmed_links(tmp_path):
    from pathlib import Path
    from containerizer.assess import assess
    from containerizer.generate import generate_app
    demo = Path(__file__).resolve().parent.parent / "examples" / "orders-demo"
    a = assess(demo)
    inn = [{"component": "orders-demo", "source": "link", "namespace": "egress-demo", "from_component": "egress-demo",
            "from": "egress-demo/egress-demo", "port": 8080, "protocol": "TCP", "target_port": 8080}]
    generate_app(a, tmp_path, links=([], inn))
    pol = [d for d in yaml.safe_load_all((tmp_path / "orders-demo" / "k8s.yaml").read_text())
           if d and d["kind"] == "NetworkPolicy" and d["metadata"]["name"] == "orders-demo"][0]
    assert pol["spec"]["ingress"][-1]["from"][0]["namespaceSelector"]["matchLabels"]["kubernetes.io/metadata.name"] == "egress-demo"
    assert cy.read(tmp_path)["inbound"][-1]["source"] == "link"


# --------------------------------------------------------------------------- confirming

@pytest.fixture
def adm():
    pytest.importorskip("jwt")
    from containerizer import admin as adminmod
    from containerizer.oidc import OidcConfig
    c = OidcConfig(issuer="https://idp.example.com", client_id="cz", client_secret="s", public_url="https://cz.example.com",
                   admins=["group:a"])
    conn = FakeConn()
    a = adminmod.Admin(c, lambda: conn, provider=object())
    a.conn = conn
    return a


def _post(adm, sid, path, csrf=None, **form):
    s = adm.sessions.get(sid)
    return adm.handle("POST", path, "", {"Cookie": f"{adm.cookie}={sid}"},
                      urlencode({"csrf": csrf if csrf is not None else s.csrf, **form}, doseq=True).encode())


def test_confirm_reject_and_link_manually(adm):
    rows = {4: {"LinkId": 4, "FromApplicationId": 1, "FromComponent": "egress-demo", "Status": "proposed", "ToApplicationId": 2,
                "ToComponent": "orders-demo"},
            5: {"LinkId": 5, "FromApplicationId": 1, "FromComponent": "egress-demo", "Status": "unresolved",
                "ToApplicationId": None, "ToComponent": None}}
    adm.conn.answers = {r"FROM cz.ComponentLink WHERE LinkId": lambda p: [rows[p[0]]] if p[0] in rows else [],
                        r"FROM cz.vLinkCandidate WHERE ApplicationId": lambda p: [{"ComponentName": "Billing.Api"}] if p[0] == 3 else [],
                        r"SELECT ProductId FROM cz.Application": [{"ProductId": 9}],
                        r"FROM cz.BusinessUnit": [], r"FROM cz.Product": [{"Id": 1, "Name": "Shop", "BusinessUnitId": None}]}
    viewer = adm.sessions.create("v@example.com", "V", False, True)
    assert _post(adm, viewer, "/admin/links/4/confirm").status == 403
    op = adm.sessions.create("o@example.com", "O", False, True, True, [])
    assert _post(adm, op, "/admin/links/4/confirm", csrf="bad").status == 403
    r = _post(adm, op, "/admin/links/4/confirm")
    assert dict(r.headers)["Location"] == "/app/1?link=confirmed#connectivity"
    (sql, p), = adm.conn.sql(r"UPDATE cz.ComponentLink SET Status = N'confirmed'")
    assert p == ("o@example.com", "O", 4)
    # Link manually: only a component assessed here, never the caller's own application
    assert "bad-target" in dict(_post(adm, op, "/admin/links/5/link", Target="3:../x").headers)["Location"]
    assert "bad-target" in dict(_post(adm, op, "/admin/links/5/link", Target="1:egress-demo").headers)["Location"]
    assert "bad-target" in dict(_post(adm, op, "/admin/links/5/link", Target="3:nope").headers)["Location"]
    _post(adm, op, "/admin/links/5/link", Target="3:billing-api")
    (sql, p), = adm.conn.sql(r"Method = N'manual'")
    assert p[:3] == (3, "billing-api", "linked by hand")
    _post(adm, op, "/admin/links/5/reject")
    assert adm.conn.sql(r"SET Status = N'rejected'")
    owner = adm.sessions.create("p@example.com", "P", False, True, False, ["product:Shop"])
    assert "not-yours" in dict(_post(adm, owner, "/admin/links/4/confirm").headers)["Location"]


def test_results_page_and_the_portfolio():
    from containerizer.connectivityui import load_portfolio, portfolio_svg, render_portfolio, section
    app = {"ApplicationId": 1, "ApplicationName": "egress-demo", "ProductId": 7, "ProductName": "Shop", "sandbox": [],
           "connectivity": {"available": True, "network": EGRESS_NET, "flows": [], "decisions": [],
                            "links_out": [{**LINK, "Status": "proposed"},
                                          {**LINK, "LinkId": 5, "Destination": "billing.corp.local", "Port": 443,
                                           "Status": "unresolved", "ToApplicationId": None}],
                            "links_in": [],
                            "candidates": [{"ApplicationId": 3, "ApplicationName": "billing", "ComponentName": "Billing.Api"}]}}
    html = section(app, {"csrf": "<input type='hidden' name='csrf' value='t'>", "link_notice": "confirmed"})
    assert "action='/admin/links/4/confirm'" in html and "action='/admin/links/5/link'" in html
    assert "<option value='3:billing-api'>billing / Billing.Api</option>" in html
    assert "href='/app/2#connectivity'" in html and "Linked:" in html and "/connectivity?product=7" in html
    assert "/admin/links/" not in section(app, {})
    conn = FakeConn({r"FROM cz.vApplicationLatest": [{"ApplicationId": 1, "ApplicationName": "egress-demo", "ProductId": 7,
                                                       "ProductName": "Shop"}],
                     r"FROM cz.vNetworkLatest": [{"ApplicationId": 1, "NetworkJson": json.dumps(EGRESS_NET)}],
                     r"FROM cz.vComponentLink": [LINK], r"FROM cz.vEgressDecision": [{"ApplicationId": 1, "Status": "approved"}]})
    data = load_portfolio(conn, product=7)
    assert [a["ApplicationName"] for a in data["apps"]] == ["egress-demo", "orders-demo"]       # the other side too
    svg = portfolio_svg(data)
    assert "cf-linked" in svg and "<script" not in svg and "style=" not in svg and ">1 approved<" in svg
    page = render_portfolio(data, "Connectivity: Shop")
    assert "orders-demo.orders-demo:80" in page and "Linked" in page
