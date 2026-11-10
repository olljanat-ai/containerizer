"""Lab mail: the mail the applications in the sandbox sent, caught by the lab's Mail (SMTP) service.

Each application that sends mail gets its own Mailpit instance in `containerizer-lab` (labservices.py, service
`smtp`): a catch-all mailbox that keeps every message and sends none on. The scan points the application's SMTP
settings at it (host, port, TLS off, pickup folder off), so mail that would have gone to the real relay, or to a
pickup folder nothing drains, lands there. Administrators and operators read it under Admin -> Lab mail
(admin_labmail.py).

The web UI has no cluster access. It hands the system agent (sysagent.py, root) a request
`{"action": "labmail", "id", "op": "list" | "show", "namespace", "message"}` and waits for the answer in
/run/containerizer/system/answers/<id>.json (appliance.py SystemPage.ask), as the database browser does
(dbbrowse.py). The agent trusts nothing in the request: a namespace must be one the lab agent runs a mailbox
for (lab-status.json), a message id is checked against Mailpit's id alphabet, and the only thing it runs is
`wget` against Mailpit's API on the pod's loopback (`kubectl exec`, fixed URL paths, no shell). Answers are
capped in size.
"""
from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

from . import labservices as L

SVC = "smtp"
LAB_STATUS = Path("/run/containerizer/system/lab-status.json")
ANSWERS_DIR = Path("/run/containerizer/system/answers")
ID_RE = re.compile(r"[A-Za-z0-9]{8,40}")                  # Mailpit's message ids
PER_BOX = 100                                           # newest messages per mailbox in the inbox
MAX_BODY = 200_000                                      # characters of a message's text or HTML
EXEC_TIMEOUT = 20
MAX_BYTES = 4_000_000


class MailError(Exception):
    pass


def _addr(a) -> dict:
    a = a if isinstance(a, dict) else {}
    return {"name": str(a.get("Name") or "")[:200], "address": str(a.get("Address") or "")[:320]}


def _addrs(v) -> list[dict]:
    return [_addr(x) for x in (v or [])[:50] if isinstance(x, dict)]


def _count(v) -> int:
    """Attachments: a number in the list, a list in a whole message."""
    if isinstance(v, list):
        return len(v)
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def summary(m: dict, ns: str) -> dict:
    """One message of Mailpit's list (GET /api/v1/messages), the fields the page shows."""
    return {"namespace": ns, "id": str(m.get("ID") or ""), "from": _addr(m.get("From")), "to": _addrs(m.get("To")),
            "cc": _addrs(m.get("Cc")), "subject": str(m.get("Subject") or "")[:500],
            "created": str(m.get("Created") or "")[:40], "size": int(m.get("Size") or 0),
            "attachments": _count(m.get("Attachments")), "snippet": str(m.get("Snippet") or "")[:300],
            "username": str(m.get("Username") or "")[:200]}


def message(m: dict, ns: str) -> dict:
    """One whole message (GET /api/v1/message/<id>)."""
    out = summary(m, ns)
    out["created"] = str(m.get("Date") or m.get("Created") or "")[:40]
    out.update({"bcc": _addrs(m.get("Bcc")), "reply_to": _addrs(m.get("ReplyTo")),
                "return_path": str(m.get("ReturnPath") or "")[:320], "message_id": str(m.get("MessageID") or "")[:500],
                "text": str(m.get("Text") or "")[:MAX_BODY], "html": str(m.get("HTML") or "")[:MAX_BODY],
                "truncated": len(str(m.get("Text") or "")) > MAX_BODY or len(str(m.get("HTML") or "")) > MAX_BODY,
                "files": [{"name": str(a.get("FileName") or "")[:300], "type": str(a.get("ContentType") or "")[:100],
                           "size": int(a.get("Size") or 0)}
                          for a in (m.get("Attachments") or [])[:100] if isinstance(a, dict)]})
    out["attachments"] = len(out["files"])
    return out


# =============================================================================== the system agent's side

@dataclass
class Agent:
    """What the agent needs from the outside, replaceable in the tests."""
    kube: object = None                                   # labagent.Kubectl
    lab_status: Path = LAB_STATUS
    runner: object = None                                 # dbbrowse.run_capped

    def _kube(self):
        if self.kube is None:
            from .labagent import Kubectl
            self.kube = Kubectl()
        return self.kube

    def mailboxes(self) -> list[str]:
        """The namespaces the lab agent runs a ready mailbox for."""
        try:
            st = json.loads(self.lab_status.read_text())
        except (OSError, ValueError):
            st = {}
        ready = ((st.get("services") or {}).get(SVC) or {}).get("ready") or []
        return sorted(ns for ns in ready if isinstance(ns, str) and L.NS_RE.fullmatch(ns) and not L.reserved(ns))

    def _get(self, ns: str, path: str) -> dict:
        """GET Mailpit's API in the namespace's mailbox (loopback inside its pod)."""
        from . import dbbrowse
        from .labagent import ready_pod
        kube = self._kube()
        pod = ready_pod(kube, SVC, L.instance(SVC, ns))
        if not pod:
            raise MailError(f"The mailbox of {ns} is not running.")
        argv = list(kube.cmd) + ([f"--kubeconfig={kube.kubeconfig}"] if kube.kubeconfig else []) + \
            ["-n", L.LAB_NS, "exec", "-i", pod["metadata"]["name"], "-c", SVC, "--",
             "wget", "-q", "-T", "10", "-O", "-", f"http://127.0.0.1:{L.MAIL_API_PORT}{path}"]
        rc, out, err, problem = (self.runner or dbbrowse.run_capped)(argv, "", timeout=EXEC_TIMEOUT, cap=MAX_BYTES)
        if rc or problem:
            raise MailError(f"The mailbox of {ns} did not answer" + (f": {(err or problem).strip()[:200]}" if (err or problem) else "."))
        try:
            data = json.loads(out)
        except ValueError:
            raise MailError(f"The mailbox of {ns} gave an answer that is not JSON.") from None
        if not isinstance(data, dict):
            raise MailError(f"The mailbox of {ns} gave an unexpected answer.")
        return data

    def list(self, req: dict) -> dict:
        boxes = self.mailboxes()
        ns = req.get("namespace")
        if ns:
            if ns not in boxes:
                raise MailError("That namespace has no mailbox in the lab.")
            boxes = [ns]

        def one(n):
            try:
                data = self._get(n, f"/api/v1/messages?limit={PER_BOX}")
                return n, [summary(m, n) for m in (data.get("messages") or [])[:PER_BOX] if isinstance(m, dict)], \
                    int(data.get("total") or 0), None
            except MailError as ex:
                return n, [], 0, str(ex)
        with ThreadPoolExecutor(max_workers=8) as pool:
            got = list(pool.map(one, boxes))
        messages = sorted((m for _, ms, _, _ in got for m in ms), key=lambda m: m["created"], reverse=True)
        return {"mailboxes": [{"namespace": n, "total": t, "error": e} for n, _, t, e in got], "messages": messages}

    def show(self, req: dict) -> dict:
        ns, ident = req.get("namespace"), req.get("message")
        if not isinstance(ns, str) or ns not in self.mailboxes():
            raise MailError("That namespace has no mailbox in the lab.")
        if not isinstance(ident, str) or not ID_RE.fullmatch(ident):
            raise MailError("Unknown message.")
        return {"message": message(self._get(ns, f"/api/v1/message/{ident}"), ns)}


def agent_request(req: dict, answers: Path = ANSWERS_DIR, agent: Agent | None = None) -> None:
    """The system agent's handling of `labmail`: always answers (a refusal too) when the id is well-formed."""
    from .dbbrowse import ID_RE as REQ_ID, clean_answers, log, write_answer
    ident = req.get("id")
    if not isinstance(ident, str) or not REQ_ID.fullmatch(ident):
        log("labmail: request without a valid id ignored")
        return
    agent = agent or Agent()
    clean_answers(answers)
    try:
        exp = req.get("expires_at")
        if not isinstance(exp, (int, float)) or isinstance(exp, bool) or time.time() > exp:
            raise MailError("The request expired before the appliance got to it.")
        op = req.get("op")
        if op == "list":
            answer = agent.list(req)
        elif op == "show":
            answer = agent.show(req)
        else:
            raise MailError("Unknown request.")
    except MailError as ex:
        answer = {"error": str(ex)}
    except Exception as ex:  # noqa: BLE001 - the page gets a plain answer, the journal the details
        log(f"labmail: {type(ex).__name__}: {ex}")
        answer = {"error": "The appliance could not read the mailbox; the details are in the system agent's journal."}
    answer["id"] = ident
    write_answer(answers, ident, answer)
