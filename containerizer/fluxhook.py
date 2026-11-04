"""Flux webhook: reconcile the sandbox's GitRepositories as soon as containerizer pushed to the output repository.

Flux polls every GitRepository on its interval (5 minutes: the root sync and each app's own source), so a deploy
used to wait up to that long after a scan, a "Make it A" variant or a connectivity decision was pushed. On the
appliance, `cz-sandbox` (root, every 2 minutes) keeps a Flux notification-controller `Receiver` (type generic) in
flux-system, `RECEIVER`, that names the root sync's GitRepository and every GitRepository containerizer generated
in the app namespaces (`receiver_manifests`). Its token is generated once and kept in the secret store (remote key
`flux-system--cz-webhook`, read through an ExternalSecret like the root sync's Git token); the webhook path Flux
derives from it (`.status.webhookPath`) and the address of the `webhook-receiver` Service (a ClusterIP: reachable
from the host only, never published) go into `/run/containerizer/flux-webhook` (root:containerizer 0640), which
the scan worker and the LLM queue runner find through CONTAINERIZER_FLUX_WEBHOOK.

`notify(reason)` POSTs to that URL after every successful push (org.Output.commit): best effort, 5-second timeout,
never raises, one log line per kind of failure. Without the file (outside the appliance, CLI runs) it does nothing;
polling stays the fallback everywhere.
"""
from __future__ import annotations

import os
import sys

ENV = "CONTAINERIZER_FLUX_WEBHOOK"          # path of the file with the webhook URL (one line)
RECEIVER = "containerizer-sandbox"          # the Receiver in flux-system and its Secret's prefix
SECRET = f"{RECEIVER}-webhook"
REMOTE_KEY = "flux-system--cz-webhook"      # remote key of the token in the secret store
NS = "flux-system"
API = "notification.toolkit.fluxcd.io/v1"
TIMEOUT = 5
_LABELS = {"app.kubernetes.io/part-of": "containerizer-sandbox", "app.kubernetes.io/managed-by": "containerizer-appliance"}
_seen: set[str] = set()                     # failure kinds logged already (once per process)


def receiver_manifests(namespaces: list[str] | tuple = (), store: str = "app-secrets") -> list[dict]:
    """The ExternalSecret of the token (key `token`) and the Receiver: the root sync's GitRepository in flux-system
    and, in each of `namespaces`, every GitRepository labelled app.kubernetes.io/managed-by=containerizer (a
    Receiver's `name: "*"` + `matchLabels` lists one namespace per entry). Flux's default flags allow references
    to other namespaces (no --no-cross-namespace-refs), as installed on the appliance and in the lab."""
    src = "source.toolkit.fluxcd.io/v1"
    resources = [{"apiVersion": src, "kind": "GitRepository", "name": RECEIVER}]
    resources += [{"apiVersion": src, "kind": "GitRepository", "name": "*", "namespace": ns,
                   "matchLabels": {"app.kubernetes.io/managed-by": "containerizer"}}
                  for ns in sorted(set(namespaces) - {NS, ""})]
    return [
        {"apiVersion": "external-secrets.io/v1", "kind": "ExternalSecret",
         "metadata": {"name": SECRET, "namespace": NS, "labels": dict(_LABELS)},
         "spec": {"refreshInterval": "1h", "secretStoreRef": {"kind": "ClusterSecretStore", "name": store},
                  "target": {"name": SECRET, "creationPolicy": "Owner", "deletionPolicy": "Retain"},
                  "dataFrom": [{"extract": {"key": REMOTE_KEY}}]}},
        {"apiVersion": API, "kind": "Receiver",
         "metadata": {"name": RECEIVER, "namespace": NS, "labels": dict(_LABELS)},
         "spec": {"type": "generic", "secretRef": {"name": SECRET}, "resources": resources}},
    ]


def url(env=None) -> str:
    """The webhook URL from the file CONTAINERIZER_FLUX_WEBHOOK names; "" when not configured or not readable."""
    env = os.environ if env is None else env
    path = env.get(ENV) or ""
    if not path:
        return ""
    try:
        with open(path) as f:
            u = f.readline().strip()
    except OSError:
        return ""
    return u if u.startswith(("http://", "https://")) else ""


def _once(kind: str, msg: str) -> None:
    if kind not in _seen:
        _seen.add(kind)
        print(f"flux webhook: {msg} (Flux still polls every 5 minutes; logged once)", file=sys.stderr)


def notify(reason: str = "", env=None, opener=None) -> bool:
    """Ask Flux to reconcile the sandbox's GitRepositories now. True when the receiver accepted it. Never raises."""
    u = url(env)
    if not u:
        return False
    try:
        import json
        import urllib.request
        req = urllib.request.Request(u, data=json.dumps({"reason": reason[:200]}).encode(), method="POST",
                                     headers={"Content-Type": "application/json"})
        with (opener or urllib.request.urlopen)(req, timeout=TIMEOUT) as r:
            ok = 200 <= getattr(r, "status", 200) < 300
        if not ok:
            _once(f"status-{getattr(r, 'status', '?')}", f"the receiver answered HTTP {getattr(r, 'status', '?')}")
        return ok
    except Exception as e:  # noqa: BLE001 - best effort: a push never fails because of the webhook
        code = getattr(e, "code", None)
        kind = f"http-{code}" if code else type(e).__name__
        # the URL holds the secret-derived path: never logged
        _once(kind, f"HTTP {code}" if code else f"{type(e).__name__}: {str(e).replace(u, '<url>')[:200]}")
        return False
