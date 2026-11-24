"""The System page of the admin pages on the containerizer appliance: the running version, the OS
snapshots, newer signed releases on GHCR, and upgrade and roll back. A newer patch release of the running OS's
series is installed as an app update (apppatch.py): only the containerizer services restart, the OS does not.

The web UI runs as an unprivileged user and cannot change the OS. It only reads the status the
system agent (sysagent.py, root) publishes in /run/containerizer/system/status.json and drops a
request into /run/containerizer/system/requests/; a systemd path unit starts the agent, which checks
the request again (a release tag of the one image repository it was built for, signed by this
project's release workflow, or a snapshot that is on the disk) before it calls Elemental. So a
compromised web process can at most ask for another signed release or an existing snapshot.

Only administrators (CONTAINERIZER_ADMINS) see the page. Outside the appliance (no status file) the
page is not offered.
"""
from __future__ import annotations

import html
import json
import os
import re
import secrets
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlencode

from . import restartplan as rp

e = html.escape

STATUS_DIR = Path("/run/containerizer/system")
VERSION_RE = re.compile(r"v(\d{1,4})\.(\d{1,4})\.(\d{1,4})")
IMAGE_RE = re.compile(r"[a-z0-9.-]+(:\d{1,5})?(/[a-z0-9._-]+)+")
CHECK_TTL = 600             # seconds between GHCR checks
MAX_TAGS_BYTES = 2 * 1024 * 1024


def parse_version(v: str | None) -> tuple[int, int, int] | None:
    m = VERSION_RE.fullmatch(v or "")
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def newer_versions(tags: list[str], current: str | None, limit: int = 10) -> list[str]:
    """Release tags (vX.Y.Z only: no pre-releases, no `latest`) newer than `current`, newest first.
    When the running version is not a release (a development build), the newest releases."""
    cur = parse_version(current)
    rel = sorted({t for t in tags if parse_version(t)}, key=parse_version, reverse=True)
    return [t for t in rel if cur is None or parse_version(t) > cur][:limit]


class RegistryError(Exception):
    pass


def ghcr_tags(image: str, timeout: float = 8.0, opener=urllib.request.urlopen) -> list[str]:
    """Tags of a public image on GHCR (anonymous pull token, then the tags list)."""
    host, _, repo = image.partition("/")
    if host != "ghcr.io" or not IMAGE_RE.fullmatch(image):
        raise RegistryError(f"not a GHCR image: {image}")
    try:
        with opener(f"https://ghcr.io/token?{urlencode({'scope': f'repository:{repo}:pull', 'service': 'ghcr.io'})}",
                    timeout=timeout) as r:
            token = json.loads(r.read(64 * 1024))["token"]
        req = urllib.request.Request(f"https://ghcr.io/v2/{repo}/tags/list?n=1000",
                                     headers={"Authorization": f"Bearer {token}", "Accept": "application/json"})
        with opener(req, timeout=timeout) as r:
            data = json.loads(r.read(MAX_TAGS_BYTES))
    except (urllib.error.URLError, OSError, ValueError, KeyError, TypeError) as ex:
        raise RegistryError(f"{type(ex).__name__}: {ex}") from None
    tags = data.get("tags") if isinstance(data, dict) else None
    if not isinstance(tags, list):
        raise RegistryError("unexpected answer from the registry")
    return [t for t in tags if isinstance(t, str)]


# certificate revocation and issuer lookups (CRL, OCSP, AIA) go over plain HTTP: HTTPS would need them to check itself
PLAIN_HTTP_NAME = re.compile(r"^(crl|ocsp|cacerts?|aia|ctldl)\d*([.-]|$)", re.I)


CERT_CATEGORY = "Certificate checks"
# the choices of the Category menu (a category already in use stays a choice too)
CATEGORIES = (CERT_CATEGORY, "Container registries", "Databases", "Internal services", "LLM", "Package registries",
              "Source control", "Other")


def category_select(name: str, current: str, cats, extra: str = "") -> str:
    opts = "".join(f"<option value='{e(c)}'{' selected' if c == current else ''}>{e(c)}</option>" for c in cats)
    return f"<select name='{name}'{extra}><option value=''>No category</option>{opts}</select>"


def guess_ports(name: str) -> str:
    """The ports to prefill for a refused name: the lookup was refused, so no connection (and no port) was seen."""
    return "80" if PLAIN_HTTP_NAME.match(name or "") else "443"


def guess_category(name: str) -> str:
    return CERT_CATEGORY if PLAIN_HTTP_NAME.match(name or "") else ""


@dataclass
class SystemPage:
    status_dir: Path = STATUS_DIR
    fetch_tags: object = ghcr_tags          # (image) -> list[str]; replaced in tests
    _cache: dict = field(default_factory=dict)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def detect(cls, env=None) -> "SystemPage | None":
        """The page when this web UI runs on the appliance (the system agent publishes its status)."""
        env = os.environ if env is None else env
        d = Path(env.get("CONTAINERIZER_SYSTEM_DIR") or STATUS_DIR)
        return cls(status_dir=d) if (d / "status.json").is_file() or env.get("CONTAINERIZER_APPLIANCE") == "1" else None

    # -- state ----------------------------------------------------------------------------------

    def status(self) -> dict:
        try:
            data = json.loads((self.status_dir / "status.json").read_text())
            return data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            return {}

    def pending(self) -> list[dict]:
        out = []
        for p in sorted((self.status_dir / "requests").glob("*.json")):
            try:
                out.append(json.loads(p.read_text()))
            except (OSError, ValueError):
                continue
        return out

    def busy(self, st: dict) -> bool:
        return bool(self.pending()) or bool(st.get("restart")) or \
            (st.get("task") or {}).get("state") in ("queued", "running", "rebooting")

    def available(self, image: str | None, current: str | None, force: bool = False) -> tuple[list[str], str | None, float | None]:
        """(newer release tags, error, when checked); cached for CHECK_TTL seconds."""
        if not image:
            return [], "The image repository is not known.", None
        with self._lock:
            c = self._cache.get(image)
            if c and not force and time.time() - c[2] < CHECK_TTL:
                return newer_versions(c[0], current), c[1], c[2]
        try:
            tags, err = self.fetch_tags(image), None
        except RegistryError as ex:
            tags, err = [], f"Could not reach {image.split('/')[0]}: {ex}"
        with self._lock:
            self._cache[image] = (tags, err, time.time())
        return newer_versions(tags, current), err, time.time()

    def request(self, action: str, user: str, name: str, **args) -> None:
        """Drop a request for the system agent: written to a temporary name, then renamed, so the path
        unit never sees a half-written file."""
        d = self.status_dir / "requests"
        body = {"action": action, "requested_by": user, "requested_by_name": name,
                "requested_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), **args}
        tmp = d / f".{secrets.token_hex(8)}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)   # may carry a private key: owner only
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(body))
        # the agent takes them in the order of their names: nanoseconds, so two requests of the same millisecond
        # (save the schedule, then back up now) keep their order
        tmp.rename(d / f"{time.time_ns()}-{secrets.token_hex(4)}.json")

    def ask(self, action: str, user: str, name: str, wait: float = 45.0, poll: float = 0.1, **args) -> dict | None:
        """A request that has an answer (the database browser, dbbrowse.py): the request carries a random id and
        the time after which the agent must not start it any more; the agent writes answers/<id>.json (for root
        and the web UI's group only). The answer, or None when none came within `wait` seconds."""
        ident = secrets.token_hex(16)
        self.request(action, user, name, id=ident, expires_at=time.time() + wait, **args)
        path = self.status_dir / "answers" / f"{ident}.json"
        deadline = time.monotonic() + wait
        while time.monotonic() < deadline:
            if path.is_file():
                try:
                    data = json.loads(path.read_text())
                except (OSError, ValueError):
                    time.sleep(poll)             # still being renamed into place
                    continue
                path.unlink(missing_ok=True)
                return data if isinstance(data, dict) and data.get("id") == ident else None
            time.sleep(poll)
        return None

    # -- pages ----------------------------------------------------------------------------------

    def handle(self, s, method: str, parts: list[str], q: dict, form: dict, shell) -> tuple[int, str, str | None]:
        """(status, body, redirect location or None) for /admin/system and /admin/firewall.
        `shell(title, active tab, body, flash)` renders the admin frame."""
        kind = parts[0]
        if not s.admin:                     # admins only, whatever other roles may reach the admin pages
            return 403, shell("Not allowed", kind, "<p>Only administrators can see and change the system.</p>", ""), None
        st = self.status()
        if kind == "firewall":
            return self.firewall(s, method, parts, q, form, shell, st)
        if kind == "sandbox-https":
            return self.sandbox_https(s, method, q, form, shell, st)
        if method == "POST":
            what = parts[1] if len(parts) > 1 else ""
            back = "/admin/system?"
            if what == "cancel-restart":
                if not st.get("restart"):
                    return 303, "", back + urlencode({"msg": "No restart is planned."})
                self.request("plan-cancel", s.user, s.name)
                return 303, "", back + urlencode({"msg": "Planned restart cancelled. Scans and the LLM queue go on."})
            if what in ("backup", "backup-now"):
                return 303, "", back + urlencode({"msg": self.backup_post(s, what, form, st)}) + "#backup"
            if what in ("sql-readonly", "sql-incoming"):
                return 303, "", back + urlencode({"msg": self.sql_access_post(s, what, form, st)}) + "#sql-access"
            if what == "app-patch-remove":
                if not st.get("app_patch"):
                    return 303, "", back + urlencode({"msg": "No app update is installed."})
                if form.get("confirm", [""])[0] != "yes":
                    return 303, "", back + urlencode({"msg": "Tick the box to confirm: the services restart."})
                if self.busy(st):
                    return 303, "", back + urlencode({"msg": "A restart is already planned, or an upgrade, roll back or "
                                                             "firewall change is in progress."})
                self.request("app-patch-remove", s.user, s.name)
                return 303, "", back + urlencode({"msg": f"Removing the app update: back to {st.get('os_version') or 'the OS image code'}; "
                                                         "the services restart."})
            if what not in ("upgrade", "rollback", "restart"):
                return 404, shell("Not found", kind, "", ""), None
            if form.get("confirm", [""])[0] != "yes":
                return 303, "", back + urlencode({"msg": "Tick the box to confirm: the appliance restarts."})
            if self.busy(st):
                return 303, "", back + urlencode({"msg": "A restart is already planned, or an upgrade, roll back or "
                                                         "firewall change is in progress."})
            try:
                at, wait = plan_time(form)
            except ValueError as ex:
                return 303, "", back + urlencode({"msg": str(ex)})
            args = {"at": at, "max_wait_minutes": wait}
            if what == "upgrade":
                v = form.get("version", [""])[0]
                newer, err, _ = self.available(st.get("image"), st.get("version"))
                if v not in newer:
                    return 303, "", back + urlencode({"msg": f"{v or 'That version'} is not a newer release."})
                args.update(then="upgrade", version=v)
            elif what == "rollback":
                sid = form.get("snapshot", [""])[0]
                ok = {str(x.get("id")) for x in st.get("snapshots") or [] if not x.get("active")}
                if not re.fullmatch(r"\d{1,6}", sid) or sid not in ok:
                    return 303, "", back + urlencode({"msg": "Pick one of the earlier snapshots."})
                args.update(then="rollback", snapshot=int(sid))
            else:
                args.update(then="reboot")
            self.request("plan", s.user, s.name, **args)
            plan = {"action": args["then"], **args}
            when = f"at {_when(at)}" if at else "now"
            restarts = "its services restart" if what == "upgrade" and self.app_update(st, args["version"]) \
                else "the appliance restarts"
            return 303, "", back + urlencode({"msg": f"{rp.describe(plan).capitalize()} planned {when}: from then on no "
                                                     f"new scan or LLM job starts, and {restarts} "
                                                     f"{rp.wait_text(wait)}."})
        flash = q.get("msg", [""])[0][:300]
        force = q.get("check", [""])[0] == "1"
        return 200, shell("System", kind, self.render(st, s, force), flash), None

    # -- firewall -------------------------------------------------------------------------------

    def firewall(self, s, method, parts, q, form, shell, st) -> tuple[int, str, str | None]:
        from .sysagent import RuleError, validate_rules
        eg = st.get("egress") or {}
        back = "/admin/firewall?"
        if method == "POST":
            if any(p.get("action") == "egress" for p in self.pending()):
                return 303, "", back + urlencode({"msg": "The previous firewall change is still being applied. Try again in a moment."})
            rules = [dict(r) for r in eg.get("rules") or []]
            mode = eg.get("mode") or "enforce"
            what = form.get("do", [""])[0]
            if what == "add":
                target = " ".join(form.get("target", [""])[0].split())
                entry = {"ports": form.get("ports", ["443"])[0] or "443", "note": form.get("note", [""])[0],
                         "category": form.get("category", [""])[0]}
                entry["cidr" if re.fullmatch(r"[0-9a-fA-F.:]+(/\d{1,3})?", target) else "host"] = target
                rules.append(entry)
                done = f"Allowed {target}"
            elif what == "remove":
                drop = {int(x) for x in form.get("rule", []) if re.fullmatch(r"\d{1,4}", x)}
                if not drop:
                    return 303, "", back + urlencode({"msg": "Select the rules to remove."})
                rules = [r for i, r in enumerate(rules) if i not in drop]
                done = f"Removed {len(drop)} rule(s)"
            elif what == "update":
                # the page names each row's rule: a change since the page was loaded must not edit the wrong one
                for i, r in enumerate(rules):
                    if f"key{i}" not in form:
                        continue
                    if form[f"key{i}"][0] != (r.get("host") or r.get("cidr") or ""):
                        return 303, "", back + urlencode({"msg": "The rules changed meanwhile: nothing saved. Edit them again."})
                    r["note"] = form.get(f"note{i}", [""])[0]
                    r["category"] = form.get(f"category{i}", [""])[0]
                done = "Saved the categories and descriptions"
            elif what == "mode":
                mode = form.get("mode", [""])[0]
                if mode == "log" and form.get("confirm", [""])[0] != "yes":
                    return 303, "", back + urlencode({"msg": "Tick the box to confirm: log only mode lets every connection out."})
                done = "Blocking turned on" if mode == "enforce" else "Log only mode: connections are logged, not blocked"
            else:
                return 303, "", back
            try:
                new = validate_rules({"mode": mode, "rules": rules})
            except RuleError as ex:
                return 303, "", back + urlencode({"msg": f"Not saved: {ex}"})
            self.request("egress", s.user, s.name, mode=new["mode"], rules=new["rules"])
            return 303, "", back + urlencode({"msg": done + ". The firewall is updated within a few seconds."})
        flash = q.get("msg", [""])[0][:300]
        return 200, shell("Firewall", "firewall", self.render_firewall(eg, s), flash), None

    def render_firewall(self, eg: dict, s) -> str:
        csrf = f"<input type='hidden' name='csrf' value='{e(s.csrf)}'>"
        if not eg:
            return "<p class='note'>The system agent has not published the firewall state yet.</p>"
        mode = eg.get("mode") or "enforce"
        out = ["<p>Incoming: only <b>SSH (22)</b> and <b>HTTPS (443)</b>. Outgoing: blocked, except to the names and "
               "networks below. A name covers its subdomains. The appliance resolves only allowed names (everything "
               "else gets NXDOMAIN), and its firewall lets connections out only to the addresses those names "
               "resolved to, on the listed ports. The same rules apply to the scan worker's builds, to Docker and to "
               "the apps in the sandbox cluster.</p>"]
        if eg.get("error"):
            out.append(f"<p class='note'>The last change was not applied: {e(eg['error'])}</p>")
        if mode == "log":
            out.append("<p class='note'><b>Log only mode:</b> nothing is blocked; refused names and connections are "
                       "still listed below, so you can build the allow-list before you turn blocking on.</p>")
        pend = " disabled" if any(p.get("action") == "egress" for p in self.pending()) else ""
        if mode == "log":
            out.append(f"<form method='post' action='/admin/firewall'>{csrf}<input type='hidden' name='do' value='mode'>"
                       f"<input type='hidden' name='mode' value='enforce'><button{pend}>Turn blocking on</button></form>")
        else:
            out.append(f"<form method='post' action='/admin/firewall' class='danger'>{csrf}<input type='hidden' name='do' value='mode'>"
                       "<input type='hidden' name='mode' value='log'><label class='small'><input type='checkbox' name='confirm' "
                       f"value='yes' required> let every connection out and only log it</label> <button{pend}>Log only mode</button></form>")
        admin_rules = list(enumerate(eg.get("rules") or []))
        in_use = {r.get("category") for _, r in admin_rules if r.get("category")}
        cats = list(CATEGORIES) + sorted(in_use - set(CATEGORIES), key=str.lower)
        out.append(f"""<h2>Allow</h2><form method='post' action='/admin/firewall'>{csrf}<input type='hidden' name='do' value='add'>
<div class='formrow'><label for='target'>Name or network</label><input name='target' id='target' required maxlength='253'
placeholder='api.nuget.org or 10.20.0.0/16'></div>
<div class='formrow'><label for='ports'>Ports</label><input name='ports' id='ports' value='443' maxlength='120'
placeholder='443 or 80,443 or udp/123'></div>
<div class='formrow'><label for='category'>Category</label>{category_select("category", "", cats, " id='category'")}</div>
<div class='formrow'><label for='note'>Why</label><input name='note' id='note' maxlength='200'><button{pend}>Allow</button></div></form>""")
        # grouped by category (uncategorised last); the form fields keep each rule's stored position
        admin_rules.sort(key=lambda ir: (not ir[1].get("category"), (ir[1].get("category") or "").lower(),
                                         ir[1].get("host") or ir[1].get("cidr") or ""))
        rows, last = [], None
        for i, r in admin_rules:
            target, cat = r.get("host") or r.get("cidr") or "", r.get("category") or ""
            if cat != last:
                rows.append(f"<tr><th colspan=5 class='group'>{e(cat or 'No category')}</th></tr>")
                last = cat
            rows.append(
                f"<tr><td><input type='checkbox' name='rule' value='{i}' aria-label='Select {e(target)}'>"
                f"<input type='hidden' name='key{i}' value='{e(target)}'></td>"
                f"<td>{e(target)}</td><td>{e(', '.join(r.get('ports') or []))}</td>"
                f"<td>{category_select(f'category{i}', cat, cats, f' aria-label=\'Category for {e(target)}\'')}</td>"
                f"<td><input name='note{i}' value='{e(r.get('note') or '')}' maxlength='200' size='32' "
                f"aria-label='Why {e(target)} is allowed'></td></tr>")
        rows = "".join(rows)
        buttons = (f"<button name='do' value='update'{pend}>Save changes</button> "
                   f"<button name='do' value='remove'{pend}>Remove selected</button>")
        out.append(f"""<h2>Allowed by administrators</h2><form method='post' action='/admin/firewall'>{csrf}
<table><thead><tr><th></th><th>Name or network</th><th>Ports</th><th>Category</th><th>Why</th></tr></thead>
<tbody>{rows or "<tr><td colspan=5 class=muted>Nothing yet.</td></tr>"}</tbody></table>
{buttons if rows else ""}</form>""")
        denied = eg.get("denied_names") or []
        if denied:
            drows = "".join(
                f"<tr><td>{e(d['name'])}</td><td>{int(d.get('count') or 0)}</td><td><form method='post' action='/admin/firewall' "
                f"class='inline'>{csrf}<input type='hidden' name='do' value='add'><input type='hidden' name='target' "
                f"value='{e(d['name'])}'><input type='hidden' name='category' value='{e(guess_category(d['name']))}'>"
                f"<input name='ports' value='{guess_ports(d['name'])}' size='8' aria-label='Ports for {e(d['name'])}'> "
                f"<button{pend}>Allow</button></form></td></tr>" for d in denied)
            out.append("<h2>Refused names, last 24 hours</h2><p class='muted small'>Names something on the appliance tried "
                       "to resolve (a build, the worker, an app in the sandbox), the most recent first. Allow only the ones you expect.</p>"
                       f"<table><thead><tr><th>Name</th><th>Lookups</th><th></th></tr></thead><tbody>{drows}</tbody></table>")
        dropped = eg.get("dropped") or []
        if dropped:
            out.append("<h2>Blocked connections, last 24 hours</h2><p class='muted small'>Connections to addresses no rule "
                       "allows: an allowed name on another port, or an address used without a name lookup.</p><table><thead>"
                       "<tr><th>Destination</th><th>Packets logged</th></tr></thead><tbody>"
                       + "".join(f"<tr><td>{e(d['name'])}</td><td>{int(d.get('count') or 0)}</td></tr>" for d in dropped)
                       + "</tbody></table>")
        sysrows = "".join(f"<tr><td>{e(r.get('host') or r.get('cidr') or '')}</td><td>{e(', '.join(r.get('ports') or []))}</td>"
                          f"<td>{e(r.get('note') or '')}</td></tr>" for r in eg.get("system_rules") or [])
        out.append("<h2>Always allowed</h2><p class='muted small'>What the appliance itself needs: its upgrades and their "
                   "signatures, and the images of its own services. Part of the OS image.</p><table><thead><tr><th>Name"
                   f"</th><th>Ports</th><th>Why</th></tr></thead><tbody>{sysrows}</tbody></table>")
        hist = eg.get("history") or []
        if hist:
            def ch(h):
                parts = [f"+ {x.get('host') or x.get('cidr')} ({', '.join(x.get('ports') or [])})" for x in h.get("added") or []]
                parts += [f"- {x.get('host') or x.get('cidr')} ({', '.join(x.get('ports') or [])})" for x in h.get("removed") or []]
                if h.get("mode") != h.get("old_mode"):
                    parts.append(f"mode {h.get('old_mode')} → {h.get('mode')}")
                return "<br>".join(e(p) for p in parts) or "no change"
            out.append("<h2>Change history</h2><table class='audit'><thead><tr><th>When</th><th>Who</th><th>Change</th></tr>"
                       "</thead><tbody>" + "".join(
                           f"<tr><td class='nowrap'>{e(_when(h.get('at')))}</td><td>{e(h.get('name') or h.get('by') or '')}"
                           f"<div class='muted small'>{e(h.get('by') or '')}</div></td><td>{ch(h)}</td></tr>" for h in hist)
                       + "</tbody></table>")
        return "".join(out)

    # -- sandbox HTTPS --------------------------------------------------------------------------

    def sandbox_https(self, s, method, q, form, shell, st) -> tuple[int, str, str | None]:
        """Admin -> Sandbox HTTPS: the wildcard domain and certificate the apps in k3s are published with.
        The page checks what was pasted (the system agent checks it again) and never shows a key."""
        from .sandbox_https import SandboxHttpsError, check
        back = "/admin/sandbox-https?"
        if method == "POST":
            if any(p.get("action") == "sandbox-https" for p in self.pending()):
                return 303, "", back + urlencode({"msg": "The previous change is still being applied. Try again in a moment."})
            what = form.get("do", [""])[0]
            if what == "remove":
                if form.get("confirm", [""])[0] != "yes":
                    return 303, "", back + urlencode({"msg": "Tick the box to confirm."})
                self.request("sandbox-https", s.user, s.name, do="remove")
                return 303, "", back + urlencode({"msg": "HTTPS for the sandbox apps is being turned off."})
            if what != "set":
                return 303, "", back
            domain, cert, key = (form.get(k, [""])[0] for k in ("domain", "cert", "key"))
            try:
                ok = check(domain, cert, key, appliance_host=self.appliance_host(st))
            except SandboxHttpsError as ex:
                return 303, "", back + urlencode({"msg": f"Not saved: {ex}"})
            # the re-encoded PEMs: nothing but the certificates and the key reaches the system agent
            self.request("sandbox-https", s.user, s.name, do="set", domain=ok.info.domain, cert=ok.cert_pem, key=ok.key_pem)
            warn = f" Note: {'; '.join(ok.info.warnings)}." if ok.info.warnings else ""
            return 303, "", back + urlencode({"msg": f"*.{ok.info.domain} is being set up; the web UI restarts its "
                                                     f"HTTPS listener for a moment.{warn}"})
        flash = q.get("msg", [""])[0][:400]
        return 200, shell("Sandbox HTTPS", "sandbox-https", self.render_sandbox_https(st, s), flash), None

    @staticmethod
    def appliance_host(st: dict) -> str:
        from urllib.parse import urlsplit
        return (urlsplit(os.environ.get("CONTAINERIZER_PUBLIC_URL") or "").hostname or st.get("hostname") or "").lower()

    def render_sandbox_https(self, st: dict, s) -> str:
        from .sandbox_https import host_for
        hs = st.get("sandbox_https") or {}
        csrf = f"<input type='hidden' name='csrf' value='{e(s.csrf)}'>"
        pend = any(p.get("action") == "sandbox-https" for p in self.pending())
        dis = " disabled" if pend else ""
        out = ["<p>Publish the apps deployed to the sandbox cluster (k3s on this appliance) over HTTPS under one "
               "wildcard domain. Each component that serves HTTP gets its own name, "
               "<code>&lt;component&gt;-&lt;app&gt;.&lt;domain&gt;</code> (just <code>&lt;app&gt;.&lt;domain&gt;</code> when "
               "the component has the app's name), from the next organization scan on. The appliance answers for them on "
               "port 443, next to the admin pages, and only over HTTPS.</p>"]
        if pend:
            out.append("<p class='note'>Waiting for the system agent to apply the last change.</p>")
        if hs.get("error"):
            out.append(f"<p class='note'>The last change was not applied: {e(hs['error'])}</p>")
        cert = hs.get("cert") or {}
        if hs.get("enabled") and hs.get("domain"):
            d = hs["domain"]
            example = host_for(d, "myapp", "web")
            warn = "".join(f"<li>{e(w)}</li>" for w in cert.get("warnings") or [])
            out.append(f"""<h2>Now</h2><table><tbody>
<tr><th>Domain</th><td><code>*.{e(d)}</code>, for example <code>https://{e(example)}/</code></td></tr>
<tr><th>Certificate</th><td>{e(cert.get('subject') or '')}<div class='muted small'>issued by {e(cert.get('issuer') or '')}</div></td></tr>
<tr><th>Valid until</th><td>{e(_when(cert.get('not_after')))}</td></tr>
<tr><th>Key</th><td>{e(cert.get('key_type') or '')} <span class='muted small'>(stored on the appliance for its web
server and k3s only; it is never shown again)</span></td></tr>
<tr><th>SHA-256 fingerprint</th><td class='small'><code>{e(cert.get('fingerprint') or '')}</code></td></tr>
<tr><th>Set</th><td>{e(_when(hs.get('set_at')))} by {e(hs.get('set_by_name') or hs.get('set_by') or '')}</td></tr>
</tbody></table>{"<ul class='note'>" + warn + "</ul>" if warn else ""}
<h2>DNS</h2><p>Point the wildcard name at this appliance, for example
<code>*.{e(d)}. 300 IN A &lt;appliance address&gt;</code> or <code>*.{e(d)}. 300 IN CNAME {e(self.appliance_host(st) or 'appliance.example.com')}.</code>
See <a href='https://containerizer.eu/sandbox-https/'>Sandbox HTTPS</a> in the documentation.</p>""")
        else:
            out.append("<p class='muted'>Not set up: the sandbox apps get no Ingress and no URL.</p>")
        out.append(f"""<h2>{"Replace the certificate" if hs.get("enabled") else "Set up"}</h2>
<form method='post' action='/admin/sandbox-https' autocomplete='off'>{csrf}<input type='hidden' name='do' value='set'>
<div class='formrow'><label for='domain'>Wildcard domain</label><input name='domain' id='domain' required maxlength='200'
placeholder='*.sandbox.example.com' value='{e("*." + hs["domain"]) if hs.get("domain") and hs.get("enabled") else ""}'></div>
<div class='formrow'><label for='cert'>Certificate (PEM)</label><textarea name='cert' id='cert' rows='8' cols='70' required
spellcheck='false' placeholder='-----BEGIN CERTIFICATE-----&#10;(the server certificate for *.sandbox.example.com, then its intermediates)'></textarea></div>
<div class='formrow'><label for='key'>Private key (PEM)</label><textarea name='key' id='key' rows='6' cols='70' required
spellcheck='false' autocomplete='off' placeholder='-----BEGIN PRIVATE KEY-----'></textarea></div>
<p class='muted small'>The certificate must name <code>*.&lt;domain&gt;</code>, be valid now and match the key (RSA 2048+ or
ECDSA P-256/P-384, without a password). Use a domain of its own: not the one the admin pages are under.</p>
<button{dis}>Save</button></form>""")
        if hs.get("enabled"):
            out.append(f"""<form method='post' action='/admin/sandbox-https' class='danger'>{csrf}<input type='hidden' name='do' value='remove'>
<label class='small'><input type='checkbox' name='confirm' value='yes' required> stop publishing the sandbox apps and delete the
certificate and key from the appliance</label> <button{dis}>Turn off</button></form>""")
        hist = hs.get("history") or []
        if hist:
            def what(h):
                if h.get("action") == "remove":
                    return f"turned off (was *.{h.get('domain') or '?'})"
                return (f"*.{h.get('domain', '')}: {h.get('subject', '')}, valid until {_when(h.get('not_after'))}"
                        f" (SHA-256 {str(h.get('fingerprint', ''))[:23]}…)")
            out.append("<h2>Change history</h2><table class='audit'><thead><tr><th>When</th><th>Who</th><th>Change</th></tr>"
                       "</thead><tbody>" + "".join(
                           f"<tr><td class='nowrap'>{e(_when(h.get('at')))}</td><td>{e(h.get('name') or h.get('by') or '')}"
                           f"<div class='muted small'>{e(h.get('by') or '')}</div></td><td>{e(what(h))}</td></tr>" for h in hist)
                       + "</tbody></table>")
        return "".join(out)

    def render(self, st: dict, s, force: bool = False) -> str:
        if not st:
            return ("<p class='note'>The system agent has not published its status yet. It runs at start-up; "
                    "check <code>systemctl status containerizer-sysagent</code> on the appliance.</p>")
        version = st.get("version") or "unknown"
        patch = st.get("app_patch") or {}
        os_version = st.get("os_version") or version
        mode = {"active": "active system", "passive": "an earlier snapshot (fallback)",
                "recovery": "the recovery system"}.get(st.get("boot_mode"), st.get("boot_mode") or "unknown")
        busy = self.busy(st)
        task = st.get("task") or {}
        out = [f"""<div class='tiles'>
<div class='tile'><div class='label'>Running version</div><div class='value small-value'>{e(version)}</div>
<div class='sub'>{e(f"app update on OS {os_version}" if patch else (st.get('image') or ''))}</div></div>
<div class='tile'><div class='label'>Booted from</div><div class='value small-value'>{e(mode)}</div>
<div class='sub'>Elemental {e(st.get('elemental') or '')}</div></div>
<div class='tile'><div class='label'>Status updated</div><div class='value small-value'>{e(_when(st.get('updated')))}</div>
<div class='sub'>{e(st.get('hostname') or '')}</div></div></div>"""]
        if st.get("boot_mode") == "passive":
            out.append("<p class='note'>The appliance started from an earlier snapshot, which happens when the newest one "
                       "failed its start-up check. Roll back to make this version the active one again, or upgrade.</p>")
        if task:
            state = task.get("state", "")
            what = {"upgrade": f"{'App update' if task.get('kind') == 'app update' else 'Upgrade'} to {task.get('version', '')}",
                    "app-patch-remove": "Remove the app update",
                    "rollback": f"Roll back to snapshot {task.get('snapshot', '')}", "reboot": "Restart",
                    "plan": "Plan a restart", "plan-cancel": "Cancel the planned restart"}.get(task.get("action"), task.get("action", ""))
            out.append(f"<h2>Last change</h2><table><tbody><tr><td>{e(what)}</td><td><b>{e(state)}</b></td>"
                       f"<td>{e(task.get('requested_by_name') or task.get('requested_by') or '')}</td>"
                       f"<td class='nowrap'>{e(_when(task.get('finished') or task.get('started')))}</td></tr>"
                       + (f"<tr><td colspan=4 class='muted small'>{e(task.get('message', ''))}</td></tr>" if task.get("message") else "")
                       + "</tbody></table>")
        drain = st.get("llm_drain")
        if isinstance(drain, dict):
            until = f"at the latest at {_when(drain['until'])}" if drain.get("until") else "when it is answered"
            out.append(f"<p class='note'>The LLM queue runner lets the LLM finish the answer it is working on, then "
                       f"restarts with {e(str(drain.get('version') or 'the new code'))}: {e(until)}. Its jobs go back "
                       f"to the queue and continue on the new code with the answers they already had. It starts no "
                       f"new job meanwhile.</p>")
        pods = st.get("pod_network")
        if isinstance(pods, dict) and pods.get("restart_needed"):
            out.append(f"<p class='note'>The sandbox node has the whole pod network now ({e(str(pods.get('pod_cidr')))}, up "
                       f"to {int(pods.get('max_pods') or 0):,} pods), but its pod bridge keeps "
                       f"{e(str(pods.get('bridge')))} until the appliance restarts: plan a restart below. Until then new "
                       f"pods still get addresses from {e(str(pods.get('bridge')))}.</p>")
        elif isinstance(pods, dict) and pods.get("error"):
            out.append(f"<p class='note'>Sandbox pod network: {e(str(pods['error']))}.</p>")
        plan = st.get("restart")
        if plan:
            out.append(self.render_plan(plan, s))
        for p in self.pending():
            out.append(f"<p class='note'>Waiting for the system agent: {e(p.get('action', ''))} requested by "
                       f"{e(p.get('requested_by_name') or p.get('requested_by') or '')}.</p>")
        confirm = ("<label class='small'><input type='checkbox' name='confirm' value='yes' required> "
                   "I understand that the appliance restarts and is unavailable for a few minutes</label>")
        csrf = f"<input type='hidden' name='csrf' value='{e(s.csrf)}'>"
        dis = " disabled" if busy else ""
        out.append(f"""<h2>Restart</h2><form method='post' action='/admin/system/restart'>{csrf}
{plan_fields("restart")}<button{dis}>Plan the restart</button>
{confirm}</form>""")
        newer, err, checked = self.available(st.get("image"), st.get("version"), force)
        out.append("<h2>Upgrade</h2>")
        if err:
            out.append(f"<p class='note'>{e(err)}</p>")
        elif not newer:
            out.append(f"<p>{e(version)} is the newest release.</p>")
        else:
            def label(v):
                return f"{v}: app update, the OS does not restart" if self.app_update(st, v) else f"{v}: OS upgrade"
            opts = "".join(f"<option value='{e(v)}'>{e(label(v))}</option>" for v in newer)
            out.append(f"""<form method='post' action='/admin/system/upgrade'>{csrf}
<div class='formrow'><label for='version'>New release</label><select name='version' id='version'>{opts}</select></div>
{plan_fields("upgrade")}<button{dis}>Upgrade</button>
<label class='small'><input type='checkbox' name='confirm' value='yes' required> I understand that the appliance
restarts (an app update: its services restart) and is unavailable for a few minutes</label></form>
<p class='muted small'>The appliance checks that the image was signed by the release workflow of
<code>{e(st.get('signer') or '')}</code>. A new minor or major version is an OS upgrade: it is written as a new
snapshot next to the running one and the appliance restarts into it; if it does not pass its start-up check, the
appliance goes back to the previous snapshot by itself. A patch release of the running series is an app update:
only the application is downloaded, and only its services restart (a minute); if they do not come up, the code
that ran before is put back.</p>""")
        out.append(f"<p class='muted small'>Checked {e(_when(checked))}. <a href='/admin/system?check=1'>Check again</a></p>")
        if patch:
            out.append(f"""<h2>App update</h2><p>The application runs from the app update <b>{e(patch.get('version') or '')}</b>
on the OS of {e(os_version)}. Removing it goes back to the OS image's own code ({e(os_version)}); only the services restart.
A roll back to a snapshot removes it too.</p>
<form method='post' action='/admin/system/app-patch-remove'>{csrf}<button{dis}>Remove the app update</button>
<label class='small'><input type='checkbox' name='confirm' value='yes' required> I understand that the services restart
and scans in progress are cut off</label></form>""")
        out.append(self.render_backup(st.get("backup"), s))
        out.append(self.render_sql_access(st.get("sql_access"), s))
        snaps = st.get("snapshots") or []
        rows = []
        for x in snaps:
            sid = str(x.get("id", ""))
            act = "<b>running</b>" if x.get("active") else ""
            rows.append(f"<tr><td>{e(sid)}</td><td>{e(x.get('version') or '-')}</td><td class='nowrap'>{e(_when(x.get('date')))}</td>"
                        f"<td class='small muted'>{e(x.get('source') or '')}</td><td>{act}</td></tr>")
        earlier = [x for x in snaps if not x.get("active")]
        out.append("<h2>Snapshots</h2><p class='muted small'>Each upgrade keeps the previous systems as snapshots. Rolling "
                   "back installs the chosen snapshot as a new active system (no download) and restarts. Data on the "
                   "persistent partition (database, configuration, clones) is not touched; the database schema is not "
                   "downgraded.</p>"
                   "<table><thead><tr><th>Snapshot</th><th>Version</th><th>Installed</th><th>Source</th><th></th></tr></thead>"
                   f"<tbody>{''.join(rows) or '<tr><td colspan=5 class=muted>No snapshots reported.</td></tr>'}</tbody></table>")
        if earlier:
            opts = "".join(f"<option value='{e(str(x.get('id', '')))}'>{e(str(x.get('id', '')))}: "
                           f"{e(x.get('version') or 'unknown version')}</option>" for x in earlier)
            out.append(f"""<form method='post' action='/admin/system/rollback'>{csrf}
<div class='formrow'><label for='snapshot'>Roll back to</label><select name='snapshot' id='snapshot'>{opts}</select></div>
{plan_fields("rollback")}<button{dis}>Roll back</button>
{confirm}</form>""")
        return "".join(out)

    # -- the results database from the network (sqlaccess.py; the system agent applies it) -------

    def sql_access_post(self, s, what: str, form: dict, st: dict) -> str:
        from .sqlaccess import LOGIN, SqlAccessError, check_password, networks
        a = st.get("sql_access") or {}
        if not a.get("local"):
            return "Not changed: the results database is an external SQL Server; its DBA decides who connects."
        if what == "sql-readonly":
            if form.get("disable", [""])[0] == "1":
                self.request("sql-readonly", s.user, s.name, enabled=False)
                return f"The read-only login {LOGIN} is being disabled."
            pw, again = form.get("password", [""])[0], form.get("password2", [""])[0]
            if pw != again:
                return "Not saved: the two passwords differ."
            try:
                check_password(pw)
            except SqlAccessError as ex:
                return f"Not saved: {ex}."
            self.request("sql-readonly", s.user, s.name, enabled=True, password=pw)
            return f"The read-only login {LOGIN} gets the new password within a few seconds."
        on = form.get("enabled", [""])[0] == "1"
        try:
            nets = networks(form.get("networks", [""])[0])
        except SqlAccessError as ex:
            return f"Not saved: {ex}."
        if on and not nets:
            return "Not saved: list the networks clients connect from (for example 10.20.0.0/16)."
        self.request("sql-incoming", s.user, s.name, enabled=on, networks=nets)
        return (f"Incoming connections on port 1433 from {', '.join(nets)}: being turned on." if on
                else "Incoming connections are being turned off.")

    @staticmethod
    def render_sql_access(a: dict | None, s) -> str:
        from .sqlaccess import LOGIN, PORT
        a = a if isinstance(a, dict) else {}
        csrf = f"<input type='hidden' name='csrf' value='{e(s.csrf)}'>"
        head = "<h2 id='sql-access'>Results database access</h2>"
        if not a.get("local"):
            return head + ("<p class='muted small'>The results database is an external SQL Server (CZ_SQL_SERVER): its "
                           "DBA makes its logins and decides who connects.</p>" if a else
                           "<p class='muted small'>Not reported by the system agent yet.</p>")
        login = (f"<p>Read-only login <code>{e(LOGIN)}</code>: <b class='good'>on</b>, password set "
                 f"{e(_when(a.get('login_set_at')))}" + (f" by {e(str(a.get('login_set_by')))}" if a.get("login_set_by") else "")
                 + "</p>" if a.get("login") else
                 f"<p>Read-only login <code>{e(LOGIN)}</code>: <b>off</b>.</p>")
        listening = ", ".join(a.get("listening") or [])
        incoming = (f"<p>Incoming connections: <b class='good'>on</b> from {e(', '.join(a.get('networks') or []))}"
                    + (f"; listening on <code>{e(listening)}</code>" if listening else "; starting") + "</p>"
                    if a.get("incoming") else "<p>Incoming connections: <b>off</b> (only this appliance's own services "
                                              "connect).</p>")
        err = f"<p class='note'>{e(str(a['error']))}</p>" if a.get("error") else ""
        nets = "\n".join(a.get("networks") or [])
        return f"""{head}
<p class='muted small'>The built-in SQL Server holds the results database. A read-only login lets reporting tools (Power
BI, Excel, a SQL client) read the results views, as the results pages do; it cannot change anything. With incoming
connections on, the appliance accepts connections to port {PORT} from the networks listed here only, never from the
sandbox's applications or the builds. Clients connect to <code>&lt;appliance address&gt;,{PORT}</code>, database
<code>Containerizer</code>, with encryption and the server's own certificate (<code>TrustServerCertificate=yes</code>).</p>
{login}{incoming}{err}
<form method='post' action='/admin/system/sql-readonly' autocomplete='off'>{csrf}
<div class='formrow'><label for='sql-pw'>Password for <code>{e(LOGIN)}</code></label>
<input type='password' id='sql-pw' name='password' minlength='12' maxlength='128' autocomplete='new-password' required>
<label for='sql-pw2'>Again</label>
<input type='password' id='sql-pw2' name='password2' minlength='12' maxlength='128' autocomplete='new-password' required></div>
<p class='muted small'>12 to 128 characters with three of: upper case, lower case, digits, symbols. It is not stored on
the appliance: keep it in your password manager.</p>
<button>{'Set a new password' if a.get('login') else 'Turn on the read-only login'}</button></form>
{f"<form method='post' action='/admin/system/sql-readonly'>{csrf}<input type='hidden' name='disable' value='1'><button class='secondary'>Turn off the read-only login</button></form>" if a.get('login') else ''}
<form method='post' action='/admin/system/sql-incoming'>{csrf}
<div class='formrow'><label class='check'><input type='checkbox' name='enabled' value='1'{' checked' if a.get('incoming') else ''}>
Accept connections from the network on port {PORT}</label></div>
<label for='sql-nets'>From these networks <span class='muted'>(one per line: 10.20.0.0/16, 192.0.2.15)</span></label>
<textarea id='sql-nets' name='networks' rows='3'>{e(nets)}</textarea>
<button>Save</button></form>"""

    # -- scheduled backup (backup.py; the system agent runs it) ---------------------------------

    def backup_post(self, s, what: str, form: dict, st: dict) -> str:
        from .backup import DAYS, MAX_KEEP
        if what == "backup-now":
            b = st.get("backup") or {}
            if b.get("running") or any(p.get("action") == "backup-now" for p in self.pending()):
                return "A backup is running already."
            self.request("backup-now", s.user, s.name)
            return "Backup started: it runs in the background; this page shows it when it is done."
        t = form.get("time", [""])[0]
        keep = form.get("keep_days", [""])[0]
        days = [d for d in form.get("days", []) if d in DAYS]
        if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", t):
            return "Not saved: the time is HH:MM (UTC)."
        if not re.fullmatch(r"\d{1,3}", keep) or not 1 <= int(keep) <= MAX_KEEP:
            return f"Not saved: keep the backups 1 to {MAX_KEEP} days."
        if not days:
            return "Not saved: pick at least one day of the week."
        on = form.get("enabled", [""])[0] == "1"
        self.request("backup-settings", s.user, s.name, enabled=on, time=t, days=days, keep_days=int(keep))
        return (f"Scheduled backup saved: at {t} UTC on {_days_text(days)}, kept {int(keep)} day(s)." if on
                else "Scheduled backups are off.")

    @staticmethod
    def render_backup(b: dict | None, s) -> str:
        from .backup import DAYS, DEFAULTS, MAX_KEEP
        b = b if isinstance(b, dict) else {}
        cfg = {**DEFAULTS, **(b.get("settings") or {})}
        csrf = f"<input type='hidden' name='csrf' value='{e(s.csrf)}'>"
        last = b.get("last") or {}
        if b.get("running"):
            state = f"<p class='note'>A backup is running (started {e(_when(last.get('started')))}).</p>"
        elif last.get("finished"):
            ok = last.get("ok")
            state = (f"<p>Last backup: <b class='{'good' if ok else 'bad'}'>{'done' if ok else 'failed'}</b> "
                     f"{e(_when(last.get('finished')))}"
                     + (f", <code>{e(str(last.get('file')))}</code> ({_size(last.get('bytes'))}, "
                        f"{e(str(last.get('seconds')))} s; database: {e(str(last.get('database') or ''))})" if ok else "")
                     + "</p>" + (f"<p class='note'>{e(str(last.get('message') or ''))}</p>" if not ok else ""))
        else:
            state = "<p class='muted'>No backup has run yet.</p>"
        if b.get("error"):
            state += f"<p class='note'>{e(str(b['error']))}</p>"
        nxt = (f"Next: {e(_when(b.get('next')))}." if b.get("next") else
               "Scheduled backups are off." if not cfg.get("enabled") else "")
        days = "".join(f"<label class='check'><input type='checkbox' name='days' value='{d}'"
                       f"{' checked' if d in cfg['days'] else ''}> {d.capitalize()}</label>" for d in DAYS)
        rows = "".join(f"<tr><td><code>{e(a['name'])}</code></td><td class='nowrap'>{e(_when(a.get('at')))}</td>"
                       f"<td class='num'>{_size(a.get('bytes'))}</td></tr>" for a in (b.get("archives") or [])[:60])
        folder = e(str(b.get("folder") or "/var/lib/containerizer/backups"))
        return f"""<h2 id='backup'>Scheduled backup</h2>
<p class='muted small'>Backs up what a rebuilt appliance needs (the results database, <code>/etc/containerizer</code>
with its secrets, the dev database uploads, the appliance settings, learned rules, the HTTPS CA, OpenBao and kubemg)
into one archive in <code>{folder}</code> on the persistent partition, readable by root only. Archives older than the
days to keep are deleted after a backup that worked; the newest one always stays. Copy them off the appliance too: a
disk failure takes them with it. The archives hold every secret of the appliance.</p>
{state}<p class='muted small'>{nxt}</p>
<form method='post' action='/admin/system/backup'>{csrf}
<div class='formrow'><label class='check'><input type='checkbox' name='enabled' value='1'{' checked' if cfg.get('enabled') else ''}>
Back up on a schedule</label></div>
<div class='formrow'><label for='backup-time'>At (UTC)</label><input type='time' id='backup-time' name='time'
value='{e(cfg['time'])}' required><span class='muted small'>on</span>{days}</div>
<div class='formrow'><label for='keep-days'>Keep for</label><input type='number' id='keep-days' name='keep_days'
min='1' max='{MAX_KEEP}' value='{int(cfg['keep_days'])}' required><span>days</span></div>
<button>Save the schedule</button></form>
<form method='post' action='/admin/system/backup-now'>{csrf}<button class='secondary'
{' disabled' if b.get('running') else ''}>Back up now</button></form>
<table><thead><tr><th>Archive</th><th>Made</th><th class='num'>Size</th></tr></thead>
<tbody>{rows or "<tr><td colspan=3 class='muted'>No archives yet.</td></tr>"}</tbody></table>"""

    @staticmethod
    def app_update(st: dict, version: str) -> bool:
        """Whether the system agent installs `version` as an app update (no OS restart): a newer patch release of
        the running OS's series, on an OS image that supports them (sysagent.upgrade decides the same way)."""
        from .apppatch import is_patch_of
        return bool(st.get("app_updates")) and is_patch_of(version, st.get("os_version") or st.get("version"))

    @staticmethod
    def render_plan(plan: dict, s) -> str:
        at = rp.starts(plan)
        holding = at is not None and datetime.now(timezone.utc) >= at
        running = plan.get("running")
        if not holding:
            state = f"Scheduled for <b>{e(_when(plan.get('at')))}</b>. Until then scans and the LLM queue run as usual."
        elif plan.get("app_update"):        # the LLM runner is drained instead (sysagent.restart_services)
            state = (f"Due since {e(_when(plan.get('at')))}: no new scan starts. "
                     + ("Checking the scans in progress..." if running is None and not plan.get("checked") else
                        "The scans in progress could not be counted (database not reachable)." if running is None else
                        f"Waiting for <b>{int(running)}</b> scan run(s) in progress.")
                     + " The LLM queue keeps running: after the update it lets the LLM finish the answer in progress, "
                       "and its jobs continue on the new code.")
        elif running is None and not plan.get("checked"):
            state = "Due: no new scan or LLM job starts. Checking the work in progress..."
        elif running is None:
            state = "Due: no new scan or LLM job starts. The work in progress could not be counted (database not reachable)."
        else:
            state = (f"Due since {e(_when(plan.get('at')))}: no new scan or LLM job starts. Waiting for "
                     f"<b>{int(running)}</b> scan run(s) and LLM job(s) in progress "
                     f"<span class='muted small'>(checked {e(_when(plan.get('checked')))})</span>.")
        wait = plan.get("max_wait_minutes")
        limit = "" if wait is None or at is None else \
            f" The appliance restarts at the latest at {e(_when((at + timedelta(minutes=int(wait))).isoformat()))}."
        return (f"<h2>Planned restart</h2><p class='note'><b>{e(rp.describe(plan).capitalize())}</b>, "
                f"{e(rp.wait_text(wait))}, planned by {e(plan.get('requested_by_name') or plan.get('requested_by') or '')}."
                f"<br>{state}{limit}</p><form method='post' action='/admin/system/cancel-restart'>"
                f"<input type='hidden' name='csrf' value='{e(s.csrf)}'><button>Cancel the planned restart</button></form>")


WAIT_LABELS = {0: "Don't wait", 30: "At most 30 minutes", 60: "At most 1 hour", 120: "At most 2 hours",
               240: "At most 4 hours", 480: "At most 8 hours"}


def plan_fields(prefix: str) -> str:
    """When and how long to wait for the work in progress: the fields of the restart, upgrade and roll back forms."""
    waits = "".join(f"<option value='{m}'{' selected' if m == rp.DEFAULT_WAIT else ''}>{e(t)}</option>"
                    for m, t in WAIT_LABELS.items()) + "<option value='done'>Until the work is done</option>"
    return f"""<div class='formrow'><label for='{prefix}-when'>When</label><select name='when' id='{prefix}-when'>
<option value='now'>Now</option><option value='at'>At the time below</option></select>
<input type='datetime-local' name='at' id='{prefix}-at' aria-label='Time (UTC)'> <span class='muted small'>UTC</span></div>
<div class='formrow'><label for='{prefix}-wait'>Wait for running scans and LLM jobs</label><select name='wait' id='{prefix}-wait'>
{waits}</select></div>"""


def plan_time(form: dict) -> tuple[str | None, int | None]:
    """(when: an ISO time in UTC, None for now; minutes to wait at most, None for until the work is done)."""
    at = None
    if form.get("when", ["now"])[0] == "at":
        raw = form.get("at", [""])[0].strip()
        try:
            d = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
        except ValueError:
            raise ValueError("Give the time of the restart (UTC).") from None
        nowt = datetime.now(timezone.utc)
        if d > nowt + rp.MAX_AHEAD:
            raise ValueError(f"Plan the restart within {rp.MAX_AHEAD.days} days.")
        if d > nowt:
            at = d.isoformat(timespec="seconds")
    w = form.get("wait", [str(rp.DEFAULT_WAIT)])[0]
    if w == "done":
        return at, None
    if not w.isdigit() or int(w) not in rp.WAITS:
        raise ValueError("Pick how long to wait for the work in progress.")
    return at, int(w)


def _size(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return ""
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "bytes" else f"{n:,.1f} {unit}"
        n /= 1024
    return ""


def _days_text(days: list[str]) -> str:
    from .backup import DAYS
    return "every day" if list(days) == list(DAYS) else ", ".join(d.capitalize() for d in days)


def _when(v) -> str:
    if v in (None, ""):
        return "-"
    if isinstance(v, (int, float)):
        v = datetime.fromtimestamp(v, timezone.utc).isoformat()
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return str(v)[:40]
