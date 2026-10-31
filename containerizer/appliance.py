"""The System page of the admin pages on the containerizer appliance: the running version, the OS
snapshots, newer signed releases on GHCR, and upgrade and roll back.

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
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode

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
        return bool(self.pending()) or (st.get("task") or {}).get("state") in ("queued", "running", "rebooting")

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
        tmp.write_text(json.dumps(body))
        os.chmod(tmp, 0o640)
        tmp.rename(d / f"{int(time.time() * 1000)}-{secrets.token_hex(4)}.json")

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
        if method == "POST":
            what = parts[1] if len(parts) > 1 else ""
            back = "/admin/system?"
            if form.get("confirm", [""])[0] != "yes":
                return 303, "", back + urlencode({"msg": "Tick the box to confirm: the appliance restarts."})
            if self.busy(st):
                return 303, "", back + urlencode({"msg": "An upgrade, roll back or firewall change is already in progress."})
            if what == "upgrade":
                v = form.get("version", [""])[0]
                newer, err, _ = self.available(st.get("image"), st.get("version"))
                if v not in newer:
                    return 303, "", back + urlencode({"msg": f"{v or 'That version'} is not a newer release."})
                self.request("upgrade", s.user, s.name, version=v)
                return 303, "", back + urlencode({"msg": f"Upgrade to {v} requested. The appliance verifies the "
                                                         "image signature, installs it and restarts."})
            if what == "rollback":
                sid = form.get("snapshot", [""])[0]
                ok = {str(x.get("id")) for x in st.get("snapshots") or [] if not x.get("active")}
                if not re.fullmatch(r"\d{1,6}", sid) or sid not in ok:
                    return 303, "", back + urlencode({"msg": "Pick one of the earlier snapshots."})
                self.request("rollback", s.user, s.name, snapshot=int(sid))
                return 303, "", back + urlencode({"msg": f"Roll back to snapshot {sid} requested. The appliance "
                                                         "installs it as the new active system and restarts."})
            return 404, shell("Not found", kind, "", ""), None
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
                entry = {"ports": form.get("ports", ["443"])[0] or "443", "note": form.get("note", [""])[0]}
                entry["cidr" if re.fullmatch(r"[0-9a-fA-F.:]+(/\d{1,3})?", target) else "host"] = target
                rules.append(entry)
                done = f"Allowed {target}"
            elif what == "remove":
                drop = {int(x) for x in form.get("rule", []) if re.fullmatch(r"\d{1,4}", x)}
                if not drop:
                    return 303, "", back + urlencode({"msg": "Select the rules to remove."})
                rules = [r for i, r in enumerate(rules) if i not in drop]
                done = f"Removed {len(drop)} rule(s)"
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
        out.append(f"""<h2>Allow</h2><form method='post' action='/admin/firewall'>{csrf}<input type='hidden' name='do' value='add'>
<div class='formrow'><label for='target'>Name or network</label><input name='target' id='target' required maxlength='253'
placeholder='api.nuget.org or 10.20.0.0/16'></div>
<div class='formrow'><label for='ports'>Ports</label><input name='ports' id='ports' value='443' maxlength='120'
placeholder='443 or 80,443 or udp/123'></div>
<div class='formrow'><label for='note'>Why</label><input name='note' id='note' maxlength='200'><button{pend}>Allow</button></div></form>""")
        rows = "".join(
            f"<tr><td><input type='checkbox' name='rule' value='{i}' aria-label='Select {e(r.get('host') or r.get('cidr') or '')}'></td>"
            f"<td>{e(r.get('host') or r.get('cidr') or '')}</td><td>{e(', '.join(r.get('ports') or []))}</td>"
            f"<td>{e(r.get('note') or '')}</td></tr>" for i, r in enumerate(eg.get("rules") or []))
        out.append(f"""<h2>Allowed by administrators</h2><form method='post' action='/admin/firewall'>{csrf}
<input type='hidden' name='do' value='remove'><table><thead><tr><th></th><th>Name or network</th><th>Ports</th><th>Why</th></tr></thead>
<tbody>{rows or "<tr><td colspan=4 class=muted>Nothing yet.</td></tr>"}</tbody></table>
{"<button" + pend + ">Remove selected</button>" if rows else ""}</form>""")
        denied = eg.get("denied_names") or []
        if denied:
            drows = "".join(
                f"<tr><td>{e(d['name'])}</td><td>{int(d.get('count') or 0)}</td><td><form method='post' action='/admin/firewall' "
                f"class='inline'>{csrf}<input type='hidden' name='do' value='add'><input type='hidden' name='target' "
                f"value='{e(d['name'])}'><input name='ports' value='443' size='8' aria-label='Ports for {e(d['name'])}'> "
                f"<button{pend}>Allow</button></form></td></tr>" for d in denied)
            out.append("<h2>Refused names, last 24 hours</h2><p class='muted small'>Names something on the appliance tried "
                       "to resolve (a build, the worker, an app in the sandbox). Allow only the ones you expect.</p>"
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

    def render(self, st: dict, s, force: bool = False) -> str:
        if not st:
            return ("<p class='note'>The system agent has not published its status yet. It runs at start-up; "
                    "check <code>systemctl status containerizer-sysagent</code> on the appliance.</p>")
        version = st.get("version") or "unknown"
        mode = {"active": "active system", "passive": "an earlier snapshot (fallback)",
                "recovery": "the recovery system"}.get(st.get("boot_mode"), st.get("boot_mode") or "unknown")
        busy = self.busy(st)
        task = st.get("task") or {}
        out = [f"""<div class='tiles'>
<div class='tile'><div class='label'>Running version</div><div class='value small-value'>{e(version)}</div>
<div class='sub'>{e(st.get('image') or '')}</div></div>
<div class='tile'><div class='label'>Booted from</div><div class='value small-value'>{e(mode)}</div>
<div class='sub'>Elemental {e(st.get('elemental') or '')}</div></div>
<div class='tile'><div class='label'>Status updated</div><div class='value small-value'>{e(_when(st.get('updated')))}</div>
<div class='sub'>{e(st.get('hostname') or '')}</div></div></div>"""]
        if st.get("boot_mode") == "passive":
            out.append("<p class='note'>The appliance started from an earlier snapshot, which happens when the newest one "
                       "failed its start-up check. Roll back to make this version the active one again, or upgrade.</p>")
        if task:
            state = task.get("state", "")
            what = {"upgrade": f"Upgrade to {task.get('version', '')}",
                    "rollback": f"Roll back to snapshot {task.get('snapshot', '')}"}.get(task.get("action"), task.get("action", ""))
            out.append(f"<h2>Last change</h2><table><tbody><tr><td>{e(what)}</td><td><b>{e(state)}</b></td>"
                       f"<td>{e(task.get('requested_by_name') or task.get('requested_by') or '')}</td>"
                       f"<td class='nowrap'>{e(_when(task.get('finished') or task.get('started')))}</td></tr>"
                       + (f"<tr><td colspan=4 class='muted small'>{e(task.get('message', ''))}</td></tr>" if task.get("message") else "")
                       + "</tbody></table>")
        for p in self.pending():
            out.append(f"<p class='note'>Waiting for the system agent: {e(p.get('action', ''))} requested by "
                       f"{e(p.get('requested_by_name') or p.get('requested_by') or '')}.</p>")
        confirm = ("<label class='small'><input type='checkbox' name='confirm' value='yes' required> "
                   "I understand that the appliance restarts and is unavailable for a few minutes</label>")
        csrf = f"<input type='hidden' name='csrf' value='{e(s.csrf)}'>"
        newer, err, checked = self.available(st.get("image"), st.get("version"), force)
        out.append("<h2>Upgrade</h2>")
        if err:
            out.append(f"<p class='note'>{e(err)}</p>")
        elif not newer:
            out.append(f"<p>{e(version)} is the newest release.</p>")
        else:
            opts = "".join(f"<option value='{e(v)}'>{e(v)}</option>" for v in newer)
            dis = " disabled" if busy else ""
            out.append(f"""<form method='post' action='/admin/system/upgrade'>{csrf}
<div class='formrow'><label for='version'>New release</label><select name='version' id='version'>{opts}</select>
<button{dis}>Upgrade</button></div>{confirm}</form>
<p class='muted small'>The appliance checks that the image was signed by the release workflow of
<code>{e(st.get('signer') or '')}</code>, writes it as a new snapshot next to the running one and restarts into it.
If the new version does not pass its start-up check, the appliance goes back to the previous snapshot by itself.</p>""")
        out.append(f"<p class='muted small'>Checked {e(_when(checked))}. <a href='/admin/system?check=1'>Check again</a></p>")
        snaps = st.get("snapshots") or []
        rows = []
        for x in snaps:
            sid = str(x.get("id", ""))
            act = "<b>running</b>" if x.get("active") else ""
            btn = "" if x.get("active") else (
                f"<form method='post' action='/admin/system/rollback' class='inline'>{csrf}"
                f"<input type='hidden' name='snapshot' value='{e(sid)}'>"
                f"<label class='small'><input type='checkbox' name='confirm' value='yes' required> confirm</label> "
                f"<button{' disabled' if busy else ''}>Roll back</button></form>")
            rows.append(f"<tr><td>{e(sid)}</td><td>{e(x.get('version') or '-')}</td><td class='nowrap'>{e(_when(x.get('date')))}</td>"
                        f"<td class='small muted'>{e(x.get('source') or '')}</td><td>{act}{btn}</td></tr>")
        out.append("<h2>Snapshots</h2><p class='muted small'>Each upgrade keeps the previous systems as snapshots. Rolling "
                   "back installs the chosen snapshot as a new active system (no download) and restarts. Data on the "
                   "persistent partition (database, configuration, clones) is not touched; the database schema is not "
                   "downgraded.</p>"
                   "<table><thead><tr><th>Snapshot</th><th>Version</th><th>Installed</th><th>Source</th><th></th></tr></thead>"
                   f"<tbody>{''.join(rows) or '<tr><td colspan=5 class=muted>No snapshots reported.</td></tr>'}</tbody></table>")
        return "".join(out)


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
