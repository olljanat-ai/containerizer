"""Admin → Source control & LLM: the tokens organization scans use (credentials.py, docs/source-control.md).

- Organizations: a read-only token for each Azure DevOps organization, GitHub organization or GitLab
  group (on the cloud service or a self-hosted server) the scans may read. A scan of an organization
  without one does not run.
- Output repositories: a write token for each repository the generated files are pushed to, matched
  by its URL.
- LLM: the server, model and key the scans ask when "Ask the LLM" is on (the Claude API or a
  self-hosted OpenAI-compatible server). One at a time.
- Built-in LLM (the appliance only, admin_local_llm.py): a CPU-only model the appliance can run itself,
  off by default, used when no LLM is set.

Administrators only. A token is entered once, sealed for the scan worker's public key at once, and
never shown again: the page offers to replace it, not to read it. Every add, replace, change and
removal is in the change history (without the token). Same conventions as admin.py: plain HTML
forms with the session's CSRF token, everything escaped.
"""
from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from urllib.parse import urlencode

from . import credentials as cr
from .admin import URL_RE, Response, _code, _d, e, page, redirect

ORG_RE = re.compile(r"[\w .\-/]{1,200}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
MODEL_RE = re.compile(r"[\w.:/@+\-]{1,200}")
LLM_URL_RE = re.compile(r"https?://[A-Za-z0-9.-]+(:\d{1,5})?(/[^\s<>\"'`?#]*)?")
SOON_DAYS = 14

# Where the tokens are made, and with what. Shown next to the forms; docs/source-control.md has the same.
DOCS = {
    "github": {
        "pat": "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/"
               "managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token",
        "policy": "https://docs.github.com/en/organizations/managing-programmatic-access-to-your-organization/"
                  "setting-a-personal-access-token-policy-for-your-organization",
    },
    "gitlab": {
        "group": "https://docs.gitlab.com/user/group/settings/group_access_tokens/",
        "project": "https://docs.gitlab.com/user/project/settings/project_access_tokens/",
        "pat": "https://docs.gitlab.com/user/profile/personal_access_tokens/",
    },
    "azure-devops": {
        "pat": "https://learn.microsoft.com/en-us/azure/devops/organizations/accounts/"
               "use-personal-access-tokens-to-authenticate",
        "scopes": "https://learn.microsoft.com/en-us/azure/devops/integrate/get-started/authentication/oauth#scopes",
        "perms": "https://learn.microsoft.com/en-us/azure/devops/repos/git/set-git-repository-permissions",
    },
}


def _a(url: str, text: str) -> str:
    return f"<a href='{e(url)}' rel='noopener noreferrer' target='_blank'>{e(text)} ↗</a>"


def guidance(purpose: str) -> str:
    """How to make a least-privilege token, per provider."""
    d = DOCS
    if purpose == "llm":
        items = [
            ("Claude API", """<p>An API key from the Claude Console, in a workspace used only by containerizer, with a
spend limit. Server: empty for the Claude API, or the https URL of a gateway in front of it. The scans send the
model only the evidence of the components the rules are unsure of, never the whole repository.</p>"""),
            ("OpenAI-compatible server", """<p>Ollama, vLLM, LM Studio, llama.cpp <code>llama-server</code>, LocalAI and
similar: the URL up to and including <code>/v1</code> (for example <code>https://llm.example.internal/v1</code>), the
model name as the server knows it, and its key if it has one (vLLM <code>--api-key</code>, a gateway). A key is only
sent over https, or plain http to this machine. Choosing a model: docs/source-control.md#the-llm.</p>"""),
        ]
        return "".join(f"<details><summary><b>{t}</b>: what to enter</summary>{b}</details>" for t, b in items)
    if purpose == "read":
        items = [
            ("GitHub", f"""<p>A <b>fine-grained personal access token</b> ({_a(d['github']['pat'], 'GitHub docs')}):
<b>Resource owner</b> the organization, <b>Repository access</b> All repositories, <b>Repository permissions</b>
<b>Contents: Read-only</b> and <b>Metadata: Read-only</b>. No other permission, and an expiration date.
The organization may have to allow or approve fine-grained tokens first ({_a(d['github']['policy'], 'token policy')}).
A classic token needs the <code>repo</code> scope for private repositories, which can also write: the worker
warns when it sees one. GitHub Enterprise Server: Server <code>https://ghe.example.com/api/v3</code>.</p>"""),
            ("GitLab", f"""<p>A <b>group access token</b> on the group ({_a(d['gitlab']['group'], 'GitLab docs')}) with
the role <b>Reporter</b> and the scopes <b>read_api</b> and <b>read_repository</b> only, and an expiration date.
Group access tokens need Premium or Ultimate on GitLab.com (any licence on self-managed GitLab); otherwise a personal access token ({_a(d['gitlab']['pat'], 'GitLab docs')}) of an
account that is a Reporter in the group, with the same two scopes. The worker warns about any other scope.
Self-managed GitLab: Server <code>https://gitlab.example.com</code>; a subgroup is <code>group/subgroup</code>.</p>"""),
            ("Azure DevOps", f"""<p>A <b>personal access token</b> ({_a(d['azure-devops']['pat'], 'Microsoft docs')})
for <b>this organization only</b> (not "All accessible organizations", which Azure DevOps is retiring), with <b>Custom defined</b> scopes
<b>Code: Read</b> and <b>Project and Team: Read</b> ({_a(d['azure-devops']['scopes'], 'scopes')}), and an expiration
date. Best made by a dedicated account that can read the repositories but not change them. Azure DevOps
Server: Server <code>https://tfs.example.com/tfs</code> and the collection as the organization.</p>"""),
        ]
    else:
        items = [
            ("GitHub", f"""<p>A separate <b>fine-grained personal access token</b> ({_a(d['github']['pat'], 'GitHub docs')}):
<b>Repository access</b> Only select repositories: the output repository alone, <b>Contents: Read and write</b>,
nothing else. Never the organization's read-only token.</p>"""),
            ("GitLab", f"""<p>A <b>project access token</b> on the output project ({_a(d['gitlab']['project'], 'GitLab docs')})
with the role <b>Developer</b> (Maintainer if Developers may not push to the branch) and the scopes
<b>read_repository</b> and <b>write_repository</b>.</p>"""),
            ("Azure DevOps", f"""<p>A <b>personal access token</b> with the scope <b>Code: Read &amp; write</b>
({_a(d['azure-devops']['pat'], 'Microsoft docs')}). It reaches every repository its account can write to, so make it
for a dedicated account whose only <b>Contribute</b> permission is on the output repository
({_a(d['azure-devops']['perms'], 'repository permissions')}).</p>"""),
        ]
    return "".join(f"<details><summary><b>{t}</b>: how to make the token</summary>{b}</details>" for t, b in items)


# --------------------------------------------------------------------------- routing

def route(adm, conn, s, a, method: str, parts: list, q: dict, form: dict) -> Response:
    flash = q.get("msg", [""])[0][:300]
    ident = int(parts[1]) if len(parts) > 1 and re.fullmatch(r"\d{1,9}", parts[1]) else None
    action = parts[2] if len(parts) > 2 else ""
    if len(parts) == 1 and method == "GET":
        return list_page(adm, conn, s, a, flash)
    if len(parts) == 2 and parts[1] == "local-llm" and method == "POST":
        from . import admin_local_llm
        return admin_local_llm.post(adm, s, a, form)
    if len(parts) == 2 and parts[1] in ("read", "write", "llm") and method == "POST":
        return add(adm, conn, s, parts[1], form)
    if ident is not None:
        if method == "GET" and not action:
            return edit_page(adm, conn, s, a, ident, flash)
        if method == "POST" and action in ("", "token", "delete"):
            return {"": save_settings, "token": replace_token, "delete": delete}[action](adm, conn, s, ident, form)
    return Response(404, page("Not found", "<h1>Not found</h1>"))


def _back(url: str, msg: str) -> Response:
    return redirect(url + ("&" if "?" in url else "?") + urlencode({"msg": msg}))


def _key(adm):
    """(public key, key id) of the scan worker, or (None, None) when the web UI has none."""
    k = getattr(adm, "credential_key", None)
    return (k, cr.key_id(k)) if k is not None else (None, None)


def _rows(conn) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(f"SELECT {cr.SELECT_COLS} FROM cz.SourceCredential ORDER BY Purpose, Provider, Host, Scope")
    return cur.fetchall()


def _scans(conn) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute("SELECT ScanId, Name, Provider, Organization, ApiUrl, OutputRepo, UseAi, Enabled FROM cz.OrgScan ORDER BY Name")
    return cur.fetchall()


def _used_by(c: cr.Credential, scans: list[dict]) -> list[dict]:
    one = cr.Credentials([c])
    if c.purpose == "read":
        return [x for x in scans if one.read_for(x["Provider"], x["ApiUrl"], x["Organization"])]
    if c.purpose == "llm":
        return [x for x in scans if x.get("UseAi")] if c.enabled else []
    return [x for x in scans if one.write_for(x["OutputRepo"])]


def status(r: dict, kid: str | None, today: date | None = None) -> list[tuple[str, str]]:
    """(css, text) chips for a credential row."""
    today = today or datetime.now(timezone.utc).date()
    out = []
    if not r["Enabled"]:
        out.append(("st-off", "Disabled"))
    if r.get("ExpiresOn"):
        if r["ExpiresOn"] < today:
            out.append(("st-bad", f"Expired {r['ExpiresOn']:%Y-%m-%d}"))
        elif r["ExpiresOn"] <= today + timedelta(days=SOON_DAYS):
            out.append(("st-run", f"Expires {r['ExpiresOn']:%Y-%m-%d}"))
    if kid and (r.get("KeyId") or "").strip() != kid:
        out.append(("st-bad", "Saved for another worker key: enter it again"))
    res = r.get("LastResult") or ""
    if res.startswith("failed"):
        out.append(("st-bad", "Last use failed"))
    elif "warning:" in res:
        out.append(("st-run", "Warning"))
    elif res.startswith("ok"):
        out.append(("st-ok", "Working"))
    return out


def _chips(chips) -> str:
    return " ".join(f"<span class='st {c}'>{e(t)}</span>" for c, t in chips)


def _provider_select(name: str = "Provider", selected: str = "github") -> str:
    return (f"<select id='{name}-{selected}' name='{name}'>" + "".join(
        f"<option value='{k}'{' selected' if k == selected else ''}>{t}</option>" for k, t in cr.PROVIDER_TEXT.items())
        + "</select>")


def _token_input(field_id: str, label: str = "Token", required: bool = True) -> str:
    return (f"<label for='{field_id}'>{label} <span class='muted'>(shown only while you type it; never shown again"
            f"{'' if required else '; empty when the server needs none'})</span></label><input id='{field_id}' name='Token' "
            f"type='password'{' required' if required else ''} minlength='8' maxlength='1000' autocomplete='off' spellcheck='false'>")


def _common_inputs(prefix: str, r: dict | None = None) -> str:
    r = r or {}
    exp = r.get("ExpiresOn")
    return (f"<label for='{prefix}ExpiresOn'>Expires on <span class='muted'>(the date you set on the token; "
            f"the pages warn {SOON_DAYS} days before)</span></label>"
            f"<input id='{prefix}ExpiresOn' name='ExpiresOn' type='date' value='{exp:%Y-%m-%d}'>" if exp else
            f"<label for='{prefix}ExpiresOn'>Expires on <span class='muted'>(the date you set on the token; "
            f"the pages warn {SOON_DAYS} days before)</span></label><input id='{prefix}ExpiresOn' name='ExpiresOn' type='date'>") + \
        (f"<label for='{prefix}Note'>Note <span class='muted'>(who owns the token, where it was made)</span></label>"
         f"<input id='{prefix}Note' name='Note' maxlength='400' value='{e(r.get('Note') or '')}'>")


def list_page(adm, conn, s, a, flash: str) -> Response:
    pub, kid = _key(adm)
    rows, scans = _rows(conn), _scans(conn)
    today = datetime.now(timezone.utc).date()

    def table(purpose: str) -> str:
        out = []
        for r in (x for x in rows if x["Purpose"] == purpose):
            c = cr.Credential.from_row(r)
            used = _used_by(c, scans)
            used_html = ", ".join(f"<a href='/admin/scans/{int(x['ScanId'])}'>{e(x['Name'])}</a>" for x in used) or \
                "<span class='muted'>no scan yet</span>"
            where = e(r["Host"]) + (f"<div class='muted small'>{e(r['ApiUrl'])}</div>" if r["ApiUrl"] else "")
            last = (f"{_d(r['LastUsedAt'])}<div class='muted small'>{e((r['LastResult'] or '')[:300])}</div>"
                    if r["LastUsedAt"] else "<span class='muted'>not used yet</span>")
            out.append(f"<tr><td><a href='/admin/source-control/{int(r['CredentialId'])}'>{e(r['Scope'])}</a>"
                       f"<div class='muted small'>{e(cr.PROVIDER_TEXT.get(r['Provider'], r['Provider']))}</div></td>"
                       f"<td>{where}</td><td>{_chips(status(r, kid, today))}<div class='muted small'>token saved "
                       f"{_d(r['TokenSetAt'])} by {e(r['TokenSetBy'])}</div></td><td>{used_html}</td><td>{last}</td></tr>")
        what = "Organization" if purpose == "read" else "Repository"
        return (f"<table><thead><tr><th>{what}</th><th>Host</th><th>Token</th><th>Used by</th><th>Last used</th></tr></thead>"
                f"<tbody>{''.join(out) or '<tr><td colspan=5 class=muted>None registered.</td></tr>'}</tbody></table>")

    if pub is None:
        key_note = ("<p class='note'>Tokens cannot be added: the web UI has no worker public key. Make a key pair with "
                    "<code>containerizer credentials keygen --private worker-key.pem --public worker-key.pub</code>, give "
                    f"the worker <code>{cr.PRIVATE_KEY_ENV}</code> and the web UI <code>{cr.PUBLIC_KEY_ENV}</code> "
                    "(docs/source-control.md). The appliance does this by itself.</p>")
        read_form = write_form = llm_form = ""
    else:
        key_note = (f"<p class='muted small'>Tokens are sealed for the scan worker's key <code>{e(kid)}</code> as soon as "
                    "you save them: this page cannot show them again, only replace them.</p>")
        read_form = f"""<h3>Add a read-only token for an organization</h3>
<p class='muted'>First make the token at your provider, with the least privileges below, then enter it here.</p>
{guidance('read')}
<form method='post' action='/admin/source-control/read' class='edit'>{adm._csrf(s)}
<label for='Provider-github'>Provider</label>{_provider_select()}
<label for='rOrganization'>Organization <span class='muted'>(Azure DevOps organization or collection, GitHub
organization, GitLab group path)</span></label><input id='rOrganization' name='Organization' required maxlength='200' placeholder='contoso'>
<label for='rApiUrl'>Server <span class='muted'>(self-hosted only: https://ghe.example.com/api/v3, https://gitlab.example.com,
https://tfs.example.com/tfs; empty: github.com, gitlab.com, dev.azure.com)</span></label>
<input id='rApiUrl' name='ApiUrl' type='url' maxlength='400' placeholder='https://'>
{_token_input('rToken')}{_common_inputs('r')}
<div><button>Add</button></div></form>"""
        write_form = f"""<h3>Add a write token for an output repository</h3>
<p class='muted'>The repository the generated Dockerfiles, manifests and GitOps files are pushed to. Its token is used
for nothing else, even when the repository is in an organization that is scanned, and the repository itself is never scanned.
The internal rules repository of the <a href='/admin/rules#repository'>rule review</a> gets its write token here too.</p>
{guidance('write')}
<form method='post' action='/admin/source-control/write' class='edit'>{adm._csrf(s)}
<label for='Provider-gitlab'>Provider</label>{_provider_select(selected='gitlab')}
<label for='wScope'>Repository URL <span class='muted'>(https, as on the scan's Output repository)</span></label>
<input id='wScope' name='Scope' type='url' required maxlength='400' placeholder='https://github.com/contoso/sandbox-deployments.git'>
{_token_input('wToken')}{_common_inputs('w')}
<div><button>Add</button></div></form>"""
        llm_form = ""
        if not any(r["Purpose"] == "llm" for r in rows):
            from .ai import CLAUDE_DEFAULT_MODEL
            llm_form = f"""<h3>Set the LLM</h3>
{guidance('llm')}
<form method='post' action='/admin/source-control/llm' class='edit'>{adm._csrf(s)}
<label for='lProvider'>Kind</label><select id='lProvider' name='Provider'>{''.join(
    f"<option value='{k}'>{t}</option>" for k, t in cr.LLM_PROVIDERS.items())}</select>
<label for='lApiUrl'>Server <span class='muted'>(Claude API: empty, or a gateway's https URL; OpenAI-compatible: the URL up to
and including /v1)</span></label><input id='lApiUrl' name='ApiUrl' type='url' maxlength='400' placeholder='https://llm.example.internal/v1'>
<label for='lModel'>Model</label><input id='lModel' name='Model' required maxlength='200' value='{e(CLAUDE_DEFAULT_MODEL)}'>
{_token_input('lToken', 'API key', required=False)}{_common_inputs('l')}
<div><button>Save</button></div></form>"""
    llm = next((r for r in rows if r["Purpose"] == "llm"), None)
    if llm:
        used = _used_by(cr.Credential.from_row(llm), scans)
        llm_html = (f"<div class='meta'><div><span class='label'>LLM</span> <a href='/admin/source-control/"
                    f"{int(llm['CredentialId'])}'>{e(cr.LLM_PROVIDERS.get(llm['Provider'], llm['Provider']))}: "
                    f"{e(llm['Model'] or '')}</a> <span class='muted small'>{e(llm['ApiUrl'] or llm['Host'])}</span> "
                    f"{_chips(status(llm, kid, today))}</div><div><span class='label'>Used by</span> "
                    + (", ".join(f"<a href='/admin/scans/{int(x['ScanId'])}'>{e(x['Name'])}</a>" for x in used)
                       or "<span class='muted'>no scan asks the LLM</span>") + "</div></div>")
    elif getattr(adm, "system", None):
        llm_html = ("<p class='muted'>None set: scans with <i>Ask the LLM</i> use the built-in LLM below when it is on, "
                    "else the worker's own settings (environment variables), if any.</p>")
    else:
        llm_html = ("<p class='muted'>None set: scans with <i>Ask the LLM</i> use the worker's own settings "
                    "(environment variables), if any.</p>")
    from . import admin_local_llm
    body = (f"<p class='muted'>Organization scans only read organizations that have a read-only token here: there is no "
            f"anonymous access, and each token is only sent with its own organization's or repository's URLs. On the "
            f"appliance, the hosts must also be on the Firewall page.</p>{key_note}"
            f"<h2>Organizations (read-only)</h2>{table('read')}{read_form}"
            f"<h2>Output repositories (write)</h2>{table('write')}{write_form}"
            f"<h2>LLM</h2>{llm_html}{llm_form}{admin_local_llm.section(adm, s, a, registered=llm is not None)}")
    return Response(200, adm._shell(s, a, "Source control and LLM", "source-control", body, flash))


# --------------------------------------------------------------------------- validation

def _common(form: dict) -> tuple[dict, list[str]]:
    v, errors = {}, []
    exp = form.get("ExpiresOn", [""])[0].strip()
    v["ExpiresOn"] = None
    if exp:
        try:
            if not DATE_RE.fullmatch(exp):
                raise ValueError
            v["ExpiresOn"] = date.fromisoformat(exp)
        except ValueError:
            errors.append("Expires on: a date as YYYY-MM-DD")
    note = " ".join(form.get("Note", [""])[0].split())
    if len(note) > 400:
        errors.append("Note is longer than 400 characters")
    v["Note"] = note or None
    return v, errors


def _llm_url_error(provider: str, url: str | None, token: str) -> str | None:
    if not url:
        return "Server is required for an OpenAI-compatible server" if provider == "openai" else None
    if len(url) > 400 or not LLM_URL_RE.fullmatch(url):
        return "Server must be a plain http(s):// address without user name, query or fragment"
    if provider == "anthropic" and not url.startswith("https://"):
        return "Server must be an https:// address"
    if url.startswith("http://") and token:
        import ipaddress
        host = cr._split(url)[1].split(":")[0]
        try:
            loop = host == "localhost" or ipaddress.ip_address(host).is_loopback
        except ValueError:
            loop = False
        if not loop:
            return "A key is only sent over https (or plain http to this machine): use an https:// server"
    return None


def validate_llm(form: dict) -> tuple[dict, list[str]]:
    v, errors = _common(form)
    prov = form.get("Provider", [""])[0]
    if prov not in cr.LLM_PROVIDERS:
        errors.append("Choose the kind of LLM")
    v["Provider"] = prov
    api = form.get("ApiUrl", [""])[0].strip().rstrip("/") or None
    tok = form.get("Token", [""])[0].strip()
    err = _llm_url_error(prov, api, tok)
    errors += [err] if err else []
    v["ApiUrl"] = api if api and cr.server_key(prov, api) else None
    model = form.get("Model", [""])[0].strip()
    if not MODEL_RE.fullmatch(model):
        errors.append("Model: the model's name (letters, digits and . : / @ + - _)")
    v["Model"] = model
    if prov == "anthropic" and not tok:
        errors.append("Enter the API key")
    elif tok:
        err = cr.check_token_text(tok)
        errors += [err] if err else []
    v["Token"], v["Scope"] = tok, cr.LLM_SCOPE
    v["Host"] = cr.host_of(prov, v["ApiUrl"]) if prov in cr.LLM_PROVIDERS and not errors else ""
    return v, errors


def validate(purpose: str, form: dict) -> tuple[dict, list[str]]:
    if purpose == "llm":
        return validate_llm(form)
    v, errors = _common(form)
    prov = form.get("Provider", [""])[0]
    if prov not in cr.PROVIDER_TEXT:
        errors.append("Choose a provider")
    v["Provider"] = prov
    if purpose == "read":
        org = " ".join(form.get("Organization", [""])[0].split()).strip("/")
        if not org:
            errors.append("Organization is required")
        elif not ORG_RE.fullmatch(org):
            errors.append("Organization: letters, digits, space, . _ - and / only")
        api = form.get("ApiUrl", [""])[0].strip().rstrip("/")
        if api and (len(api) > 400 or not URL_RE.fullmatch(api)):
            errors.append("Server must be a plain https:// address")
        v["Scope"], v["ApiUrl"] = org, (api if api and prov in cr.PROVIDER_TEXT and cr.server_key(prov, api) else None)
        v["Host"] = cr.host_of(prov, v["ApiUrl"]) if prov in cr.PROVIDER_TEXT and not errors else ""
    else:
        url = form.get("Scope", [""])[0].strip()
        if not url:
            errors.append("Repository URL is required")
        elif len(url) > 400 or not URL_RE.fullmatch(url) or "@" in url.split("/")[2] or "?" in url or "#" in url:
            errors.append("Repository URL must be a plain https:// address without user name, query or fragment")
        else:
            url = url.rstrip("/")
            guess = cr.guess_provider(url)
            if guess and prov in cr.PROVIDER_TEXT and guess != prov:
                errors.append(f"That repository is on {cr.PROVIDER_TEXT[guess]}, not {cr.PROVIDER_TEXT[prov]}")
        v["Scope"], v["ApiUrl"] = url, None
        v["Host"] = cr._split(url)[1] if url and not errors else ""
    tok = form.get("Token", [""])[0].strip()
    err = cr.check_token_text(tok)
    if err:
        errors.append(err)
    v["Token"] = tok
    return v, errors


# --------------------------------------------------------------------------- changes

def add(adm, conn, s, purpose: str, form: dict) -> Response:
    pub, kid = _key(adm)
    if pub is None:
        return _back("/admin/source-control", "Not saved: the web UI has no worker public key.")
    v, errors = validate(purpose, form)
    if errors:
        return _back("/admin/source-control", "Not saved: " + "; ".join(errors))
    sealed = cr.seal(pub, v.pop("Token"), cr.binding(purpose, v["Provider"], v["ApiUrl"], v["Scope"]))
    cur = conn.cursor()
    try:
        if purpose == "llm":
            # one LLM: the check and the insert in one transaction, so two admins cannot add two
            cur.execute("SELECT COUNT(*) FROM cz.SourceCredential WITH (UPDLOCK, HOLDLOCK) WHERE Purpose = N'llm'")
            if cur.fetchone()[0]:
                conn.rollback()
                return _back("/admin/source-control", "An LLM is already set: open it to change it, or remove it first.")
        cur.execute("INSERT cz.SourceCredential (Purpose, Provider, ApiUrl, Host, Scope, Model, Note, ExpiresOn, TokenSealed, "
                    "KeyId, TokenSetBy) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s); SELECT CAST(SCOPE_IDENTITY() AS int)",
                    (purpose, v["Provider"], v["ApiUrl"], v["Host"], v["Scope"], v.get("Model"), v["Note"], v["ExpiresOn"],
                     sealed, kid, s.user[:256]))
        ident = cur.fetchone()[0]
        conn.commit()
    except Exception as ex:
        conn.rollback()
        if _code(ex) in (2601, 2627):
            return _back("/admin/source-control", f"{v['Scope']} already has a token: open it to replace the token.")
        raise
    if purpose == "llm":
        return _back(f"/admin/source-control/{ident}", "LLM saved. Scans with Ask the LLM use it from their next run.")
    what = "Read-only token" if purpose == "read" else "Write token"
    return _back(f"/admin/source-control/{ident}", f"{what} saved for {v['Scope']}. The next run of its scans uses it.")


def _one(conn, ident: int) -> dict | None:
    cur = conn.cursor(as_dict=True)
    cur.execute(f"SELECT {cr.SELECT_COLS} FROM cz.SourceCredential WHERE CredentialId = %s", (ident,))
    return cur.fetchone()


def edit_page(adm, conn, s, a, ident: int, flash: str) -> Response:
    r = _one(conn, ident)
    if not r:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    pub, kid = _key(adm)
    c = cr.Credential.from_row(r)
    used = _used_by(c, _scans(conn))
    llm = c.purpose == "llm"
    kind = {"read": "Read-only token of the organization", "write": "Write token of the output repository",
            "llm": "The LLM scans ask when Ask the LLM is on"}[c.purpose]
    facts = [("Access", {"read": "read only: lists and clones the organization's repositories",
                         "write": "write: pushes the generated files to this repository only",
                         "llm": "the evidence of uncertain components is sent to this server"}[c.purpose]),
             ("Provider", e((cr.LLM_PROVIDERS if llm else cr.PROVIDER_TEXT).get(c.provider, c.provider))),
             ("Model", e(c.model) if llm else ""), ("Host", e(r["Host"])),
             ("Server", e(r["ApiUrl"] or "")), ("Token", f"{_chips(status(r, kid))} saved {_d(r['TokenSetAt'])} by "
                                                        f"{e(r['TokenSetBy'])}"),
             ("Used by", ", ".join(f"<a href='/admin/scans/{int(x['ScanId'])}'>{e(x['Name'])}</a>" for x in used)
              or "no scan yet"),
             ("Last used", (_d(r["LastUsedAt"]) + " · " + e(r["LastResult"] or "")) if r["LastUsedAt"] else "not used yet")]
    meta = "".join(f"<div><span class='label'>{k}</span> {v}</div>" for k, v in facts if v)
    replace = (f"<form method='post' action='/admin/source-control/{ident}/token' class='edit'>{adm._csrf(s)}"
               f"{_token_input('newToken', 'API key' if llm else 'Token', required=not llm or c.provider == 'anthropic')}"
               f"<label for='tExpiresOn'>Expires on</label>"
               f"<input id='tExpiresOn' name='ExpiresOn' type='date'><div><button>Replace the token</button></div></form>"
               if pub is not None else "<p class='muted'>The web UI has no worker public key: tokens cannot be replaced.</p>")
    model_in = (f"<label for='sModel'>Model</label><input id='sModel' name='Model' required maxlength='200' "
                f"value='{e(c.model)}'>") if llm else ""
    settings = (f"<form method='post' action='/admin/source-control/{ident}' class='edit'>{adm._csrf(s)}"
                f"{model_in}{_common_inputs('s', r)}<label class='check'><input type='checkbox' name='Enabled' value='1'"
                f"{' checked' if r['Enabled'] else ''}> Enabled (unchecked: scans that need it do not run)</label>"
                f"<div><button>Save</button> <a href='/admin/source-control'>Back</a></div></form>")
    delete = (f"<form method='post' action='/admin/source-control/{ident}/delete' class='danger'>{adm._csrf(s)}"
              f"<button>Remove the token for {e(c.scope)}</button></form><p class='muted small'>Also revoke it where it was "
              f"made: removing it here only stops this tool from using it.</p>")
    what = "server" if llm else "organization or repository"
    body = (f"<p class='muted'>{kind}. To point it at another {what}, remove it and add a new one."
            f"</p><div class='meta'>{meta}</div><h2>Replace the {'key' if llm else 'token'}</h2>{replace}{guidance(c.purpose)}"
            f"<h2>Settings</h2>{settings}{delete}<h2>Changes</h2>{adm._history(conn, 'SourceCredential', ident)}")
    return Response(200, adm._shell(s, a, "LLM" if llm else c.scope, "source-control", body, flash))


def replace_token(adm, conn, s, ident: int, form: dict) -> Response:
    pub, kid = _key(adm)
    back = f"/admin/source-control/{ident}"
    if pub is None:
        return _back(back, "Not saved: the web UI has no worker public key.")
    r = _one(conn, ident)
    if not r:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    v, errors = _common(form)
    tok = form.get("Token", [""])[0].strip()
    c = cr.Credential.from_row(r)
    if c.purpose == "llm" and c.provider == "openai" and not tok:
        err = None                                   # a server without a key
    else:
        err = cr.check_token_text(tok)
    if c.purpose == "llm" and not err:
        err = _llm_url_error(c.provider, c.api_url, tok)
    errors += [err] if err else []
    if errors:
        return _back(back, "Not saved: " + "; ".join(errors))
    sealed = cr.seal(pub, tok, c.aad())
    cur = conn.cursor()
    cur.execute("UPDATE cz.SourceCredential SET TokenSealed = %s, KeyId = %s, TokenSetAt = SYSUTCDATETIME(), TokenSetBy = %s"
                + (", ExpiresOn = %s" if v["ExpiresOn"] else "") + " WHERE CredentialId = %s",
                (sealed, kid, s.user[:256], *([v["ExpiresOn"]] if v["ExpiresOn"] else []), ident))
    conn.commit()
    return _back(back, "Token replaced. Revoke the old one where it was made.")


def save_settings(adm, conn, s, ident: int, form: dict) -> Response:
    back = f"/admin/source-control/{ident}"
    v, errors = _common(form)
    r = _one(conn, ident)
    if not r:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    model = form.get("Model", [""])[0].strip() if r["Purpose"] == "llm" else None
    if r["Purpose"] == "llm" and not MODEL_RE.fullmatch(model):
        errors.append("Model: the model's name (letters, digits and . : / @ + - _)")
    if errors:
        return _back(back, "Not saved: " + "; ".join(errors))
    cur = conn.cursor()
    cur.execute("UPDATE cz.SourceCredential SET Note = %s, ExpiresOn = %s, Enabled = %s"
                + (", Model = %s" if model is not None else "") + " WHERE CredentialId = %s",
                (v["Note"], v["ExpiresOn"], form.get("Enabled", [""])[0] == "1", *([model] if model is not None else []), ident))
    n = cur.rowcount
    conn.commit()
    if not n:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    return _back(back, "Saved.")


def delete(adm, conn, s, ident: int, form: dict) -> Response:
    cur = conn.cursor()
    cur.execute("DELETE cz.SourceCredential WHERE CredentialId = %s", (ident,))
    n = cur.rowcount
    conn.commit()
    if not n:
        return Response(404, page("Not found", "<h1>Not found</h1>"))
    return _back("/admin/source-control", "Token removed. Revoke it where it was made, too.")


def scan_tokens(conn, scan: dict) -> str:
    """The tokens a scan will use, for its page (no token values: what they are for and their state)."""
    rows = _rows(conn)
    creds = cr.Credentials([cr.Credential.from_row(r) for r in rows if r["Enabled"]])
    by_id = {int(r["CredentialId"]): r for r in rows}
    out = []
    read = creds.read_for(scan["Provider"], scan["ApiUrl"], scan["Organization"])
    write = creds.write_for(scan.get("OutputRepo"))
    llm = creds.llm() if scan.get("UseAi") else None
    for c, what in ((read, "Read-only token"), (write, "Output repository token"), (llm, "LLM")):
        if c:
            out.append(f"<div><span class='label'>{what}</span> <a href='/admin/source-control/{c.id}'>{e(c.label)}</a> "
                       f"{_chips(status(by_id[c.id], None))}</div>")
    return f"<div class='meta'>{''.join(out)}</div>" if out else ""
