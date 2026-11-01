"""The results page's Build pipeline box and its downloads (pipelines.py, docs/build-pipelines.md).

- The box (webui.render_application): where the application's code lives, the files the pipeline adds, the
  Download .patch / .tar.gz links, how to apply it and the files as a diff. Administrators, operators and the
  application's product owners see all of it; everyone else sees that it exists.
- GET /admin/build-pipeline/<application id>.patch?provider=&sign=: the `git am` patch;
  GET /admin/build-pipeline/<application id>.tar.gz?provider=&sign=: the same files as a tarball.

Deterministic, no LLM, no queue: the files are made from what the scan recorded with the assessment
(assessment.json `build_pipeline`: the generated Dockerfiles, the components' folders, the files the
repository already has). The patch only adds files, so it does not need the source: it is made on an
empty commit and `git am` applies it on the assessed commit (the scan checked that none of the files
exist there) and on later ones that do not have them either. Reading the assessment's report needs the
admin login (the web login cannot read it), so the box is filled for people who may download.
"""
from __future__ import annotations

import html
import json
import re
import sys

from . import pipelines as pl

BASE = "/admin/build-pipeline"
e = html.escape


def _rows(conn, sql: str, params: tuple = ()) -> list[dict]:
    cur = conn.cursor(as_dict=True)
    cur.execute(sql, params)
    return cur.fetchall()


def _choice(q: dict, key: str, allowed: tuple, default: str | None) -> str | None:
    v = (q.get(key) or [""])[0]
    return v if v in allowed else default


def org_source(conn, repository_url: str | None) -> dict:
    """The organization scan that has the repository: Provider, ApiUrl, Registry, DefaultBranch ({} if none)."""
    if not repository_url:
        return {}
    try:
        rows = _rows(conn, "SELECT TOP (1) s.Provider, s.ApiUrl, s.Registry, r.DefaultBranch FROM cz.OrgRepository r "
                           "JOIN cz.OrgScan s ON s.ScanId = r.ScanId WHERE r.RepositoryUrl = %s AND r.RemovedAt IS NULL "
                           "ORDER BY r.LastScannedAt DESC, r.RepositoryId DESC", (repository_url,))
    except Exception:  # noqa: BLE001 - an older schema, or no access: the URL decides
        try:
            conn.rollback()
        except Exception:  # noqa: BLE001
            pass
        return {}
    return rows[0] if rows else {}


def load_spec(conn, assessment_id) -> dict | None:
    rows = _rows(conn, "SELECT ReportJson FROM cz.ApplicationAssessment WHERE AssessmentId = %s", (int(assessment_id),))
    try:
        doc = json.loads(rows[0]["ReportJson"]) if rows and rows[0].get("ReportJson") else {}
    except (TypeError, ValueError):
        doc = {}
    sp = doc.get("build_pipeline")
    return sp if isinstance(sp, dict) and sp.get("components") and sp.get("version") == pl.SPEC_VERSION else None


def resolve(spec: dict, org: dict, app: dict) -> tuple[dict, str | None, str]:
    """(spec with the organization scan's registry and branch, the provider, where the provider is known from)."""
    sp = dict(spec)
    reg = (org.get("Registry") or "").rstrip("/")
    if not sp.get("registry") and reg and reg not in pl.UNKNOWN_REGISTRIES:
        sp["registry"] = reg
    if org.get("DefaultBranch"):
        sp["branch"] = org["DefaultBranch"]
    prov = pl.detect_provider(provider=org.get("Provider"))
    if prov:
        return sp, prov, "the organization scan"
    prov = sp.get("detected") or pl.detect_provider(app.get("RepositoryUrl"), api_url=org.get("ApiUrl"))
    return sp, prov, ("the repository URL" if prov else "")


def may_download(a, conn, app: dict) -> bool:
    """Administrators and operators; product owners for their products' applications."""
    if a.admin or a.operator:
        return True
    pid = app.get("ProductId")
    if pid is None and app.get("ApplicationId") is not None:
        r = _rows(conn, "SELECT ProductId FROM cz.Application WHERE ApplicationId = %s", (int(app["ApplicationId"]),))
        pid = r[0]["ProductId"] if r else None
    return pid is not None and pid in a.products


def page_data(admin, s, app: dict, q: dict) -> dict:
    """What the box shows: {"allowed": False} for people who may not download, else the spec, the provider and
    the files (None when the assessment recorded no build pipeline)."""
    out = {"allowed": False, "signin": bool(admin)}
    if admin is None or s is None or not (s.admin or s.operator or s.scopes):
        return out
    from .roles import Access
    try:
        conn = admin.connect_admin()
    except Exception:  # noqa: BLE001
        return out
    try:
        a = Access.resolve(conn, s.admin, s.operator, s.scopes)
        if not may_download(a, conn, app):
            return out
        out["allowed"] = True
        spec = load_spec(conn, app["AssessmentId"]) if app.get("AssessmentId") is not None else None
        if spec is None:
            out["spec"] = None
            return out
        sp, prov, how = resolve(spec, org_source(conn, app.get("RepositoryUrl")), app)
    except Exception as ex:  # noqa: BLE001 - the rest of the page still shows
        print(f"build pipeline box of application {app.get('ApplicationId')}: {type(ex).__name__}: {ex}", file=sys.stderr)
        return {"allowed": False, "signin": True, "error": True}
    finally:
        conn.close()
    chosen = _choice(q, "pipeline", pl.PROVIDERS, prov)
    sign = _choice(q, "sign", pl.SIGN_MODES, "none")
    out.update(spec=sp, provider=prov, how=how, chosen=chosen, sign=sign)
    if chosen:
        fm = pl.files(sp, chosen, sign)
        out["files"] = fm
        try:
            out["patch"] = pl.patch_for(sp, chosen, sign).decode("utf-8", "replace")
        except Exception as ex:  # noqa: BLE001
            print(f"build pipeline patch of application {app.get('ApplicationId')}: {ex}", file=sys.stderr)
            out["patch"] = ""
    return out


def _md(s: str) -> str:
    """Escaped text with `code` spans."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", e(s))


def _links(app_id: int, provider: str, sign: str) -> str:
    qs = f"?provider={e(provider)}&amp;sign={e(sign)}"
    return (f"<a class='button' href='{BASE}/{int(app_id)}.patch{qs}'>Download .patch</a> "
            f"<a href='{BASE}/{int(app_id)}.tar.gz{qs}'>the files (.tar.gz)</a>")


def how_to_apply(sp: dict, provider: str, sign: str, commit: str | None, filename: str) -> str:
    c = e(str(commit or "<commit>")[:12])
    f = e(filename)
    setup = "".join(f"<li>{_md(x)}</li>" for x in pl.setup_steps(sp, provider, sign))
    return ("<h3>How to apply</h3><ol class='steps'>"
            f"<li>In a checkout of the repository, start a branch (at the assessed commit, or at your default branch: "
            f"the patch only adds files):<pre class='code'>git checkout -b containerizer-build-pipeline {c}</pre></li>"
            f"<li>Apply the patch as a commit:<pre class='code'>git am &lt; {f}</pre></li>"
            f"<li>Before the first run, in {e(pl.HOST_TEXT[provider])}:<ul>{setup}</ul></li>"
            "<li>Push the branch and open a pull request. Its first run builds every component (the pipeline file is "
            "new), makes an SBOM and scans each image, and pushes nothing.</li>"
            "<li>Merge it: the default branch builds again and pushes <code>1.&lt;yyyymmdd&gt;.&lt;hhmm&gt;</code> "
            "and <code>sha-&lt;commit&gt;</code>. The GitOps image automation of the sandbox picks the new tag up "
            "within its interval (Flux: 10 minutes to see it, 30 to commit it) when it watches the same registry.</li>"
            "</ol>")


def section(app: dict, ctx: dict | None) -> str:
    """The Build pipeline box (empty for an application with no component to build)."""
    comps = app.get("components") or []
    if not any(c.get("Verdict") != "blocker" and c.get("Tier") in ("server", None) for c in comps):
        return ""
    d = (ctx or {}).get("pipeline") or {}
    prov_url = pl.detect_provider(app.get("RepositoryUrl"))
    intro = ("<p class='muted small'>A CI pipeline for the application's own repository: on pull and merge requests it "
             "builds each component's image with the generated Dockerfile, makes an SBOM (Syft) and scans it (Trivy); "
             "on the default branch it also pushes the image with the tags the sandbox's GitOps image automation "
             "follows. Made without an LLM from this assessment; nothing is written to the repository.</p>")
    out = ["<section class='card build-pipeline' id='build-pipeline'><h2>Build pipeline</h2>", intro]
    if not d.get("allowed"):
        where = f" for {e(pl.PROVIDER_TEXT[prov_url])}" if prov_url else ""
        out.append(f"<p class='muted small'>Administrators, operators and the application's product owners can download "
                   f"the build pipeline{where} here" + (" (sign in)." if d.get("signin") else
                                                         ", or make it with <code>containerizer pipeline</code>.")
                   + "</p></section>")
        return "".join(out)
    sp = d.get("spec")
    if not sp:
        out.append("<p class='muted small'>This assessment has no build pipeline: it is made when the application is "
                   "generated (organization scans, <code>containerizer analyze --sql</code>). Scan the repository again, "
                   "or run <code>containerizer pipeline &lt;path&gt;</code> on a checkout.</p></section>")
        return "".join(out)
    app_id = int(app["ApplicationId"])
    prov, chosen, sign = d.get("provider"), d.get("chosen"), d.get("sign") or "none"
    known = (f"<b>{e(pl.HOST_TEXT[prov])}</b> (from {e(d.get('how') or '')}): {e(pl.PROVIDER_TEXT[prov])}" if prov
             else "<b>not known</b> from the repository URL: choose the provider")
    out.append(f"<div class='meta'><div><span class='label'>Code on</span> {known}</div>"
               f"<div><span class='label'>Registry</span> "
               + (f"<code>{e(sp['registry'])}</code> (the scan's)" if sp.get("registry") else
                  "not set by the scan: " + {"github": "GitHub Container Registry", "gitlab": "the project's registry",
                                             "azure-devops": "a placeholder to replace"}.get(chosen or "", "the provider's"))
               + "</div></div>")
    opts = "".join(f"<option value='{p}'{' selected' if p == chosen else ''}>{e(pl.PROVIDER_TEXT[p])}</option>"
                   for p in pl.PROVIDERS)
    signs = {"none": "No signing", "keyless": "cosign keyless (OIDC)", "key": "cosign with a key"}
    sopts = "".join(f"<option value='{m}'{' selected' if m == sign else ''}>{e(signs[m])}</option>" for m in pl.SIGN_MODES)
    pick = "" if chosen else "<option value=''>Provider…</option>"
    out.append(f"<form method='get' action='/app/{app_id}#build-pipeline' class='formrow'>"
               f"<select name='pipeline' aria-label='Provider'>{pick}{opts}</select><select name='sign' aria-label='Signing'>{sopts}</select><button>Show</button></form>")
    if not chosen:
        out.append("<p>" + " · ".join(f"{e(pl.PROVIDER_TEXT[p])}: {_links(app_id, p, sign)}" for p in pl.PROVIDERS) + "</p>")
        return "".join(out) + "</section>"
    fm = d.get("files") or {}
    out.append("<h3>Files it adds</h3><ul class='checks'>" + "".join(f"<li><code>{e(p)}</code></li>" for p in fm) + "</ul>")
    if sp.get("existing"):
        out.append("<p class='bad small'>The repository already has " + ", ".join(f"<code>{e(x)}</code>" for x in sp["existing"])
                   + ": the patch does not apply over them; use the files instead.</p>")
    if chosen == "gitlab" and sp.get("gitlab_ci"):
        out.append("<p class='small'>The repository has a <code>.gitlab-ci.yml</code>: the pipeline is "
                   "<code>containerizer.gitlab-ci.yml</code>, which it includes (see How to apply).</p>")
    if chosen == "azure-devops" and sign == "keyless":
        out.append("<p class='small'>Azure Pipelines has no OIDC token for Sigstore: the pipeline signs with a key.</p>")
    out.append(f"<p>{_links(app_id, chosen, sign)}</p>")
    out.append(how_to_apply(sp, chosen, sign, app.get("SourceCommit"), pl.patch_filename(sp.get("app") or "", chosen)))
    if d.get("patch"):
        from .admin_refactor import render_diff
        out.append(f"<details><summary>The files ({len(fm)})</summary>{render_diff(d['patch'])}</details>")
    return "".join(out) + "</section>"


# --------------------------------------------------------------------------- downloads (admin pages)

def route(adm, conn, s, a, method: str, parts: list, q: dict):
    from .admin import Response
    from .admin_scans import _nf
    m = re.fullmatch(r"(\d{1,9})\.(patch|tar\.gz)", parts[1]) if len(parts) == 2 else None
    if method != "GET" or not m:
        return _nf()
    if not (a.admin or a.operator or a.owner):
        return Response(403, adm._shell(s, a, "Not allowed", "", "<p>Your role does not include this page.</p>"))
    rows = _rows(conn, "SELECT ApplicationId, ApplicationName, ProductId, AssessmentId, SourceCommit, RepositoryUrl "
                       "FROM cz.vApplicationLatest WHERE ApplicationId = %s", (int(m[1]),))
    if not rows or not may_download(a, conn, rows[0]):
        return _nf()
    app = rows[0]
    spec = load_spec(conn, app["AssessmentId"])
    if spec is None:
        return Response(404, "No build pipeline for this assessment: scan the repository again.\n",
                        ctype="text/plain; charset=utf-8")
    sp, prov, _ = resolve(spec, org_source(conn, app.get("RepositoryUrl")), app)
    provider = _choice(q, "provider", pl.PROVIDERS, prov)
    if provider is None:
        return Response(400, "Choose the provider: ?provider=github, gitlab or azure-devops.\n",
                        ctype="text/plain; charset=utf-8")
    sign = _choice(q, "sign", pl.SIGN_MODES, "none")
    fm = pl.files(sp, provider, sign)
    name = pl.patch_filename(sp.get("app") or app["ApplicationName"], provider)
    if m[2] == "patch":
        return Response(200, pl.patch_for(sp, provider, sign), [("Content-Disposition", f'attachment; filename="{name}"')],
                        ctype="text/x-diff; charset=utf-8")
    tname = name[:-len(".patch")]
    return Response(200, pl.tarball(fm, tname), [("Content-Disposition", f'attachment; filename="{tname}.tar.gz"')],
                    ctype="application/gzip")
