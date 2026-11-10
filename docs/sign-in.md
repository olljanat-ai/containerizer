# Sign-in and roles

The web UI signs people in with your identity provider over OpenID Connect (Microsoft Entra ID, Okta,
Keycloak, Google Workspace, ...). The admin pages, the System and Firewall pages and the API appear only
once sign-in is set up. Sign-in and roles are the only web UI settings that are not on the admin pages:
they are in `/etc/containerizer/web.env` on the appliance (mode 600), because they decide who may use
the admin pages in the first place. Restart the web UI after a change
(`systemctl restart containerizer-web`).

For development without an identity provider (never on the appliance, where it is refused), see
[admin pages without sign-in](local-dev-server.md#admin-pages-without-sign-in).

## Register the app at your identity provider

The redirect URI is `https://<CZ_HOSTNAME>/auth/callback`, where `CZ_HOSTNAME` is the name set in
`appliance.env` ([first boot](appliance.md#first-boot)). Then fill in:

| Variable | Meaning |
| --- | --- |
| `CONTAINERIZER_OIDC_ISSUER` | Issuer URL, e.g. `https://login.microsoftonline.com/<tenant id>/v2.0` (Entra ID), `https://<org>.okta.com`, `https://<keycloak>/realms/<realm>` |
| `CONTAINERIZER_OIDC_CLIENT_ID` / `CONTAINERIZER_OIDC_CLIENT_SECRET` | The app registration. The secret is optional (PKCE is always used); prefer a confidential client. |
| `CONTAINERIZER_ADMINS` | Who is an administrator (see the rules below). |
| `CONTAINERIZER_OIDC_SCOPES` | Optional. Default `openid profile email`. |
| `CONTAINERIZER_PUBLIC_URL` | Optional. Default `https://<CZ_HOSTNAME>`. |

Allow the identity provider's host on **Admin → Firewall** (or in `egress.json` before the first
sign-in, e.g. `login.microsoftonline.com`): the web UI fetches its signing keys.

**Microsoft Entra ID**: register a web application (App registrations) with the redirect URI above and add a
client secret. Roles can come from groups, app roles or both:

- **Groups**: under Token configuration, add a groups claim (security groups, or only the groups assigned to
  the application) for the ID token. The claim holds the groups' object IDs, so the rules are
  `group:<object id>`. For a user in more than 200 groups Entra ID leaves the claim out of the token (it points
  to Microsoft Graph instead, which the web UI does not query), so such a user matches no `group:` rule;
  "Groups assigned to the application" avoids that.
- **App roles**: create app roles (for example `Containerizer.Admin`, `Containerizer.Operator`,
  `Containerizer.Read`, `Finance.Owner`) and assign users or groups to them under Enterprise applications. The
  rules are `role:<value>`: readable names instead of IDs, and no group limit.

Assigning groups to an application (for app roles, or "Groups assigned to the application") needs Entra ID P1
or P2. Entra ID does not send `email_verified`, so `email:` and `domain:` rules never match there.

## Roles

The operator, product owner and viewer roles come from one of two places, chosen with
`CONTAINERIZER_ROLE_SOURCE`:

- `env` (the default): allow-lists in `web.env`, described in this section.
- `ui`: an administrator gives them to people on **Admin → Users and roles**
  ([below](#roles-on-the-admin-pages)).

The two are never mixed. Administrators always come from `CONTAINERIZER_ADMINS`, in both.

Each role is an allow-list of rules, comma separated:

| Rule | Matches |
| --- | --- |
| `group:<id>` | a group claim (Entra ID: the group's object id) |
| `role:<name>` | an app role |
| `email:<address>`, `domain:<e-mail domain>` | the e-mail address, only when the provider marks it verified (`email_verified`) |
| `sub:<subject id>` | one user |

| Role | Variable | Can |
| --- | --- | --- |
| Admin | `CONTAINERIZER_ADMINS` | Everything, including business units, [application tags](#application-tags), the [sandbox databases](dev-databases.md#browse-and-fix-the-data), Source control & LLM, Rule review, Lab services, Firewall, System and the access log. |
| Operator | `CONTAINERIZER_OPERATORS` | Read everything, including the change history. Run and schedule organization scans (discovery and full scans), enable and disable projects and repositories, order and pause the LLM queue and set when it runs, order [refactoring patches](refactoring.md) of B-rated applications and download them (Admin → Refactoring), upload dev database backups, [browse and fix the sandbox databases](dev-databases.md#browse-and-fix-the-data), [tag applications](#application-tags). Cannot change the mapping. |
| Product owner | `CONTAINERIZER_PRODUCT_OWNERS` | Read everything, including the change history. Map applications and change their display name, owner, description, hidden flag and sandbox switch, and change their products, but only within their scope (below). |
| Viewer | `CONTAINERIZER_VIEWERS` | Read the results pages. Only matters when sign-in for the results pages is on. |

Applications not yet mapped to a product appear on the front page for administrators only.

Refactoring patches contain source code: product owners and viewers see an order's status on the
application's results page, but not the patch, and only administrators and operators see the
**Make it A** button ([who can order one](refactoring.md#who-can-order-one)).

Nobody outside these lists gets into `/admin`. One person can have several roles; admin includes all of
them. The roles are enforced by the web UI and the API, and every change in the change history records
the role it was made in.

**Product owner scopes.** Each entry is `<rules>=<scopes>`; entries are separated by `;`, rules and
scopes within an entry by `,`:

```sh
CONTAINERIZER_PRODUCT_OWNERS="role:Finance.Owner=bu:Finance; group:6f1c...=product:Billing,product:#12"
```

- `bu:<name>`: a business unit and every product in it, now and later. With a business unit in scope,
  the owner can also add products to it and delete empty ones.
- `product:<name>`: one product and its applications.
- `bu:#<id>` / `product:#<id>`: the same by id (the number in the admin page address). An id keeps
  working after a rename; a name scope does not. Names are matched without regard to case.

A product owner can take over unmapped applications by mapping them to one of their products, and move
their applications between their products. Everything outside their scope shows as *view only*. Scopes
are checked on every request, so a product moved to another business unit leaves (or joins) that
owner's scope at once.

### Roles on the admin pages

With `CONTAINERIZER_ROLE_SOURCE=ui` administrators give the viewer, operator and product owner roles on
**Admin → Users and roles** instead of in `web.env`:

```sh
CONTAINERIZER_ROLE_SOURCE=ui
CONTAINERIZER_ADMINS=group:6f1c...            # still required: the only way to be an administrator
CONTAINERIZER_VIEWERS_REQUIRED=true           # optional: the results pages need sign-in and a role
```

`CONTAINERIZER_OPERATORS`, `CONTAINERIZER_PRODUCT_OWNERS` and `CONTAINERIZER_VIEWERS` must then be empty or
unset: the web UI does not start, and names them, if one is set. Nobody can be made an administrator on the
page (the database refuses it too).

![Admin → Users and roles: who signed in, their roles, and the form that gives one](images/admin-users.png#only-light){ .cz-shot }
![Admin → Users and roles: who signed in, their roles, and the form that gives one](images/admin-users-dark.png#only-dark){ .cz-shot }

- **Who is listed.** Everyone who has signed in, with the e-mail address or user name and the time of
  their last sign-in. Administrators show as *admin (from configuration)*: that is whether
  `CONTAINERIZER_ADMINS` matched at their last sign-in, and it cannot be changed here.
- **Giving a role.** Choose the person, the role and, for a product owner, one or more business units
  and products (a business unit covers all its products, as `bu:` does above), and optionally a note.
  For someone who has not signed in yet, type their e-mail address instead.
- **Matching.** Roles follow the person's account at the identity provider, its stable subject (`sub`),
  not their e-mail address. A role given to an address waits until someone signs in with that address
  verified by the provider (`email_verified`; Entra ID, which does not send it, the address or user name the
  change history shows). It then belongs to that person's account; whoever gets the address later does not
  get the role.
- **Effect.** Roles are read from the database on every request, so a removed role is gone at the
  person's next click, without signing out.
- **History.** Every role given or removed is in the change history (**Users and roles**), with the
  administrator who did it and the note.
- **API.** A person's access token gets the operator and product owner roles of the account with the
  token's `sub`. With Entra ID, where `sub` differs from one application to another, that needs the API's
  audience to be the sign-in app registration; otherwise use [API keys](api.md). API clients
  (`CONTAINERIZER_API_CLIENTS`) and API keys are unchanged.

With `CONTAINERIZER_ROLE_SOURCE=env` the page is read-only: it lists the rules of each role from `web.env`.

## Application tags

Administrators and operators tag applications on their results page: **Tags**, under the owner and the
source, takes a comma-separated list such as `customer-facing, pci, wave 1` and **Save tags** replaces the
application's tags (an empty list removes them). Product owners and viewers see the tags but cannot change
them. A tag is up to 40 letters, digits, spaces and `- _ . + / & #`; an application has up to 20. Tags are
compared without regard to case, so `PCI` and `pci` are one tag, and the change history records every change.

![An application's tags on its results page, with the editor administrators and operators see](images/results-tags-edit.png#only-light){ .cz-shot }
![An application's tags on its results page, with the editor administrators and operators see](images/results-tags-edit-dark.png#only-dark){ .cz-shot }

Containerizer adds **automatic tags** from the assessment: `stateful` on an application with a server component
that keeps its own data (it runs with a persistent volume, one replica: see
[Application data on persistent volumes](overview.md#application-data-on-persistent-volumes)). It shows in
italics with the others and the filter finds it, but the editor neither shows nor stores it: nobody can add or
remove it, and it goes away when a scan no longer finds such data. The API returns people's tags only.

Everyone who can read the results filters the front page by them: the **Tags** row under the business units
lists the tags of the applications shown, with how many have each. A tag, on that row or next to an
application's name, shows only the applications with it, and the tiles, bars and groups count only those;
**Any** (or the selected tag again) clears it. A tag filter and a business unit filter combine, and the
address (`/?bu=3&tag=pci`) can be shared or bookmarked. The [API](api.md) returns the tags
(`"tags": ["pci", "wave 1"]`) and filters by one (`/api/v1/applications?tag=pci`).

![The front page filtered by a tag: only the applications with it, counted in the tiles](images/front-tags.png#only-light){ .cz-shot }
![The front page filtered by a tag: only the applications with it, counted in the tiles](images/front-tags-dark.png#only-dark){ .cz-shot }

## Sign-in for the results pages (optional)

By default anyone who reaches the web UI over HTTPS can read the results. Set `CONTAINERIZER_VIEWERS`
to limit that to named people (with `CONTAINERIZER_ROLE_SOURCE=ui`: `CONTAINERIZER_VIEWERS_REQUIRED=true`, and
give the viewer role on **Admin → Users and roles**); admins, operators and product owners can always read. Opening a results
page without a session then goes straight to the identity provider and back. People who match no
list get a "not allowed" page, and the database is not read for them.

`CONTAINERIZER_VIEW_AUDIT=true` (needs `CONTAINERIZER_VIEWERS`, or `CONTAINERIZER_VIEWERS_REQUIRED=true`) records every sign-in, refused sign-in,
results page opened and sign-out in the **access log**, which admins see on the admin pages. If a row
cannot be written, the page is not shown, so a view is never left unrecorded. The access log is personal
data: tell users their access is recorded, and keep it only as long as your policy says (deleting old
rows needs the database owner).

## Session security

- Authorization code flow with PKCE (S256), `state` and `nonce`. The ID token's signature is verified
  with the provider's published keys, as are issuer, audience and expiry; unsigned and HMAC tokens are
  refused.
- The session is a random id in an `HttpOnly`, `SameSite=Lax`, `Secure`, `__Host-` cookie, new at every
  sign-in, ending after 8 hours, 1 hour idle, or at sign-out. Sessions are kept in memory, so a restart
  signs everyone out.
- Every form carries a per-session CSRF token and cross-site posts are refused by `Origin`. Responses
  carry a strict Content-Security-Policy (no inline script), `X-Frame-Options: DENY`, HSTS and
  `no-store`; errors are logged on the server and never shown.
- The change history (business units, products, application mapping, scans, repositories, tokens, lab
  services, roles given on the admin pages, rule decisions) is written by database triggers, so even direct SQL changes are recorded.
  No database role of the web UI can update or delete audit or access log rows; forward them to your
  SIEM if they must be tamper-proof.

Grafana has its own sign-in: user `admin` with the password in `/etc/containerizer/secrets/grafana-admin`,
or your identity provider through `GF_AUTH_GENERIC_OAUTH_*` (or `GF_AUTH_AZUREAD_*`, ...) settings in
`/etc/containerizer/grafana.env`. Once a provider is enabled there (`GF_AUTH_<provider>_ENABLED=true`), the
appliance hides Grafana's user name and password form and sends people straight to the provider
(`GF_AUTH_DISABLE_LOGIN_FORM=true`, `GF_AUTH_<provider>_AUTO_LOGIN=true`; set either in `grafana.env` to choose
yourself, e.g. `GF_AUTH_DISABLE_LOGIN_FORM=false` to sign in as `admin` again). The `admin` password still works
for Grafana's API. Reboot after a change (the settings are worked out at start-up). Grafana's home page is the **Containerizer: organization scans** dashboard.
