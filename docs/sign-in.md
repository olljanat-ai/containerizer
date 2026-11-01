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

**Microsoft Entra ID**: register a web application with the redirect URI above and add a client secret.
Create one app role per role below (for example `Containerizer.Admin`, `Containerizer.Operator`,
`Containerizer.Read`, and one per owned business unit such as `Finance.Owner`) and assign them to groups
under Enterprise applications. Entra ID does not send `email_verified`, so use `role:` or `group:` rules
there, not `email:` or `domain:`.

## Roles

Each role is an allow-list of rules, comma separated:

| Rule | Matches |
| --- | --- |
| `group:<id>` | a group claim (Entra ID: the group's object id) |
| `role:<name>` | an app role |
| `email:<address>`, `domain:<e-mail domain>` | the e-mail address, only when the provider marks it verified (`email_verified`) |
| `sub:<subject id>` | one user |

| Role | Variable | Can |
| --- | --- | --- |
| Admin | `CONTAINERIZER_ADMINS` | Everything, including business units, Source control & LLM, Rule review, Lab services, Firewall, System and the access log. |
| Operator | `CONTAINERIZER_OPERATORS` | Read everything, including the change history. Run and schedule organization scans (discovery and full scans), enable and disable projects and repositories, order and pause the LLM queue and set when it runs, order [refactoring patches](refactoring.md) of B-rated applications and download them (Admin → Refactoring), upload dev database backups. Cannot change the mapping. |
| Product owner | `CONTAINERIZER_PRODUCT_OWNERS` | Read everything, including the change history. Map applications and change their display name, owner, description and hidden flag, and change their products, but only within their scope (below). |
| Viewer | `CONTAINERIZER_VIEWERS` | Read the results pages. Only matters when sign-in for the results pages is on. |

Refactoring patches contain source code: product owners and viewers see an order's status on the
application's results page, but not the patch, and only administrators and operators see the
**Request a refactoring patch** button ([who can order one](refactoring.md#who-can-order-one)).

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

## Sign-in for the results pages (optional)

By default anyone who reaches the web UI over HTTPS can read the results. Set `CONTAINERIZER_VIEWERS`
to limit that to named people; admins, operators and product owners can always read. Opening a results
page without a session then goes straight to the identity provider and back. People who match no
list get a "not allowed" page, and the database is not read for them.

`CONTAINERIZER_VIEW_AUDIT=true` (needs `CONTAINERIZER_VIEWERS`) records every sign-in, refused sign-in,
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
  services, rule decisions) is written by database triggers, so even direct SQL changes are recorded.
  No database role of the web UI can update or delete audit or access log rows; forward them to your
  SIEM if they must be tamper-proof.

Grafana has its own sign-in: user `admin` with the password in `/etc/containerizer/secrets/grafana-admin`,
or your identity provider through `GF_AUTH_GENERIC_OAUTH_*` settings in `/etc/containerizer/grafana.env`.
