# Sandbox identity provider

Apps that sign users in usually point at a corporate identity provider: Entra ID, AD FS or an Okta
tenant. They can't use it in a sandbox, because nobody will register a lab URL there. So `containerizer org`
deploys its own identity provider into the sandbox cluster. Every component that signs users in with
**OpenID Connect**, **SAML 2.0** or **WS-Federation** is registered there and pointed at it, through
configuration only. The app's code is never changed. Test users and groups are created too.

Everything is declarative and lives in the output repository under `sandbox/idp/`, next to the apps.
Flux applies it with the apps; the secrets come from the secret store
([External Secrets](external-secrets.md)).

## What you get

| | |
| --- | --- |
| IdP | WSO2 Identity Server 7.3 at `https://containerizer-idp.<sandbox domain>/` (console: `/console`) |
| OpenID Connect | issuer `https://containerizer-idp.<domain>/oauth2/token`, discovery `…/oauth2/token/.well-known/openid-configuration` |
| SAML 2.0 | entity ID `https://containerizer-idp.<domain>`, metadata `…/identity/metadata/saml2` |
| WS-Federation | metadata `…/wsfed-metadata/FederationMetadata/2007-06/FederationMetadata.xml`, passive endpoint `…/wsfed` |
| Test users | `alice` (group `sandbox-admins`), `bob` and `carol` (`sandbox-users`), e-mail `<user>@<domain>` |
| Where the details are shown | application page of the results UI (**Sign-in in the sandbox**), `sandbox/idp/README.md`, each component's `idp.json` |

On the appliance, `containerizer idp users` on the console prints the test users' passwords.

The IdP needs a sandbox domain (`--ingress-domain`, or the appliance's Sandbox HTTPS setting): issuer,
metadata and redirect URLs have to be the same for the browser and for the apps. Without a domain, or with
`--no-sandbox-idp`, nothing changes.

## Why WSO2 Identity Server

The IdP had to speak all three protocols that .NET line-of-business apps use, with the least to run. That
means one process, an embedded database, no licence key, and an open-source licence that lets us ship it.

| | OIDC | SAML 2.0 | WS-Federation | Licence | Notes |
| --- | --- | --- | --- | --- | --- |
| **WSO2 Identity Server 7.3** | yes | yes | yes (passive STS, built in) | Apache 2.0 | one JVM container, embedded H2, about 1 GiB RAM, REST APIs for everything |
| Keycloak + [keycloak-wsfed](https://github.com/cloudtrust/keycloak-wsfed) | yes | yes | extension | Apache 2.0 + AGPL-3.0 | the WS-Fed extension's last release targets Keycloak 8 (WildFly); it does not load in current Keycloak |
| authentik | yes | yes | Enterprise edition only | MIT / commercial | the WS-Federation provider is not in the open-source edition |
| Shibboleth IdP | (plugin) | yes | no | Apache 2.0 | SAML-first; no WS-Federation |
| A .NET IdP (Duende IdentityServer + WS-Fed plugin) | yes | plugin | plugin | commercial | needs a licence and code we would have to write and maintain |

WSO2 is the only option that covers all three protocols out of the box under a permissive licence. It
also configures entirely over documented REST APIs (applications, SCIM 2.0 users and groups, claims),
which is what makes a declarative, Git-driven setup possible.

## How a component is detected and configured

Detection rules (`rules/38-sandbox-idp.yaml`) set facts from packages and code:

| Protocol | Detected from | Settings section looked for in `appsettings.json` (+ `appsettings.Production.json`) |
| --- | --- | --- |
| OpenID Connect | `Microsoft.AspNetCore.Authentication.OpenIdConnect`, `.AddOpenIdConnect(`; Entra ID (`Microsoft.Identity.Web`) is reported | a section with `ClientId` and `Authority` or `MetadataAddress` |
| WS-Federation | `Microsoft.AspNetCore.Authentication.WsFederation`, `.AddWsFederation(` | a section with `Wtrealm`, or `MetadataAddress` and `Realm` |
| SAML 2.0 | `Sustainsys.Saml2.AspNetCore2`, `ITfoxtec.Identity.Saml2`, `.AddSaml2(` | a section named like `Saml*` with an IdP metadata key |

For each section found, the generator:

1. registers the component at the IdP as `<app>--<component>`, with its sandbox URL
   (`https://<component>-<app>.<domain>/`) as redirect URI, realm or SP entity ID;
2. overrides the keys of that section with environment variables in the component's `k8s.yaml`, for
   example `OpenIdConnect__Authority`, `OpenIdConnect__ClientId`, `WsFederation__MetadataAddress`,
   `WsFederation__Wtrealm`, `Saml2__IdpMetadata`, `Saml2__IdpEntityId`, `Saml2__EntityId`. It also sets
   `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true`, so the app builds `https://` redirect URLs behind Traefik;
3. gives an OIDC client a secret when the section has a `ClientSecret` key. The value is made once and
   kept in the secret store, and the component reads it through its existing `<component>-secrets`
   ExternalSecret (remote key `<namespace>--<component>`, property e.g. `OpenIdConnect__ClientSecret`).
   Without a `ClientSecret` key the client is public with PKCE;
4. lets the component's pods reach the IdP's public name: a CoreDNS override sends
   `containerizer-idp.<domain>` to Traefik in the cluster, and the component's egress policy allows Traefik.

The key names it matches are listed under `idp.protocols` in the rules file. A component whose sign-in
settings are only in code (no section found) is not changed; its `idp.json` and the application page
say so.

Claims, as the apps expect them from Entra ID or AD FS:

* OIDC: `sub`, `name`, `given_name`, `family_name`, `email`, `preferred_username`, `groups`;
* WS-Federation and SAML: the AD FS claim types (`…/claims/name`, `…/emailaddress`, `…/givenname`,
  `…/surname`, `…/role` from groups). The name identifier is the user name.

## What is in Git

```
sandbox/idp/
  kustomization.yaml     ConfigMaps from the files below, all resources
  namespace.yaml         containerizer-idp, Pod Security "restricted"
  secrets.yaml           ExternalSecret cz-idp (remote key containerizer-idp--cz-idp) and its store access
  server.yaml            WSO2 (PVC on the data partition, init container, Deployment, Service, Ingress, /wsfed redirect)
  sync.yaml              CronJob cz-idp-sync, every 5 minutes
  network.yaml           default deny; Traefik in, DNS + Traefik out
  dns.yaml               coredns-custom key containerizer-idp.override
  config/                deployment.toml, init.sh, FederationMetadata.xml.in
  sync/                  idp.json (claims, groups, users), apps__<app>--<component>.json, idp_sync.py
  README.md              the IdP's URLs and every registered client
```

`cz-idp-sync` applies `sync/` through WSO2's REST APIs and can run as often as you like. It creates missing
groups and users, creates or updates applications, and deletes the applications it created that are no
longer in Git. Applications someone added by hand in the console stay. It uses only the Python standard
library, talks to the IdP's public HTTPS URL and never prints a secret.

With **Argo CD** the app-of-apps may only create Applications, so apply the IdP once yourself:
`kubectl apply -k sandbox/idp`.

## Secrets

Nothing secret is in Git. The remote key `containerizer-idp--cz-idp` in the secret store holds:

| Property | |
| --- | --- |
| `admin-password` | the IdP's `admin` user (console and the sync job) |
| `keystore-password` | the IdP's own key store; the key is generated on first start and never leaves the volume |
| `user-<name>` | test users' passwords |
| `client-<app>--<component>` | OIDC client secrets; the same value is put under the component's own remote key |

On the appliance, `cz-sandbox` runs `containerizer idp secrets` every 2 minutes. Once Flux has deployed
`sandbox/idp`, it creates the values that are missing and keeps the ones that exist, through server-side
apply with field manager `containerizer-idp`. With another store (Vault, a cloud secret manager), create
these properties there yourself.

## Limitations and quirks

* **One IdP host name per repository.** When the domain changes, the IdP starts afresh: new key, empty
  database, everything rebuilt by the sync job.
* **WS-Federation tokens are SAML 2.0.** WSO2's SAML 1.1 tokens use an `xsi:type` that the .NET SAML 1.1
  reader rejects. The metadata therefore advertises `/wsfed`, which Traefik redirects to WSO2's
  `/passivests` with a request for a SAML 2.0 token.
* **WS-Federation: one role value.** WSO2 sends a user's groups as one comma-separated role value, so
  each test user is in one group.
* **.NET 8 and WS-Federation.** ASP.NET Core 8's WS-Federation handler depends on
  Microsoft.IdentityModel 7.1.2, which rejects every token (IDX10204,
  [dotnet/aspnetcore#52099](https://github.com/dotnet/aspnetcore/issues/52099)), with AD FS as with this
  IdP. Rule `wsfed-identitymodel-issuer-bug` reports it; the fix is a package reference to 7.4.1 or later.
* **OIDC `Identity.Name`.** Like Entra ID, the token has a `name` claim, not `unique_name`. An app that
  reads `User.Identity.Name` needs `TokenValidationParameters.NameClaimType = "name"`, as it would with
  Entra ID.
* **Trust of the wildcard certificate.** Apps call the IdP's metadata over HTTPS. A certificate from a
  private CA must be trusted by the app's image too (see the sandbox HTTPS settings).
* **The console is exposed** at `/console` on the sandbox domain, protected by the admin password. The
  sandbox should only be reachable from your network.
* **Entra ID-only apps** (`Microsoft.Identity.Web`) are reported, not changed: the library expects Entra
  ID's endpoints.

## How it was verified

The generated `sandbox/idp/` files were run in Docker: the WSO2 container with the same mounts, the init
script under a read-only root file system, a TLS proxy in front, and the sync job. Then three unmodified
ASP.NET Core 8 apps (`examples/sandbox-idp/`) signed in as `alice` in a real browser, configured only with
the generated environment variables. OIDC, WS-Federation and SAML 2.0 (Sustainsys) all returned the
expected claims. The Traefik redirect middleware and the CoreDNS override are standard k3s resources but
have not yet been run in a k3s cluster: they wait for the sandbox cluster CI job.
