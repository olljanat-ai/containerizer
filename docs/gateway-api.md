# Gateway API routes

Every web component (a component that serves HTTP: `web` and `spa`) gets an **HTTPRoute** in its
`<component>/k8s.yaml`. The route carries what IIS or App Service did for the application: timeouts, sticky
sessions, rewrite rules, redirects and response headers. They are set in standard Gateway API fields, so the
application code stays as it is. The route does not use vendor annotations. The mapping is data in
[`rules/60-security.yaml`](../rules/60-security.yaml) (`gateway:`).

## The platform owns the Gateway

The routes attach to a Gateway that the platform team runs. Containerizer does not generate it per app.

- Its **HTTPS listener** holds the certificate. TLS terminates at the Gateway, and the pods stay on plain
  HTTP.
- Its **HTTP listener** only redirects to HTTPS. No route attaches to it.
- The routes attach to the HTTPS listener only (`sectionName`).

The default parent is `gateway-system/platform-gateway`, listener `https`. Change it with
`--gateway <namespace>/<name>` and `--gateway-listener <listener>` (`containerizer generate`, `analyze`,
`gate`, `org`). The environment variables are `CONTAINERIZER_GATEWAY` and `CONTAINERIZER_GATEWAY_LISTENER`, or
`gateway.parent` in the rules.

An example Gateway (the class and the certificate Secret are the platform's own):

```yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: platform-gateway
  namespace: gateway-system
spec:
  gatewayClassName: example        # the implementation's class
  listeners:
    - name: https
      protocol: HTTPS
      port: 443
      hostname: "*.apps.example.com"
      tls:
        mode: Terminate
        certificateRefs: [{name: apps-example-com-tls}]
      allowedRoutes:
        namespaces: {from: All}    # or a selector on the applications' namespaces
    - name: http                   # only redirects; no route attaches here
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces: {from: Same}
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: https-redirect
  namespace: gateway-system
spec:
  parentRefs: [{name: platform-gateway, sectionName: http}]
  rules:
    - filters: [{type: RequestRedirect, requestRedirect: {scheme: https, statusCode: 301}}]
```

## Host names

A route's host is `<component>.<app>.<domain>`, or `<app>.<domain>` when the component has the app's name. The
domain is `--ingress-domain` (or the organization's setting). Without a domain, the placeholder
`example.invalid` is used, and `MIGRATION.md` says so. A wildcard certificate covers one label only: a listener
for `*.apps.example.com` matches `web.shop.apps.example.com`, but its certificate does not. Give the Gateway a
certificate per application (`*.shop.apps.example.com`), or change `gateway.host` to
`'{component}-{app}.{domain}'` so that one wildcard certificate covers every route.

## What maps to which field

| Finding or configuration | HTTPRoute |
| --- | --- |
| `host-long-request-timeout` (`executionTimeout`, ANCM `requestTimeout`) | `rules[].timeouts.request` and `backendRequest` (the longest timeout, at most 3600 s). The pod's `terminationGracePeriodSeconds` covers it too (at most 600 s). |
| `signalr-scaleout`, `host-blazor-server` | timeouts of at least 3600 s for the long-lived connections |
| `in-memory-session-scaleout`, `state-session-in-memory`, `host-arr-affinity`, `signalr-scaleout`, `host-blazor-server` | cookie session affinity at the Gateway implementation (listed in `MIGRATION.md`), or `sessionPersistence` on the rule with `gateway.session_persistence.emit: true` |
| `<rewrite>` rule, HTTP to HTTPS (`{HTTPS}` off, `X-Forwarded-Proto`, port 80) | nothing: the Gateway's HTTP listener does it |
| `<rewrite>` rule, prefix rewrite or redirect (`^old/(.*)` to `new/{R:1}`) | `URLRewrite` or `RequestRedirect` with `ReplacePrefixMatch` on a `PathPrefix` match |
| `<rewrite>` rule, one path (`^about$` to `about/`, so trailing slashes too) | `ReplaceFullPath` on an `Exact` match |
| `<rewrite>` rule, whole site to another host | `RequestRedirect` with `hostname`. With a `{HTTP_HOST}` condition, it is a route of its own for the old host, which needs a listener and a certificate for that host. |
| `<httpRedirect>` | `RequestRedirect` |
| `<httpProtocol><customHeaders>` | `ResponseHeaderModifier` (`set`, `remove`) |
| HSTS | `ResponseHeaderModifier` sets `Strict-Transport-Security` on every rule that reaches the app |

Redirects use 301 or 302, the codes in the standard channel, so every generated route deploys on a cluster with
the standard-channel CRDs.

`sessionPersistence` is in Gateway API's **experimental channel**. With only the standard-channel CRDs
installed, server-side apply (Flux) rejects a route that has it (`field not declared in schema`). So it is
opt-in. By default the route has no such field, and `MIGRATION.md` and `HARDENING.md` say the component needs
cookie session affinity at the Gateway implementation. They name the cookie (`CZAFFINITY`) and the findings
that call for it. On a cluster with the experimental CRDs, set `gateway.session_persistence.emit: true` in the
rules, and the route carries the cookie `sessionPersistence` itself. The findings are not marked resolved
either way: one replica keeps working, but scaling out needs the affinity.

## What the Gateway implementation sets

Gateway API has no standard field for some settings. `MIGRATION.md` and `HARDENING.md` list them with their
values, to set in the implementation's own policy:

- request body limits: `<requestLimits maxAllowedContentLength>`, `<httpRuntime maxRequestLength>`, and file
  uploads (`IFormFile`), which need at least the IIS and Kestrel default of 30,000,000 bytes;
- URL and query string limits (`maxUrl`, `maxQueryString`);
- client IP allow and deny lists (`<ipSecurity>`, as CIDRs).

## What is not translated

These rules are listed in `MIGRATION.md` with their original XML, to re-create at the Gateway or with ASP.NET
Core's `UseRewriter`, which reads IIS rules:

- rules with conditions on other server variables (`{HTTP_USER_AGENT}`, `{QUERY_STRING}`, `{REQUEST_FILENAME}`
  file checks);
- rules that set server variables, use rewrite maps or back-references other than `{R:1}`;
- outbound rules;
- request filtering other than the limits;
- configuration scoped to a `<location path>`.

The `web-config-rewrite` finding is marked resolved (`resolved_by: gateway-httproute`) only when every item
translated and nothing is left for the implementation.

Gateway API picks the most specific match (an exact path, then the longest prefix), while IIS runs its rules in
order. Path matches are case-sensitive, and IIS rules ignore case by default. Review overlapping rules.

## Checks and permissions

- The gate's lint checks every HTTPRoute. `route-parent`: it attaches to a Gateway. `route-listener`: it attaches
  to an HTTPS listener (`gateway.https_listener`, or the configured listener), never by port and never without a
  `sectionName`. `route-hostname`: it names its hosts, with no wildcard and no address. `HARDENING.md` reports
  these checks in its Gateway row.
- The component's NetworkPolicy lets the Gateway's namespace call the service port
  ([Inbound](egress.md#inbound)).
- The built-in `admin` role does not cover Gateway API resources. The Flux tenant (`gitops/flux/tenant.yaml`)
  therefore gets a Role for `httproutes` in the app's namespace.
- **The sandbox** keeps its Traefik Ingress ([Sandbox HTTPS](sandbox-https.md)). The appliance's Traefik has no
  Gateway API provider, so the sandbox's copy of each app's Flux Kustomization drops the HTTPRoutes.
