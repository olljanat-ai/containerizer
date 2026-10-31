# Sandbox HTTPS

Publish the apps that the organization scans deploy to the sandbox cluster over HTTPS, under one
wildcard domain that an administrator sets up. Each component that serves HTTP gets its own address,
the sandbox health check opens it, and the application page and `sandbox/HEALTH.md` link to it.

## What you need

- **A domain for the sandbox apps**, for example `sandbox.example.com`. Give the sandbox a domain of its
  own: not the domain the admin pages are under. The appliance refuses a domain that contains its own
  host name, so an app can never share a name with the admin pages. A separate registrable domain
  (`example-sandbox.net`) isolates the apps from your other sites best.
- **A wildcard certificate for `*.<domain>`** with its private key, both in PEM:
    - the server certificate first, then its intermediates (the root is optional);
    - RSA with at least 2048 bits, or ECDSA P-256 or P-384;
    - the key without a password (`openssl pkey -in key.pem -out plain.pem`);
    - valid now. The page warns when it expires within 30 days. Renew it before then and paste the new one.
- **A DNS record** that points the wildcard name at the appliance (see [DNS](#dns)).

A certificate from a public CA works in every browser. A certificate from your internal CA works where
that CA is trusted, including the appliance's own health check (see [The health check](#the-health-check)).

## Set it up

**Admin → Sandbox HTTPS** (administrators only, on the appliance):

1. Enter the domain as `*.sandbox.example.com`, paste the certificate chain and the private key, and click **Save**.
2. The page checks what you pasted before it saves anything. The certificate must name `*.<domain>`, match
   the key, be valid now, come with its chain in order, and be a server certificate. The page tells you
   what is wrong if a check fails.
3. The system agent (root) checks it all again and then does the following:
    - It writes the certificate and key to `/var/lib/containerizer/system/sandbox-https.{crt,key}`. The key
      is readable only by root and Caddy.
    - It adds a site for `*.<domain>` to Caddy. Caddy validates the site before it is restarted, so a
      broken site never takes the admin pages down. If anything fails, every file goes back to what it was.
    - It installs the certificate in k3s as Traefik's default certificate (see [How it works](#how-it-works)).
4. The page then shows the domain, the certificate's subject, issuer, expiry, key type and SHA-256
   fingerprint, and who set it up and when. **The key is never shown again.** The change history on the
   same page records each change: who, when, the domain and the certificate's fingerprint and expiry.
   It never records the key or the certificate text.

**Turn off** deletes the certificate and key from the appliance, Caddy and k3s. Generated Ingresses stay
in the output repository until the next scan without a domain.

Each organization scan from then on generates the Ingresses. Scans read the domain from
`/var/lib/containerizer/system/sandbox-https.json`, which holds no secrets. Outside the appliance, pass
`--ingress-domain sandbox.example.com` to `containerizer org` or `containerizer generate`.

## Names

Each component that serves HTTP gets exactly one DNS label under the domain:

| Component | App (namespace) | URL |
| --- | --- | --- |
| `web` | `shop` | `https://web-shop.sandbox.example.com/` |
| `shop` | `shop` | `https://shop.sandbox.example.com/` |
| `api` | `expense-claims` | `https://api-expense-claims.sandbox.example.com/` |

The rule is `<component>-<app>.<domain>`, or just `<app>.<domain>` when the component has the app's
name. Both parts are the Kubernetes names (lower case, letters, digits and hyphens). A name longer than
63 characters is cut and gets 8 hex characters of a SHA-256 of `<app>/<component>`, so it stays unique
and does not change between scans. The name has one label because a wildcard certificate covers exactly
one label: `*.sandbox.example.com` covers `web-shop.sandbox.example.com` but not
`web.shop.sandbox.example.com`.

Two different apps can end up with the same name, for example component `a` of app `b-c` and component
`a-b` of app `c`. That is rare but possible. The health check then marks the one that does not answer as
failing. Rename a component or an app to fix it.

## DNS

Point the wildcard at the appliance, in the zone of the domain:

```
*.sandbox.example.com.   300  IN  A      192.0.2.10                 ; the appliance's address
; or, when the appliance has a DNS name:
*.sandbox.example.com.   300  IN  CNAME  containerizer.example.com.
```

- Use an `AAAA` record as well if the appliance has an IPv6 address that clients use.
- An internal-only sandbox needs the record only in your internal DNS zone. The certificate can still be
  from a public CA if the domain is one you own publicly.
- Check it with `dig +short web-shop.sandbox.example.com` (any name under the domain must return the
  appliance), then `curl -I https://web-shop.sandbox.example.com/`.
- The appliance itself never resolves these names: its health check connects to its own Caddy
  (`127.0.0.1:443`) and sends the real host name. So the record is for your users, not for the appliance,
  and nothing needs to be allowed on the Firewall page.

## How it works

```
browser ──https://web-shop.<domain>──► :443 Caddy (appliance) ──TLS──► Traefik (k3s, 10.43.0.80) ──► Service web ──► pods
             wildcard certificate          *.<domain> site            same certificate, Host routing      namespace shop
```

- **Port 443 is not opened for this: it is already open.** Caddy answers on 443 for the admin pages and
  picks the site by the name the browser asks for. `*.<domain>` is a second site next to the admin pages'
  own name. The firewall's inbound rules stay the same: TCP 22 and 443, nothing else. Port 80 stays
  closed, so the apps are never reachable over plain HTTP from outside.
- **Caddy** terminates TLS with the wildcard certificate and adds `Strict-Transport-Security`. It removes
  its `Server` header and passes the request to Traefik over TLS. It checks Traefik's certificate against
  the same certificate chain, so the hop from the host into the cluster is encrypted and authenticated too.
- **Traefik**, the ingress controller that k3s ships, runs again on the appliance. It is configured by
  `/var/lib/rancher/k3s/server/manifests/containerizer-traefik.yaml`, which lives in the OS image. Its
  Service has the fixed cluster address `10.43.0.80` and no load balancer or host ports, so nothing
  outside the appliance reaches it directly. Its HTTP entry point only redirects to HTTPS. Its default
  certificate is the wildcard: TLSStore `default` points to the TLS Secret `containerizer-sandbox-tls`
  in `kube-system`. It trusts `X-Forwarded-For` only from the node's bridge address (Caddy), so apps see
  the client's address.
- **The certificate in k3s goes through External Secrets** when External Secrets Operator is installed
  on the sandbox:
    - The value goes into the sandbox's secret store (Secret `containerizer-sandbox-tls` in namespace
      `containerizer-secrets`, read by ClusterSecretStore `app-secrets`).
    - `kube-system` may read that one key only (ServiceAccount `app-secrets-reader`, a Role with
      `resourceNames`).
    - An `ExternalSecret` in `kube-system` creates the TLS Secret from it.

  Before ESO is installed, the system agent writes the TLS Secret directly. Either way, k3s encrypts
  Secrets at rest (`secrets-encryption: true`). `containerizer-sandbox` runs
  `python -m containerizer.sysagent sandbox-https sync` every 2 minutes. That brings k3s in line with
  the setting, including right after a restart, before Traefik is up.
- **No key in the apps' namespaces or in Git.** The generated Ingress names its host under `spec.tls`
  without a `secretName`, so the ingress controller's default certificate serves it. The private key is
  never copied into an app's namespace, where the app's own reconciler could read it. The output
  repository never contains a Secret for it.

## The generated Ingress

For each component with a Service (`web` and `spa` components), `<component>/k8s.yaml` gets:

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    containerizer.io/url: https://web-shop.sandbox.example.com/
    traefik.ingress.kubernetes.io/router.entrypoints: websecure   # HTTPS only on Traefik
    traefik.ingress.kubernetes.io/router.tls: "true"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"              # HTTP -> HTTPS on ingress-nginx
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
    - hosts: [web-shop.sandbox.example.com]                        # default certificate: no secretName
  rules:
    - host: web-shop.sandbox.example.com
      http:
        paths:
          - {path: /, pathType: Prefix, backend: {service: {name: web, port: {name: http}}}}
```

- No `ingressClassName` is set, so the cluster's default class applies. On k3s that is Traefik.
- The component's NetworkPolicy already admits its port from other namespaces, so the ingress controller
  can reach it. The default-deny policy stays.
- The Argo CD AppProject allows `Ingress` because it is one of the generated kinds. The Flux tenant's
  `admin` role covers it in the namespace.
- **On another cluster**, give the ingress controller the wildcard certificate as its default. For
  ingress-nginx, use `--default-ssl-certificate`. For Traefik, use a `default` TLSStore. Redirect HTTP to
  HTTPS at the entry point: the Traefik annotations above put the route on `websecure` only.

## The health check

`containerizer org --verify-sandbox` and `containerizer sandbox verify` open each component's URL once
its pods are healthy:

- **What is requested:** a GET of the path of the readiness probe, or `/`, over HTTPS. The certificate is
  checked against the host name as a browser would check it.
- **What counts as up:** any answer below 500 (a 401 or a 404 at `/` is fine). Redirects are not followed.
- **What counts as failing:** a TLS error, a refused or timed-out connection, or a 5xx answer, after 3
  attempts. The component is then marked failing with the reason.
- **On the appliance:** the check connects to `127.0.0.1:443` (Caddy) and trusts the chain that was set
  up, so it also works with an internal CA and without DNS. Elsewhere, it uses the name's DNS address and
  the system's CAs. Override this with `--ingress-address host:port` and `--ingress-ca ca.pem`.

**Where the URL shows up:**

- `sandbox/HEALTH.md` (URL column) and `health.json` (`url`, `url_check`) in the output repository.
- The results database: `SandboxCheck.Url`, `UrlCheck`, schema version 11.
- The application page of the web UI: the component's sandbox status links the URL.

## Troubleshooting

| What you see | Where to look |
| --- | --- |
| "Not saved: …" on the page | The sentence says which check failed: name, key, order, validity |
| "The last change was not applied" | Caddy or the agent refused it: `journalctl -u containerizer-sysagent` |
| Browser: certificate error | The chain is incomplete (paste the intermediates) or the CA is not trusted on that machine |
| 404 at a URL | No Ingress with that host: was the app scanned after the domain was set? `kubectl get ingress -A` |
| 502 at a URL | Traefik is not up or does not have the certificate yet: `kubectl -n kube-system get pods,tlsstore`, `journalctl -u containerizer-sandbox` |
| Health check: "does not answer over HTTPS" | The app's own answer (5xx) or TLS, with the detail; open the URL from the application page |
