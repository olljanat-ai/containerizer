"""The sandbox identity provider: one IdP in the sandbox cluster that every generated app signs in with.

Components that sign users in with OpenID Connect, WS-Federation or SAML 2.0 (rules/38-sandbox-idp.yaml)
are registered at WSO2 Identity Server in the k3s sandbox, and their own settings are overridden with
environment variables so they use it, without changing the application:

- OIDC: `<Section>__Authority`, `__ClientId` (and `__ClientSecret` through the secret store when the
  app has a ClientSecret setting, otherwise the client is public and uses PKCE);
- WS-Federation: `<Section>__MetadataAddress`, `__Wtrealm`;
- SAML: the IdP metadata URL and entity id, and the app's own entity id.

Everything the IdP needs is declarative and lives in the output repository (`sandbox/idp/`): the WSO2
configuration, one WSO2 application definition per component (`apps__<app>--<component>.json`), the
test users and groups (`idp.json`) and the Kubernetes manifests. A CronJob applies the definitions
through WSO2's REST API (containerizer/idp_sync.py). Passwords and client secrets come from the secret
store through External Secrets (remote key `containerizer-idp--cz-idp`; on the appliance cz-sandbox
generates them, `python -m containerizer idp secrets`), never from Git.

URLs: the IdP is at https://containerizer-idp.<sandbox domain>/ behind the wildcard certificate
(sandbox HTTPS), each component at https://<component>-<app>.<domain>/. Pods reach the IdP under the same
public name (issuer and metadata URLs must match): a CoreDNS override sends it to Traefik in the cluster.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

from .rules import RULES_DIR

NAMESPACE = "containerizer-idp"
SERVER = "cz-idp"
SYNC = "cz-idp-sync"
SECRET = "cz-idp"                                   # the Secret External Secrets writes in NAMESPACE
TRAEFIK = {"namespace": "kube-system", "labels": {"app.kubernetes.io/name": "traefik"}, "port": 8443}
WSO2_HOME = "/home/wso2carbon/wso2is-7.3.0"
WSO2_UID = 802
HTTP_PORT = 9763                                    # plain HTTP inside the cluster; TLS ends at Traefik
WSFED_PATH = "/wsfed"                               # passive endpoint in the metadata; Traefik adds wreq
WSFED_METADATA = "/wsfed-metadata/FederationMetadata/2007-06/FederationMetadata.xml"
SAML2_TOKEN = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0"
LABELS = {"app.kubernetes.io/part-of": "containerizer-sandbox", "app.kubernetes.io/managed-by": "containerizer"}
DOCS = "https://containerizer.eu/sandbox-idp/"
LABEL_MAX = 63
W = "http://wso2.org/claims/"
ADFS_CLAIMS = {          # claim types AD FS sends (ClaimTypes.*) -> WSO2 local claims
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": "username",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn": "username",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "emailaddress",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": "givenname",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": "lastname",
    "http://schemas.microsoft.com/ws/2008/06/identity/claims/role": "groups",
}
NAME_CLAIM = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
ROLE_CLAIM = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
OIDC_CLAIMS = ("username", "emailaddress", "givenname", "lastname", "groups", "formattedName", "displayName")
APP_NAME_RE = re.compile(r"[a-zA-Z0-9._-]+")


@lru_cache(maxsize=1)
def config() -> dict:
    return yaml.safe_load((RULES_DIR / "38-sandbox-idp.yaml").read_text())["idp"]


# --------------------------------------------------------------------------- names and URLs

def host_label(app: str, component: str) -> str:
    """The component's DNS label under the sandbox wildcard domain (as sandbox_https.host_label)."""
    label = app if component == app else f"{component}-{app}"
    if len(label) > LABEL_MAX or label == config()["host_label"]:
        h = hashlib.sha256(f"{app}/{component}".encode()).hexdigest()[:8]
        label = label[:LABEL_MAX - 9].rstrip("-") + "-" + h
    return label


@dataclass(frozen=True)
class Sandbox:
    """The IdP of one sandbox cluster, at https://containerizer-idp.<domain>/."""
    domain: str

    @property
    def host(self) -> str:
        return f"{config()['host_label']}.{self.domain}"

    @property
    def url(self) -> str:
        return f"https://{self.host}"

    # WSO2's own (super) tenant: its signing key is the IdP's keystore, so every URL is fixed
    @property
    def issuer(self) -> str:                      # SAML entity id and WS-Federation token issuer
        return self.url

    @property
    def authority(self) -> str:                   # OIDC issuer; discovery at <authority>/.well-known/...
        return f"{self.url}/oauth2/token"

    @property
    def oidc_discovery(self) -> str:
        return f"{self.authority}/.well-known/openid-configuration"

    @property
    def saml_metadata(self) -> str:
        return f"{self.url}/identity/metadata/saml2"

    @property
    def wsfed_metadata(self) -> str:
        return self.url + WSFED_METADATA

    @property
    def wsfed_endpoint(self) -> str:
        return self.url + WSFED_PATH

    def app_url(self, app: str, component: str) -> str:
        return f"https://{host_label(app, component)}.{self.domain}"


# --------------------------------------------------------------------------- detection

def _walk(node, path=()):
    if isinstance(node, dict):
        yield path, node
        for k, v in node.items():
            if isinstance(v, (dict, list)):
                yield from _walk(v, path + (str(k),))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            if isinstance(v, (dict, list)):
                yield from _walk(v, path + (str(i),))


def find_sections(cfg: dict) -> list[dict]:
    """Configuration sections of a sign-in protocol in merged appsettings: [{protocol, path, keys}], where
    keys maps the canonical name (authority, client_id, ...) to {key, value} as found."""
    out = []
    protos = config()["protocols"]
    for path, node in _walk(cfg):
        if not path:
            continue
        lower = {str(k).lower(): k for k in node}
        for proto, spec in protos.items():
            if spec.get("section_name") and not any(re.search(spec["section_name"], p) for p in path):
                continue
            if not any(all(r.lower() in lower for r in req) for req in spec["section_requires"]):
                continue
            keys = {}
            for canon, names in spec["keys"].items():
                for n in names:
                    k = lower.get(n.lower())
                    if k is not None and not isinstance(node[k], (dict, list)):
                        keys[canon] = {"key": k, "value": "" if node[k] is None else str(node[k])}
                        break
            out.append({"protocol": proto, "path": ":".join(path), "keys": keys})
    # one section per protocol: the shortest path (an outer section wins over an inner copy)
    best: dict[str, dict] = {}
    for s in out:
        if s["protocol"] not in best or len(s["path"]) < len(best[s["protocol"]]["path"]):
            best[s["protocol"]] = s
    return sorted(best.values(), key=lambda s: s["protocol"])


def protocols_used(facts: dict) -> list[str]:
    return [p for p in ("oidc", "wsfed", "saml") if facts.get(f"auth_{p}")]


# --------------------------------------------------------------------------- clients

@dataclass
class Client:
    """One component registered at the sandbox IdP."""
    app: str                      # namespace (Kubernetes name of the application)
    component: str                # Kubernetes name of the component (its Service)
    protocol: str                 # oidc | wsfed | saml
    url: str                      # https://<component>-<app>.<domain>
    identifier: str               # OIDC client id, WS-Fed realm or SAML SP entity id
    section: str                  # configuration section in appsettings ("OpenIdConnect")
    env: dict = field(default_factory=dict)           # setting overrides (no secrets)
    secret_env: str = ""          # env var of the client secret (from the secret store), "" for public clients
    redirect_uris: list = field(default_factory=list)
    metadata_url: str = ""        # what the app reads: OIDC discovery, WS-Fed or SAML metadata
    notes: list = field(default_factory=list)

    @property
    def name(self) -> str:        # WSO2 application name; also the secret property suffix
        return f"{self.app}--{self.component}"

    @property
    def secret_property(self) -> str:
        return f"client-{self.name}" if self.secret_env else ""

    def to_dict(self) -> dict:
        return asdict(self)


def _env_name(section: str, key: str) -> str:
    return "__".join(section.split(":") + [key])


def _path_of(value: str, default: str) -> str:
    """A callback setting is a path (/signin-oidc) or an absolute URL; return the path."""
    v = (value or "").strip()
    if re.match(r"https?://", v):
        v = re.sub(r"^https?://[^/]+", "", v) or "/"
    if not v.startswith("/"):
        v = default
    return v


def clients_for(app: str, component: str, facts: dict, packages: list[str], sb: Sandbox) -> tuple[list[Client], list[str]]:
    """The sandbox IdP registrations of one component, and notes for what could not be registered."""
    notes: list[str] = []
    used = protocols_used(facts)
    if facts.get("auth_entra") and "oidc" not in used:
        notes.append("signs in with Microsoft.Identity.Web, which only works with Entra ID: not pointed at the "
                     "sandbox IdP")
    if not used:
        return [], notes
    sections = {s["protocol"]: s for s in facts.get("auth_sections") or []}
    url = sb.app_url(app, component)
    out: list[Client] = []
    for proto in used:
        s = sections.get(proto)
        if not s:
            notes.append(f"uses {LABEL[proto]} but its settings are not in appsettings.json (set in code?): "
                         "not pointed at the sandbox IdP; move them to configuration")
            continue
        k = s["keys"]
        c = Client(app=app, component=component, protocol=proto, url=url, identifier="", section=s["path"])
        if proto == "oidc":
            c.identifier = c.name
            if "authority" in k:
                c.env[_env_name(s["path"], k["authority"]["key"])] = sb.authority
            if "metadata" in k:
                c.env[_env_name(s["path"], k["metadata"]["key"])] = sb.oidc_discovery
            if "authority" not in k:
                c.env[_env_name(s["path"], "Authority")] = sb.authority
            c.env[_env_name(s["path"], k["client_id"]["key"])] = c.identifier
            if "client_secret" in k:
                c.secret_env = _env_name(s["path"], k["client_secret"]["key"])
            d = config()["protocols"]["oidc"]["defaults"]
            cb = _path_of((k.get("callback") or {}).get("value"), d["callback"])
            so = _path_of((k.get("signout_callback") or {}).get("value"), d["signout_callback"])
            c.redirect_uris = [url + cb, url + so]
            c.metadata_url = sb.oidc_discovery
        elif proto == "wsfed":
            c.identifier = url + "/"
            c.env[_env_name(s["path"], (k.get("metadata") or {"key": "MetadataAddress"})["key"])] = sb.wsfed_metadata
            c.env[_env_name(s["path"], k["realm"]["key"])] = c.identifier
            cb = _path_of((k.get("callback") or {}).get("value"), config()["protocols"]["wsfed"]["defaults"]["callback"])
            if "reply" in k:
                c.env[_env_name(s["path"], k["reply"]["key"])] = url + cb
            c.redirect_uris = [url + cb]
            c.metadata_url = sb.wsfed_metadata
        else:
            c.identifier = url + "/"
            c.env[_env_name(s["path"], k["metadata"]["key"])] = sb.saml_metadata
            if "idp_entity_id" in k:
                c.env[_env_name(s["path"], k["idp_entity_id"]["key"])] = sb.issuer
            if "sp_entity_id" in k:
                c.env[_env_name(s["path"], k["sp_entity_id"]["key"])] = c.identifier
            else:
                notes.append("SAML: no entity id setting found next to the metadata setting; the app's own entity "
                             "id is not known, so it is not registered")
                continue
            for key in ("sso_url", "slo_url"):
                if key in k:
                    c.env[_env_name(s["path"], k[key]["key"])] = f"{sb.url}/samlsso"
            c.redirect_uris = _saml_acs(url, k, packages)
            c.metadata_url = sb.saml_metadata
        out.append(c)
    return out, notes


LABEL = {"oidc": "OpenID Connect", "wsfed": "WS-Federation", "saml": "SAML 2.0"}


def _saml_acs(url: str, k: dict, packages: list[str]) -> list[str]:
    acs = []
    if "acs" in k:
        acs.append(url + _path_of(k["acs"]["value"], "/Saml2/Acs"))
    pk = " ".join(packages)
    if "Sustainsys" in pk or not acs:
        mp = _path_of((k.get("module_path") or {}).get("value"), "/Saml2").rstrip("/")
        acs.append(f"{url}{mp}/Acs")
    if "ITfoxtec" in pk:
        acs.append(f"{url}/Auth/AssertionConsumerService")
    return list(dict.fromkeys(acs))


# --------------------------------------------------------------------------- the app side

def inject(docs: list[dict], clients: list[Client]) -> None:
    """Point the component's workloads at the sandbox IdP: setting overrides (they replace any env var
    of the same name), the client secret from the component's secret, forwarded headers (TLS ends at the
    ingress; without them the app sends http:// redirect URIs), and egress to the IdP through Traefik."""
    if not clients:
        return
    env = {}
    for c in clients:
        env.update(c.env)
    env.setdefault("ASPNETCORE_FORWARDEDHEADERS_ENABLED", "true")
    secret_envs = {c.secret_env for c in clients if c.secret_env}
    comp = clients[0].component
    for d in docs:
        spec = _pod_spec(d)
        if spec is None:
            continue
        for ct in spec.get("containers") or []:
            cur = [e for e in ct.get("env") or [] if e["name"] not in env]
            names = {e["name"] for e in cur}
            ref = next((e["valueFrom"]["secretKeyRef"]["name"] for e in cur
                        if (e.get("valueFrom") or {}).get("secretKeyRef")), f"{comp}-secrets")
            for s in sorted(secret_envs - names):
                cur.append({"name": s, "valueFrom": {"secretKeyRef": {"name": ref, "key": s, "optional": True}}})
            ct["env"] = cur + [{"name": k, "value": v} for k, v in sorted(env.items())]
    for d in docs:
        if d.get("kind") == "NetworkPolicy" and "Egress" in ((d.get("spec") or {}).get("policyTypes") or []):
            rule = egress_to_idp()
            if rule not in d["spec"].setdefault("egress", []):
                d["spec"]["egress"].append(rule)


def _pod_spec(d: dict) -> dict | None:
    k = d.get("kind")
    if k in ("Deployment", "StatefulSet", "Job"):
        return ((d.get("spec") or {}).get("template") or {}).get("spec")
    if k == "CronJob":
        return ((((d.get("spec") or {}).get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec")
    return None


def egress_to_idp() -> dict:
    """Pods reach the IdP's public name through Traefik in the cluster (CoreDNS override); policies see
    the Traefik pod and its container port after the Service address is translated."""
    return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": TRAEFIK["namespace"]}},
                    "podSelector": {"matchLabels": dict(TRAEFIK["labels"])}}],
            "ports": [{"port": TRAEFIK["port"], "protocol": "TCP"}]}


# --------------------------------------------------------------------------- WSO2 application definitions

MARKER_DESC = "Generated by containerizer for the sandbox"


def _escape_re(s: str) -> str:
    return re.sub(r"([.\\+*?\[^\]$(){}=!<>|:-])", r"\\\1", s)


def wso2_application(c: Client) -> dict:
    """The WSO2 application (POST /api/server/v1/applications body) of one client. The client secret is
    not here: the sync job reads it from the secret store (x-containerizer-client-secret)."""
    body: dict = {"name": c.name, "description": f"{MARKER_DESC}: {c.app}/{c.component} ({LABEL[c.protocol]})",
                  "accessUrl": c.url + "/",
                  "advancedConfigurations": {"skipLoginConsent": True, "skipLogoutConsent": True}}
    if c.protocol == "oidc":
        body["inboundProtocolConfiguration"] = {"oidc": {
            "clientId": c.identifier,
            # ASP.NET Core's handler defaults to response_type=id_token (implicit, form_post); code flow
            # with PKCE when the app asks for it
            "grantTypes": ["authorization_code", "implicit", "refresh_token"],
            "callbackURLs": ["regexp=(" + "|".join(_escape_re(u) for u in c.redirect_uris) + ")"],
            "publicClient": not c.secret_env,
            "pkce": {"mandatory": not c.secret_env, "supportPlainTransformAlgorithm": False},
            "allowedOrigins": [],
        }}
        if c.secret_env:
            # where the secret goes: the sync job reads the property, the appliance writes the same value
            # into the app's remote key under the env name the component's ExternalSecret lists
            body["x-containerizer-client-secret"] = c.secret_property
            body["x-containerizer-secret-env"] = c.secret_env
            from . import eso
            body["x-containerizer-secret-remote"] = eso.remote_key(c.app, c.component)
        body["claimConfiguration"] = {
            "dialect": "LOCAL",
            "requestedClaims": [{"claim": {"uri": W + x}, "mandatory": False} for x in OIDC_CLAIMS],
            "subject": {"claim": {"uri": W + "username"}, "includeUserDomain": False, "includeTenantDomain": False}}
    elif c.protocol == "wsfed":
        body["inboundProtocolConfiguration"] = {"passiveSts": {"realm": c.identifier, "replyTo": c.redirect_uris[0]}}
        body["claimConfiguration"] = _adfs_claims(wsfed=True)
    else:
        body["inboundProtocolConfiguration"] = {"saml": {"manualConfiguration": {
            "issuer": c.identifier,
            "assertionConsumerUrls": c.redirect_uris,
            "defaultAssertionConsumerUrl": c.redirect_uris[0],
            "singleSignOnProfile": {"bindings": ["HTTP_POST", "HTTP_REDIRECT"],
                                    "assertion": {"nameIdFormat": "urn/oasis/names/tc/SAML/1.1/nameid-format/unspecified",
                                                  "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256"}},
            "attributeProfile": {"enabled": True, "alwaysIncludeAttributesInResponse": True},
            "responseSigning": {"enabled": True, "signingAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"},
            "requestValidation": {"enableSignatureValidation": False},
        }}}
        body["claimConfiguration"] = _adfs_claims(wsfed=False)
    return body


def _adfs_claims(wsfed: bool) -> dict:
    """AD FS claim types (what legacy .NET apps read: ClaimTypes.Name, Role, Email ...).

    WS-Federation: WSO2's passive STS writes a SAML 2.0 attribute with Name = the claim URI up to its last
    '/' (and FriendlyName = the rest), so the claim is registered with one more segment: Name is then
    exactly the AD FS claim type (`.../claims/name/name` -> Name `.../claims/name`)."""
    t = (lambda u: u + "/" + u.rsplit("/", 1)[1]) if wsfed else (lambda u: u)
    return {"dialect": "CUSTOM",
            "claimMappings": [{"applicationClaim": t(k), "localClaim": {"uri": W + v}} for k, v in ADFS_CLAIMS.items()],
            "requestedClaims": [{"claim": {"uri": t(k)}, "mandatory": False} for k in ADFS_CLAIMS],
            "subject": {"claim": {"uri": t(NAME_CLAIM)}, "includeUserDomain": False, "includeTenantDomain": False},
            "role": {"claim": {"uri": t(ROLE_CLAIM)}, "includeUserDomain": False}}


def users(sb: Sandbox) -> list[dict]:
    return [{**u, "email": f"{u['username']}@{sb.domain}"} for u in config()["users"]]


def idp_json(sb: Sandbox) -> dict:
    return {"admin": "admin", "groups": list(config()["groups"]), "users": users(sb),
            "oidc": {"claims": {"name": W + "formattedName"}, "scope_claims": {"profile": ["groups"]}}}


# --------------------------------------------------------------------------- sandbox/idp/

def deployment_toml(sb: Sandbox) -> str:
    h = sb.host
    db = "jdbc:h2:./repository/database/{0};DB_CLOSE_ON_EXIT=FALSE;LOCK_TIMEOUT=60000"
    return f"""# WSO2 Identity Server of the containerizer sandbox (generated; docs: {DOCS})
[server]
hostname = "{h}"
node_ip = "127.0.0.1"
base_path = "https://$ref{{server.hostname}}"

[super_admin]
username = "admin"
password = "$env{{IDP_ADMIN_PASSWORD}}"
create_admin_account = true

[user_store]
type = "database_unique_id"

# H2 on the pod's volume: one node, and everything in it is rebuilt from sandbox/idp/ by the sync job
[database.identity_db]
type = "h2"
url = "{db.format('WSO2IDENTITY_DB')}"
username = "wso2carbon"
password = "wso2carbon"

[database.shared_db]
type = "h2"
url = "{db.format('WSO2SHARED_DB')}"
username = "wso2carbon"
password = "wso2carbon"

[datasource.AgentIdentity]
id = "AgentIdentity"
url = "{db.format('WSO2AGENTIDENTITY_DB')}"
username = "wso2carbon"
password = "wso2carbon"
driver = "org.h2.Driver"

# the IdP's own key (generated on first start, never leaves the volume): TLS of the pod port, token
# signing; the image's default key is public and is not used
[keystore.primary]
file_name = "idp.p12"
password = "$env{{IDP_KEYSTORE_PASSWORD}}"
alias = "idp"
key_password = "$env{{IDP_KEYSTORE_PASSWORD}}"
type = "PKCS12"

[truststore]
file_name = "client-truststore.p12"
password = "wso2carbon"
type = "PKCS12"

# TLS ends at Traefik (443); the pod serves HTTP on {HTTP_PORT} inside the cluster, to Traefik only
# (network policy)
[transport.http.properties]
proxyPort = 443

[transport.https.properties]
proxyPort = 443

# requests through Traefik count as HTTPS (X-Forwarded-Proto), so the APIs that require a confidential
# transport (SCIM 2.0) answer instead of redirecting to the pod's port 9443. Only Traefik reaches the
# pod (network policy); the IdP calls itself on https://localhost:9443.
[catalinaValves.remoteIpValve]
enable = true
internalProxies = '10\\.\\d{{1,3}}\\.\\d{{1,3}}\\.\\d{{1,3}}|172\\.(1[6-9]|2[0-9]|3[0-1])\\.\\d{{1,3}}\\.\\d{{1,3}}|192\\.168\\.\\d{{1,3}}\\.\\d{{1,3}}'
remoteIpHeader = "X-Forwarded-For"
protocolHeader = "X-Forwarded-Proto"
proxiesHeader = "X-Forwarded-By"
trustedProxies = ""

# SAML entity id and WS-Federation token issuer
[saml]
entity_id = "{sb.issuer}"

# the WS-Federation metadata (FederationMetadata.xml) the init container writes is public, like the
# SAML and OIDC metadata
[[resource.access_control]]
context = "(.*)/wsfed-metadata/(.*)"
secure = false
http_method = "GET"

[account_recovery.endpoint.auth]
hash = "66cd9688a2ae068244ea01e70f0e230f5623b7fa4cdecb65070a09ec06452262"

[identity.auth_framework.endpoint]
app_password = "dashboard"
"""


INIT_SH = r"""#!/bin/sh
# Init container of the sandbox IdP (generated by containerizer). On the data volume:
#   host          the host name the data belongs to: a new name starts the IdP afresh (the sync job
#                 recreates everything from sandbox/idp/)
#   security/     idp.p12 (the IdP's own key, generated here once), idp.crt, client-truststore.p12 (the
#                 image's truststore + idp.crt: the server calls its own APIs on https://localhost:9443)
#   database/     H2 databases, first copied from the image
#   wsfed/        FederationMetadata/2007-06/FederationMetadata.xml with the signing certificate
set -eu
S=__HOME__/repository
D=/data
umask 077
if [ -f $D/host ] && [ "$(cat $D/host)" != "$IDP_HOST" ]; then
  echo "host name changed: starting the IdP afresh"
  rm -rf $D/database $D/security $D/wsfed
fi
mkdir -p $D/security $D/database $D/wsfed/FederationMetadata/2007-06
if [ ! -s $D/security/idp.p12 ]; then
  keytool -genkeypair -alias idp -keyalg RSA -keysize 3072 -sigalg SHA256withRSA -validity 3650 \
    -dname "CN=$IDP_HOST" -ext "SAN=dns:$IDP_HOST,dns:localhost" \
    -keystore $D/security/idp.p12.tmp -storetype PKCS12 \
    -storepass:env IDP_KEYSTORE_PASSWORD -keypass:env IDP_KEYSTORE_PASSWORD
  mv $D/security/idp.p12.tmp $D/security/idp.p12
  rm -rf $D/database && mkdir -p $D/database
fi
if [ -z "$(ls -A $D/database)" ]; then cp -a $S/database/. $D/database/; fi
keytool -exportcert -rfc -alias idp -keystore $D/security/idp.p12 -storetype PKCS12 \
  -storepass:env IDP_KEYSTORE_PASSWORD > $D/security/idp.crt
cp $S/resources/security/client-truststore.p12 $D/security/truststore.tmp
keytool -importcert -noprompt -alias containerizer-idp -file $D/security/idp.crt \
  -keystore $D/security/truststore.tmp -storetype PKCS12 -storepass wso2carbon
mv $D/security/truststore.tmp $D/security/client-truststore.p12
CERT=$(sed '/-----/d' $D/security/idp.crt | tr -d '\r\n')
case "$CERT" in *[!A-Za-z0-9+/=]*) echo "unexpected certificate encoding" >&2; exit 1;; esac
sed "s#@CERT@#$CERT#" /config/FederationMetadata.xml.in > $D/wsfed/FederationMetadata/2007-06/FederationMetadata.xml
chmod 644 $D/wsfed/FederationMetadata/2007-06/FederationMetadata.xml
printf %s "$IDP_HOST" > $D/host
""".replace("__HOME__", WSO2_HOME)


def wsfed_metadata_template(sb: Sandbox) -> str:
    """FederationMetadata.xml for WS-Federation relying parties (WSO2 does not publish one): the issuer,
    the passive requestor endpoint and the signing certificate (@CERT@, filled in by the init container),
    in the form the .NET WS-Federation handlers (Microsoft.IdentityModel.Protocols.WsFederation) read."""
    from xml.sax.saxutils import escape, quoteattr
    ns = "http://docs.oasis-open.org/wsfed/federation/200706"
    return (f'<?xml version="1.0" encoding="utf-8"?>\n'
            f'<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID={quoteattr(sb.issuer)}>\n'
            f'  <RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="{ns}" '
            f'xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="{ns}">\n'
            f'    <KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data>'
            f'<X509Certificate>@CERT@</X509Certificate></X509Data></KeyInfo></KeyDescriptor>\n'
            f'    <fed:TokenTypesOffered><fed:TokenType Uri="{SAML2_TOKEN}"/></fed:TokenTypesOffered>\n'
            f'    <fed:PassiveRequestorEndpoint><EndpointReference xmlns="http://www.w3.org/2005/08/addressing">'
            f'<Address>{escape(sb.wsfed_endpoint)}</Address></EndpointReference></fed:PassiveRequestorEndpoint>\n'
            f'  </RoleDescriptor>\n'
            f'</EntityDescriptor>\n')


def _meta(name: str, extra: dict | None = None, ns: str = NAMESPACE) -> dict:
    return {"name": name, "namespace": ns, "labels": {**LABELS, "app.kubernetes.io/name": name, **(extra or {})}}


SEC = {"runAsNonRoot": True, "allowPrivilegeEscalation": False, "capabilities": {"drop": ["ALL"]},
       "seccompProfile": {"type": "RuntimeDefault"}}


def server_manifests(sb: Sandbox) -> list[dict]:
    img = config()["images"]["server"]
    sel = {"app.kubernetes.io/name": SERVER}
    sec_env = lambda var, key: {"name": var, "valueFrom": {"secretKeyRef": {"name": SECRET, "key": key}}}  # noqa: E731
    sp = f"{WSO2_HOME}/repository"
    mounts = [
        {"name": "config", "mountPath": "/home/wso2carbon/wso2-config-volume/repository/conf/deployment.toml",
         "subPath": "deployment.toml", "readOnly": True},
        {"name": "data", "mountPath": f"{sp}/database", "subPath": "database"},
        {"name": "data", "mountPath": f"{sp}/resources/security/idp.p12", "subPath": "security/idp.p12", "readOnly": True},
        {"name": "data", "mountPath": f"{sp}/resources/security/client-truststore.p12",
         "subPath": "security/client-truststore.p12", "readOnly": True},
        {"name": "data", "mountPath": f"{sp}/deployment/server/webapps/wsfed-metadata", "subPath": "wsfed", "readOnly": True},
    ]
    health = {"httpGet": {"path": "/api/health-check/v1.0/health", "port": "http"}}
    pod = {
        "automountServiceAccountToken": False,
        "enableServiceLinks": False,
        "securityContext": {"runAsNonRoot": True, "runAsUser": WSO2_UID, "runAsGroup": WSO2_UID, "fsGroup": WSO2_UID,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "initContainers": [{
            "name": "init", "image": img, "imagePullPolicy": "IfNotPresent",
            "command": ["sh", "/config/init.sh"],
            "env": [{"name": "IDP_HOST", "value": sb.host}, sec_env("IDP_KEYSTORE_PASSWORD", "keystore-password")],
            "securityContext": {**SEC, "readOnlyRootFilesystem": True},
            "resources": {"requests": {"cpu": "50m", "memory": "128Mi"}, "limits": {"memory": "512Mi"}},
            "volumeMounts": [{"name": "data", "mountPath": "/data"}, {"name": "config", "mountPath": "/config", "readOnly": True},
                             {"name": "tmp", "mountPath": "/tmp"}]}],
        "containers": [{
            "name": "wso2is", "image": img, "imagePullPolicy": "IfNotPresent",
            "env": [sec_env("IDP_ADMIN_PASSWORD", "admin-password"), sec_env("IDP_KEYSTORE_PASSWORD", "keystore-password"),
                    {"name": "JAVA_OPTS", "value": "-Djava.security.egd=file:/dev/urandom"}],
            "ports": [{"name": "http", "containerPort": HTTP_PORT}],
            # the server writes to its own folders (deployment, logs, tmp): root filesystem stays writable,
            # nothing else is (no capabilities, no privilege escalation, non-root)
            "securityContext": {**SEC, "readOnlyRootFilesystem": False},
            "resources": {"requests": {"cpu": "250m", "memory": "1Gi"}, "limits": {"memory": "2Gi"}},
            "startupProbe": {**health, "periodSeconds": 5, "failureThreshold": 120},
            "readinessProbe": {**health, "periodSeconds": 10},
            "livenessProbe": {**health, "periodSeconds": 30, "failureThreshold": 5},
            "volumeMounts": mounts}],
        "volumes": [{"name": "data", "persistentVolumeClaim": {"claimName": f"{SERVER}-data"}},
                    {"name": "config", "configMap": {"name": f"{SERVER}-config"}},
                    {"name": "tmp", "emptyDir": {}}],
    }
    host = sb.host
    tls_ann = {"traefik.ingress.kubernetes.io/router.entrypoints": "websecure",
               "traefik.ingress.kubernetes.io/router.tls": "true"}
    rule = lambda path, ptype: {"host": host, "http": {"paths": [{  # noqa: E731
        "path": path, "pathType": ptype, "backend": {"service": {"name": SERVER, "port": {"name": "http"}}}}]}}
    # WS-Federation: WSO2 issues SAML 1.1 tokens unless the request asks for SAML 2.0 (wreq), and the .NET
    # SAML 1.1 reader rejects them; the endpoint in the metadata (/wsfed) redirects to /passivests with
    # wreq added, so the apps get SAML 2.0 tokens without code changes
    from urllib.parse import quote
    wreq = quote(f'<wst:RequestSecurityToken xmlns:wst="http://docs.oasis-open.org/ws-sx/ws-trust/200512">'
                 f'<wst:TokenType>{SAML2_TOKEN}</wst:TokenType></wst:RequestSecurityToken>', safe="")
    return [
        {"apiVersion": "v1", "kind": "PersistentVolumeClaim", "metadata": _meta(f"{SERVER}-data"),
         "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": "2Gi"}}}},
        {"apiVersion": "apps/v1", "kind": "Deployment", "metadata": _meta(SERVER),
         "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "selector": {"matchLabels": sel},
                  "template": {"metadata": {"labels": {**LABELS, **sel}}, "spec": pod}}},
        {"apiVersion": "v1", "kind": "Service", "metadata": _meta(SERVER),
         "spec": {"selector": sel, "ports": [{"name": "http", "port": 80, "targetPort": "http"}]}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
         "metadata": {**_meta(SERVER), "annotations": {"containerizer.io/url": f"https://{host}/", **tls_ann}},
         "spec": {"tls": [{"hosts": [host]}], "rules": [rule("/", "Prefix")]}},
        {"apiVersion": "traefik.io/v1alpha1", "kind": "Middleware", "metadata": _meta(f"{SERVER}-wsfed-saml2"),
         "spec": {"redirectRegex": {"regex": rf"^https://([^/]+){WSFED_PATH}\?(.*)$",
                                    "replacement": f"https://${{1}}/passivests?${{2}}&wreq={wreq}",
                                    "permanent": False}}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
         "metadata": {**_meta(f"{SERVER}-wsfed"), "annotations": {
             **tls_ann, "traefik.ingress.kubernetes.io/router.middlewares": f"{NAMESPACE}-{SERVER}-wsfed-saml2@kubernetescrd"}},
         "spec": {"tls": [{"hosts": [host]}], "rules": [rule(WSFED_PATH, "Exact")]}},
    ]


def sync_manifests(sb: Sandbox) -> list[dict]:
    pod = {
        "automountServiceAccountToken": False, "enableServiceLinks": False, "restartPolicy": "Never",
        "serviceAccountName": SYNC,
        "securityContext": {"runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
                            "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [{
            "name": "sync", "image": config()["images"]["sync"], "imagePullPolicy": "IfNotPresent",
            "command": ["python", "-I", "-B", "/sync/idp_sync.py", "--url", sb.url, "--config", "/sync",
                        "--secrets", "/secrets"],
            "securityContext": {**SEC, "readOnlyRootFilesystem": True},
            "resources": {"requests": {"cpu": "20m", "memory": "64Mi"}, "limits": {"memory": "256Mi"}},
            "volumeMounts": [{"name": "sync", "mountPath": "/sync", "readOnly": True},
                             {"name": "secrets", "mountPath": "/secrets", "readOnly": True}]}],
        "volumes": [{"name": "sync", "configMap": {"name": SYNC}},
                    {"name": "secrets", "secret": {"secretName": SECRET, "defaultMode": 0o400}}],
    }
    labels = {**LABELS, "app.kubernetes.io/name": SYNC}
    return [
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": _meta(SYNC), "automountServiceAccountToken": False},
        {"apiVersion": "batch/v1", "kind": "CronJob", "metadata": _meta(SYNC),
         "spec": {"schedule": "*/5 * * * *", "concurrencyPolicy": "Forbid", "successfulJobsHistoryLimit": 1,
                  "failedJobsHistoryLimit": 3,
                  "jobTemplate": {"spec": {"backoffLimit": 1, "activeDeadlineSeconds": 900, "ttlSecondsAfterFinished": 86400,
                                           "template": {"metadata": {"labels": labels}, "spec": pod}}}}},
    ]


def remote_key() -> str:
    """Remote key of the IdP's own secrets (`containerizer-idp--cz-idp` with the default key format)."""
    from . import eso
    return eso.remote_key(NAMESPACE, SERVER)


def secret_manifests() -> list[dict]:
    """ExternalSecret of the IdP's passwords and client secrets (remote_key()), the namespace's store
    reader and its access (kubernetes provider: a Role on exactly that key), as eso.py writes them for
    every namespace."""
    from . import eso
    es = eso.external_secret(SECRET, NAMESPACE, remote_key(), labels=LABELS, set_namespace=True)
    es.pop("_comment")
    es["spec"]["refreshInterval"] = "5m"          # new client secrets reach the sync job quickly
    return [eso.reader_service_account(NAMESPACE, LABELS, set_namespace=True), es] + \
        eso.store_access(NAMESPACE, [remote_key()], LABELS)


def network_manifests() -> list[dict]:
    dns = {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                   "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}}}],
           "ports": [{"port": 53, "protocol": "UDP"}, {"port": 53, "protocol": "TCP"}]}
    traefik_in = {"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": TRAEFIK["namespace"]}},
                            "podSelector": {"matchLabels": dict(TRAEFIK["labels"])}}],
                  "ports": [{"port": HTTP_PORT, "protocol": "TCP"}]}
    np = lambda name, sel, types, ingress=None, egress=None: {  # noqa: E731
        "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy", "metadata": _meta(name),
        "spec": {"podSelector": {"matchLabels": sel} if sel else {}, "policyTypes": types,
                 **({"ingress": ingress} if ingress is not None else {}), **({"egress": egress} if egress is not None else {})}}
    return [
        np("default-deny-all", None, ["Ingress", "Egress"]),
        # the IdP: requests only from Traefik; out only to DNS and to its own public name (Traefik)
        np(SERVER, {"app.kubernetes.io/name": SERVER}, ["Ingress", "Egress"], [traefik_in], [dns, egress_to_idp()]),
        # the sync job talks to the IdP's public URL like the apps do
        np(SYNC, {"app.kubernetes.io/name": SYNC}, ["Ingress", "Egress"], [], [dns, egress_to_idp()]),
    ]


def coredns_override(sb: Sandbox) -> dict:
    """k3s CoreDNS imports *.override from ConfigMap kube-system/coredns-custom: pods resolve the IdP's
    public name to Traefik in the cluster, which serves the wildcard certificate."""
    return {"apiVersion": "v1", "kind": "ConfigMap",
            "metadata": {"name": "coredns-custom", "namespace": "kube-system", "labels": dict(LABELS)},
            "data": {f"{config()['host_label']}.override":
                     f"rewrite stop {{\n  name exact {sb.host}. traefik.kube-system.svc.cluster.local.\n  answer auto\n}}\n"}}


def namespace() -> dict:
    from .harden import namespace_manifest
    ns = namespace_manifest(NAMESPACE)
    ns["metadata"]["labels"].update(LABELS)
    return ns


class _NoAlias(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _dump(docs: list[dict]) -> str:
    return "---\n".join(yaml.dump(d, Dumper=_NoAlias, sort_keys=False) for d in docs)


def sandbox_files(sb: Sandbox, apps: dict[str, dict]) -> dict[str, str]:
    """Every file of sandbox/idp/ (path relative to it -> content). `apps`: WSO2 application name ->
    definition."""
    sync_src = (Path(__file__).parent / "idp_sync.py").read_text()
    app_files = {f"apps__{n}.json": json.dumps(apps[n], indent=2, sort_keys=True) + "\n" for n in sorted(apps)}
    files = {
        "namespace.yaml": _dump([namespace()]),
        "server.yaml": _dump(server_manifests(sb)),
        "sync.yaml": _dump(sync_manifests(sb)),
        "secrets.yaml": _dump(secret_manifests()),
        "network.yaml": _dump(network_manifests()),
        "dns.yaml": _dump([coredns_override(sb)]),
        "config/deployment.toml": deployment_toml(sb),
        "config/init.sh": INIT_SH,
        "config/FederationMetadata.xml.in": wsfed_metadata_template(sb),
        "sync/idp.json": json.dumps(idp_json(sb), indent=2) + "\n",
        "sync/idp_sync.py": sync_src,
        **{f"sync/{k}": v for k, v in app_files.items()},
    }
    files["kustomization.yaml"] = yaml.safe_dump({
        "apiVersion": "kustomize.config.k8s.io/v1beta1", "kind": "Kustomization",
        "resources": ["namespace.yaml", "secrets.yaml", "network.yaml", "server.yaml", "sync.yaml", "dns.yaml"],
        "configMapGenerator": [
            {"name": f"{SERVER}-config", "namespace": NAMESPACE, "options": {"labels": dict(LABELS)},
             "files": [f"config/{x}" for x in ("deployment.toml", "init.sh", "FederationMetadata.xml.in")]},
            {"name": SYNC, "namespace": NAMESPACE, "options": {"labels": {**LABELS, "app.kubernetes.io/name": SYNC}},
             "files": ["sync/idp.json", "sync/idp_sync.py"] + [f"sync/{k}" for k in app_files]},
        ]}, sort_keys=False)
    files["README.md"] = readme(sb, apps)
    return files


def readme(sb: Sandbox, apps: dict[str, dict]) -> str:
    rows = []
    for n in sorted(apps):
        a = apps[n]
        ib = a.get("inboundProtocolConfiguration") or {}
        proto = "OIDC" if "oidc" in ib else "WS-Federation" if "passiveSts" in ib else "SAML 2.0"
        ident = ((ib.get("oidc") or {}).get("clientId") or (ib.get("passiveSts") or {}).get("realm")
                 or ((ib.get("saml") or {}).get("manualConfiguration") or {}).get("issuer") or "")
        rows.append(f"| `{n}` | {proto} | `{ident}` | {a.get('accessUrl', '')} |")
    users_txt = "\n".join(f"| `{u['username']}` | {', '.join(u['groups'])} | {u['email']} |" for u in users(sb))
    return f"""# Sandbox identity provider

WSO2 Identity Server at **{sb.url}/** (console: {sb.url}/console, user `admin`). Generated by containerizer
from the apps in this repository; do not edit, the next run rewrites this folder. Docs: {DOCS}

| For apps | URL |
| --- | --- |
| OpenID Connect authority (discovery: `/.well-known/openid-configuration`) | {sb.authority} |
| SAML 2.0 metadata (entity id `{sb.issuer}`) | {sb.saml_metadata} |
| WS-Federation metadata | {sb.wsfed_metadata} |

## Registered components

| Application | Protocol | Client id / realm / entity id | URL |
| --- | --- | --- | --- |
{chr(10).join(rows) or '| - | | | |'}

## Test users

| User | Groups (roles) | E-mail |
| --- | --- | --- |
{users_txt}

Passwords are in the secret store (remote key `{remote_key()}`, properties `user-<name>`), not in Git.
On the appliance: `/usr/lib/containerizer/venv/bin/python -m containerizer idp users`.

## How it is applied

`kustomization.yaml` (included by the Flux root Kustomization) deploys the server (`server.yaml`), its
External Secret (`secrets.yaml`), network policies and a CoreDNS override (pods resolve
`{sb.host}` to Traefik in the cluster). CronJob `{SYNC}` applies `sync/idp.json` and
`sync/apps__*.json` to the server through its REST API every 5 minutes and removes applications it created
that are no longer listed.
"""


# --------------------------------------------------------------------------- the appliance's secrets

USER_PW_LEN = 24


def password(n: int = USER_PW_LEN) -> str:
    """Random password that meets WSO2's default policy (8-30 characters, upper, lower, digit, symbol)."""
    import secrets
    import string
    alnum = string.ascii_letters + string.digits
    chars = [secrets.choice(alnum) for _ in range(n - 4)] + [
        secrets.choice(string.ascii_uppercase), secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits), secrets.choice("-_.!")]
    rnd = secrets.SystemRandom()
    rnd.shuffle(chars)
    return "".join(chars)


def needed_secrets(cfg: dict, apps: list[dict]) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """From the deployed sync configuration: the IdP properties to make (property -> kind) and, per app
    remote key, the env names that must carry the same client secret: ({prop: kind}, {remote: {env: prop}})."""
    props = {"admin-password": "password", "keystore-password": "token"}
    for u in cfg.get("users") or []:
        if re.fullmatch(r"[a-z][a-z0-9._-]{0,40}", u.get("username", "")):
            props[f"user-{u['username']}"] = "password"
    app_keys: dict[str, dict[str, str]] = {}
    for a in apps:
        prop = a.get("x-containerizer-client-secret")
        envname = a.get("x-containerizer-secret-env")
        remote = a.get("x-containerizer-secret-remote")
        if not prop or not re.fullmatch(r"client-[a-z0-9.-]+--[a-z0-9.-]+", prop):
            continue
        props[prop] = "token"
        if envname and remote and re.fullmatch(r"[A-Za-z0-9_.-]+", envname) and re.fullmatch(r"[a-z0-9.-]+--[a-z0-9.-]+", remote):
            app_keys.setdefault(remote, {})[envname] = prop
    return props, app_keys


def make_value(kind: str) -> str:
    import secrets
    return password() if kind == "password" else secrets.token_urlsafe(32)


class ApplianceError(Exception):
    pass


def _kubectl(cmd: list[str], args: list[str], stdin: str | None = None) -> str:
    import subprocess
    p = subprocess.run(cmd + args, input=stdin, capture_output=True, text=True, timeout=120)
    if p.returncode:
        # kubectl errors name objects, never values (values only ever go through stdin)
        raise ApplianceError(f"kubectl {' '.join(args[:3])}: {p.stderr.strip()[:300]}")
    return p.stdout


def _store_namespace() -> str:
    """The appliance runs the kubernetes provider: remote Secrets live in one namespace of its k3s."""
    from . import eso
    if eso.provider() != "kubernetes":
        raise ApplianceError(f"secret store provider {eso.provider()}: create the IdP's values in that store "
                             "yourself (docs/sandbox-idp.md)")
    return eso.remote_namespace()


def _remote_secret(cmd: list[str], name: str) -> dict[str, str]:
    import base64
    import subprocess
    p = subprocess.run(cmd + ["-n", _store_namespace(), "get", "secret", name, "-o", "json"],
                       capture_output=True, text=True, timeout=60)
    if p.returncode:
        if "NotFound" in p.stderr or "not found" in p.stderr:
            return {}
        raise ApplianceError(f"kubectl get secret {name}: {p.stderr.strip()[:300]}")
    data = json.loads(p.stdout).get("data") or {}
    return {k: base64.b64decode(v).decode() for k, v in data.items()}


def _apply_remote(cmd: list[str], name: str, values: dict[str, str]) -> None:
    import base64
    doc = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
           "metadata": {"name": name, "namespace": _store_namespace(),
                        "labels": {"app.kubernetes.io/managed-by": "containerizer-appliance"}},
           "data": {k: base64.b64encode(v.encode()).decode() for k, v in sorted(values.items())}}
    # server-side apply with our own field manager: we own exactly these keys of the remote Secret, other
    # writers (External Secrets setup, component secrets) keep theirs
    _kubectl(cmd, ["apply", "--server-side", "--force-conflicts", "--field-manager=containerizer-idp", "-f", "-"],
             stdin=json.dumps(doc))


def deployed_config(cmd: list[str]) -> tuple[dict, list[dict]]:
    """idp.json and the application definitions of the sync ConfigMap(s) Flux deployed."""
    import subprocess
    p = subprocess.run(cmd + ["-n", NAMESPACE, "get", "configmap", "-l", f"app.kubernetes.io/name={SYNC}", "-o", "json"],
                       capture_output=True, text=True, timeout=60)
    if p.returncode:
        raise ApplianceError(f"kubectl get configmap: {p.stderr.strip()[:300]}")
    cfg: dict = {}
    apps: list[dict] = []
    for cm in sorted(json.loads(p.stdout).get("items") or [], key=lambda x: x["metadata"].get("creationTimestamp", "")):
        data = cm.get("data") or {}
        try:
            cfg = json.loads(data.get("idp.json") or "{}") or cfg
            apps += [json.loads(v) for k, v in sorted(data.items()) if k.startswith("apps__") and k.endswith(".json")]
        except ValueError:
            continue
    return cfg, apps


def appliance_secrets(cmd: list[str], log=print) -> dict:
    """Make the passwords and client secrets the deployed IdP configuration needs, once: missing values
    are generated, existing ones are kept. Values go to kubectl through stdin only."""
    cfg, apps = deployed_config(cmd)
    if not cfg:
        return {"created": [], "apps": 0}
    props, app_keys = needed_secrets(cfg, apps)
    have = _remote_secret(cmd, remote_key())
    values = {k: have.get(k) or make_value(kind) for k, kind in props.items()}
    created = sorted(k for k in props if not have.get(k))
    if created or any(k not in have for k in values):
        _apply_remote(cmd, remote_key(), values)
        # the IdP's ExternalSecret reads now, not after ESO's back-off from its first, failed read
        import time
        try:
            _kubectl(cmd, ["-n", NAMESPACE, "annotate", "--overwrite", "externalsecrets.external-secrets.io", SECRET,
                           f"force-sync={int(time.time())}"])
        except ApplianceError:
            pass
    for remote, envs in sorted(app_keys.items()):
        cur = _remote_secret(cmd, remote)
        want = {env: values[prop] for env, prop in envs.items()}
        if any(cur.get(k) != v for k, v in want.items()):
            _apply_remote(cmd, remote, want)
            log(f"client secret of {remote}")
    if created:
        log(f"generated {', '.join(created)}")
    return {"created": created, "apps": len(app_keys)}


def appliance_users(cmd: list[str]) -> list[tuple[str, str, str]]:
    """(user, groups, password) of the sandbox test users, for an administrator on the console."""
    cfg, _ = deployed_config(cmd)
    have = _remote_secret(cmd, remote_key())
    return [(u["username"], ", ".join(u.get("groups") or []), have.get(f"user-{u['username']}", "(not generated yet)"))
            for u in cfg.get("users") or []]
