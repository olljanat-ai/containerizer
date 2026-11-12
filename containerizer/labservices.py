"""Lab services: backing services that the appliance runs in its k3s sandbox for the scanned apps.

An administrator turns each service on or off under Admin -> Lab services (admin_lab.py). The system
agent writes the result to `lab-services.json` (CONFIG_PATH). The lab agent (labagent.py, root) runs the
services, and the scans (org.py) read the same file. Then, for every component that depends on a
service that is on:

- the generated manifests point the component at the lab service by overriding its configuration
  with environment variables (`ConnectionStrings__Shop`, `AWS_ENDPOINT_URL_S3`, ...), so the code does
  not change;
- the credentials come from External Secrets Operator: an ExternalSecret `lab-<service>` in the app's
  namespace reads remote key `<namespace>--cz-lab-<service>` from the secret store, and the lab agent
  fills that key in when it creates the app's database, user or instance;
- the component's NetworkPolicy may reach the service's port in namespace `containerizer-lab`, and the
  lab's NetworkPolicies let in only the namespaces the agent provisioned.

Two kinds of service:

- shared (SQL Server, PostgreSQL, MySQL, MongoDB, RabbitMQ): one server; each app gets its own database and
  login (RabbitMQ: virtual host and user), with rights on that database only;
- per app (Redis, S3, Azure Blob, Kafka, SFTP, Mail): one small instance per app, because these protocols
  cannot keep apps apart on one server without code changes (Redis has no per-database ACL; bucket,
  container and topic names would collide between apps; an SFTP client expects its own root; a mail
  catcher cannot tell which app sent a message).

Data lives on persistent volumes (k3s local-path storage, on the appliance's persistent partition).
Turning a service off stops it but keeps the volumes and the credentials, so turning it on again
brings the data back.

This module is pure (no I/O besides reading the rules): the catalog, names, detection, the generated
app-side documents and the lab-side manifests.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

LAB_NS = "containerizer-lab"
LABEL = "containerizer.io/lab-service"          # on everything that belongs to one service
APP_LABEL = "containerizer.io/lab-app"          # the app namespace a per-app object belongs to
MANAGED = {"app.kubernetes.io/managed-by": "containerizer-appliance"}
CONFIG_ENV = "CONTAINERIZER_LAB_SERVICES"       # path of lab-services.json for the scans
CONFIG_PATH = Path("/var/lib/containerizer/system/lab-services.json")
REMOTE_PREFIX = "cz-lab-"                       # remote keys <namespace>--cz-lab-<service>
SECRET_PREFIX = "lab-"                          # ExternalSecret / Secret lab-<service> in the app namespace
RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "lab-services.yaml"
# namespaces that may never ask for lab credentials
MAIL_API_PORT = 8025                            # Mailpit's API, on the pod's loopback only
MAIL_MAX = 1000                                 # messages kept per app mailbox (the oldest go first)
MAIL_MAX_AGE = "30d"
RESERVED_NS = frozenset({LAB_NS, "containerizer-secrets", "kube-system", "kube-public", "kube-node-lease",
                         "default", "flux-system", "external-secrets", "containerizer-verify"})
NS_RE = re.compile(r"[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?")


def reserved(ns: str) -> bool:
    """A namespace that may never ask for lab credentials: these, and every namespace no application may have
    (generate.reserved_namespace: the cluster's, the platform's, Containerizer's own)."""
    from .generate import reserved_namespace
    return ns in RESERVED_NS or reserved_namespace(ns)


@dataclass(frozen=True)
class Service:
    id: str
    title: str
    engine: str                 # what runs: shown on the page
    shared: bool                # one server with a database per app, or one instance per app
    port: int
    uid: int                    # runAsUser / runAsGroup / fsGroup
    image_var: str              # images.env
    default: bool               # on before an administrator has chosen
    memory: tuple[str, str]     # request, limit
    storage: str                # PersistentVolumeClaim request
    summary: str
    service_port: int = 0       # the Service's port when it differs from the container's (SFTP: 22)

    @property
    def svc_port(self) -> int:
        return self.service_port or self.port


SERVICES: dict[str, Service] = {s.id: s for s in (
    Service("sqlserver", "SQL Server", "SQL Server 2025 Developer edition", True, 1433, 10001,
            "CZ_IMAGE_MSSQL", True, ("2Gi", "3Gi"), "20Gi",
            "One server, a database and login per app (db_owner of its own database only). Apps with an "
            "uploaded dev database backup get that backup restored next to them instead."),
    Service("postgres", "PostgreSQL", "PostgreSQL 18", True, 5432, 70,
            "CZ_IMAGE_LAB_POSTGRES", False, ("256Mi", "1Gi"), "10Gi",
            "One server, a database and role per app (owner of its own database only)."),
    Service("mysql", "MySQL", "MySQL 8.4 LTS", True, 3306, 999,
            "CZ_IMAGE_LAB_MYSQL", False, ("512Mi", "1Gi"), "10Gi",
            "One server, a database and user per app (all rights on its own database only)."),
    Service("redis", "Redis", "Redis 8.8", False, 6379, 999,
            "CZ_IMAGE_LAB_REDIS", False, ("32Mi", "256Mi"), "1Gi",
            "One instance per app with its own password; append-only file on a persistent volume."),
    Service("s3", "S3 object storage", "Versity S3 Gateway (S3 API over files)", False, 7070, 10001,
            "CZ_IMAGE_LAB_S3", False, ("32Mi", "256Mi"), "5Gi",
            "One S3 endpoint per app with its own access key; any bucket the app creates is its own."),
    Service("azure-blob", "Azure Blob storage", "Azurite (Azure Storage emulator), blob service", False, 10000, 1000,
            "CZ_IMAGE_LAB_AZURITE", False, ("64Mi", "512Mi"), "5Gi",
            "One Azurite blob endpoint per app with its own account key."),
    Service("mongodb", "MongoDB", "MongoDB 8.0 Community", True, 27017, 999,
            "CZ_IMAGE_LAB_MONGODB", False, ("256Mi", "1Gi"), "10Gi",
            "One server, a database and user per app (dbOwner of its own database only)."),
    Service("rabbitmq", "RabbitMQ", "RabbitMQ 4.4", True, 5672, 100,
            "CZ_IMAGE_LAB_RABBITMQ", False, ("256Mi", "768Mi"), "5Gi",
            "One broker, a virtual host and user per app (rights on its own virtual host only)."),
    Service("kafka", "Kafka", "Apache Kafka 4.4 (KRaft, one node)", False, 9092, 1000,
            "CZ_IMAGE_LAB_KAFKA", False, ("512Mi", "1Gi"), "5Gi",
            "One single-node broker per app; only the app's namespace can reach it (no client login)."),
    Service("sftp", "SFTP", "SFTPGo (SFTP server)", False, 2022, 1000,
            "CZ_IMAGE_LAB_SFTP", False, ("32Mi", "256Mi"), "5Gi",
            "One SFTP server per app with its own user and password, on port 22.", service_port=22),
    Service("smtp", "Mail (SMTP)", "Mailpit (catch-all mailbox, never relays)", False, 1025, 1000,
            "CZ_IMAGE_LAB_MAILPIT", True, ("32Mi", "256Mi"), "1Gi",
            "One SMTP mailbox per app on port 25 that keeps every message and sends none on; administrators and "
            "operators read them under Admin -> Lab mail.", service_port=25),
)}
ORDER = list(SERVICES)


class LabError(ValueError):
    pass


# --------------------------------------------------------------------------- configuration

def defaults() -> dict[str, bool]:
    return {s.id: s.default for s in SERVICES.values()}


def validate(services) -> dict[str, bool]:
    """{service id: on} with exactly the known services; anything else is refused."""
    if not isinstance(services, dict) or set(services) != set(SERVICES) \
            or not all(isinstance(v, bool) for v in services.values()):
        raise LabError("lab services: give true or false for each of " + ", ".join(ORDER))
    return {k: services[k] for k in ORDER}


def load_config(path: Path | None = None) -> dict:
    """lab-services.json: {"services": {id: bool}, "changed_by", "changed_at"}; the defaults when the
    file does not exist yet."""
    p = Path(path) if path else CONFIG_PATH
    try:
        data = json.loads(p.read_text())
    except FileNotFoundError:
        return {"services": defaults(), "changed_by": None, "changed_at": None}
    except (OSError, ValueError) as ex:
        raise LabError(f"{p}: {ex}") from None
    services = (data or {}).get("services")
    if isinstance(services, dict):          # a service this version added: its default until an administrator chooses
        services = {**{k: v.default for k, v in SERVICES.items() if k not in services}, **services}
    return {"services": validate(services), "changed_by": data.get("changed_by"),
            "changed_at": data.get("changed_at")}


def enabled_from_env(env=None) -> set[str] | None:
    """The services the scans may use: None when lab services are not set up here (no
    CONTAINERIZER_LAB_SERVICES), else the ids that are on."""
    env = os.environ if env is None else env
    path = (env.get(CONFIG_ENV) or "").strip()
    if not path:
        return None
    return {k for k, v in load_config(Path(path))["services"].items() if v}


# --------------------------------------------------------------------------- names

def _label(base: str, key: str) -> str:
    """A DNS label (Service name, at most 63, starts with a letter) for `base`; long names keep a hash."""
    if len(base) <= 63:
        return base
    h = hashlib.sha256(key.encode()).hexdigest()[:8]
    return base[:54].rstrip("-") + "-" + h


def instance(svc: str, ns: str) -> str:
    """Name of a per-app instance (Deployment, Service, PVC prefix) in the lab namespace."""
    return _label(f"{svc}-{ns}", f"{svc}/{ns}")


def host(svc: str, ns: str) -> str:
    name = svc if SERVICES[svc].shared else instance(svc, ns)
    return f"{name}.{LAB_NS}.svc.cluster.local"


def secret_name(svc: str) -> str:
    return f"{SECRET_PREFIX}{svc}"


def remote_name(svc: str) -> str:
    return f"{REMOTE_PREFIX}{svc}"


def remote_key(ns: str, svc: str) -> str:
    from . import eso
    return eso.remote_key(ns, remote_name(svc))


def db_name(ns: str) -> str:
    """Database and login/role of an app on a shared server: its namespace, hyphens as underscores."""
    return ns.replace("-", "_")


def check_namespace(ns: str) -> None:
    if not NS_RE.fullmatch(ns or "") or reserved(ns):
        raise LabError(f"namespace {ns!r} cannot use lab services")


# --------------------------------------------------------------------------- what an app needs

_SQLSERVER = re.compile(r"(?i)\b(Initial Catalog|Integrated Security|Trusted_Connection|MultipleActiveResultSets|"
                        r"TrustServerCertificate|Persist Security Info)\s*=|\(localdb\)|"
                        r"\b(Data Source|Server|Addr|Address)\s*=\s*(tcp:)?[^;]*(\\|,\s*\d{2,5}\b)")
_SERVER_DB = re.compile(r"(?i)\b(Server|Data Source)\s*=[^;]+;.*\bDatabase\s*=")
_NOT_SQLSERVER = re.compile(r"(?i)\b(Port|Host|SslMode|Ssl Mode|Uid|CharSet|AllowPublicKeyRetrieval)\s*=")
_MYSQL = re.compile(r"(?i)^\s*mysql://|\b(Server|Host|Data Source)\s*=[^;]+;.*(\b(Uid|Pwd)\s*=|\bPort\s*=\s*3306\b|"
                    r"\b(AllowPublicKeyRetrieval|CharSet|AllowUserVariables|ConvertZeroDateTime|TreatTinyAsBoolean)\s*=)")
# Db2 (IBM Data Server Provider) and Informix put the port after a colon: Server=db2.example.com:50000
_COLON_PORT = re.compile(r"(?i)\bServer\s*=\s*[^;:,\\]+:\d{2,5}\s*(;|$)")
# drivers of databases the lab does not run: a connection string of such a component is not a lab database, even
# when it looks like one (Db2's Server=...;Database=...;UID=...;PWD=... reads like MySQL's)
OTHER_DB_PACKAGES = re.compile(r"(?i)^(Net\.)?IBM\.Data\.(DB2|Db2|Informix)([.\-].*)?$|^IBM\.EntityFrameworkCore(-lnx|-osx)?$|"
                               r"^Oracle\.(ManagedDataAccess|DataAccess|EntityFrameworkCore)(\..*)?$|"
                               r"^com\.ibm\.db2:jcc$|^com\.oracle\.database\.jdbc:.*|^ibm_db$|^oracledb$|^cx_Oracle$")
_ODBC_SQLSERVER = re.compile(r"(?i)\bDriver\s*=\s*\{?[^;]*SQL Server")
_POSTGRES = re.compile(r"(?i)^\s*postgres(ql)?://|\bHost\s*=[^;]+;.*\b(Username|User ID|User Id|UserName|Database|Port)\s*=|"
                       r"\b(Username|Database|Port)\s*=[^;]*;.*\bHost\s*=")
_REDIS_OPTS = re.compile(r"(?i)^\s*rediss?://|,\s*(abortConnect|connectTimeout|syncTimeout|allowAdmin|ssl|password|"
                         r"defaultDatabase|connectRetry|keepAlive)\s*=")
_HOSTPORT = re.compile(r"^\s*[\w.\-]+:\d{2,5}\s*(,|$)")
_AZURE = re.compile(r"(?i)\bUseDevelopmentStorage\s*=\s*true|\bAccountName\s*=[^;]+;.*\bAccountKey\s*=|"
                    r"\bBlobEndpoint\s*=|\bDefaultEndpointsProtocol\s*=")
_S3_SECTION = re.compile(r"(?i)(^|:)[^:]*(s3|minio|aws)[^:]*:")
_S3_LEAF = {"serviceurl": "s3:endpoint", "endpoint": "s3:endpoint", "endpointurl": "s3:endpoint",
            "serviceuri": "s3:endpoint", "accesskey": "s3:access-key", "accesskeyid": "s3:access-key",
            "secretkey": "s3:secret-key", "secretaccesskey": "s3:secret-key", "region": "s3:region",
            "authenticationregion": "s3:region", "forcepathstyle": "s3:path-style"}
_MONGO = re.compile(r"(?i)^\s*mongodb(\+srv)?://")
_AMQP = re.compile(r"(?i)^\s*amqps?://")
_RABBIT_KEY = re.compile(r"(?i)rabbit|amqp|easynetq")
# the pieces of a client configuration in its own section: {service: (section, {leaf: secret key})}
PARTS: dict[str, tuple[re.Pattern, dict[str, str]]] = {
    "mongodb": (re.compile(r"(?i)(^|:)[^:]*mongo[^:]*:"),
                {"databasename": "database", "database": "database", "dbname": "database"}),
    "rabbitmq": (re.compile(r"(?i)(^|:)[^:]*(rabbit|amqp|easynetq)[^:]*:"),
                 {"host": "host", "hostname": "host", "server": "host", "port": "port", "username": "username",
                  "user": "username", "password": "password", "virtualhost": "vhost", "vhost": "vhost",
                  "uri": "connection-string", "url": "connection-string", "amqpuri": "connection-string",
                  "connectionstring": "connection-string"}),
    "kafka": (re.compile(r"(?i)(^|:)[^:]*kafka[^:]*:"),
              {"bootstrapservers": "bootstrap-servers", "brokers": "bootstrap-servers", "brokerlist": "bootstrap-servers",
               "metadatabrokerlist": "bootstrap-servers", "securityprotocol": "security-protocol"}),
    "sftp": (re.compile(r"(?i)(^|:)[^:]*(sftp|ssh)[^:]*:"),
             {"host": "host", "hostname": "host", "server": "host", "address": "host", "port": "port",
              "username": "username", "user": "username", "login": "username", "password": "password"}),
}
# SMTP client settings: in a section named after mail or SMTP (Mail:Host, Smtp:Port, EmailSettings:SmtpServer),
# or a leaf that says it (Worker:SmtpHost, Worker:MailPickupFolder). The sender's address, recipients and
# credentials stay as they are: the lab's mailbox takes any login, or none.
_SMTP_SECTION = re.compile(r"(?i)(^|:)[^:]*(mail|smtp)[^:]*:")
_SMTP_LEAF = {"host": "host", "hostname": "host", "server": "host", "smtphost": "host", "smtpserver": "host",
              "relay": "host", "smtprelay": "host", "port": "port", "smtpport": "port",
              "enablessl": "tls", "usessl": "tls", "ssl": "tls", "usetls": "tls", "enabletls": "tls",
              "starttls": "tls", "usestarttls": "tls", "smtpenablessl": "tls", "smtpusessl": "tls",
              "pickupfolder": "pickup", "pickupdirectory": "pickup", "pickupdirectorylocation": "pickup",
              "pickuppath": "pickup", "pickupdir": "pickup", "securesocketoptions": "secure",
              "socketoptions": "secure", "secureoptions": "secure"}
# sections of HTTP mail APIs (their Server or Host is not an SMTP server)
_MAIL_API = re.compile(r"(?i)sendgrid|mailgun|mailchimp|mailjet|postmark|mandrill|sparkpost|graph|exchange|ews|imap|pop3")
_SMTP_PREFIXED = re.compile(r"(?i)(smtp|mail)(host|server|relay|port|enablessl|usessl|pickupfolder|pickupdirectory|"
                            r"pickupdirectorylocation|pickuppath)")
_PICKUP_METHOD = re.compile(r"(?i)(SpecifiedPickupDirectory|PickupDirectoryFromIis)")
# parts that are plain settings, not values from the lab secret
_PLAIN_PARTS = {"kafka:security-protocol": "Plaintext",
                # the lab's mailbox speaks plain SMTP on the node's pod network (like Kafka; see docs)
                "smtp:tls": "false",
                # mail written to a pickup folder: an empty folder makes the app send over SMTP instead
                "smtp:pickup": "",
                "smtp:delivery": "Network",     # SmtpDeliveryMethod.Network
                "smtp:mode": "Smtp",            # Mode: Pickup -> Smtp
                "smtp:secure": "None"}          # MailKit SecureSocketOptions


def smtp_kind(key: str, value) -> str | None:
    """`smtp:<part>` for an SMTP client setting (see _SMTP_LEAF), else None."""
    leaf = key.rsplit(":", 1)[-1].replace("_", "").replace(".", "").lower()
    if isinstance(value, str) and len(value) > 500 or _MAIL_API.search(key):
        return None
    if _SMTP_SECTION.search(key) or re.match(r"(?i)(smtp|mail)", leaf):
        if leaf in ("deliverymethod", "smtpdeliverymethod") and isinstance(value, str) and _PICKUP_METHOD.fullmatch(value.strip()):
            return "smtp:delivery"
        if leaf in ("mode", "deliverymode", "mailmode", "delivery") and isinstance(value, str) \
                and value.strip().lower() == "pickup":
            return "smtp:mode"
    if _SMTP_SECTION.search(key) and leaf in _SMTP_LEAF:
        part = _SMTP_LEAF[leaf]
    elif _SMTP_PREFIXED.fullmatch(leaf):
        m = _SMTP_PREFIXED.fullmatch(leaf)
        part = _SMTP_LEAF.get(m.group(2).lower()) or _SMTP_LEAF.get("smtp" + m.group(2).lower())
    else:
        return None
    if part == "tls":
        return "smtp:tls" if isinstance(value, bool) or str(value).strip().lower() in ("true", "false") else None
    if part == "port":
        return "smtp:port" if not isinstance(value, bool) and re.fullmatch(r"\d{1,5}", str(value).strip()) else None
    if part == "pickup":
        return "smtp:pickup" if isinstance(value, str) else None
    if part == "secure":
        return "smtp:secure" if isinstance(value, str) and re.fullmatch(
            r"(?i)Auto|SslOnConnect|StartTls|StartTlsWhenAvailable|None", value.strip()) else None
    # a host name, not a URL of an HTTP API or an empty placeholder
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][\w.\-]*", value.strip()):
        return "smtp:host"
    return None


def classify(key: str, value) -> str | None:
    """Which lab service a configuration value (appsettings key `Section:Name`) is the setting of:
    a service id, `s3:<part>` for the pieces of an S3 client configuration, or None."""
    if not isinstance(value, (str, bool, int)) or key.startswith("Logging:"):
        return None
    leaf = key.rsplit(":", 1)[-1].replace("_", "").lower()
    if _S3_SECTION.search(key) and leaf in _S3_LEAF and type(value) is not int:
        return _S3_LEAF[leaf]
    if isinstance(value, str) and _MONGO.search(value):
        return "mongodb"
    if isinstance(value, str) and (_AMQP.search(value) or (_RABBIT_KEY.search(key) and re.search(r"(?i)\bhost\s*=", value))):
        return "rabbitmq"
    leaf = leaf.replace(".", "")
    smtp = smtp_kind(key, value)
    if smtp:
        return smtp
    for svc, (section, leaves) in PARTS.items():
        if section.search(key) and leaf in leaves and not isinstance(value, bool):
            return f"{svc}:{leaves[leaf]}"
    if leaf == "bootstrapservers" and isinstance(value, str):     # "bootstrap.servers" in a flat client config
        return "kafka:bootstrap-servers"
    if not isinstance(value, str) or not value.strip() or len(value) > 2000:
        return None
    if _AZURE.search(value):
        return "azure-blob"
    if _POSTGRES.search(value):
        return "postgres"
    if _COLON_PORT.search(value):
        return None             # Db2 or Informix: not a database the lab runs
    if _MYSQL.search(value) and not _ODBC_SQLSERVER.search(value):
        return "mysql"
    if _SQLSERVER.search(value) or (_SERVER_DB.search(value) and not _NOT_SQLSERVER.search(value)):
        return "sqlserver"
    rediskey = re.search(r"(?i)redis|cache", key)
    if _REDIS_OPTS.search(value) and (rediskey or _HOSTPORT.match(value) or value.lower().startswith("redis")):
        return "redis"
    if rediskey and _HOSTPORT.match(value):
        return "redis"
    if _HOSTPORT.match(value) and re.search(r":63(79|80)\b", value):
        return "redis"
    return None


def settings_facts(flat: list[tuple[str, object]]) -> dict[str, str]:
    """facts["lab_settings"]: {configuration key: what classify() says} for one appsettings.json."""
    out = {}
    for k, v in flat:
        kind = classify(k, v)
        if kind:
            out[k] = kind
    return out


def rules() -> dict:
    data = yaml.safe_load(RULES_FILE.read_text()) or {}
    svcs = data.get("services") or {}
    unknown = set(svcs) - set(SERVICES)
    if unknown:
        raise LabError(f"{RULES_FILE.name}: unknown services {sorted(unknown)}")
    return svcs


def needs(repo, c) -> dict[str, list[str]]:
    """{service id: why} for one component: a package rule from rules/lab-services.yaml on the component
    or a project it references, or a setting the scan classified (facts["lab_settings"])."""
    from .harden import _projects
    from .rules import Context, Rule, run_rule
    out: dict[str, list[str]] = {}
    for svc, spec in rules().items():
        if not spec.get("when"):
            continue
        r = Rule.from_dict({"id": f"lab-{svc}", "when": spec["when"], "phase": "network"})
        for p in _projects(repo, c):
            m = run_rule(r, Context(repo, p, c.role))
            if m is not None:
                out.setdefault(svc, []).append(f"package in {p.rel}" if p is not c.project else "package")
                break
    # a component with a Db2 or Oracle driver and none of a lab database: its connection strings are for that one
    other_db = any(OTHER_DB_PACKAGES.match(n) for p in _projects(repo, c) for n in p.packages)
    for key, kind in sorted(((c.facts or {}).get("lab_settings") or {}).items()):
        svc = kind.split(":", 1)[0]
        if svc in SQL_DBS and other_db and svc not in out:
            continue
        if svc in SERVICES:
            out.setdefault(svc, []).append(f"setting {key}")
    return {k: out[k] for k in ORDER if k in out}


# --------------------------------------------------------------------------- the app side

def _env_key(key: str) -> str:
    return key.replace(":", "__")


def connection_keys(c, svc: str, needed: dict) -> list[str]:
    """The connection string / setting keys of component `c` that should point at `svc`."""
    lab = (c.facts or {}).get("lab_settings") or {}
    keys = [k for k, v in lab.items() if v == svc]
    if keys or svc in ("s3", "azure-blob", "kafka", "sftp", "smtp"):
        return sorted(keys)
    if svc == "redis":
        return ["ConnectionStrings:Redis"]
    # databases: connection strings whose engine the scan could not tell, when this is the only
    # database the component needs; otherwise the conventional DefaultConnection
    css = [f"ConnectionStrings:{k}" for k in (c.facts or {}).get("connection_strings") or []]
    unknown = [k for k in css if k not in lab]
    dbs = [s for s in ("sqlserver", "postgres", "mysql") if s in needed]
    if unknown and dbs == [svc]:
        return unknown
    if not css:
        return ["ConnectionStrings:DefaultConnection"]
    return []


# --------------------------------------------------------------------------- stacks other than .NET
#
# A Java, Node.js, Python or Go component is configured through environment variables of its own: the ones its
# framework binds (Spring Boot, Quarkus, Micronaut), else the ones its code reads (process.env.X, os.environ["X"],
# os.Getenv("X"), System.getenv("X"), .env.example), else a widespread name (DATABASE_URL, REDIS_URL...), with a
# note that says so.

SQL_DBS = ("sqlserver", "postgres", "mysql")
_ENV_READS = {
    "node": re.compile(r"""process\.env\.([A-Z][A-Z0-9_]*)|process\.env\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\]"""),
    "python": re.compile(r"""os\.(?:environ\.get|getenv|environ\.setdefault)\(\s*['"]([A-Z][A-Z0-9_]*)['"]|"""
                         r"""os\.environ\[\s*['"]([A-Z][A-Z0-9_]*)['"]\s*\]|"""
                         r"""\benv(?:\.\w+)?\(\s*['"]([A-Z][A-Z0-9_]*)['"]|config\(\s*['"]([A-Z][A-Z0-9_]*)['"]"""),
    "go": re.compile(r"""os\.(?:Getenv|LookupEnv)\(\s*"([A-Z][A-Z0-9_]*)"\s*\)"""),
    "java": re.compile(r"""System\.getenv\(\s*"([A-Z][A-Z0-9_]*)"\s*\)|\$\{([A-Z][A-Z0-9_]*)(?::[^}]*)?\}"""),
}
_ENV_EXAMPLES = (".env.example", ".env.sample", ".env.template", ".env.dist", "example.env", ".env.defaults")
# the service a variable's name says (the first that matches a word of it); "db" is whichever database is needed
_ENV_SVC = (("sqlserver", {"MSSQL", "SQLSERVER"}), ("postgres", {"PG", "POSTGRES", "POSTGRESQL", "PSQL"}),
            ("mysql", {"MYSQL", "MARIADB"}), ("mongodb", {"MONGO", "MONGODB"}), ("redis", {"REDIS"}),
            ("rabbitmq", {"RABBIT", "RABBITMQ", "AMQP"}), ("kafka", {"KAFKA"}), ("sftp", {"SFTP"}),
            ("smtp", {"SMTP", "MAIL", "EMAIL"}), ("db", {"DB", "DATABASE", "SQL", "JDBC", "DATASOURCE"}))
# what a variable holds, by the last word of its name
_ENV_PART = {"URL": "url", "URI": "url", "DSN": "url", "CONNSTR": "url", "HOST": "host", "HOSTNAME": "host",
             "SERVER": "host", "ADDR": "hostport", "ADDRESS": "hostport", "PORT": "port", "USER": "username",
             "USERNAME": "username", "LOGIN": "username", "PASS": "password", "PASSWORD": "password",
             "PASSWD": "password", "PWD": "password", "NAME": "database", "DATABASE": "database", "DB": "database",
             "VHOST": "vhost", "BROKERS": "bootstrap", "BROKER": "bootstrap", "SERVERS": "bootstrap"}
_LIBPQ = {"PGHOST": "host", "PGPORT": "port", "PGUSER": "username", "PGPASSWORD": "password", "PGDATABASE": "database"}
# the variables a framework binds to its client configuration: {framework: {service: [(name, part)]}}
_FRAMEWORK_ENV = {
    "spring": {
        "db": [("SPRING_DATASOURCE_URL", "jdbc"), ("SPRING_DATASOURCE_USERNAME", "username"),
               ("SPRING_DATASOURCE_PASSWORD", "password")],
        # Spring Boot 3 reads spring.data.redis.*, Spring Boot 2 spring.redis.*
        "redis": [("SPRING_DATA_REDIS_HOST", "host"), ("SPRING_DATA_REDIS_PORT", "port"),
                  ("SPRING_DATA_REDIS_PASSWORD", "password"), ("SPRING_REDIS_HOST", "host"),
                  ("SPRING_REDIS_PORT", "port"), ("SPRING_REDIS_PASSWORD", "password")],
        "mongodb": [("SPRING_DATA_MONGODB_URI", "url")],
        "rabbitmq": [("SPRING_RABBITMQ_HOST", "host"), ("SPRING_RABBITMQ_PORT", "port"),
                     ("SPRING_RABBITMQ_USERNAME", "username"), ("SPRING_RABBITMQ_PASSWORD", "password"),
                     ("SPRING_RABBITMQ_VIRTUAL_HOST", "vhost")],
        "kafka": [("SPRING_KAFKA_BOOTSTRAP_SERVERS", "bootstrap")],
        "smtp": [("SPRING_MAIL_HOST", "host"), ("SPRING_MAIL_PORT", "port")],
    },
    "quarkus": {
        "db": [("QUARKUS_DATASOURCE_JDBC_URL", "jdbc"), ("QUARKUS_DATASOURCE_USERNAME", "username"),
               ("QUARKUS_DATASOURCE_PASSWORD", "password")],
        "redis": [("QUARKUS_REDIS_HOSTS", "url")],
        "mongodb": [("QUARKUS_MONGODB_CONNECTION_STRING", "url")],
        "kafka": [("KAFKA_BOOTSTRAP_SERVERS", "bootstrap")],
        "smtp": [("QUARKUS_MAILER_HOST", "host"), ("QUARKUS_MAILER_PORT", "port")],
    },
    "micronaut": {
        "db": [("DATASOURCES_DEFAULT_URL", "jdbc"), ("DATASOURCES_DEFAULT_USERNAME", "username"),
               ("DATASOURCES_DEFAULT_PASSWORD", "password")],
        "kafka": [("KAFKA_BOOTSTRAP_SERVERS", "bootstrap")],
    },
}
# a widespread name, when neither a framework nor the code says which variable the component reads
_COMMON_ENV = {"db": [("DATABASE_URL", "url")], "redis": [("REDIS_URL", "url")], "mongodb": [("MONGODB_URI", "url")],
               "rabbitmq": [("AMQP_URL", "url")], "kafka": [("KAFKA_BROKERS", "bootstrap")],
               "smtp": [("SMTP_HOST", "host"), ("SMTP_PORT", "port")]}
_AZURE_ENV = re.compile(r"^(AZURE_?STORAGE|AZURE_?BLOB|BLOB)\w*_CONNECTION_?STRING$")


def stack(c) -> str:
    """dotnet | java | node | python | go: whose conventions the component's settings follow."""
    kind = getattr(getattr(c, "project", None), "kind_hint", "") or "dotnet"
    return kind if kind in _ENV_READS else "dotnet"


def env_part(name: str) -> tuple[str, str] | None:
    """(service or "db", part) a variable's name says: DATABASE_URL -> ("db", "url"), POSTGRES_DB ->
    ("postgres", "database"), REDIS_HOST -> ("redis", "host"); None for a name that says neither."""
    if name in _LIBPQ:
        return "postgres", _LIBPQ[name]
    words = name.split("_")
    if words[-2:] == ["CONNECTION", "STRING"]:
        words = words[:-2] + ["CONNSTR"]
    for svc, tokens in _ENV_SVC:
        at = next((i for i, w in enumerate(words) if w in tokens), None)
        if at is None:
            continue
        rest = words[:at] + words[at + 1:]
        part = _ENV_PART.get(rest[-1]) if rest else None
        if part == "bootstrap" and svc != "kafka":
            return None
        return (svc, part) if part else None
    return None


def env_reads(c) -> list[str]:
    """The environment variables the component's code reads, and the ones its .env example lists."""
    p, rx, names = c.project, _ENV_READS[stack(c)], set()
    for f in p.source_files():
        names |= {n for m in rx.finditer(p.text(f)) for n in m.groups() if n}
    for n in _ENV_EXAMPLES:
        try:
            text = (p.dir / n).read_text(errors="replace")
        except OSError:
            continue
        names |= set(re.findall(r"(?m)^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=", text))
    if stack(c) == "java":
        from .facts_jvm_node import _placeholder_env, java_config
        names |= {n for v in java_config(p).values() for n in _placeholder_env(str(v))}
    return sorted(names)


def db_url(svc: str, c, host_: str, port, database: str, user: str, password: str, jdbc: bool = False) -> str:
    """The database URL in the form the component's stack (and its client package) reads; `jdbc`: without the
    login, which the framework takes from its own username and password settings."""
    kind, pk = stack(c), set(getattr(c.project, "packages", None) or {})
    if kind == "java":
        if svc == "sqlserver":
            url = f"jdbc:sqlserver://{host_}:{port};databaseName={database};encrypt=true;trustServerCertificate=true"
            return url if jdbc else url + f";user={user};password={password}"
        maria = any(n.startswith("org.mariadb.jdbc:") for n in pk) and not any("mysql-connector" in n for n in pk)
        url = f"jdbc:{'postgresql' if svc == 'postgres' else 'mariadb' if maria else 'mysql'}://{host_}:{port}/{database}"
        return url if jdbc else url + f"?user={user}&password={password}"
    at = f"{user}:{password}@{host_}:{port}"
    if svc == "postgres":
        # lib/pq asks for TLS unless told otherwise; the lab's PostgreSQL has none (its traffic stays on the node)
        return f"postgresql://{at}/{database}" + ("?sslmode=disable" if kind == "go" else "")
    if svc == "mysql":
        if kind == "go":                                        # go-sql-driver's DSN
            return f"{user}:{password}@tcp({host_}:{port})/{database}"
        scheme = "mysql+pymysql" if kind == "python" and "pymysql" in pk and "mysqlclient" not in pk else "mysql"
        return f"{scheme}://{at}/{database}"
    if kind == "go":
        return f"sqlserver://{at}?database={database}&encrypt=true&TrustServerCertificate=true"
    if kind == "python":
        if "pymssql" in pk:
            return f"mssql+pymssql://{at}/{database}"
        return f"mssql+pyodbc://{at}/{database}?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes"
    if pk & {"prisma", "@prisma/client"}:
        return f"sqlserver://{host_}:{port};database={database};user={user};password={password};trustServerCertificate=true"
    return f"mssql://{at}/{database}?encrypt=true&trustServerCertificate=true"


def stack_names(svc: str, c, needed: dict) -> tuple[list[tuple[str, str]], str]:
    """[(environment variable, part)] that point a Java, Node.js, Python or Go component at `svc`, and how they
    were found: "framework", "code", "common" (a widespread name: the component may not read it) or "" (none)."""
    only_db = [s for s in SQL_DBS if s in needed] or [s for s in ("mongodb",) if s in needed]
    generic = svc in SQL_DBS + ("mongodb",) and only_db == [svc]      # DB_*, DATABASE_URL mean this one
    group = "db" if svc in SQL_DBS else svc
    fw = _FRAMEWORK_ENV.get((getattr(c, "facts", None) or {}).get("java_framework") or "", {})
    names = list(fw.get(group, [])) if group != "db" or generic else []
    how = "framework" if names else ""
    for n in env_reads(c):
        hit = env_part(n)
        if hit and (hit[0] == svc or (hit[0] == "db" and generic)) and n not in dict(names):
            names.append((n, hit[1]))
            how = how or "code"
    if not names and (group != "db" or generic):
        names = list(_COMMON_ENV.get(group, []))
        how = "common" if names else ""
    return names, how


def stack_env(svc: str, ns: str, c, needed: dict) -> tuple[list[dict], list[str]]:
    """env_for of a component that is not .NET."""
    sec, s, h = secret_name(svc), SERVICES[svc], host(svc, ns)

    def ref(name: str, key: str) -> dict:
        return {"name": name, "valueFrom": {"secretKeyRef": {"name": sec, "key": key}}}
    where = f"the Secret {sec} (keys: {', '.join(secret_keys(svc))})"
    if svc == "s3":                 # the AWS SDKs of every language read these
        return [ref("AWS_ACCESS_KEY_ID", "access-key-id"), ref("AWS_SECRET_ACCESS_KEY", "secret-access-key"),
                {"name": "AWS_REGION", "value": "us-east-1"},
                {"name": "AWS_ENDPOINT_URL_S3", "value": f"http://{h}:{s.port}"}], \
            ["The AWS SDK reads AWS_ENDPOINT_URL_S3 (SDK releases since late 2023); a client that sets its endpoint "
             "in code, or needs path-style addressing, still needs that setting."]
    if svc == "azure-blob":
        found = [n for n in env_reads(c) if _AZURE_ENV.match(n)]
        notes = [] if found else ["No Azure Storage connection string variable was found in the code: "
                                  "AZURE_STORAGE_CONNECTION_STRING is set (a common name). If the component reads "
                                  f"another setting, point it at {where}."]
        return [ref(n, "connection-string") for n in found or ["AZURE_STORAGE_CONNECTION_STRING"]], notes
    names, how = stack_names(svc, c, needed)
    if not names:
        dbs = [SERVICES[x].title for x in SQL_DBS if x in needed]
        why = (f"it uses more than one database ({', '.join(dbs)}) and its variables do not say which is which"
               if svc in SQL_DBS and len(dbs) > 1 else "no environment variable for it was found in its code")
        return [], [f"{s.title} is not wired for this component ({why}): point its settings at {where} yourself."]
    keys = new_credentials(svc, ns)
    user, pw = f"CZ_LAB_{svc.upper().replace('-', '_')}_USERNAME", f"CZ_LAB_{svc.upper().replace('-', '_')}_PASSWORD"
    env, helpers = [], set()
    for name, part in names:
        if part == "bootstrap" or (svc == "kafka" and part in ("url", "hostport")):
            env.append(ref(name, "bootstrap-servers"))
        elif part == "hostport":
            env.append({"name": name, "value": f"{h}:{s.svc_port}"})
        elif part == "jdbc":
            env.append({"name": name, "value": db_url(svc, c, h, s.port, db_name(ns), "", "", jdbc=True)})
        elif part == "url" and svc in SQL_DBS:
            helpers |= {"username", "password"}
            env.append({"name": name, "value": db_url(svc, c, h, s.port, db_name(ns), f"$({user})", f"$({pw})")})
        elif part == "url" and svc == "redis":
            helpers.add("password")
            env.append({"name": name, "value": f"redis://:$({pw})@{h}:{s.port}"})
        elif part == "url" and "connection-string" in keys:
            env.append(ref(name, "connection-string"))
        elif part in keys:
            env.append(ref(name, part))
    env = [ref(user if k == "username" else pw, k) for k in sorted(helpers)] + env
    notes = []
    if how == "common":
        notes.append(f"No environment variable for {s.title} was found in the code: "
                     f"{', '.join(n for n, _ in names)} set (a common name). If the component reads another "
                     f"setting, point it at {where}.")
    return env, notes


def env_for(svc: str, ns: str, c, needed: dict) -> tuple[list[dict], list[str]]:
    """Environment entries (secret references first, then plain settings, which may use them with
    Kubernetes' $(VAR) expansion) and notes for the README."""
    if stack(c) != "dotnet":
        return stack_env(svc, ns, c, needed)
    sec = secret_name(svc)

    def ref(name: str, key: str) -> dict:
        return {"name": name, "valueFrom": {"secretKeyRef": {"name": sec, "key": key}}}
    h, notes = host(svc, ns), []
    keys = connection_keys(c, svc, needed)
    if svc in ("sqlserver", "postgres", "mysql", "redis"):
        # the whole connection string comes from the store: nothing secret in the manifest
        return [ref(_env_key(k), "connection-string") for k in keys], notes
    if svc == "s3":
        endpoint = f"http://{h}:7070"
        env = [ref("AWS_ACCESS_KEY_ID", "access-key-id"), ref("AWS_SECRET_ACCESS_KEY", "secret-access-key"),
               {"name": "AWS_REGION", "value": "us-east-1"}, {"name": "AWS_ENDPOINT_URL_S3", "value": endpoint}]
        lab = (c.facts or {}).get("lab_settings") or {}
        part = {"s3:endpoint": endpoint, "s3:access-key": "$(AWS_ACCESS_KEY_ID)",
                "s3:secret-key": "$(AWS_SECRET_ACCESS_KEY)", "s3:region": "us-east-1", "s3:path-style": "true"}
        env += [{"name": _env_key(k), "value": part[lab[k]]} for k in sorted(lab) if lab[k] in part]
        if not any(lab.get(k) == "s3:endpoint" for k in lab):
            notes.append("No S3 endpoint setting found in appsettings.json: the AWS SDK reads AWS_ENDPOINT_URL_S3 "
                         "(AWSSDK.S3 3.7.300 or later); a client that sets ServiceURL in code still needs that setting.")
        return env, notes
    if svc == "azure-blob":
        if not keys:
            notes.append("No Azure Storage connection string found in appsettings.json: point the app's setting at "
                         f"the Secret {sec}, key connection-string.")
        return [ref(_env_key(k), "connection-string") for k in keys], notes
    if svc == "smtp":
        lab = (c.facts or {}).get("lab_settings") or {}
        env = []
        for k in sorted(lab):
            kind = lab[k]
            if kind in ("smtp:host", "smtp:port"):
                env.append(ref(_env_key(k), kind.split(":", 1)[1]))
            elif kind.startswith("smtp:") and kind in _PLAIN_PARTS:
                env.append({"name": _env_key(k), "value": _PLAIN_PARTS[kind]})
        if not any(lab[k] == "smtp:host" for k in lab):
            notes.append(f"No SMTP host setting found in appsettings.json: point the app's SMTP host and port at the "
                         f"Secret {sec} (keys host, port); mail it sends elsewhere is not caught.")
        pickup = any(str(getattr(getattr(f, "rule", None), "id", "")).startswith("cfg-smtp-pickup") for f in getattr(c, "findings", None) or [])
        if pickup and not any(lab[k] in ("smtp:pickup", "smtp:delivery", "smtp:mode") for k in lab):
            notes.append("The code writes mail to a pickup folder and no setting turns that off: nothing sends it, and "
                         "the lab's mailbox does not see it.")
        return env, notes
    if svc in PARTS:
        lab = (c.facts or {}).get("lab_settings") or {}
        env = [ref(_env_key(k), "connection-string") for k in keys]
        for k in sorted(lab):
            kind = lab[k]
            if not kind.startswith(f"{svc}:"):
                continue
            if kind in _PLAIN_PARTS:
                env.append({"name": _env_key(k), "value": _PLAIN_PARTS[kind]})
            else:
                env.append(ref(_env_key(k), kind.split(":", 1)[1]))
        if not env:
            notes.append(f"No {SERVICES[svc].title} setting found in appsettings.json: point the app's settings at the "
                         f"Secret {sec} (keys: {', '.join(secret_keys(svc))}).")
        return env, notes
    raise LabError(f"unknown lab service {svc!r}")


def egress_rule(svc: str, ns: str) -> dict:
    """NetworkPolicy egress to the service's pods in the lab namespace."""
    pods = {LABEL: svc} if SERVICES[svc].shared else {LABEL: svc, APP_LABEL: ns}
    return {"to": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": LAB_NS}},
                    "podSelector": {"matchLabels": pods}}],
            "ports": [{"port": SERVICES[svc].port, "protocol": "TCP"}]}


def inject(docs: list[dict], svc: str, ns: str, c, needed: dict) -> list[str]:
    """Point component `c`'s workloads at the lab service: environment (replacing entries of the same
    name, secret references first so $(VAR) resolves) and NetworkPolicy egress. Returns notes."""
    env, notes = env_for(svc, ns, c, needed)
    names = {e["name"] for e in env}
    refs = [e for e in env if "valueFrom" in e]
    vals = [e for e in env if "valueFrom" not in e]
    for d in docs:
        if d.get("kind") in ("Deployment", "StatefulSet", "CronJob", "Job"):
            spec = d.get("spec") or {}
            tpl = ((spec.get("jobTemplate") or {}).get("spec") or spec).get("template") or {}
            for ct in (tpl.get("spec") or {}).get("containers") or []:
                rest = [e for e in ct.get("env") or [] if e["name"] not in names]
                ct["env"] = copy.deepcopy(refs) + rest + copy.deepcopy(vals)
        elif d.get("kind") == "NetworkPolicy" and "Egress" in ((d.get("spec") or {}).get("policyTypes") or []):
            rule = egress_rule(svc, ns)
            eg = d["spec"].setdefault("egress", [])
            if rule not in eg:
                eg.append(rule)
            ann = d.setdefault("metadata", {}).setdefault("annotations", {})
            key = "containerizer.io/egress"
            have = [x for x in (ann.get(key) or "").split(",") if x and x != "none"]
            if f"lab-{svc}" not in have:
                ann[key] = ",".join(have + [f"lab-{svc}"])
    return notes


def app_docs(ns: str, services: list[str]) -> list[dict]:
    """lab/k8s.yaml of an app: one ExternalSecret per lab service it uses."""
    from . import eso
    out = []
    for svc in services:
        doc = eso.external_secret(secret_name(svc), ns, remote_key(ns, svc),
                                  labels={"app.kubernetes.io/part-of": ns, "app.kubernetes.io/managed-by": "containerizer",
                                          LABEL: svc},
                                  comment=f"{SERVICES[svc].title} in the lab: the appliance's lab agent puts the "
                                          f"credentials in the secret store (remote key {remote_key(ns, svc)})")
        out.append(doc)
    return out


@dataclass
class AppPlan:
    """What generate_app records about lab services for one app."""
    needed: dict          # service -> {component: [why]}
    provided: list        # services the app was pointed at
    missing: list         # needed but turned off
    notes: dict           # component -> [notes]
    overrides: dict       # component -> [env names]

    def to_dict(self) -> dict:
        return {"needed": {k: sorted(v) for k, v in self.needed.items()}, "provided": self.provided,
                "missing": self.missing, "overrides": self.overrides}


def readme(app: str, plan: AppPlan) -> str:
    lines = [f"# Lab services of {app}", "",
             "The appliance runs these services in namespace `containerizer-lab` (Admin -> Lab services). "
             "The app's configuration is overridden with environment variables; its code is unchanged. "
             "Credentials come from the secret store through External Secrets Operator.", ""]
    for svc in plan.provided:
        s = SERVICES[svc]
        lines += [f"## {s.title}", "", f"- Host `{host(svc, app)}`, port {s.port} ({s.engine}).",
                  f"- Credentials: Secret `{secret_name(svc)}` (ExternalSecret, remote key `{remote_key(app, svc)}`)."]
        if s.shared:
            lines.append(f"- Database and login `{db_name(app)}`, owner of that database only.")
        if svc == "smtp":
            lines.append("- A catch-all mailbox: every message the app sends stays in the lab, none is sent on. "
                         "Administrators and operators read them under Admin -> Lab mail.")
        for comp, envs in sorted(plan.overrides.items()):
            mine = [e for e in envs if e.startswith(f"{svc}:")]
            if mine:
                lines.append(f"- **{comp}**: " + ", ".join(f"`{e.split(':', 1)[1]}`" for e in mine))
        lines.append("")
    if plan.missing:
        lines += ["## Needed but turned off", ""]
        for svc in plan.missing:
            comps = ", ".join(sorted(plan.needed.get(svc) or {}))
            lines.append(f"- **{SERVICES[svc].title}** ({comps}): turn it on under Admin -> Lab services and scan "
                         "again; until then the app keeps its own settings.")
        lines.append("")
    notes = [(comp, n) for comp, ns in sorted(plan.notes.items()) for n in ns]
    if notes:
        lines += ["## Notes", ""] + [f"- {comp}: {n}" for comp, n in notes] + [""]
    return "\n".join(lines)


# --------------------------------------------------------------------------- the lab side

def _labels(svc: str, ns: str | None = None) -> dict:
    lab = {"app.kubernetes.io/name": instance(svc, ns) if ns else svc, "app.kubernetes.io/part-of": LAB_NS,
           LABEL: svc, **MANAGED}
    if ns:
        lab[APP_LABEL] = ns
    return lab


def namespace_docs() -> list[dict]:
    """The lab namespace: Pod Security restricted, deny everything not allowed below, quota defaults."""
    meta = {"labels": dict(MANAGED)}
    return [
        {"apiVersion": "v1", "kind": "Namespace",
         "metadata": {"name": LAB_NS, "labels": {**MANAGED, "pod-security.kubernetes.io/enforce": "restricted",
                                                 "pod-security.kubernetes.io/enforce-version": "latest",
                                                 "pod-security.kubernetes.io/audit": "restricted",
                                                 "pod-security.kubernetes.io/warn": "restricted"}}},
        {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
         "metadata": {"name": "default-deny-all", "namespace": LAB_NS, **copy.deepcopy(meta)},
         "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]}},
        {"apiVersion": "v1", "kind": "LimitRange", "metadata": {"name": "defaults", "namespace": LAB_NS, **copy.deepcopy(meta)},
         "spec": {"limits": [{"type": "Container", "default": {"memory": "256Mi", "ephemeral-storage": "1Gi"},
                              "defaultRequest": {"cpu": "50m", "memory": "64Mi", "ephemeral-storage": "64Mi"},
                              "max": {"memory": "4Gi"}}]}},
        # no API access from any lab pod
        {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "lab-service", "namespace": LAB_NS, **copy.deepcopy(meta)},
         "automountServiceAccountToken": False},
    ]


def _pod(svc: str, labels: dict, container: dict, volumes: list[dict], caps_add: list[str] | None = None) -> dict:
    """A pod template hardened like the generated apps (rules/60-security.yaml baseline): non-root,
    read-only root file system, no capabilities, RuntimeDefault seccomp and AppArmor, no token."""
    from .harden import harden_pod
    s = SERVICES[svc]
    meta = {"labels": dict(labels)}
    pod = {"containers": [container], "volumes": volumes}
    harden_pod(meta, pod, s.uid, svc, [])
    pod["serviceAccountName"] = "lab-service"
    pod["automountServiceAccountToken"] = False
    pod["enableServiceLinks"] = False
    if caps_add:
        container["securityContext"]["capabilities"]["add"] = list(caps_add)
    req, lim = s.memory
    container["resources"] = {"requests": {"cpu": "50m", "memory": req, "ephemeral-storage": "64Mi"},
                              "limits": {"memory": lim, "ephemeral-storage": "1Gi"}}
    return {"metadata": meta, "spec": pod}


def _scratch(*paths: str) -> tuple[list[dict], list[dict]]:
    vols, mounts = [], []
    for i, p in enumerate(paths):
        vols.append({"name": f"tmp{i}", "emptyDir": {"sizeLimit": "256Mi"}})
        mounts.append({"name": f"tmp{i}", "mountPath": p})
    return vols, mounts


def pvc(name: str, labels: dict, size: str) -> dict:
    """Persistent volume (default StorageClass: k3s local-path, under /var/lib/rancher on the persistent
    partition). Kept when the service is turned off."""
    return {"apiVersion": "v1", "kind": "PersistentVolumeClaim",
            "metadata": {"name": name, "namespace": LAB_NS, "labels": dict(labels)},
            "spec": {"accessModes": ["ReadWriteOnce"], "resources": {"requests": {"storage": size}}}}


def _deployment(name: str, labels: dict, template: dict, checksum: str | None = None) -> dict:
    sel = {k: labels[k] for k in ("app.kubernetes.io/name", LABEL)}
    tpl = copy.deepcopy(template)
    tpl["metadata"]["labels"].update(sel)
    if checksum:
        tpl["metadata"].setdefault("annotations", {})["containerizer.io/config-sha256"] = checksum
    return {"apiVersion": "apps/v1", "kind": "Deployment",
            "metadata": {"name": name, "namespace": LAB_NS, "labels": dict(labels)},
            "spec": {"replicas": 1, "strategy": {"type": "Recreate"}, "revisionHistoryLimit": 2,
                     "selector": {"matchLabels": sel}, "template": tpl}}


def _service(name: str, labels: dict, svc: str) -> dict:
    sel = {k: labels[k] for k in ("app.kubernetes.io/name", LABEL)}
    s = SERVICES[svc]
    return {"apiVersion": "v1", "kind": "Service", "metadata": {"name": name, "namespace": LAB_NS, "labels": dict(labels)},
            "spec": {"selector": sel, "ports": [{"name": "svc", "port": s.svc_port, "targetPort": s.port, "protocol": "TCP"}]}}


def ingress_policy(svc: str, ns: str) -> dict:
    """Lets app namespace `ns` (its own pods only) reach the service's port; nothing else gets in."""
    s = SERVICES[svc]
    labels = {**_labels(svc), APP_LABEL: ns}
    pods = {LABEL: svc} if s.shared else {LABEL: svc, APP_LABEL: ns}
    name = _label(f"{svc}-from-{ns}", f"from/{svc}/{ns}")
    return {"apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name, "namespace": LAB_NS, "labels": labels},
            "spec": {"podSelector": {"matchLabels": pods}, "policyTypes": ["Ingress"],
                     "ingress": [{"from": [{"namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": ns}},
                                            "podSelector": {"matchLabels": {"app.kubernetes.io/part-of": ns}}}],
                                  "ports": [{"port": s.port, "protocol": "TCP"}]}]}}


def admin_secret_name(svc: str) -> str:
    return f"{svc}-admin"


def shared_manifests(svc: str, image: str) -> list[dict]:
    """Server of a shared service: Deployment (one replica, Recreate), Service, data volume. Its admin
    password is the Secret `<svc>-admin` (key `password`), created by the lab agent."""
    s = SERVICES[svc]
    labels = _labels(svc)
    admin = {"valueFrom": {"secretKeyRef": {"name": admin_secret_name(svc), "key": "password"}}}
    if svc == "sqlserver":
        vols, mounts = _scratch("/tmp")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{svc}-data"}})
        mounts.append({"name": "data", "mountPath": "/var/opt/mssql"})
        ready = ["/bin/sh", "-c", 'SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" /opt/mssql-tools18/bin/sqlcmd -C -S localhost '
                                  '-U sa -b -Q "SET NOCOUNT ON; SELECT 1" -o /dev/null']
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             # Developer edition: free for development and test, not licensed for production; lab only
             "env": [{"name": "ACCEPT_EULA", "value": "Y"}, {"name": "MSSQL_PID", "value": "Developer"},
                     {"name": "MSSQL_MEMORY_LIMIT_MB", "value": "2048"},
                     {"name": "MSSQL_AGENT_ENABLED", "value": "false"},
                     {"name": "MSSQL_SA_PASSWORD", **admin}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "startupProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10, "failureThreshold": 60},
             "readinessProbe": {"exec": {"command": ready}, "periodSeconds": 15, "timeoutSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
        # sqlservr carries the file capability cap_net_bind_service; exec needs it in the bounding set
        # (the only capability Pod Security "restricted" allows). With no_new_privs it is never raised.
        tpl = _pod(svc, labels, c, vols, caps_add=["NET_BIND_SERVICE"])
    elif svc == "postgres":
        vols, mounts = _scratch("/tmp", "/var/run/postgresql")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{svc}-data"}})
        mounts.append({"name": "data", "mountPath": "/var/lib/postgresql"})
        ready = ["pg_isready", "-h", "127.0.0.1", "-p", "5432", "-U", "postgres"]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "args": ["postgres", "-c", "listen_addresses=*", "-c", "password_encryption=scram-sha-256",
                      "-c", "log_connections=on", "-c", "log_disconnections=on", "-c", "max_connections=200"],
             "env": [{"name": "POSTGRES_PASSWORD", **admin}, {"name": "POSTGRES_HOST_AUTH_METHOD", "value": "scram-sha-256"},
                     {"name": "POSTGRES_INITDB_ARGS", "value": "--auth-host=scram-sha-256 --auth-local=peer"}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "startupProbe": {"exec": {"command": ready}, "periodSeconds": 5, "failureThreshold": 60},
             "readinessProbe": {"exec": {"command": ready}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
        tpl = _pod(svc, labels, c, vols)
    elif svc == "mysql":
        vols, mounts = _scratch("/tmp", "/var/run/mysqld", "/var/lib/mysql-files")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{svc}-data"}})
        mounts.append({"name": "data", "mountPath": "/var/lib/mysql"})
        ready = ["mysqladmin", "--protocol=tcp", "-h", "127.0.0.1", "ping"]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "args": ["mysqld", "--innodb-buffer-pool-size=256M", "--max-connections=200", "--skip-name-resolve"],
             # root also as root@127.0.0.1 (TCP inside the pod only): the agent provisions over TCP, which
             # the probes already prove, not the socket, which a restarted server may not get back
             "env": [{"name": "MYSQL_ROOT_PASSWORD", **admin}, {"name": "MYSQL_ROOT_HOST", "value": "127.0.0.1"}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "startupProbe": {"exec": {"command": ready}, "periodSeconds": 5, "failureThreshold": 120},
             "readinessProbe": {"exec": {"command": ready}, "periodSeconds": 10, "timeoutSeconds": 5},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
        tpl = _pod(svc, labels, c, vols)
    elif svc == "mongodb":
        vols, mounts = _scratch("/tmp", "/data/configdb")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{svc}-data"}})
        mounts.append({"name": "data", "mountPath": "/data/db"})
        ready = ["mongosh", "--nodb", "--quiet", "--eval",
                 'quit(new Mongo("mongodb://127.0.0.1:27017").getDB("admin").runCommand({ping: 1}).ok ? 0 : 1)']
        # the image's entry point creates the root user on first start and then runs mongod --auth
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "args": ["mongod", "--bind_ip_all", "--wiredTigerCacheSizeGB", "0.25"],
             "env": [{"name": "MONGO_INITDB_ROOT_USERNAME", "value": "root"},
                     {"name": "MONGO_INITDB_ROOT_PASSWORD", **admin}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "startupProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 5, "failureThreshold": 60},
             "readinessProbe": {"exec": {"command": ready}, "periodSeconds": 15, "timeoutSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
        tpl = _pod(svc, labels, c, vols)
    elif svc == "rabbitmq":
        conf = {"apiVersion": "v1", "kind": "ConfigMap",
                "metadata": {"name": f"{svc}-config", "namespace": LAB_NS, "labels": dict(labels)},
                # replaces the image's conf.d, which lets guest/guest in from anywhere
                "data": {"10-lab.conf": "listeners.tcp.default = 5672\nloopback_users.guest = true\n"
                                        "log.console = true\nlog.console.level = info\nlog.file = false\n"}}
        vols, mounts = _scratch("/tmp")
        vols += [{"name": "config", "configMap": {"name": f"{svc}-config"}},
                 {"name": "data", "persistentVolumeClaim": {"claimName": f"{svc}-data"}}]
        mounts += [{"name": "config", "mountPath": "/etc/rabbitmq/conf.d", "readOnly": True},
                   {"name": "data", "mountPath": "/var/lib/rabbitmq"}]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             # a fixed node name: the data directory is named after it and the pod name changes
             "env": [{"name": "RABBITMQ_NODENAME", "value": "rabbit@localhost"}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "startupProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 5, "failureThreshold": 60},
             "readinessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
        tpl = _pod(svc, labels, c, vols)
        checksum = hashlib.sha256(json.dumps(conf["data"], sort_keys=True).encode()).hexdigest()
        return [conf, pvc(f"{svc}-data", labels, s.storage), _deployment(svc, labels, tpl, checksum),
                _service(svc, labels, svc)]
    else:
        raise LabError(f"{svc} is not a shared service")
    return [pvc(f"{svc}-data", labels, s.storage), _deployment(svc, labels, tpl), _service(svc, labels, svc)]


def per_app_manifests(svc: str, ns: str, image: str, cred: dict) -> list[dict]:
    """A per-app instance: its config Secret (built from the app's credentials), Deployment, Service,
    data volume and the ingress policy for its app."""
    s = SERVICES[svc]
    name = instance(svc, ns)
    labels = _labels(svc, ns)
    if svc == "redis":
        # the password only as its SHA-256: the config file holds no secret that works against the server
        digest = hashlib.sha256(cred["password"].encode()).hexdigest()
        conf = ("bind * -::*\nport 6379\nprotected-mode yes\ndir /data\nappendonly yes\nappendfsync everysec\n"
                "save 3600 1 300 100 60 10000\nmaxmemory 200mb\nmaxmemory-policy noeviction\n"
                f"user default on #{digest} ~* &* +@all -@admin\n")
        files = {"redis.conf": conf}
        vols, mounts = _scratch("/tmp")
        vols += [{"name": "config", "secret": {"secretName": name, "defaultMode": 0o440}},
                 {"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}}]
        mounts += [{"name": "config", "mountPath": "/etc/redis", "readOnly": True},
                   {"name": "data", "mountPath": "/data"}]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "command": ["redis-server", "/etc/redis/redis.conf"],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "readinessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    elif svc == "s3":
        files = {"ROOT_ACCESS_KEY_ID": cred["access-key-id"], "ROOT_SECRET_ACCESS_KEY": cred["secret-access-key"]}
        vols, mounts = _scratch("/tmp")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}})
        mounts.append({"name": "data", "mountPath": "/data"})
        env = [{"name": k, "valueFrom": {"secretKeyRef": {"name": name, "key": k}}} for k in sorted(files)]
        # objects under /data/buckets, their metadata in a sidecar directory (no extended attributes needed)
        env += [{"name": "VGW_PORT", "value": ":7070"}, {"name": "VGW_HEALTH", "value": "/health"},
                {"name": "VGW_REGION", "value": "us-east-1"},
                {"name": "VGW_VIRTUAL_DOMAIN", "value": host(svc, ns)},
                {"name": "VGW_META_SIDECAR", "value": "/data/meta"}]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "command": ["/bin/sh", "-c", "mkdir -p /data/buckets /data/meta && exec /usr/local/bin/versitygw posix /data/buckets"],
             "env": env, "ports": [{"name": "svc", "containerPort": s.port}],
             "readinessProbe": {"httpGet": {"path": "/health", "port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    elif svc == "azure-blob":
        # AZURITE_ACCOUNTS replaces the emulator's well-known account: only this app's account exists
        files = {"AZURITE_ACCOUNTS": f"{cred['account-name']}:{cred['account-key']}"}
        vols, mounts = _scratch("/tmp")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}})
        mounts.append({"name": "data", "mountPath": "/data"})
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "command": ["azurite-blob", "--blobHost", "0.0.0.0", "--blobPort", str(s.port), "--location", "/data",
                         "--disableProductStyleUrl", "--disableTelemetry", "--skipApiVersionCheck"],
             "env": [{"name": "AZURITE_ACCOUNTS", "valueFrom": {"secretKeyRef": {"name": name, "key": "AZURITE_ACCOUNTS"}}},
                     {"name": "HOME", "value": "/tmp"}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "readinessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    elif svc == "kafka":
        files = {"server.properties": kafka_properties(ns)}
        vols, mounts = _scratch("/tmp")
        vols += [{"name": "config", "secret": {"secretName": name, "defaultMode": 0o440}},
                 {"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}}]
        mounts += [{"name": "config", "mountPath": "/etc/kafka-lab", "readOnly": True},
                   {"name": "data", "mountPath": "/var/lib/kafka/data"}]
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "command": ["/bin/sh", "-c", "/opt/kafka/bin/kafka-storage.sh format --ignore-formatted "
                         f"--cluster-id {kafka_cluster_id(ns)} --config /etc/kafka-lab/server.properties && "
                         "exec /opt/kafka/bin/kafka-server-start.sh /etc/kafka-lab/server.properties"],
             "env": [{"name": "KAFKA_HEAP_OPTS", "value": "-Xms256m -Xmx384m"}, {"name": "LOG_DIR", "value": "/tmp/logs"}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "startupProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 5, "failureThreshold": 60},
             "readinessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    elif svc == "sftp":
        # SFTPGo with its in-memory user store loaded from this file: one user, the app's
        users = {"users": [{"id": 1, "status": 1, "username": cred["username"], "password": cred["password"],
                            "home_dir": f"/var/lib/sftpgo/data/{cred['username']}", "permissions": {"/": ["*"]}}],
                 "folders": [], "groups": [], "admins": [], "api_keys": [], "shares": [], "event_actions": [],
                 "event_rules": [], "roles": [], "ip_lists": [], "configs": {}, "version": 17}
        files = {"users.json": json.dumps(users, indent=1, sort_keys=True)}
        vols, mounts = _scratch("/tmp")
        vols += [{"name": "config", "secret": {"secretName": name, "defaultMode": 0o440}},
                 {"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}}]
        mounts += [{"name": "config", "mountPath": "/etc/sftpgo-lab", "readOnly": True},
                   {"name": "data", "mountPath": "/var/lib/sftpgo"}]
        env = {"SFTPGO_DATA_PROVIDER__DRIVER": "memory", "SFTPGO_DATA_PROVIDER__NAME": "/etc/sftpgo-lab/users.json",
               "SFTPGO_SFTPD__BINDINGS__0__PORT": str(s.port),
               # no web admin, REST API, WebDAV, FTP or telemetry listener: SFTP only
               "SFTPGO_HTTPD__BINDINGS__0__PORT": "0", "SFTPGO_TELEMETRY__BIND_PORT": "0",
               "SFTPGO_FTPD__BINDINGS__0__PORT": "0", "SFTPGO_WEBDAVD__BINDINGS__0__PORT": "0",
               "SFTPGO_COMMON__DEFENDER__ENABLED": "true", "SFTPGO_LOG_FILE_PATH": ""}
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "command": ["sftpgo", "serve", "--config-dir", "/var/lib/sftpgo"],
             "env": [{"name": k, "value": v} for k, v in sorted(env.items())],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "readinessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    elif svc == "smtp":
        # Mailpit: keeps every message (the newest MAIL_MAX, at most MAIL_MAX_AGE), relays none (no relay or
        # forward configuration), takes any SMTP login or none. Its web UI and API listen on the pod's loopback
        # only: the system agent reads them with kubectl exec (labmail.py); nothing else can reach them.
        files = {}
        vols, mounts = _scratch("/tmp")
        vols.append({"name": "data", "persistentVolumeClaim": {"claimName": f"{name}-data"}})
        mounts.append({"name": "data", "mountPath": "/data"})
        c = {"name": svc, "image": image, "imagePullPolicy": "IfNotPresent",
             "args": ["--smtp", f"0.0.0.0:{s.port}", "--listen", f"127.0.0.1:{MAIL_API_PORT}",
                      "--database", "/data/mailpit.db", "--max", str(MAIL_MAX), "--max-age", MAIL_MAX_AGE,
                      "--smtp-auth-accept-any", "--smtp-auth-allow-insecure", "--smtp-disable-rdns",
                      "--disable-version-check", "--block-remote-css-and-fonts"],
             "env": [{"name": "TMPDIR", "value": "/tmp"}],
             "ports": [{"name": "svc", "containerPort": s.port}],
             "readinessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 10},
             "livenessProbe": {"tcpSocket": {"port": s.port}, "periodSeconds": 30},
             "volumeMounts": mounts}
    else:
        raise LabError(f"{svc} is not a per-app service")
    checksum = hashlib.sha256(json.dumps(files, sort_keys=True).encode()).hexdigest()
    tpl = _pod(svc, labels, c, vols)
    docs = [pvc(f"{name}-data", labels, s.storage), _deployment(name, labels, tpl, checksum),
            _service(name, labels, svc), ingress_policy(svc, ns)]
    if files:
        docs.insert(0, {"apiVersion": "v1", "kind": "Secret",
                        "metadata": {"name": name, "namespace": LAB_NS, "labels": dict(labels)},
                        "type": "Opaque", "stringData": files})
    return docs


def kafka_cluster_id(ns: str) -> str:
    """A fixed KRaft cluster id per app (16 bytes, base64url without padding)."""
    import base64
    return base64.urlsafe_b64encode(hashlib.sha256(f"kafka/{ns}".encode()).digest()[:16]).decode().rstrip("=")


def kafka_properties(ns: str) -> str:
    """One node that is broker and controller. Clients connect without a login: only the app's own
    namespace can reach the instance (NetworkPolicy)."""
    h = host("kafka", ns)
    return "\n".join([
        "process.roles=broker,controller", "node.id=1", "controller.quorum.voters=1@localhost:9093",
        "listeners=PLAINTEXT://:9092,CONTROLLER://localhost:9093", f"advertised.listeners=PLAINTEXT://{h}:9092",
        "controller.listener.names=CONTROLLER", "inter.broker.listener.name=PLAINTEXT",
        "listener.security.protocol.map=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT",
        "log.dirs=/var/lib/kafka/data/logs", "num.partitions=1", "default.replication.factor=1",
        "offsets.topic.replication.factor=1", "transaction.state.log.replication.factor=1",
        "transaction.state.log.min.isr=1", "share.coordinator.state.topic.replication.factor=1",
        "share.coordinator.state.topic.min.isr=1", "group.initial.rebalance.delay.ms=0",
        "auto.create.topics.enable=true", "log.retention.hours=168", "log.segment.bytes=104857600", ""])


# --------------------------------------------------------------------------- credentials and provisioning

_ALNUM = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"


def new_password(length: int = 32) -> str:
    """Letters and digits only (nothing to escape in a connection string or SQL literal), always with
    upper, lower and digit (SQL Server's password policy)."""
    import secrets
    while True:
        p = "".join(secrets.choice(_ALNUM) for _ in range(length))
        if re.search(r"[A-Z]", p) and re.search(r"[a-z]", p) and re.search(r"\d", p):
            return p


SECRET_PARTS = ("password", "access-key-id", "secret-access-key", "account-key")
ADMIN_PASSWORD = ("sqlserver", "postgres", "mysql", "mongodb")      # shared servers with an admin password secret


def new_credentials(svc: str, ns: str, keep: dict | None = None) -> dict:
    """The remote key's properties for an app; secret parts already in `keep` (the store) are kept,
    everything derived from them (connection strings) is built again."""
    import base64
    import secrets
    keep = {k: v for k, v in (keep or {}).items() if k in SECRET_PARTS and isinstance(v, str) and v}
    h, port = host(svc, ns), str(SERVICES[svc].port)
    if svc in ("sqlserver", "postgres", "mysql"):
        cred = {"host": h, "port": port, "database": db_name(ns), "username": db_name(ns),
                "password": keep.get("password") or new_password()}
        return {**cred, "connection-string": connection_string(svc, cred)}
    if svc == "redis":
        cred = {"host": h, "port": port, "password": keep.get("password") or new_password()}
        return {**cred, "connection-string": connection_string(svc, cred)}
    if svc == "s3":
        return {"endpoint": f"http://{h}:{port}", "region": "us-east-1",
                "access-key-id": keep.get("access-key-id") or
                "CZ" + "".join(secrets.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(18)),
                "secret-access-key": keep.get("secret-access-key") or new_password(40)}
    if svc == "mongodb":
        cred = {"host": h, "port": port, "database": db_name(ns), "username": db_name(ns),
                "password": keep.get("password") or new_password()}
        return {**cred, "connection-string": connection_string(svc, cred)}
    if svc == "rabbitmq":
        cred = {"host": h, "port": port, "vhost": ns, "username": db_name(ns),
                "password": keep.get("password") or new_password()}
        return {**cred, "connection-string": connection_string(svc, cred)}
    if svc == "kafka":
        return {"bootstrap-servers": f"{h}:{port}"}
    if svc == "sftp":
        return {"host": h, "port": str(SERVICES[svc].svc_port), "username": db_name(ns),
                "password": keep.get("password") or new_password()}
    if svc == "smtp":
        # no login: the mailbox takes any (or none), and only the app's own namespace can reach it
        return {"host": h, "port": str(SERVICES[svc].svc_port)}
    if svc == "azure-blob":
        account = "lab" + hashlib.sha256(ns.encode()).hexdigest()[:12]
        key = keep.get("account-key") or base64.b64encode(secrets.token_bytes(64)).decode()
        return {"account-name": account, "account-key": key,
                "connection-string": f"DefaultEndpointsProtocol=http;AccountName={account};AccountKey={key};"
                                     f"BlobEndpoint=http://{h}:{port}/{account};"}
    raise LabError(f"unknown lab service {svc!r}")


def _app_name_value(name: str) -> str:
    """A value that needs no quoting in an ADO.NET connection string."""
    return re.sub(r"[^A-Za-z0-9_.-]", "-", str(name))[:128] or "app"


def connection_string(svc: str, c: dict) -> str:
    """ADO.NET (Microsoft.Data.SqlClient, Npgsql) and StackExchange.Redis connection strings. SQL Server
    encrypts with its own certificate; the lab's other traffic stays on the node (see docs)."""
    # Application Name: the app's namespace, so the shared lab server shows whose session it is (sys.dm_exec_sessions,
    # pg_stat_activity); not for MySQL: MySql.Data refuses keywords it does not know
    app = _app_name_value(c.get("app") or c.get("database") or "")
    if svc == "sqlserver":
        return (f"Server={c['host']},{c['port']};Database={c['database']};User Id={c['username']};"
                f"Password={c['password']};Encrypt=True;TrustServerCertificate=True;Application Name={app}")
    if svc == "postgres":
        return (f"Host={c['host']};Port={c['port']};Database={c['database']};Username={c['username']};"
                f"Password={c['password']};Application Name={app}")
    if svc == "mysql":
        # MySQL encrypts with the certificate it made at first start; Required does not check it
        return (f"Server={c['host']};Port={c['port']};Database={c['database']};User ID={c['username']};"
                f"Password={c['password']};SslMode=Required")
    if svc == "redis":
        return f"{c['host']}:{c['port']},password={c['password']},abortConnect=false"
    if svc == "mongodb":
        return f"mongodb://{c['username']}:{c['password']}@{c['host']}:{c['port']}/{c['database']}?authSource={c['database']}"
    if svc == "rabbitmq":
        return f"amqp://{c['username']}:{c['password']}@{c['host']}:{c['port']}/{c['vhost']}"
    raise LabError(f"{svc} has no connection string")


def secret_keys(svc: str) -> list[str]:
    """The keys of Secret lab-<svc> in the app's namespace."""
    return sorted(new_credentials(svc, "app"))


def complete(svc: str, ns: str, cred: dict) -> bool:
    """The stored credentials are whole and match the names this version derives (host, connection
    string): nothing to write."""
    return bool(cred) and new_credentials(svc, ns, cred) == cred


def _safe(v: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_]{1,128}", v):
        raise LabError("unsafe identifier or password")
    return v


def provision_sql(svc: str, ns: str, cred: dict) -> str:
    """Script (on stdin, never arguments) that creates or updates the app's database and login."""
    db, user, pw = _safe(db_name(ns)), _safe(cred["username"]), _safe(cred["password"])
    if svc == "sqlserver":
        return f"""SET NOCOUNT ON;
IF SUSER_ID(N'{user}') IS NULL
BEGIN
    CREATE LOGIN [{user}] WITH PASSWORD = N'{pw}', CHECK_POLICY = ON, CHECK_EXPIRATION = OFF, DEFAULT_DATABASE = [master];
END
ELSE
BEGIN
    ALTER LOGIN [{user}] WITH PASSWORD = N'{pw}';
END
IF DB_ID(N'{db}') IS NULL CREATE DATABASE [{db}];
GO
ALTER AUTHORIZATION ON DATABASE::[{db}] TO [{user}];
ALTER LOGIN [{user}] WITH DEFAULT_DATABASE = [{db}];
DENY VIEW ANY DATABASE TO [{user}];
DENY VIEW SERVER STATE TO [{user}];
GO
"""
    if svc == "postgres":
        return f"""\\set ON_ERROR_STOP on
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
SELECT 'CREATE ROLE "{user}" LOGIN' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '{user}')\\gexec
ALTER ROLE "{user}" WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '{pw}';
SELECT 'CREATE DATABASE "{db}" OWNER "{user}"' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '{db}')\\gexec
ALTER DATABASE "{db}" OWNER TO "{user}";
REVOKE ALL ON DATABASE "{db}" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE "{db}" TO "{user}";
\\connect "{db}"
ALTER SCHEMA public OWNER TO "{user}";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
"""
    if svc == "mysql":
        return f"""CREATE DATABASE IF NOT EXISTS `{db}`;
CREATE USER IF NOT EXISTS '{user}'@'%' IDENTIFIED BY '{pw}';
ALTER USER '{user}'@'%' IDENTIFIED BY '{pw}';
GRANT ALL PRIVILEGES ON `{db}`.* TO '{user}'@'%';
"""
    if svc == "mongodb":
        # mongosh reads this from stdin; the root password stays in the server's environment
        return f"""try {{
  const conn = new Mongo("mongodb://127.0.0.1:27017");
  const admin = conn.getDB("admin");
  admin.auth("root", process.env.MONGO_INITDB_ROOT_PASSWORD);
  const d = conn.getDB("{db}");
  const roles = [{{ role: "dbOwner", db: "{db}" }}];
  if (d.getUser("{user}")) {{ d.updateUser("{user}", {{ pwd: "{pw}", roles: roles }}); }}
  else {{ d.createUser({{ user: "{user}", pwd: "{pw}", roles: roles }}); }}
}} catch (e) {{ print("provisioning failed: " + e.message); quit(1); }}
"""
    if svc == "rabbitmq":
        vhost = _safe_ns(ns)
        # sh -s: printf is a builtin, so the password never is a process argument; every other
        # rabbitmqctl reads /dev/null, not the rest of this script
        return f"""set -e
q() {{ rabbitmqctl -q "$@" </dev/null; }}
if q list_users --no-table-headers | cut -f1 | grep -qx guest; then q delete_user guest; fi
q list_vhosts --no-table-headers | grep -qx '{vhost}' || q add_vhost '{vhost}'
if q list_users --no-table-headers | cut -f1 | grep -qx '{user}'; then
  printf '%s\n' '{pw}' | rabbitmqctl -q change_password '{user}'
else
  printf '%s\n' '{pw}' | rabbitmqctl -q add_user '{user}'
fi
q set_permissions -p '{vhost}' '{user}' '.*' '.*' '.*'
"""
    raise LabError(f"{svc} has no database to provision")


def _safe_ns(v: str) -> str:
    if not NS_RE.fullmatch(v or ""):
        raise LabError("unsafe namespace")
    return v


def provision_command(svc: str) -> list[str]:
    """What the lab agent runs in the server's container (kubectl exec -i), the script on stdin. The
    admin password stays in the container's environment."""
    if svc == "sqlserver":
        return ["/bin/sh", "-c", 'SQLCMDPASSWORD="$MSSQL_SA_PASSWORD" exec /opt/mssql-tools18/bin/sqlcmd -C -S localhost '
                                 '-U sa -b -I -i /dev/stdin']
    if svc == "postgres":
        return ["psql", "-X", "-q", "-U", "postgres", "-d", "postgres", "-f", "-"]
    if svc == "mysql":
        return ["/bin/sh", "-c", 'MYSQL_PWD="$MYSQL_ROOT_PASSWORD" exec mysql -uroot --protocol=tcp -h 127.0.0.1']
    if svc == "mongodb":
        return ["mongosh", "--nodb", "--quiet"]
    if svc == "rabbitmq":
        return ["/bin/sh", "-s"]
    raise LabError(f"{svc} has no database to provision")
