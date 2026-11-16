"""What a failed image build says, in a line or two: the lines of its log that name an error, and the names whose
lookups failed (the appliance's DNS filter refuses every name no egress rule allows; Alpine's apk, for one, then
reports only "DNS: transient error"), so the reason points at Admin -> Firewall instead of Docker's own
"failed to solve ... exit code: 3"."""
from __future__ import annotations

import re

ERROR_RE = re.compile(r"\berror\b|\bexception\b|\bfailed\b|\bfatal\b|\bunable to\b|\bno such\b|could not resolve|"
                      r"name resolution|\bENOTFOUND\b|\bEAI_AGAIN\b", re.I)
# Docker's report of the failed step: says which step, not why
DOCKER_RE = re.compile(r"^(?:#\d+\s+)?(?:ERROR: failed to solve|ERROR: process \"|------|>>>|\d+ \|)")
DNS_FAIL_RE = re.compile(r"DNS: transient error|Temporary failure in name resolution|Could not resolve host|"
                         r"Name or service not known|Name does not resolve|\bENOTFOUND\b|\bEAI_AGAIN\b|no such host|"
                         r"Failed to resolve|failed to resolve|could not resolve|getaddrinfo|Resolving timed out", re.I)
HOST = r"([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+)"
HOST_RES = [re.compile(p, re.I) for p in (
    r"[a-z][a-z0-9+.-]*://(?:[^@/\s]*@)?" + HOST,            # https://dl-cdn.alpinelinux.org/alpine/...
    r"Could not resolve host:?\s*'?" + HOST,                 # curl, git, pip
    r"\blookup\s+" + HOST,                                   # Go: lookup proxy.golang.org on 10.0.0.1:53
    r"\bENOTFOUND\s+" + HOST,                                # npm: getaddrinfo ENOTFOUND registry.npmjs.org
    r"\bresolve\s+(?:host\s+)?'?" + HOST,                    # Failed to resolve 'pypi.org'
    r"\bfor\s+" + HOST + r"(?=[:'\"\s]|$)")]                 # Temporary failure resolving / unknown host for x


def error_lines(log: str, limit: int = 1500) -> str:
    """What a failed build or run says: its lines that name an error (the last ones, about `limit` characters),
    else the end of the log. The end alone is often Docker's own report of the failed step, without the error."""
    lines = [" ".join(l.split()) for l in (log or "").splitlines()]
    errs = [l for l in lines if ERROR_RE.search(l) and not DOCKER_RE.match(l)]
    out = " | ".join(dict.fromkeys(errs))
    return out[-limit:] if errs else " ".join((log or "").split())[-600:]


def unresolved_hosts(log: str) -> list[str]:
    """The names whose lookups failed, from the lines that say a lookup failed."""
    out: list[str] = []
    for line in (log or "").splitlines():
        if not DNS_FAIL_RE.search(line):
            continue
        for rx in HOST_RES:
            for m in rx.finditer(line):
                h = m.group(1).lower().rstrip(".")
                if "." in h and not re.fullmatch(r"[\d.]+", h) and h not in out:
                    out.append(h)
    return out[:10]


def failure_text(log: str, limit: int = 600) -> str:
    """Why a build failed, for a result's reason: the error lines, and a pointer to the firewall for the names whose
    lookups failed."""
    hosts = unresolved_hosts(log)
    hint = (f" · name lookup failed for {', '.join(hosts)}: allow {'it' if len(hosts) == 1 else 'them'} on "
            f"Admin → Firewall if the build needs {'it' if len(hosts) == 1 else 'them'}") if hosts else ""
    return error_lines(log, max(200, limit - len(hint))) + hint
