"""The appliance's configuration files in the output repository, without their secrets (docs/appliance-admin.md#backup).

The files in /etc/containerizer change only by hand (and a reboot applies them), so they are backed up once per boot:

- `collect()` (root, cz-firstboot at every boot): copies appliance.env, web.env, worker.env, sandbox.env,
  grafana.env, egress.json and network/*.network to /run/containerizer/config-backup with every secret value
  replaced: a setting whose name says it is one (TOKEN, PASSWORD, SECRET, KEY, ...) keeps its name and says whether
  it is set; a password inside a value (connection string, URL) is cut out. secrets/ and tls/ are never read.
- `sync()` (the LLM queue runner, which holds the output repositories' write tokens): commits that folder to
  `.appliance/<appliance name>/config/` of every output repository (cz.OrgScan.OutputRepo), only when it changed since
  the last commit. A dot folder: no organization of any provider has such a name, so it is never an app folder.
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import socket
from pathlib import Path

CONFIG = Path("/etc/containerizer")
STAGE = Path("/run/containerizer/config-backup")
FILES = ("appliance.env", "web.env", "worker.env", "sandbox.env", "grafana.env", "egress.json")
FOLDER = ".appliance"
STATE = "config-backup.json"
NAME_FILE = ".name"
SET, UNSET = "<set: not backed up>", ""
# a setting whose value is a secret, by its name
SECRET_NAME_RE = re.compile(r"TOKEN|PASSWORD|PASSWD|PWD|SECRET|PRIVATE|CREDENTIAL|API_?KEY|(?:^|_)KEY(?:$|_)", re.I)
# a secret inside a value: Password=...; in a connection string, user:password@ in a URL
INLINE_RE = re.compile(r"(?i)\b((?:password|pwd|secret|token|api[_-]?key)\s*=\s*)([^;&\s\"']+)")
USERINFO_RE = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/@\s:]+:[^/@\s]+@")
NETWORK_SECRET_RE = re.compile(r"(?i)^(\s*(?:PrivateKey|PresharedKey|Password|PrivateKeyFile|PresharedKeyFile)\s*=\s*).+$", re.M)


def redact_value(v: str) -> str:
    v = INLINE_RE.sub(lambda m: m[1] + "<redacted>", v)
    return USERINFO_RE.sub(lambda m: m[1] + "<redacted>@", v)


def redact_env(text: str) -> str:
    """An .env file with its secrets replaced; comments and the other settings as they are."""
    out = []
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or "=" not in s:
            out.append(line)
            continue
        k, v = line.split("=", 1)
        name = k.strip().removeprefix("export ").strip()
        if SECRET_NAME_RE.search(name):
            val = v.strip().strip('"').strip("'")
            out.append(f"{k}={SET if val else UNSET}")
        else:
            out.append(f"{k}={redact_value(v)}")
    return "\n".join(out) + ("\n" if text.endswith("\n") or out else "")


def redact_network(text: str) -> str:
    return redact_value(NETWORK_SECRET_RE.sub(lambda m: m[1] + "<redacted>", text))


def redact_json(text: str) -> str:
    """egress.json: no secret in it by design; a value that holds one anyway is redacted."""
    try:
        doc = json.loads(text)
    except ValueError:
        return redact_value(text)

    def walk(x):
        if isinstance(x, dict):
            return {k: (SET if SECRET_NAME_RE.search(str(k)) and v else walk(v)) for k, v in x.items()}
        if isinstance(x, list):
            return [walk(v) for v in x]
        return redact_value(x) if isinstance(x, str) else x
    return json.dumps(walk(doc), indent=1, ensure_ascii=False) + "\n"


def appliance_name(config: Path = CONFIG) -> str:
    """CZ_HOSTNAME of appliance.env, else the machine's name, as a folder name."""
    from .sysagent import read_env
    name = read_env(config / "appliance.env").get("CZ_HOSTNAME") or socket.gethostname() or "appliance"
    return re.sub(r"[^A-Za-z0-9._-]", "-", name.strip().lower()).strip(".-")[:100] or "appliance"


README = """# Configuration of the appliance {name}

Copied from `/etc/containerizer` at its last boot, without secrets: a setting whose value is a secret says only
whether it is set (`{set}`); passwords inside values are `<redacted>`. `secrets/` (generated passwords, the
credential key) and `tls/` are never copied: back them up separately (docs/appliance-admin.md#backup).
"""


def collect(config: Path = CONFIG, stage: Path = STAGE) -> list[str]:
    """Stage the redacted configuration (root, at boot). Returns the files staged."""
    tmp = stage.with_name(stage.name + ".tmp")
    shutil.rmtree(tmp, ignore_errors=True)
    tmp.mkdir(parents=True, mode=0o755)
    done = []

    def put(rel: str, text: str) -> None:
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        p.write_text(text)
        p.chmod(0o644)
        done.append(rel)

    for f in FILES:
        src = config / f
        if src.is_file() and not src.is_symlink():
            text = src.read_text(errors="replace")
            put(f, redact_json(text) if f.endswith(".json") else redact_env(text))
    net = config / "network"
    if net.is_dir():
        for src in sorted(net.glob("*.network")):
            if src.is_file() and not src.is_symlink():
                put(f"network/{src.name}", redact_network(src.read_text(errors="replace")))
    name = appliance_name(config)
    put("README.md", README.format(name=name, set=SET))
    (tmp / NAME_FILE).write_text(name + "\n")
    (tmp / NAME_FILE).chmod(0o644)
    shutil.rmtree(stage, ignore_errors=True)
    tmp.rename(stage)
    stage.chmod(0o755)
    return done


def staged(stage: Path = STAGE) -> tuple[str, dict[str, str]]:
    """(appliance name, {relative path: text}) of the staged configuration; ("", {}) when there is none."""
    if not (stage / NAME_FILE).is_file():
        return "", {}
    name = (stage / NAME_FILE).read_text().strip()
    files = {p.relative_to(stage).as_posix(): p.read_text(errors="replace")
             for p in sorted(stage.rglob("*")) if p.is_file() and p.name != NAME_FILE}
    return name, files


def write_into(root: Path, name: str, files: dict[str, str]) -> Path:
    """Replace .appliance/<name>/config/ of an output repository checkout with the staged files."""
    dest = root / FOLDER / name / "config"
    shutil.rmtree(dest, ignore_errors=True)
    for rel, text in files.items():
        p = dest / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return dest


def sync(connect, key, work: Path, stage: Path = STAGE, log=print) -> int:
    """The queue runner's periodic step: commit the staged configuration to every output repository once it changed
    (work/config-backup.json holds what was committed). Returns the commits made."""
    name, files = staged(stage)
    if not files:
        return 0
    sig = hashlib.sha256(json.dumps([name, sorted(files.items())]).encode()).hexdigest()
    state = work / STATE
    if state.is_file() and state.read_text() == sig:
        return 0
    from .credentials import load, private_key_from_env
    from .org import Output, host_allowed
    from .orgsource import REDACT
    from .variant import _rows, options
    from .worker import allowed_hosts
    conn = connect()
    try:
        scans = _rows(conn, "SELECT * FROM cz.OrgScan WHERE OutputRepo IS NOT NULL ORDER BY ScanId")
        creds = load(conn, key if key is not None else private_key_from_env()) if scans else None
    finally:
        conn.close()
    if not scans:
        return 0
    n, seen, failed = 0, set(), False
    hosts = allowed_hosts() | (creds.hosts() if creds else set())
    for scan in scans:
        repo = scan["OutputRepo"]
        if repo in seen:
            continue
        seen.add(repo)
        write = creds.write_for(repo) if creds else None
        if write is None or not write.token or not host_allowed(repo, hosts):
            log(f"configuration backup: {repo} not updated: no write token for it, or its host is not allowed")
            continue
        REDACT.add(write.token, write.username)
        d = work / f"config-backup-{len(seen)}"
        shutil.rmtree(d, ignore_errors=True)
        try:
            out = Output(options(scan, write, d), d)
            write_into(out.root, name, files)
            if out.commit(f"containerizer: configuration of the appliance {name} (non-secret values, at boot)"):
                n += 1
                log(f"configuration backup: {repo}: {FOLDER}/{name}/config updated")
        except Exception as ex:  # noqa: BLE001 - the repository away: tried again next time
            failed = True
            log(f"configuration backup: {repo}: {REDACT(f'{type(ex).__name__}: {ex}')[:300]}")
        finally:
            shutil.rmtree(d, ignore_errors=True)
    if not failed:
        work.mkdir(parents=True, exist_ok=True)
        state.write_text(sig)
    return n


def main(argv: list[str] | None = None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="python -m containerizer.configbackup",
                                description="stage /etc/containerizer without secrets for the output repository")
    p.add_argument("command", choices=["collect"])
    p.add_argument("--config", default=str(CONFIG))
    p.add_argument("--stage", default=str(STAGE))
    a = p.parse_args(argv)
    files = collect(Path(a.config), Path(a.stage))
    print(f"configuration backup: {len(files)} file(s) staged in {a.stage}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
