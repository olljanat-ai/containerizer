"""App updates of the appliance: a patch release (vX.Y.Z, Z > 0) without a new OS image.

A full upgrade downloads the whole OS image, writes it as a new btrfs snapshot and restarts the server: on a
physical server that takes long. Within one release series (vX.Y) the OS does not change: the release workflow
refuses a patch release that touches the OS (appliance/, monitoring/), so a patch release differs from its vX.Y.0
only in the application, the Python code and the rules. For each release the workflow also publishes that part
alone as a small image, ghcr.io/<owner>/containerizer-app:vX.Y.Z, signed by the same workflow identity as the OS
image:

    /app/manifest.json      {"version": "vX.Y.Z", "series": "X.Y", "requirements_sha256": "<sha256 of the lock>"}
    /app/containerizer/     the package
    /app/rules/             the rules (without learned/: those are on the persistent partition)

The system agent (sysagent.py, root) installs one by its verified digest: this module fetches the manifest and
the layers from the registry, checks every digest, unpacks them with tarfile's `data` filter into
/var/lib/containerizer/app-patches/<version>/ (persistent), and the agent checks that the code imports before it
makes it active. The active update is mounted read-only on /run/containerizer/app-patch, which the venv's
containerizer.pth lists before the OS image's own /usr/lib/containerizer/app: Python takes the package from the
first. Only the containerizer services restart; the OS does not.

An update applies only to the series it was built for and only while the OS keeps the same Python packages
(requirements_sha256): after a full upgrade to a new minor or major version it is not mounted any more, and the
OS image's own code runs. That check is made at every start (`sysagent app-patch select`), with the OS image's
own code, so a broken update can always be removed (`sysagent app-patch remove`).
"""
from __future__ import annotations

import hashlib
import io
import json
import re
import shutil
import tarfile
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlencode, urljoin, urlparse

VERSION_RE = re.compile(r"v(\d{1,4})\.(\d{1,4})\.(\d{1,4})")
DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
SHA_RE = re.compile(r"[0-9a-f]{64}")
IMAGE_RE = re.compile(r"[a-z0-9.-]+(:\d{1,5})?(/[a-z0-9._-]+)+")
MANIFEST_TYPES = ("application/vnd.oci.image.manifest.v1+json",
                  "application/vnd.docker.distribution.manifest.v2+json")
INDEX_TYPES = ("application/vnd.oci.image.index.v1+json",
               "application/vnd.docker.distribution.manifest.list.v2+json")
MAX_MANIFEST = 4 * 1024 * 1024
MAX_BLOB = 256 * 1024 * 1024        # the code and rules are a few MB; anything this large is not an app update
MAX_UNPACKED = 512 * 1024 * 1024
KEEP = 2                            # update folders kept: the active one and the one before it


class PatchError(Exception):
    pass


def parse_version(v: str | None) -> tuple[int, int, int] | None:
    m = VERSION_RE.fullmatch(v or "")
    return (int(m[1]), int(m[2]), int(m[3])) if m else None


def series(v: str | None) -> str | None:
    p = parse_version(v)
    return f"{p[0]}.{p[1]}" if p else None


def is_patch_of(version: str | None, os_version: str | None) -> bool:
    """A newer release of the same series as the OS: what an app update can bring."""
    v, o = parse_version(version), parse_version(os_version)
    return bool(v and o and v[:2] == o[:2] and v > o)


def app_image(os_image: str) -> str:
    """ghcr.io/<owner>/containerizer-appliance -> ghcr.io/<owner>/containerizer-app"""
    return os_image.removesuffix("-appliance") + "-app"


# =============================================================================== the manifest

def read_manifest(root: Path) -> dict:
    try:
        m = json.loads((root / "manifest.json").read_text())
    except (OSError, ValueError) as ex:
        raise PatchError(f"no readable manifest.json in {root}: {ex}") from None
    if not isinstance(m, dict):
        raise PatchError("manifest.json is not an object")
    return m


def check_manifest(m: dict, version: str, os_version: str | None, requirements_sha256: str | None) -> None:
    """The update is the version asked for, of the running OS's series, newer than it, for its Python packages."""
    if m.get("version") != version or not parse_version(version):
        raise PatchError(f"the update is {m.get('version')!r}, not {version}")
    if m.get("series") != series(version):
        raise PatchError(f"the update says series {m.get('series')!r}, its version {version}")
    if not is_patch_of(version, os_version):
        raise PatchError(f"{version} is not a newer release of the running OS's series ({os_version or 'unknown'}): "
                         f"that needs a full upgrade")
    if not requirements_sha256:
        raise PatchError("this OS image does not support app updates (no requirements.sha256): use a full upgrade")
    if m.get("requirements_sha256") != requirements_sha256:
        raise PatchError("the update needs other Python packages than this OS image has: use a full upgrade")


def check_tree(root: Path, version: str) -> None:
    init = root / "containerizer" / "__init__.py"
    if not init.is_file() or not (root / "rules").is_dir():
        raise PatchError("the update has no containerizer/ package or no rules/")
    m = re.search(r'^__version__ = "([^"]+)"$', init.read_text(), re.M)
    if not m or f"v{m[1]}" != version:
        raise PatchError(f"containerizer/__init__.py says {m[1] if m else '?'}, the update {version}")


# =============================================================================== the registry

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _default_open(req, timeout):
    return urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout)


class Registry:
    """Just enough of the OCI distribution API to fetch one image by digest, anonymously (a public package)."""

    def __init__(self, image: str, opener=_default_open, timeout: float = 60.0):
        if not IMAGE_RE.fullmatch(image):
            raise PatchError(f"not an image repository: {image!r}")
        self.host, _, self.repo = image.partition("/")
        self.opener, self.timeout, self.token = opener, timeout, None

    def _get(self, url: str, accept: str = "*/*", limit: int = MAX_BLOB, auth: bool = True, hops: int = 5) -> tuple[bytes, dict]:
        headers = {"Accept": accept}
        if auth and self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            with self.opener(urllib.request.Request(url, headers=headers), self.timeout) as r:
                data = r.read(limit + 1)
                hdrs = {k.lower(): v for k, v in r.headers.items()}
        except urllib.error.HTTPError as ex:
            loc = ex.headers.get("Location") if ex.headers else None
            if ex.code in (301, 302, 303, 307, 308) and loc and hops:
                new = urljoin(url, loc)
                if urlparse(new).scheme != "https":
                    raise PatchError(f"redirected to a non-HTTPS address: {new}") from None
                # the blob store's signed address: the registry's token is not sent there
                same = urlparse(new).netloc == self.host
                return self._get(new, accept, limit, auth=auth and same, hops=hops - 1)
            if ex.code == 401 and auth and self.token is None:
                self._login(ex.headers.get("WWW-Authenticate", "") if ex.headers else "")
                return self._get(url, accept, limit, auth, hops)
            raise PatchError(f"{url}: HTTP {ex.code}") from None
        except (urllib.error.URLError, OSError) as ex:
            raise PatchError(f"{url}: {ex}") from None
        if len(data) > limit:
            raise PatchError(f"{url}: larger than {limit} bytes")
        return data, hdrs

    def _login(self, challenge: str) -> None:
        realm = re.search(r'realm="([^"]+)"', challenge)
        service = re.search(r'service="([^"]+)"', challenge)
        url = realm[1] if realm else f"https://{self.host}/token"
        if urlparse(url).scheme != "https":
            raise PatchError(f"not an HTTPS token service: {url}")
        q = {"scope": f"repository:{self.repo}:pull", "service": service[1] if service else self.host}
        data, _ = self._get(f"{url}?{urlencode(q)}", "application/json", 64 * 1024, auth=False)
        try:
            self.token = json.loads(data)["token"]
        except (ValueError, KeyError, TypeError):
            raise PatchError("unexpected answer from the token service") from None

    def blob(self, digest: str, limit: int = MAX_BLOB) -> bytes:
        if not DIGEST_RE.fullmatch(digest or ""):
            raise PatchError(f"not a digest: {digest!r}")
        data, _ = self._get(f"https://{self.host}/v2/{self.repo}/blobs/{digest}", limit=limit)
        _check_digest(data, digest)
        return data

    def manifest(self, digest: str) -> dict:
        """The image manifest of `digest` (an index is followed to its linux/amd64 image), its digest checked."""
        if not DIGEST_RE.fullmatch(digest or ""):
            raise PatchError(f"not a digest: {digest!r}")
        data, _ = self._get(f"https://{self.host}/v2/{self.repo}/manifests/{digest}",
                            ", ".join(MANIFEST_TYPES + INDEX_TYPES), MAX_MANIFEST)
        _check_digest(data, digest)
        try:
            m = json.loads(data)
        except ValueError:
            raise PatchError("the manifest is not JSON") from None
        if m.get("mediaType") in INDEX_TYPES or "manifests" in m:
            for d in m.get("manifests") or []:
                p = d.get("platform") or {}
                if p.get("os") == "linux" and p.get("architecture") == "amd64":
                    return self.manifest(d.get("digest", ""))
            raise PatchError("no linux/amd64 image in the index")
        if not isinstance(m.get("layers"), list) or not m["layers"]:
            raise PatchError("the manifest has no layers")
        return m


def _check_digest(data: bytes, digest: str) -> None:
    if "sha256:" + hashlib.sha256(data).hexdigest() != digest:
        raise PatchError(f"the content does not match {digest}")


# =============================================================================== unpacking

def unpack_layers(layers: list[bytes], dest: Path) -> None:
    """The /app folder of the image's layers, in order, into `dest`. tarfile's `data` filter refuses absolute
    paths, paths and links that leave `dest`, device files and set-uid bits; whiteouts are refused here (the
    image is built FROM scratch: there is nothing below to delete)."""
    dest.mkdir(parents=True)
    total = 0
    for blob in layers:
        try:
            tf = tarfile.open(fileobj=io.BytesIO(blob), mode="r:*")
        except tarfile.TarError as ex:
            raise PatchError(f"a layer is not a tar archive: {ex}") from None
        with tf:
            members = []
            for ti in tf.getmembers():
                name = ti.name[2:] if ti.name.startswith("./") else ti.name
                if Path(name).name.startswith(".wh."):
                    raise PatchError(f"whiteout in an app update: {ti.name}")
                if name == "app" or not name.startswith("app/"):
                    continue
                total += max(ti.size, 0)
                if total > MAX_UNPACKED:
                    raise PatchError("the update unpacks to more than allowed")
                ti.name = name.removeprefix("app/")
                if ti.islnk():
                    ti.linkname = (ti.linkname[2:] if ti.linkname.startswith("./") else ti.linkname).removeprefix("app/")
                members.append(ti)
            try:
                tf.extractall(dest, members=members, filter="data")
            except (tarfile.TarError, OSError) as ex:
                raise PatchError(f"could not unpack the update: {ex}") from None


def fetch(image: str, digest: str, dest: Path, registry: Registry | None = None) -> None:
    """Fetch the verified digest of an app update into `dest` (which must not exist)."""
    reg = registry or Registry(image)
    m = reg.manifest(digest)
    blobs = []
    for layer in m["layers"]:
        size = layer.get("size")
        if not isinstance(size, int) or size > MAX_BLOB:
            raise PatchError(f"layer {layer.get('digest')} is too large ({size})")
        blobs.append(reg.blob(layer.get("digest", ""), limit=size))
    unpack_layers(blobs, dest)


def remove_tree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)
