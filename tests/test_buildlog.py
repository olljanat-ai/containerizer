"""A failed build's reason: the error lines and the names whose lookups failed, not Docker's report of the step."""
from containerizer import buildlog, org

# docker build --progress=plain (stderr) of an Alpine stage whose package index the DNS filter refused
APK_LOG = """#5 [builder 1/7] FROM docker.io/library/python:3.13-alpine
#5 DONE 0.1s
#6 [builder 2/7] RUN apk add --no-cache build-base libxml2-dev libxslt-dev
#6 5.542 WARNING: fetching https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz: DNS: transient error (try again later)
#6 10.55 WARNING: fetching https://dl-cdn.alpinelinux.org/alpine/v3.24/community/x86_64/APKINDEX.tar.gz: DNS: transient error (try again later)
#6 10.55 ERROR: unable to select packages:
#6 10.55   build-base (no such package):
#6 10.55     required by: world[build-base]
#6 10.55   libxml2-dev (no such package):
#6 10.55     required by: world[libxml2-dev]
#6 ERROR: process "/bin/sh -c apk add --no-cache build-base libxml2-dev libxslt-dev" did not complete successfully: exit code: 3
------
 > [builder 2/7] RUN apk add --no-cache build-base libxml2-dev libxslt-dev:
------
Dockerfile:3
--------------------
   1 |     FROM python:3.13-alpine AS builder
   2 |
   3 | >>> RUN apk add --no-cache build-base libxml2-dev libxslt-dev
   4 |
   5 |     WORKDIR /mkdocs
--------------------
ERROR: failed to solve: process "/bin/sh -c apk add --no-cache build-base libxml2-dev libxslt-dev" did not complete successfully: exit code: 3
"""


def test_reason_names_the_error_and_the_refused_name():
    text = buildlog.failure_text(APK_LOG)
    assert "DNS: transient error" in text and "ERROR: unable to select packages" in text and "no such package" in text
    assert "failed to solve" not in text and ">>>" not in text and "WORKDIR" not in text
    assert text.endswith("name lookup failed for dl-cdn.alpinelinux.org: allow it on Admin → Firewall if the build "
                         "needs it")
    assert len(text) <= 600


def test_hosts_of_other_tools_lookup_failures():
    log = "\n".join([
        "npm ERR! request to https://registry.npmjs.org/express failed, reason: getaddrinfo ENOTFOUND registry.npmjs.org",
        "go: downloading x: dial tcp: lookup proxy.golang.org on 10.0.0.1:53: no such host",
        "fatal: unable to access 'https://github.com/acme/x.git/': Could not resolve host: github.com",
        "WARNING: Retrying (Retry(total=4)) after connection broken by 'NameResolutionError(\"<urllib3...>: Failed to "
        "resolve 'pypi.org' ([Errno -3] Temporary failure in name resolution)\")': /simple/flask/",
        "Downloading https://repo.maven.apache.org/maven2/x.pom",          # no failed lookup on this line
    ])
    assert buildlog.unresolved_hosts(log) == ["registry.npmjs.org", "proxy.golang.org", "github.com", "pypi.org"]


def test_a_build_without_failed_lookups_has_no_hint():
    log = "#7 3.1 src/app.ts(4,7): error TS2322: Type 'string' is not assignable to type 'number'.\n" \
          "ERROR: failed to solve: process \"/bin/sh -c npm run build\" did not complete successfully: exit code: 2\n"
    text = buildlog.failure_text(log)
    assert "error TS2322" in text and "Firewall" not in text and "failed to solve" not in text


def test_gate_failure_says_why_the_build_failed():
    comp = {"build_error": APK_LOG[-800:], "build_failure": buildlog.failure_text(APK_LOG)}
    why = org.gate_failure(comp)
    assert why.startswith("image build failed: ") and "dl-cdn.alpinelinux.org" in why
    assert org.gate_failure({"build_error": "x"}) == "image build failed"          # results of an older release


def test_hardened_run_reason_names_the_failing_line():
    """The hardened run (non-root, read-only root file system, no capabilities): the reason says what failed."""
    log = ("INFO  -  Building documentation...\n"
           "ERROR   -  [Errno 30] Read-only file system: '/mkdocs/site'\n"
           "nginx: [emerg] mkdir() \"/var/cache/nginx/client_temp\" failed (30: Read-only file system)\n")
    why = org.gate_failure({"run": {"status": "hardening-failure", "errors": ["Read-only file system"], "log": log}})
    assert why == ("does not run with the hardened pod security context: ERROR - [Errno 30] Read-only file system: "
                   "'/mkdocs/site'")
    assert org.gate_failure({"run": {"status": "hardening-failure"}}) == org.HARDENED_RUN


# npm ci against a private feed that refused the token (the repository's own Dockerfile)
NPM_401_LOG = """#9 [build 5/7] RUN npm ci
#9 5.818 npm error code E401
#9 5.818 npm error Unable to authenticate, your authentication token seems to be invalid.
#9 5.818 npm error To correct this please try logging in again with:
#9 5.818 npm error   npm login
#9 ERROR: process "/bin/sh -c npm ci" did not complete successfully: exit code: 1
ERROR: failed to solve: process "/bin/sh -c npm ci" did not complete successfully: exit code: 1
"""


def test_reason_points_a_refused_sign_in_at_the_package_feeds():
    text = buildlog.failure_text(NPM_401_LOG)
    assert "E401" in text and "Unable to authenticate" in text
    assert "a package feed refused the build's sign-in" in text and "Admin → Source control → Package feeds" in text
    assert "Firewall" not in text and len(text) <= 600
    nuget = ("error NU1301: Unable to load the service index for source "
             "https://pkgs.dev.azure.com/contoso/_packaging/main/nuget/v3/index.json.\n"
             "  Response status code does not indicate success: 401 (Unauthorized).")
    assert buildlog.refused_feeds(nuget) == ["pkgs.dev.azure.com"]
    assert buildlog.refused_feeds(APK_LOG) is None
