"""Build plans and Dockerfiles for Java and Node.js components.

Java: Maven or Gradle (the repository's wrapper) builds the module on the JDK line it targets; the
result runs on distroless Java (17+) or the Temurin JRE (8, 11) as uid 65532: Spring Boot and
other executable jars with `java -jar`, Quarkus' fast-jar, plain programs with their main class and
dependencies on the class path, and WARs without an embedded server on Tomcat.

Node.js: npm, pnpm or yarn install from the lockfile (workspaces at their root), the build script,
dev dependencies pruned, then distroless Node.js runs the start command as uid 65532. A start
command that needs a shell runs on the slim image through the package manager instead.
"""
from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

CA_ENV = "if [ -f /run/secrets/ca ]; then export SSL_CERT_FILE=/run/secrets/ca NODE_EXTRA_CA_CERTS=/run/secrets/ca npm_config_cafile=/run/secrets/ca; fi"
JAVA_DOCS = "https://docs.spring.io/spring-boot/reference/features/external-config.html#features.external-config.typesafe-configuration-properties.relaxed-binding.environment-variables"
NODE_PORT_DOCS = "https://nodejs.org/en/learn/getting-started/nodejs-the-difference-between-development-and-production"


def _images():
    from .generate import images
    return images()


def _rel(p: Path, root: Path) -> str:
    r = str(p.resolve().relative_to(root.resolve())).replace("\\", "/")
    return "" if r == "." else r


def _q(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


# --------------------------------------------------------------------------- Java plan

def java_line(v: str | None, boot: str | None = None) -> int:
    """LTS line for a declared Java version: the same line, or the next LTS above a non-LTS one."""
    lines = sorted(int(x) for x in _images()["java"].get("lines", [8, 11, 17, 21, 25]))
    try:
        want = int(str(v).split(".")[-1] if str(v).startswith("1.") else str(v).split(".")[0])
    except (TypeError, ValueError):
        want = 17 if (boot or "").startswith("2.") else 21
    if want >= 45:
        want -= 44                            # a class file version (61 = Java 17)
    return next((x for x in lines if x >= want), lines[-1])


def _maven_root(repo, p) -> Path:
    """The highest in-repository aggregator whose <modules> chain reaches the module."""
    cur = p.dir.resolve()
    root = repo.root.resolve()
    while cur != root:
        parent = cur.parent
        q = repo.project_by_path(parent / "pom.xml")
        if q is None:
            break
        mods = [(parent / m).resolve() for m in (q.properties.get("Modules") or "").split(",") if m]
        if cur not in mods:
            break
        cur = parent
    return cur


def java_plan(a, c, plan: dict) -> None:
    from .scan_java import _gradle_root
    p, f = c.project, c.facts
    props = p.properties or {}
    root = a.repo.root
    pk = {n for n in p.packages if n not in p.dev_packages}
    plugins = set((props.get("Plugins") or "").split(",")) | set((props.get("ParentPlugins") or "").split(","))
    fw = f.get("java_framework") or "plain"
    tool = props.get("BuildTool", "maven")
    line = java_line(props.get("JavaVersion"), props.get("SpringBootVersion") if props.get("SpringBoot") == "true" else None)
    plan.update({"java": line, "build_tool": tool, "framework": fw, "main_class": props.get("MainClass") or "",
                 "uid": _images()["java"]["app_uid"], "base": "distroless" if line >= 17 else "temurin",
                 "memory": {"request": "512Mi", "limit": "1Gi"}})
    if tool == "maven":
        mroot = _maven_root(a.repo, p)
        plan["build_root"] = _rel(mroot, root)
        plan["module"] = _rel(p.dir, mroot)
        wd = (root / props["WrapperDir"]).resolve() if props.get("WrapperDir") else None
        plan["mvnw"] = _rel(wd / "mvnw", mroot) if wd is not None and (wd / "mvnw").is_relative_to(mroot) else ""
    else:
        sroot = _gradle_root(p.dir, root).resolve()
        wdir = (root / props["WrapperDir"]).resolve() if props.get("WrapperDir") else None
        top = wdir if wdir is not None and sroot.is_relative_to(wdir) else sroot
        if wdir is not None and not wdir.is_relative_to(top):
            wdir = None                       # a wrapper outside the build: use the gradle image
        plan["build_root"] = _rel(top, root)
        plan["module"] = _rel(p.dir, top)
        plan["wrapper"] = (_rel(wdir, top) + "/gradlew").lstrip("/") if wdir is not None else ""
        plan["gradle_root_project"] = p.dir.resolve() == sroot
    # how the application is packaged and started
    packaging = props.get("Packaging", "jar")
    if fw == "quarkus":
        mode = "quarkus"
    elif fw == "spring" and (tool == "gradle" and "org.springframework.boot" in plugins
                             or tool == "maven" and "spring-boot-maven-plugin" in plugins):
        mode = "boot"                         # executable jar or war with the embedded server
    elif packaging == "war":
        mode = "jar" if plan["main_class"] else "tomcat"     # an executable WAR (Jenkins) or a plain one
    elif tool == "gradle" and plugins & {"com.github.johnrengelman.shadow", "com.gradleup.shadow", "io.github.goooler.shadow"}:
        mode = "jar"
    elif plan["main_class"]:
        mode = "classpath"
    else:
        mode = "jar"
    plan["java_mode"] = mode
    plan["packaging"] = packaging
    if tool == "gradle":
        war = packaging == "war"
        plan["gradle_task"] = {"boot": "bootWar" if war else "bootJar", "quarkus": "quarkusBuild", "tomcat": "war",
                               "classpath": "installDist"}.get(mode, "shadowJar" if mode == "jar" and not war and
                                                               plugins & {"com.github.johnrengelman.shadow", "com.gradleup.shadow",
                                                                          "io.github.goooler.shadow"} else "war" if war else "jar")
    if mode == "tomcat":
        api = f.get("servlet_api") or "javax"
        tline = 10 if api == "jakarta" else 9
        jre = {9: [8, 17, 21], 10: [17, 21]}[tline]
        plan["tomcat"] = f"tomcat{tline}_{next((x for x in jre if x >= line), jre[-1])}"
        plan["add_writable"] += ["/usr/local/tomcat/work", "/usr/local/tomcat/temp", "/usr/local/tomcat/logs"]
        from .generate import add_reason
        add_reason(plan, "java-war-tomcat", f"The module is a WAR without an embedded server; it runs as the root web "
                   f"application of Tomcat {'10.1 (jakarta.servlet)' if tline == 10 else '9 (javax.servlet)'}, unpacked at "
                   "build time so the server needs no writable webapps folder.",
                   ["https://tomcat.apache.org/whichversion.html"])
    env = plan["env"]
    env["JAVA_TOOL_OPTIONS"] = "-XX:MaxRAMPercentage=75.0 -XX:+ExitOnOutOfMemoryError"
    if c.role == "web":
        if mode != "tomcat":
            port_env = {"spring": {"SERVER_PORT": "8080"}, "quarkus": {"QUARKUS_HTTP_PORT": "8080", "QUARKUS_HTTP_HOST": "0.0.0.0"},
                        "micronaut": {"MICRONAUT_SERVER_PORT": "8080"},
                        "helidon": {"SERVER_PORT": "8080", "SERVER_HOST": "0.0.0.0"}}.get(fw)
            if port_env:
                env.update(port_env)
            elif f.get("port_env"):
                env["PORT"] = "8080"
            elif f.get("port"):
                plan["port"] = int(f["port"])        # set in code: keep it
        if fw == "spring" and f.get("health"):
            boot = props.get("SpringBootVersion") or ""
            if re.match(r"1\.|2\.[0-2]\.", boot):
                f["health"] = f["readiness"] = None     # no liveness/readiness groups before 2.3
            else:
                env["MANAGEMENT_ENDPOINT_HEALTH_PROBES_ENABLED"] = "true"
        plan["health"] = f.get("health")
        plan["readiness"] = f.get("readiness")
    if plan.get("spa_root") and not plugins & {"frontend-maven-plugin", "com.github.node-gradle.node", "com.moowork.node",
                                               "org.siouan.frontend", "vaadin-maven-plugin", "com.vaadin",
                                               "quarkus-quinoa", "io.quarkiverse.quinoa"} \
            and not any(n.startswith("io.quarkiverse.quinoa:") for n in pk):
        plan["spa_prebuild"] = True
    else:
        plan["spa_root"] = None
    _repoint(plan, f, fw)


def _repoint(plan: dict, facts: dict, style: str) -> None:
    """Windows paths in configuration move under /data through environment variables."""
    from .facts_jvm_node import env_name
    from .generate import add_reason, linux_path
    win = facts.get("windows_paths") or {}
    if not win:
        return
    new = {k: v for k, v in ((k, linux_path(plan, v)) for k, v in sorted(win.items())) if v}
    if not new:
        return
    if style == "node-config":
        tree: dict = {}
        for k, v in new.items():
            cur = tree
            parts = k.split(".")
            for x in parts[:-1]:
                cur = cur.setdefault(x, {})
            cur[parts[-1]] = v
        plan["env"]["NODE_CONFIG"] = json.dumps(tree, separators=(",", ":"), sort_keys=True)
        refs = ["https://github.com/node-config/node-config/wiki/Environment-Variables#node_config"]
    else:
        for k, v in new.items():
            plan["env"][env_name(k, style)] = v
        refs = [JAVA_DOCS if style == "spring" else "https://quarkus.io/guides/config-reference#environment-variables"
                if style == "quarkus" else "https://docs.micronaut.io/latest/guide/#propertySource"
                if style == "micronaut" else "https://download.eclipse.org/microprofile/microprofile-config-3.1/microprofile-config-spec-3.1.html#default_configsources.env.mapping"]
    add_reason(plan, "config-windows-paths", "Windows paths in configuration (drive letters, UNC shares) are overridden "
               "with environment variables to folders under /data, which the manifests mount as volumes; the "
               "application code is not changed.", refs)


# --------------------------------------------------------------------------- Java Dockerfile

JAVA_PROXY = ('hp=""; if [ -n "${HTTPS_PROXY:-$https_proxy}" ]; then hp="${HTTPS_PROXY:-$https_proxy}"; hp="${hp#*://}"; hp="${hp#*@}"; '
              'hp="${hp%%/*}"; export JAVA_TOOL_OPTIONS="-Dhttps.proxyHost=${hp%:*} -Dhttps.proxyPort=${hp##*:} '
              '-Dhttp.proxyHost=${hp%:*} -Dhttp.proxyPort=${hp##*:} -Dhttp.nonProxyHosts=localhost|127.0.0.1"; fi')
# Maven's resolver does not read the JVM proxy properties: a global settings file carries the proxy
MAVEN_PROXY = ('if [ -n "${hp:-}" ]; then printf \'<settings><proxies><proxy><id>https</id><protocol>https</protocol>'
               '<host>%s</host><port>%s</port><nonProxyHosts>localhost|127.0.0.1</nonProxyHosts></proxy><proxy><id>http</id>'
               '<protocol>http</protocol><host>%s</host><port>%s</port><nonProxyHosts>localhost|127.0.0.1</nonProxyHosts>'
               '</proxy></proxies></settings>\' "${hp%:*}" "${hp##*:}" "${hp%:*}" "${hp##*:}" > /tmp/cz-proxy.xml; '
               'set -- -gs /tmp/cz-proxy.xml; fi')
JAVA_CA = ("if [ -f /run/secrets/ca ]; then ks=$(find \"$JAVA_HOME\" -name cacerts | head -1); "
           "awk '/BEGIN CERT/{n++} n{print > (\"/tmp/ca-\" n \".pem\")}' /run/secrets/ca; "
           "for f in /tmp/ca-*.pem; do keytool -importcert -noprompt -keystore \"$ks\" -storepass changeit "
           "-alias \"cz-$(basename \"$f\" .pem)\" -file \"$f\" >/dev/null 2>&1 || true; done; rm -f /tmp/ca-*.pem; fi")
JAR_PICK = ("f=$(ls -S {d}/*.{ext} 2>/dev/null | grep -Ev -- '-(sources|javadoc|tests|test-fixtures|plain)\\.{ext}$|/original-[^/]*$' "
            "| head -1); [ -n \"$f\" ] || {{ echo \"containerizer: no .{ext} was built in {d}\" >&2; exit 1; }}")


def dockerfile_java(plan: dict) -> str:
    from .generate import _writable_abs, reason_comments
    im = _images()["java"]
    line, tool, mode = java_line(str(plan["java"])), plan["build_tool"], plan["java_mode"]
    uid = im["app_uid"]
    root, mod = plan.get("build_root") or "", plan.get("module") or ""
    mdir = mod or "."
    build_img = im[f"maven_{line}"] if tool == "maven" or plan.get("wrapper") else im["gradle"]
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} ({plan['role']}, Java {line}, {tool}, {mode})",
             *reason_comments(plan),
             f"FROM {build_img} AS build"]
    if plan.get("spa_prebuild"):
        node = _images()["node"]["build"]
        lines += [f"COPY --from={node} /usr/local/bin/node /usr/local/bin/node",
                  f"COPY --from={node} /usr/local/lib/node_modules /usr/local/lib/node_modules",
                  "RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm"]
    lines += ["WORKDIR /src", f"COPY {root + '/' if root else '.'} ."]
    for fn in plan["remove_files"]:
        lines.append(f"RUN find . -name '{fn}' -not -path '*/node_modules/*' -delete")
    lines += ["# optional build secret 'ca': CA bundle for TLS-inspecting corporate proxies (added to the build JDK only)",
              "RUN --mount=type=secret,id=ca,required=false \\", f"    {JAVA_CA}"]
    if plan.get("spa_prebuild"):
        spa = str(PurePosixPath(mdir) / plan["spa_root"])
        lines += ["RUN --mount=type=secret,id=ca,required=false \\", f"    {CA_ENV}; \\",
                  f"    cd {_q(spa)} && if [ -f package-lock.json ]; then npm ci; else npm install; fi && npm run build"]
    extra = " ".join(plan["publish_args"])
    if tool == "maven":
        goals = "package" + (" dependency:copy-dependencies -DincludeScope=runtime -DoutputDirectory=target/cz-lib"
                             if mode == "classpath" else "")
        sel = f" -pl {_q(mod)} -am" if mod else ""
        mvn = f"sh ./{plan['mvnw']}" if plan.get("maven_wrapper") and plan.get("mvnw") else "mvn"
        cmd = f"{MAVEN_PROXY}; \\\n    {mvn} -B -ntp \"$@\" -DskipTests{sel} {extra} {goals}".replace("  ", " ")
        cache = "/root/.m2"
        out = f"{mdir}/target"
    else:
        import posixpath
        task = (":" if plan.get("gradle_root_project") else "") + plan["gradle_task"]
        gw = posixpath.relpath(plan["wrapper"], mdir) if plan.get("wrapper") else "gradle"
        gw = "gradle" if gw == "gradle" else f"sh {gw}"      # sh: a wrapper committed without the executable bit
        run = (f"cd {_q(mod)} && " if mod else "") + f"{gw} --no-daemon -x test {extra} {task}"
        cmd = run.replace("  ", " ")
        cache = "/root/.gradle"
        out = f"{mdir}/build/libs"
    if plan.get("build_env"):
        lines.append("ENV " + " ".join(f"{k}={json.dumps(str(v))}" for k, v in sorted(plan["build_env"].items())))
    lines += ["RUN --mount=type=cache,target=" + cache + " --mount=type=secret,id=ca,required=false \\",
              f"    {JAVA_PROXY}; \\", f"    {cmd}"]
    collect = ["mkdir -p /out"]
    if mode == "quarkus":
        qd = f"{mdir}/target/quarkus-app" if tool == "maven" else f"{mdir}/build/quarkus-app"
        collect.append(f"cp -r {_q(qd)} /out/quarkus-app")
        entry = ["java", "-jar", "/app/quarkus-app/quarkus-run.jar"]
    elif mode == "classpath" and tool == "gradle":
        collect.append(f"cp -r {mdir}/build/install/*/lib /out/lib")
        entry = ["java", "-cp", "/app/lib/*", plan["main_class"]]
    elif mode == "classpath":
        collect += [JAR_PICK.format(d=out, ext="jar"), 'cp "$f" /out/app.jar', f"cp -r {_q(out + '/cz-lib')} /out/lib"]
        entry = ["java", "-cp", "/app/app.jar:/app/lib/*", plan["main_class"]]
    elif mode == "tomcat":
        out = out if tool == "maven" else f"{mdir}/build/libs"
        collect += [JAR_PICK.format(d=out, ext="war"), "mkdir -p /out/ROOT", 'cd /out/ROOT && jar xf "$f"']
        entry = []
    else:
        ext = "war" if plan.get("packaging") == "war" else "jar"
        collect += [JAR_PICK.format(d=out, ext=ext), f'cp "$f" /out/app.{ext}']
        entry = ["java", "-jar", f"/app/app.{ext}"]
    lines.append("RUN " + " \\\n && ".join(collect))
    writable = sorted({_writable_abs(w) for w in plan["add_writable"]})
    if writable:
        lines.append("RUN mkdir -p " + " ".join("/writable" + w for w in writable))
    if mode == "tomcat":
        lines += ["", f"FROM {im[plan['tomcat']]} AS final",
                  "# the application stays owned by root: read-only for the app user",
                  "COPY --from=build /out/ROOT /usr/local/tomcat/webapps/ROOT"]
    else:
        lines += ["", f"FROM {im[f'runtime_{line}']} AS final", "WORKDIR /app",
                  "# application files stay owned by root: read-only for the app user",
                  "COPY --from=build /out/ /app/"]
    for w in writable:
        lines.append(f"COPY --from=build --chown={uid}:{uid} /writable{w} {w}")
    env = dict(plan["env"])
    if env:
        lines.append("ENV " + " \\\n    ".join(f"{k}={json.dumps(v)}" for k, v in sorted(env.items())))
    lines.append(f"USER {uid}")
    if plan.get("port"):
        lines.append(f"EXPOSE {plan['port']}")
    if entry:
        lines.append("ENTRYPOINT " + json.dumps(entry + plan["args"]))
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- Node.js plan

RESOLVE_BIN = r"""// prints the file a package's command line ("bin") runs, searching node_modules up from the cwd
const fs = require('fs'), path = require('path');
const bin = process.argv[2];
for (let d = process.cwd(); ; d = path.dirname(d)) {
  const nm = path.join(d, 'node_modules');
  if (fs.existsSync(nm)) {
    for (const n of fs.readdirSync(nm)) {
      const names = n.startsWith('@') ? fs.readdirSync(path.join(nm, n)).map(x => n + '/' + x) : [n];
      for (const name of names) {
        try {
          const pj = JSON.parse(fs.readFileSync(path.join(nm, name, 'package.json'), 'utf8'));
          const b = typeof pj.bin === 'string' ? { [String(pj.name).split('/').pop()]: pj.bin } : (pj.bin || {});
          if (b[bin]) { console.log(fs.realpathSync(path.join(nm, name, b[bin]))); process.exit(0); }
        } catch (e) { /* not a package */ }
      }
    }
  }
  if (path.dirname(d) === d) break;
}
console.error(`containerizer: no installed package provides the command '${bin}'`);
process.exit(1);
"""


def node_line(props: dict) -> int:
    lines = sorted(int(x) for x in _images()["node"].get("server_lines", [22, 24]))
    mx = props.get("NodeEngineMax")
    if mx and mx.isdigit():
        return next((x for x in reversed(lines) if x <= int(mx)), lines[0])
    return lines[-1]


def _topo_deps(repo, p) -> list:
    """In-repository Node.js packages the project uses, dependencies first."""
    out, seen = [], set()

    def visit(q):
        for r in q.project_refs:
            d = repo.project_by_path(r)
            if d is None or d.kind_hint != "node" or d.path in seen:
                continue
            seen.add(d.path)
            visit(d)
            out.append(d)
    visit(p)
    return out


def node_build_plan(a, c, plan: dict) -> None:
    """Install and build steps (servers and single-page apps alike)."""
    from .generate import add_reason
    p = c.project
    props = p.properties or {}
    root = a.repo.root
    line = node_line(props)
    lock = props.get("Lockfile") or ""
    pm = props.get("PackageManager") or "npm"
    if pm not in ("npm", "pnpm", "yarn"):
        add_reason(plan, "node-package-manager", f"{pm} is not supported by the generator; npm installs the "
                   "dependencies from package.json without a lockfile.")
        pm, lock = "npm", ""
    lock_dir = (root / lock).parent.resolve() if lock else None
    if lock_dir and not p.dir.resolve().is_relative_to(lock_dir):
        lock_dir = None
    ws = props.get("WorkspaceRoot")
    ws_dir = (root / ws).parent.resolve() if ws else None
    install = lock_dir or ws_dir or p.dir.resolve()
    if ws_dir and ws_dir != install and ws_dir.is_relative_to(root.resolve()) and install.is_relative_to(ws_dir):
        install = ws_dir
    berry = pm == "yarn" and ((props.get("PackageManagerVersion") or "1").split(".")[0] not in ("", "0", "1")
                              or (install / ".yarnrc.yml").exists())
    # without a packageManager field corepack takes the newest pnpm, which cannot read lockfiles of
    # older majors (ERR_PNPM_BROKEN_LOCKFILE): lockfile 5.x is pnpm 7, 6.0 is pnpm 8
    pm_pin = ""
    if pm == "pnpm" and lock and not props.get("PackageManagerVersion"):
        try:
            with open(root / lock, encoding="utf-8", errors="replace") as fh:
                m = re.match(r"\s*lockfileVersion:\s*'?(\d+)", fh.readline())
        except OSError:
            m = None
        major = {5: "7", 6: "8"}.get(int(m.group(1))) if m else None
        if major:
            pm_pin = f"pnpm@{major}"
            add_reason(plan, "node-pnpm-version", f"The lockfile was written by pnpm {major} (lockfileVersion "
                       f"{m.group(1)}) and package.json names no packageManager; the build uses pnpm {major}, as "
                       "newer pnpm cannot read it.", ["https://pnpm.io/npmrc#lockfile-version"])
    plan.update({"node": line, "pm": pm, "yarn_berry": berry, "pm_pin": pm_pin, "lockfile": bool(lock), "uid": _images()["node"]["app_uid"],
                 "build_root": _rel(install, root), "module": _rel(p.dir, install), "base": "distroless",
                 "workspace": install != p.dir.resolve() or bool(props.get("Workspaces"))})
    if not lock:
        add_reason(plan, "node-no-lockfile", "There is no lockfile: dependency versions are resolved at build time "
                   "and can change between builds. Commit package-lock.json (or the pnpm/yarn lockfile).",
                   ["https://docs.npmjs.com/cli/configuring-npm/package-lock-json"])
    runtime = {n for n in p.packages if n not in p.dev_packages}
    from .confidence import NODE_NATIVE
    plan["native_build"] = bool(props.get("LockNativeBuild")) or bool(runtime & NODE_NATIVE)
    # build steps: in-repository dependencies first, then the package itself
    steps = []
    for d in _topo_deps(a.repo, p):
        if (d.manifest.get("scripts") or {}).get("build") and d.dir.resolve().is_relative_to(install):
            steps.append(_rel(d.dir, install))
    if (p.manifest.get("scripts") or {}).get("build"):
        steps.append(plan["module"])
    plan["build_steps"] = steps
    plan["package_name"] = p.name if (p.manifest or {}).get("name") else ""


def node_plan(a, c, plan: dict) -> None:
    from .generate import add_reason
    node_build_plan(a, c, plan)
    p, f = c.project, c.facts
    pm = plan["pm"]
    runtime = {n for n in p.packages if n not in p.dev_packages}
    # start command
    st = f.get("node_start") or {}
    argv = list(st.get("argv") or [])
    env = plan["env"]
    env["NODE_ENV"] = "production"
    for k, v in (st.get("env") or {}).items():
        env.setdefault(k, v)
    if st.get("pre"):
        add_reason(plan, "node-start-pre-steps", "The start script also runs `" + " && ".join(st["pre"]) + "` before the "
                   "server. The image starts the server only: run those steps (migrations, builds) as a Kubernetes Job "
                   "or init container, or at build time.")
    if argv and argv[0] == "node":
        plan["node_entry"] = argv[1:]
        # packages loaded by node itself (--import=tsx, -r ts-node/register) must survive pruning
        loaded = []
        for i, x in enumerate(argv[1:], 1):
            m = re.match(r"--(?:import|require|loader|experimental-loader)=(.+)", x)
            if m:
                loaded.append(m.group(1))
            elif x in ("-r", "--require", "--import", "--loader", "--experimental-loader") and i + 1 < len(argv):
                loaded.append(argv[i + 1])
        dev = [m for m in loaded if not m.startswith(".") and
               re.sub(r"^(@[^/]+/[^/]+|[^/]+).*$", r"\1", m) in p.dev_packages]
        if dev:
            plan["prune"] = False
            add_reason(plan, "node-start-dev-dependency", f"The start command loads `{dev[0]}`, a development "
                       "dependency, so the image keeps devDependencies. Compile at build time, or move it to dependencies.")
        if st.get("default"):
            add_reason(plan, "node-default-start", f"package.json has no production start script; the image runs "
                       f"`node {argv[-1]}` (npm's default start command is `node server.js`, a package's entry point "
                       "is its main file, index.js by default).",
                       ["https://docs.npmjs.com/cli/using-npm/scripts#default-values"])
    elif argv:
        plan["node_bin"] = argv[0]
        plan["node_entry"] = [".containerizer-start.js"] + argv[1:]
        if argv[0] in p.dev_packages or argv[0] in {"ts-node", "tsx", "babel-node"} and argv[0] not in runtime:
            plan["prune"] = False
            add_reason(plan, "node-start-dev-dependency", f"The start command runs `{argv[0]}`, a development "
                       "dependency, so the image keeps devDependencies. Compile at build time and start with node.")
    elif st.get("shell") or st.get("script"):
        plan["base"] = "slim"
        plan["node_script"] = st.get("script") or "start"
        why = ("is a development command (watch mode or dev server)" if st.get("dev") else "needs a shell")
        add_reason(plan, "node-start-shell", f"The start script `{st.get('shell')}` {why}; the image runs it with "
                   "`npm run` on the slim Node.js image instead of distroless.")
    plan.setdefault("prune", True)
    if plan["prune"] and (pm == "yarn" or pm == "pnpm" and plan["workspace"]):
        plan["prune"] = False
        add_reason(plan, "node-keep-dev-dependencies", f"{pm}{' workspaces' if pm == 'pnpm' else ''} cannot remove "
                   "devDependencies in place without reinstalling (which drops generated files such as the Prisma "
                   "client), so the image keeps them.")
    # port: the frameworks and most servers read $PORT; a fixed port in code or on the command line is kept
    if c.role == "web":
        flag = next((argv[i + 1] for i, x in enumerate(argv[:-1]) if x in ("-p", "--port")), None)
        if flag and flag.isdigit():
            plan["port"] = int(flag)
        elif f.get("port_env") or not f.get("port") or f.get("port_source") != "code":
            env["PORT"] = "8080"
        else:
            plan["port"] = int(f["port"])
        env.setdefault("HOST", "0.0.0.0")
        if "next" in runtime:
            env["HOSTNAME"] = "0.0.0.0"         # Next.js standalone server
            plan["add_writable"].append(f"/app/{plan['module'] + '/' if plan['module'] else ''}.next/cache")
        h = f.get("health")
        plan["health"] = ("/" + h.lstrip("/")) if h else None
    if plan["base"] == "slim":
        env.update({"HOME": "/tmp", "npm_config_cache": "/tmp/.npm", "npm_config_update_notifier": "false"})
    _repoint(plan, f, "node-config")


def node_buildable(c) -> bool:
    st = c.facts.get("node_start")
    return bool(st) or c.role in ("console", "worker") and bool((c.project.manifest or {}).get("main"))


# --------------------------------------------------------------------------- Node.js Dockerfile

def _install_cmd(plan: dict) -> str:
    pm, lock = plan["pm"], plan["lockfile"]
    if pm == "pnpm":
        pin = f" && corepack install -g {plan['pm_pin']}" if plan.get("pm_pin") else ""
        return f"corepack enable{pin} && pnpm install " + ("--frozen-lockfile" if lock else "--no-frozen-lockfile")
    if pm == "yarn":
        if plan["yarn_berry"]:
            return "corepack enable && yarn install" + (" --immutable" if lock else " --no-immutable")
        return ("corepack enable && yarn install" + (" --frozen-lockfile" if lock else "")
                + " --ignore-engines --network-timeout 600000")
    return "npm ci --no-audit --no-fund" if plan["lockfile"] else "npm install --no-audit --no-fund"


def _build_lines(plan: dict) -> list[str]:
    """The build scripts: in-repository dependencies first (pnpm orders a filtered run itself)."""
    steps = plan.get("build_steps") or []
    if not steps:
        return []
    pm = plan["pm"]
    if pm == "pnpm" and plan.get("workspace") and plan.get("package_name"):
        cmds = [f"pnpm --filter {_q(plan['package_name'] + '...')} run build"]
    else:
        run = {"npm": "npm run", "pnpm": "pnpm run", "yarn": "yarn run"}[pm]
        cmds = [(f"(cd {_q(st)} && {run} build)" if st else f"{run} build") for st in steps]
    return [f"RUN --mount=type=secret,id=ca,required=false {CA_ENV}; \\",
            "    export NODE_ENV=production; \\", "    " + " \\\n && ".join(cmds)]


def node_build_stage(plan: dict) -> list[str]:
    """FROM ... AS build: the toolchain, the dependencies from the lockfile and the build scripts."""
    im = _images()["node"]
    line, root = plan["node"], plan.get("build_root") or ""
    native = plan.get("native_build")
    lines = [*(["# native addons compile at install time: the full image has Python, make and g++"] if native else []),
             f"FROM {im[f'server_build_native_{line}' if native else f'server_build_{line}']} AS build"]
    lines += ["WORKDIR /src", f"COPY {root + '/' if root else '.'} ."]
    for fn in plan["remove_files"]:
        lines.append(f"RUN find . -name '{fn}' -not -path '*/node_modules/*' -delete")
    envb = ["COREPACK_ENABLE_DOWNLOAD_PROMPT=0", "CI=true"] + (["YARN_NODE_LINKER=node-modules"] if plan.get("yarn_berry") else []) \
        + [f"{k}={json.dumps(str(v))}" for k, v in sorted((plan.get("build_env") or {}).items())]
    lines.append("ENV " + " ".join(envb))
    mounts = ("--mount=type=cache,target=/root/.npm --mount=type=cache,target=/root/.local/share/pnpm/store "
              "--mount=type=secret,id=ca,required=false")      # corepack's own home stays in the layer: it holds the pinned version
    lines += ["# optional build secret 'ca': CA bundle for TLS-inspecting corporate proxies",
              f"RUN {mounts} \\", f"    {CA_ENV}; \\", f"    {_install_cmd(plan)}"]
    return lines + _build_lines(plan)


def dockerfile_node(plan: dict) -> str:
    from .generate import _writable_abs, reason_comments
    im = _images()["node"]
    line, pm, uid = plan["node"], plan["pm"], im["app_uid"]
    mod = plan.get("module") or ""
    mdir = mod or "."
    lines = ["# syntax=docker/dockerfile:1.7",
             f"# Generated by containerizer for {plan['component']} ({plan['role']}, Node.js {line}, {pm})",
             *reason_comments(plan), *node_build_stage(plan)]
    if plan.get("prune"):
        lines.append("RUN npm prune --omit=dev --no-audit --no-fund" if pm == "npm" else "RUN pnpm prune --prod")
    if plan.get("node_bin"):
        lines.append("COPY <<'EOF' /usr/local/lib/containerizer-resolve-bin.cjs\n" + RESOLVE_BIN + "EOF")
        cd = f"cd {_q(mod)} && " if mod else ""
        lines += [f"RUN {cd}f=$(node /usr/local/lib/containerizer-resolve-bin.cjs {_q(plan['node_bin'])}) \\",
                  ' && ln -s "$(realpath --relative-to=. "$f")" .containerizer-start.js']
    writable = sorted({_writable_abs(w) for w in plan["add_writable"]})
    if writable:
        lines.append("RUN mkdir -p " + " ".join("/writable" + w for w in writable))
    workdir = "/app" + (f"/{mod}" if mod else "")
    slim = plan.get("base") == "slim"
    lines += ["", f"FROM {im[f'server_slim_{line}' if slim else f'server_runtime_{line}']} AS final"]
    lines += [f"WORKDIR {workdir}", "# application files stay owned by root: read-only for the app user",
              "COPY --from=build /src /app"]
    for w in writable:
        lines.append(f"COPY --from=build --chown={uid}:{uid} /writable{w} {w}")
    env = dict(plan["env"])
    if env:
        lines.append("ENV " + " \\\n    ".join(f"{k}={json.dumps(v)}" for k, v in sorted(env.items())))
    lines.append(f"USER {uid}")
    if plan.get("port"):
        lines.append(f"EXPOSE {plan['port']}")
    if slim:
        # npm runs any package.json script, whichever package manager installed the dependencies
        lines.append("ENTRYPOINT " + json.dumps(["npm", "run", plan.get("node_script") or "start"] + plan["args"]))
    else:
        lines.append("ENTRYPOINT " + json.dumps(["/nodejs/bin/node"] + list(plan.get("node_entry") or []) + plan["args"]))
    return "\n".join(lines) + "\n"
