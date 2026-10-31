"""Java and Node.js: build plans, Dockerfiles, manifests and the facts behind them."""
import json

import yaml

from containerizer.assess import assess
from containerizer.facts_jvm_node import env_name, java_config, node_start
from containerizer.generate import buildable, dockerfile_for, generate_app, k8s_manifests, make_plan
from containerizer.gen_jvm_node import java_line
from containerizer.verify import diagnose, load_failures
from tests.test_engine import write
from tests.test_java_node import BOOT_APP, BOOT_PARENT, BOOT_PLUGIN, EXPRESS, SERVER, WEB, boot_app, comp, dep, node, pom


def plan_and_df(root, name):
    a = assess(root)
    c = comp(a, name)
    plan = make_plan(a, c)
    return a, c, plan, dockerfile_for(plan, c)


# ------------------------------------------------------------------ Java

def test_spring_boot_maven_dockerfile(tmp_path):
    boot_app(tmp_path, WEB + dep("org.springframework.boot", "spring-boot-starter-actuator") + dep("org.postgresql", "postgresql"))
    write(tmp_path, "src/main/resources/application.properties",
          "server.port=9000\nspring.datasource.url=jdbc:postgresql://db:5432/orders\nspring.datasource.password=${DB_PASSWORD}\n"
          "app.export-dir=D:\\\\Exports\\\\Orders\n")
    a, c, plan, df = plan_and_df(tmp_path, "orders")
    assert buildable(c)
    assert plan["java"] == 17 and plan["java_mode"] == "boot" and plan["uid"] == 65532
    assert "FROM maven:3.9" in df and "eclipse-temurin-17 AS build" in df
    assert "mvn -B -ntp" in df and "-DskipTests" in df and " -pl " not in df     # a single module
    assert "FROM gcr.io/distroless/java17-debian12:nonroot AS final" in df
    assert 'ENTRYPOINT ["java", "-jar", "/app/app.jar"]' in df and "USER 65532" in df
    # Spring relaxed binding overrides: port, the Windows folder; health groups of the actuator
    assert plan["env"]["SERVER_PORT"] == "8080"
    assert plan["env"]["APP_EXPORTDIR"] == "/data/exports/orders"
    assert plan["health"] == "/actuator/health/liveness" and plan["readiness"] == "/actuator/health/readiness"
    assert plan["env"]["MANAGEMENT_ENDPOINT_HEALTH_PROBES_ENABLED"] == "true"
    # credentials are Secret references: the placeholder's variable, or the relaxed-binding name
    assert set(c.facts["secret_settings"]) == {"DB_PASSWORD", "SPRING_DATASOURCE_URL"}
    docs = k8s_manifests(a, c, plan, "registry.local/x:1")
    dep_doc = next(d for d in docs if d["kind"] == "Deployment")
    pod = dep_doc["spec"]["template"]["spec"]
    ct = pod["containers"][0]
    assert pod["securityContext"]["fsGroup"] == 65532
    assert ct["readinessProbe"]["httpGet"]["path"] == "/actuator/health/readiness"
    assert ct["livenessProbe"]["httpGet"]["path"] == "/actuator/health/liveness"
    assert ct["resources"]["limits"]["memory"] == "1Gi"
    refs = {e["name"] for e in ct["env"] if "valueFrom" in e}
    assert {"DB_PASSWORD", "SPRING_DATASOURCE_URL"} <= refs


def test_secured_actuator_is_probed_over_tcp(tmp_path):
    boot_app(tmp_path, WEB + dep("org.springframework.boot", "spring-boot-starter-actuator")
             + dep("org.springframework.boot", "spring-boot-starter-security"))
    _, _, plan, _ = plan_and_df(tmp_path, "orders")
    assert plan["health"] is None          # a 401 would fail every probe


def test_maven_module_is_built_with_its_reactor(tmp_path):
    write(tmp_path, "pom.xml", pom("parent", packaging="pom", modules="<module>common</module><module>api</module>"))
    write(tmp_path, "common/pom.xml", pom("common"))
    write(tmp_path, "api/pom.xml", pom("api", WEB + dep("com.acme", "common"), BOOT_PARENT, plugins=BOOT_PLUGIN))
    write(tmp_path, "api/src/main/java/com/acme/App.java", BOOT_APP)
    _, _, plan, df = plan_and_df(tmp_path, "api")
    assert plan["build_root"] == "" and plan["module"] == "api"
    assert "-pl 'api' -am" in df and "./api/target" not in df and "api/target/*.jar" in df


def test_old_java_runs_on_its_own_line_and_war_on_tomcat(tmp_path):
    write(tmp_path, "pom.xml", pom("shop", dep("javax.servlet", "javax.servlet-api", "provided"), packaging="war",
                                   props="<maven.compiler.source>1.8</maven.compiler.source>"))
    write(tmp_path, "src/main/java/com/acme/Hello.java",
          "package com.acme;\nimport javax.servlet.http.HttpServlet;\npublic class Hello extends HttpServlet {}\n")
    _, c, plan, df = plan_and_df(tmp_path, "shop")
    assert plan["java"] == 8 and plan["java_mode"] == "tomcat" and plan["tomcat"] == "tomcat9_8"
    assert "maven:3.9-eclipse-temurin-8 AS build" in df
    assert "FROM tomcat:9.0-jre8-temurin-noble AS final" in df
    assert "COPY --from=build /out/ROOT /usr/local/tomcat/webapps/ROOT" in df and "USER 65532" in df
    assert "/usr/local/tomcat/work" in plan["add_writable"] and "ENTRYPOINT" not in df


def test_executable_war_and_plain_main(tmp_path):
    jar_main = ("<plugin><artifactId>maven-jar-plugin</artifactId><configuration><archive><manifest>"
                "<mainClass>com.acme.Main</mainClass></manifest></archive></configuration></plugin>")
    write(tmp_path, "pom.xml", pom("worker", dep("com.rabbitmq", "amqp-client"), plugins=jar_main,
                                   props="<maven.compiler.release>21</maven.compiler.release>"))
    write(tmp_path, "src/main/java/com/acme/Main.java", "package com.acme; public class Main { public static void main(String[] a) {} }")
    _, _, plan, df = plan_and_df(tmp_path, "worker")
    assert plan["java_mode"] == "classpath" and plan["java"] == 21
    assert "dependency:copy-dependencies -DincludeScope=runtime" in df
    assert 'ENTRYPOINT ["java", "-cp", "/app/app.jar:/app/lib/*", "com.acme.Main"]' in df


def test_gradle_wrapper_boot_and_quarkus(tmp_path):
    write(tmp_path, "settings.gradle", "include 'app'\n")
    write(tmp_path, "gradlew", "#!/bin/sh\n")
    write(tmp_path, "app/build.gradle", "plugins { id 'java'; id 'org.springframework.boot' version '3.3.0' }\n"
          "java { toolchain { languageVersion = JavaLanguageVersion.of(21) } }\n"
          "dependencies { implementation 'org.springframework.boot:spring-boot-starter-web' }\n")
    write(tmp_path, "app/src/main/java/com/acme/App.java", BOOT_APP)
    _, _, plan, df = plan_and_df(tmp_path, "app")
    assert plan["build_tool"] == "gradle" and plan["gradle_task"] == "bootJar" and plan["wrapper"] == "gradlew"
    assert "cd 'app' && sh ../gradlew --no-daemon -x test bootJar" in df
    assert "app/build/libs/*.jar" in df and "distroless/java21" in df


def test_quarkus_fast_jar(tmp_path):
    write(tmp_path, "pom.xml", pom("heroes", dep("io.quarkus", "quarkus-rest") + dep("io.quarkus", "quarkus-smallrye-health"),
                                   props="<maven.compiler.release>21</maven.compiler.release>",
                                   plugins="<plugin><groupId>io.quarkus</groupId><artifactId>quarkus-maven-plugin</artifactId></plugin>"))
    write(tmp_path, "src/main/java/com/acme/Res.java", "package com.acme;\nimport jakarta.ws.rs.Path;\n@Path(\"/heroes\") public class Res {}\n")
    _, c, plan, df = plan_and_df(tmp_path, "heroes")
    assert c.role == "web" and plan["java_mode"] == "quarkus"
    assert "cp -r './target/quarkus-app' /out/quarkus-app" in df
    assert 'ENTRYPOINT ["java", "-jar", "/app/quarkus-app/quarkus-run.jar"]' in df
    assert plan["env"]["QUARKUS_HTTP_PORT"] == "8080" and plan["health"] == "/q/health/live"


def test_ear_is_not_buildable(tmp_path):
    write(tmp_path, "pom.xml", pom("legacy", packaging="ear"))
    a = assess(tmp_path)
    assert not any(buildable(c) for c in a.components)


def test_java_line_and_relaxed_binding():
    assert java_line("1.8") == 8 and java_line("11") == 11 and java_line("16") == 17 and java_line("23") == 25
    assert java_line("61") == 17 and java_line(None) == 21 and java_line(None, "2.7.0") == 17
    assert env_name("app.export-dir", "spring") == "APP_EXPORTDIR"
    assert env_name("my.list[0].name", "spring") == "MY_LIST_0__NAME"
    assert env_name("quarkus.datasource.jdbc.url", "quarkus") == "QUARKUS_DATASOURCE_JDBC_URL"


def test_java_config_profiles(tmp_path):
    write(tmp_path, "pom.xml", pom("svc"))
    write(tmp_path, "src/main/resources/application.yml",
          "server:\n  port: 8081\n---\nspring:\n  config:\n    activate:\n      on-profile: dev\nserver:\n  port: 9999\n")
    write(tmp_path, "src/main/resources/application.properties", "%dev.x.y=1\n%prod.x.z=2\na.b = c \\\n  d\n")
    from containerizer.scan import scan
    p = scan(tmp_path).projects[0]
    cfg = java_config(p)
    assert cfg["server.port"] == "8081" and cfg["x.z"] == "2" and "x.y" not in cfg and cfg["a.b"] == "c d"


# ------------------------------------------------------------------ Node.js

def test_express_npm_dockerfile(tmp_path):
    node(tmp_path, "", EXPRESS, {"server.js": SERVER, "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {}}),
                                 ".env.example": "DATABASE_URL=\nJWT_SECRET=\nLOG_LEVEL=info\n"})
    a, c, plan, df = plan_and_df(tmp_path, "api")
    assert buildable(c) and plan["pm"] == "npm" and plan["node"] == 24 and plan["prune"]
    assert "FROM node:24-bookworm-slim AS build" in df and "npm ci --no-audit --no-fund" in df
    assert "npm prune --omit=dev" in df
    assert "FROM gcr.io/distroless/nodejs24-debian12:nonroot AS final" in df
    assert 'ENTRYPOINT ["/nodejs/bin/node", "server.js"]' in df and "USER 65532" in df
    assert plan["env"]["PORT"] == "8080" and plan["env"]["NODE_ENV"] == "production" and plan["port"] == 8080
    assert plan["health"] == "/health"
    assert set(c.facts["secret_settings"]) == {"DATABASE_URL", "JWT_SECRET"}


def test_start_script_parsing():
    s = {"start": "cross-env NODE_ENV=production node --enable-source-maps dist/index.js"}
    assert node_start({"scripts": s}) == {"script": "start", "env": {"NODE_ENV": "production"},
                                         "argv": ["node", "--enable-source-maps", "dist/index.js"]}
    st = node_start({"scripts": {"start": "nest start", "start:prod": "npm run migrate && node dist/main"}})
    assert st["argv"] == ["node", "dist/main"] and st["pre"] == ["npm run migrate"]
    st = node_start({"scripts": {"start": "npm run serve", "serve": "next start -p 4000"}})
    assert st["argv"] == ["next", "start", "-p", "4000"]
    assert node_start({"scripts": {"start": "nodemon index.js"}})["dev"]
    assert "shell" in node_start({"scripts": {"start": "node a.js | tee log"}})
    assert node_start({"main": "lib/app.js"})["argv"] == ["node", "lib/app.js"]


def test_next_bin_is_resolved_at_build_time(tmp_path):
    node(tmp_path, "", {"name": "site", "scripts": {"build": "next build", "start": "next start -p 4000"},
                        "dependencies": {"next": "15.0.0", "react": "19.0.0"}},
         {"app/page.tsx": "export default function P() { return null }", "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
    a, c, plan, df = plan_and_df(tmp_path, "site")
    assert c.role == "web" and plan["pm"] == "pnpm" and plan["port"] == 4000 and "PORT" not in plan["env"]
    assert "corepack enable && pnpm install --frozen-lockfile" in df and "pnpm run build" in df
    assert "containerizer-resolve-bin.cjs 'next'" in df
    assert 'ENTRYPOINT ["/nodejs/bin/node", ".containerizer-start.js", "start", "-p", "4000"]' in df
    assert "/app/.next/cache" in plan["add_writable"] and plan["env"]["HOSTNAME"] == "0.0.0.0"


def test_shell_start_runs_on_slim_with_npm(tmp_path):
    node(tmp_path, "", {"name": "svc", "scripts": {"start": "node a.js || node b.js"}, "dependencies": {"express": "4"}},
         {"a.js": "require('express')().listen(process.env.PORT)"})
    _, _, plan, df = plan_and_df(tmp_path, "svc")
    assert plan["base"] == "slim"
    assert "FROM node:24-bookworm-slim AS final" in df and 'ENTRYPOINT ["npm", "run", "start"]' in df
    assert plan["env"]["npm_config_cache"] == "/tmp/.npm"


def test_workspace_member_builds_from_root_with_dependencies(tmp_path):
    write(tmp_path, "package.json", json.dumps({"name": "mono", "private": True, "workspaces": ["packages/*", "apps/*"]}))
    write(tmp_path, "yarn.lock", "# yarn lockfile v1\n")
    node(tmp_path, "packages/shared/", {"name": "@m/shared", "main": "dist/index.js", "scripts": {"build": "tsc"}})
    node(tmp_path, "apps/api/", {"name": "@m/api", "scripts": {"build": "tsc", "start": "node dist/main.js"},
                                 "dependencies": {"express": "4", "@m/shared": "*"}},
         {"src/main.ts": "import express from 'express'; express().listen(process.env.PORT);"})
    _, _, plan, df = plan_and_df(tmp_path, "@m/api")
    assert plan["build_root"] == "" and plan["module"] == "apps/api" and plan["workspace"]
    assert plan["build_steps"] == ["packages/shared", "apps/api"]
    assert "yarn install --frozen-lockfile --ignore-engines" in df
    assert df.index("(cd 'packages/shared' && yarn run build)") < df.index("(cd 'apps/api' && yarn run build)")
    assert "WORKDIR /app/apps/api" in df and not plan["prune"]


def test_native_addons_build_on_the_full_image_and_old_engines(tmp_path):
    node(tmp_path, "", {"name": "svc", "engines": {"node": "^20"}, "scripts": {"start": "node index.js"},
                        "dependencies": {"express": "4", "bcrypt": "5"}}, {"index.js": SERVER})
    _, _, plan, df = plan_and_df(tmp_path, "svc")
    assert plan["native_build"] and plan["node"] == 22
    assert "FROM node:22-bookworm AS build" in df and "nodejs22-debian12" in df and "apt-get" not in df


def test_node_spa_uses_the_repository_package_manager(tmp_path):
    node(tmp_path, "", {"name": "web", "scripts": {"build": "vite build"}, "devDependencies": {"vite": "5", "react": "18"}},
         {"index.html": "<div id=root></div>", "pnpm-lock.yaml": "lockfileVersion: '9.0'\n"})
    a, c, plan, df = plan_and_df(tmp_path, "web")
    assert c.role == "spa"
    assert "pnpm install --frozen-lockfile" in df and "nginx-unprivileged" in df and "for d in 'dist/browser' 'dist'" in df


def test_node_config_windows_paths(tmp_path):
    node(tmp_path, "", {"name": "svc", "scripts": {"start": "node index.js"}, "dependencies": {"express": "4", "config": "3"}},
         {"index.js": SERVER, "config/default.json": json.dumps({"storage": {"dir": "E:\\Files\\In"}, "port": 1})})
    _, _, plan, _ = plan_and_df(tmp_path, "svc")
    assert json.loads(plan["env"]["NODE_CONFIG"]) == {"storage": {"dir": "/data/files/in"}}
    assert "/data/files/in" in plan["add_writable"]


def test_dotnet_plan_rules_do_not_apply(tmp_path):
    node(tmp_path, "", EXPRESS, {"server.js": SERVER})
    _, _, plan, df = plan_and_df(tmp_path, "api")
    assert not any(r.startswith("plan-") for r in plan["applied"]) and "DataProtection" not in df


def test_generate_writes_java_and_node_components(tmp_path):
    boot_app(tmp_path / "repo", rel="orders/")
    node(tmp_path / "repo", "web/", EXPRESS, {"server.js": SERVER})
    out = tmp_path / "out"
    generate_app(assess(tmp_path / "repo"), out)
    assert (out / "orders" / "Dockerfile").exists() and (out / "api" / "Dockerfile").exists()
    k = yaml.safe_load((out / "kustomization.yaml").read_text())
    assert {"orders/k8s.yaml", "api/k8s.yaml"} <= set(k["resources"])


# ------------------------------------------------------------------ verification failures

def test_failure_rules_for_java_and_node():
    fr = load_failures()

    def d(log, stage):
        r = diagnose(log, stage, fr)
        return (r[0]["id"], r[1]) if r else None

    assert d("[ERROR] error: release version 21 not supported", "build") == ("build-java-release-too-new", {"ver": "21"})
    assert d("class file has wrong version 61.0, should be 55.0", "build")[1] == {"ver": "61"}
    assert d("npm ERR! `npm ci` can only install packages when your package.json and package-lock.json or "
             "npm-shrinkwrap.json are in sync.", "build")[0] == "build-npm-lock-out-of-sync"
    assert d("gyp ERR! find Python", "build")[0] == "build-node-gyp-toolchain"
    assert d("FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory", "build")[0] == "build-node-heap"
    assert d("Error: Cannot find module 'ts-node'\nRequire stack:", "run")[0] == "run-node-module-not-found"
    assert d("Error: Cannot find module './dist/main'", "run") is None or \
        d("Error: Cannot find module './dist/main'", "run")[0] != "run-node-module-not-found"
    assert d("Error: EROFS: read-only file system, open '/app/data/db.json'", "run") == \
        ("run-readonly-path-node-java", {"path": "/app/data/db.json", "dir": "/app/data"})
    for log in ("org.postgresql.util.PSQLException: Connection to db:5432 refused",
                "MongooseServerSelectionError: connect ECONNREFUSED 127.0.0.1:27017",
                "Could not resolve placeholder 'jwt.secret' in value \"${jwt.secret}\""):
        assert diagnose(log, "run", fr)[0]["outcome"] == "external", log


def test_old_pnpm_lockfile_pins_pnpm_major(tmp_path):
    node(tmp_path, "", {"name": "svc", "scripts": {"start": "node index.js"}, "dependencies": {"express": "4"}},
         {"index.js": SERVER, "pnpm-lock.yaml": "lockfileVersion: '6.0'\n"})
    _, _, plan, df = plan_and_df(tmp_path, "svc")
    assert plan["pm_pin"] == "pnpm@8" and "corepack enable && corepack install -g pnpm@8 && pnpm install" in df


def test_git_properties_plugins_are_skipped(tmp_path):
    plugin = "<plugin><groupId>io.github.git-commit-id</groupId><artifactId>git-commit-id-maven-plugin</artifactId></plugin>"
    write(tmp_path, "pom.xml", pom("orders", WEB, BOOT_PARENT, plugins=BOOT_PLUGIN + plugin))
    write(tmp_path, "src/main/java/com/acme/App.java", BOOT_APP)
    _, _, plan, df = plan_and_df(tmp_path, "orders")
    assert "plan-maven-git-commit-id" in plan["applied"] and "-Dmaven.gitcommitid.skip=true" in df


def test_committed_node_modules_stay_in_the_build_context(tmp_path):
    import subprocess
    from containerizer.generate import DOCKERIGNORE, dockerignore
    node(tmp_path, "", EXPRESS, {"server.js": SERVER, "packages/node_modules/@x/core/index.js": "module.exports = 1"})
    a = assess(tmp_path)
    assert dockerignore(a.repo) == DOCKERIGNORE                      # not a git checkout
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    assert "**/node_modules/" not in dockerignore(a.repo)


def test_node_util_removal_moves_to_node_22():
    r = diagnose("TypeError: util_1.isNullOrUndefined is not a function", "run", load_failures())
    assert r[0]["id"] == "run-node-util-removed" and r[0]["fix"] == {"node": 22}


def test_node_run_and_loader_from_dev_dependencies(tmp_path):
    node(tmp_path, "", {"name": "kuma", "scripts": {"start": "node --run start-server",
                                                    "start-server": "node --import=tsx server/server.js"},
                        "dependencies": {"express": "4"}, "devDependencies": {"tsx": "4"}},
         {"server/server.js": SERVER})
    _, _, plan, df = plan_and_df(tmp_path, "kuma")
    assert plan["node_entry"] == ["--import=tsx", "server/server.js"] and not plan["prune"]
    assert "npm prune" not in df


def test_relative_mkdir_failure_becomes_a_writable_app_folder():
    from containerizer.generate import _writable_abs
    r = diagnose("Error: ENOENT: no such file or directory, mkdir './data/'", "run", load_failures())
    assert r[0]["id"] == "run-readonly-path-node-java" and _writable_abs(r[1]["dir"]) == "/app/data"
