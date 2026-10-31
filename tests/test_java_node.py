"""Java and Node.js: build-file parsing, roles, findings, statelessness and confidence."""
import json

from containerizer.assess import assess, classify_role
from containerizer.rules import load_rules
from containerizer.scan import scan
from containerizer.scan_node import engine_max_major
from tests.test_engine import write

RULES = load_rules()

BOOT_APP = """\
    package com.acme;
    import org.springframework.boot.SpringApplication;
    import org.springframework.boot.autoconfigure.SpringBootApplication;
    @SpringBootApplication public class App { public static void main(String[] a) { SpringApplication.run(App.class, a); } }
    """


def pom(artifact, deps="", parent="", packaging="", props="", plugins="", modules="", group="com.acme"):
    return f"""\
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          {parent}
          <groupId>{group}</groupId><artifactId>{artifact}</artifactId><version>1.0</version>
          {f'<packaging>{packaging}</packaging>' if packaging else ''}
          <properties>{props}</properties>
          {f'<modules>{modules}</modules>' if modules else ''}
          <dependencies>{deps}</dependencies>
          <build><plugins>{plugins}</plugins></build>
        </project>
        """


def dep(g, a, scope="", version=""):
    return (f"<dependency><groupId>{g}</groupId><artifactId>{a}</artifactId>"
            + (f"<version>{version}</version>" if version else "") + (f"<scope>{scope}</scope>" if scope else "")
            + "</dependency>")


BOOT_PARENT = ("<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId>"
               "<version>3.3.0</version></parent>")
WEB = dep("org.springframework.boot", "spring-boot-starter-web")
BOOT_PLUGIN = "<plugin><groupId>org.springframework.boot</groupId><artifactId>spring-boot-maven-plugin</artifactId></plugin>"


def boot_app(root, deps=WEB, code=BOOT_APP, rel="", props="<java.version>17</java.version>"):
    write(root, f"{rel}pom.xml", pom("orders", deps, BOOT_PARENT, props=props, plugins=BOOT_PLUGIN))
    write(root, f"{rel}src/main/java/com/acme/App.java", code)


def project(root, name):
    return next(p for p in scan(root).projects if p.name == name)


def role_of(root, name):
    repo = scan(root)
    p = next(p for p in repo.projects if p.name == name)
    return classify_role(repo, p, RULES)[0]


def comp(a, name):
    return next(c for c in a.components if c.name == name)


def ids(c):
    return {f.rule.id for f in c.findings if not f.dormant}


# ------------------------------------------------------------------ Maven parsing

def test_maven_parent_properties_profiles_and_test_scope(tmp_path):
    write(tmp_path, "pom.xml", pom("parent", dep("org.projectlombok", "lombok", version="${lombok.version}"),
                                   packaging="pom", props="<lombok.version>1.18.30</lombok.version><java.version>21</java.version>",
                                   modules="<module>api</module>"))
    write(tmp_path, "api/pom.xml", pom(
        "api", WEB + dep("org.junit.jupiter", "junit-jupiter", "test"),
        "<parent><groupId>com.acme</groupId><artifactId>parent</artifactId><version>1.0</version></parent>",
        plugins=BOOT_PLUGIN).replace("</project>", "<profiles><profile><id>pg</id><dependencies>"
                                     + dep("org.postgresql", "postgresql") + "</dependencies></profile></profiles></project>"))
    p = project(tmp_path, "api")
    assert p.properties["JavaVersion"] == "21"
    assert p.packages["org.projectlombok:lombok"] == "1.18.30"           # inherited from the parent
    assert "org.postgresql:postgresql" in p.packages                     # profile dependency
    assert "org.junit.jupiter:junit-jupiter" in p.dev_packages
    assert "org.springframework.boot:spring-boot-starter-web" not in p.dev_packages
    assert "spring-boot-maven-plugin" in p.properties["Plugins"]
    root = project(tmp_path, "parent")
    assert root.properties["Packaging"] == "pom" and root.properties["Modules"] == "api"
    assert role_of(tmp_path, "parent") == "library"


def test_maven_module_dependency_is_a_project_reference(tmp_path):
    write(tmp_path, "common/pom.xml", pom("common", WEB))
    write(tmp_path, "app/pom.xml", pom("app", dep("com.acme", "common", version="1.0"), BOOT_PARENT, plugins=BOOT_PLUGIN))
    write(tmp_path, "app/src/main/java/com/acme/App.java", BOOT_APP)
    repo = scan(tmp_path)
    app = next(p for p in repo.projects if p.name == "app")
    assert [repo.rel(r) for r in app.project_refs] == ["common/pom.xml"]
    # the web starter comes in through the shared module (mall-security)
    assert role_of(tmp_path, "app") == "web"
    assert role_of(tmp_path, "common") == "library"
    a = assess(tmp_path)
    assert comp(a, "app").uncertain == []                                 # in-repo modules are not unknowns


# ------------------------------------------------------------------ Gradle parsing

def test_gradle_catalog_subprojects_and_project_refs(tmp_path):
    write(tmp_path, "settings.gradle", "rootProject.name = 'shop'\ninclude 'core', 'web'\n")
    write(tmp_path, "gradle/libs.versions.toml", """\
        [versions]
        boot = "3.3.0"
        [libraries]
        boot-web = { module = "org.springframework.boot:spring-boot-starter-web", version.ref = "boot" }
        pg = "org.postgresql:postgresql:42.7.3"
        [plugins]
        spring-boot = { id = "org.springframework.boot", version.ref = "boot" }
        """)
    write(tmp_path, "build.gradle", """\
        subprojects {
            apply plugin: 'java'
            java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }
            dependencies { testImplementation 'org.junit.jupiter:junit-jupiter:5.10.0' }
        }
        """)
    write(tmp_path, "core/build.gradle", "plugins { id 'java-library' }\ndependencies { api libs.pg }\n")
    write(tmp_path, "web/build.gradle", """\
        plugins { alias(libs.plugins.spring.boot) }
        dependencies {
            implementation project(':core')
            implementation libs.boot.web
            implementation group: 'org.flywaydb', name: 'flyway-core', version: '10.0.0'
        }
        """)
    write(tmp_path, "web/src/main/java/com/acme/App.java", BOOT_APP)
    repo = scan(tmp_path)
    web = next(p for p in repo.projects if p.rel == "web/build.gradle")
    assert web.packages["org.springframework.boot:spring-boot-starter-web"] == "3.3.0"
    assert web.packages["org.flywaydb:flyway-core"] == "10.0.0"
    assert "org.junit.jupiter:junit-jupiter" in web.dev_packages          # from subprojects {}
    assert web.properties["JavaVersion"] == "17"
    assert "org.springframework.boot" in web.properties["Plugins"]
    assert web.properties["SpringBoot"] == "true"
    assert [repo.rel(r) for r in web.project_refs] == ["core/build.gradle"]
    assert classify_role(repo, web, RULES)[0] == "web"


def test_pom_and_gradle_in_one_folder_is_one_project(tmp_path):
    boot_app(tmp_path)
    write(tmp_path, "build.gradle", "plugins { id 'org.springframework.boot' version '3.3.0' }\n")
    assert len([p for p in scan(tmp_path).projects if p.kind_hint == "java"]) == 1


# ------------------------------------------------------------------ Java roles

def test_java_roles(tmp_path):
    boot_app(tmp_path, rel="web/")
    write(tmp_path, "worker/pom.xml", pom("worker", dep("org.springframework.kafka", "spring-kafka"), BOOT_PARENT))
    write(tmp_path, "worker/src/main/java/W.java", BOOT_APP)
    write(tmp_path, "batch/pom.xml", pom("batch", dep("org.springframework.boot", "spring-boot-starter-batch"), BOOT_PARENT))
    write(tmp_path, "batch/src/main/java/B.java", BOOT_APP)
    write(tmp_path, "legacy/pom.xml", pom("legacy", dep("javax.servlet", "javax.servlet-api", "provided"), packaging="war"))
    write(tmp_path, "desk/pom.xml", pom("desk"))
    write(tmp_path, "desk/src/main/java/D.java",
          "import javax.swing.*; public class D extends JFrame { public static void main(String[] a) { new D(); } }")
    write(tmp_path, "lib/pom.xml", pom("lib", WEB))                      # web starter, no application class
    write(tmp_path, "lib/src/main/java/L.java", "public class L {}")
    assert role_of(tmp_path, "orders") == "web"
    assert role_of(tmp_path, "worker") == "worker"
    assert role_of(tmp_path, "batch") == "console"
    assert role_of(tmp_path, "legacy") == "web"
    assert role_of(tmp_path, "desk") == "desktop"
    assert role_of(tmp_path, "lib") == "library"


def test_frontend_inside_java_module_is_hosted(tmp_path):
    boot_app(tmp_path)
    write(tmp_path, "src/main/webui/package.json", json.dumps({"name": "webui", "scripts": {"build": "vite build"},
                                                             "dependencies": {"react": "^18.0.0"}}))
    assert project(tmp_path, "webui").properties["HostedBy"] == "pom.xml"
    assert role_of(tmp_path, "webui") == "spa-assets"


# ------------------------------------------------------------------ Java findings and state

def test_plain_boot_app_with_postgres_is_a(tmp_path):
    boot_app(tmp_path, WEB + dep("org.springframework.boot", "spring-boot-starter-data-jpa")
             + dep("org.postgresql", "postgresql") + dep("com.h2database", "h2", "test"))
    a = assess(tmp_path)
    assert a.rating == "A", a.summary()
    assert comp(a, "orders").confidence == 1.0


def test_h2_only_is_in_memory_state(tmp_path):
    boot_app(tmp_path, WEB + dep("org.springframework.boot", "spring-boot-starter-data-jpa") + dep("com.h2database", "h2"))
    a = assess(tmp_path)
    assert "java-embedded-db-memory" in ids(comp(a, "orders"))
    assert a.rating == "B"


def test_h2_next_to_server_driver_is_optional(tmp_path):
    boot_app(tmp_path, WEB + dep("org.springframework.boot", "spring-boot-starter-data-jpa")
             + dep("com.h2database", "h2") + dep("com.mysql", "mysql-connector-j"))
    a = assess(tmp_path)
    c = comp(a, "orders")
    assert "java-embedded-db-optional" in ids(c) and c.stateless and a.rating == "A"


def test_h2_file_database_is_local_state(tmp_path):
    boot_app(tmp_path, WEB + dep("com.h2database", "h2"))
    write(tmp_path, "src/main/resources/application.properties", "spring.datasource.url=jdbc:h2:file:./data/orders\n")
    a = assess(tmp_path)
    assert "java-embedded-db-file" in ids(comp(a, "orders")) and a.rating == "B"


def test_session_state_unless_spring_session(tmp_path):
    code = BOOT_APP + """
        class C { @org.springframework.web.bind.annotation.GetMapping("/") String m(javax.servlet.http.HttpSession s) {
            s.setAttribute("cart", 1); return "ok"; } }
        """
    boot_app(tmp_path, code=code)
    assert "java-session-in-memory" in ids(comp(assess(tmp_path), "orders"))
    boot_app(tmp_path, WEB + dep("org.springframework.session", "spring-session-data-redis"), code=code)
    assert "java-session-in-memory" not in ids(comp(assess(tmp_path), "orders"))


def test_uploads_to_local_disk_is_local_state(tmp_path):
    boot_app(tmp_path, code=BOOT_APP + """
        class U { void save(org.springframework.web.multipart.MultipartFile f) throws Exception {
            f.transferTo(java.nio.file.Paths.get("uploads", f.getOriginalFilename())); } }
        """)
    c = comp(assess(tmp_path), "orders")
    assert "java-local-uploads" in ids(c) and not c.stateless


def test_home_directory_is_local_state(tmp_path):
    boot_app(tmp_path, code=BOOT_APP + """
        class Home { java.io.File root() {
            String h = System.getenv("ORDERS_HOME");
            return h != null ? new java.io.File(h) : new java.io.File(System.getProperty("user.home"), ".orders"); } }
        """)
    c = comp(assess(tmp_path), "orders")
    assert "java-app-home-directory" in ids(c) and not c.stateless


def test_tool_home_variables_are_not_app_state(tmp_path):
    boot_app(tmp_path, code=BOOT_APP + 'class J { String j = System.getenv("JAVA_HOME"); String m = System.getenv("MAVEN_HOME"); }')
    assert "java-app-home-directory" not in ids(comp(assess(tmp_path), "orders"))


def test_test_sources_are_not_scanned(tmp_path):
    boot_app(tmp_path)
    write(tmp_path, "src/test/java/T.java", 'class T { void t() { Runtime.getRuntime().exec("cmd /c dir"); } }')
    write(tmp_path, "src/test/resources/application.properties", "spring.datasource.url=jdbc:h2:file:./x\n")
    c = comp(assess(tmp_path), "orders")
    assert not ids(c) & {"java-process-windows-commands", "java-embedded-db-file"}


def test_windows_native_and_com(tmp_path):
    boot_app(tmp_path, WEB + dep("net.sf.jacob-project", "jacob"), code=BOOT_APP + """
        class W { void m() { com.sun.jna.platform.win32.Kernel32.INSTANCE.GetTickCount(); } }
        """)
    a = assess(tmp_path)
    c = comp(a, "orders")
    assert {"java-com-bridge", "java-jna-win32"} <= ids(c)
    assert c.verdict == "blocker" and a.rating == "E"


def test_os_checked_windows_code_is_info(tmp_path):
    boot_app(tmp_path, code=BOOT_APP + """
        class W { void m() { if (com.sun.jna.Platform.isWindows()) { com.sun.jna.platform.win32.Kernel32.INSTANCE.GetTickCount(); } } }
        """)
    c = comp(assess(tmp_path), "orders")
    assert "java-jna-win32" not in ids(c) and "java-jna-win32-guarded" in ids(c)


def test_mssql_integrated_security_and_old_java(tmp_path):
    boot_app(tmp_path, WEB + dep("com.microsoft.sqlserver", "mssql-jdbc"), props="<java.version>1.7</java.version>")
    write(tmp_path, "src/main/resources/application.properties",
          "spring.datasource.url=jdbc:sqlserver://db;databaseName=x;integratedSecurity=true\n")
    c = comp(assess(tmp_path), "orders")
    assert {"java-mssql-integrated-auth", "java-unsupported-version"} <= ids(c)
    assert c.verdict == "refactor"


def test_unknown_java_dependency_lowers_confidence(tmp_path):
    boot_app(tmp_path, WEB + dep("com.vendor.secret", "native-thing"))
    c = comp(assess(tmp_path), "orders")
    assert c.uncertain == ["package:com.vendor.secret:native-thing"] and c.confidence < 1.0


# ------------------------------------------------------------------ Node parsing

def node(root, rel, manifest, files=None):
    write(root, f"{rel}package.json", json.dumps(manifest))
    for name, txt in (files or {}).items():
        write(root, f"{rel}{name}", txt)


EXPRESS = {"name": "api", "private": True, "scripts": {"start": "node server.js"},
           "dependencies": {"express": "^4.19.0", "pg": "^8.0.0"}, "devDependencies": {"jest": "^29.0.0"}}
SERVER = "const app = require('express')(); app.get('/health', (q, r) => r.send('ok')); app.listen(process.env.PORT || 3000);"


def test_node_manifest_and_lockfile(tmp_path):
    node(tmp_path, "", {**EXPRESS, "engines": {"node": "^14 || ^16"}, "packageManager": "pnpm@9.1.0"}, {"server.js": SERVER})
    write(tmp_path, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
        "": {"name": "api"},
        "node_modules/express": {"version": "4.19.0", "dependencies": {"winonly": "1.0.0"}},
        "node_modules/winonly": {"version": "1.0.0", "os": ["win32"]},
        "node_modules/pg": {"version": "8.0.0", "optionalDependencies": {"opt-win": "1"}},
        "node_modules/opt-win": {"version": "1", "os": ["win32"], "optional": True},
        "node_modules/jest": {"version": "29.0.0", "dev": True, "dependencies": {"fsevents": "2"}},
        "node_modules/fsevents": {"version": "2", "os": ["darwin"], "hasInstallScript": True}}}))
    p = project(tmp_path, "api")
    assert p.dev_packages == {"jest": "^29.0.0"}
    assert p.properties["StartScript"] == "node server.js"
    assert p.properties["PackageManager"] == "pnpm"                     # packageManager wins over the lockfile
    assert p.properties["NodeEngineMax"] == "16"
    assert p.properties["LockWindowsOnly"] == "winonly"                   # not the optional or the dev one
    assert "LockNativeBuild" not in p.properties
    c = comp(assess(tmp_path), "api")
    assert {"node-unsupported-version", "node-windows-only-dependency"} <= ids(c)
    assert c.uncertain == []                    # the Windows-only package is explained by the finding


def test_engine_ranges():
    assert engine_max_major("^14") == 14
    assert engine_max_major(">=10 <15") == 14
    assert engine_max_major(">=18") is None
    assert engine_max_major("12.x || 14.x") == 14


def test_workspaces_link_packages_and_root_is_not_deployed(tmp_path):
    node(tmp_path, "", {"name": "mono", "private": True, "workspaces": ["packages/*"]})
    node(tmp_path, "packages/api/", {**EXPRESS, "dependencies": {**EXPRESS["dependencies"], "@acme/ui-kit": "workspace:*"}},
         {"server.js": SERVER})
    node(tmp_path, "packages/ui-kit/", {"name": "@acme/ui-kit", "main": "dist/index.js", "exports": "./dist/index.js",
                                        "peerDependencies": {"react": "^18"}, "devDependencies": {"react": "^18"}})
    node(tmp_path, "packages/web/", {"name": "web", "private": True, "scripts": {"build": "vite build"},
                                     "dependencies": {"react": "^18", "@acme/ui-kit": "workspace:*"}}, {"index.html": "<div/>"})
    repo = scan(tmp_path)
    api = next(p for p in repo.projects if p.name == "api")
    assert api.properties["WorkspaceRoot"] == "package.json"
    assert [repo.rel(r) for r in api.project_refs] == ["packages/ui-kit/package.json"]
    assert role_of(tmp_path, "mono") == "library"
    assert role_of(tmp_path, "api") == "web"
    assert role_of(tmp_path, "@acme/ui-kit") == "library"                 # component library, not an app
    assert role_of(tmp_path, "web") == "spa"


def test_node_roles(tmp_path):
    node(tmp_path, "a/", EXPRESS, {"server.js": SERVER})
    node(tmp_path, "b/", {"name": "consumer", "scripts": {"start": "node worker.js"}, "dependencies": {"amqplib": "^0.10"}})
    node(tmp_path, "c/", {"name": "cli", "bin": {"cli": "bin/cli.js"}, "dependencies": {"commander": "^12"}})
    node(tmp_path, "d/", {"name": "desk", "main": "main.js", "devDependencies": {"electron": "^30"}})
    node(tmp_path, "e/", {"name": "express-plugin", "main": "index.js", "peerDependencies": {"express": "^4"},
                          "dependencies": {"express": "^4"}}, {"index.js": "module.exports = (req, res, next) => next();"})
    node(tmp_path, "f/", {"name": "next-app", "scripts": {"build": "next build", "start": "next start"},
                          "dependencies": {"next": "^14", "react": "^18"}})
    assert role_of(tmp_path, "api") == "web"
    assert role_of(tmp_path, "consumer") == "worker"
    assert role_of(tmp_path, "cli") == "tool"
    assert role_of(tmp_path, "desk") == "desktop"
    assert role_of(tmp_path, "express-plugin") == "library"
    assert role_of(tmp_path, "next-app") == "web"


def test_monorepo_packages_folder_is_scanned(tmp_path):
    node(tmp_path, "packages/api/", EXPRESS, {"server.js": SERVER})
    assert any(p.name == "api" for p in scan(tmp_path).projects)


# ------------------------------------------------------------------ Node findings and state

def test_plain_express_with_postgres_is_a(tmp_path):
    node(tmp_path, "", EXPRESS, {"server.js": SERVER})
    a = assess(tmp_path)
    assert a.rating == "A", a.summary()


def test_express_session_memory_store_is_state(tmp_path):
    m = {**EXPRESS, "dependencies": {**EXPRESS["dependencies"], "express-session": "^1.18"}}
    node(tmp_path, "", m, {"server.js": SERVER + "\napp.use(require('express-session')({secret: process.env.S}));"})
    a = assess(tmp_path)
    assert "node-session-memory" in ids(comp(a, "api")) and a.rating == "B"
    m["dependencies"]["connect-redis"] = "^7"
    node(tmp_path, "", m)
    assert "node-session-memory" not in ids(comp(assess(tmp_path), "api"))


def test_sqlite_only_is_local_state_and_optional_next_to_pg(tmp_path):
    node(tmp_path, "", {**EXPRESS, "dependencies": {"express": "^4", "sqlite3": "^5"}}, {"server.js": SERVER})
    a = assess(tmp_path)
    assert "node-embedded-db-local" in ids(comp(a, "api")) and a.rating == "B"
    node(tmp_path, "", {**EXPRESS, "dependencies": {"express": "^4", "sqlite3": "^5", "pg": "^8"}})
    c = comp(assess(tmp_path), "api")
    assert "node-embedded-db-optional" in ids(c) and c.stateless


def test_multer_disk_uploads_are_local_state(tmp_path):
    node(tmp_path, "", {**EXPRESS, "dependencies": {**EXPRESS["dependencies"], "multer": "^1"}},
         {"server.js": SERVER + "\nconst upload = require('multer')({ dest: 'uploads/' });"})
    assert "node-local-uploads" in ids(comp(assess(tmp_path), "api"))


def test_uploaded_themes_on_local_disk_are_state(tmp_path):
    theme = ("const fs = require('fs-extra'); const path = require('path');\n"
             "const dir = path.join(config.contentPath, 'themes');\n"
             "async function install(zip, name) { await fs.ensureDir(dir); await fs.move(zip, path.join(dir, name)); }")
    node(tmp_path, "", {**EXPRESS, "dependencies": {**EXPRESS["dependencies"], "@aws-sdk/client-s3": "^3"}},
         {"server.js": SERVER, "themes.js": theme})
    c = comp(assess(tmp_path), "api")
    assert "node-local-extensions" in ids(c) and not c.stateless     # the S3 client covers media, not themes


def test_reading_bundled_themes_is_not_state(tmp_path):
    node(tmp_path, "", EXPRESS, {"server.js": SERVER + "\nconst t = require('path').join(__dirname, 'themes');"})
    assert "node-local-extensions" not in ids(comp(assess(tmp_path), "api"))


def test_windows_only_node_packages(tmp_path):
    node(tmp_path, "", {**EXPRESS, "dependencies": {**EXPRESS["dependencies"], "winax": "^3", "node-sspi": "^0.2",
                                                    "winreg": "^1"}}, {"server.js": SERVER})
    write(tmp_path, "web.config", '<configuration><system.webServer><handlers>'
          '<add name="iisnode" path="server.js" verb="*" modules="iisnode" /></handlers></system.webServer></configuration>')
    a = assess(tmp_path)
    c = comp(a, "api")
    assert {"node-com-activex", "node-windows-sspi", "node-windows-registry", "node-iisnode"} <= ids(c)
    assert a.rating == "E"


def test_child_process_windows_commands_unless_platform_checked(tmp_path):
    node(tmp_path, "", EXPRESS, {"server.js": SERVER + "\nrequire('child_process').exec('cmd /c dir');"})
    assert "node-process-windows-commands" in ids(comp(assess(tmp_path), "api"))
    node(tmp_path, "", EXPRESS, {"server.js": SERVER + "\nif (process.platform === 'win32') require('child_process').exec('cmd /c dir');"})
    assert "node-process-windows-commands" not in ids(comp(assess(tmp_path), "api"))


def test_node_test_files_are_not_scanned(tmp_path):
    node(tmp_path, "", EXPRESS, {"server.js": SERVER, "test/setup.js": "require('child_process').exec('cmd /c dir');",
                                 "src/a.spec.ts": "exec('powershell Get-Item')"})
    assert "node-process-windows-commands" not in ids(comp(assess(tmp_path), "api"))


def test_dotnet_only_rules_do_not_fire_on_node(tmp_path):
    node(tmp_path, "", EXPRESS, {"server.js": SERVER + "\nconst f = 'report.mdb'; File.Create(x); app.AddSignalR();"})
    c = comp(assess(tmp_path), "api")
    assert not ids(c) & {"oledb-odbc-access", "local-state-files", "signalr-scaleout"}
