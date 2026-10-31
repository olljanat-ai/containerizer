# Java and Node.js

The rule engine assesses Java (Maven and Gradle, Spring Boot, Quarkus, Micronaut, plain JVM
programs and WAR files) and Node.js (npm, yarn and pnpm; Express, Fastify, Koa, NestJS, Next.js,
Nuxt and others) the same way as .NET: rules first, every finding explained with references, the
same ratings, and the same stateless requirement for an **A**. Nothing from the repository is
built or run during the assessment.

## What is read

**Java** (`containerizer/scan_java.py`)

- `pom.xml`: coordinates, packaging (jar, war, ear, pom), properties and `${...}` references,
  in-repository parents (`<relativePath>`), inherited dependencies and plugins, profiles,
  `dependencyManagement` versions, the Spring Boot line, the Java version and the main class.
- `build.gradle` / `build.gradle.kts`: plugins (`id`, `apply plugin`, `alias(libs.plugins.x)`),
  dependencies by configuration (string, map and version catalog notations), `project(':x')`
  references, `subprojects {}` and `allprojects {}` blocks, toolchains and `settings.gradle`
  includes; `gradle/libs.versions.toml` is resolved, bundles included.
- A folder with both `pom.xml` and `build.gradle` is one project (Maven's).
- Dependencies are named `groupId:artifactId`. Test-scoped dependencies (Maven `test`, Gradle
  `test*` configurations) are kept apart, and `src/test/` is not searched by code rules.

**Node.js** (`containerizer/scan_node.py`)

- `package.json`: dependencies (devDependencies kept apart), scripts and the start command,
  `main`, `bin`, `engines.node`, `packageManager`, library markers (`exports`, `files`,
  `peerDependencies`) and npm/yarn workspaces or `pnpm-workspace.yaml`.
- Workspace packages that depend on each other become project references, so a finding in a
  shared package reaches the applications that use it.
- The lockfile (`package-lock.json` v2/v3 or `pnpm-lock.yaml`) is walked from the package's own
  runtime dependencies: packages that install only on Windows (`"os": ["win32"]`, not optional)
  and packages that compile a native addon are recorded.
- Test files and folders (`__tests__/`, `test/`, `*.spec.ts`, ...) are not searched by code rules.

A front end inside a Java module (`src/main/webui`, `frontend-maven-plugin`, the Gradle node
plugin, a build that writes into the module) is served by that module, like a ClientApp in an
ASP.NET Core project.

## Roles

| Role | Java | Node.js |
|---|---|---|
| web | `@SpringBootApplication` with a web stack (also through a shared module), Quarkus/Micronaut/Helidon HTTP, Javalin/Dropwizard/Vert.x with a `main`, a WAR or EAR | a server framework among the runtime dependencies and a start script, `.listen()` or a self-starting framework (Next.js, Nuxt, NestJS) |
| worker | a Spring Boot/Quarkus application with listeners or schedulers and no HTTP | a start script and a queue, scheduler or bot package |
| console | Spring Batch, other Spring Boot applications, a declared main class | a start script that runs `node` |
| spa | | React/Angular/Vue/Svelte apps with an `index.html` or app tooling |
| desktop | Swing, JavaFX, SWT, Android | Electron, React Native, Ionic, Tauri |
| library | Maven aggregators and BOMs, modules without an application | workspace roots, component libraries, middleware packages |
| tool | | command line packages (`bin`) |

## Findings

Rules are in `rules/12-java.yaml`, `rules/13-node.yaml` and `rules/14-java-node-common.yaml`.

- **Blockers and rewrites**: COM automation (JACOB, com4j, winax), Windows API calls through JNA,
  FFI or NodeRT with no OS check, native libraries shipped only as DLLs, the JDBC-ODBC bridge.
  Each has an entry in the migration assistant (`rules/migrations.yaml`).
- **Refactoring**: Windows integrated authentication (WAFFLE, node-sspi), the Windows registry,
  Windows-only helper packages and dependencies, Edge.js, starting Windows programs, Java 7 or
  older, Node.js 17 or older, node-sass, full Jakarta EE servers (EJB, EAR) and vendor server APIs.
- **Configuration**: SQL Server integrated security from JDBC, msnodesqlv8, iisnode, Windows
  service wrappers (procrun, WinSW, node-windows), file-only logging, schedulers that run in every
  replica, Quartz's in-memory store, Socket.IO without an adapter, headless browsers, Oracle Thick
  mode, process managers, Windows environment variables and drive paths in code.

## Stateless

As for .NET, an application is **A** only when every server component keeps its data in external
services. These keep a component stateful (rated **B** when otherwise ready):

- an embedded database in file mode (H2/HSQLDB file URLs, Derby, SQLite, LowDB, NeDB, LevelDB)
  with no server database driver in the repository;
- an embedded in-memory database (H2, HSQLDB, Derby) as the only database;
- HTTP sessions in process memory (HttpSession, form login, Vaadin/JSF without Spring Session;
  express-session's default store) or in local files;
- uploads and data files written to the local disk without an object storage client;
- a local Lucene index (FSDirectory, the Hibernate Search Lucene backend).

Not counted: an embedded database next to a server database driver (the deployment can choose
the server one), and in-memory test databases.

## Confidence

Java runtime dependencies that are not in `rules/packages-java.yaml` lower the confidence, as do
Node.js native addons and Windows-only packages not in `rules/packages-node.yaml` (pure
JavaScript packages are portable and do not count). Low confidence triggers verification and the
optional LLM review, as for .NET.

## Containers

`containerizer generate` (and `verify`, `gate`) builds Java and Node.js components the same way as
.NET ones: a multi-stage Dockerfile that uses the application folder as build context, a hardened
Kubernetes manifest (non-root, read-only root file system, no capabilities, seccomp, resource
limits, NetworkPolicy) and a `plan.json` that explains every non-default decision. Base images are
in `rules/images.yaml`; `containerizer images --update` pins patched tags in `rules/images.lock.yaml`.

**Java** (`containerizer/gen_jvm_node.py`)

| | |
|---|---|
| Java line | the version the build declares (`maven.compiler.release`, `java.version`, toolchains), rounded up to an LTS line: 8, 11, 17, 21 or 25. The build and the runtime use the same line. |
| Build | Maven from the image (`-pl <module> -am` from the in-repository aggregator), or the repository's Gradle wrapper (`bootJar`, `quarkusBuild`, `installDist`, `shadowJar`, `war`). Tests are skipped in the image build. A CA bundle passed as the `ca` build secret is added to the build JDK; `HTTPS_PROXY` is passed to Maven and Gradle. |
| Runtime | distroless Java 17/21/25, or the Temurin JRE for Java 8 and 11, as uid 65532. Spring Boot and executable jars or WARs run with `java -jar`; Quarkus runs its fast-jar; a plain program runs its main class with its dependencies on the class path; a WAR without an embedded server is unpacked into Tomcat 9 (`javax.servlet`) or 10.1 (`jakarta.servlet`). |
| Port | `SERVER_PORT`, `QUARKUS_HTTP_PORT`, `MICRONAUT_SERVER_PORT` or `PORT` set to 8080; a port fixed in code is kept. |
| Probes | Spring Boot Actuator liveness and readiness groups (not when Spring Security protects them and the code does not open them), SmallRye Health, Micronaut management; a TCP probe otherwise. The context path is taken into account. |
| Configuration | Windows paths in `application.properties`/`.yml` (and the prod profile) are overridden through environment variables (Spring relaxed binding, MicroProfile names) to folders under `/data`. Credentials (passwords, secrets, JDBC URLs) become optional Secret references; a `${DB_PASSWORD}` placeholder references that variable. |
| Memory | `-XX:MaxRAMPercentage=75`, request 512Mi, limit 1Gi. |

**Node.js**

| | |
|---|---|
| Node.js line | the newest supported LTS line (22 or 24) that `engines.node` allows. |
| Install | `npm ci`, `pnpm install --frozen-lockfile` or `yarn install` (classic or Berry, with the `node-modules` linker) through corepack, at the workspace root. Packages with native addons build on the full Debian image (Python, make, g++). |
| Build | the `build` script of the package and of the in-repository packages it uses, dependencies first (pnpm orders a filtered run itself). devDependencies are pruned afterwards with npm and pnpm (not in pnpm or yarn workspaces, where that means a reinstall). |
| Start | the production start script (`start:prod`, `start`, ...), parsed without a shell: `node <file>`, a package's command (`next start`, resolved at build time to the file it runs), `nest start` and `nx serve` mapped to their compiled output. Without a start script: `server.js`, `main` or `index.js`. A start command that needs a shell runs with `npm run` on the slim image. |
| Runtime | distroless Node.js as uid 65532, `NODE_ENV=production`, `PORT=8080`, `HOST=0.0.0.0`. |
| Probes | a `/health`-style route on the application object, a NestJS Terminus controller; a TCP probe otherwise. |
| Configuration | variables listed in `.env.example` that hold credentials or connection URLs become Secret references; Windows paths in node-config files (`config/default.json`) are overridden with `NODE_CONFIG`. |

Single-page apps build with the repository's package manager and are served by unprivileged nginx.

## Verification

`containerizer verify` builds and runs Java and Node.js images hardened, as for .NET. Failure rules
in `rules/50-failures.yaml` recognise Java and Node.js build and start failures: a dependency that
needs a newer Java line, Maven version enforcement (the build switches to the Maven wrapper), a
lockfile out of sync, missing native toolchains, the V8 heap during builds, a devDependency needed at
run time, writes to read-only folders, and databases, brokers, config servers or variables that only
the real environment provides. Unknown failures go to the optional LLM, which gets a
language-specific evidence pack and plan vocabulary; what works is learned for review, as for .NET.

## Organisation runs

`containerizer org` treats Java and Node.js repositories like .NET ones: each buildable component
(a Maven or Gradle jar/war, a Node.js server or single-page app) gets its Dockerfile, hardened
manifests and GitOps entries. Repositories without .NET, Java or Node.js code are still skipped and say so.

## Validation corpus

`bench/realworld.yaml` holds 17 public Java (`jv-*`) and Node.js (`nd-*`) repositories, pinned to a
commit, with ratings and roles judged by reading each repository. Run them with
`python -m containerizer.realworld --root <dir> --clone jv-petclinic nd-ghost ...`.

15 of 17 match. The two misses are both rated A where B is right:

- Jenkins keeps jobs, configuration and build history in `JENKINS_HOME` through `java.io.File`
  helpers that no rule ties to persistent data.
- Ghost keeps uploaded themes, settings and logs in `content/` on local disk, while images can
  use its S3 adapter, so the object storage client hides the local state.

Images were built and run hardened (`verify`) for Spring PetClinic, Quarkus rest-heroes (Java 25),
PiggyMetrics account-service (Java 8), Halo, RealWorld Express (Nx), Node-RED, Uptime Kuma and the
React RealWorld single-page app; each either served or stopped only at a database or config server
it needs from the real environment. Taxonomy's build needs its runtime variables (reported as a
finding) and the NestJS RealWorld app fails on its own outdated dependencies.
