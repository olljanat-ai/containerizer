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
