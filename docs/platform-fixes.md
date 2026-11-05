# Platform fixes for refactor findings

Containerizer's job is to move as many applications as possible into containers with as few application code
changes as possible. Some findings that look like code problems can be satisfied by the platform instead: a pod
setting, a volume, a Secret mounted where the runtime already looks. When such a **platform technique** applies,
the finding counts as `config` (the code stays as it is), the application's rating goes up, and the generated
`plan.json` and Dockerfile header say what was done and why.

## How a technique works

A plan rule in [`rules/40-plan.yaml`](https://github.com/olljanat-ai/containerizer/blob/main/rules/40-plan.yaml)
names the findings it satisfies with `resolves:`, and, when the configuration depends on the code, a `technique:`
implemented in `containerizer/techniques.py`. During the assessment, a finding that a technique resolves gets
`resolved_by` (shown in `assessment.json` with `rule_severity`, the rule's own severity) and counts as `config`.
A resolved finding is never sent to a refactoring ("Make it A"). During generation the rule's patch is applied;
`plan.json` lists it in `applied`, in `resolved` (rule → findings) and in `reasons`, and the Dockerfile header
carries the reason and references.

A technique only resolves a finding when the code is within its reach; otherwise the finding stays as it is, so a
rating never goes up for code the configuration cannot fix.

| Technique | Resolves | Generated configuration | Stays a finding when |
|---|---|---|---|
| `plan-machine-hostname` | `os-machine-name-switch` | `hostname:` in the pod spec, set to the host name the code compares `Environment.MachineName` with (a production-looking one when there are several; the others are listed in the reason) | the comparison is case-sensitive with an upper-case name (`== "PRODWEB01"`): Kubernetes host names are lower-case |
| `plan-x509-user-store` | `cert-store` | an optional Secret `<component>-x509-my` (External Secrets) mounted read-only at `/home/app/.dotnet/corefx/cryptography/x509stores/my`, where .NET on Linux reads `CurrentUser\My`: put each certificate in it as a **password-less `.pfx`** key (the name must end in `.pfx`) | the code opens a `LocalMachine` store other than Root/CA (`cert-store-localmachine-code`): it does not exist on Linux |
| `plan-special-folder-workdir` | `os-special-folder-windows` | a volume at `/app/<Folder>` for each `Path.Combine(GetFolderPath(ProgramFiles), "<Folder>", ...)`: `GetFolderPath` returns `""` for Windows-only folders on Linux, so the path is relative to the working directory `/app` | the folder is kept in a variable, joined with `\`, is a file name, or already ships with the app |

`LocalMachine\Root` and `LocalMachine\CA` need nothing: on Linux they are the image's CA bundle.

The three techniques were checked with [examples/platform-techniques](https://github.com/olljanat-ai/containerizer/tree/main/examples/platform-techniques):
the image Containerizer generates for it, run as uid 1654 with a read-only root file system and the generated
host name and mounts, takes the production branch, finds the certificate by subject name and reads the vendor
file; the same image without them does none of that. Without the techniques the example is rated B, with them A.

## Audit of the refactor rules

Every curated `severity: refactor` rule, classified (a test keeps this table complete):

- **platform**: generated configuration satisfies it; done by a technique above.
- **partial**: a platform mechanism exists for some cases or with a trade-off (an unpatched image, a sidecar,
  one replica); candidates for further techniques.
- **code-only**: no configuration reaches it on Linux (the component can still run in a Windows container where
  the rule says so).

`config` rules need no code change by definition; the generator already applies many of them automatically
(Kestrel endpoints, connection strings and secret settings from Secrets, Windows paths in configuration,
Serilog/NLog sinks, Data Protection keys, writable folders, wkhtmltopdf paths; see
[Techniques used to avoid application changes](overview.md#generated-output)), and the
others say in their `fix` what to set.

| Rule | File | Finding | Platform fix | Mechanism, or why not |
|---|---|---|---|---|
| `aspnetcore-on-netfx` | 10-runtime.yaml | ASP.NET Core 2.x app on .NET Framework | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `netfx-library` | 10-runtime.yaml | Shared library targets .NET Framework | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `core-windows-tfm` | 10-runtime.yaml | Windows-specific target framework (-windows) | partial | Build-stage retarget to plain `netX.0` (never in the repository) when no Windows-only API is called. |
| `linq-to-sql` | 10-runtime.yaml | LINQ to SQL | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `system-web-apis-in-core` | 10-runtime.yaml | System.Web HttpContext usage in .NET Core code | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `http-sys` | 10-runtime.yaml | HTTP.sys server | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `windows-service-netfx` | 10-runtime.yaml | Windows Service host (ServiceBase/Topshelf) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `system-drawing-core` | 10-runtime.yaml | System.Drawing on .NET 6+ | partial | On .NET 6 only: `System.Drawing.EnableUnixSupport` in runtimeconfig plus `libgdiplus`, on the unpatched .NET 6 image. Removed in .NET 7. |
| `java-process-windows-commands` | 12-java.yaml | Starts Windows programs (cmd, PowerShell, .exe) | partial | As `process-start-exe`: the Linux tool under the same name, when one exists. |
| `java-waffle-windows-auth` | 12-java.yaml | Windows integrated authentication with WAFFLE | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `java-unsupported-version` | 12-java.yaml | Java 7 or older | partial | Run on an archived JDK image of that line (unpatched), as done for out-of-support .NET. |
| `java-ee-application-server` | 12-java.yaml | Needs a full Jakarta EE application server (EJB, EAR) | partial | The vendor's Linux image (Open Liberty, WildFly, Payara) with the server configuration as files/env. |
| `java-vendor-app-server-api` | 12-java.yaml | Vendor application server APIs (WebLogic, WebSphere, JBoss) | partial | The vendor's Linux image of the same server, when the vendor publishes one. |
| `node-edge-dotnet` | 13-node.yaml | .NET code run in-process with Edge.js | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `node-windows-sspi` | 13-node.yaml | Windows integrated authentication (SSPI, NTLM) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `node-windows-registry` | 13-node.yaml | Reads or writes the Windows registry | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `node-windows-only-tools` | 13-node.yaml | Windows-only helper packages (printing, WMI, event log) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `node-windows-only-dependency` | 13-node.yaml | Dependency that installs only on Windows | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `node-process-windows-commands` | 13-node.yaml | Starts Windows programs (cmd, PowerShell, .exe) | partial | As `process-start-exe`: the Linux tool under the same name, when one exists. |
| `node-unsupported-version` | 13-node.yaml | Pinned to an end-of-life Node.js line | partial | Run on the archived Node.js image of that line (unpatched), as done for out-of-support .NET. |
| `node-sass-libsass` | 13-node.yaml | node-sass (LibSass) native build | partial | Build stage on a Node.js line that node-sass has binaries for; the runtime image is unaffected. |
| `pinvoke-kernel32` | 20-platform.yaml | Win32 kernel/OLE/system DLL native calls | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `native-dll-shipped` | 20-platform.yaml | Binary DLLs checked into the source tree | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `registry` | 20-platform.yaml | Windows Registry | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `eventlog-write` | 20-platform.yaml | Writes to the Windows Event Log | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `perf-counters` | 20-platform.yaml | Windows performance counters | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `wmi` | 20-platform.yaml | WMI | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `windows-service-control` | 20-platform.yaml | Controls Windows services | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `process-start-exe` | 20-platform.yaml | Starts Windows executables | partial | Install the Linux build of the tool under the same name on `PATH` (as done for wkhtmltopdf paths in configuration); a Windows-only tool cannot. |
| `efs-ntfs` | 20-platform.yaml | NTFS ACLs / EFS encryption | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `winrt-tfm` | 20-platform.yaml | Targets the Windows 10 SDK TFM (WinRT projections) | partial | As `core-windows-tfm`. |
| `supported-os-windows` | 20-platform.yaml | Code marked Windows-only by its authors | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `winforms-reference-library` | 20-platform.yaml | References Windows Desktop assemblies | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `windows-auth-iis` | 30-integration.yaml | Windows (Kerberos/NTLM) authentication | partial | Negotiate with a keytab (`plan-negotiate-krb5`) when the app registers the Negotiate handler; IIS-hosted Windows authentication itself needs code. |
| `active-directory-ds` | 30-integration.yaml | Active Directory via System.DirectoryServices | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `dpapi` | 30-integration.yaml | DPAPI (Windows data protection) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `cert-store-localmachine-code` | 30-integration.yaml | Code opens a LocalMachine certificate store that does not exist on Linux | code-only | LocalMachine\My does not exist on Linux (`X509Store.Open` throws); no folder or variable changes that. Windows container, or load from a file. (CurrentUser stores: `cert-store`, **done** by `plan-x509-user-store`.) |
| `conn-string-compiled-in` | 30-integration.yaml | Database connection string compiled into the code | partial | The server name can be resolved by an `ExternalName` Service or `hostAliases`; the credentials stay in the code (a secret in the image), which is the reason it stays refactor. |
| `msdtc` | 30-integration.yaml | Distributed transactions (MSDTC) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `sql-filestream` | 30-integration.yaml | SQL Server FILESTREAM / FileTable | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `ssrs-reportviewercore` | 30-integration.yaml | Local RDLC reports with ReportViewerCore.NETCore | partial | Fonts the reports use installed in a full image (an image change, no code); every report still needs a test run. |
| `ibm-i-access` | 30-integration.yaml | IBM i Access Client (cwbx/iSeries provider) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `msmq` | 30-integration.yaml | MSMQ | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `named-pipes` | 30-integration.yaml | Named pipes IPC | partial | .NET named pipes are Unix domain sockets under `/tmp` on Linux: two processes in one pod sharing `/tmp` work; pipes to another host (`\\server\pipe`) do not. |
| `os-drive-path-hardcoded` | 35-config-os.yaml | Windows drive paths hard-coded in code | code-only | On Linux `C:\data\x.txt` is one relative file name (with backslashes) in the working directory `/app`; no mount can give it folders. Windows container, or configuration in code. |
| `os-backslash-path-join` | 35-config-os.yaml | File paths built with backslashes | code-only | `\` is part of a file name on Linux; a case-insensitive or backslash-aware file system is not available to pods. |
| `os-special-folder-windows` | 35-config-os.yaml | Uses Windows-only special folders (Program Files, Windows, System32) | platform | **Done** (`plan-special-folder-workdir`): `GetFolderPath` is `""` on Linux, so `Path.Combine(GetFolderPath(ProgramFiles), "Acme", ...)` is `/app/Acme/...`; a volume is mounted there. Stays refactor when the folder is kept in a variable, joined with `\`, or ships with the app. |
| `os-drive-letters` | 35-config-os.yaml | Uses drive letters (DriveInfo("C"), GetLogicalDrives) | code-only | `DriveInfo("C")` / `GetLogicalDrives` have no drive letters to report on Linux. |
| `os-exe-location` | 35-config-os.yaml | Locates application files from the process executable | partial | Publish with the app host (`UseAppHost=true`) and start `/app/<App>` instead of `dotnet <App>.dll`, so the process executable is in the app folder. Proposed follow-up. |
| `os-machine-name-switch` | 35-config-os.yaml | Behaviour switched on the server's machine name | platform | **Done** (`plan-machine-hostname`): pod `hostname:` set to the name the code compares with. Stays refactor when the comparison is case-sensitive with an upper-case name (Kubernetes host names are lower-case). |
| `os-named-sync-objects` | 35-config-os.yaml | Named semaphores or wait handles | code-only | Named `Semaphore`/`EventWaitHandle` throw `PlatformNotSupportedException` on Linux (verified on .NET 10; same on every .NET Core line), so pinning the runtime image does not help. Named `Mutex` works (finding `os-named-mutex`, info). |
| `cfg-smtp-pickup-iis` | 35-config-os.yaml | Sends mail through the IIS SMTP pickup directory | partial | A sidecar that watches the pickup folder (shared `emptyDir`) and relays the `.eml` files over SMTP. Proposed follow-up. |
| `cfg-localhost-endpoint-in-code` | 35-config-os.yaml | Service endpoint on localhost hard-coded in code | partial | A sidecar proxy in the same pod listening on `localhost:<port>` and forwarding to the Service. Proposed follow-up. |
| `host-azure-functions-inprocess` | 35-hosting.yaml | Azure Functions in-process model | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `host-service-fabric-stateless` | 35-hosting.yaml | Service Fabric Reliable Services (stateless) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `host-app-service-easyauth` | 35-hosting.yaml | Relies on App Service Authentication (Easy Auth) | partial | An auth proxy at the ingress (oauth2-proxy) that sets the `X-MS-CLIENT-PRINCIPAL*` headers the app reads, and strips client-sent ones. |
| `host-aws-lambda-handler` | 35-hosting.yaml | AWS Lambda function handlers | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `host-orleans-localhost-clustering` | 35-hosting.yaml | Orleans localhost/development clustering only | partial | Works with exactly one replica (localhost clustering); more replicas need a clustering provider. |
| `mig-binaryformatter` | 35-migration.yaml | BinaryFormatter-family serializers | partial | Up to .NET 8: `EnableUnsafeBinaryFormatterSerialization` (runtimeconfig) on that runtime image; .NET 9+ removed it. A security trade-off, so not applied automatically. |
| `mig-javascriptserializer` | 35-migration.yaml | JavaScriptSerializer (System.Web.Extensions) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-thread-abort` | 35-migration.yaml | Thread.Abort / Suspend / Resume | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-delegate-begininvoke` | 35-migration.yaml | Asynchronous delegate invocation (BeginInvoke/EndInvoke) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-reflection-only-load` | 35-migration.yaml | Reflection-only assembly loading | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-codedom-compile` | 35-migration.yaml | Runtime compilation with CodeDom | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-xslt-script` | 35-migration.yaml | XSLT with embedded script blocks | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-crypto-pnse` | 35-migration.yaml | Windows CSP-only cryptography | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-oracleclient` | 35-migration.yaml | System.Data.OracleClient | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-http-modules-handlers` | 35-migration.yaml | Custom IIS/ASP.NET modules and handlers | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-session-out-of-proc` | 35-migration.yaml | Out-of-process ASP.NET session state (StateServer/SQLServer) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-system-web-cache` | 35-migration.yaml | System.Web cache (HttpRuntime.Cache / CacheDependency) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-membership-providers` | 35-migration.yaml | ASP.NET Membership / Role / Profile providers | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-apiauthorization-identityserver` | 35-migration.yaml | ASP.NET Core ApiAuthorization with IdentityServer (SPA template auth) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-wif` | 35-migration.yaml | Windows Identity Foundation (WIF) on System.Web | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-aspnet-signalr` | 35-migration.yaml | ASP.NET SignalR 2 (classic) server | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-asmx-client` | 35-migration.yaml | ASMX web reference client (SoapHttpClientProtocol) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-wcf-message-security` | 35-migration.yaml | WCF WS-* message security / reliable sessions | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-enterprise-library` | 35-migration.yaml | Microsoft Enterprise Library (Data/Logging/Exception Handling blocks) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-vb-compatibility` | 35-migration.yaml | VB6 compatibility libraries | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-vb-my-namespace` | 35-migration.yaml | VB.NET My namespace features unsupported on .NET Core | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-httpcontext-in-library` | 35-migration.yaml | HttpContext.Current in a shared library | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `mig-ef6-edmx` | 35-migration.yaml | Entity Framework EDMX designer model | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-activereports-legacy` | 35-vendor-packages.yaml | Old ActiveReports version (.NET Framework) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-stimulsoft-netfx` | 35-vendor-packages.yaml | Stimulsoft Reports .NET Framework edition | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-fastreport-gdi` | 35-vendor-packages.yaml | FastReport on System.Drawing | partial | As `system-drawing-core` (.NET 6 switch + libgdiplus). |
| `pkg-qrcoder-gdi` | 35-vendor-packages.yaml | QRCoder renderer drawing with System.Drawing | partial | As `system-drawing-core` (.NET 6 switch + libgdiplus). |
| `pkg-spire-netfx` | 35-vendor-packages.yaml | Spire.* (e-iceblue) on System.Drawing | code-only | .NET Framework edition; needs the .NET Standard package. |
| `pkg-imaging-sdk` | 35-vendor-packages.yaml | Commercial imaging/OCR SDK with native engine (GdPicture, LEADTOOLS) | partial | Linux native packages and fonts in the image, licence from a Secret; needs a Linux-capable release. |
| `pkg-desktop-ui-library-ref` | 35-vendor-packages.yaml | References WinForms/WPF component suite packages | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-web-ui-suite-systemweb` | 35-vendor-packages.yaml | Vendor controls for ASP.NET WebForms/MVC 5 (System.Web) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-windows-browser-engine` | 35-vendor-packages.yaml | Windows-only browser engine / HTML-to-PDF converter | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-telerik-documents-netfx` | 35-vendor-packages.yaml | Telerik Document Processing for .NET Framework | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-mschart` | 35-vendor-packages.yaml | Microsoft Chart Controls (MSChart / DataVisualization) | code-only | System.Web/WinForms chart controls. |
| `pkg-winrt-packages` | 35-vendor-packages.yaml | WinRT / Windows App SDK packages | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-system-speech` | 35-vendor-packages.yaml | System.Speech / Microsoft Speech Platform | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-web-administration` | 35-vendor-packages.yaml | Manages IIS (Microsoft.Web.Administration) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-taskscheduler-api` | 35-vendor-packages.yaml | Creates Windows scheduled tasks (TaskScheduler library) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-mmi-cim` | 35-vendor-packages.yaml | CIM/WMI through Microsoft.Management.Infrastructure | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-powershell-windows` | 35-vendor-packages.yaml | Hosts Windows PowerShell 5.1 | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-naudio-windows` | 35-vendor-packages.yaml | NAudio Windows audio APIs | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-windows-service-hosts` | 35-vendor-packages.yaml | Windows Service host library | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-winscp` | 35-vendor-packages.yaml | WinSCP .NET assembly | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-ews-managed-api` | 35-vendor-packages.yaml | Exchange Web Services (EWS) Managed API | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-sap-nco` | 35-vendor-packages.yaml | SAP .NET Connector (NCo) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-legacy-azure-servicebus` | 35-vendor-packages.yaml | Legacy Azure Service Bus SDK (WindowsAzure.ServiceBus) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-oracle-unmanaged` | 35-vendor-packages.yaml | Unmanaged ODP.NET (Oracle.DataAccess) | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-db2-netfx-provider` | 35-vendor-packages.yaml | IBM Db2 provider from the Db2 client install | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-sybase-ase` | 35-vendor-packages.yaml | SAP/Sybase ASE ADO.NET provider | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-informix` | 35-vendor-packages.yaml | IBM Informix .NET provider | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-pdfiumviewer` | 35-vendor-packages.yaml | PdfiumViewer | code-only | Replaces a Windows-only or removed API; no configuration reaches it (Windows container or code change). |
| `pkg-ghostscript-net` | 35-vendor-packages.yaml | Ghostscript.NET (native Ghostscript) | partial | Install `ghostscript` in the image; older wrappers need the library path from configuration. |
| `pkg-tesseract-native` | 35-vendor-packages.yaml | Tesseract OCR wrapper with Windows native DLLs | partial | Install `tesseract-ocr`/`leptonica` in the image; works when the wrapper can load the Linux libraries. |
