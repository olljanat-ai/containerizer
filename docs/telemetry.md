---
title: A+ and OpenTelemetry
description: Make it A+ instruments an application rated A with OpenTelemetry in the sandbox, without a code change, and Grafana shows its traces, metrics and logs.
---

# A+: OpenTelemetry for the applications rated A

**A+** is an application that rates **A** and whose OpenTelemetry telemetry is collected: its traces, metrics and
logs arrive at the sandbox's collector, and Grafana shows them. **Make it A+** gets an A application there without a
code change, without the LLM and without a build.

A+ is shown in place of A (the front page, the application's results page); it is not a sixth rating. The rules
still rate the application A, and an application that stops rating A is no longer A+. The
[trends page](index.md) counts it within A and shows how many of the A are A+: an application that is A+ now
counts as A+ from the day its telemetry first arrived.

![The results page of an A+ application: the badge, and the OpenTelemetry box with its instrumented component](images/results-make-it-a-plus.png#only-light){ .cz-shot }
![The results page of an A+ application: the badge, and the OpenTelemetry box with its instrumented component](images/results-make-it-a-plus-dark.png#only-dark){ .cz-shot }

## Make it A+

Only administrators order it, and only for an application whose latest assessment rates A (make a B application
A first: [Make it A](refactoring.md#make-it-a)).

- **One application:** the **OpenTelemetry** box on its results page has the button **Make it A+**.
- **Many at once:** Admin → **Make it A+** lists every application rated A with its state. The ones without
  OpenTelemetry are ticked; **Make it A+: the ticked applications** orders them. Nothing is ordered by opening the
  page. Admin → Refactoring links here too.

![Make it A+: every A application, with the state of each](images/admin-make-it-a-plus.png#only-light){ .cz-shot }
![Make it A+: every A application, with the state of each](images/admin-make-it-a-plus-dark.png#only-dark){ .cz-shot }

The order is a switch on the application (the change history records who turned it). The LLM queue runner applies
it within a few minutes, the way it applies [debug mode](scheduled-scans.md#debug-mode): it writes patches into the
sandbox's copy of the application's Flux Kustomization (`<app>/gitops/sandbox/`), in one commit, and Flux rolls
the pods over once. The application's own folder does not change, so the other
[clusters](clusters.md) of the output repository deploy it as before. **Turn it off** on the results page takes the
patches out again.

A scan that deploys the application again keeps the instrumentation: every writer of `clusters/sandbox/` knows the
switch.

## What is injected

What the [OpenTelemetry Operator](https://opentelemetry.io/docs/platforms/kubernetes/operator/automatic/) injects,
written out as patches, so the cluster needs no operator and no admission webhook. For each Deployment,
StatefulSet and CronJob of a component:

- an **init container** that copies the agent of the component's runtime into an `emptyDir` (the operator
  project's auto-instrumentation image, pinned by digest; non-root, read-only root filesystem, no capabilities);
- the **environment** that loads the agent, added to what the image and the manifest set already
  (`JAVA_TOOL_OPTIONS`, `NODE_OPTIONS` and `PYTHONPATH` keep their values);
- **where to send** and as what: `OTEL_EXPORTER_OTLP_ENDPOINT` (the sandbox's collector, OTLP over HTTP),
  `OTEL_SERVICE_NAME` (the component) and `OTEL_RESOURCE_ATTRIBUTES` (`service.namespace` and
  `k8s.namespace.name`: the application's namespace; the pod and the container);
- one more egress rule in the component's **NetworkPolicy**: the collector's pods, port 4318. Nothing else opens.

The runtime is read from the image the component runs on (the last `FROM` of its generated Dockerfile). An
application [moved from another platform](platform-migration.md) runs its own image: the scan notes what the
repository's Dockerfile builds on (through its stage names and `ARG` defaults, with the `ENV` it sets), or the
image it mirrors. For one moved before 0.53.2 that was built from its own Dockerfile, this is known from the next
scan.

| Runtime | Agent | Instrumented |
| --- | --- | --- |
| .NET | OpenTelemetry .NET automatic instrumentation 1.19 | .NET 8, 9 and 10 |
| Java | OpenTelemetry Java agent 2.33 | Java 8 and later (Temurin, distroless, Tomcat) |
| Node.js | `@opentelemetry/auto-instrumentations-node` 0.83 | Node.js 22 and later |
| Python | `opentelemetry-distro` 0.66 | Python 3.10 and later |

Other cases:

- **Its own SDK.** A component whose code already has the OpenTelemetry SDK (a package such as
  `OpenTelemetry.Extensions.Hosting`, `@opentelemetry/sdk-node`, `opentelemetry-sdk`,
  `go.opentelemetry.io/otel/sdk`) gets the environment and the NetworkPolicy rule, and no agent. This is known
  from the next scan that deploys it; until then a .NET, Java, Node.js or Python component gets the agent.
- **Go.** OpenTelemetry has no agent for a Go binary that runs under the sandbox's restrictions. Add the SDK to
  the code; the component then counts as instrumented.
- **A runtime the agent does not support** (.NET 6, Node.js 20, ...) is left as it is.
- **Alpine images** of .NET and Python are left as they are: the injected agents are built for glibc. Java and
  Node.js are instrumented on Alpine too.
- **Static files** (a single-page application served by nginx) run no code of the application: left as they are,
  and they do not keep the application from A+.

The agents, their images, the versions and the packages that mean "its own SDK" are data:
[`rules/65-telemetry.yaml`](https://github.com/olljanat-ai/containerizer/blob/main/rules/65-telemetry.yaml).

## When it is A+

The OpenTelemetry box says where the application is:

| State | Means |
| --- | --- |
| **Ordered** | The queue runner has not written the patches yet (a few minutes). |
| **Instrumented** | The patches are in the sandbox; nothing has arrived yet. A pod sends its first metrics half a minute after it starts. |
| **A+** | Every component that runs code is instrumented, and the application's telemetry arrives. |
| **No telemetry** | It arrived before and stopped: the pods do not run (see the Sandbox column), or the agent keeps the component from starting. |
| **Partly instrumented** / **Not instrumented** | A component cannot be instrumented; the table says which and why. The others send. |
| **Not in the sandbox** | The application has no folder in the output repository (not deployed, or its sandbox is turned off). |

Whether telemetry arrives is measured, not assumed: the queue runner asks Prometheus which services of the
application's namespace have a series (`CONTAINERIZER_TELEMETRY_PROMETHEUS`; on the appliance
`http://127.0.0.1:9090`). Without a Prometheus to ask (the setting is empty), an instrumented application counts as
A+ and the box says that it is not checked.

## Grafana

The appliance's sandbox cluster runs what receives the telemetry, in the namespace `cz-monitoring`
(`containerizer-telemetry.yaml`, applied by k3s at every start):

- an **OpenTelemetry Collector** (`otel-collector`, OTLP on 4318 and 4317). It leaves the kubelet's health
  probes out of the traces and makes request metrics from the spans (rate, errors, duration by service and
  operation);
- **Tempo** for the traces and **Loki** for the logs, 7 days each, on volumes of the persistent partition;
- the metrics go to the appliance's **Prometheus** (job `sandbox-telemetry`), each series with its application
  (`k8s_namespace_name`) and component (`service_name`).

Grafana (`https://<appliance>/grafana/`) has the data sources **Tempo** and **Loki** next to Prometheus, and the
dashboard **Containerizer: application telemetry**: which applications and services send, their request rate,
errors and duration, the latest traces and the logs. A trace opens with its spans, a span links to its log lines,
and a log line with a trace links back. **HTTP status (traces)** at the top keeps the traces with a span that
answered with that status: a class (2xx, 3xx, 4xx, 5xx, 4xx and 5xx) or one of the common codes (404, 500, ...);
a row of *Recent traces* opens to the matching spans with their status. The rows are *Who sends telemetry*, *Traces and logs* and *Requests (from the
traces)*.

Every application's results page has a **Grafana** line with links that set the dashboards' filters to that
application: **its pods in the sandbox** (the k3s dashboard, for its namespaces) and, with OpenTelemetry on, **its
traces, metrics and logs** (this dashboard, for its namespace). Everyone sees the links when Grafana is read
without sign-in ([the appliance's default](appliance-admin.md#metrics)), else administrators and operators.

![Grafana: the application telemetry dashboard](images/grafana-telemetry-dashboard.png#only-light)
![Grafana: the application telemetry dashboard](images/grafana-telemetry-dashboard-dark.png#only-dark)

## Another collector

The instrumented workloads send to `http://otel-collector.cz-monitoring.svc.cluster.local:4318`.
`CONTAINERIZER_OTLP_ENDPOINT` in the queue runner's and the scan worker's environment (`worker.env` on the
appliance) names another one; the NetworkPolicy rule still opens the collector of `rules/65-telemetry.yaml`
(`collector.namespace`, `pod_labels`, `port`), so change those with it.

## Limits

- **The sandbox only.** The patches are on the sandbox's copy of the application. For another cluster, the same
  environment and init container work with that cluster's collector; the OpenTelemetry Operator does the same from
  an annotation.
- **An application in its own output repository** ([clusters](clusters.md)) has no components in the scan's
  output repository: it is reported as *not in the sandbox* and is not instrumented.
- **Memory.** An agent needs memory of its own (the Java agent the most). The limits are not raised: a component
  that is killed for memory after Make it A+ shows as failing in the Sandbox column, and **Turn it off** brings it
  back.
- **.NET.** Native AOT and self-contained applications are not instrumented by an injected agent; the generated
  images are neither. Only one CLR profiler can be attached: a component with another APM agent keeps that one.
- **Node.js.** Applications written as ES modules (`import`) are instrumented through Node's loader hook
  (`--experimental-loader`, which prints an *ExperimentalWarning* at start). **Logs** arrive only from a logging
  library the agent knows (winston, pino, bunyan): what the application writes with `console.log` stays in the
  pod's log and is not in Grafana's *Logs*.
- **Python.** The agent's packages are put on the application's path; an application that pins an incompatible
  version of one of them (`protobuf`, `requests`, ...) can fail to start.
- **Checked here:** the .NET agent on the generated (chiseled, read-only, non-root) image in a k3s cluster, and
  the Python agent on a generated Flask image; the Node.js agent with a small HTTP server on Node.js 22 and 24
  (CommonJS and ES modules: traces and metrics); the Java agent is configured as the operator does and was not run
  against an application.
