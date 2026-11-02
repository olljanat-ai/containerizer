# Egress and network connectivity

The sandbox is isolated. Containerizer generates a default-deny NetworkPolicy for every component that opens
egress only on the ports it can infer from packages, code and configuration (a SQL Server client opens 1433, an
HTTP client 443 and 80, a configured `Server=db,14330` its port), and on the appliance nothing leaves the sandbox
at all unless an administrators' egress rule allows it (**Admin → Firewall**: its firewall drops everything else and
its DNS filter refuses every other name), whatever a NetworkPolicy says. A dependency of an application is then
blocked in the sandbox, and someone has to find out what the application needs, and write the real environment's
firewall rules for it.

Containerizer finds and documents it; agents only propose, people approve:

1. The **egress observer** records what the sandbox blocks, at every layer: the NetworkPolicies, the appliance's
   firewall and its DNS filter, with the name a pod looked up just before.
2. The **egress review** (an [LLM queue](scheduled-scans.md#the-llm-queue) job) looks at the new ones of
   applications rated **A** that run in the sandbox. A deterministic pre-filter decides first, then the LLM: is the
   destination named by the application's configuration or code (it quotes the file and line), and why does the
   application need it? It proposes, reports or flags it as suspicious.
3. Administrators, operators and the application's product owners **approve or reject** each proposal. Approving
   **documents** the destination for the real environment: the queue runner writes it to the application's
   **`connectivity.yaml`** in the output repository. It opens nothing in the sandbox.

[Links between applications](#links-between-applications) connect the components that call each other across
repositories and products; those calls stay inside the sandbox cluster, and a confirmed link opens them there.

**Network connectivity** brings everything together: on the application's results page as a diagram with the
details, and next to the manifests in the output repository as `connectivity.yaml`, `CONNECTIVITY.md` and
`connectivity.svg`, which the platform or firewall team uses to write the real environment's rules.

![The Network connectivity section of an application in the sandbox: the diagram, a suspicious paste site, a proposed API with its evidence, and Approve and Reject](images/results-connectivity-proposed.png#only-light){ .cz-shot }
![The Network connectivity section of an application in the sandbox: the diagram, a suspicious paste site, a proposed API with its evidence, and Approve and Reject](images/results-connectivity-proposed-dark.png#only-dark){ .cz-shot }

## Network connectivity

Every application has a **Network connectivity** section on its results page, whether it runs in the sandbox or
not. It shows what the application needs from the network, from every source, each marked by where it comes from:

| Source | What |
| --- | --- |
| Configuration, code | URLs and connection strings in the configuration (`appsettings.json`, `web.config`, `.properties`, `.yaml`, `.env`) and the code, with the file and line. Development settings, comments, documentation and schema URLs are left out. |
| Package | A dependency the generated NetworkPolicy opens a port for (a SQL Server client, an HTTP client, a message broker) when no configuration names its destination. |
| NetworkPolicy | What the generated policy allows: the inferred ports to any address but the blocked ranges, the application's own pods, DNS. |
| Lab service | The [lab services](lab-services.md) the components need. |
| Observed in the sandbox | Connections the sandbox blocked (the egress observer), with the dropped packets, when, and from which pods. |
| Approved | A destination a person approved for the real environment (documented; the sandbox stays as it is). |
| Ingress, service port | Who reaches the components: the sandbox HTTPS host, the service port. |

The diagram has the inbound side on the left, the components in the middle and the destinations on the right, one
line per connection, styled by its status:

| Status | Meaning |
| --- | --- |
| **Allowed** | The generated NetworkPolicy allows it. |
| **Approved (documented)** | A person approved it for the real environment after the egress review. The sandbox still blocks it unless its NetworkPolicy and, on the appliance, an egress rule allow it (the **Sandbox** column). |
| **Proposed** | The egress review proposes it: waiting for a person. |
| **Blocked** | The sandbox blocked it; not reviewed yet, or reported (nothing to propose: an IP address without a name, a platform service). |
| **Not allowed (will time out)** | The configuration or code names it, and nothing allows it. |
| **Suspicious** | The review flagged it (a paste or file-sharing site, a tunnel, a metadata endpoint, ...): never proposed. |
| **Rejected** | A person rejected it. |

The table under the diagram has the details: the component, the destination with port and protocol, the status,
the sources, why (the review's reason, or the dependency the policy opens the port for), the evidence (the quoted
lines, the flows and pods), **Sandbox** (below) and, for staff, Approve and Reject. A destination whose name the
appliance's DNS filter refused has no port (nothing was connected): it is shown with *port unknown*, or on the
entry of the same name that the configuration names with its port.

**Sandbox**: whether the sandbox can reach a destination, and what blocks it:

- the component's **NetworkPolicy**: it allows the ports the assessment inferred (and confirmed links), nothing else;
- on the appliance, its **egress rules** (Admin → Firewall: the system rules of the OS image and the administrators'
  rules, read from the same files, the same way as the firewall itself, and never changed from here): *allowed by*
  the rule that covers it, *refused by the appliance's DNS filter* (a name no rule covers), or *dropped by the
  appliance firewall* (an address or port no rule covers); in log mode everything is allowed and logged;
- without an appliance (a lab): *no appliance firewall (lab)*.

In the diagram, an allowed or approved destination the sandbox cannot reach is drawn with a thin dotted line.

**Findings** under the table point at what to look at:

- **Missing**: the configuration or code names a destination that nothing allows. The connection fails in the
  sandbox, and behind a default-deny firewall in the real environment, until a rule allows it.
- **Unexplained**: a port the NetworkPolicy opens to any address for a package or code pattern, but no configuration
  names a destination on it; or an approved destination that the configuration no longer names. Keep it only if the
  application needs it.

An application that is not in the sandbox (yet) shows what the assessment inferred, and says that nothing was
observed. Assessments made before this version have no inferred network: scan the application again.

## The egress observer

`containerizer egress-observe` runs on the sandbox node. It is deterministic: no LLM.

- **What it reads**, the three places the sandbox blocks a connection:
  - **NetworkPolicies.** k3s's network policy controller (kube-router) logs every packet a NetworkPolicy drops to the
    netlink log group 100 with the prefix `DROP by policy <namespace>/<policy>`, at most **10 packets a minute per
    policy**. The observer binds to that group (NFLOG over a `NETLINK_NETFILTER` socket, no packages and no tcpdump),
    asks for the first 128 bytes of each packet and reads the IPv4 or IPv6 header and the TCP or UDP ports. Nothing
    else of the packet is kept. A drop of a cluster address on port 53 is the controller catching up with a pod that
    just started (every generated policy allows the cluster's DNS): it is left out.
  - **The appliance firewall.** Its egress chain logs what it drops to the kernel log
    (`cz-egress-drop: IN=cni0 OUT=eth0 ... SRC=<pod> DST=<address> ... PROTO=TCP ... DPT=443`, at most 30 a minute).
    The observer reads those lines from `/dev/kmsg` (`--kernel-log`), takes the ones whose source is an application
    pod (looked up across the application namespaces) and ignores the rest.
  - **The appliance's DNS filter.** It refuses every name no egress rule covers; CoreDNS passes the refusal on and
    logs it. A name an application pod asked for and was refused is a blocked destination by itself, with no port
    (nothing was connected).
- **Egress only.** A drop counts when its source is a pod of the namespace; a drop of a pod's incoming traffic is
  not a dependency. Drops in the platform's namespaces (`kube-system`, `flux-system`, `containerizer-*`, ...) are
  left out.
- **Names.** CoreDNS logs every query (`log` in the `coredns-custom` ConfigMap: the appliance ships it, the lab script
  turns it on). The observer follows that log and remembers which names each pod looked up in the last 10 minutes.
  When a pod's connection to an address is dropped, the address is matched to a name the same pod, or another pod
  of the namespace, looked up: the observer resolves those names (through the cluster's DNS on the appliance) and
  takes the one that resolves to the address. A destination without such a name stays an IP address, which the
  review reports and never proposes. An address a named flow had is explained by it and left out.
- **Which pod.** The pods of the namespace through the Kubernetes API (address, pod name, the component from its
  `app.kubernetes.io/name` label).
- **Stored** every minute in the results database, added up per namespace, component, destination, port and
  protocol: the dropped packets, first and last seen, a few pods, the policy, and the layer that blocked it
  (`network-policy`, `appliance-firewall`, `dns-filter`; `cz.EgressFlow`, through the
  procedure `cz.RecordEgressFlow`, with the scanner's writer login). Because kube-router logs at most 10 packets a
  minute per policy, the count is a lower bound.
- **Which application.** A namespace belongs to the application whose sandbox check last read it, or to the "Make
  it A" order whose [sandbox variant](refactoring.md#the-sandbox-variant) runs in it (`cz.vSandboxNamespace`).

`--dry-run` prints each blocked connection (with its layer) and stores nothing:

```sh
sudo -E containerizer egress-observe --dry-run --kubeconfig ~/.kube/config --seconds 60
```

### On the appliance

`containerizer-egress-observer.service` runs it with the least it needs:

- **User** `containerizer`, not root, with two capabilities: **CAP_NET_ADMIN**, which binding to an NFLOG group needs
  (the socket only reads), and **CAP_SYSLOG**, which reading the kernel log needs (`kernel.dmesg_restrict=1`): the
  appliance firewall's drops. Of the devices, only `/dev/kmsg` is visible (read only); `ProtectKernelLogs` is off for
  that reason, since it would hide it. `NoNewPrivileges`, a read-only system, no home directories, and only the address
  families it uses (netlink, IPv4, IPv6, Unix). It changes no firewall rule.
- **Kubernetes**: its own ServiceAccount, `containerizer-egress-observer` (in `containerizer-verify`), with get and
  list on pods and get on `pods/log` in `kube-system` (the CoreDNS query log) and get and list on pods in every
  namespace Containerizer generated. No Secrets, no write verbs, nothing cluster-wide. `cz-sandbox` applies the Roles
  every 2 minutes and writes the kubeconfig (`/run/containerizer/egress-observer.kubeconfig`, `root:containerizer`
  0640, a 24-hour token renewed every 12 hours).
- **CoreDNS query log**: `/var/lib/rancher/k3s/server/manifests/containerizer-coredns-log.yaml` (the `coredns-custom`
  ConfigMap, `log.override`). The log has the names pods look up and their addresses in the cluster, no answers and
  no payloads; it stays in the cluster's log (`kubectl -n kube-system logs`).
- **Database**: the scanner's writer login (`cz.RecordEgressFlow`).

### In the lab

```sh
ci/lab-sandbox/egress-observer.sh install    # Roles and kubeconfig, CoreDNS query log, systemd unit lab-egress-observer
ci/lab-sandbox/egress-observer.sh remove
```

The unit runs as the lab user with CAP_NET_ADMIN only, writes to the lab's results database with the scanner login
(`results/.env`) and restarts every 12 hours with a fresh token; `sync.sh` gives it the Roles of new namespaces. The lab
has no appliance firewall or DNS filter: only NetworkPolicy drops are seen there.

## The egress review

The LLM queue runner looks for new blocked flows every minute (part of its housekeeping, with the job kind `egress`;
`containerizer llm-queue --kinds` chooses the kinds a runner takes). A flow is new when no decision exists for its
application, component, destination, port and protocol. Only applications rated **A** whose namespace is healthy
in the sandbox, and "Make it A" variants that run, are reviewed.

**The pre-filter** decides first and is never overruled by the LLM. Its lists are in
[`rules/60-security.yaml`](https://github.com/olljanat-ai/containerizer/blob/main/rules/60-security.yaml)
(`network.egress_review`):

| Verdict | When |
| --- | --- |
| Suspicious | A metadata endpoint or one of the `blocked_cidrs` (169.254.169.254, ...), a wildcard name, a paste, file-sharing, tunnelling or request-capture service (`suspicious_domains`: pastebin, transfer.sh, ngrok, webhook.site, ...) |
| Reported: platform | A drop in a platform namespace, a service of the cloud platform (`platform_domains`: Key Vault, the container registry, ...) |
| Reported: IP address | No pod of the namespace looked the address up by name |
| Reported: in the cluster | A pod or service address of the cluster (a call to another namespace: allow it with a NetworkPolicy, not egress) |
| Reported: unusual port | A port that is not in `ports` (443, 80, the usual database and broker ports, ...): a person decides |

**The LLM** gets the rest, one job per application (at most 10 destinations a call): each destination with its
port, protocol, component, the dropped packets and when, the pods, and the lines of the application's source that
name it, from the **assessed commit** (the source is loaded as for a [refactoring patch](refactoring.md): the scan
worker's clone). Without the source, the lines the assessment recorded. It answers per destination, in a fixed JSON
schema:

```json
{"destinations": [{"destination": "api.github.com", "port": 443, "verdict": "propose",
  "reason": "The application configures its upstream API URL (Upstream:Url) ...",
  "file": "src/Egress.Demo/appsettings.json", "line": 4, "quote": "\"Upstream\": { \"Url\": \"https://api.github.com/zen\" }"}]}
```

- **propose**: the configuration or code names it, or it is an ordinary public API the application plainly uses
  with a steady flow;
- **report**: nothing explains it, or a person should decide;
- **suspicious**: exfiltration, command and control, a hard-coded destination unrelated to what the application does.

The answer is checked: a quoted line must be in the source (near the line it names), else the evidence is dropped
and the reason says so; a proposal with no such line and fewer than 3 dropped packets is reported instead. A
destination the LLM did not answer for is reported. The job goes through the queue's
[approval policy](scheduled-scans.md#the-llm-queue) like the other kinds (`egress` in *Jobs that wait for approval*).

## Approving

**Admin → Egress** lists the decisions of the applications one may decide for, open ones first; the results page
has the same buttons in its Network connectivity table.

![Admin → Egress: a suspicious paste site, an IP address without a name, and an approved API with who approved it and the commit](images/admin-egress.png#only-light){ .cz-shot }
![Admin → Egress: a suspicious paste site, an IP address without a name, and an approved API with who approved it and the commit](images/admin-egress-dark.png#only-dark){ .cz-shot }

| Role | Approve, Reject |
| --- | --- |
| Administrator, Operator | Every application |
| Product owner | The applications of their products |
| Viewer, anyone without sign-in | Sees the decisions, not the buttons |

- **Approve** is possible for named destinations the review proposed or reported, never for suspicious ones, the
  platform's or IP addresses. A rejected proposal can be approved later.
- **Reject**: connectivity.yaml records the decision.
- An approved destination stays approved: Containerizer never rewrites or removes it. To take one back, remove it
  from connectivity.yaml in a commit of your own.

Every decision records who made it and when (`DecidedBy`, `DecidedAt`, and the change history).

### What approving changes

**Approving documents; it opens nothing.** Within a minute the LLM queue runner, which holds the output repository's
write token (the one registered for the organization scan's output repository, as for
[sandbox variants](refactoring.md#the-sandbox-variant)), commits the application's `connectivity.yaml`,
`CONNECTIVITY.md` and `connectivity.svg` with the approved destination: the FQDN, port and protocol, why, the
evidence and who approved it. That is what the real environment's firewall rules are written from.

The sandbox stays isolated. The NetworkPolicies keep allowing only what the assessment inferred, and on the
appliance only the administrators' egress rules let anything out of the sandbox. If an application must reach a
destination in the sandbox too, an administrator adds an egress rule on **Admin → Firewall**; the **Sandbox**
column then shows the rule (the NetworkPolicy still has to allow the port: it allows the inferred ones).

![After approving: the API is approved for the real environment, with who approved it; the paste site stays suspicious](images/results-connectivity-approved.png#only-light){ .cz-shot }
![After approving: the API is approved for the real environment, with who approved it; the paste site stays suspicious](images/results-connectivity-approved-dark.png#only-dark){ .cz-shot }

Later organization scans keep approved entries: the generator reads the application's connectivity.yaml from the
output repository and the new connectivity.yaml keeps every approved entry as it was (its sandbox status is
computed again). A sandbox variant takes the original's. New decisions (also reported and suspicious ones) and
rejections are written to connectivity.yaml the same way.

## connectivity.yaml

Next to the application's manifests in the output repository (`<Org>/<Project>/<Repo>/connectivity.yaml`), written by
every organization scan with the manifests, and refreshed by the queue runner when there are new decisions,
approvals or rejections. `CONNECTIVITY.md` is the same as a page, with the diagram (`connectivity.svg`, light and
dark).

```yaml
apiVersion: containerizer.eu/v1
kind: Connectivity
application: egress-demo
namespace: egress-demo                # in the sandbox
generatedAt: '2026-11-02T03:45:01Z'
observed: true                        # false: inferred only, nothing observed in the sandbox
note: Approved destinations are documented for the real environment ...
components:
- {name: egress-demo, component: Egress.Demo, role: web, port: 8080, service_port: 80}
inbound:
- {component: egress-demo, from: 'https://egress-demo.sandbox.lab.test/', port: 80, protocol: TCP, source: ingress, target_port: 8080}
- {component: egress-demo, from: any namespace (Service), port: 80, protocol: TCP, source: service, target_port: 8080}
internal: []                          # component to component, lab services
outbound:
- component: egress-demo
  destination: api.github.com
  type: fqdn                          # fqdn, ip, any (a port open to any address), component (another application)
  port: 443
  protocol: TCP
  status: approved                    # allowed, approved, proposed, blocked, not-allowed, suspicious, rejected, reported
  sources: [config, observed, approved]
  reason: The application configures its upstream API URL ...
  evidence:
  - {file: src/Egress.Demo/appsettings.json, line: 4, quote: '"Upstream": { "Url": "https://api.github.com/zen" }'}
  observed: {packets: 3, first_seen: '2026-11-02T03:38:59Z', last_seen: '2026-11-02T03:38:59Z', pods: [...], ips: [140.82.121.6]}
  approved_by: john.doe@example.com
  approved_at: '2026-11-02T03:43:46Z'
  blocked_by: [network-policy]        # the layers the sandbox blocked it at: network-policy, appliance-firewall, dns-filter
  sandbox:                            # whether the sandbox can reach it (computed on every write)
    network_policy: blocks port 443
    appliance: 'refused by the appliance''s DNS filter: no egress rule allows it'   # lab: no appliance firewall (lab)
    reachable: false
    blocked_by: network-policy
- component: egress-demo
  destination: orders-demo.orders-demo     # as the configuration names it
  type: component                          # another application's component (links between applications)
  port: 80
  protocol: TCP
  status: linked                           # linked, link-proposed
  sources: [config, link-config]
  target: {application: orders-demo, application_id: 1011, component: orders-demo, namespace: orders-demo,
           service: orders-demo.orders-demo.svc.cluster.local, port: 8080}
  link: {id: 1, status: confirmed, method: config, confidence: 0.95, reason: the configuration names ...}
  linked_by: john.doe@example.com
  linked_at: '2026-11-02T04:12:59Z'
- component: egress-demo
  destination: pastebin.com
  type: fqdn
  port: 443
  protocol: TCP
  status: suspicious
  category: file-sharing
  sources: [code, observed]
  reason: pastebin.com is a paste, file-sharing, tunnelling or request-capture service ...
findings:
- {kind: unexplained, component: ..., text: ...}
```

| Field | Meaning |
| --- | --- |
| `outbound[].destination`, `port`, `protocol` | What a firewall rule needs. `type: any` is a port the generated policy opens to any address (a package needs it; name the destination for production). |
| `status` | As on the results page (table above). `approved` entries are never rewritten or dropped by Containerizer. |
| `sources` | `config`, `code`, `package`, `policy`, `observed`, `approved`, `lab-service`. |
| `evidence` | The lines that name the destination (file, line, the line itself). |
| `observed` | What the sandbox blocked: dropped packets (a lower bound), first and last seen, pods, addresses. |
| `blocked_by` | The layers the sandbox blocked it at: `network-policy`, `appliance-firewall`, `dns-filter`. |
| `sandbox` | Whether the sandbox can reach it: what its NetworkPolicy does, the appliance's egress rule that allows it (`rule`) or what blocks it (`blocked_by`), `reachable`. |
| `port_unknown` | The appliance's DNS filter refused the name, so no port was seen and the configuration names none (`port: 0`). |
| `approved_by`, `approved_at`, `rejected_by`, `rejected_at` | Who decided, when. |
| `inbound`, `internal` | Who reaches the components (the Ingress host, the service port, and confirmed callers from other applications: `source: link`, with their application, component and namespace), component to component and lab services. |
| `target` (`type: component`) | The other application's component a destination is: application, component, namespace, service name and container port. |
| `findings` | `missing` and `unexplained`, as on the results page. |

## Links between applications

A real application is often several Containerizer applications: components in different repositories, owned by
different teams or products, calling each other. An outbound destination can then be **another component assessed
here**, and connectivity says so: the destination is linked to that component (`type: component` in
connectivity.yaml), the diagram draws it as a teal box with the other application's name, and the table links to
its page.

![A link to another application: egress-demo calls orders-demo through a configured URL, linked and allowed in both NetworkPolicies](images/results-connectivity-linked.png#only-light){ .cz-shot }
![A link to another application: egress-demo calls orders-demo through a configured URL, linked and allowed in both NetworkPolicies](images/results-connectivity-linked-dark.png#only-dark){ .cz-shot }

**How links are found** (`cz.ComponentLink`, every minute by the LLM queue runner's housekeeping), each recorded with
how it was found and its evidence:

| Found by | When |
| --- | --- |
| Configuration matches (`config`) | A configured host is another application's component: its service in the sandbox (`<component>.<namespace>`, `...svc`, `...svc.cluster.local`) or its sandbox Ingress host. Confidence 0.95. |
| Observed in the sandbox (`observed`) | The sandbox blocked a call from one application's pod to another application's pod (the observer names such a destination `<component>.<namespace>.svc.cluster.local`). Not recorded again when the configuration already links it. |
| LLM (`llm`) | A configured destination that looks internal (one label, or `.local`, `.internal`, `.corp`, `.lan`, `.intranet`, `.svc`, ...) and that nothing matched. A `link` job of the [LLM queue](scheduled-scans.md#the-llm-queue) (with its approval policy) gives the LLM the destination, its configuration lines and a shortlist of 15 candidate components of other applications (name, application, product, project, role, repository) and asks for the best match, its confidence and why, or none. Answers below 0.5 or outside the shortlist are not taken. |
| By hand (`manual`) | **Link manually** on the results page: pick one of the components assessed here. |

Every link is a **proposal** until a person confirms it: **Confirm** and **Reject** on the calling application's
results page, for administrators, operators and the calling application's product owners; a link made by hand is
confirmed at once. A destination that looks internal and is not linked shows as *Looks internal, not linked*, with
*Link manually*. Every decision is recorded with who made it (and in the change history).

**A confirmed link** is written by the queue runner to **both** applications in the output repository, in one commit:

- the caller's connectivity.yaml names the other application, component, namespace, service and port
  (`type: component`, `target`), and the caller's NetworkPolicy gets an egress rule to that namespace and those pods
  on the component's container port;
- the callee's connectivity.yaml lists the caller under `inbound` (`source: link`), and its NetworkPolicy gets an
  ingress rule from the caller's namespace and pods.

Later scans keep both (the generator reads them from connectivity.yaml), as they keep approved egress.

The callee's page shows its callers:

![The called application's page: its callers from other applications under Inbound](images/results-connectivity-callee.png#only-light){ .cz-shot }
![The called application's page: its callers from other applications under Inbound](images/results-connectivity-callee-dark.png#only-dark){ .cz-shot }

**How the applications connect** (`/connectivity`, linked from each application's section; `?product=<id>` or
`?bu=<id>` for one product or business unit): the applications as groups of their components, the links between them
(confirmed solid, proposed dashed), each application's decided outbound destinations summed up, and the links in a
table. The other side of a link outside the product is shown too, with a dashed frame.

![How the applications connect: two applications, their components and a confirmed link](images/connectivity-portfolio.png#only-light){ .cz-shot }
![How the applications connect: two applications, their components and a confirmed link](images/connectivity-portfolio-dark.png#only-dark){ .cz-shot }

## Limits

- **Only what is blocked is seen.** The observer reads the drop log; allowed traffic is not recorded, so
  Containerizer cannot tell whether an allowed or approved destination is still used.
- **Names come from DNS.** A connection to an address no pod of the namespace looked up (a hard-coded IP, a name
  looked up more than 10 minutes before, a DNS-over-HTTPS client) stays an address. Shared CDN addresses can serve
  several names; the observer takes the name the namespace's own pods looked up.
- **Rate limit.** kube-router logs at most 10 packets a minute per policy: a burst is counted as at most 10.
- **The LLM can be wrong.** It only proposes; the quoted line is checked against the source, and a person approves.
- **The appliance's signals are rate limited too**: its firewall logs at most 30 drops a minute.
- **Approval is documentation.** It never changes the sandbox: a destination an application needs in the sandbox
  as well needs an administrators' egress rule (and a port its NetworkPolicy allows).
