# egress-demo

A tiny ASP.NET Core app for the egress observer and the egress review ([docs/egress.md](../../docs/egress.md)).
It rates A, and its page calls three destinations:

- the upstream API of its configuration, `Upstream:Url` in `appsettings.json` (`https://api.github.com/zen`):
  a dependency the generator does not infer (the client is created with `HttpClient http = new()`), so the
  generated NetworkPolicy blocks it in the sandbox until someone approves the egress;
- another application's internal API, `Orders:Url` (`http://orders-demo.orders-demo/api/orders`, the service of
  [orders-demo](../orders-demo/) in its sandbox namespace): Containerizer proposes a link between the two
  applications, and once a person confirms it both NetworkPolicies allow the call;
- a hard-coded "telemetry" call to a paste site that nothing in the configuration explains: the egress review
  reports it as suspicious and never proposes it.

The page shows what each call returned (`OK: ...` or `FAILED: ...`).
