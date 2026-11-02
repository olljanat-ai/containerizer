# egress-demo

A tiny ASP.NET Core app for the egress observer and the egress review ([docs/egress.md](../../docs/egress.md)).
It rates A, and its page calls two HTTPS destinations:

- the upstream API of its configuration, `Upstream:Url` in `appsettings.json` (`https://api.github.com/zen`):
  a dependency the generator does not infer (the client is created with `HttpClient http = new()`), so the
  generated NetworkPolicy blocks it in the sandbox until someone approves the egress;
- a hard-coded "telemetry" call to a paste site that nothing in the configuration explains: the egress review
  reports it as suspicious and never proposes it.

The page shows what each call returned (`OK: ...` or `FAILED: ...`).
