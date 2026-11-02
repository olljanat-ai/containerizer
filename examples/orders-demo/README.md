# orders-demo

A small internal API (`GET /api/orders`) for the links between applications (docs/egress.md#links-between-applications).
It is its own application, in its own repository in a real organization; [egress-demo](../egress-demo/) calls it
through a configured URL (`Orders:Url`, `http://orders-demo.orders-demo/api/orders`: the service `orders-demo` in
the sandbox namespace `orders-demo`). Containerizer matches that name to this application's component and proposes
the link; once a person confirms it, both applications' NetworkPolicies allow the call.
