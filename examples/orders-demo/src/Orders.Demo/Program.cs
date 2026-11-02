var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// A small internal API that another application (examples/egress-demo) calls through a configured URL.
app.MapGet("/api/orders", () => Results.Json(new { orders = 3, service = "orders-demo" }));
app.MapGet("/", () => "Orders API");
app.MapGet("/healthz", () => Results.Ok("ok"));

app.Run();
