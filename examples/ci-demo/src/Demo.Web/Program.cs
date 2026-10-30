var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

app.MapGet("/", () => "Hello from a Linux container");
app.MapGet("/healthz", () => Results.Ok("ok"));

app.Run();
