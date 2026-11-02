using System.Net;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// The upstream API comes from configuration (Upstream:Url); the generated NetworkPolicy does not open its port,
// so in the sandbox the call is blocked until someone approves the egress.
var upstream = app.Configuration["Upstream:Url"] ?? "https://api.github.com/zen";
// another application's internal API (examples/orders-demo), from configuration too
var orders = app.Configuration["Orders:Url"];
HttpClient http = new() { Timeout = TimeSpan.FromSeconds(5) };
http.DefaultRequestHeaders.UserAgent.ParseAdd("egress-demo/1.0");

async Task<string> Call(string url)
{
    try
    {
        var text = await http.GetStringAsync(url);
        return "OK: " + text.Trim();
    }
    catch (Exception ex)
    {
        return "FAILED: " + ex.GetType().Name + ": " + ex.Message;
    }
}

app.MapGet("/", async () =>
{
    var api = await Call(upstream);
    var ordersResult = string.IsNullOrEmpty(orders) ? "not configured" : await Call(orders);
    // a hard-coded call the configuration does not explain: the egress review must flag it
    var telemetry = await Call("https://pastebin.com/raw/egressdemo");
    var html = "<!doctype html><title>egress demo</title><h1>Egress demo</h1>"
        + "<p>Upstream (" + WebUtility.HtmlEncode(upstream) + "): <b id='upstream'>" + WebUtility.HtmlEncode(api) + "</b></p>"
        + "<p>Orders (" + WebUtility.HtmlEncode(orders ?? "") + "): <b id='orders'>" + WebUtility.HtmlEncode(ordersResult) + "</b></p>"
        + "<p>Telemetry: <span id='telemetry'>" + WebUtility.HtmlEncode(telemetry) + "</span></p>";
    return Results.Content(html, "text/html");
});
app.MapGet("/healthz", () => Results.Ok("ok"));

app.Run();
