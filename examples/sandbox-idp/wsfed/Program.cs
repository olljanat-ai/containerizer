using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.WsFederation;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(o => { o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme; o.DefaultChallengeScheme = WsFederationDefaults.AuthenticationScheme; })
  .AddCookie()
  .AddWsFederation(o => { o.MetadataAddress = builder.Configuration["WsFederation:MetadataAddress"]; o.Wtrealm = builder.Configuration["WsFederation:Wtrealm"]; });
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication(); app.UseAuthorization();
app.MapGet("/", (HttpContext ctx) => Results.Text("signed in as " + ctx.User.Identity!.Name + "\n" + string.Join("\n", ctx.User.Claims.Select(c => c.Type + "=" + c.Value)))).RequireAuthorization();
app.MapGet("/healthz", () => "ok");
app.Run();
