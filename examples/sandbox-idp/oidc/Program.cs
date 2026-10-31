using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddAuthentication(o => { o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme; o.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme; })
  .AddCookie()
  .AddOpenIdConnect(o => builder.Configuration.Bind("OpenIdConnect", o));
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication(); app.UseAuthorization();
app.MapGet("/", (HttpContext ctx) => Results.Text("signed in as " + ctx.User.Identity!.Name + "\n" + string.Join("\n", ctx.User.Claims.Select(c => c.Type + "=" + c.Value)))).RequireAuthorization();
app.MapGet("/healthz", () => "ok");
app.Run();
