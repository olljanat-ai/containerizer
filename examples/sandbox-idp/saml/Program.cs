using Microsoft.AspNetCore.Authentication.Cookies;
using Sustainsys.Saml2;
using Sustainsys.Saml2.AspNetCore2;
using Sustainsys.Saml2.Metadata;
var builder = WebApplication.CreateBuilder(args);
var cfg = builder.Configuration;
builder.Services.AddAuthentication(o => { o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme; o.DefaultChallengeScheme = Saml2Defaults.Scheme; })
  .AddCookie()
  .AddSaml2(o => {
     o.SPOptions.EntityId = new EntityId(cfg["Saml2:EntityId"]);
     o.IdentityProviders.Add(new IdentityProvider(new EntityId(cfg["Saml2:IdpEntityId"]), o.SPOptions) { MetadataLocation = cfg["Saml2:IdpMetadata"], LoadMetadata = true });
  });
builder.Services.AddAuthorization();
var app = builder.Build();
app.UseAuthentication(); app.UseAuthorization();
app.MapGet("/", (HttpContext ctx) => Results.Text("signed in as " + ctx.User.Identity!.Name + "\n" + string.Join("\n", ctx.User.Claims.Select(c => c.Type + "=" + c.Value)))).RequireAuthorization();
app.MapGet("/healthz", () => "ok");
app.Run();
