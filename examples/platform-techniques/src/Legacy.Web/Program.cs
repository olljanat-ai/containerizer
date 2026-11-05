using System.Security.Cryptography.X509Certificates;

var app = WebApplication.CreateBuilder(args).Build();

app.MapGet("/healthz", () => "ok");
app.MapGet("/", () =>
{
    // written for the old Windows servers: none of this is changed for the container
    var production = Environment.MachineName.ToLowerInvariant() == "prodweb01";

    string? subject = null;
    using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
    {
        store.Open(OpenFlags.ReadOnly);
        var found = store.Certificates.Find(X509FindType.FindBySubjectName, "signing.example", false);
        subject = found.Count > 0 ? found[0].Subject : null;
    }

    var vendorFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "Acme", "rates.xml");

    return new
    {
        machine = Environment.MachineName,
        production,
        certificate = subject,
        vendorFile = File.Exists(vendorFile),
    };
});

app.Run();
