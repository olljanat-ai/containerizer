# platform-techniques

A small ASP.NET Core app written the way many Windows-hosted apps are, used to check that Containerizer's platform
techniques ([docs/overview.md](../../docs/overview.md#generated-output)) let it run in a
container **without code changes**:

- it switches to production settings when `Environment.MachineName` is `prodweb01` (the pod's `hostname:` is set);
- it signs with a certificate it finds in `CurrentUser\My` by subject name (a Secret with a password-less `.pfx` is
  mounted at `~/.dotnet/corefx/cryptography/x509stores/my`);
- it reads a vendor file from `Program Files\Acme` (`GetFolderPath` is `""` on Linux, so the path is `Acme/...`
  under `/app`, where a volume is mounted).

Without the techniques these three findings are `refactor` and the app is rated B; with them it is rated A.

`GET /` returns what the app sees: the machine name, whether the certificate was found and whether the vendor file
was read. Verified with the .NET 10 runtime image (uid 1654, read-only root file system): `docker run --hostname
prodweb01 -v <dir with cert.pfx>:/home/app/.dotnet/corefx/cryptography/x509stores/my:ro -v <dir>:/app/Acme ...`
shows `"production": true, "certificate": "CN=signing.example", "vendorFile": true`; without them the same image
shows `false`, `null`, `false`. The image was the one `containerizer generate` writes for this folder.
