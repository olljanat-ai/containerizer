# ci-demo

A tiny ASP.NET Core app that this repository's CI gates with its own GitHub Action
(`.github/workflows/ci.yml`). Add a Windows-only dependency here in a pull request, for example
`<PackageReference Include="Microsoft.Win32.Registry" Version="5.0.0" />` plus a registry call, and the
check fails and comments on the pull request.
