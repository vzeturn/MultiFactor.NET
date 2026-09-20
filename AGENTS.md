# Agent Instructions — MM.Auth

## What this repository is

A standalone .NET 10 library. It has exactly one consumer story: a host wires `AddMmAuth` plus a
storage adapter plus a secret protector plus one or more factors. It is not an application and has
no runtime of its own.

## Rules an agent must not break

- **Single target framework.** `net10.0`, set once in `Directory.Build.props`. Do not add a second
  TFM and do not reference `System.Security.Cryptography.ProtectedData`.
- **The core stays dependency-free.** `src/MM.Auth` may reference
  `Microsoft.Extensions.DependencyInjection.Abstractions`, `xunit` and `AwesomeAssertions` (the last
  two because the conformance suite ships inside it) and nothing else. A DB driver or cipher in the
  core csproj is a design regression, not a convenience.
- **`AddMmAuth` registers no defaults.** It registers `MfaOptions` and `IMfaFactorService` only.
  Adding a fallback repository or protector re-creates exactly the coupling this library exists to
  remove.
- **Factors never see ciphertext.** `IMfaFactor` takes plaintext secrets. If a change makes a factor
  aware of `ISecretProtector`, the change is wrong.
- **Repositories never see plaintext.** `IMfaRepository` stores the bytes it is handed. If a change
  makes an adapter call a protector, the change is wrong.
- **No engine-specific SQL outside an adapter.** Timestamps are computed in C# and bound as
  parameters. `strftime`, `datetime('now')` and friends belong nowhere.
- **New storage adapters inherit `MM.Auth.Testing.MfaRepositoryConformanceTests`.** Do not hand-write
  a parallel suite.
- **`TreatWarningsAsErrors` is on.** Fix the warning; do not add a `NoWarn`.

## Testing conventions

xUnit with AwesomeAssertions, globally imported via `<Using>` in each test csproj. One test class
per component. Test names are sentences with underscores. Assert discriminated-union cases with
`Assert.IsType<T>(...)`; assert values with `.Should().Be(...)`.

## Git

Commits stay local. Pushing to a remote, adding a remote, or publishing a package requires the
user's explicit in-session confirmation, every time.
