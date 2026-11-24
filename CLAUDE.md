# MM.Auth

Standalone .NET 10 multi-factor authentication library — abstractions, orchestration and a
behavioural conformance suite, with pluggable storage/crypto/factor adapters and a headless React
client. It is not a runtime service: no host, no `Program.cs`, no HTTP endpoints of its own. It is
a redesign of (not an upgrade to) the older `MM.Mfa` package, published separately via a local NuGet
feed for consumption by other services in the hospitality SaaS portfolio (e.g. a host such as the
.NET Hub) — this repo itself has no visibility into that consumer's architecture.

## Stack & versions

- .NET 10 (`net10.0`, single TFM by design — see `Directory.Build.props`), C# `LangVersion=latest`,
  nullable + implicit usings enabled, `TreatWarningsAsErrors=true`.
- Tests: xUnit 2.9.3 + AwesomeAssertions 9.4.0 (globally `<Using>`d per test csproj).
- `MM.Auth.Sqlite`: Dapper 2.1.66 + Microsoft.Data.Sqlite 10.0.0.
- `MM.Auth.Totp`: Otp.NET 1.4.0 (RFC 6238).
- `@mm/auth-react` (web/packages/auth-react): TypeScript 5.7, React 19 peer dep, Vitest 4.1,
  pnpm 11.5 workspace, package version 2.0.0.
- No CI config found (`.github/workflows` absent) — build/test commands below are read from the
  slnx/csproj/scripts, not verified against a pipeline.

## Commands

- Build: `dotnet build -c Release` (solution is `MM.Auth.slnx`).
- Test all: `dotnet test`.
- Test one project: `dotnet test tests/MM.Auth.Tests/MM.Auth.Tests.csproj`.
- Test one case: `dotnet test --filter "FullyQualifiedName~MfaFactorServiceTests.MethodName"`.
- Frontend (`web/packages/auth-react`): `pnpm typecheck`, `pnpm test` (vitest run), `pnpm build`.
- Local packaging (NuGet + npm tarball into `$env:MM_FEED`, default `E:\MM-Feed`):
  `./publish-local.ps1` (PowerShell; packs all 4 .csproj + `pnpm pack` for auth-react).
- No migrations tool: `SqliteMfaSchema.EnsureAsync` creates the adapter's own tables in-process.
- Deploy/publish to a real feed or remote: not confirmed here — ask the user first regardless
  (publish-local.ps1 only writes to a local/mapped path).

## Architecture map

- `src/MM.Auth` — core: `IMfaFactor`, `IMfaRepository`, `ISecretProtector`, `IMfaKeyProvider`,
  `IMfaConnectionFactory`, `MfaOptions`, `MfaFactorService` (the orchestrator), and
  `MfaServiceCollectionExtensions.AddMmAuth` (the composition entry point — registers only
  `MfaOptions` + `IMfaFactorService`, no defaults). Also ships
  `Testing/MfaRepositoryConformanceTests`, an abstract xUnit suite adapter authors inherit.
- `src/MM.Auth.Totp` — `TotpFactor : IMfaFactor` (RFC 6238, SHA-1, 6 digits, 30s step).
- `src/MM.Auth.Sqlite` — `SqliteMfaRepository` + `SqliteMfaSchema`, `AddMmAuthSqlite`.
- `src/MM.Auth.Crypto.Aes` — `AesGcmSecretProtector` (AES-256-GCM, key-rotation-aware blob:
  version byte + keyId + nonce + ciphertext + tag), `AddMmAuthAesProtector`.
- `web/packages/auth-react` — `createMfaApi`, `useMfaEnrollment`, `useMfaChallenge`: headless hooks
  over whatever HTTP endpoints the host exposes; ships no UI.
- No single composition root: each package exposes one `IServiceCollection` extension method
  (`AddMmAuth`, `AddMmAuthSqlite`, `AddMmAuthAesProtector`); the consuming host wires them together.

## Conventions

- Core package (`src/MM.Auth`) is deliberately dependency-free beyond
  `Microsoft.Extensions.DependencyInjection.Abstractions`, `xunit` and `AwesomeAssertions` — the
  latter two ship because the conformance suite lives inside the core assembly. Do not add a DB
  driver or cipher there.
- `AddMmAuth` registers zero defaults; a host missing a repository/protector/factor fails at
  `BuildServiceProvider`, by design.
- Factors handle plaintext only; repositories handle ciphertext only — never cross that seam.
- No engine-specific SQL outside an adapter; timestamps are computed in C# and bound as parameters.
- xUnit test names are full sentences with underscores; discriminated-union cases asserted via
  `Assert.IsType<T>(...)`, values via `.Should().Be(...)`.
- `MfaOptions.Table(string)` is `internal`, exposed to `MM.Auth.Tests` and `MM.Auth.Sqlite` via
  `InternalsVisibleTo`.
- See `AGENTS.md` for the hard rules (single TFM, no fallback defaults, no `NoWarn` for
  `TreatWarningsAsErrors`) — that file is the authoritative rule set; this file is orientation.
- `docs/CHANGELOG.md` is maintained; update it for behavioural changes.

## Gotchas

- `IMfaKeyProvider.CurrentKeyId` must be 1–255 UTF-8 bytes; keys must be exactly 32 bytes
  (AES-256). Returning `null` from `GetKeyAsync` for a retired key permanently strands data sealed
  under it.
- `ProtectionContext` in `MfaOptions` feeds AES-GCM as AAD — changing it after data is sealed makes
  that data unreadable.
- No MM.Mfa → MM.Auth in-place upgrade: DPAPI-sealed data cannot be read by
  `AesGcmSecretProtector`; migration requires clearing `{prefix}mfa_secret` /
  `{prefix}mfa_backup_code` and re-enrollment (see `docs/CHANGELOG.md`).
- `web/packages/auth-react` is `"license": "UNLICENSED"` — internal-only package.
- Only env var of note found in-repo: `MM_FEED` (local packaging destination path, no secret).
- Commits stay local per `AGENTS.md`; pushing/adding a remote/publishing needs explicit
  user confirmation each time.
