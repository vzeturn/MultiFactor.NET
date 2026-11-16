# MM.Auth

Multi-factor authentication for .NET 10, split so that nothing you do not use gets pulled in.

| Package | What it gives you |
|---|---|
| `MM.Auth` | Abstractions + `MfaFactorService` orchestration + the repository conformance suite. No DB driver, no cipher, no factor. |
| `MM.Auth.Totp` | `TotpFactor` — RFC 6238, SHA-1, 6 digits, 30s step, ±1 step tolerance. |
| `MM.Auth.Sqlite` | `SqliteMfaRepository` + `SqliteMfaSchema`, over Dapper. |
| `MM.Auth.Crypto.Aes` | `AesGcmSecretProtector` — AES-256-GCM, runs on any OS. |
| `@mm/auth-react` | Headless React hooks and an HTTP client for the endpoints your host exposes. |

## Wiring

The core registers no defaults, on purpose. You supply three things: storage, secret protection,
and at least one factor. Miss one and `BuildServiceProvider` fails at startup rather than at the
first login attempt.

```csharp
services.AddSingleton<IMfaConnectionFactory, MyConnectionFactory>();

services.AddMmAuth(o => o with
{
    Issuer = "MyApp",
    ProtectionContext = "MyApp.Auth",
    TablePrefix = "app_",
});

services.AddMmAuthSqlite();
services.AddMmAuthAesProtector(new MyKeyProvider(configuration));
services.AddSingleton<IMfaFactor>(sp => new TotpFactor(sp.GetRequiredService<MfaOptions>()));
```

## The key provider is yours

`MM.Auth` never generates, stores, or rotates a key. You implement `IMfaKeyProvider` over whatever
secret manager you already run:

```csharp
public interface IMfaKeyProvider
{
    ValueTask<ReadOnlyMemory<byte>> GetCurrentKeyAsync(CancellationToken ct = default);
    ValueTask<ReadOnlyMemory<byte>?> GetKeyAsync(string keyId, CancellationToken ct = default);
    string CurrentKeyId { get; }
}
```

Keys must be exactly 32 bytes. `CurrentKeyId` is recorded in every blob, so after a rotation
`GetKeyAsync(oldKeyId)` must keep returning the retired key for as long as data sealed with it is
still in the database. Once you return `null` for a key id, every blob sealed under it is
permanently unreadable and those users must re-enroll.

## Writing another database adapter

Implement `IMfaRepository`, then inherit the suite that ships with the core package:

```csharp
public sealed class PostgresMfaRepositoryConformanceTests : MM.Auth.Testing.MfaRepositoryConformanceTests
{
    protected override IMfaRepository CreateRepository() => /* your repository over an empty DB */;

    protected override IMfaRepository CreateRepositoryWithExpiredChallenges() =>
        /* the same, with a negative ChallengeLifetime */;
}
```

Compute timestamps in C# and bind them as parameters, as `SqliteMfaRepository` does — the SQL text
should carry no engine-specific date functions.

## Local packaging

`./publish-local.ps1` packs all four NuGet packages and the npm tarball into `$env:MM_FEED`
(default `E:\MM-Feed`).
