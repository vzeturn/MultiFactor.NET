# Changelog

## 1.0.0

First release. MM.Auth is a redesign of MM.Mfa, not an upgrade of it: the two are separate
packages, and MM.Mfa remains published and untouched.

### Added

- `MM.Auth` core: `IMfaFactor`, `FactorProof`, `FactorEnrollStart`, `FactorEnrollResult`,
  `ISecretProtector`, `IMfaKeyProvider`, `SecretProtectionException`, `IMfaRepository`,
  `IMfaConnectionFactory`, `IMfaFactorService`, `MfaFactorService`, `MfaOptions`, `MfaChallenge`,
  `MfaChallengeSubject`, `MfaEnrollStart`, `AddMmAuth`.
- `MM.Auth.Testing.MfaRepositoryConformanceTests`, shipped inside the core package, so a new
  storage adapter inherits the full behavioural suite.
- `MM.Auth.Totp` with `TotpFactor`.
- `MM.Auth.Sqlite` with `SqliteMfaRepository`, `SqliteMfaSchema` and `AddMmAuthSqlite`.
- `MM.Auth.Crypto.Aes` with `AesGcmSecretProtector` and `AddMmAuthAesProtector`.
- `@mm/auth-react` 2.0.0, renamed from `@mm/mfa-react` 1.0.0 with no change to any hook, type or
  endpoint.

### Changed from MM.Mfa

- Runs on any OS .NET 10 supports. DPAPI and the `net10.0-windows` target framework are gone.
- Secret protection is an interface (`ISecretProtector`), not a sealed concrete class, and the
  default implementation ships in a separate package so a host using a KMS pulls in no AES code.
- `IMfaService` became `IMfaFactorService`; `string code` parameters became `FactorProof`;
  `MfaEnrollResult` became `FactorEnrollResult` and `InvalidCode` became `InvalidProof`.
- `IMfaRepository` takes already-encrypted bytes and a `factorKind`, and does no crypto itself.
- `MfaOptions.EntropyLabel` became `ProtectionContext`; all properties are now `init`-only and the
  three required ones have no default.
- `AddMmAuth` registers no repository, protector, key provider or factor. Hosts wire those
  explicitly; a missing one fails at startup.
- `mfa_secret` is keyed by `(initial, factor_kind)` rather than `initial` alone.
- No DDL column has a database-side time default; adapters bind C#-computed timestamps.

### Migration warning

Secret protection moved from DPAPI to AES-256-GCM, so **no MM.Mfa enrollment can be read by
MM.Auth**. Before switching a deployment over, clear the existing `{prefix}mfa_secret` and
`{prefix}mfa_backup_code` rows and tell every enrolled user to re-enroll. There is no in-place
upgrade path, and this was accepted deliberately when the redesign was approved.
