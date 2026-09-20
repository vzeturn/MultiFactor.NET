namespace MM.Auth;

/// <summary>
/// Persistence for already-encrypted factor secrets, one-time backup codes, and short-lived
/// single-use login challenges. An adapter never touches <see cref="ISecretProtector"/>: it stores
/// the bytes it is handed and returns them unchanged.
/// </summary>
/// <remarks>
/// <para>Suggested (not enforced) shape, with <c>{prefix}</c> from <see cref="MfaOptions.TablePrefix"/>:</para>
/// <list type="bullet">
/// <item><c>{prefix}mfa_secret(initial, factor_kind, secret_encrypted, enrolled_at, enabled)</c>,
/// primary key <c>(initial, factor_kind)</c> so one subject can hold several factors.</item>
/// <item><c>{prefix}mfa_backup_code(id, initial, code_hash, used_at, created_at)</c> — keyed by
/// subject only, deliberately: one set of backup codes covers every factor the subject has.</item>
/// <item><c>{prefix}mfa_challenge(challenge_token, initial, rvc, created_at, expires_at, consumed_at)</c>.</item>
/// </list>
/// <para>Adapters must compute every timestamp in C# and bind it as a parameter, never via a
/// database-specific time function, so the same logic ports across engines.</para>
/// </remarks>
public interface IMfaRepository
{
    Task<bool> IsEnabledAsync(string subject, string factorKind, CancellationToken ct = default);

    /// <summary>The stored ciphertext, exactly as written, or null when not enrolled.</summary>
    Task<byte[]?> GetSecretAsync(string subject, string factorKind, CancellationToken ct = default);

    /// <summary>
    /// Replaces any prior enrollment of this factor: drops that factor's secret and all of the
    /// subject's backup codes, then writes the fresh secret and codes.
    /// </summary>
    Task EnrollAsync(string subject, string factorKind, byte[] encryptedSecret,
        IReadOnlyList<string> backupCodes, CancellationToken ct = default);

    /// <summary>Removes this factor's secret and all of the subject's backup codes.</summary>
    Task DisableAsync(string subject, string factorKind, CancellationToken ct = default);

    /// <summary>Consumes one unused backup code. False when none matched.</summary>
    Task<bool> TryConsumeBackupCodeAsync(string subject, string code, CancellationToken ct = default);

    Task<int> CountRemainingBackupCodesAsync(string subject, CancellationToken ct = default);

    Task<string> CreateChallengeAsync(string subject, int scope, CancellationToken ct = default);

    /// <summary>Atomically consumes an unexpired, unconsumed challenge. Null if invalid, expired or spent.</summary>
    Task<MfaChallengeSubject?> TryConsumeChallengeAsync(string challengeToken, CancellationToken ct = default);
}
