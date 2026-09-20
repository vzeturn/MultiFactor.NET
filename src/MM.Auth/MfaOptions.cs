using System.Text.RegularExpressions;

namespace MM.Auth;

/// <summary>
/// Host-supplied configuration. <see cref="ProtectionContext"/> and <see cref="TablePrefix"/> are
/// compatibility surfaces: changing either on a deployed app orphans every existing enrollment.
/// </summary>
public sealed partial record MfaOptions
{
    /// <summary>Shown by the authenticator app and embedded in the otpauth URI.</summary>
    public required string Issuer { get; init; }

    /// <summary>
    /// Root of the authenticated-data label handed to <see cref="ISecretProtector"/>. Replaces the
    /// DPAPI-specific EntropyLabel of MM.Mfa.
    /// </summary>
    public required string ProtectionContext { get; init; }

    /// <summary>Prepended to the three table names. Interpolated into SQL, hence validated.</summary>
    public required string TablePrefix { get; init; }

    public int BackupCodeCount { get; init; } = 10;

    public TimeSpan ChallengeLifetime { get; init; } = TimeSpan.FromMinutes(5);

    public TimeSpan PendingEnrollLifetime { get; init; } = TimeSpan.FromMinutes(10);

    internal string Table(string suffix) => TablePrefix + "mfa_" + suffix;

    /// <summary>Fails loud at startup rather than letting a malformed prefix reach the SQL text.</summary>
    public MfaOptions Validate()
    {
        if (string.IsNullOrWhiteSpace(Issuer))
            throw new ArgumentException("MfaOptions.Issuer must not be blank.", nameof(Issuer));
        if (string.IsNullOrWhiteSpace(ProtectionContext))
            throw new ArgumentException(
                "MfaOptions.ProtectionContext must not be blank.", nameof(ProtectionContext));
        if (TablePrefix.Length > 0 && !IdentifierPattern().IsMatch(TablePrefix))
            throw new ArgumentException(
                "MfaOptions.TablePrefix is not a safe SQL identifier prefix: " + TablePrefix,
                nameof(TablePrefix));
        if (BackupCodeCount is < 1 or > 100)
            throw new ArgumentException(
                "MfaOptions.BackupCodeCount must be 1..100.", nameof(BackupCodeCount));
        if (ChallengeLifetime == TimeSpan.Zero || PendingEnrollLifetime == TimeSpan.Zero)
            throw new ArgumentException(
                "MfaOptions lifetimes must be non-zero.", nameof(ChallengeLifetime));
        return this;
    }

    [GeneratedRegex("^[a-z_][a-z0-9_]*$")]
    private static partial Regex IdentifierPattern();
}
